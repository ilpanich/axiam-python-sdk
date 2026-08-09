"""Bounded read-only retry policy — CONTRACT.md §16.

This SDK had **no** §16 policy before D5 — only §9.3's refresh-then-retry-once,
which is a different mechanism (it reacts to a 401 by refreshing, and
deliberately does not loop). §11.2 rule 5 and §14.2 rule 6 had both been
requiring "the SDK's existing bounded read-only retry policy" against a policy
that did not exist here.

Sync and async variants share :func:`backoff_ms` and :func:`delay_ms` so the
two cannot drift — the arithmetic is the contract, and duplicating it is how
eleven SDKs ended up with three different answers in the first place.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

from ._errors import NetworkError
from ._telemetry import Retry, TelemetryDispatcher

__all__ = [
    "MAX_ATTEMPTS",
    "BASE_DELAY_MS",
    "MAX_DELAY_MS",
    "backoff_ms",
    "delay_ms",
    "retry_sync",
    "retry_async",
]

#: Attempt cap: 1 initial + 2 retries (§16.1).
MAX_ATTEMPTS = 3
#: First backoff step, in milliseconds (§16.1).
BASE_DELAY_MS = 200.0
#: Ceiling on any single computed backoff, in milliseconds (§16.1).
MAX_DELAY_MS = 5_000.0

T = TypeVar("T")


def backoff_ms(attempt: int) -> float:
    """Un-jittered backoff for a 1-based *attempt*: ``min(cap, base * 2^(n-1))``.

    Attempt 1 → 200 ms, attempt 2 → 400 ms.
    """
    return min(MAX_DELAY_MS, BASE_DELAY_MS * float(2 ** (attempt - 1)))


def delay_ms(attempt: int, retry_after_ms: float | None, fraction: float) -> float:
    """The actual wait: **full jitter** over ``[0, backoff]``, raised to any
    server-supplied ``Retry-After`` (§16.1).

    Full jitter, not ``backoff ± 10%``. Partial jitter keeps every client's
    retries clustered around the same instant, which is the thundering herd
    retries are supposed to prevent rather than cause.

    ``Retry-After`` is a **floor, never a ceiling**: the server is saying when
    it will be ready, so retrying sooner is not permitted — and a
    ``Retry-After: 0`` cannot shorten the wait below what jitter chose.

    *fraction* is the jitter draw in ``[0, 1]``, injected so tests can pin it.
    """
    jittered = backoff_ms(attempt) * min(max(fraction, 0.0), 1.0)
    return jittered if retry_after_ms is None else max(jittered, retry_after_ms)


def _retry_after_of(err: BaseException) -> float | None:
    """A ``Retry-After`` hint carried on *err*, in milliseconds, if any."""
    value = getattr(err, "retry_after_ms", None)
    return float(value) if isinstance(value, (int, float)) else None


def _should_retry(err: BaseException) -> bool:
    """Only ``NetworkError`` is retried.

    The §2 taxonomy folds ``408``/``429``/``5xx``/transport into that one type,
    so this implements the whole §16.3 table: ``AuthError`` and ``AuthzError``
    are decisive answers from the server, not transport failures, and repeating
    them just reproduces the same rejection.
    """
    return isinstance(err, NetworkError)


def retry_sync(
    op: Callable[[int], T],
    *,
    operation: str,
    enabled: bool = True,
    telemetry: TelemetryDispatcher | None = None,
    sleep: Callable[[float], None] | None = None,
    rand: Callable[[], float] | None = None,
) -> T:
    """Run *op* under the §16 policy, synchronously.

    *op* receives the 1-based attempt number so it can label its §19 request
    pair — §19.2 rule 5 requires one pair per attempt so a caller can count real
    wire calls.

    *op* MUST be side-effect-free. This helper — like every retry helper —
    cannot tell the difference, so routing a mutation through it would silently
    duplicate a side effect, or replay a single-use credential (an authorization
    code, a device code at redemption, a rotating refresh token) into a hard
    ``invalid_grant``.
    """
    _sleep = sleep if sleep is not None else lambda ms: time.sleep(ms / 1000.0)
    _rand = rand if rand is not None else random.random
    attempts = MAX_ATTEMPTS if enabled else 1

    for attempt in range(1, attempts + 1):
        try:
            return op(attempt)
        except Exception as err:  # noqa: BLE001 — re-raised below unless retryable.
            if attempt == attempts or not _should_retry(err):
                raise
            wait = delay_ms(attempt, _retry_after_of(err), _rand())
            if telemetry is not None:
                # §16.5 — without this a retried-then-succeeded call is
                # invisible: a slow success with no signal the server is failing.
                telemetry.emit(
                    Retry(operation=operation, attempt=attempt, delay_ms=wait, reason=str(err))
                )
            _sleep(wait)

    raise NetworkError("retry loop exhausted without a result")  # pragma: no cover


async def retry_async(
    op: Callable[[int], Awaitable[T]],
    *,
    operation: str,
    enabled: bool = True,
    telemetry: TelemetryDispatcher | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    rand: Callable[[], float] | None = None,
) -> T:
    """Async twin of :func:`retry_sync`, sharing its arithmetic exactly."""

    async def _default_sleep(ms: float) -> None:
        """Await *ms* milliseconds, the default when no sleep is injected."""
        await asyncio.sleep(ms / 1000.0)

    _sleep = sleep if sleep is not None else _default_sleep
    _rand = rand if rand is not None else random.random
    attempts = MAX_ATTEMPTS if enabled else 1

    for attempt in range(1, attempts + 1):
        try:
            return await op(attempt)
        except Exception as err:  # noqa: BLE001 — re-raised below unless retryable.
            if attempt == attempts or not _should_retry(err):
                raise
            wait = delay_ms(attempt, _retry_after_of(err), _rand())
            if telemetry is not None:
                telemetry.emit(
                    Retry(operation=operation, attempt=attempt, delay_ms=wait, reason=str(err))
                )
            await _sleep(wait)

    raise NetworkError("retry loop exhausted without a result")  # pragma: no cover
