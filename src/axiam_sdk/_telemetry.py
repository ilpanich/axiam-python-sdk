"""Telemetry hooks — CONTRACT.md §19.

An optional callback surface so callers can wire OpenTelemetry, Prometheus or a
log line **without this package depending on any of them**. No hook installed
costs one ``is None`` check per request.

Two rules from §19.2 are enforced here rather than left to documentation:

* **A hook cannot break the SDK.** :meth:`TelemetryDispatcher.emit` swallows
  anything a sink raises, so a broken hook cannot fail an authorization check.
* **No secrets, ever.** The event dataclasses are frozen with a fixed field set
  and no free-form ``extra`` mapping, so there is no place to put a token in a
  payload bound for a metrics backend. The type, not a review comment, is what
  keeps them out.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

__all__ = [
    "Outcome",
    "RefreshRole",
    "RequestStart",
    "RequestEnd",
    "Retry",
    "Refresh",
    "TelemetryEvent",
    "TelemetryHook",
    "TelemetryDispatcher",
]

#: Why a request finished.
Outcome = Literal["success", "failure"]

#: Whether this caller performed a §9 refresh or waited on another's.
RefreshRole = Literal["leader", "follower"]


@dataclass(frozen=True)
class RequestStart:
    """Emitted before an outbound call leaves the SDK."""

    #: Canonical operation name, e.g. ``check_access``.
    operation: str
    #: HTTP method.
    method: str
    #: Path **template** — ``/api/v1/authz/check``, never a URL with ids
    #: substituted in. A metric label carrying a UUID is a cardinality bomb.
    path_template: str
    #: 1 for the first attempt, incrementing per §16 retry.
    attempt: int


@dataclass(frozen=True)
class RequestEnd:
    """Emitted after a call completes, success or failure."""

    operation: str
    method: str
    path_template: str
    attempt: int
    #: HTTP status, or ``None`` when the call never got a response.
    status: int | None
    #: Wall-clock duration of this attempt, in milliseconds.
    duration_ms: float
    outcome: Outcome


@dataclass(frozen=True)
class Retry:
    """Emitted before each §16 retry wait.

    §16.5 requires this: a retried-then-succeeded operation is otherwise
    invisible — the caller sees a slow success and no signal that the server is
    failing. That silence is the standing objection to automatic retry.
    """

    operation: str
    #: The attempt that just failed.
    attempt: int
    #: The delay about to be taken, after jitter and any ``Retry-After``.
    delay_ms: float
    #: Redacted failure description. Never carries a token (§2 redaction rules).
    reason: str


@dataclass(frozen=True)
class Refresh:
    """Emitted around a §9 single-flight refresh."""

    role: RefreshRole
    duration_ms: float


#: A §19 telemetry event.
TelemetryEvent = RequestStart | RequestEnd | Retry | Refresh

#: A caller-supplied telemetry sink.
#:
#: Invoked on the calling path, so it must not block: §19.2 rule 4 makes
#: buffering the caller's job so they can pick the policy. Every mature metrics
#: library already buffers.
TelemetryHook = Callable[[TelemetryEvent], None]


class TelemetryDispatcher:
    """Internal dispatcher. ``None`` is the common case and costs one check."""

    __slots__ = ("_hook",)

    def __init__(self, hook: TelemetryHook | None = None) -> None:
        """Wrap *hook*, or nothing at all when it is ``None`` (the default)."""
        self._hook = hook

    @property
    def installed(self) -> bool:
        """Whether a hook is installed."""
        return self._hook is not None

    def emit(self, event: TelemetryEvent) -> None:
        """Emit *event*, swallowing anything the caller's hook raises.

        §19.2 rule 2: telemetry is not permitted to fail an authorization
        check. A hook that raises is the caller's bug, and surfacing it here
        would turn a metrics problem into an authorization failure.
        """
        if self._hook is None:
            return
        try:
            self._hook(event)
        except Exception:  # noqa: BLE001 — deliberately swallowed, see above.
            pass

    def request(
        self, operation: str, method: str, path_template: str, attempt: int = 1
    ) -> _RequestSpan:
        """Open a §19 request pair around one **attempt**.

        Per attempt, not per logical call: §19.2 rule 5 requires a caller to be
        able to count real wire calls from the events, which one pair per
        operation would hide — a retried call would look like a single slow one.
        """
        return _RequestSpan(self, operation, method, path_template, attempt)


class _RequestSpan:
    """Context manager emitting ``RequestStart`` then ``RequestEnd``."""

    __slots__ = ("_d", "_op", "_method", "_path", "_attempt", "_started", "status", "outcome")

    def __init__(
        self,
        dispatcher: TelemetryDispatcher,
        operation: str,
        method: str,
        path_template: str,
        attempt: int,
    ) -> None:
        """Capture the labels this span's two events will carry."""
        self._d = dispatcher
        self._op = operation
        self._method = method
        self._path = path_template
        self._attempt = attempt
        self._started = 0.0
        self.status: int | None = None
        self.outcome: Outcome = "failure"

    def __enter__(self) -> _RequestSpan:
        """Emit ``RequestStart`` and start the clock."""
        if self._d.installed:
            self._d.emit(
                RequestStart(
                    operation=self._op,
                    method=self._method,
                    path_template=self._path,
                    attempt=self._attempt,
                )
            )
            self._started = time.monotonic()
        return self

    def __exit__(self, exc_type: object, *_: object) -> Literal[False]:
        """Emit ``RequestEnd``, never suppressing the in-flight exception."""
        if self._d.installed:
            # An exception leaving the block is a failure even if the caller
            # never set `outcome` — the common path for a transport error.
            outcome: Outcome = "failure" if exc_type is not None else self.outcome
            self._d.emit(
                RequestEnd(
                    operation=self._op,
                    method=self._method,
                    path_template=self._path,
                    attempt=self._attempt,
                    status=self.status,
                    duration_ms=(time.monotonic() - self._started) * 1000.0,
                    outcome=outcome,
                )
            )
        return False
