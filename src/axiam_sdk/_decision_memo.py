"""Client-side decision memo — CONTRACT.md §17.

**Disabled by default.** §11.2 rule 6's ban on caching allow/deny decisions is
still the default behaviour; this is the single opt-in exception that section
carves out, and a caller has to switch it on having read the cost.

What it costs
-------------

The staleness bound is the TTL, **in both directions**. A grant revoked on the
server can still read as allowed for up to the TTL, and a grant just added can
still read as denied for up to the TTL. That second direction is the one that
surprises people: **reads-your-own-writes is not guaranteed.** An admin UI that
grants a role and immediately re-checks is the case that breaks, and it breaks
silently.

This mirrors the server's own bound rather than inventing a second staleness
story — ``AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS`` (default 5 s) makes the same
trade server-side. One deliberate difference: the server's setting is an
unclamped integer, so an operator can configure a multi-hour staleness window.
:data:`MAX_TTL_MS` clamps this one at 5 s, because the client has no reason to
repeat that.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable

__all__ = ["MAX_TTL_MS", "memo_key", "DecisionMemo"]

#: The §17.1 rule 2 ceiling, in milliseconds. A configured TTL above this is
#: clamped, not rejected: a caller who asked for 60 s wants caching, and
#: silently giving them the maximum safe value beats failing construction.
MAX_TTL_MS = 5_000.0

#: Entry cap before FIFO eviction (§17.1 rule 8). The memo is a latency
#: optimisation, so dropping an entry is always correct.
_MAX_ENTRIES = 1024

#: Joins the key components. ``\x1f`` (unit separator) cannot appear in an
#: action, a UUID or a scope, so no combination of caller-supplied values can
#: forge a collision.
_SEP = "\x1f"

#: Marks an *absent* optional, which is why an absent scope can never collide
#: with a present one — a memo that let them collide would answer a narrower
#: question with a broader answer.
_ABSENT = "\x00"


def memo_key(
    action: str,
    resource_id: str,
    scope: str | None = None,
    subject_id: str | None = None,
) -> str:
    """The §17.1 rule 3 key: all four components, absent distinguished from present."""
    return _SEP.join(
        (
            subject_id if subject_id is not None else _ABSENT,
            resource_id,
            action,
            scope if scope is not None else _ABSENT,
        )
    )


class DecisionMemo:
    """A bounded, TTL-clamped decision memo.

    ``ttl_ms == 0`` means **disabled** — not "cache for zero milliseconds".
    That is the default, and both :meth:`get` and :meth:`set` become no-ops.

    Thread-safe: the sync client is commonly shared across a thread pool, and a
    cache that corrupted under concurrency would be a worse bug than the one it
    is optimising away.
    """

    __slots__ = ("_ttl_ms", "_entries", "_now", "_lock")

    def __init__(self, ttl_ms: float = 0.0, now: Callable[[], float] | None = None) -> None:
        """
        :param ttl_ms: requested TTL in milliseconds; ``0`` disables the memo and
            any value above :data:`MAX_TTL_MS` is clamped to it.
        :param now: injected monotonic clock in seconds, so the TTL can be
            tested without waiting.
        """
        self._ttl_ms = min(max(float(ttl_ms), 0.0), MAX_TTL_MS)
        self._entries: OrderedDict[str, tuple[object, float]] = OrderedDict()
        self._now = now if now is not None else time.monotonic
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """Whether this memo does anything. ``False`` for the default config."""
        return self._ttl_ms > 0

    @property
    def effective_ttl_ms(self) -> float:
        """The TTL after clamping."""
        return self._ttl_ms

    def get(self, key: str) -> object | None:
        """A live decision for *key*, if one is memoized and unexpired."""
        if not self.enabled:
            return None
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            decision, stored_at = entry
            if (self._now() - stored_at) * 1000.0 >= self._ttl_ms:
                del self._entries[key]
                return None
            # Returned whole, including ``reason_code``: §17.1 rule 5 forbids
            # returning ``allowed`` while dropping the code, which would make
            # the field intermittently absent — worse than never having had it.
            return decision

    def set(self, key: str, decision: object) -> None:
        """Memoize a decision the server actually returned.

        Callers must only reach here on success. §17.1 rule 7 forbids
        negative-caching a failure: memoizing a transport error as a deny would
        turn a blip into a TTL-long outage, and memoizing it as an allow is
        unthinkable.
        """
        if not self.enabled:
            return
        with self._lock:
            self._entries.pop(key, None)
            self._entries[key] = (decision, self._now())
            while len(self._entries) > _MAX_ENTRIES:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        """Drop every entry (§17.1 rule 9).

        Called on login, verify_mfa, refresh and logout. Entries are keyed by
        subject, not by session, so a re-authentication as a *different*
        principal would otherwise read the previous principal's decisions.
        """
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
