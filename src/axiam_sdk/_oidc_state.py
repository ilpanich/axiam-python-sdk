"""``OidcStateStore`` + ``MemoryOidcStateStore`` (CONTRACT.md §12.3 rule 1).

**Strictly optional.** The nine §12 operations never touch a store:
``oidc_begin`` and ``oidc_exchange`` are stateless by contract, and the
caller normally keeps ``state``/``nonce``/``code_verifier`` in its own HTTP
session. This store exists for the framework glue
(``fastapi.oidc_login_router``, ``django``'s OIDC view pair), where a login
and its callback are two separate HTTP requests with nothing but a ``state``
value linking them.

Semantics mirror the server's ``federation_login_state`` table exactly:
10-minute TTL, single-use consume — the same symmetry
``the TypeScript SDK's src/node/oidcState.ts`` documents.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import SecretStr

#: The contract-mandated TTL for stored login state: 10 minutes, matching the
#: server's ``federation_login_state`` row lifetime (D-22, CONTRACT.md §12.3
#: rule 1).
OIDC_STATE_TTL_SECONDS = 600.0

#: How many in-flight logins :class:`MemoryOidcStateStore` holds before it evicts the oldest.
#: The login route is unauthenticated and every call saves one entry, so an unbounded dict is a
#: memory-exhaustion lever.
DEFAULT_MAX_ENTRIES = 10_000


@dataclass(frozen=True)
class OidcStateEntry:
    """The tuple an :class:`OidcStateStore` holds for one in-flight login.

    ``code_verifier`` stays a ``SecretStr`` while stored (CONTRACT.md §12.5:
    the verifier is secret for its whole lifetime, "including ... in any
    ``OidcStateStore`` entry"), so ``repr()``/``str()`` of an entry — e.g.
    logged by a Redis-backed store implementation — never emits the raw
    verifier.
    """

    #: The ``state`` value this entry is keyed by. Not a secret (§12.3 rule 2).
    state: str
    #: The ``nonce`` to check the ID token's ``nonce`` claim against. Not a
    #: secret (§12.3 rule 2).
    nonce: str
    #: The PKCE verifier for the matching authorization request (§12.5 secret).
    code_verifier: SecretStr
    #: The ``redirect_uri`` that was sent on the authorization request and
    #: must be replayed on exchange.
    redirect_uri: str
    #: Optional application-owned data, e.g. the page the user was heading
    #: to before login.
    return_to: str | None = None
    #: Lower-case hex SHA-256 of the browser-binding cookie value the login route set
    #: (CONTRACT.md §12.8 rule 1, contract 1.68). **Optional** so a store written against 1.67
    #: still works and an entry without it can be read -- the glue then refuses the callback.
    #: A caller-supplied store MUST persist this member and return it unchanged: one that
    #: rebuilds entries from a fixed column list refuses every sign-in after the upgrade, which
    #: is the safe failure. Not secret, but not logged either, which is why it is left out of
    #: ``repr()`` (§12.8 rule 1 (e)): a store that logs ``repr(entry)`` must not emit it.
    binding_digest: str | None = field(default=None, repr=False)


class OidcStateStore(Protocol):
    """Optional server-side store for in-flight ``oidc_begin`` state
    (CONTRACT.md §12.3 rule 1).

    Implement this to back the login/callback handlers with your own
    storage (Redis, a database, an encrypted cookie). Two invariants are
    normative:

    1. **Single-use.** :meth:`consume` MUST return the entry *and delete it
       atomically*, so a replayed callback cannot reuse a ``state``.
    2. **Expiry.** An entry older than 10 minutes MUST NOT be returned.
    """

    def save(self, entry: OidcStateEntry) -> None:
        """Persist ``entry``, keyed by its ``state``, starting its TTL now."""
        ...

    def consume(self, state: str) -> OidcStateEntry | None:
        """Atomically fetch **and remove** the entry for ``state``.

        Returns ``None`` when the state is unknown, already consumed, or
        expired — three cases a caller MUST treat identically (as a failed
        login), because distinguishing them leaks whether a ``state`` ever
        existed.
        """
        ...


class MemoryOidcStateStore:
    """In-memory reference implementation of :class:`OidcStateStore`
    (CONTRACT.md §12.3 rule 1).

    Per-instance (never process-global), single-use, 10-minute TTL. Expired
    entries are dropped lazily on :meth:`consume` and swept opportunistically
    on :meth:`save` — no background thread/timer is held, since a library
    must not keep the host process alive (port-brief-addendum item 8).

    Bounded (``max_entries``, 10 000 by default): the oldest entry is evicted first.

    Suitable for a single-process app and for tests. A multi-instance
    deployment needs a shared store (Redis, database) — implement
    :class:`OidcStateStore` yourself for that; nothing in the SDK assumes
    this class.

    Thread-safe: guarded by a single ``threading.Lock`` so concurrent sync
    and async (via ``asyncio``'s default single-threaded event loop, or a
    thread-pool-offloaded call) callers never corrupt the underlying dict.
    """

    def __init__(
        self,
        ttl_seconds: float = OIDC_STATE_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        """Build an empty store.

        Args:
            ttl_seconds: Entry lifetime in seconds. Defaults to
                :data:`OIDC_STATE_TTL_SECONDS` (10 minutes) and is
                **clamped to it**: a shorter TTL is honored (useful in
                tests), a longer one is reduced, because CONTRACT.md §12.3
                rule 1 fixes 10 minutes as the maximum.
            max_entries: Most entries held at once (default
                :data:`DEFAULT_MAX_ENTRIES`). Beyond it the oldest entry is evicted
                first; an evicted login simply fails at its callback and restarts.
        """
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._ttl_seconds = min(ttl_seconds, OIDC_STATE_TTL_SECONDS)
        self._max_entries = max_entries
        # Insertion-ordered: re-saving a state moves it to the newest position.
        self._entries: dict[str, tuple[OidcStateEntry, float]] = {}
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        """Number of unexpired entries currently held (tests/metrics)."""
        with self._lock:
            self._sweep_locked()
            return len(self._entries)

    def save(self, entry: OidcStateEntry) -> None:
        """Persist ``entry`` under its own ``state``, expiring
        ``ttl_seconds`` from now."""
        with self._lock:
            self._sweep_locked()
            self._entries.pop(entry.state, None)
            self._entries[entry.state] = (entry, time.monotonic() + self._ttl_seconds)
            while len(self._entries) > self._max_entries:
                del self._entries[next(iter(self._entries))]

    def consume(self, state: str) -> OidcStateEntry | None:
        """Atomically return and delete the entry for ``state``.

        Deletion happens before the expiry check, so even an expired hit is
        removed rather than left to accumulate, and a second call can never
        return the same entry twice.
        """
        with self._lock:
            held = self._entries.pop(state, None)
            if held is None:
                return None
            entry, expires_at = held
            if expires_at <= time.monotonic():
                return None
            return entry

    def _sweep_locked(self) -> None:
        """Drop every expired entry. Caller MUST already hold ``self._lock``.
        Lazy housekeeping — no background timer."""
        now = time.monotonic()
        expired = [
            state for state, (_entry, expires_at) in self._entries.items() if expires_at <= now
        ]
        for state in expired:
            del self._entries[state]
