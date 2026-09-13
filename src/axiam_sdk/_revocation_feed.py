"""CONTRACT.md §10.4 — the optional session-revocation feed poller
(contract 1.44; AXIAM threats T-39 and T-143).

What this narrows, and what it is not
-------------------------------------

An AXIAM access token is self-contained and valid for up to fifteen minutes,
and :meth:`~axiam_sdk._jwks.JwksVerifier.verify_access_token` verifies it
locally. A logout, a role removal or an account disable therefore does not
reach a token already in a caller's hands until it expires — §10.2 records
that, and the documented answer has been "route the decision through gRPC
introspection instead", which is correct and costs a round trip **per
request**.

A deployment may publish ``GET /oauth2/revocations``: the base64url-unpadded
SHA-256 of every session id revoked within the last access-token lifetime. A
guard that polls it rejects a revoked session within **one poll interval**
instead, for one cacheable fetch per interval.

It is **not a control**, and every rule below follows from that:

* **Default off.** Nothing polls unless a caller attaches one.
* **Never on the request path.** :meth:`RevocationFeed.is_revoked` answers from
  the cached set; once warm, a stale cache is refreshed and the answer still
  comes from what is currently held.
* **Never fail closed.** An unreachable feed, a non-200, a body that does not
  parse, an ``alg`` this build does not know — every one behaves exactly as no
  feed at all. Not as an empty list: an empty list asserts that nothing has
  been revoked, which is a guard silently honouring no revocations while
  appearing to honour them.
* **It only ever rejects.** Every §10.1 rule runs first and still decides.
* **A token with no ``sid`` is never matched.** There is no session behind a
  client-credentials token, an RPT or a token exchange, and hashing ``jti``
  instead would match nothing while looking like it worked.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from typing import Any

import httpx

__all__ = [
    "DEFAULT_POLL_INTERVAL_SECONDS",
    "MAX_ENTRIES",
    "MIN_POLL_INTERVAL_SECONDS",
    "REVOCATION_FEED_PATH",
    "RevocationFeed",
]

#: Where the feed is published, relative to the AXIAM base URL.
REVOCATION_FEED_PATH = "/oauth2/revocations"

#: The only digest the feed publishes, and the only one this poller accepts.
#:
#: A document naming anything else is treated as unusable — exactly as an
#: unreachable feed is — rather than as a list of entries that happen not to
#: match. Silently matching nothing is how a guard ends up reporting that it
#: honours revocations while honouring none.
_SUPPORTED_ALG = "SHA-256"

#: The shortest interval a caller may configure (§10.4 rule 2).
#:
#: Bounded because the feed is one deployment-wide document and a fleet of
#: guards polling it ten times a second is a load source rather than a security
#: improvement. Applied by clamping, not by refusing: a caller who asked for
#: something faster gets the fastest thing on offer.
MIN_POLL_INTERVAL_SECONDS = 15.0

#: The default interval, and the one §10.4 recommends.
DEFAULT_POLL_INTERVAL_SECONDS = 30.0

#: The largest number of entries kept in the cache (§10.4 rule 2).
#:
#: The server bounds the document by its own revocation rate over one token
#: lifetime, so this is defence against a server that stops doing so — a cache
#: with no ceiling is an allocation an unauthenticated endpoint controls.
#: Overflow drops the **whole** set rather than truncating it: a truncated set
#: is a guard that admits some revoked sessions and reports none, which is
#: worse than one that admits all of them and says the feed is unusable.
MAX_ENTRIES = 100_000


def revocation_entry_for(sid: str) -> str:
    """The feed entry for a ``sid``, as the server computes it.

    Base64url without padding over the claim's **exact string** — never a
    parsed and re-rendered UUID, or the answer depends on this SDK's parser
    rather than on the feed.
    """
    digest = hashlib.sha256(sid.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class RevocationFeed:
    """A poller for one deployment's revocation feed.

    Share one instance across the guards that should poll once between them,
    rather than once each. Thread-safe.
    """

    def __init__(
        self,
        base_url: str,
        *,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        client: httpx.Client | None = None,
        now: Any = time.monotonic,
    ) -> None:
        """Build a poller against ``{base_url}/oauth2/revocations``.

        Args:
            base_url: The AXIAM server's base URL;
                :data:`REVOCATION_FEED_PATH` is appended after stripping any
                trailing slash.
            poll_interval_seconds: How often a guard's first call after this
                many seconds refetches the document. Raised to
                :data:`MIN_POLL_INTERVAL_SECONDS` if lower — the server caches
                the feed for that long, so polling faster costs requests and
                buys no freshness.
            client: An ``httpx.Client`` to fetch through, for callers that
                pin a transport, a proxy or a CA bundle. A per-call client
                with a bounded timeout is used when omitted.
            now: The monotonic clock, injected so tests can pin staleness
                without sleeping.
        """
        self._feed_url = base_url.rstrip("/") + REVOCATION_FEED_PATH
        self._poll_interval = max(poll_interval_seconds, MIN_POLL_INTERVAL_SECONDS)
        self._client = client
        self._now = now
        # ``None`` means "never successfully fetched", which is NOT the same as
        # an empty set — and is why this is not a bare ``set``.
        self._entries: set[str] | None = None
        self._last_attempt: float | None = None
        self._lock = threading.Lock()

    def is_revoked(self, sid: str) -> bool:
        """Has this session been revoked, as far as this poller knows?

        ``False`` whenever the answer is not a confident yes — a feed never
        fetched, unreachable, malformed, or simply not listing this session.
        The caller admits the request in all of those cases, which is §10.4
        rule 3 and is the whole reason the feature is safe to turn on.
        """
        self._refresh_if_stale()
        with self._lock:
            entries = self._entries
        return entries is not None and revocation_entry_for(sid) in entries

    def refresh(self) -> None:
        """Fetch now, whatever the interval says. For tests, and for warming."""
        fetched = self._fetch_once()
        with self._lock:
            self._last_attempt = self._now()
            if fetched is not None:
                self._entries = fetched
            # On failure the previous set is deliberately left in place: a blip
            # must not un-revoke a session the guard already knows about.

    def _refresh_if_stale(self) -> None:
        """Refetch if the poll interval has elapsed since the last *attempt*.

        Attempt, not success: a feed that is down must not be retried on every
        request, which would put the request path back on the network — the
        cost §10.4 exists to avoid.
        """
        with self._lock:
            last = self._last_attempt
            due = last is None or (self._now() - last) >= self._poll_interval
        if due:
            self.refresh()

    def _fetch_once(self) -> set[str] | None:
        """One fetch. ``None`` for every kind of failure, which the caller
        treats identically — see the module docstring on why "unusable" must
        not collapse into "empty"."""
        try:
            if self._client is not None:
                response = self._client.get(self._feed_url)
            else:
                response = httpx.get(self._feed_url, timeout=5.0)
            if response.status_code != 200:
                return None
            document = response.json()
        except Exception:
            return None
        if not isinstance(document, dict):
            return None
        if document.get("alg") != _SUPPORTED_ALG:
            return None
        revoked = document.get("revoked")
        if not isinstance(revoked, list) or len(revoked) > MAX_ENTRIES:
            return None
        return {entry for entry in revoked if isinstance(entry, str)}
