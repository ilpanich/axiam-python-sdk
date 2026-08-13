"""Shared, transport-agnostic OIDC/SSO relying-party logic (CONTRACT.md §12).

``_OidcMixin`` holds every part of the nine §12 operations that does NOT
touch the network: request/form-body building, response parsing, the
discovery cache, PKCE/state/nonce generation (``oidc_begin`` performs no I/O
at all), ID-token validation orchestration, and tenant/client-credential
resolution. :class:`~axiam_sdk._client.AxiamClient` and
:class:`~axiam_sdk._async_client.AsyncAxiamClient` each add only the actual
``httpx`` send call around these helpers — mirrors the existing
``_login_body``/``_handle_login_response`` split in ``_client.py``, so sync
and async never duplicate logic (CONTRACT.md §12 "MUST be built on the SDK's
existing machinery ... No SDK may fork, duplicate, or re-implement any of
them for §12").

Reuse, not reimplementation:

* transport + §2 error mapping + §3 CSRF + §4 cookie jar + §5 tenant header
  + §6 TLS -> the existing ``_Session`` (``_session.py``);
* §7/§12.5 redaction -> ``pydantic.SecretStr`` (already this SDK's
  ``Sensitive`` equivalent);
* §9 single-flight refresh -> ``RefreshGuard.run_exclusive_sync/async``
  (``token/refresh_guard.py``), extended (never forked) for §12;
* §12.4 signature verification -> ``_jwks.JwksVerifier``, extended (never
  forked) via its new public ``get_signing_key`` method.
"""

from __future__ import annotations

import asyncio
import re
import threading
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from pydantic import SecretStr

from axiam_sdk._errors import (
    AuthError,
    NetworkError,
    OAuthProtocolError,
    error_from_http_status,
    error_from_oauth2_response,
)
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk._models import (
    AuthorizationRequest,
    DeviceAuthorization,
    ExchangedToken,
    IntrospectionResult,
    OidcConfiguration,
    OidcTokenSet,
    RequestingPartyToken,
    ResourceSet,
    SsoCompleteResult,
    SsoStartResult,
    UmaChallenge,
    VerifiedLogoutToken,
)
from axiam_sdk._oidc_idtoken import validate_id_token
from axiam_sdk._oidc_pkce import (
    CODE_CHALLENGE_METHOD_S256,
    compute_code_challenge,
    generate_code_verifier,
    random_url_safe_token,
)

if TYPE_CHECKING:
    import logging

    from axiam_sdk._session import _Session

#: Path of the OIDC discovery document, relative to the client base URL.
DISCOVERY_PATH = "/.well-known/openid-configuration"

#: Path of the federation SSO step-1 endpoint.
SSO_START_PATH = "/api/v1/auth/federation/oidc/start"

#: Path of the federation SSO step-2 (callback) endpoint.
SSO_CALLBACK_PATH = "/api/v1/auth/federation/oidc/callback"

#: Minimum — and default — discovery-cache TTL. CONTRACT.md §12.3 rule 6
#: sets a floor of 5 minutes; a smaller configured value is raised to it.
MIN_DISCOVERY_TTL_SECONDS = 300.0

DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
"""``grant_type`` of the device access-token request (RFC 8628 §3.4)."""

DEFAULT_POLL_INTERVAL_SECONDS = 5
"""Polling interval used when the authorization response omits ``interval``
(RFC 8628 §3.2, §14.2 rule 2). An SDK MUST NOT hard-code a faster floor."""

SLOW_DOWN_INCREMENT_SECONDS = 5
"""Seconds added to the polling interval on each ``slow_down`` (§14.2
rule 1). The increase is permanent and cumulative."""

TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
"""``grant_type`` of an RFC 8693 exchange."""

ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
"""The ``actor_token_type`` this SDK sends, and the ``subject_token_type`` a
caller names for the same-domain exchange of §15.1.

There is no default: the type is a **required** argument of ``token_exchange``.
"""

JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
"""A JWT from a trusted external issuer — the cross-domain exchange of §15.7.

Pass it as ``subject_token_type`` to exchange a partner IdP's token. AXIAM also
accepts :data:`ACCESS_TOKEN_TYPE` for an external issuer, and refuses refresh
and ID token types **by name**.
"""

UMA_TICKET_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:uma-ticket"
"""``grant_type`` of the UMA ticket grant (UMA 2.0 §3.3.1, CONTRACT.md §20.1)."""

UMA_PROTECTION_SCOPE = "uma_protection"
"""The scope that makes an access token a Protection API Token (§20.2 rule 1)."""

UMA_CLAIM_TOKEN_FORMAT = "urn:ietf:params:oauth:token-type:access_token"
"""The only ``claim_token_format`` AXIAM v1 accepts (§20.2 rule 2)."""


def uma_parse_challenge(header: str) -> UmaChallenge | None:
    """Parse a ``WWW-Authenticate: UMA …`` header value (CONTRACT.md §20.3).

    **This deliberately does not exchange the ticket.** Parsing a challenge and
    acting on it are separate decisions: the ``as_uri`` names an authorization
    server the caller has not necessarily chosen to trust, and auto-exchanging
    would send the requesting party's ``claim_token`` to whatever host answered
    the 403. The caller decides.

    Returns ``None`` when the header is not a UMA challenge.
    """
    trimmed = header.strip()
    if not trimmed.startswith("UMA"):
        return None
    rest = trimmed[3:]
    # "UMA" alone is a valid, if useless, challenge; anything else must be
    # separated by whitespace so `UMAX realm="…"` is not read as UMA.
    if rest and not rest[0].isspace():
        return None

    fields: dict[str, str] = {}
    for part in rest.split(","):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        fields[key.strip()] = value.strip().strip('"')

    ticket = fields.get("ticket")
    return UmaChallenge(
        realm=fields.get("realm"),
        as_uri=fields.get("as_uri"),
        ticket=SecretStr(ticket) if ticket is not None else None,
    )


def uma_challenge_header(realm: str, as_uri: str, ticket: SecretStr | str) -> str:
    """Format a ``WWW-Authenticate: UMA`` header value (§20.3, emit half).

    The resource-server side: having obtained a ticket from
    ``uma_request_ticket``, tell the caller where to redeem it.
    """
    return f'UMA realm="{realm}", as_uri="{as_uri}", ticket="{_expose_secret(ticket)}"'


@dataclass(frozen=True)
class UmaChallenger:
    """A configured ``WWW-Authenticate: UMA`` challenge emitter (§20.3, emit half).

    Hand one to :func:`axiam_sdk.fastapi.require_access` (or Django's
    ``@require_access``) and a denial stops being a bare 403: the guard mints a
    fresh permission ticket for the pairs the caller lacked and returns it in
    the header, so a UMA-aware client knows where to go for authority instead of
    only being told "no".

    **Opt-in, and deliberately so.** Emitting a challenge means minting a
    credential — a wire call to the Protection API, and a live ticket, produced
    on a path the caller did not explicitly request. A guard that did that on
    every denial by default would turn each unauthorized request into a
    Protection API call, which is a denial-of-service amplifier pointed at your
    own authorization server.

    **Failure is not escalation.** If minting fails — the PAT expired, the
    Protection API is down, the resource declares none of the requested scopes —
    the denial still surfaces as an ordinary 403 without a challenge. A caller
    who was going to be refused is refused either way; letting a Protection API
    outage turn a deny into a 500 would hand the outage a second consequence,
    and letting it turn into an allow would be a security bug.

    :param realm: The protection realm to name in the header.
    :param as_uri: The authorization server to send the caller to — normally
        this deployment's issuer, read from discovery rather than concatenated
        by hand.
    :param pat: A Protection API Token: a *client-credentials* token carrying
        the ``uma_protection`` scope (§20.2 rule 1). A user token cannot stand
        in — a minted ticket is bound to the ``client_id`` that minted it.
    :param client: The client whose ``uma_request_ticket`` mints the ticket.
        Async guards need the async client; sync guards the sync one.
    """

    realm: str
    as_uri: str
    pat: SecretStr | str
    client: Any


BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
"""The ``events`` member that distinguishes a logout token from an ID token
(OIDC Back-Channel Logout 1.0 §2.4)."""

MAX_LOGOUT_TOKEN_AGE_SECONDS = 300
"""Maximum accepted age for a logout token's ``iat``. AXIAM issues them with
a 120 s lifetime; this bound is the same order and stops a token captured
from a mis-configured RP being replayed days later."""


class PollSchedule:
    """The §14.2 polling schedule: the interval, and the deadline it stops at.

    A plain value object with no I/O, so the arithmetic §14.2 rules 1, 2 and 4
    describe can be tested exhaustively and instantly. Driving that arithmetic
    through a mock HTTP server would test ``httpx`` and a sleeping event loop
    rather than the rule, and would take a real half-minute to assert one
    ``slow_down``.
    """

    def __init__(self, interval_seconds: int, expires_in_seconds: int) -> None:
        """Build from a ``DeviceAuthorization``'s ``interval``/``expires_in``."""
        self._interval = interval_seconds if interval_seconds > 0 else DEFAULT_POLL_INTERVAL_SECONDS
        self._remaining = expires_in_seconds

    @property
    def interval_seconds(self) -> int:
        """The current inter-poll delay, in seconds."""
        return self._interval

    def slow_down(self) -> None:
        """Apply one ``slow_down`` (§14.2 rule 1): **cumulative, never reset.**"""
        self._interval += SLOW_DOWN_INCREMENT_SECONDS

    def tick(self) -> bool:
        """Consume one interval's worth of the grant's remaining life.

        Returns:
            ``False`` when the deadline has been reached, at which point the
            caller MUST stop (§14.2 rule 4) — the deadline is authoritative
            even if the server is still answering ``authorization_pending``.
        """
        if self._interval >= self._remaining:
            self._remaining = 0
            return False
        self._remaining -= self._interval
        return True


#: The ``openid`` scope, which every authorization request must carry
#: (§12.1 rule 4).
_OPENID_SCOPE = "openid"

#: The eight query parameters ``oidc_begin`` owns (§12.1 rule 5).
#: Caller-supplied ``extra_params`` may add to the authorization request but
#: never override these.
_RESERVED_AUTHORIZE_PARAMS = frozenset(
    {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    }
)

#: Shape of a UUID, used to reject a slug where §12.3 rule 4 requires a UUID.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def normalize_origin(url: str) -> str:
    """Normalize a URL to its discovery-cache key: lowercased scheme and
    host with the port always explicit (CONTRACT.md §12.3 rule 6).

    ``https://IAM.example.com/`` and ``https://iam.example.com:443/x``
    therefore share one key, while ``http://iam.example.com`` gets its own.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    default_port = "443" if scheme == "https" else "80" if scheme == "http" else ""
    port = str(parts.port) if parts.port is not None else default_port
    return f"{scheme}://{host}:{port}"


def _expose_secret(value: SecretStr | str) -> str:
    """Read a secret that the caller may have supplied wrapped or bare
    (port-brief-addendum item 6)."""
    return value.get_secret_value() if isinstance(value, SecretStr) else value


def _normalize_scope(scope: str | Sequence[str] | None) -> str:
    """Normalize the requested scope to a space-separated string that always
    contains ``openid`` (§12.1 rule 4 — the helper adds it when the caller
    omits it). Duplicate entries are collapsed so ``"openid openid
    profile"`` cannot be produced."""
    if scope is None:
        requested: Sequence[str] = []
    elif isinstance(scope, str):
        requested = scope.split(" ")
    else:
        requested = scope
    values = [value.strip() for value in requested if value.strip()]
    if _OPENID_SCOPE not in values:
        values.insert(0, _OPENID_SCOPE)
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return " ".join(deduped)


def _append_query(endpoint: str, params: dict[str, str]) -> str:
    """Append ``params`` to ``endpoint`` as RFC 3986-percent-encoded query
    parameters (§12.1 rule 5), preserving any existing query string.

    ``urllib.parse.quote`` (not ``quote_plus``) is used deliberately: it
    percent-encodes a space as ``%20``, not ``+`` (port-brief-addendum
    item 10).
    """
    parts = urlsplit(endpoint)
    new_query = "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in params.items())
    combined = f"{parts.query}&{new_query}" if parts.query else new_query
    return urlunsplit((parts.scheme, parts.netloc, parts.path, combined, parts.fragment))


class _DiscoveryCache:
    """Origin-keyed discovery cache with single-flight fetching (CONTRACT.md
    §12.3 rule 6).

    The key is the **normalized scheme + host + port** of the base URL the
    document was fetched from, so a document fetched from one origin can
    never be served for another (cross-issuer cache poisoning). The cache is
    per-client-instance (never process-global) and is not keyed on, or
    shared across, tenants.

    Single-flight is achieved by holding the relevant lock across the
    ENTIRE fetch (mirrors ``RefreshGuard``'s own double-check-after-lock
    idiom): any concurrent caller against the same cache instance blocks
    until the in-progress fetch completes, then reads the now-populated
    cache instead of re-fetching. A client only ever exercises ONE of
    :meth:`get_sync`/:meth:`get_async` (a sync ``AxiamClient`` never calls
    the async path and vice versa), but both share ``self._documents`` so
    either path benefits from whatever the other has already cached.
    """

    def __init__(self, ttl_seconds: float) -> None:
        """Build a cache with the given TTL, floored at
        :data:`MIN_DISCOVERY_TTL_SECONDS` (§12.3 rule 6)."""
        self._ttl = max(ttl_seconds, MIN_DISCOVERY_TTL_SECONDS)
        self._documents: dict[str, tuple[OidcConfiguration, float]] = {}
        self._sync_lock = threading.Lock()
        self._async_lock = asyncio.Lock()

    def _fresh(self, origin_key: str) -> OidcConfiguration | None:
        """Return the cached document for ``origin_key`` if it exists and
        has not yet expired, else ``None``."""
        cached = self._documents.get(origin_key)
        if cached is not None and cached[1] > time.monotonic():
            return cached[0]
        return None

    def get_sync(
        self, origin_key: str, fetch: Callable[[], OidcConfiguration]
    ) -> OidcConfiguration:
        """Sync single-flight lookup: fetch and cache ``origin_key``'s
        discovery document, or return the cached one when still fresh."""
        fresh = self._fresh(origin_key)
        if fresh is not None:
            return fresh
        with self._sync_lock:
            fresh = self._fresh(origin_key)
            if fresh is not None:
                return fresh
            document = fetch()
            self._documents[origin_key] = (document, time.monotonic() + self._ttl)
            return document

    async def get_async(
        self, origin_key: str, fetch: Callable[[], Awaitable[OidcConfiguration]]
    ) -> OidcConfiguration:
        """Async twin of :meth:`get_sync`."""
        fresh = self._fresh(origin_key)
        if fresh is not None:
            return fresh
        async with self._async_lock:
            fresh = self._fresh(origin_key)
            if fresh is not None:
                return fresh
            document = await fetch()
            self._documents[origin_key] = (document, time.monotonic() + self._ttl)
            return document


class _SyncFlight:
    """One sync ``oidc_refresh`` attempt's **publication** — the object a
    waiter joins, holds, and reads its outcome from (CONTRACT.md §9 rule 6).

    The in-flight slot is a *result-sharing channel, not a busy flag*: each
    attempt gets its own publication, and a waiter that joined this attempt
    blocks on **this** object's event and reads **this** object's outcome.
    That is what makes rule 6b hold on the waiter side — a waiter asks "has
    the attempt I joined settled?" (:meth:`is_settled`), never "is the
    coalescer's slot occupied?", so a *newer* attempt occupying the slot can
    never be misread by a lagging waiter as "my own refresh is still on the
    wire" (which would hand it a different burst's outcome, breaking §9
    rule 2).
    """

    __slots__ = ("_settled", "exc", "result")

    def __init__(self) -> None:
        """Build an unsettled publication with no outcome yet."""
        self._settled = threading.Event()
        self.result: Any = None
        self.exc: BaseException | None = None

    def publish(self, *, result: Any = None, exc: BaseException | None = None) -> None:
        """Make this attempt's outcome observable to every joined waiter.

        The fields are assigned *before* the event is set, so a waiter
        released by the event can never read a half-written outcome.
        """
        self.result = result
        self.exc = exc
        self._settled.set()

    def is_settled(self) -> bool:
        """Whether this attempt has published its outcome (rule 6b: this —
        not slot occupancy — is the liveness test for *this* attempt)."""
        return self._settled.is_set()

    def outcome(self) -> Any:
        """Block until this attempt publishes, then return its result or
        re-raise its exception **as-is** (§9.3: no retry, ever)."""
        self._settled.wait()
        if self.exc is not None:
            raise self.exc
        return self.result


class _SyncSingleFlight:
    """Collapse N concurrent sync callers of an operation into exactly one
    real invocation, all sharing its result/exception — the request-
    coalescing half of ``oidc_refresh``'s two-part single-flight behavior
    (port-brief-addendum item 14): "de-duplicates its own concurrent
    callers AND runs the wire call inside the existing §9 guard." This
    class provides the de-duplication; :meth:`RefreshGuard.run_exclusive_sync
    <axiam_sdk.token.refresh_guard.RefreshGuard.run_exclusive_sync>` (called
    by the ONE selected caller's ``fn``) provides the "inside the existing
    §9 guard" half, so an ``oidc_refresh`` and a concurrent cookie-session
    ``refresh()`` still cannot interleave.

    **Rule 6 invariants (CONTRACT.md §9 rule 6, contract 1.6) — do not
    regress these:**

    * **(6a) publish-before-vacate** — :meth:`_publish_then_vacate` sets the
      attempt's publication *first* and clears the slot *second*, so a
      caller can only ever find the slot (i) occupied by a live attempt (it
      joins and waits), (ii) occupied by an already-settled attempt (it
      joins and gets that outcome immediately, with **no** second wire
      call), or (iii) empty — which now means "the previous attempt settled
      *and published*", so leading a fresh attempt is correct. The fourth,
      forbidden state — *empty with nothing published* — is unreachable,
      and that is the state that would let a second caller replay an
      already-consumed single-use refresh token.
    * **(6b) occupancy is not liveness** — waiters block on their own
      :class:`_SyncFlight`, so slot occupancy is never used as a proxy for
      "my refresh is still on the wire".
    * **(6c) only the owner vacates** — the clear is identity-checked
      (``self._in_flight is flight``), so an attempt unwinding late (a
      failure, or a signal delivered during teardown) can never clear a
      *newer* attempt's entry.
    * **(6d) late callers lead** — once the slot is vacated, the next caller
      finds it empty and performs its own new wire call; a settled
      publication is never retained as a one-entry cache.
    """

    def __init__(self) -> None:
        """Build an idle single-flight coalescer with no call in progress."""
        self._lock = threading.Lock()
        self._in_flight: _SyncFlight | None = None
        # Test-only seam: invoked inside the publish -> vacate window so a
        # test can deterministically land a caller there (rule 6a). NEVER
        # set in production — nothing in the SDK assigns it.
        self._after_publish: Callable[[], None] | None = None

    def run(self, fn: Callable[[], Any]) -> Any:
        """Run ``fn()`` exactly once across any number of concurrent
        callers; every other concurrent caller blocks and then receives the
        same result or re-raises the same exception."""
        with self._lock:
            joined = self._in_flight
            if joined is None:
                mine = _SyncFlight()
                self._in_flight = mine

        if joined is not None:
            # Waiter: wait on the publication we joined — never on the slot.
            return joined.outcome()

        try:
            result = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised to every waiter as-is
            self._publish_then_vacate(mine, exc=exc)
            raise

        self._publish_then_vacate(mine, result=result)
        return result

    def _publish_then_vacate(
        self, flight: _SyncFlight, *, result: Any = None, exc: BaseException | None = None
    ) -> None:
        """Publish ``flight``'s outcome, then release the slot — in that
        order (rule 6a), clearing only our own entry (rule 6c)."""
        flight.publish(result=result, exc=exc)
        if self._after_publish is not None:
            self._after_publish()
        with self._lock:
            if self._in_flight is flight:
                self._in_flight = None


class _AsyncSingleFlight:
    """Async twin of :class:`_SyncSingleFlight`.

    The in-flight slot holds one :class:`asyncio.Task` per burst — the
    "shared future/promise" mechanism §9 rule 5 permits — and **every**
    participant, the caller that created it included, joins it through
    :func:`asyncio.shield`. Electing a leader is a single synchronous step
    (:meth:`_claim_or_join`, no ``await`` inside), so asyncio's cooperative
    scheduling makes the check-then-claim atomic and two callers can never
    both start a wire call.

    **Rule 6 invariants (CONTRACT.md §9 rule 6, contract 1.6) — do not
    regress these:**

    * **(6a) publish-before-vacate** — the outcome *is* the task, so it is
      observable the instant the task completes; the slot is cleared by
      :meth:`_vacate`, a **done callback** on that same task, which by
      construction cannot run before the task has settled. The forbidden
      "slot empty, nothing published" instant is therefore structurally
      unreachable — there is no ordering left to get wrong. (The previous
      implementation did the opposite: it cleared ``_pending`` and *then*
      called ``set_result``/``set_exception`` on a bare future — the exact
      shape of the Go bug, and reachable in practice because a joining
      caller's cancellation could make the publication step fail outright.)
    * **(6b) occupancy is not liveness** — a task in the slot may already be
      done (the bookkeeping window before its done callback runs); a caller
      landing there joins that settled outcome instead of starting a second
      wire call. A *cancelled* task, conversely, will never publish
      anything, so it is treated as **absent** and the arriving caller leads
      a fresh attempt rather than inheriting a spurious
      :exc:`asyncio.CancelledError`.
    * **(6c) only the owner vacates** — :meth:`_vacate` clears the slot only
      when it still holds the very task it was attached to, so a task
      unwinding after a newer leader has claimed the slot cannot clear the
      newer one's entry.
    * **(6d) late callers lead** — once vacated, the next caller finds the
      slot empty and performs its own new wire call.

    Cancellation (rule 6c's main source in asyncio): every participant awaits
    ``asyncio.shield(task)``, so cancelling *any* caller — the one that
    created the task included — cancels only that caller's await. The shared
    wire call is never torn down under the other participants, and the
    publication can never be destroyed by a joiner (awaiting a bare
    ``Future`` directly, as the previous implementation did, let a cancelled
    joiner cancel the *shared* future: its waiters got a spurious
    ``CancelledError`` and the leader's own ``set_result`` raised
    ``InvalidStateError``, losing an already-rotated token set).
    """

    def __init__(self) -> None:
        """Build an idle single-flight coalescer with no call in progress."""
        self._pending: asyncio.Task[Any] | None = None
        # Test-only seam: invoked inside the publish -> vacate window so a
        # test can deterministically land a caller there (rule 6a). NEVER
        # set in production — nothing in the SDK assigns it.
        self._after_publish: Callable[[], None] | None = None

    def _claim_or_join(self, fn: Callable[[], Awaitable[Any]]) -> asyncio.Task[Any]:
        """Elect this caller a leader or a waiter and return the task
        carrying this burst's single wire call.

        Fully synchronous — there is no ``await`` between reading the slot
        and claiming it, which is what makes the election atomic under
        asyncio's cooperative scheduling (§9 rule 4).
        """
        task = self._pending
        if task is not None and not task.cancelled():
            # Live, or settled-but-not-yet-vacated: join it either way
            # (rules 6a/6b). A cancelled task publishes nothing, so it does
            # not qualify and this caller leads instead.
            return task
        task = asyncio.ensure_future(fn())
        self._pending = task
        # Chaining the clear onto the task itself is what orders publication
        # before vacating (rule 6a) — a done callback cannot run earlier.
        task.add_done_callback(self._vacate)
        return task

    def _vacate(self, task: asyncio.Task[Any]) -> None:
        """Release the slot once ``task`` has settled — clearing it only if
        it is still *our* entry (rule 6c)."""
        if not task.cancelled():
            # Mark a failure as retrieved: every participant re-raises it
            # from its own ``shield``, but a burst whose callers all went
            # away must not log "exception was never retrieved".
            task.exception()
        if self._after_publish is not None:
            self._after_publish()
        if self._pending is task:
            self._pending = None

    async def run(self, fn: Callable[[], Awaitable[Any]]) -> Any:
        """Async twin of :meth:`_SyncSingleFlight.run`."""
        return await asyncio.shield(self._claim_or_join(fn))


class _OidcMixin:
    """Shared OIDC/SSO logic mixed into
    :class:`~axiam_sdk._client._AxiamClientBase` (CONTRACT.md §12).

    Data attributes below are declared (not assigned) here for ``mypy
    --strict``'s benefit — they are actually initialized by
    :meth:`_init_oidc` and (for ``_session``/``_logger``/tenant-context
    attributes) by ``_AxiamClientBase.__init__`` itself, since a mixin's own
    ``__init__`` is never called directly (multiple inheritance runs
    ``_AxiamClientBase.__init__`` only).
    """

    _session: _Session
    _logger: logging.Logger
    _oidc_client_id: str | None
    _oidc_client_secret: SecretStr | None
    _oidc_discovery_ttl_seconds: float
    _oidc_clock_skew_sec: float | None
    _resolved_tenant_id: str | None
    _org_slug: str | None

    def _init_oidc(
        self,
        *,
        client_id: str | None,
        client_secret: str | SecretStr | None,
        discovery_ttl_seconds: float | None,
        clock_skew_sec: float | None,
    ) -> None:
        """Initialize the OIDC-specific instance state (CONTRACT.md §12).

        Called once from ``_AxiamClientBase.__init__`` — a mixin has no
        ``__init__`` of its own that multiple inheritance would invoke.
        """
        self._oidc_client_id = client_id
        self._oidc_client_secret = (
            SecretStr(client_secret) if isinstance(client_secret, str) else client_secret
        )
        self._oidc_discovery_ttl_seconds = discovery_ttl_seconds or MIN_DISCOVERY_TTL_SECONDS
        self._oidc_clock_skew_sec = clock_skew_sec
        self._resolved_tenant_id = None
        self._discovery_cache = _DiscoveryCache(self._oidc_discovery_ttl_seconds)
        self._jwks_verifiers: dict[str, JwksVerifier] = {}
        self._oidc_refresh_single_flight_sync = _SyncSingleFlight()
        self._oidc_refresh_single_flight_async = _AsyncSingleFlight()

    # ------------------------------------------------------------------
    # Protocol stubs — provided by ``_AxiamClientBase`` (CONTRACT.md §5.1
    # org-context resolution and §4 post-login cookie-jar sync); declared
    # here only so ``mypy --strict`` can typecheck this mixin standalone.
    # ------------------------------------------------------------------

    def resolved_org_id(self) -> str | None:
        """Provided by ``_AxiamClientBase.resolved_org_id``."""
        raise NotImplementedError

    def _absorb_session_cookies(self) -> None:
        """Provided by ``_AxiamClientBase._absorb_session_cookies``."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # 1. oidc_discover
    # ------------------------------------------------------------------

    def _discovery_origin_key(self) -> str:
        """The cache key for this client's own base URL (§12.3 rule 6)."""
        return normalize_origin(self._session.base_url)

    def _parse_discovery_response(self, response: httpx.Response) -> OidcConfiguration:
        """Parse a ``GET /.well-known/openid-configuration`` response into
        a typed :class:`~axiam_sdk._models.OidcConfiguration`, raising the
        mapped taxonomy error on any non-2xx status."""
        if response.status_code != httpx.codes.OK:
            raise error_from_http_status(
                response.status_code, "oidc discovery request failed", response=response
            )
        return OidcConfiguration.model_validate(response.json())

    # ------------------------------------------------------------------
    # 2. oidc_begin — pure local computation, no network I/O (§12.1)
    # ------------------------------------------------------------------

    def _oidc_begin_impl(
        self,
        *,
        configuration: OidcConfiguration,
        redirect_uri: str,
        scope: str | Sequence[str] | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> AuthorizationRequest:
        """Build an :class:`~axiam_sdk._models.AuthorizationRequest`
        (CONTRACT.md §12.1) — pure local computation, no network I/O.

        Generates a 32-byte CSPRNG ``state`` and ``nonce`` (base64url,
        unpadded) and a fresh PKCE verifier/challenge pair using **S256
        only**. The URL is built from the discovery document's
        ``authorization_endpoint`` with exactly the eight parameters §12.1
        rule 5 mandates, plus any ``extra_params`` the caller adds.

        Nothing is stored: persist the returned ``state``, ``nonce``, and
        ``code_verifier`` yourself (§12.3 rule 1).

        Raises:
            AuthError: if no ``client_id`` was configured at construction
                time.
            ValueError: if ``extra_params`` tries to override one of the
                eight SDK-owned parameters (a programming error, per
                port-brief-addendum item 9 — deliberately NOT the auth-error
                taxonomy).
        """
        client_id = self._require_oidc_client_id()
        state = random_url_safe_token()
        nonce = random_url_safe_token()
        code_verifier = generate_code_verifier()
        code_challenge = compute_code_challenge(code_verifier)

        query: dict[str, str] = {}
        for key, value in (extra_params or {}).items():
            if key in _RESERVED_AUTHORIZE_PARAMS:
                raise ValueError(
                    f"oidc_begin: extra_params may not override the SDK-owned authorization "
                    f'parameter "{key}" (CONTRACT.md §12.1 rule 5).'
                )
            query[key] = value

        query["response_type"] = "code"
        query["client_id"] = client_id
        query["redirect_uri"] = redirect_uri
        query["scope"] = _normalize_scope(scope)
        query["state"] = state
        query["nonce"] = nonce
        query["code_challenge"] = code_challenge
        query["code_challenge_method"] = CODE_CHALLENGE_METHOD_S256

        url = _append_query(configuration.authorization_endpoint, query)
        return AuthorizationRequest(
            url=url, state=state, nonce=nonce, code_verifier=SecretStr(code_verifier)
        )

    # ------------------------------------------------------------------
    # 3-5. Token endpoint grants — form bodies + response parsing (shared)
    # ------------------------------------------------------------------

    def _exchange_form(
        self, *, code: str, code_verifier: SecretStr | str, redirect_uri: str
    ) -> dict[str, str]:
        """Build the ``grant_type=authorization_code`` form body (§12.1)."""
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": _expose_secret(code_verifier),
            "redirect_uri": redirect_uri,
            "client_id": self._require_oidc_client_id(),
        }
        self._append_client_secret(form)
        return form

    def _refresh_form(self, *, refresh_token: SecretStr | str, scope: str | None) -> dict[str, str]:
        """Build the ``grant_type=refresh_token`` form body (§12.1)."""
        form = {
            "grant_type": "refresh_token",
            "refresh_token": _expose_secret(refresh_token),
            "client_id": self._require_oidc_client_id(),
        }
        self._append_client_secret(form)
        if scope is not None:
            form["scope"] = scope
        return form

    def _client_credentials_form(self, *, scope: str | None) -> dict[str, str]:
        """Build the ``grant_type=client_credentials`` form body (§12.1)."""
        form = {
            "grant_type": "client_credentials",
            "client_id": self._require_oidc_client_id(),
            "client_secret": self._require_client_secret("login_client_credentials"),
        }
        if scope is not None:
            form["scope"] = scope
        return form

    def _introspect_form(
        self, *, token: SecretStr | str, token_type_hint: str | None
    ) -> dict[str, str]:
        """Build the RFC 7662 introspection form body (§12.1 note 4)."""
        form = {
            "token": _expose_secret(token),
            "client_id": self._require_oidc_client_id(),
            "client_secret": self._require_client_secret("introspect"),
        }
        if token_type_hint is not None:
            form["token_type_hint"] = token_type_hint
        return form

    def _revoke_form(
        self, *, token: SecretStr | str, token_type_hint: str | None
    ) -> dict[str, str]:
        """Build the RFC 7009 revocation form body (§12.1 note 4)."""
        form = {
            "token": _expose_secret(token),
            "client_id": self._require_oidc_client_id(),
            "client_secret": self._require_client_secret("revoke"),
        }
        if token_type_hint is not None:
            form["token_type_hint"] = token_type_hint
        return form

    def _token_endpoint_url(self, configuration: OidcConfiguration, tenant_id: str | None) -> str:
        """The token endpoint URL with the mandatory ``?tenant_id=<uuid>``
        query parameter (§12.1 note 2)."""
        return self._endpoint_url(configuration.token_endpoint, tenant_id)

    def _endpoint_url(self, endpoint: str, tenant_id: str | None) -> str:
        """Build the final endpoint URL: the discovery document's endpoint
        plus the mandatory ``?tenant_id=<uuid>`` query parameter (§12.1
        note 2). Existing query parameters on the endpoint are preserved."""
        resolved = self._resolve_oauth2_tenant_id(tenant_id)
        url = httpx.URL(endpoint)
        return str(url.copy_merge_params({"tenant_id": resolved}))

    def _handle_token_response(
        self,
        response: httpx.Response,
        configuration: OidcConfiguration,
        nonce: str | None,
    ) -> OidcTokenSet:
        """Parse ``POST /oauth2/token``'s response into an
        :class:`~axiam_sdk._models.OidcTokenSet`, validating any
        ``id_token`` first (§12.4).

        Validation precedes construction, so a failure discards the whole
        set — the caller never sees the access or refresh token from a
        response whose ID token was rejected (§12.4 rule 7). A non-2xx
        response is mapped via :func:`~axiam_sdk._errors.error_from_oauth2_response`
        (§12.3 rule 3) rather than the generic §2 mapping.
        """
        if response.status_code != httpx.codes.OK:
            raise error_from_oauth2_response(response.status_code, response, "token request failed")
        wire = response.json()
        return self._build_token_set(wire, configuration, nonce)

    def _build_token_set(
        self,
        wire: dict[str, Any],
        configuration: OidcConfiguration,
        nonce: str | None,
    ) -> OidcTokenSet:
        """Convert a raw ``TokenResponse`` JSON body into an
        :class:`~axiam_sdk._models.OidcTokenSet`, running the §12.4
        ID-token checklist first when the response carries an ``id_token``.
        """
        id_claims = None
        id_token = wire.get("id_token")
        if id_token:
            verifier = self._verifier_for(configuration.jwks_uri)
            id_claims = validate_id_token(
                id_token,
                verifier,
                issuer=configuration.issuer,
                client_id=self._require_oidc_client_id(),
                nonce=nonce,
                clock_skew_sec=self._oidc_clock_skew_sec,
            )

        return OidcTokenSet(
            access_token=SecretStr(wire["access_token"]),
            token_type=wire["token_type"],
            expires_in=wire["expires_in"],
            scope=wire.get("scope"),
            refresh_token=SecretStr(wire["refresh_token"]) if wire.get("refresh_token") else None,
            id_token=SecretStr(id_token) if id_token else None,
            id_claims=id_claims,
        )

    def _verifier_for(self, jwks_uri: str) -> JwksVerifier:
        """Lazily build (and reuse) the JWKS verifier for a ``jwks_uri``
        (§12.3 rule 6) — one verifier per URI, never process-global.

        Built against the discovery document's ``jwks_uri`` directly (the
        :class:`~axiam_sdk._jwks.JwksVerifier` ``jwks_url`` override), never
        a re-derived ``base_url + JWKS_PATH`` — the two may legitimately
        differ (§12.3 rule 6).
        """
        existing = self._jwks_verifiers.get(jwks_uri)
        if existing is not None:
            return existing
        verifier = JwksVerifier(jwks_uri, jwks_url=jwks_uri)
        self._jwks_verifiers[jwks_uri] = verifier
        return verifier

    # ------------------------------------------------------------------
    # 6-7. introspect / revoke — form bodies + response parsing (shared)
    # ------------------------------------------------------------------

    def _endpoint_url_for_introspect(
        self, configuration: OidcConfiguration, tenant_id: str | None
    ) -> str:
        """The introspection endpoint URL with the mandatory ``tenant_id``
        query parameter (§12.1 note 2)."""
        return self._endpoint_url(configuration.introspection_endpoint, tenant_id)

    def _endpoint_url_for_revoke(
        self, configuration: OidcConfiguration, tenant_id: str | None
    ) -> str:
        """The revocation endpoint URL with the mandatory ``tenant_id``
        query parameter (§12.1 note 2)."""
        return self._endpoint_url(configuration.revocation_endpoint, tenant_id)

    def _handle_introspect_response(self, response: httpx.Response) -> IntrospectionResult:
        """Parse ``POST /oauth2/introspect``'s response (§12.1 note 4)."""
        if response.status_code != httpx.codes.OK:
            raise error_from_oauth2_response(
                response.status_code, response, "introspect request failed"
            )
        return IntrospectionResult.model_validate(response.json())

    def _handle_revoke_response(self, response: httpx.Response) -> None:
        """Handle ``POST /oauth2/revoke``'s response.

        Per RFC 7009 the server answers ``200`` for unknown, expired, or
        already-revoked tokens alike, so revocation is **idempotent**: a
        ``200`` MUST be treated as success and no error is raised for a
        token the server has never seen. CONTRACT.md §12.1 note 5 (as
        corrected in contract 1.5) additionally makes any other ``2xx``
        (e.g. a ``204 No Content``) success too — RECOMMENDED, and what
        every sibling SDK's HTTP client reports natively — so this checks
        :attr:`httpx.Response.is_success` rather than pinning the literal
        ``200`` (cross-SDK conformance review F-08). Only a ``401`` (client
        authentication failed) is an error, surfaced as
        :class:`~axiam_sdk._errors.OAuthProtocolError` (§12.3 rule 3). A
        ``5xx`` stays a network error — it does not become "success" just
        because the contract says ``revoke`` returns void
        (port-brief-addendum item 20).
        """
        if not response.is_success:
            raise error_from_oauth2_response(
                response.status_code, response, "revoke request failed"
            )

    # ------------------------------------------------------------------
    # 8-9. Federation SSO — form bodies + response parsing (shared)
    # ------------------------------------------------------------------

    def _sso_start_body(
        self,
        *,
        federation_config_id: str,
        redirect_uri: str,
        tenant_id: str | None = None,
        tenant_slug: str | None = None,
        org_id: str | None = None,
        org_slug: str | None = None,
    ) -> dict[str, str]:
        """Build the ``POST /api/v1/auth/federation/oidc/start`` request
        body (CONTRACT.md §12.3 rule 4, §5.1): one tenant form and one org
        form, defaulting to the client's own construction-time / resolved
        context when the caller supplies neither.

        Raises:
            AuthError: client-side, without a wire call, when neither
                tenant nor organization context can be resolved
                (port-brief-addendum item 15).
        """
        resolved_tenant_id = tenant_id or self._resolved_tenant_id
        resolved_tenant_slug = tenant_slug or self._session.tenant_slug
        resolved_org_id = org_id or self.resolved_org_id()
        resolved_org_slug = org_slug or self._org_slug

        if not resolved_tenant_id and not resolved_tenant_slug:
            raise AuthError(
                "sso_start requires tenant context: pass tenant_id or tenant_slug, or "
                "construct the client with one (CONTRACT.md §5.1)."
            )
        if not resolved_org_id and not resolved_org_slug:
            raise AuthError(
                "sso_start requires organization context: pass org_id or org_slug, or "
                "construct the client with one (CONTRACT.md §5.1)."
            )

        body: dict[str, str] = {
            "federation_config_id": federation_config_id,
            "redirect_uri": redirect_uri,
        }
        if resolved_tenant_id:
            body["tenant_id"] = resolved_tenant_id
        elif resolved_tenant_slug:
            body["tenant_slug"] = resolved_tenant_slug
        if resolved_org_id:
            body["org_id"] = resolved_org_id
        elif resolved_org_slug:
            body["org_slug"] = resolved_org_slug
        return body

    def _handle_sso_start_response(self, response: httpx.Response) -> SsoStartResult:
        """Parse ``POST /api/v1/auth/federation/oidc/start``'s response.

        Per port-brief-addendum item 12, the federation error body shape is
        undocumented for this endpoint — a non-2xx response falls through
        to the generic §2 status mapping (never
        :class:`~axiam_sdk._errors.OAuthProtocolError`, which is reserved
        for the ``/oauth2/*`` endpoints).
        """
        if response.status_code != httpx.codes.OK:
            raise error_from_http_status(
                response.status_code, "ssoStart request failed", response=response
            )
        return SsoStartResult.model_validate(response.json())

    def _handle_sso_complete_response(self, response: httpx.Response) -> SsoCompleteResult:
        """Parse ``POST /api/v1/auth/federation/oidc/callback``'s response.

        The session arrives as **``Set-Cookie``**, not in the response body
        (§12.1 note 6) — on success this calls the same
        :meth:`_absorb_session_cookies` post-login hook ``login()``/
        ``verify_mfa()`` use, so the session is marked authenticated and the
        cached access token / CSRF state stay in sync (port-brief-addendum
        item 16). §12.4 does not apply here — no ID token ever reaches the
        SDK on the federation path.
        """
        if response.status_code != httpx.codes.OK:
            raise error_from_http_status(
                response.status_code, "ssoComplete request failed", response=response
            )
        self._absorb_session_cookies()
        return SsoCompleteResult.model_validate(response.json())

    # ------------------------------------------------------------------
    # Shared configuration/resolution helpers
    # ------------------------------------------------------------------

    def _require_oidc_client_id(self) -> str:
        """The relying party's ``client_id``, required by every §12
        operation that builds a request (all except ``oidc_discover``).

        Raises:
            AuthError: client-side, without a wire call, when no
                ``client_id`` was configured at construction time
                (CONTRACT.md T1 reference judgment call #21 — "client_id
                comes from client configuration, not a per-call argument").
        """
        if not self._oidc_client_id:
            raise AuthError(
                "this OIDC operation requires client_id to be configured at AxiamClient "
                "construction time (CONTRACT.md §12)."
            )
        return self._oidc_client_id

    def _append_client_secret(self, form: dict[str, str]) -> None:
        """Add ``client_secret`` to a form body for a confidential client,
        and omit it entirely for a public client — §12.1 forbids sending an
        empty/null value for an absent optional field."""
        if self._oidc_client_secret is not None:
            form["client_secret"] = _expose_secret(self._oidc_client_secret)

    def _require_client_secret(self, operation: str) -> str:
        """The ``client_secret`` for an operation that cannot be performed
        without one (§12.1 note 4: ``introspect``/``revoke``/
        ``login_client_credentials``).

        Raises:
            AuthError: client-side, without a wire call, when no
                ``client_secret`` was configured.
        """
        if self._oidc_client_secret is None:
            raise AuthError(
                f"{operation} requires confidential-client credentials: construct the client "
                "with client_secret (CONTRACT.md §12.1 note 4)."
            )
        return _expose_secret(self._oidc_client_secret)

    def _resolve_oauth2_tenant_id(self, explicit: str | None) -> str:
        """Resolve the tenant UUID for the ``/oauth2/*`` ``tenant_id`` query
        parameter (CONTRACT.md §12.3 rule 4): the explicit argument, else
        the tenant UUID resolved from a prior ``login()``/``verify_mfa()``/
        ``refresh()`` — and only ever a UUID.

        Raises:
            AuthError: client-side, without a wire call, when no UUID is
                available, or when the resolved value is not a UUID (a
                tenant slug cannot be substituted).
        """
        candidate = explicit or self._resolved_tenant_id
        if not candidate:
            raise AuthError(
                "this operation requires a tenant_id UUID for the /oauth2 query parameter: "
                "pass tenant_id explicitly, or call login()/verify_mfa() first to resolve one "
                "from the session (CONTRACT.md §12.3 rule 4)."
            )
        if not _UUID_RE.match(candidate):
            raise AuthError(
                "tenant_id must be a UUID for the /oauth2 query parameter; a tenant slug "
                "cannot be substituted (CONTRACT.md §12.3 rule 4)."
            )
        return candidate

    # ------------------------------------------------------------------
    # §14 device authorization grant (RFC 8628)
    # ------------------------------------------------------------------

    def _device_authorize_form(self, *, scope: str | None) -> dict[str, str]:
        """Build the ``POST /oauth2/device_authorization`` form body (§14.1).

        **No ``client_secret``**, ever: a device that cannot show a browser
        also cannot hold one, so §14.1 makes this operation unauthenticated
        and forbids refusing a client constructed without a secret.
        """
        form = {"client_id": self._require_oidc_client_id()}
        if scope is not None:
            form["scope"] = scope
        return form

    def _device_poll_form(self, *, device_code: SecretStr | str) -> dict[str, str]:
        """Build the device-code ``POST /oauth2/token`` form body (§14.1)."""
        return {
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "device_code": _expose_secret(device_code),
            "client_id": self._require_oidc_client_id(),
        }

    def _device_authorization_url(
        self, configuration: OidcConfiguration, tenant_id: str | None
    ) -> str:
        """The device authorization endpoint URL with the mandatory
        ``?tenant_id=<uuid>`` query parameter.

        Raises:
            AuthError: when the discovery document advertises no
                ``device_authorization_endpoint``. The URL is never built by
                concatenation onto the issuer — that works against AXIAM and
                breaks against every other OP the same code is pointed at.
        """
        endpoint = configuration.device_authorization_endpoint
        if not endpoint:
            raise AuthError(
                "the authorization server's discovery document advertises no "
                "device_authorization_endpoint: this server does not support the device "
                "grant (CONTRACT.md §14.1)."
            )
        return self._endpoint_url(endpoint, tenant_id)

    def _build_device_authorization(self, wire: dict[str, Any]) -> DeviceAuthorization:
        """Convert a ``DeviceAuthorizationResponse`` body into the model."""
        interval = wire.get("interval")
        return DeviceAuthorization(
            device_code=SecretStr(wire["device_code"]),
            user_code=wire["user_code"],
            verification_uri=wire["verification_uri"],
            verification_uri_complete=wire.get("verification_uri_complete"),
            expires_in=wire["expires_in"],
            # §14.2 rule 2: the interval comes from the response; only its
            # absence falls back to the RFC default. A server-sent 0 is
            # treated as absent — polling with no delay is never what the
            # server meant, and RFC 8628 §3.2 makes 5 s the floor.
            interval=(
                interval
                if isinstance(interval, int) and interval > 0
                else DEFAULT_POLL_INTERVAL_SECONDS
            ),
        )

    @staticmethod
    def _device_poll_outcome(exc: BaseException) -> str:
        """Classify a failed poll per §14.2.

        Returns ``"pending"``, ``"slow_down"``, ``"retry"`` (a transport or
        5xx failure, which rule 6 makes non-terminal) or ``"terminal"``.

        §14.2 rule 5: all five RFC 8628 §3.5 answers arrive as ``400``, which
        the §2 taxonomy would map to one indistinguishable error — so this
        dispatches on the ``error`` field *first*.
        """
        code = getattr(exc, "error", None)
        if code == "authorization_pending":
            return "pending"
        if code == "slow_down":
            return "slow_down"
        if code is not None:
            return "terminal"
        if isinstance(exc, NetworkError):
            return "retry"
        return "terminal"

    @staticmethod
    def _device_expired_error() -> AuthError:
        """The client-side deadline error (§14.2 rule 4).

        Reported under the same ``expired_token`` code the server would have
        used, so a caller's branch does not care which side noticed first.
        """
        return OAuthProtocolError(
            "expired_token",
            "the device authorization expired before the user completed it "
            "(client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)",
        )

    # ------------------------------------------------------------------
    # §15 token exchange (RFC 8693)
    # ------------------------------------------------------------------

    def _token_exchange_form(
        self,
        *,
        subject_token: SecretStr | str,
        subject_token_type: str,
        actor_token: SecretStr | str | None,
        scopes: Sequence[str] | None,
        audience: str | None,
        resource: str | None,
    ) -> dict[str, str]:
        """Build the RFC 8693 exchange form body (§15.1).

        The exchanging client **authenticates**: unlike §14's device, this is
        a confidential service, so a client with no secret fails here —
        client-side, with no wire call.
        """
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "subject_token": _expose_secret(subject_token),
            # Whatever the caller named, verbatim. The subject token is NEVER
            # decoded to pick this (§15.7): which kind of token the caller
            # holds is the caller's to know, and a guess here is the
            # difference between a request that is refused and one that is
            # silently reinterpreted.
            "subject_token_type": subject_token_type,
            "client_id": self._require_oidc_client_id(),
            "client_secret": self._require_client_secret("token_exchange"),
        }
        if actor_token is not None:
            form["actor_token"] = _expose_secret(actor_token)
            # Sent exactly when `actor_token` is: RFC 8693 §2.1 requires the
            # pair, and the type alone is a malformed request.
            form["actor_token_type"] = ACCESS_TOKEN_TYPE
        if scopes is not None:
            form["scope"] = " ".join(scopes)
        if audience is not None:
            form["audience"] = audience
        if resource is not None:
            form["resource"] = resource
        return form

    def _handle_exchange_response(self, response: httpx.Response) -> ExchangedToken:
        """Parse a token-exchange response into an :class:`ExchangedToken`.

        §15.3: a non-2xx body is mapped through the same
        ``OAuth2ErrorResponse`` path as every other ``/oauth2/*`` call, so the
        six §15.3 codes reach the caller verbatim in ``error``.
        """
        if response.status_code != httpx.codes.OK:
            raise error_from_oauth2_response(
                response.status_code, response, "token exchange request failed"
            )
        wire = response.json()
        return ExchangedToken(
            access_token=SecretStr(wire["access_token"]),
            issued_token_type=wire["issued_token_type"],
            token_type=wire["token_type"],
            expires_in=wire["expires_in"],
            scope=wire.get("scope"),
        )

    # ------------------------------------------------------------------
    # §20 UMA 2.0 — Protection API and ticket grant
    # ------------------------------------------------------------------

    def _uma_protection_url(self, path: str) -> str:
        """A Protection API URL. These are host-root paths fixed by UMA 2.0
        FedAuthz §2.2, not discovery-provided endpoints."""
        return f"{normalize_origin(self._session.base_url)}{path}"

    def _uma_protection_headers(self, pat: SecretStr | str) -> dict[str, str]:
        """The PAT goes in ``Authorization``.

        It is an explicit argument on every Protection API call rather than
        this client's own session, because a PAT must be a
        **client-credentials** token — a ticket binds to the ``client_id`` that
        minted it — and this client's session is usually a *user* session,
        which names no client to bind to (§20.2 rule 1).
        """
        return {"Authorization": f"Bearer {_expose_secret(pat)}"}

    def _uma_resource_payload(self, resource: ResourceSet) -> dict[str, object]:
        """The wire body for a register/update.

        ``resource_scopes`` is always sent, even when empty: an update
        **replaces** the scope list, and omitting the key would leave the
        server's copy untouched (§20.2 rule 8).
        """
        payload: dict[str, object] = {
            "name": resource.name,
            "resource_scopes": list(resource.resource_scopes),
        }
        if resource.type is not None:
            payload["type"] = resource.type
        return payload

    def _handle_uma_protection_response(self, response: httpx.Response, fallback: str) -> object:
        """Raise on a non-2xx Protection API response, else return the JSON."""
        if response.status_code >= httpx.codes.BAD_REQUEST:
            raise error_from_oauth2_response(response.status_code, response, fallback)
        if response.status_code == httpx.codes.NO_CONTENT or not response.content:
            return None
        return response.json()

    def _resource_set_from_wire(self, wire: object) -> ResourceSet:
        """Map the snake_case wire body onto :class:`ResourceSet`.

        ``_id`` becomes ``id``: it **is** the AXIAM resource id, so the value
        is carried across unchanged rather than translated.
        """
        data = cast("dict[str, object]", wire)
        return ResourceSet(
            id=cast("str | None", data.get("_id")),
            name=cast("str", data["name"]),
            type=cast("str | None", data.get("type")),
            resource_scopes=cast("list[str]", data.get("resource_scopes") or []),
        )

    def _uma_ticket_form(
        self, *, ticket: SecretStr | str, claim_token: SecretStr | str
    ) -> dict[str, str]:
        """Build the uma-ticket grant form body (§20.1).

        ``claim_token`` is a **required** parameter, though UMA 2.0 §3.3.1
        marks it optional: v1 implements neither incremental authorization nor
        claims-gathering, so it is the only channel that names a requesting
        party. Defaulting it to the resource server's own PAT would mint an RPT
        for the resource server instead of for the user (§20.2 rule 2).
        """
        return {
            "grant_type": UMA_TICKET_GRANT_TYPE,
            "ticket": _expose_secret(ticket),
            "claim_token": _expose_secret(claim_token),
            "claim_token_format": UMA_CLAIM_TOKEN_FORMAT,
            "client_id": self._require_oidc_client_id(),
            "client_secret": self._require_client_secret("uma_exchange_ticket"),
        }

    def _handle_rpt_response(self, response: httpx.Response) -> RequestingPartyToken:
        """Parse a uma-ticket grant response into a
        :class:`RequestingPartyToken`.

        §20.4: the non-2xx body goes through the same ``OAuth2ErrorResponse``
        path as every other ``/oauth2/*`` call, so ``invalid_grant`` and
        ``access_denied`` reach the caller verbatim in ``error`` — including
        when ``access_denied`` arrives as **403** (UMA 2.0 §3.3.6) rather than
        the 400 every other OAuth2 error uses.
        """
        if response.status_code != httpx.codes.OK:
            raise error_from_oauth2_response(
                response.status_code, response, "uma ticket exchange request failed"
            )
        wire = response.json()
        return RequestingPartyToken(
            access_token=SecretStr(wire["access_token"]),
            token_type=wire["token_type"],
            expires_in=wire["expires_in"],
        )

    # ------------------------------------------------------------------
    # §12.7 logout helpers
    # ------------------------------------------------------------------

    def _logout_url_impl(
        self,
        configuration: OidcConfiguration,
        *,
        id_token: SecretStr | str,
        post_logout_redirect_uri: str | None,
        state: str | None,
    ) -> str:
        """Build the RP-initiated logout URL (§12.7.2).

        ``end_session_endpoint`` is read from discovery and never synthesised
        from the issuer (rule 1). ``post_logout_redirect_uri`` is passed
        through **unvalidated against any local list** (rule 3): the
        allow-list lives in the client's server-side registration, and a
        client-side copy would drift and reject a URI an operator had just
        registered.
        """
        endpoint = configuration.end_session_endpoint
        if not endpoint:
            raise AuthError(
                "the authorization server's discovery document advertises no "
                "end_session_endpoint: this server does not support RP-initiated logout "
                "(CONTRACT.md §12.7.2 rule 1)."
            )
        params = {"id_token_hint": _expose_secret(id_token)}
        if post_logout_redirect_uri is not None:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state is not None:
            params["state"] = state
        return str(httpx.URL(endpoint).copy_merge_params(params))

    def _verify_logout_token_impl(
        self, token: str, configuration: OidcConfiguration
    ) -> VerifiedLogoutToken:
        """Verify a back-channel logout token (§12.7.3).

        Every check exists because skipping it has a name — see the public
        ``verify_logout_token`` docstring on the client classes.
        """
        verifier = self._verifier_for(configuration.jwks_uri)
        try:
            claims = verifier.verify_logout_token_signature(token)
        except AuthError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalized to the §2 taxonomy
            # The message never embeds the token: an unverifiable logout token
            # is exactly the case a naive implementation logs verbatim.
            raise AuthError(f"logout token signature verification failed: {exc}") from None

        if claims.get("iss") != configuration.issuer:
            raise AuthError("logout token issuer does not match the discovery document")
        if claims.get("aud") != self._require_oidc_client_id():
            raise AuthError("logout token audience does not match this client_id")

        # Without this check the whole method is an elaborate way to accept an
        # ID token.
        events = claims.get("events")
        if not isinstance(events, dict) or not isinstance(
            events.get(BACKCHANNEL_LOGOUT_EVENT), dict
        ):
            raise AuthError(
                "not a logout token: the events claim does not carry "
                "http://schemas.openid.net/event/backchannel-logout"
            )

        if "nonce" in claims:
            raise AuthError(
                "logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 forbids: "
                "this is an ID token being replayed as a logout token"
            )

        sid = claims.get("sid")
        sub = claims.get("sub")
        if sid is None and sub is None:
            raise AuthError("logout token names neither sid nor sub, so it identifies no session")

        now = int(time.time())
        skew = int(self._oidc_clock_skew_sec or 0)
        exp = claims.get("exp")
        iat = claims.get("iat")
        if not isinstance(exp, int) or exp + skew < now:
            raise AuthError("logout token has expired")
        if not isinstance(iat, int) or iat - skew > now:
            raise AuthError("logout token was issued in the future")
        if now - iat > MAX_LOGOUT_TOKEN_AGE_SECONDS + skew:
            raise AuthError("logout token is too old to be a live delivery")

        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise AuthError("logout token carries no jti, so the RP cannot dedup redeliveries")

        return VerifiedLogoutToken(sid=sid, sub=sub, jti=jti)
