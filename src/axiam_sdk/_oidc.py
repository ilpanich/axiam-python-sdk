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
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from pydantic import SecretStr

from axiam_sdk._errors import AuthError, error_from_http_status, error_from_oauth2_response
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk._models import (
    AuthorizationRequest,
    IntrospectionResult,
    OidcConfiguration,
    OidcTokenSet,
    SsoCompleteResult,
    SsoStartResult,
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
    """

    def __init__(self) -> None:
        """Build an idle single-flight coalescer with no call in progress."""
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._in_flight = False
        self._result: Any = None
        self._exc: BaseException | None = None

    def run(self, fn: Callable[[], Any]) -> Any:
        """Run ``fn()`` exactly once across any number of concurrent
        callers; every other concurrent caller blocks and then receives the
        same result or re-raises the same exception."""
        with self._lock:
            if self._in_flight:
                while self._in_flight:
                    self._condition.wait()
                if self._exc is not None:
                    raise self._exc
                return self._result
            self._in_flight = True

        try:
            result = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised to every waiter as-is
            with self._lock:
                self._exc = exc
                self._in_flight = False
                self._condition.notify_all()
            raise

        with self._lock:
            self._result = result
            self._exc = None
            self._in_flight = False
            self._condition.notify_all()
        return result


class _AsyncSingleFlight:
    """Async twin of :class:`_SyncSingleFlight`.

    Safe under asyncio's single-threaded cooperative scheduling: checking
    and setting ``self._pending`` happens with no ``await`` in between, so
    two concurrent callers can never both decide to start a fresh call.
    """

    def __init__(self) -> None:
        """Build an idle single-flight coalescer with no call in progress."""
        self._pending: asyncio.Future[Any] | None = None

    async def run(self, fn: Callable[[], Awaitable[Any]]) -> Any:
        """Async twin of :meth:`_SyncSingleFlight.run`."""
        pending = self._pending
        if pending is not None:
            return await pending

        loop = asyncio.get_running_loop()
        future: asyncio.Future[Any] = loop.create_future()
        self._pending = future
        try:
            result = await fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised to every waiter as-is
            self._pending = None
            future.set_exception(exc)
            raise
        self._pending = None
        future.set_result(result)
        return result


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
