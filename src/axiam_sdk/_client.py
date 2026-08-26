"""Sync AxiamClient — the AXIAM SDK's sync REST surface (D-01/D-19, SC#1).

``AxiamClient`` exposes sync ``login``/``verify_mfa``/``refresh``/``logout``/
``check_access``/``can``/``batch_check`` methods only. The async twins live on
the dedicated :class:`~axiam_sdk.AsyncAxiamClient` (see ``_async_client.py``,
SDK-Q08) — NOT as ``async_*`` methods on this class. Both classes share the
``_AxiamClientBase`` construction/body-building/response-parsing logic defined
below (one ``_Session``: cookie jar, CSRF state, tenant/org context, refresh
guard); only the transport (sync vs. async httpx client) and the single-flight
refresh-guard call differ. Mirrors ``the Go SDK's client.go`` + ``the Go SDK's login.go``
+ ``the Go SDK's authz.go``, adapted to Python's sync+async duality.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, cast

import httpx
from pydantic import SecretStr

from axiam_sdk._account import MfaEnrollment, PasswordResetContext, _AccountMixin
from axiam_sdk._decision_memo import DecisionMemo, memo_key
from axiam_sdk._errors import (
    AuthError,
    NetworkError,
    error_from_http_status,
    error_from_oauth2_response,
)
from axiam_sdk._models import (
    AccessCheck,
    AccessResult,
    AuthorizationRequest,
    BatchCheckResult,
    DeviceAuthorization,
    ExchangedToken,
    IntrospectionResult,
    LoginResult,
    OidcConfiguration,
    OidcTokenSet,
    PushedAuthorizationRequest,
    RequestedPermission,
    RequestingPartyToken,
    ResourceSet,
    SsoCompleteResult,
    SsoStartResult,
    VerifiedLogoutToken,
)
from axiam_sdk._oidc import (
    DISCOVERY_PATH,
    SSO_CALLBACK_PATH,
    SSO_START_PATH,
    PollSchedule,
    _OidcMixin,
)
from axiam_sdk._retry import retry_sync
from axiam_sdk._session import _Session
from axiam_sdk._telemetry import TelemetryDispatcher, TelemetryHook
from axiam_sdk._webauthn import (
    WebauthnChallenge,
    WebauthnCredential,
    WebauthnLoginResult,
    WebauthnWorkspace,
    _WebauthnMixin,
)
from axiam_sdk.management.ops import ManagementNamespaces

if TYPE_CHECKING:  # pragma: no cover - typing only
    # Imported for types only. At runtime `_opaque` is imported inside the two
    # methods that use it, so an installation without `libaxiam_opaque_ffi`
    # neither pays for the ctypes machinery nor fails at import.
    from axiam_sdk._opaque import LoginExchange, OpaqueLoginStart

LOGIN_PATH = "/api/v1/auth/login"
OPAQUE_REGISTER_START_PATH = "/api/v1/auth/opaque/register/start"
OPAQUE_LOGIN_START_PATH = "/api/v1/auth/opaque/login/start"
OPAQUE_LOGIN_FINISH_PATH = "/api/v1/auth/opaque/login/finish"
MFA_VERIFY_PATH = "/api/v1/auth/mfa/verify"
REFRESH_PATH = "/api/v1/auth/refresh"
LOGOUT_PATH = "/api/v1/auth/logout"
CHECK_PATH = "/api/v1/authz/check"
BATCH_CHECK_PATH = "/api/v1/authz/check/batch"

ACCESS_COOKIE = "axiam_access"
REFRESH_COOKIE = "axiam_refresh"


def _decode_unverified_claims(token: str) -> dict[str, Any]:
    """Base64url-decode a JWT's payload segment WITHOUT verifying its
    signature — signature verification is the JWKS/middleware concern
    (``_jwks.py``, ``fastapi``/``django`` integrations), not this
    org_id/tenant_id-resolution helper. Mirrors Go's
    ``decodeUnverifiedClaims``."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError(f"malformed access token: expected 3 segments, got {len(parts)}")
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        claims: Any = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        # SDK-10: never interpolate the decoder's exception into the message —
        # a ValueError/JSONDecodeError can echo back the decoded payload
        # segment (non-secret but sensitive claims) into logs/exceptions. Keep
        # the message static and content-free.
        raise AuthError("failed to decode access token claims") from None
    # IN-02: json.loads succeeds for any valid JSON, including arrays/scalars.
    # The function's own signature promises a dict; every caller does
    # ``.get(...)`` on the result, which would raise AttributeError on a
    # non-object payload. Validate the shape here so a malformed token
    # surfaces a clean AuthError, mirroring the isinstance(..., dict) checks
    # already in _jwks.py and amqp/_hmac.py.
    if not isinstance(claims, dict):
        raise AuthError("access token payload is not a JSON object")
    return claims


class _AxiamClientBase(_OidcMixin, _WebauthnMixin, _AccountMixin):
    """Shared construction + body-building/response-parsing logic for both
    :class:`AxiamClient` (sync) and :class:`~axiam_sdk._async_client.AsyncAxiamClient`
    (async, SDK-Q08). Not part of the public API (leading underscore) — holds
    no transport-specific (sync vs. async httpx client) code itself; each
    concrete subclass supplies its own ``login``/``verify_mfa``/``refresh``/
    ``logout``/``check_access``/``can``/``batch_check`` using the helpers here.

    Also mixes in :class:`~axiam_sdk._oidc._OidcMixin` (CONTRACT.md §12):
    the shared, transport-agnostic half of the nine OIDC/SSO relying-party
    operations (``oidc_discover``, ``oidc_begin``, ``oidc_exchange``,
    ``oidc_refresh``, ``login_client_credentials``, ``introspect``,
    ``revoke``, ``sso_start``, ``sso_complete``) — see ``_oidc.py``.
    """

    def __init__(
        self,
        *,
        base_url: str,
        tenant_slug: str,
        org_slug: str | None = None,
        org_id: str | None = None,
        custom_ca: str | None = None,
        client_cert: str | bytes | None = None,
        client_key: str | bytes | None = None,
        timeout: httpx.Timeout | None = None,
        logger: logging.Logger | None = None,
        client_id: str | None = None,
        client_secret: str | SecretStr | None = None,
        oidc_discovery_ttl_seconds: float | None = None,
        oidc_clock_skew_sec: float | None = None,
        retry_enabled: bool = True,
        decision_memo_ttl_ms: float = 0.0,
        telemetry_hook: TelemetryHook | None = None,
    ) -> None:
        """Construct the shared client state (CONTRACT.md §5/§6/§6.1/§7/§12).

        ``tenant_slug`` is required — AXIAM is multi-tenant with no default
        tenant; omitting it is an ``AuthError`` at construction time, never a
        silent fallback (§5). ``org_slug``/``org_id`` are mutually exclusive
        and optional here — the real org UUID is usually only known after a
        successful login/refresh resolves it from the access token's
        ``org_id`` claim (Pitfall 3, see :meth:`resolved_org_id`). ``custom_ca``
        is the sole *server*-trust override permitted by §6 — a PEM-encoded CA
        bundle, never a boolean.

        ``client_cert``/``client_key`` opt this client into **mutual TLS**
        (CONTRACT.md §6.1): a PEM certificate chain plus its PEM private key
        (each ``str`` or ``bytes``), presented for client authentication on
        the REST transport. They must be supplied together. Presenting a
        client certificate never relaxes server verification (§6.1 rule 2),
        and the private key is secret — it is loaded straight into the TLS
        stack, never logged, stored as a public attribute, or exposed via a
        getter (§6.1 rule 3 / §7). ``timeout`` overrides the default httpx
        connect/read timeouts. ``logger`` is injectable (D-15); a silent
        :func:`_null_logger` is used when omitted.

        ``client_id``/``client_secret`` configure this client as an OIDC
        relying party (CONTRACT.md §12): ``client_id`` is required by every
        §12 operation except ``oidc_discover`` (T1 reference judgment call
        #21 — it comes from client configuration, never a per-call
        argument), and ``client_secret`` (accepted wrapped or bare) opts
        into confidential-client behavior, required by ``introspect``,
        ``revoke``, and ``login_client_credentials`` (§12.1 note 4). Both
        are optional here so a pure REST/gRPC/AMQP consumer that never uses
        §12 is not forced to supply them — omitting them only becomes an
        error if an OIDC operation that needs one is actually called.
        ``oidc_discovery_ttl_seconds``/``oidc_clock_skew_sec`` override the
        §12.3 rule 6 discovery-cache TTL (floored at 5 minutes) and the
        §12.4 rule 5 ID-token clock skew (capped at 60s) respectively.

        Raises:
            AuthError: if ``tenant_slug`` is empty, or if both ``org_slug``
                and ``org_id`` are supplied.
            ValueError: if exactly one of ``client_cert``/``client_key`` is
                supplied, or if the supplied client identity is not valid PEM.
        """
        if not tenant_slug:
            raise AuthError(
                "tenant_slug is required — AXIAM is multi-tenant and there is no default "
                "tenant (CONTRACT.md §5)"
            )
        if org_slug and org_id:
            raise AuthError("org_slug and org_id are mutually exclusive — supply at most one")

        self._org_slug = org_slug
        self._org_id = org_id
        self._resolved_org_id: str | None = org_id

        self._logger = logger or _null_logger()
        # §16.1 disable switch. There is deliberately no knob for the attempt
        # cap, base delay or delay cap: §16.1 forbids raising them, and eleven
        # SDKs agreeing on one table is the point.
        self._retry_enabled = retry_enabled
        # §17.1 rule 1 — off unless the caller asked for it.
        self._decision_memo = DecisionMemo(decision_memo_ttl_ms)
        self._telemetry = TelemetryDispatcher(telemetry_hook)
        # §19.2 rule 6: a clamped setting is reported, not swallowed. Emitted
        # once, here, because construction is the only moment an operator can
        # act on it.
        self._decision_memo.report_clamp(decision_memo_ttl_ms, self._telemetry)
        # §18 shutdown flag, read on every operation.
        self._closed = False

        self._session = _Session(
            base_url=base_url,
            tenant_slug=tenant_slug,
            custom_ca=custom_ca,
            client_cert=client_cert,
            client_key=client_key,
            timeout=timeout,
            logger=self._logger,
        )

        self._init_oidc(
            client_id=client_id,
            client_secret=client_secret,
            discovery_ttl_seconds=oidc_discovery_ttl_seconds,
            clock_skew_sec=oidc_clock_skew_sec,
        )

    # ------------------------------------------------------------------
    # org_id resolution (Pitfall 3 — the real login/refresh endpoints
    # require an org_id/org_slug beyond CONTRACT.md §5's tenant-only
    # minimum)
    # ------------------------------------------------------------------

    def resolved_org_id(self) -> str | None:
        """The organization UUID to use in a request body: the explicitly
        configured ``org_id`` if present, otherwise the value resolved from
        the access token's ``org_id`` claim after login/refresh, if any."""
        return self._resolved_org_id

    def resolved_tenant_id(self) -> str | None:
        """The tenant UUID resolved from the access token's ``tenant_id`` claim.

        The public twin of :meth:`resolved_org_id`, and symmetric with it for the
        same reason: this client is constructed with a tenant *slug* (§5 requires
        one and there is no ``tenant_id`` argument), so the UUID only exists
        after a login or refresh has decoded it. CONTRACT.md §27 routes that name
        a tenant explicitly -- the signing CAs under ``ca_certificates``, and the
        ``tenants`` namespace itself -- take that UUID as an ordinary argument
        rather than defaulting it (§27.4 rule 3, because there it names the
        object being acted on rather than the context), so a caller needs a way
        to read the one the session already knows instead of re-deriving it.

        Returns ``None`` before any login, exactly as :meth:`resolved_org_id`
        does.
        """
        return self._resolved_tenant_id

    def _set_resolved_org_id(self, org_id: str) -> None:
        """Cache ``org_id`` resolved from an access token's ``org_id`` claim
        (Pitfall 3), so later :meth:`resolved_org_id` and refresh calls no
        longer need it re-supplied explicitly."""
        self._resolved_org_id = org_id

    # ------------------------------------------------------------------
    # login / verify_mfa body-building + response handling (shared)
    # ------------------------------------------------------------------

    def _login_body(self, email: str, password: str) -> dict[str, Any]:
        """Build the ``POST /api/v1/auth/login`` request body: tenant slug,
        ``username_or_email``, ``password``, and whichever of ``org_id``/
        ``org_slug`` was supplied at construction time (mutually exclusive,
        §5)."""
        body: dict[str, Any] = {
            "tenant_slug": self._session.tenant_slug,
            "username_or_email": email,
            "password": password,
        }
        if self._org_id:
            body["org_id"] = self._org_id
        elif self._org_slug:
            body["org_slug"] = self._org_slug
        return body

    # ------------------------------------------------------------------
    # OPAQUE, RFC 9807 (CONTRACT.md §23) — shared between the sync and async clients
    # ------------------------------------------------------------------
    #
    # Everything except the two HTTP sends lives here. Duplicating the protocol
    # across the two client classes is how they end up disagreeing about which
    # identity goes into the KDF or whether M2 was checked.

    def _opaque_login_start_body(self, username_or_email: str, ke1: str) -> dict[str, Any]:
        """Build the ``POST /api/v1/auth/opaque/login/start`` body.

        Reuses :meth:`_login_body` so tenant/org resolution cannot drift between
        the two login paths, then drops ``password`` — it has no business on
        this request, and that is the entire point of the exchange.
        """
        body = self._login_body(username_or_email, "")
        body.pop("password", None)
        body["ke1"] = ke1
        return body

    def _opaque_register_start_body(self, registration_request: str) -> dict[str, Any]:
        """Build the ``POST /api/v1/auth/opaque/register/start`` body.

        Same workspace resolution, with both the password *and* the username
        dropped: enrolment names no account. The record binds to a credential
        identifier the server chooses, which is why the SRP verifier's
        ``identity`` argument has no successor here — and why a later rename
        cannot invalidate a credential.
        """
        body = self._login_body("", "")
        body.pop("password", None)
        body.pop("username_or_email", None)
        body["registration_request"] = registration_request
        return body

    def _opaque_start_error(self, response: httpx.Response, what: str) -> Exception:
        """Map a non-200 from either ``*/start`` endpoint.

        A ``404`` is a property of the tenant ("OPAQUE is off here"), not of the
        user and not of the credentials — so it is a ``NetworkError`` a caller
        can fall back on, never an ``AuthError`` that would be shown as "invalid
        password".
        """
        if response.status_code == httpx.codes.NOT_FOUND:
            return NetworkError(
                "this tenant does not offer OPAQUE (opaque_mode is disabled); use login() instead"
            )
        return error_from_http_status(response.status_code, f"OPAQUE {what} failed")

    def _opaque_finish_login(
        self, exchange: LoginExchange, started: OpaqueLoginStart, password: str
    ) -> str:
        """Open the envelope and produce ``KE3``, or fail the login.

        Shared by the sync and async clients so the *meaning* of a failure
        cannot drift between them, and it turns on which of two exceptions the
        exchange raises:

        * ``NetworkError`` — the KSF the server named is one this build cannot
          perform, or a cost is missing or out of range. A configuration
          problem, re-raised unchanged; flattening it into an authentication
          failure would report it to the user as a wrong password and send an
          operator looking in the wrong place.
        * ``AuthError`` — the envelope did not open, or ``KE2``'s MAC did not
          verify. A wrong password, an account that does not exist, and a server
          that does not hold the record are indistinguishable by design.

        Either way ``KE3`` is never sent (§23.4 rule 7), which is why this
        raises rather than returning a sentinel the caller could ignore. What
        the *caller* does with an ``AuthError`` then depends on
        ``started.mode`` and on nothing else — see
        :attr:`~axiam_sdk._opaque.OpaqueLoginStart.allows_password_fallback`.
        A ``*/start`` response missing ``ke2`` is a malformed response rather
        than a credential failure, so it becomes a ``NetworkError``.
        """
        if started.ke2 is None:
            raise NetworkError("OPAQUE login/start returned no `ke2`")
        try:
            return exchange.finish(password, started.ke2, started.ksf)
        except (NetworkError, AuthError):
            raise
        except Exception as exc:
            raise AuthError("invalid credentials") from exc

    def opaque_available(self) -> bool:
        """Whether this installation can perform OPAQUE (§23.2).

        Genuinely able to answer ``False``: the protocol comes from the shared
        ``libaxiam_opaque_ffi``, a per-platform release asset rather than a
        PyPI package, and a consumer whose tenant does not use OPAQUE should not
        be made to carry a compiled artifact. Reports rather than raising, so an
        application can choose the password path before attempting a login
        instead of discovering the gap mid-exchange.
        """
        from ._opaque import opaque_available

        return opaque_available()

    def _mfa_verify_body(self, mfa_token: Any, code: str) -> dict[str, str]:
        """Build the ``POST /api/v1/auth/mfa/verify`` request body from the
        ``challenge_token`` returned by :meth:`~AxiamClient.login` (accepted
        as either a plain string or a ``Sensitive``-style wrapper exposing
        ``get_secret_value()``, §7) and the user-supplied TOTP ``code``."""
        token_value = (
            mfa_token.get_secret_value() if hasattr(mfa_token, "get_secret_value") else mfa_token
        )
        return {"challenge_token": token_value, "totp_code": code}

    def _handle_login_response(self, response: httpx.Response) -> LoginResult:
        """Parse a ``login``/``verify_mfa`` HTTP response into a typed
        :class:`~axiam_sdk._models.LoginResult`.

        A ``200`` means the session is fully established: absorbs the
        Set-Cookie tokens via :meth:`_absorb_session_cookies` and returns
        ``mfa_required=False``. A ``202`` means MFA is required: returns
        ``mfa_required=True`` with the server's ``challenge_token`` for a
        follow-up ``verify_mfa`` call, without touching cookies. Any other
        status is logged (status code only, D-15) and raised via
        :func:`~axiam_sdk._errors.error_from_http_status`.
        """
        if response.status_code == httpx.codes.OK:
            wire = response.json()
            result = LoginResult(
                mfa_required=False,
                user_id=wire.get("user", {}).get("id"),
                tenant_id=self._session.tenant_slug,
                session_id=wire.get("session_id"),
                expires_in=wire.get("expires_in"),
            )
            self._absorb_session_cookies()
            return result
        if response.status_code == httpx.codes.ACCEPTED:
            wire = response.json()
            return LoginResult(
                mfa_required=True,
                mfa_token=wire.get("challenge_token"),
            )
        # CONTRACT.md §25.2 rule 1: a `403` carrying `mfa_setup_required` is an
        # OUTCOME, not a refusal. The tenant requires MFA, this account has
        # none, and the server handed back the token to finish. Mapping it
        # through §2 to AuthzError told the caller they lacked permission to
        # log in, when what the server said was recoverable and came with the
        # means to recover.
        #
        # Matched on the body's own discriminant rather than on the status
        # alone: a genuine authorization refusal is also a `403`, and only one
        # of the two carries a `setup_token`.
        if response.status_code == httpx.codes.FORBIDDEN:
            setup = self._mfa_setup_required(response)
            if setup is not None:
                return setup
        # D-15: log the failure with status code only — never the request
        # body, response body, or any token/credential value.
        self._logger.warning("axiam_sdk: login/verify_mfa failed: status=%s", response.status_code)
        raise error_from_http_status(
            response.status_code, "login/verify_mfa failed", response=response
        )

    @staticmethod
    def _mfa_setup_required(response: httpx.Response) -> LoginResult | None:
        """The ``403 mfa_setup_required`` branch of ``login`` (§25.2 rule 1).

        Returns ``None`` for any other ``403`` — including a genuine
        authorization refusal, which must keep raising.
        """
        try:
            wire = response.json()
        except ValueError:
            return None
        if not isinstance(wire, dict):
            return None
        if wire.get("mfa_setup_required") is not True:
            return None
        token = wire.get("setup_token")
        if not isinstance(token, str) or not token:
            return None
        return LoginResult(
            mfa_required=False, mfa_setup_required=True, setup_token=SecretStr(token)
        )

    def _absorb_session_cookies(self) -> None:
        """Read the access/refresh tokens the server just set via
        Set-Cookie (already captured by the shared cookie jar), decode the
        access token's org_id claim (Pitfall 3) and cache it, and seed the
        refresh guard so a subsequent 401 has the correct observed
        baseline."""
        access = self._session.cookie_value(ACCESS_COOKIE)
        if not access:
            raise AuthError("server response did not set the axiam_access cookie")
        refresh = self._session.cookie_value(REFRESH_COOKIE)

        claims = _decode_unverified_claims(access)
        org_id_claim = claims.get("org_id")
        if org_id_claim:
            self._set_resolved_org_id(org_id_claim)
        # CONTRACT.md §12.3 rule 4: cache the tenant UUID so a subsequent
        # oidc_exchange/oidc_refresh/introspect/revoke/login_client_credentials
        # call can default its `tenant_id` query parameter from the session
        # rather than requiring it as an explicit argument every time.
        tenant_id_claim = claims.get("tenant_id")
        if tenant_id_claim:
            self._resolved_tenant_id = tenant_id_claim

        self._session.refresh_guard.seed(access, refresh, claims.get("exp"))

    # ------------------------------------------------------------------
    # refresh body-building + response handling (shared) — exactly one
    # literal /api/v1/auth/refresh POST, routed through the single-flight
    # guard (Pitfall 4, §9.3)
    # ------------------------------------------------------------------

    def _refresh_identifiers(self, observed_access: str) -> tuple[str, str]:
        """Derive the ``(tenant_id, org_id)`` pair required by the refresh
        request body from the currently observed access token's claims.

        ``tenant_id`` comes straight from the token claim. ``org_id`` prefers
        the already-resolved value (:meth:`resolved_org_id`) and falls back
        to the token's own ``org_id`` claim.

        Raises:
            AuthError: if ``tenant_id`` is absent from the claims, or if no
                ``org_id`` can be resolved (the caller must ``login()``
                successfully, or supply ``org_id``/``org_slug`` explicitly,
                before ``refresh()`` can succeed).
        """
        claims = _decode_unverified_claims(observed_access)
        tenant_id = claims.get("tenant_id")
        if not tenant_id:
            raise AuthError("tenant_id could not be resolved from the access token")
        org_id = self.resolved_org_id() or claims.get("org_id")
        if not org_id:
            raise AuthError(
                "org_id could not be resolved; login() must succeed before refresh() — "
                "supply org_id/org_slug or call login() first"
            )
        return tenant_id, org_id

    def _refresh_body(self, tenant_id: str, org_id: str) -> dict[str, str]:
        """Build the ``POST /api/v1/auth/refresh`` request body."""
        return {"tenant_id": tenant_id, "org_id": org_id}

    def _handle_refresh_response(self, response: httpx.Response) -> dict[str, Any]:
        """Parse a ``refresh`` HTTP response into the ``access``/``refresh``/
        ``exp`` mapping consumed by
        :class:`~axiam_sdk.token.refresh_guard.RefreshGuard`'s ``do_refresh``
        contract.

        A non-``200`` status is logged (status code only, D-15) and raised
        immediately via :func:`~axiam_sdk._errors.error_from_http_status` —
        no retry loop on refresh failure (§9.3). On success, re-reads the
        fresh ``axiam_access``/``axiam_refresh`` cookies from the shared jar
        and decodes the new access token's ``exp`` claim.

        Raises:
            AuthError: if the response is ``200`` but did not set a fresh
                ``axiam_access`` cookie.
        """
        if response.status_code != httpx.codes.OK:
            # §9.3: no retry loop on refresh failure — propagate as-is.
            # D-15: status code only, never a token value.
            self._logger.warning("axiam_sdk: token refresh failed: status=%s", response.status_code)
            raise error_from_http_status(response.status_code, "refresh failed", response=response)

        new_access = self._session.cookie_value(ACCESS_COOKIE)
        if not new_access:
            raise AuthError("refresh response did not set axiam_access")
        new_refresh = self._session.cookie_value(REFRESH_COOKIE)
        claims = _decode_unverified_claims(new_access)
        tenant_id_claim = claims.get("tenant_id")
        if tenant_id_claim:
            self._resolved_tenant_id = tenant_id_claim
        return {"access": new_access, "refresh": new_refresh, "exp": claims.get("exp")}

    # ------------------------------------------------------------------
    # logout (shared)
    # ------------------------------------------------------------------

    def _session_id_for_logout(self) -> str:
        """Resolve the current session id (the access token's ``jti`` claim)
        to send as ``POST /api/v1/auth/logout``'s ``session_id``.

        Raises:
            AuthError: if there is no active session (no ``axiam_access``
                cookie), or the access token carries no ``jti`` claim.
        """
        access = self._session.cookie_value(ACCESS_COOKIE)
        if not access:
            raise AuthError("no active session to log out")
        claims = _decode_unverified_claims(access)
        jti = claims.get("jti")
        if not jti:
            raise AuthError("access token has no session id (jti) to log out")
        return str(jti)

    # ------------------------------------------------------------------
    # REST authz body-building (shared)
    # ------------------------------------------------------------------

    def _access_check_body(
        self,
        action: str,
        resource_id: str,
        scope: str | None,
        subject_id: str | None = None,
    ) -> dict[str, Any]:
        """Build a single ``{action, resource_id, scope?, subject_id?}``
        check body shared by ``check_access``/``can`` (CONTRACT.md §1) —
        ``scope``/``subject_id`` are each omitted entirely when ``None``
        rather than sent as JSON ``null``.

        ``subject_id`` (CONTRACT.md §11.2) checks the given subject's
        permissions rather than the authenticated caller's own — used by the
        declarative ``require_access`` helpers (§11) to check the *request's*
        authenticated user rather than this client's own (often
        service-account) session. The server requires the caller to hold
        ``authz:check_as`` whenever ``subject_id`` is supplied.
        """
        body: dict[str, Any] = {"action": action, "resource_id": resource_id}
        if scope is not None:
            body["scope"] = scope
        if subject_id is not None:
            body["subject_id"] = subject_id
        return body

    def _ensure_open(self) -> None:
        """Raise if :meth:`close` has been called (§18.1 rule 4).

        Use-after-close is an error, not a silent reconnect: a client that
        quietly rebuilt its transport would make ``close()`` meaningless and
        hide the lifecycle bug that caused the call.
        """
        if self._closed:
            raise NetworkError("client is closed: this client was shut down with close()")

    def _on_credential_change(self) -> None:
        """Drop memoized decisions (§17.1 rule 9).

        Entries are keyed by subject rather than session, so a re-authentication
        as a *different* principal would otherwise inherit the previous one's
        decisions.
        """
        self._decision_memo.clear()


class AxiamClient(_AxiamClientBase, ManagementNamespaces):
    """The AXIAM SDK's sync REST entry point (CONTRACT.md §1-§10).

    ``client.login(...)`` returns a typed :class:`~axiam_sdk._models.LoginResult`
    with ``mfa_required`` (SC#1). For the async twin, use
    :class:`~axiam_sdk.AsyncAxiamClient` (SDK-Q08) — a separate class, not an
    ``async_*`` method on this one.
    """

    # ------------------------------------------------------------------
    # Lifecycle (D-19)
    # ------------------------------------------------------------------

    def __enter__(self) -> AxiamClient:
        """Context-manager entry — returns ``self`` (D-19); no separate
        setup beyond what ``__init__`` already did."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Context-manager exit — always calls :meth:`close`, regardless of
        whether the ``with`` block raised (D-19)."""
        self.close()

    def close(self) -> None:
        """Release this client's local resources (D-19, CONTRACT.md §18).

        Idempotent — calling it twice is not an error. Cleanup runs from error
        paths, and an error path that itself raises hides the original failure.

        **This does not log out.** §18.1 rule 5: shutting down a client releases
        *local* resources and never reaches the network. The server-side session
        deliberately outlives the client object, which is what lets a process
        restart and resume; a ``close()`` that logged out would silently end
        every user's session on each deploy. Call :meth:`logout` first if
        ending the session is what you want.

        After this returns, any operation on the client raises ``NetworkError``
        rather than silently reconnecting.
        """
        self._closed = True
        self._decision_memo.clear()
        self._session.close()

    # ------------------------------------------------------------------
    # login / verify_mfa
    # ------------------------------------------------------------------

    def login(self, email: str, password: str) -> LoginResult:
        """``POST /api/v1/auth/login`` (CONTRACT.md §1). Returns a typed
        :class:`LoginResult`; check ``mfa_required`` before assuming the
        session is established (SC#1)."""
        self._ensure_open()
        self._on_credential_change()
        request = self._session.sync_client.build_request(
            "POST", LOGIN_PATH, json=self._login_body(email, password)
        )
        response = self._session._send_sync(request)
        return self._handle_login_response(response)

    def login_opaque(self, username_or_email: str, password: str) -> LoginResult:
        """OPAQUE login (CONTRACT.md §23) — the password never leaves this process.

        Returns the same :class:`LoginResult` as :meth:`login`, including the
        ``mfa_required`` case, so a caller needs one result handler for both.

        What crosses the wire is a blinded group element and a MAC, neither
        useful without the account's registration record **and** the tenant's
        OPRF seed — so a TLS-terminating proxy, an accidentally verbose request
        log, or a heap dump on the server cannot capture a plaintext password,
        because the server never has one. It also means a stolen record database
        is not offline-crackable on its own, which is the property SRP could not
        offer. It does **not** protect against a compromised AXIAM server.

        Unlike its SRP predecessor this returns without verifying a server
        proof, and there is nothing missing: RFC 9807's AKE authenticates the
        server during the handshake, so opening ``KE2`` *is* the proof that it
        holds the record. §23.3 rule 6 had to mandate an ``M2`` check in
        capitals because skipping it kept only half the protocol; there is now
        nothing to skip.

        :raises NetworkError: when the tenant has OPAQUE disabled, when the
            shared library is not installed, or when the server names a KSF this
            SDK cannot perform. Deliberately not ``AuthError``: reporting a
            configuration gap as a credential failure would send a user off to
            reset a working password, and would stop a caller falling back to
            :meth:`login`.
        :raises AuthError: for a wrong password, an account that does not exist,
            an account with no registration record, and a server that does not
            hold the record — indistinguishable by design. **Nothing is sent to
            ``login/finish`` in that case** (§23.4 rule 7).

        **The ``mode`` field decides what happens after a failed exchange**, and
        nothing else does (§23.4 rule 7). ``login/start`` carries the tenant's
        ``opaque_mode``:

        * ``"optional"`` — this method retries over :meth:`login` with the same
          credentials before reporting anything, and returns that call's
          outcome. Under ``optional`` an account with no record is the ordinary
          case rather than an error: every account has none the moment an
          operator enables OPAQUE, and they acquire one only as they next set a
          password. Treating the failed exchange as final would lock out every
          user of a tenant mid-migration, which is the state ``optional`` exists
          to serve.
        * ``"required"``, an unrecognised value, or **no ``mode`` at all** (a
          server older than the field) — the failure is final and nothing is
          retried over :meth:`login`. It would be refused anyway: ``required``
          answers ``403 opaque_required`` for every principal in the tenant, so
          trying would put a plaintext password on the wire for nothing.

        ``mode`` is **not** downgrade protection and must not be read as such: a
        hostile server that wanted the plaintext could answer ``404`` and get
        the fallback whatever it puts here. ``required`` is what closes that,
        server-side, by refusing ``/auth/login`` before examining any
        credential.

        This runs the tenant's key-stretching function: Argon2id at 19 MiB by
        default, tens to hundreds of milliseconds of blocking work. That cost is
        the point — it is what makes a stolen record expensive to attack even by
        someone holding the OPRF seed.
        """
        from ._opaque import OpaqueLoginStart, start_login

        self._ensure_open()
        self._on_credential_change()

        exchange = start_login(password)

        # One round trip, always. SRP had to guess a group before the server
        # named one and restart the exchange if it guessed wrong; ``KE1`` does
        # not depend on the KSF.
        request = self._session.sync_client.build_request(
            "POST",
            OPAQUE_LOGIN_START_PATH,
            json=self._opaque_login_start_body(username_or_email, exchange.ke1),
        )
        response = self._session._send_sync(request)
        if response.status_code != httpx.codes.OK:
            raise self._opaque_start_error(response, "login/start")
        started = OpaqueLoginStart.from_wire(response.json())

        try:
            ke3 = self._opaque_finish_login(exchange, started, password)
        except AuthError:
            # §23.4 rule 7. `KE3` is not sent either way; `mode` — and only
            # `mode` — decides whether the plaintext path may be tried.
            if not started.allows_password_fallback:
                raise
            return self.login(username_or_email, password)

        request = self._session.sync_client.build_request(
            "POST",
            OPAQUE_LOGIN_FINISH_PATH,
            json={"opaque_session": started.opaque_session, "ke3": ke3},
        )
        response = self._session._send_sync(request)
        if response.status_code not in (httpx.codes.OK, httpx.codes.ACCEPTED):
            raise error_from_http_status(response.status_code, "OPAQUE login/finish failed")
        return self._handle_login_response(response)

    def opaque_enrollment(self, password: str) -> dict[str, Any]:
        """Build a registration record to send with any request that sets a
        password (user creation, change-password, reset completion).

        The server cannot build one — it never sees the plaintext — so it has to
        arrive with the request or not at all.

        Performs a ``register/start`` round trip, which the SRP verifier this
        replaces did not need: OPAQUE's envelope is sealed under the server's
        oblivious PRF, so there is no offline computation that produces a valid
        record.

        Note the absence of an ``identity`` argument. The SRP version required
        the account's canonical username, and passing an email produced a
        verifier no login could ever satisfy. A record binds to a credential
        identifier the server chooses, so there is nothing here to get wrong.

        :raises NetworkError: when the tenant has OPAQUE disabled, when the
            shared library is not installed, or when the server names a KSF this
            SDK cannot perform.
        """
        from ._opaque import KsfParams, start_registration

        self._ensure_open()
        exchange = start_registration(password)

        request = self._session.sync_client.build_request(
            "POST",
            OPAQUE_REGISTER_START_PATH,
            json=self._opaque_register_start_body(exchange.request),
        )
        response = self._session._send_sync(request)
        if response.status_code != httpx.codes.OK:
            raise self._opaque_start_error(response, "register/start")
        started = response.json()

        return {
            "opaque_session": started["opaque_session"],
            "registration_record": exchange.finish(
                password, started["registration_response"], KsfParams.from_wire(started)
            ),
        }

    def verify_mfa(self, mfa_token: Any, code: str) -> LoginResult:
        """``POST /api/v1/auth/mfa/verify`` (CONTRACT.md §1) — completes the
        two-phase flow started by :meth:`login` when ``mfa_required`` was
        true."""
        self._ensure_open()
        self._on_credential_change()
        request = self._session.sync_client.build_request(
            "POST", MFA_VERIFY_PATH, json=self._mfa_verify_body(mfa_token, code)
        )
        response = self._session._send_sync(request)
        return self._handle_login_response(response)

    # ------------------------------------------------------------------
    # refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """``POST /api/v1/auth/refresh`` (CONTRACT.md §1), routed through
        the shared single-flight guard (§9) so concurrent 401s collapse
        into exactly one in-flight refresh call. A 401 on the refresh call
        itself is ``AuthError`` with no retry (§9.3, Pitfall 4)."""
        self._ensure_open()
        self._on_credential_change()
        observed_access = self._session.cookie_value(ACCESS_COOKIE)
        if not observed_access:
            raise AuthError("no access token to refresh — call login() first")

        tenant_id, org_id = self._refresh_identifiers(observed_access)
        # D-15: diagnostic-only, never a token value. Off by default
        # (NullHandler); integrates with the consuming app's logging config.
        self._logger.debug("axiam_sdk: token refresh triggered")
        self._session.refresh_guard.refresh_if_needed_sync(
            observed_access, lambda: self._do_refresh_sync(tenant_id, org_id)
        )

    def _do_refresh_sync(self, tenant_id: str, org_id: str) -> dict[str, Any]:
        """Perform the actual ``POST /api/v1/auth/refresh`` call — the
        ``do_refresh`` closure passed to
        :meth:`~axiam_sdk.token.refresh_guard.RefreshGuard.refresh_if_needed_sync`
        by :meth:`refresh`. Not called directly by SDK users; always routed
        through the single-flight guard so concurrent 401s collapse into
        one in-flight call (§9)."""
        # The literal /api/v1/auth/refresh path is required so the
        # Path-scoped axiam_refresh cookie attaches (Pitfall 4).
        request = self._session.sync_client.build_request(
            "POST", "/api/v1/auth/refresh", json=self._refresh_body(tenant_id, org_id)
        )
        response = self._session._send_sync(request)
        return self._handle_refresh_response(response)

    # ------------------------------------------------------------------
    # logout
    # ------------------------------------------------------------------

    def logout(self) -> None:
        """``POST /api/v1/auth/logout`` (CONTRACT.md §1)."""
        self._ensure_open()
        self._on_credential_change()
        session_id = self._session_id_for_logout()
        request = self._session.sync_client.build_request(
            "POST", LOGOUT_PATH, json={"session_id": session_id}
        )
        response = self._session._send_sync(request)
        if response.status_code >= 300:
            raise error_from_http_status(response.status_code, "logout failed", response=response)
        self._session.refresh_guard = type(self._session.refresh_guard)()

    # ------------------------------------------------------------------
    # REST authz: check_access / can / batch_check (Task 3)
    # ------------------------------------------------------------------

    def check_access(
        self,
        action: str,
        resource_id: str,
        scope: str | None = None,
        *,
        subject_id: str | None = None,
    ) -> AccessResult:
        """``POST /api/v1/authz/check`` (CONTRACT.md §1).

        ``subject_id`` (CONTRACT.md §11.2), when supplied, checks the given
        subject's permissions rather than this client's own — the caller
        must hold ``authz:check_as`` server-side. This is what the
        declarative ``require_access`` helpers (§11) pass to check the
        *request's* authenticated user.
        """
        self._ensure_open()
        # §17: consult the memo first. Disabled by default, in which case this
        # is one dict lookup that always misses.
        key = memo_key(action, resource_id, scope, subject_id)
        memoized = self._decision_memo.get(key)
        if memoized is not None:
            assert isinstance(memoized, AccessResult)
            return memoized

        body = self._access_check_body(action, resource_id, scope, subject_id)
        wire = self._authz_post_sync(CHECK_PATH, body, operation="check_access")
        result = AccessResult(**wire)

        # Only a decision the server actually returned is memoized: reaching
        # here means success, so §17.1 rule 7's ban on caching a failure is
        # structural rather than a check that could be forgotten.
        self._decision_memo.set(key, result)
        return result

    def can(self, action: str, resource_id: str, scope: str | None = None) -> bool:
        """Alias for ``check_access`` returning only the allowed boolean
        (CONTRACT.md §1 note, browser/UI scenarios)."""
        return self.check_access(action, resource_id, scope).allowed

    def batch_check(self, checks: list[AccessCheck]) -> list[AccessResult]:
        """``POST /api/v1/authz/check/batch`` (CONTRACT.md §1) — results
        returned in the same order as ``checks``."""
        self._ensure_open()
        body = {"checks": [c.model_dump(exclude_none=True) for c in checks]}
        wire = self._authz_post_sync(BATCH_CHECK_PATH, body, operation="batch_check")
        return BatchCheckResult(**wire).results

    def _authz_post_sync(
        self, path: str, body: dict[str, Any], *, operation: str
    ) -> dict[str, Any]:
        """POST an authz request body to *path* under the §16 retry policy.

        The call is a ``POST`` but changes no server state, so it is
        retry-eligible: §16.2's test is "changes no server state", NOT "is a
        GET". Gating on the verb would exclude the single most important
        operation this policy covers.

        The §9.3 refresh-then-retry-once on a 401 is a *different* mechanism and
        stays inside one §16 attempt: a 401 means the token expired, which
        refreshing fixes, and neither backing off nor counting it against the
        transport-failure budget would make sense.
        """
        return retry_sync(
            lambda attempt: self._authz_post_sync_once(path, body, operation, attempt),
            operation=operation,
            enabled=self._retry_enabled,
            telemetry=self._telemetry,
        )

    def _authz_post_sync_once(
        self, path: str, body: dict[str, Any], operation: str, attempt: int
    ) -> dict[str, Any]:
        """One §16 attempt, with its §19 request pair."""
        request = self._session.sync_client.build_request("POST", path, json=body)
        with self._telemetry.request(operation, "POST", path, attempt) as span:
            response = self._session._send_sync(request)

            if response.status_code == httpx.codes.UNAUTHORIZED:
                response = self._retry_after_refresh_sync(request)

            span.status = response.status_code
            if response.status_code < 200 or response.status_code >= 300:
                raise error_from_http_status(
                    response.status_code, "authz check failed", response=response
                )
            span.outcome = "success"
            result: dict[str, Any] = response.json()
            return result

    def _retry_after_refresh_sync(self, original_request: httpx.Request) -> httpx.Response:
        """On a 401, refresh exactly once (via the shared single-flight
        guard) then retry the failed authz call exactly once. A second
        failure propagates through the caller's own status check (§9.3, no
        retry loop)."""
        self.refresh()
        retry_request = self._session.sync_client.build_request(
            original_request.method,
            original_request.url,
            content=original_request.content,
            headers={
                k: v
                for k, v in original_request.headers.items()
                if k.lower() not in ("content-length", "x-csrf-token")
            },
        )
        return self._session._send_sync(retry_request)

    # ------------------------------------------------------------------
    # OIDC / SSO relying-party helpers (CONTRACT.md §12, Task T3)
    # ------------------------------------------------------------------

    def oidc_discover(self) -> OidcConfiguration:
        """``GET /.well-known/openid-configuration`` (CONTRACT.md §12.1) —
        fetch the OIDC discovery document, cached per origin with a
        ≥5-minute TTL and single-flight de-duplication of concurrent calls
        (§12.3 rule 6)."""

        def fetch() -> OidcConfiguration:
            """Perform the actual discovery-document GET; called by the
            discovery cache at most once per cache miss/expiry."""
            request = self._session.sync_client.build_request("GET", DISCOVERY_PATH)
            response = self._session._send_sync(request)
            return self._parse_discovery_response(response)

        return self._discovery_cache.get_sync(self._discovery_origin_key(), fetch)

    def oidc_begin(
        self,
        *,
        configuration: OidcConfiguration,
        redirect_uri: str,
        scope: str | list[str] | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> AuthorizationRequest:
        """Build an authorization request (CONTRACT.md §12.1) — **pure
        local computation, no network I/O**. Nothing is stored: persist
        the returned ``state``, ``nonce``, and ``code_verifier`` yourself
        (§12.3 rule 1)."""
        return self._oidc_begin_impl(
            configuration=configuration,
            redirect_uri=redirect_uri,
            scope=scope,
            extra_params=extra_params,
        )

    def oidc_par(
        self,
        *,
        request: AuthorizationRequest,
        redirect_uri: str,
        scope: str | list[str] | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> PushedAuthorizationRequest:
        """``POST /oauth2/par`` (CONTRACT.md §26.1) — push the authorization
        request over the back channel and get an opaque handle to redirect
        with.

        PAR moves the authorization request off the browser. Instead of putting
        ``scope``, ``redirect_uri``, ``state`` and the PKCE challenge into a
        URL the user agent carries, the client POSTs them straight to AXIAM
        over an authenticated channel and puts an opaque ``request_uri`` in the
        redirect. What travels through the browser is then a random string that
        cannot be edited into meaning something else.

        **Required for a FAPI 2.0 client** — ``profile: "fapi2"`` refuses a
        registration that does not set ``require_par``, so such a client cannot
        authorize any other way (§21.1).

        A §12 extension, not a replacement: ``oidc_exchange`` afterwards is
        unchanged, and takes the ``code_verifier`` carried on the result.

        Not retried on a ``5xx`` or a transport failure — it is a POST that
        creates server state, so it falls outside §16.2's read-only
        eligibility exactly as ``oidc_exchange`` does. The safe recovery is a
        fresh push (§26.2 rule 4).

        Raises:
            AuthError: when the discovery document advertises no
                ``pushed_authorization_request_endpoint``.
            OAuthProtocolError: on any ``error`` the server returns.
        """
        config = configuration or self.oidc_discover()
        form = self._par_form(request=request, redirect_uri=redirect_uri, scope=scope)
        url = self._par_url(config, tenant_id)
        http_request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(http_request)
        return self._build_pushed_request(response, configuration=config, request=request)

    def oidc_exchange(
        self,
        *,
        code: str,
        code_verifier: SecretStr | str,
        redirect_uri: str,
        nonce: str,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> OidcTokenSet:
        """``POST /oauth2/token`` with ``grant_type=authorization_code``
        (CONTRACT.md §12.1) — exchange an authorization code for a token
        set, validating the returned ID token in full before returning
        (§12.4). On ANY §12.4 failure the whole token set is discarded and
        ``AuthError`` is raised with the matching reason code (§12.4
        rule 7) — the access/refresh token from the same response is never
        returned."""
        config = configuration or self.oidc_discover()
        form = self._exchange_form(
            code=code, code_verifier=code_verifier, redirect_uri=redirect_uri
        )
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(request)
        return self._handle_token_response(response, config, nonce)

    def oidc_refresh(
        self,
        *,
        refresh_token: SecretStr | str,
        scope: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> OidcTokenSet:
        """``POST /oauth2/token`` with ``grant_type=refresh_token``
        (CONTRACT.md §12.1) — refresh an ``OidcTokenSet``.

        A **distinct operation** from :meth:`refresh`, which drives the
        cookie/opaque-token session path at ``POST /api/v1/auth/refresh``
        (§12.1 "``oidc_refresh`` vs ``refresh``") — the two are never
        merged, aliased, or made to fall back to one another. Concurrent
        ``oidc_refresh`` calls collapse into exactly one wire call, and the
        selected caller's wire call additionally runs inside the same §9
        single-flight guard the cookie-session :meth:`refresh` uses, so an
        ``oidc_refresh`` and a concurrent cookie-session refresh can never
        interleave.
        """

        def do_refresh() -> OidcTokenSet:
            """Perform the actual ``refresh_token`` grant call; run inside
            :meth:`~axiam_sdk.token.refresh_guard.RefreshGuard.run_exclusive_sync`
            by ``under_guard``, and de-duplicated across concurrent callers
            by the single-flight coalescer below."""
            config = configuration or self.oidc_discover()
            form = self._refresh_form(refresh_token=refresh_token, scope=scope)
            url = self._token_endpoint_url(config, tenant_id)
            request = self._session.sync_client.build_request("POST", url, data=form)
            response = self._session._send_sync(request)
            # No nonce: rule 6 does not apply to a refresh-issued ID token.
            return self._handle_token_response(response, config, None)

        def under_guard() -> OidcTokenSet:
            """Run ``do_refresh`` inside the shared §9 refresh-guard lock,
            so it can never interleave with a concurrent cookie-session
            :meth:`refresh` call."""
            token_set: OidcTokenSet = self._session.refresh_guard.run_exclusive_sync(do_refresh)
            return token_set

        result: OidcTokenSet = self._oidc_refresh_single_flight_sync.run(under_guard)
        return result

    def login_client_credentials(
        self,
        *,
        scope: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> OidcTokenSet:
        """``POST /oauth2/token`` with ``grant_type=client_credentials``
        (CONTRACT.md §12.1) — service-account machine-to-machine login.
        Requests no ``openid`` scope, so the response carries no
        ``id_token``.

        Raises:
            AuthError: when no ``client_secret`` was configured — this
                grant cannot be performed by a public client.
        """
        config = configuration or self.oidc_discover()
        form = self._client_credentials_form(scope=scope)
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(request)
        # No nonce: rule 6 does not apply to this grant.
        return self._handle_token_response(response, config, None)

    def device_authorize(
        self,
        *,
        scope: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> DeviceAuthorization:
        """``POST /oauth2/device_authorization`` (CONTRACT.md §14.1) — start
        the device grant and obtain the code pair.

        **Unauthenticated by design.** A device that cannot show a browser
        also cannot hold a client secret, so this never sends
        ``client_secret`` and never refuses a client built without one.

        Raises:
            AuthError: when the discovery document advertises no
                ``device_authorization_endpoint``.
        """
        config = configuration or self.oidc_discover()
        form = self._device_authorize_form(scope=scope)
        url = self._device_authorization_url(config, tenant_id)
        request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(request)
        if response.status_code != httpx.codes.OK:
            raise error_from_oauth2_response(
                response.status_code, response, "device authorization request failed"
            )
        return self._build_device_authorization(response.json())

    def device_poll(
        self,
        *,
        device_code: SecretStr | str,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> OidcTokenSet:
        """``POST /oauth2/token`` with the device-code grant (§14.1) — **one**
        poll attempt.

        The raw single call, so an application driving its own loop (a UI
        rendering a countdown, say) can. The five RFC 8628 §3.5 answers
        surface as ``OAuthProtocolError`` — ``authorization_pending`` and
        ``slow_down`` included — so a hand-rolled loop sees exactly what
        :meth:`device_login` sees. Most callers want :meth:`device_login`.
        """
        config = configuration or self.oidc_discover()
        form = self._device_poll_form(device_code=device_code)
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(request)
        # No nonce: the device grant has no authorization request to carry one.
        return self._handle_token_response(response, config, None)

    def device_login(
        self,
        on_user_code: Callable[[DeviceAuthorization], None],
        *,
        scope: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> OidcTokenSet:
        """The composed §14.3 helper: start the grant, hand the caller the
        user code, poll to completion.

        ``on_user_code`` is called with the :class:`DeviceAuthorization`
        **before the first poll** — §14.3 rule 2 requires the caller to have
        had the chance to display the code before polling begins. The SDK
        never prints it: what the device does with it (screen, QR code, e-ink
        panel) is the application's decision.

        Per §14.3 rule 4 (contract 1.7 errata) this SDK **returns** the token
        set rather than adopting it, matching its ``login_client_credentials``
        posture.

        Polling follows §14.2: the interval comes from the response;
        ``slow_down`` adds 5 s **permanently**; ``authorization_pending``
        loops; ``access_denied`` and ``expired_token`` raise distinct errors;
        polling stops at ``expires_in`` even if the server has not yet said
        ``expired_token``. A 5xx or transport failure mid-poll is **not**
        terminal (rule 6) — the loop absorbs it and tries again, bounded by
        the same deadline, because a server restart must not lose a grant the
        user has already approved.
        """
        config = configuration or self.oidc_discover()
        authorization = self.device_authorize(
            scope=scope, tenant_id=tenant_id, configuration=config
        )

        # §14.3 rule 2 — before any polling.
        on_user_code(authorization)

        schedule = PollSchedule(authorization.interval, authorization.expires_in)
        while True:
            if not schedule.tick():
                raise self._device_expired_error()
            time.sleep(schedule.interval_seconds)
            try:
                return self.device_poll(
                    device_code=authorization.device_code,
                    tenant_id=tenant_id,
                    configuration=config,
                )
            except Exception as exc:  # noqa: BLE001 - classified by §14.2
                outcome = self._device_poll_outcome(exc)
                if outcome == "pending" or outcome == "retry":
                    continue
                if outcome == "slow_down":
                    schedule.slow_down()
                    continue
                raise

    def token_exchange(
        self,
        *,
        subject_token: SecretStr | str,
        subject_token_type: str,
        actor_token: SecretStr | str | None = None,
        scopes: Sequence[str] | None = None,
        audience: str | None = None,
        resource: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> ExchangedToken:
        """``POST /oauth2/token`` with the RFC 8693 grant (CONTRACT.md §15.1)
        — exchange a token for a **narrower** one.

        What this method deliberately does *not* do:

        * **No default ``actor_token``** (§15.2 rule 1). Passing none asks for
          *impersonation*; the SDK will not quietly reuse the client's own
          session token as the actor and turn that into a delegation.
        * **No retry or downgrade on ``unauthorized_client``** (rule 2) — a
          registration fact an operator must fix.
        * **No auto-narrowing on ``invalid_scope``** (rule 3). The server
          refuses instead of silently narrowing precisely so the caller finds
          out here.
        * **No adoption** (rule 5). The returned token is handed onward in one
          outbound call; adopting it would silently re-privilege every
          subsequent call this client makes.

        A cross-tenant subject token answers ``invalid_grant``, identically to
        an expired one. The SDK does not try to tell them apart (§15.3): the
        server collapses them because distinguishing them is a
        tenant-enumeration signal.

        Args:
            subject_token_type: What kind of token ``subject_token`` is.
                ``None`` sends :data:`~axiam_sdk._oidc.ACCESS_TOKEN_TYPE`, the
                same-domain exchange of §15.1. To exchange a token from a
                **trusted external issuer** (§15.7), set this explicitly —
                normally to :data:`~axiam_sdk._oidc.JWT_TOKEN_TYPE`. The SDK
                never reads ``subject_token`` to decide the value: which kind
                of token you hold is something only you know, AXIAM refuses
                refresh and ID token types by name, and the SDK will not retry
                a refusal as a different type.

        Raises:
            AuthError: when no ``client_secret`` was configured — client-side,
                with no wire call.
        """
        config = configuration or self.oidc_discover()
        form = self._token_exchange_form(
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            scopes=scopes,
            audience=audience,
            resource=resource,
        )
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(request)
        return self._handle_exchange_response(response)

    def uma_register_resource(self, pat: SecretStr | str, resource: ResourceSet) -> ResourceSet:
        """``POST /uma2/rreg/resource_set`` — register a resource set
        (CONTRACT.md §20.1).

        The returned ``id`` **is** the AXIAM resource id, directly usable as
        the ``resource_id`` of a later :meth:`uma_request_ticket`.
        """
        request = self._session.sync_client.build_request(
            "POST",
            self._uma_protection_url("/uma2/rreg/resource_set"),
            json=self._uma_resource_payload(resource),
            headers=self._uma_protection_headers(pat),
        )
        response = self._session._send_sync(request)
        wire = self._handle_uma_protection_response(response, "uma resource registration failed")
        return self._resource_set_from_wire(wire)

    def uma_read_resource(self, pat: SecretStr | str, resource_id: str) -> ResourceSet:
        """``GET /uma2/rreg/resource_set/{id}`` — read a resource set (§20.1)."""
        request = self._session.sync_client.build_request(
            "GET",
            self._uma_protection_url(f"/uma2/rreg/resource_set/{resource_id}"),
            headers=self._uma_protection_headers(pat),
        )
        response = self._session._send_sync(request)
        wire = self._handle_uma_protection_response(response, "uma resource read failed")
        return self._resource_set_from_wire(wire)

    def uma_update_resource(
        self, pat: SecretStr | str, resource_id: str, resource: ResourceSet
    ) -> ResourceSet:
        """``PUT /uma2/rreg/resource_set/{id}`` — replace a resource set (§20.1).

        **The scope list is replaced, not merged** (§20.2 rule 8). Whatever
        ``resource.resource_scopes`` holds becomes the complete declared set;
        omitting a scope removes it, which is how a resource server drops an
        authority. This method performs no read-before-write.
        """
        request = self._session.sync_client.build_request(
            "PUT",
            self._uma_protection_url(f"/uma2/rreg/resource_set/{resource_id}"),
            json=self._uma_resource_payload(resource),
            headers=self._uma_protection_headers(pat),
        )
        response = self._session._send_sync(request)
        wire = self._handle_uma_protection_response(response, "uma resource update failed")
        return self._resource_set_from_wire(wire)

    def uma_delete_resource(self, pat: SecretStr | str, resource_id: str) -> None:
        """``DELETE /uma2/rreg/resource_set/{id}`` — deregister (§20.1)."""
        request = self._session.sync_client.build_request(
            "DELETE",
            self._uma_protection_url(f"/uma2/rreg/resource_set/{resource_id}"),
            headers=self._uma_protection_headers(pat),
        )
        response = self._session._send_sync(request)
        self._handle_uma_protection_response(response, "uma resource delete failed")

    def uma_list_resources(self, pat: SecretStr | str) -> list[str]:
        """``GET /uma2/rreg/resource_set`` — list the ids **this client**
        registered (§20.1).

        Not the tenant's whole resource tree: a protection scope does not
        entitle a caller to enumerate it.
        """
        request = self._session.sync_client.build_request(
            "GET",
            self._uma_protection_url("/uma2/rreg/resource_set"),
            headers=self._uma_protection_headers(pat),
        )
        response = self._session._send_sync(request)
        wire = self._handle_uma_protection_response(response, "uma resource list failed")
        return cast("list[str]", wire or [])

    def uma_request_ticket(
        self, pat: SecretStr | str, permissions: Sequence[RequestedPermission]
    ) -> SecretStr:
        """``POST /uma2/perm`` — mint a permission ticket (§20.1).

        Scope names are validated **here**, against each resource's declared
        set. Asking for an undeclared scope is a ``400``, not a denial — the
        two are different failures, and this SDK surfaces the distinction the
        server draws rather than flattening it.
        """
        body = [
            {"resource_id": p.resource_id, "resource_scopes": list(p.resource_scopes)}
            for p in permissions
        ]
        request = self._session.sync_client.build_request(
            "POST",
            self._uma_protection_url("/uma2/perm"),
            json=body,
            headers=self._uma_protection_headers(pat),
        )
        response = self._session._send_sync(request)
        wire = cast(
            "dict[str, str]",
            self._handle_uma_protection_response(response, "uma ticket request failed"),
        )
        return SecretStr(wire["ticket"])

    def uma_exchange_ticket(
        self,
        *,
        ticket: SecretStr | str,
        claim_token: SecretStr | str,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> RequestingPartyToken:
        """``POST /oauth2/token`` with the uma-ticket grant (§20.1) — exchange
        a ticket for an RPT.

        **This method never retries.** It issues exactly one request and is
        outside the §16 retry policy — not on ``5xx``, not on timeout, not on
        any transport failure (§20.2 rule 6). The ticket is consumed *before*
        the request is evaluated, so a failed exchange has already spent it: a
        retry cannot succeed, and under concurrency it is precisely the
        concurrent redemption a server whose storage engine this SDK cannot
        attest may admit twice (ilpanich/axiam#302). On failure, request a
        **new** ticket.

        What this method deliberately does *not* do:

        * **No default ``claim_token``** (rule 2) — it is required. Defaulting
          it to the resource server's own PAT would mint an RPT for the
          resource server instead of for the user.
        * **No auto-narrowing on ``access_denied``** (rule 3). A partial grant
          is refused whole; whether two-of-three permissions is useful is the
          application's judgement, not this SDK's.
        * **No adoption** (rule 4). The RPT is the *requesting party's* token.
          Adopting it would re-privilege every later call this client makes as
          that user.

        The four ticket refusals — unknown, expired, already used, wrong client
        — all answer ``invalid_grant`` with one message. This SDK does not try
        to tell them apart (§20.4): the server collapses them so a caller
        cannot probe for live ticket handles.

        Raises:
            AuthError: when no ``client_secret`` was configured — client-side,
                with no wire call.
        """
        config = configuration or self.oidc_discover()
        form = self._uma_ticket_form(ticket=ticket, claim_token=claim_token)
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(request)
        return self._handle_rpt_response(response)

    def logout_url(
        self,
        *,
        id_token: SecretStr | str,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> str:
        """Build the RP-initiated logout URL to redirect the user agent to
        (CONTRACT.md §12.7.2).

        Performs **no network I/O** beyond the discovery fetch the SDK caches
        anyway, and does **not** clear this client's own session: whether the
        local session ends is the application's decision — a backend holding a
        service-account session must not lose it because a *user* logged out.

        ``end_session_endpoint`` is read from discovery and never synthesised
        from the issuer (rule 1). ``post_logout_redirect_uri`` is passed
        through unvalidated against any local list (rule 3): the allow-list
        lives in the client's server-side registration, and a client-side copy
        would drift and reject a URI an operator had just registered.

        ``state`` is the caller's to generate and the caller's to check; the
        SDK never invents one, because the value only means something to the
        application that will receive it back.
        """
        config = configuration or self.oidc_discover()
        return self._logout_url_impl(
            config,
            id_token=id_token,
            post_logout_redirect_uri=post_logout_redirect_uri,
            state=state,
        )

    def verify_logout_token(
        self,
        token: str,
        *,
        configuration: OidcConfiguration | None = None,
    ) -> VerifiedLogoutToken:
        """Verify a back-channel logout token the OP POSTed to this
        application's ``backchannel_logout_uri`` (CONTRACT.md §12.7.3).

        Every check exists because skipping it has a name:

        1. **Signature**, through the same §12.4 JWKS verifier the ID-token
           path uses — no second key-fetching path — with the same
           ``kid``-required discipline.
        2. **``iss``/``aud``**: a token minted for another RP is not accepted.
        3. **``events`` carries the back-channel-logout key.** This is what
           distinguishes a logout token from an ID token; skipping it means
           accepting a replayed ID token as a logout instruction.
        4. **``nonce`` is absent.** Back-Channel Logout 1.0 §2.4 forbids it,
           and its presence is the documented signature of an ID token being
           replayed. Rejected, not ignored.
        5. **At least one of ``sid``/``sub``** — a token naming neither
           identifies nothing.
        6. **``exp`` in the future, ``iat`` recent.**

        Returns:
            The ``sid``/``sub``/``jti`` the token names — never a bare
            ``bool``, because the RP has to know *which* session to end.
            **Dedup on ``jti`` yourself**: delivery is at-least-once, so a
            valid token legitimately arrives twice, and an SDK-side guard
            would have no durable store and would silently drop a real second
            logout after a restart.
        """
        config = configuration or self.oidc_discover()
        return self._verify_logout_token_impl(token, config)

    def introspect(
        self,
        *,
        token: SecretStr | str,
        token_type_hint: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> IntrospectionResult:
        """``POST /oauth2/introspect`` (RFC 7662, CONTRACT.md §12.1) — ask
        the server whether a token is active and, if so, for its metadata.
        Requires confidential-client credentials (§12.1 note 4). A ``401``
        here is a client-credential failure surfaced as
        ``OAuthProtocolError``; it never enters the §9 single-flight
        refresh guard (a client-credential failure is not a session
        expiry)."""
        config = configuration or self.oidc_discover()
        form = self._introspect_form(token=token, token_type_hint=token_type_hint)
        url = self._endpoint_url_for_introspect(config, tenant_id)
        request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(request)
        return self._handle_introspect_response(response)

    def revoke(
        self,
        *,
        token: SecretStr | str,
        token_type_hint: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> None:
        """``POST /oauth2/revoke`` (RFC 7009, CONTRACT.md §12.1) — revoke
        an access or refresh token. Idempotent: any ``200`` (including for
        a token the server has never seen) is success (§12.1 note 5); only
        a ``401`` (client authentication failed) is an error."""
        config = configuration or self.oidc_discover()
        form = self._revoke_form(token=token, token_type_hint=token_type_hint)
        url = self._endpoint_url_for_revoke(config, tenant_id)
        request = self._session.sync_client.build_request("POST", url, data=form)
        response = self._session._send_sync(request)
        self._handle_revoke_response(response)

    def sso_start(
        self,
        *,
        federation_config_id: str,
        redirect_uri: str,
        tenant_id: str | None = None,
        tenant_slug: str | None = None,
        org_id: str | None = None,
        org_slug: str | None = None,
    ) -> SsoStartResult:
        """``POST /api/v1/auth/federation/oidc/start`` (CONTRACT.md §12.1)
        — step 1 of first-time SSO against an upstream IdP. One tenant
        form and one org form must be resolvable, from the arguments or
        from the client's construction-time/resolved context (§5.1)."""
        body = self._sso_start_body(
            federation_config_id=federation_config_id,
            redirect_uri=redirect_uri,
            tenant_id=tenant_id,
            tenant_slug=tenant_slug,
            org_id=org_id,
            org_slug=org_slug,
        )
        request = self._session.sync_client.build_request("POST", SSO_START_PATH, json=body)
        response = self._session._send_sync(request)
        return self._handle_sso_start_response(response)

    def sso_complete(self, *, state: str, code: str) -> SsoCompleteResult:
        """``POST /api/v1/auth/federation/oidc/callback`` (CONTRACT.md
        §12.1) — step 2 of upstream SSO: consumes the single-use ``state``,
        provisions or links the user, and establishes the session via
        ``Set-Cookie`` (§4 cookie jar). §12.4 does not apply here — no ID
        token ever reaches the SDK on the federation path."""
        request = self._session.sync_client.build_request(
            "POST", SSO_CALLBACK_PATH, json={"state": state, "code": code}
        )
        response = self._session._send_sync(request)
        return self._handle_sso_complete_response(response)

    # ------------------------------------------------------------------
    # §24 WebAuthn / passkeys — the relying-party layer
    #
    # Python has no authenticator, so §24.6b's linked-API helper is
    # deliberately absent: §24.6b rule 2 forbids emulating one in software,
    # and a "credential" held in process memory is not a second factor. What
    # is here is the half that talks to AXIAM, plus §24.6a's JSON bridge —
    # which is what lets a Python service be the relying party for a ceremony
    # a handset ran.
    # ------------------------------------------------------------------

    def webauthn_register_start(self) -> WebauthnChallenge:
        """``POST /api/v1/auth/webauthn/register/start`` (CONTRACT.md §24.1).

        Requires a session — enrolling a passkey is something a signed-in user
        does to their own account — and refuses **client-side with no wire
        call** when there is none.

        A ``503`` means the tenant's attestation policy requires attestation
        and the FIDO metadata service has no usable snapshot. That is a server
        configuration state, not a transient failure, so §24.4 rule 2
        deliberately does **not** retry it.
        """
        self._ensure_open()
        self._require_webauthn_session("webauthn_register_start")
        request = self._session.sync_client.build_request("POST", self._WA_REGISTER_START, json={})
        response = self._session._send_sync(request)
        return self._webauthn_challenge(response, "webauthn_register_start")

    def webauthn_register_finish(
        self,
        *,
        state_token: SecretStr | str,
        credential_name: str,
        response: dict[str, Any] | str,
    ) -> WebauthnCredential:
        """``POST /api/v1/auth/webauthn/register/finish`` (CONTRACT.md §24.1).

        ``response`` is either the parsed authenticator answer or the
        platform's own JSON string (§24.6a rule 2) — Android's
        ``registrationResponseJson``, a browser's ``credential.toJSON()``. It
        reaches the server unchanged either way: it is the input to a
        signature check over bytes this SDK did not produce.
        """
        self._ensure_open()
        self._require_webauthn_session("webauthn_register_finish")
        body = self._webauthn_register_finish_body(state_token, credential_name, response)
        request = self._session.sync_client.build_request(
            "POST", self._WA_REGISTER_FINISH, json=body
        )
        return self._webauthn_credential(self._session._send_sync(request))

    def webauthn_authenticate_start(self, *, challenge_token: SecretStr | str) -> WebauthnChallenge:
        """``POST /api/v1/auth/webauthn/authenticate/start`` (CONTRACT.md §24.1).

        The **second-factor** ceremony: it continues a ``login()`` that
        answered ``mfa_required`` with ``"webauthn"`` among its methods, and
        ``challenge_token`` is that result's ``mfa_token``.

        A different flow from :meth:`webauthn_discoverable_start`, not the same
        one with an optional argument — see §24.2 for why they cannot be
        merged.
        """
        self._ensure_open()
        request = self._session.sync_client.build_request(
            "POST", self._WA_AUTH_START, json={"challenge_token": _expose_token(challenge_token)}
        )
        response = self._session._send_sync(request)
        return self._webauthn_challenge(response, "webauthn_authenticate_start")

    def webauthn_authenticate_finish(
        self, *, state_token: SecretStr | str, response: dict[str, Any] | str
    ) -> WebauthnLoginResult:
        """``POST /api/v1/auth/webauthn/authenticate/finish`` (CONTRACT.md §24.1).

        Leaves this client authenticated (§24.3 rule 1). That is not §14.3's
        "MAY adopt" posture: ``device_login`` mints tokens a caller may want to
        route elsewhere, and this is the SDK's own primary authentication —
        returning a token set without adopting it would make a passkey sign-in
        the one way to log in that does not log you in.
        """
        return self._webauthn_finish_sync(
            self._WA_AUTH_FINISH, state_token, response, "webauthn_authenticate_finish"
        )

    def webauthn_discoverable_start(
        self, *, workspace: WebauthnWorkspace | None = None
    ) -> WebauthnChallenge:
        """``POST .../authenticate/discoverable/start`` (CONTRACT.md §24.1).

        The **primary-factor** ceremony: nothing precedes it, the server sends
        an empty ``allowCredentials``, and the assertion itself identifies the
        user. The workspace still has to be named — a discoverable credential
        is resolved inside one tenant — but it comes from this client's own
        configuration unless overridden, and slugs are accepted.
        """
        self._ensure_open()
        body = self._webauthn_discoverable_body(workspace)
        request = self._session.sync_client.build_request(
            "POST", self._WA_DISCOVERABLE_START, json=body
        )
        response = self._session._send_sync(request)
        return self._webauthn_challenge(response, "webauthn_discoverable_start")

    def webauthn_discoverable_finish(
        self, *, state_token: SecretStr | str, response: dict[str, Any] | str
    ) -> WebauthnLoginResult:
        """``POST .../authenticate/discoverable/finish`` (CONTRACT.md §24.1).

        Leaves this client authenticated (§24.3). Unlike its username-bound
        twin, this fires the server's ``login.post_auth`` reactor hook (§22.5):
        there was no password step for the event to have been fired at.
        """
        return self._webauthn_finish_sync(
            self._WA_DISCOVERABLE_FINISH, state_token, response, "webauthn_discoverable_finish"
        )

    def _webauthn_finish_sync(
        self,
        path: str,
        state_token: SecretStr | str,
        response: dict[str, Any] | str,
        operation: str,
    ) -> WebauthnLoginResult:
        """The shared tail of both authentication ceremonies."""
        self._ensure_open()
        # §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and
        # this call changes the subject.
        self._on_credential_change()
        body = self._webauthn_finish_body(state_token, response, operation)
        request = self._session.sync_client.build_request("POST", path, json=body)
        http_response = self._session._send_sync(request)
        result = self._webauthn_login_result(http_response, operation)
        # The server sets the same axiam_access/axiam_refresh/axiam_csrf triple
        # here as it does on a password login, so adoption is the same call.
        self._absorb_session_cookies()
        return result

    # ------------------------------------------------------------------
    # §25 Account lifecycle and MFA enrolment
    # ------------------------------------------------------------------

    def mfa_enroll(self) -> MfaEnrollment:
        """``POST /api/v1/auth/mfa/enroll`` (CONTRACT.md §25.1) — start
        voluntary TOTP enrolment for the signed-in user.

        Changes nothing about the current session. In particular it does
        **not** clear the §17 decision memo: the subject has not changed, and
        discarding a warm memo on an unrelated profile action costs a round
        trip on every check that follows (§25.2 rule 3).
        """
        self._ensure_open()
        request = self._session.sync_client.build_request("POST", self._AC_MFA_ENROLL, json={})
        return self._mfa_enrollment(self._session._send_sync(request), "mfa_enroll")

    def mfa_confirm(self, *, totp_code: str) -> bool:
        """``POST /api/v1/auth/mfa/confirm`` (CONTRACT.md §25.1) — activate the
        factor :meth:`mfa_enroll` offered."""
        self._ensure_open()
        request = self._session.sync_client.build_request(
            "POST", self._AC_MFA_CONFIRM, json={"totp_code": totp_code}
        )
        return self._mfa_confirmed(self._session._send_sync(request))

    def mfa_setup_enroll(self, *, setup_token: SecretStr | str) -> MfaEnrollment:
        """``POST /api/v1/auth/mfa/setup/enroll`` (CONTRACT.md §25.1) — start
        the enrolment a ``login()`` demanded.

        Reached when ``login()`` returns ``mfa_setup_required``: the tenant
        requires MFA and this account has none. There is no session yet — the
        setup token *is* the credential.
        """
        self._ensure_open()
        request = self._session.sync_client.build_request(
            "POST", self._AC_MFA_SETUP_ENROLL, json={"setup_token": _expose_token(setup_token)}
        )
        return self._mfa_enrollment(self._session._send_sync(request), "mfa_setup_enroll")

    def mfa_setup_confirm(self, *, setup_token: SecretStr | str, totp_code: str) -> LoginResult:
        """``POST /api/v1/auth/mfa/setup/confirm`` (CONTRACT.md §25.1) — finish
        forced enrolment and, with it, the login that was interrupted.

        Adopts credentials exactly as ``login()`` does, because it *is* the
        completion of a login (§25.2 rule 2).
        """
        self._ensure_open()
        self._on_credential_change()
        request = self._session.sync_client.build_request(
            "POST",
            self._AC_MFA_SETUP_CONFIRM,
            json={"setup_token": _expose_token(setup_token), "totp_code": totp_code},
        )
        return self._handle_login_response(self._session._send_sync(request))

    def verify_email(self, *, token: SecretStr | str, tenant_id: str) -> None:
        """``POST /api/v1/auth/verify-email`` (CONTRACT.md §25.1).

        Unauthenticated: a user whose address is unverified may have no session
        at all. ``tenant_id`` is a **body** field here — this is not an
        ``/oauth2/*`` endpoint, so §12.1 rule 2's query-parameter convention
        does not reach it.
        """
        self._ensure_open()
        request = self._session.sync_client.build_request(
            "POST",
            self._AC_VERIFY_EMAIL,
            json={"token": _expose_token(token), "tenant_id": tenant_id},
        )
        self._expect_no_content(self._session._send_sync(request), "verify_email")

    def resend_verification(self, *, email: str, tenant_id: str) -> None:
        """``POST /api/v1/auth/resend-verification`` (CONTRACT.md §25.1)."""
        self._ensure_open()
        request = self._session.sync_client.build_request(
            "POST", self._AC_RESEND_VERIFICATION, json={"email": email, "tenant_id": tenant_id}
        )
        self._expect_no_content(self._session._send_sync(request), "resend_verification")

    def request_password_reset(
        self,
        *,
        email: str,
        org_slug: str | None = None,
        tenant_id: str | None = None,
        tenant_slug: str | None = None,
    ) -> None:
        """``POST /api/v1/auth/reset`` (CONTRACT.md §25.1) — ask for a reset
        mail.

        **Returns normally whether or not the address exists**, and this SDK
        exposes no way to tell the two apart. That is not an omission to
        improve on: a client that surfaced a "no such user" state — even one
        inferred from timing — would turn the endpoint into the account
        enumeration oracle its uniform response exists to prevent (§25.4).
        """
        self._ensure_open()
        body = self._password_reset_body(
            email=email, org_slug=org_slug, tenant_id=tenant_id, tenant_slug=tenant_slug
        )
        request = self._session.sync_client.build_request("POST", self._AC_RESET, json=body)
        self._expect_no_content(self._session._send_sync(request), "request_password_reset")

    def password_reset_context(self, *, token: SecretStr | str) -> PasswordResetContext:
        """``GET /api/v1/auth/reset/context`` (CONTRACT.md §25.1) — the OPAQUE
        policy for the account a reset token belongs to.

        Call this before :meth:`confirm_password_reset` on any tenant that
        might have §23 enabled: the client has to build a registration record,
        and building one needs parameters it cannot know before it has a token
        to ask with. Sending a plaintext password to a tenant in
        ``opaque_mode: required`` is refused, and refused late (§25.4 rule 1).
        """
        self._ensure_open()
        request = self._session.sync_client.build_request(
            "GET", self._AC_RESET_CONTEXT, params={"token": _expose_token(token)}
        )
        return self._reset_context(self._session._send_sync(request))

    def confirm_password_reset(
        self,
        *,
        token: SecretStr | str,
        new_password: SecretStr | str,
        tenant_id: str,
        opaque: dict[str, Any] | None = None,
    ) -> None:
        """``POST /api/v1/auth/reset/confirm`` (CONTRACT.md §25.1)."""
        self._ensure_open()
        body = self._password_reset_confirm_body(
            token=token, new_password=new_password, tenant_id=tenant_id, opaque=opaque
        )
        request = self._session.sync_client.build_request("POST", self._AC_RESET_CONFIRM, json=body)
        self._expect_no_content(self._session._send_sync(request), "confirm_password_reset")


def _expose_token(value: SecretStr | str) -> str:
    """Unwrap a ``SecretStr`` at the point of handing it to the transport."""
    return value.get_secret_value() if isinstance(value, SecretStr) else value


def _null_logger() -> logging.Logger:
    """An injectable stdlib logger with a NullHandler attached, OFF by
    default (D-15) — silent unless the consuming app configures logging."""
    logger = logging.getLogger("axiam_sdk")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger
