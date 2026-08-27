"""AsyncAxiamClient — the AXIAM SDK's dedicated async REST surface (SDK-Q08).

A SEPARATE class from the sync :class:`~axiam_sdk.AxiamClient` (D-01/D-19,
CONTRACT.md §1 note on SDK-Q08's ruling): exposes the canonical operation
names (``login``, ``verify_mfa``, ``refresh``, ``logout``, ``check_access``,
``can``, ``batch_check``) as ``async def`` — NOT as ``async_*`` twins on the
sync client. Shares :class:`axiam_sdk._client._AxiamClientBase`'s
construction/body-building/response-parsing logic (one ``_Session``: cookie
jar, CSRF state, tenant/org context, refresh guard) with ``AxiamClient``; only
the transport (async httpx client) and the single-flight async refresh-guard
call path are specific to this class. Mirrors ``the Go SDK's client.go`` +
``the Go SDK's login.go`` + ``the Go SDK's authz.go``, adapted to Python's async idiom.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, cast

import httpx
from pydantic import SecretStr

from axiam_sdk._account import MfaEnrollment, PasswordResetContext
from axiam_sdk._client import (
    ACCESS_COOKIE,
    BATCH_CHECK_PATH,
    CHECK_PATH,
    LOGIN_PATH,
    LOGOUT_PATH,
    MFA_VERIFY_PATH,
    OPAQUE_LOGIN_FINISH_PATH,
    OPAQUE_LOGIN_START_PATH,
    OPAQUE_REGISTER_START_PATH,
    _AxiamClientBase,
    _expose_token,
)
from axiam_sdk._decision_memo import memo_key
from axiam_sdk._errors import AuthError, error_from_http_status, error_from_oauth2_response
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
)
from axiam_sdk._retry import retry_async
from axiam_sdk._webauthn import (
    WebauthnChallenge,
    WebauthnCredential,
    WebauthnLoginResult,
    WebauthnWorkspace,
)
from axiam_sdk.management.ops import AsyncManagementNamespaces


class AsyncAxiamClient(_AxiamClientBase, AsyncManagementNamespaces):
    """The AXIAM SDK's dedicated async REST entry point (CONTRACT.md §1-§10,
    SDK-Q08).

    ``await client.login(...)`` returns a typed
    :class:`~axiam_sdk._models.LoginResult` with ``mfa_required`` (SC#1) — the
    same contract as the sync :class:`~axiam_sdk.AxiamClient`, on its own
    dedicated async object. Constructing both an ``AxiamClient`` and an
    ``AsyncAxiamClient`` against the same ``base_url``/``tenant_slug`` gives
    each its own independent ``_Session`` (cookie jar, CSRF state, refresh
    guard) — the two classes do NOT share session state with each other, only
    each shares consistently within its own sync or async call path.
    """

    # ------------------------------------------------------------------
    # Lifecycle (D-19)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> AsyncAxiamClient:
        """Async context-manager entry — returns ``self`` (D-19); no
        separate setup beyond what ``__init__`` already did."""
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """Async context-manager exit — always calls :meth:`aclose`,
        regardless of whether the ``async with`` block raised (D-19)."""
        await self.aclose()

    async def aclose(self) -> None:
        """Release this client's local resources (D-19, CONTRACT.md §18).

        Idempotent — calling it twice is not an error. Cleanup runs from error
        paths, and an error path that itself raises hides the original failure.

        **This does not log out.** §18.1 rule 5: shutting down a client releases
        *local* resources and never reaches the network. The server-side session
        deliberately outlives the client object, which is what lets a process
        restart and resume; an ``aclose()`` that logged out would silently end
        every user's session on each deploy. Call :meth:`logout` first if
        ending the session is what you want.

        After this returns, any operation on the client raises ``NetworkError``
        rather than silently reconnecting.
        """
        self._closed = True
        self._decision_memo.clear()
        await self._session.aclose()

    # ------------------------------------------------------------------
    # login / verify_mfa
    # ------------------------------------------------------------------

    async def login(self, email: str, password: str) -> LoginResult:
        """``POST /api/v1/auth/login`` (CONTRACT.md §1). Returns a typed
        :class:`LoginResult`; check ``mfa_required`` before assuming the
        session is established (SC#1)."""
        self._ensure_open()
        self._on_credential_change()
        request = self._session.async_client.build_request(
            "POST", LOGIN_PATH, json=self._login_body(email, password)
        )
        response = await self._session._send_async(request)
        return self._handle_login_response(response)

    async def login_opaque(self, username_or_email: str, password: str) -> LoginResult:
        """OPAQUE login (CONTRACT.md §23) — the password never leaves this process.

        The async twin of :meth:`AxiamClient.login_opaque`; see that method for
        the full contract — including what the ``login/start`` response's
        ``mode`` field decides after a failed exchange (§23.4 rule 7): under
        ``"optional"`` this retries over :meth:`login` and returns that call's
        outcome, and under ``"required"``, an unrecognised value or no ``mode``
        at all it raises :class:`AuthError` and retries nothing. Returns the
        same :class:`LoginResult` as :meth:`login`, including the
        ``mfa_required`` case.

        The key-stretching function runs on the event loop thread and blocks it:
        Argon2id at 19 MiB by default is tens to hundreds of milliseconds. In a
        server handling other requests concurrently, wrap the call in
        :func:`asyncio.to_thread`.
        """
        from ._opaque import OpaqueLoginStart, start_login

        self._ensure_open()
        self._on_credential_change()

        exchange = start_login(password)

        request = self._session.async_client.build_request(
            "POST",
            OPAQUE_LOGIN_START_PATH,
            json=self._opaque_login_start_body(username_or_email, exchange.ke1),
        )
        response = await self._session._send_async(request)
        if response.status_code != httpx.codes.OK:
            raise self._opaque_start_error(response, "login/start")
        started = OpaqueLoginStart.from_wire(response.json())

        try:
            ke3 = self._opaque_finish_login(exchange, started, password)
        except AuthError:
            # §23.4 rule 7, decided identically to the sync client — the shared
            # `allows_password_fallback` is what keeps the two from drifting.
            if not started.allows_password_fallback:
                raise
            return await self.login(username_or_email, password)

        request = self._session.async_client.build_request(
            "POST",
            OPAQUE_LOGIN_FINISH_PATH,
            json={"opaque_session": started.opaque_session, "ke3": ke3},
        )
        response = await self._session._send_async(request)
        if response.status_code not in (httpx.codes.OK, httpx.codes.ACCEPTED):
            raise error_from_http_status(response.status_code, "OPAQUE login/finish failed")
        return self._handle_login_response(response)

    async def opaque_enrollment(self, password: str) -> dict[str, Any]:
        """Build a registration record for *password*.

        The async twin of :meth:`AxiamClient.opaque_enrollment`; see that method
        for the full contract.
        """
        from ._opaque import KsfParams, start_registration

        self._ensure_open()
        exchange = start_registration(password)

        request = self._session.async_client.build_request(
            "POST",
            OPAQUE_REGISTER_START_PATH,
            json=self._opaque_register_start_body(exchange.request),
        )
        response = await self._session._send_async(request)
        if response.status_code != httpx.codes.OK:
            raise self._opaque_start_error(response, "register/start")
        started = response.json()

        return {
            "opaque_session": started["opaque_session"],
            "registration_record": exchange.finish(
                password, started["registration_response"], KsfParams.from_wire(started)
            ),
        }

    async def verify_mfa(self, mfa_token: Any, code: str) -> LoginResult:
        """``POST /api/v1/auth/mfa/verify`` (CONTRACT.md §1) — completes the
        two-phase flow started by :meth:`login` when ``mfa_required`` was
        true."""
        self._ensure_open()
        self._on_credential_change()
        request = self._session.async_client.build_request(
            "POST", MFA_VERIFY_PATH, json=self._mfa_verify_body(mfa_token, code)
        )
        response = await self._session._send_async(request)
        return self._handle_login_response(response)

    # ------------------------------------------------------------------
    # refresh — exactly one literal /api/v1/auth/refresh POST, routed
    # through the single-flight guard (Pitfall 4, §9.3)
    # ------------------------------------------------------------------

    async def refresh(self) -> None:
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
        await self._session.refresh_guard.refresh_if_needed_async(
            observed_access, lambda: self._do_refresh_async(tenant_id, org_id)
        )

    async def _do_refresh_async(self, tenant_id: str, org_id: str) -> dict[str, Any]:
        """Perform the actual ``POST /api/v1/auth/refresh`` call — the
        ``do_refresh`` closure passed to
        :meth:`~axiam_sdk.token.refresh_guard.RefreshGuard.refresh_if_needed_async`
        by :meth:`refresh`. Not called directly by SDK users; always routed
        through the single-flight guard so concurrent 401s collapse into
        one in-flight call (§9)."""
        # The literal /api/v1/auth/refresh path is required so the
        # Path-scoped axiam_refresh cookie attaches (Pitfall 4).
        request = self._session.async_client.build_request(
            "POST", "/api/v1/auth/refresh", json=self._refresh_body(tenant_id, org_id)
        )
        response = await self._session._send_async(request)
        return self._handle_refresh_response(response)

    # ------------------------------------------------------------------
    # logout
    # ------------------------------------------------------------------

    async def logout(self) -> None:
        """``POST /api/v1/auth/logout`` (CONTRACT.md §1)."""
        self._ensure_open()
        self._on_credential_change()
        session_id = self._session_id_for_logout()
        request = self._session.async_client.build_request(
            "POST", LOGOUT_PATH, json={"session_id": session_id}
        )
        response = await self._session._send_async(request)
        if response.status_code >= 300:
            raise error_from_http_status(response.status_code, "logout failed", response=response)
        self._session.refresh_guard = type(self._session.refresh_guard)()

    # ------------------------------------------------------------------
    # REST authz: check_access / can / batch_check
    # ------------------------------------------------------------------

    async def check_access(
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
        declarative ``require_access`` helper (§11) passes to check the
        *request's* authenticated user rather than this client's own
        (often service-account) session.
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
        wire = await self._authz_post_async(CHECK_PATH, body, operation="check_access")
        result = AccessResult(**wire)

        # Only a decision the server actually returned is memoized: reaching
        # here means success, so §17.1 rule 7's ban on caching a failure is
        # structural rather than a check that could be forgotten.
        self._decision_memo.set(key, result)
        return result

    async def can(self, action: str, resource_id: str, scope: str | None = None) -> bool:
        """Alias for ``check_access`` returning only the allowed boolean
        (CONTRACT.md §1 note, browser/UI scenarios)."""
        result = await self.check_access(action, resource_id, scope)
        return result.allowed

    async def batch_check(self, checks: list[AccessCheck]) -> list[AccessResult]:
        """``POST /api/v1/authz/check/batch`` (CONTRACT.md §1) — results
        returned in the same order as ``checks``."""
        body = {"checks": [c.model_dump(exclude_none=True) for c in checks]}
        wire = await self._authz_post_async(BATCH_CHECK_PATH, body, operation="batch_check")
        return BatchCheckResult(**wire).results

    async def _authz_post_async(
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
        return await retry_async(
            lambda attempt: self._authz_post_async_once(path, body, operation, attempt),
            operation=operation,
            enabled=self._retry_enabled,
            telemetry=self._telemetry,
        )

    async def _authz_post_async_once(
        self, path: str, body: dict[str, Any], operation: str, attempt: int
    ) -> dict[str, Any]:
        """One §16 attempt, with its §19 request pair."""
        request = self._session.async_client.build_request("POST", path, json=body)
        with self._telemetry.request(operation, "POST", path, attempt) as span:
            response = await self._session._send_async(request)

            if response.status_code == httpx.codes.UNAUTHORIZED:
                response = await self._retry_after_refresh_async(request)

            span.status = response.status_code
            if response.status_code < 200 or response.status_code >= 300:
                raise error_from_http_status(
                    response.status_code, "authz check failed", response=response
                )
            span.outcome = "success"
            result: dict[str, Any] = response.json()
            return result

    async def _retry_after_refresh_async(self, original_request: httpx.Request) -> httpx.Response:
        """On a 401, refresh exactly once (via the shared single-flight
        guard) then retry the failed authz call exactly once. A second
        failure propagates through the caller's own status check (§9.3, no
        retry loop)."""
        await self.refresh()
        retry_request = self._session.async_client.build_request(
            original_request.method,
            original_request.url,
            content=original_request.content,
            headers={
                k: v
                for k, v in original_request.headers.items()
                if k.lower() not in ("content-length", "x-csrf-token")
            },
        )
        return await self._session._send_async(retry_request)

    # ------------------------------------------------------------------
    # OIDC / SSO relying-party helpers (CONTRACT.md §12, Task T3, SDK-Q08)
    # ------------------------------------------------------------------

    async def oidc_discover(self) -> OidcConfiguration:
        """``GET /.well-known/openid-configuration`` (CONTRACT.md §12.1) —
        fetch the OIDC discovery document, cached per origin with a
        ≥5-minute TTL and single-flight de-duplication of concurrent calls
        (§12.3 rule 6)."""

        async def fetch() -> OidcConfiguration:
            """Perform the actual discovery-document GET; called by the
            discovery cache at most once per cache miss/expiry."""
            request = self._session.async_client.build_request("GET", DISCOVERY_PATH)
            response = await self._session._send_async(request)
            return self._parse_discovery_response(response)

        return await self._discovery_cache.get_async(self._discovery_origin_key(), fetch)

    async def oidc_begin(
        self,
        *,
        configuration: OidcConfiguration,
        redirect_uri: str,
        scope: str | list[str] | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> AuthorizationRequest:
        """Build an authorization request (CONTRACT.md §12.1) — **pure
        local computation, no network I/O**; this ``async def`` has no
        internal ``await`` (CONTRACT.md §12.2's Python naming table gives
        ``oidc_begin`` no synchronous carve-out the way it does for C#).
        Nothing is stored: persist the returned ``state``, ``nonce``, and
        ``code_verifier`` yourself (§12.3 rule 1)."""
        return self._oidc_begin_impl(
            configuration=configuration,
            redirect_uri=redirect_uri,
            scope=scope,
            extra_params=extra_params,
        )

    async def oidc_par(
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
        config = configuration or await self.oidc_discover()
        form = self._par_form(request=request, redirect_uri=redirect_uri, scope=scope)
        url = self._par_url(config, tenant_id)
        http_request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(http_request)
        return self._build_pushed_request(response, configuration=config, request=request)

    async def oidc_exchange(
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
        config = configuration or await self.oidc_discover()
        form = self._exchange_form(
            code=code, code_verifier=code_verifier, redirect_uri=redirect_uri
        )
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(request)
        return self._handle_token_response(response, config, nonce)

    async def oidc_refresh(
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

        async def do_refresh() -> OidcTokenSet:
            """Perform the actual ``refresh_token`` grant call; run inside
            :meth:`~axiam_sdk.token.refresh_guard.RefreshGuard.run_exclusive_async`
            by ``under_guard``, and de-duplicated across concurrent callers
            by the single-flight coalescer below."""
            config = configuration or await self.oidc_discover()
            form = self._refresh_form(refresh_token=refresh_token, scope=scope)
            url = self._token_endpoint_url(config, tenant_id)
            request = self._session.async_client.build_request("POST", url, data=form)
            response = await self._session._send_async(request)
            # No nonce: rule 6 does not apply to a refresh-issued ID token.
            return self._handle_token_response(response, config, None)

        async def under_guard() -> OidcTokenSet:
            """Run ``do_refresh`` inside the shared §9 refresh-guard lock,
            so it can never interleave with a concurrent cookie-session
            :meth:`refresh` call."""
            token_set: OidcTokenSet = await self._session.refresh_guard.run_exclusive_async(
                do_refresh
            )
            return token_set

        result: OidcTokenSet = await self._oidc_refresh_single_flight_async.run(under_guard)
        return result

    async def login_client_credentials(
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
        config = configuration or await self.oidc_discover()
        form = self._client_credentials_form(scope=scope)
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(request)
        # No nonce: rule 6 does not apply to this grant.
        return self._handle_token_response(response, config, None)

    async def device_authorize(
        self,
        *,
        scope: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> DeviceAuthorization:
        """``POST /oauth2/device_authorization`` (CONTRACT.md §14.1) — start
        the device grant and obtain the code pair.

        **Unauthenticated by design**: a device that cannot show a browser also
        cannot hold a client secret, so this never sends ``client_secret`` and
        never refuses a client built without one.

        Async twin of :meth:`axiam_sdk.AxiamClient.device_authorize`; §14.4
        requires the same three names on both clients.
        """
        config = configuration or await self.oidc_discover()
        form = self._device_authorize_form(scope=scope)
        url = self._device_authorization_url(config, tenant_id)
        request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(request)
        if response.status_code != httpx.codes.OK:
            raise error_from_oauth2_response(
                response.status_code, response, "device authorization request failed"
            )
        return self._build_device_authorization(response.json())

    async def device_poll(
        self,
        *,
        device_code: SecretStr | str,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> OidcTokenSet:
        """``POST /oauth2/token`` with the device-code grant (§14.1) — **one**
        poll attempt.

        The five RFC 8628 §3.5 answers surface as ``OAuthProtocolError``,
        ``authorization_pending`` and ``slow_down`` included, so a hand-rolled
        loop sees exactly what :meth:`device_login` sees.
        """
        config = configuration or await self.oidc_discover()
        form = self._device_poll_form(device_code=device_code)
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(request)
        return self._handle_token_response(response, config, None)

    async def device_login(
        self,
        on_user_code: Callable[[DeviceAuthorization], None | Awaitable[None]],
        *,
        scope: str | None = None,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> OidcTokenSet:
        """The composed §14.3 helper: start the grant, hand the caller the
        user code, poll to completion.

        ``on_user_code`` is invoked — and **awaited when it returns an
        awaitable** — before the first poll (§14.3 rule 2). A device rendering
        a QR code may need to await a paint, and polling before that resolves
        would defeat the rule as surely as not calling back at all.

        Per §14.3 rule 4 (contract 1.7 errata) this SDK **returns** the token
        set rather than adopting it. Polling follows §14.2 — see the sync
        twin's docstring for the full rule set.
        """
        config = configuration or await self.oidc_discover()
        authorization = await self.device_authorize(
            scope=scope, tenant_id=tenant_id, configuration=config
        )

        # §14.3 rule 2 — before any polling.
        result = on_user_code(authorization)
        if isinstance(result, Awaitable):
            await result

        schedule = PollSchedule(authorization.interval, authorization.expires_in)
        while True:
            if not schedule.tick():
                raise self._device_expired_error()
            await asyncio.sleep(schedule.interval_seconds)
            try:
                return await self.device_poll(
                    device_code=authorization.device_code,
                    tenant_id=tenant_id,
                    configuration=config,
                )
            except Exception as exc:  # noqa: BLE001 - classified by §14.2
                outcome = self._device_poll_outcome(exc)
                if outcome in ("pending", "retry"):
                    continue
                if outcome == "slow_down":
                    schedule.slow_down()
                    continue
                raise

    async def token_exchange(
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
        """``POST /oauth2/token`` with the RFC 8693 grant (§15.1) — exchange a
        token for a **narrower** one.

        Async twin of :meth:`axiam_sdk.AxiamClient.token_exchange`; see that
        docstring for what this method deliberately refuses to do (no
        defaulted ``actor_token``, no auto-narrowing, no adoption) and for
        ``subject_token_type``, which reaches the external exchange of §15.7
        and is never inferred from the token.
        """
        config = configuration or await self.oidc_discover()
        form = self._token_exchange_form(
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            scopes=scopes,
            audience=audience,
            resource=resource,
        )
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(request)
        return self._handle_exchange_response(response)

    async def uma_register_resource(
        self, pat: SecretStr | str, resource: ResourceSet
    ) -> ResourceSet:
        """``POST /uma2/rreg/resource_set`` — register a resource set
        (CONTRACT.md §20.1).

        The returned ``id`` **is** the AXIAM resource id, directly usable as
        the ``resource_id`` of a later :meth:`uma_request_ticket`.
        """
        request = self._session.async_client.build_request(
            "POST",
            self._uma_protection_url("/uma2/rreg/resource_set"),
            json=self._uma_resource_payload(resource),
            headers=self._uma_protection_headers(pat),
        )
        response = await self._session._send_async(request)
        wire = self._handle_uma_protection_response(response, "uma resource registration failed")
        return self._resource_set_from_wire(wire)

    async def uma_read_resource(self, pat: SecretStr | str, resource_id: str) -> ResourceSet:
        """``GET /uma2/rreg/resource_set/{id}`` — read a resource set (§20.1)."""
        request = self._session.async_client.build_request(
            "GET",
            self._uma_protection_url(f"/uma2/rreg/resource_set/{resource_id}"),
            headers=self._uma_protection_headers(pat),
        )
        response = await self._session._send_async(request)
        wire = self._handle_uma_protection_response(response, "uma resource read failed")
        return self._resource_set_from_wire(wire)

    async def uma_update_resource(
        self, pat: SecretStr | str, resource_id: str, resource: ResourceSet
    ) -> ResourceSet:
        """``PUT /uma2/rreg/resource_set/{id}`` — replace a resource set (§20.1).

        **The scope list is replaced, not merged** (§20.2 rule 8). Whatever
        ``resource.resource_scopes`` holds becomes the complete declared set;
        omitting a scope removes it, which is how a resource server drops an
        authority. This method performs no read-before-write.
        """
        request = self._session.async_client.build_request(
            "PUT",
            self._uma_protection_url(f"/uma2/rreg/resource_set/{resource_id}"),
            json=self._uma_resource_payload(resource),
            headers=self._uma_protection_headers(pat),
        )
        response = await self._session._send_async(request)
        wire = self._handle_uma_protection_response(response, "uma resource update failed")
        return self._resource_set_from_wire(wire)

    async def uma_delete_resource(self, pat: SecretStr | str, resource_id: str) -> None:
        """``DELETE /uma2/rreg/resource_set/{id}`` — deregister (§20.1)."""
        request = self._session.async_client.build_request(
            "DELETE",
            self._uma_protection_url(f"/uma2/rreg/resource_set/{resource_id}"),
            headers=self._uma_protection_headers(pat),
        )
        response = await self._session._send_async(request)
        self._handle_uma_protection_response(response, "uma resource delete failed")

    async def uma_list_resources(self, pat: SecretStr | str) -> list[str]:
        """``GET /uma2/rreg/resource_set`` — list the ids **this client**
        registered (§20.1).

        Not the tenant's whole resource tree: a protection scope does not
        entitle a caller to enumerate it.
        """
        request = self._session.async_client.build_request(
            "GET",
            self._uma_protection_url("/uma2/rreg/resource_set"),
            headers=self._uma_protection_headers(pat),
        )
        response = await self._session._send_async(request)
        wire = self._handle_uma_protection_response(response, "uma resource list failed")
        return cast("list[str]", wire or [])

    async def uma_request_ticket(
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
        request = self._session.async_client.build_request(
            "POST",
            self._uma_protection_url("/uma2/perm"),
            json=body,
            headers=self._uma_protection_headers(pat),
        )
        response = await self._session._send_async(request)
        wire = cast(
            "dict[str, str]",
            self._handle_uma_protection_response(response, "uma ticket request failed"),
        )
        return SecretStr(wire["ticket"])

    async def uma_exchange_ticket(
        self,
        *,
        ticket: SecretStr | str,
        claim_token: SecretStr | str,
        tenant_id: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> RequestingPartyToken:
        """Async twin of :meth:`axiam_sdk.AxiamClient.uma_exchange_ticket`.

        ``POST /oauth2/token`` with the uma-ticket grant (§20.1) — exchange a
        ticket for an RPT.

        **This method never retries.** It issues exactly one request and is
        outside the §16 retry policy — not on ``5xx``, not on timeout, not on
        any transport failure (§20.2 rule 6). The ticket is consumed *before*
        the request is evaluated, so a failed exchange has already spent it: a
        retry cannot succeed, and under concurrency it is precisely the second
        concurrent redemption a server whose storage engine this SDK cannot
        attest may admit twice (ilpanich/axiam#302). On
        failure, request a **new** ticket.

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
        config = configuration or await self.oidc_discover()
        form = self._uma_ticket_form(ticket=ticket, claim_token=claim_token)
        url = self._token_endpoint_url(config, tenant_id)
        request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(request)
        return self._handle_rpt_response(response)

    async def logout_url(
        self,
        *,
        id_token: SecretStr | str,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
        configuration: OidcConfiguration | None = None,
    ) -> str:
        """Build the RP-initiated logout URL (§12.7.2).

        Async only because discovery may need fetching; the URL construction
        itself performs no I/O, and this does **not** clear the client's own
        session.
        """
        config = configuration or await self.oidc_discover()
        return self._logout_url_impl(
            config,
            id_token=id_token,
            post_logout_redirect_uri=post_logout_redirect_uri,
            state=state,
        )

    async def verify_logout_token(
        self,
        token: str,
        *,
        configuration: OidcConfiguration | None = None,
    ) -> VerifiedLogoutToken:
        """Verify a back-channel logout token (§12.7.3).

        Async twin of :meth:`axiam_sdk.AxiamClient.verify_logout_token`; see
        that docstring for the six checks and why each exists.
        """
        config = configuration or await self.oidc_discover()
        return self._verify_logout_token_impl(token, config)

    async def introspect(
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
        config = configuration or await self.oidc_discover()
        form = self._introspect_form(token=token, token_type_hint=token_type_hint)
        url = self._endpoint_url_for_introspect(config, tenant_id)
        request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(request)
        return self._handle_introspect_response(response)

    async def revoke(
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
        config = configuration or await self.oidc_discover()
        form = self._revoke_form(token=token, token_type_hint=token_type_hint)
        url = self._endpoint_url_for_revoke(config, tenant_id)
        request = self._session.async_client.build_request("POST", url, data=form)
        response = await self._session._send_async(request)
        self._handle_revoke_response(response)

    async def sso_start(
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
        request = self._session.async_client.build_request("POST", SSO_START_PATH, json=body)
        response = await self._session._send_async(request)
        return self._handle_sso_start_response(response)

    async def sso_complete(self, *, state: str, code: str) -> SsoCompleteResult:
        """``POST /api/v1/auth/federation/oidc/callback`` (CONTRACT.md
        §12.1) — step 2 of upstream SSO: consumes the single-use ``state``,
        provisions or links the user, and establishes the session via
        ``Set-Cookie`` (§4 cookie jar). §12.4 does not apply here — no ID
        token ever reaches the SDK on the federation path."""
        request = self._session.async_client.build_request(
            "POST", SSO_CALLBACK_PATH, json={"state": state, "code": code}
        )
        response = await self._session._send_async(request)
        return self._handle_sso_complete_response(response)

    # ------------------------------------------------------------------
    # §24 WebAuthn / passkeys — the relying-party layer (async twins)
    #
    # Python has no authenticator, so §24.6b's linked-API helper is
    # deliberately absent: §24.6b rule 2 forbids emulating one in software,
    # and a "credential" held in process memory is not a second factor. What
    # is here is the half that talks to AXIAM, plus §24.6a's JSON bridge —
    # which is what lets a Python service be the relying party for a ceremony
    # a handset ran.
    # ------------------------------------------------------------------

    async def webauthn_register_start(self) -> WebauthnChallenge:
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
        request = self._session.async_client.build_request("POST", self._WA_REGISTER_START, json={})
        response = await self._session._send_async(request)
        return self._webauthn_challenge(response, "webauthn_register_start")

    async def webauthn_register_finish(
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
        request = self._session.async_client.build_request(
            "POST", self._WA_REGISTER_FINISH, json=body
        )
        return self._webauthn_credential(await self._session._send_async(request))

    async def webauthn_authenticate_start(
        self, *, challenge_token: SecretStr | str
    ) -> WebauthnChallenge:
        """``POST /api/v1/auth/webauthn/authenticate/start`` (CONTRACT.md §24.1).

        The **second-factor** ceremony: it continues a ``login()`` that
        answered ``mfa_required`` with ``"webauthn"`` among its methods, and
        ``challenge_token`` is that result's ``mfa_token``.

        A different flow from :meth:`webauthn_discoverable_start`, not the same
        one with an optional argument — see §24.2 for why they cannot be
        merged.
        """
        self._ensure_open()
        request = self._session.async_client.build_request(
            "POST", self._WA_AUTH_START, json={"challenge_token": _expose_token(challenge_token)}
        )
        response = await self._session._send_async(request)
        return self._webauthn_challenge(response, "webauthn_authenticate_start")

    async def webauthn_authenticate_finish(
        self, *, state_token: SecretStr | str, response: dict[str, Any] | str
    ) -> WebauthnLoginResult:
        """``POST /api/v1/auth/webauthn/authenticate/finish`` (CONTRACT.md §24.1).

        Leaves this client authenticated (§24.3 rule 1). That is not §14.3's
        "MAY adopt" posture: ``device_login`` mints tokens a caller may want to
        route elsewhere, and this is the SDK's own primary authentication —
        returning a token set without adopting it would make a passkey sign-in
        the one way to log in that does not log you in.
        """
        return await self._webauthn_finish_async(
            self._WA_AUTH_FINISH, state_token, response, "webauthn_authenticate_finish"
        )

    async def webauthn_discoverable_start(
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
        request = self._session.async_client.build_request(
            "POST", self._WA_DISCOVERABLE_START, json=body
        )
        response = await self._session._send_async(request)
        return self._webauthn_challenge(response, "webauthn_discoverable_start")

    async def webauthn_discoverable_finish(
        self, *, state_token: SecretStr | str, response: dict[str, Any] | str
    ) -> WebauthnLoginResult:
        """``POST .../authenticate/discoverable/finish`` (CONTRACT.md §24.1).

        Leaves this client authenticated (§24.3). Unlike its username-bound
        twin, this fires the server's ``login.post_auth`` reactor hook (§22.5):
        there was no password step for the event to have been fired at.
        """
        return await self._webauthn_finish_async(
            self._WA_DISCOVERABLE_FINISH, state_token, response, "webauthn_discoverable_finish"
        )

    async def _webauthn_finish_async(
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
        request = self._session.async_client.build_request("POST", path, json=body)
        http_response = await self._session._send_async(request)
        result = self._webauthn_login_result(http_response, operation)
        # The server sets the same axiam_access/axiam_refresh/axiam_csrf triple
        # here as it does on a password login, so adoption is the same call.
        self._absorb_session_cookies()
        return result

    # ------------------------------------------------------------------
    # §25 Account lifecycle and MFA enrolment (async twins)
    # ------------------------------------------------------------------

    async def mfa_enroll(self) -> MfaEnrollment:
        """``POST /api/v1/auth/mfa/enroll`` (CONTRACT.md §25.1) — start
        voluntary TOTP enrolment for the signed-in user.

        Changes nothing about the current session. In particular it does
        **not** clear the §17 decision memo: the subject has not changed, and
        discarding a warm memo on an unrelated profile action costs a round
        trip on every check that follows (§25.2 rule 3).
        """
        self._ensure_open()
        request = self._session.async_client.build_request("POST", self._AC_MFA_ENROLL, json={})
        return self._mfa_enrollment(await self._session._send_async(request), "mfa_enroll")

    async def mfa_confirm(self, *, totp_code: str) -> bool:
        """``POST /api/v1/auth/mfa/confirm`` (CONTRACT.md §25.1) — activate the
        factor :meth:`mfa_enroll` offered."""
        self._ensure_open()
        request = self._session.async_client.build_request(
            "POST", self._AC_MFA_CONFIRM, json={"totp_code": totp_code}
        )
        return self._mfa_confirmed(await self._session._send_async(request))

    async def mfa_setup_enroll(self, *, setup_token: SecretStr | str) -> MfaEnrollment:
        """``POST /api/v1/auth/mfa/setup/enroll`` (CONTRACT.md §25.1) — start
        the enrolment a ``login()`` demanded.

        Reached when ``login()`` returns ``mfa_setup_required``: the tenant
        requires MFA and this account has none. There is no session yet — the
        setup token *is* the credential.
        """
        self._ensure_open()
        request = self._session.async_client.build_request(
            "POST", self._AC_MFA_SETUP_ENROLL, json={"setup_token": _expose_token(setup_token)}
        )
        return self._mfa_enrollment(await self._session._send_async(request), "mfa_setup_enroll")

    async def mfa_setup_confirm(
        self, *, setup_token: SecretStr | str, totp_code: str
    ) -> LoginResult:
        """``POST /api/v1/auth/mfa/setup/confirm`` (CONTRACT.md §25.1) — finish
        forced enrolment and, with it, the login that was interrupted.

        Adopts credentials exactly as ``login()`` does, because it *is* the
        completion of a login (§25.2 rule 2).
        """
        self._ensure_open()
        self._on_credential_change()
        request = self._session.async_client.build_request(
            "POST",
            self._AC_MFA_SETUP_CONFIRM,
            json={"setup_token": _expose_token(setup_token), "totp_code": totp_code},
        )
        return self._handle_login_response(await self._session._send_async(request))

    async def verify_email(self, *, token: SecretStr | str, tenant_id: str) -> None:
        """``POST /api/v1/auth/verify-email`` (CONTRACT.md §25.1).

        Unauthenticated: a user whose address is unverified may have no session
        at all. ``tenant_id`` is a **body** field here — this is not an
        ``/oauth2/*`` endpoint, so §12.1 rule 2's query-parameter convention
        does not reach it.
        """
        self._ensure_open()
        request = self._session.async_client.build_request(
            "POST",
            self._AC_VERIFY_EMAIL,
            json={"token": _expose_token(token), "tenant_id": tenant_id},
        )
        self._expect_no_content(await self._session._send_async(request), "verify_email")

    async def resend_verification(self, *, email: str, tenant_id: str) -> None:
        """``POST /api/v1/auth/resend-verification`` (CONTRACT.md §25.1) — the
        **unauthenticated** resend, for a caller with no session.

        **Returns normally whatever the outcome.** The address may not exist,
        may already be verified, or may be over the daily limit, and this
        answers identically in all of them, because it takes an address from an
        anonymous caller and anything else is an oracle for which addresses have
        accounts (§25.7).

        A caller that *is* signed in wants :meth:`resend_own_verification`,
        which says which of those happened. Do not reach for this one because it
        is the name you already knew.
        """
        self._ensure_open()
        request = self._session.async_client.build_request(
            "POST", self._AC_RESEND_VERIFICATION, json={"email": email, "tenant_id": tenant_id}
        )
        self._expect_no_content(await self._session._send_async(request), "resend_verification")

    async def resend_own_verification(self) -> None:
        """``POST /api/v1/users/me/resend-verification`` (CONTRACT.md
        §25.1, §25.7) — resend the **signed-in caller's own** verification mail,
        and say what happened.

        Takes no address. The server reads it off the caller's own record, and
        this signature deliberately offers no way to name a different one: a
        parameter here would let an authenticated session mail an arbitrary
        address.

        Unlike :meth:`resend_verification` this reports the outcome, because the
        caller is signed in to the account it is asking about and none of the
        outcomes tells it anything it did not already know:

        * returns — a token was minted and the mail **enqueued**. Delivery is
          asynchronous and can still fail at the provider; a queue that accepts
          everything in front of one that rejects it looks exactly like this
          succeeding.
        * :class:`~axiam_sdk.ConflictError` (from ``409``) — already verified,
          or the account is in a state that must not be sent a live token.
        * :class:`~axiam_sdk.NetworkError` (from ``429``) — the daily limit.

        §25.7 rule 2 forbids falling back to the unauthenticated endpoint on
        either of those, and this SDK does not: the fallback would turn both
        failures back into a normal return and restore the bug this operation
        exists to fix, with an extra round-trip.
        """
        self._ensure_open()
        request = self._session.async_client.build_request(
            "POST", self._AC_RESEND_OWN_VERIFICATION, json={}
        )
        self._expect_no_content(await self._session._send_async(request), "resend_own_verification")

    async def request_password_reset(
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
        request = self._session.async_client.build_request("POST", self._AC_RESET, json=body)
        self._expect_no_content(await self._session._send_async(request), "request_password_reset")

    async def password_reset_context(self, *, token: SecretStr | str) -> PasswordResetContext:
        """``GET /api/v1/auth/reset/context`` (CONTRACT.md §25.1) — the OPAQUE
        policy for the account a reset token belongs to.

        Call this before :meth:`confirm_password_reset` on any tenant that
        might have §23 enabled: the client has to build a registration record,
        and building one needs parameters it cannot know before it has a token
        to ask with. Sending a plaintext password to a tenant in
        ``opaque_mode: required`` is refused, and refused late (§25.4 rule 1).
        """
        self._ensure_open()
        request = self._session.async_client.build_request(
            "GET", self._AC_RESET_CONTEXT, params={"token": _expose_token(token)}
        )
        return self._reset_context(await self._session._send_async(request))

    async def confirm_password_reset(
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
        request = self._session.async_client.build_request(
            "POST", self._AC_RESET_CONFIRM, json=body
        )
        self._expect_no_content(await self._session._send_async(request), "confirm_password_reset")
