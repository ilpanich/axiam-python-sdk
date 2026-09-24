"""Sync + async gRPC authorization clients (D-12, CONTRACT.md §1/§1.1/§6/§9).

``AuthzGrpcClient`` (sync, ``grpcio``) and ``AsyncAuthzGrpcClient`` (async,
``grpc.aio``) both perform ``CheckAccess``/``BatchCheckAccess`` and the
gRPC-only ``GetUserInfo`` (``get_user_info``, CONTRACT.md §1.1) over a
strict-TLS channel (``_tls.build_channel_credentials``), with a sync-safe
auth/tenant interceptor (``_interceptor.py``) and exactly-once
UNAUTHENTICATED refresh-and-retry (§9.3) via a caller-supplied refresh
closure — this module never imports ``axiam_sdk._client`` (no import cycle,
mirrors ``the Go SDK's grpc/client.go``'s ``RefreshFunc`` decoupling).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import cast

import grpc
import grpc.aio
from pydantic import SecretStr

from axiam_sdk._errors import AuthError, error_from_grpc_status
from axiam_sdk._models import (
    AccessResult,
    RptPermission,
    TokenCnf,
    TokenIntrospection,
    TokenValidation,
    UserInfo,
)
from axiam_sdk.grpc._interceptor import AsyncAuthInterceptor, SyncAuthInterceptor
from axiam_sdk.grpc._tls import build_channel_credentials
from axiam_sdk.grpc.gen import (
    authorization_pb2,
    authorization_pb2_grpc,
    token_pb2,
    token_pb2_grpc,
    userinfo_pb2,
    userinfo_pb2_grpc,
)

# Sync refresh_fn: a zero-arg callable that performs the caller-owned
# single-flight refresh (§9) and returns once a fresh access token is
# cached. May be None, in which case UNAUTHENTICATED errors are mapped and
# returned immediately without a retry.
SyncRefreshFn = Callable[[], None]
# Async twin of SyncRefreshFn.
AsyncRefreshFn = Callable[[], Awaitable[None]]


def _to_wire(
    subject_id: str, action: str, resource_id: str, tenant_id: str, scope: str | None
) -> authorization_pb2.CheckAccessRequest:
    """Build a single ``CheckAccessRequest`` protobuf message, shared by
    both the single-check and batch-check call sites of both the sync and
    async clients. ``scope`` is left unset on the message entirely when
    ``None`` rather than set to an empty string."""
    wire = authorization_pb2.CheckAccessRequest(
        tenant_id=tenant_id,
        subject_id=subject_id,
        action=action,
        resource_id=resource_id,
    )
    if scope is not None:
        wire.scope = scope
    return wire


def _to_decision(
    response: authorization_pb2.CheckAccessResponse,
) -> AccessResult:
    """Map a ``CheckAccessResponse`` protobuf message to an
    :class:`~axiam_sdk._models.AccessResult`, shared by the single-check and
    batch-check call sites of both the sync and async clients.

    SDK-Q10 / CONTRACT.md §11.2 rule 9 (contract 1.19): read ``reason`` (field
    4), and fall back to the deprecated ``deny_reason`` (field 2) **only** when
    ``reason`` is absent. ``reason`` has explicit presence precisely so a
    client can tell a pre-SDK-Q10 server (refuses with ``reason`` unset and
    ``deny_reason`` populated) from an allow (nothing to say) — which is why
    the fallback is guarded by ``HasField`` rather than by truthiness. Both
    fields carry the identical string on a current server; ``deny_reason``
    is removed at AXIAM 2.0 and this fallback goes with it. Callers see one
    ``reason``, never two.

    An empty value on either field becomes ``None`` rather than ``""`` — the
    same rule ``reason_code`` follows below, and for the same reason: ``""``
    is a value callers could accidentally branch on.
    """
    reason = response.reason if response.HasField("reason") else response.deny_reason
    return AccessResult(
        allowed=response.allowed,
        reason=reason or None,
        # §11 rule 9. proto3 renders an unset `string` as "", so an older
        # server that never set field 3 is indistinguishable from one that
        # set it empty — both mean "no reason code", and both become None
        # rather than "" (a value callers could accidentally branch on).
        reason_code=response.reason_code or None,
    )


def _to_user_info(response: userinfo_pb2.GetUserInfoResponse) -> UserInfo:
    """Map a ``GetUserInfoResponse`` protobuf message to the typed
    :class:`~axiam_sdk._models.UserInfo` record (CONTRACT.md §1.1), shared by
    both the sync and async ``get_user_info`` call sites.

    ``sub``/``tenant_id``/``org_id`` are always present; the ``optional``
    ``email`` and ``preferred_username`` proto fields map to ``None`` when the
    server omitted them (scope-gated), distinguished from an empty string via
    ``HasField``."""
    return UserInfo(
        sub=response.sub,
        tenant_id=response.tenant_id,
        org_id=response.org_id,
        email=response.email if response.HasField("email") else None,
        preferred_username=(
            response.preferred_username if response.HasField("preferred_username") else None
        ),
    )


def _expose(value: SecretStr | str) -> str:
    """Unwrap a ``SecretStr`` at the point of handing it to the transport
    (§7) — a local one-shot rather than importing
    ``axiam_sdk._client._expose_token``, which this module's docstring
    already commits to never importing (no import cycle, D-12)."""
    return value.get_secret_value() if isinstance(value, SecretStr) else value


def _to_cnf(
    response: token_pb2.ValidateTokenResponse | token_pb2.IntrospectTokenResponse,
) -> TokenCnf | None:
    """Map a response's ``cnf`` sub-message to a typed
    :class:`~axiam_sdk._models.TokenCnf`, or ``None`` when the field was not
    set at all (CONTRACT.md §10.3 rule 3): absence of the whole ``cnf``
    message means unbound, distinct from a present-but-empty one (which
    :meth:`~axiam_sdk._models.TokenValidation.verify_possession` refuses,
    never reading as unconstrained). ``HasField`` is what tells the two
    apart — proto3 cannot distinguish an absent scalar from an empty one,
    but ``cnf`` is a message field, which has explicit presence.
    """
    if not response.HasField("cnf"):
        return None
    return TokenCnf(
        x5t_s256=response.cnf.x5t_s256 or None,
        jkt=response.cnf.jkt or None,
    )


def _to_validation(response: token_pb2.ValidateTokenResponse) -> TokenValidation:
    """Map a ``ValidateTokenResponse`` protobuf message to a typed
    :class:`~axiam_sdk._models.TokenValidation` (CONTRACT.md §1.1.1 rule 3)
    — every field the response defines, ``cnf`` included."""
    return TokenValidation(
        valid=response.valid,
        subject_id=response.subject_id or None,
        tenant_id=response.tenant_id or None,
        org_id=response.org_id or None,
        exp=response.exp or None,
        cnf=_to_cnf(response),
        token_type=response.token_type or None,
    )


def _to_introspection(response: token_pb2.IntrospectTokenResponse) -> TokenIntrospection:
    """Map an ``IntrospectTokenResponse`` protobuf message to a typed
    :class:`~axiam_sdk._models.TokenIntrospection` (CONTRACT.md §1.1.1
    rule 3) — the RFC 7662 set, ``cnf``, ``permissions`` and
    ``ext_exchange_iss`` included."""
    return TokenIntrospection(
        active=response.active,
        sub=response.sub or None,
        tenant_id=response.tenant_id or None,
        org_id=response.org_id or None,
        iss=response.iss or None,
        iat=response.iat or None,
        exp=response.exp or None,
        jti=response.jti or None,
        scope=response.scope or None,
        client_id=response.client_id or None,
        token_type=response.token_type or None,
        cnf=_to_cnf(response),
        permissions=tuple(
            RptPermission(
                resource_id=p.resource_id,
                resource_scopes=list(p.resource_scopes),
                exp=p.exp,
            )
            for p in response.permissions
        ),
        ext_exchange_iss=response.ext_exchange_iss or None,
    )


class AuthzGrpcClient:
    """Sync (``grpcio``) authorization client for ``CheckAccess``/
    ``BatchCheckAccess`` (CONTRACT.md §1).
    """

    def __init__(
        self,
        target: str,
        *,
        token_fn: Callable[[], str | None],
        tenant_id: str,
        refresh_fn: SyncRefreshFn | None = None,
        custom_ca: str | None = None,
        client_cert: str | bytes | None = None,
        client_key: str | bytes | None = None,
    ) -> None:
        """Open a strict-TLS secure channel to ``target`` with the
        auth/tenant interceptor installed.

        Args:
            target: The gRPC server address (``host:port``).
            token_fn: Non-blocking accessor for the current cached access
                token, forwarded to :class:`~axiam_sdk.grpc._interceptor.SyncAuthInterceptor`.
            tenant_id: Injected as ``x-tenant-id`` metadata on every call
                (CONTRACT.md §5).
            refresh_fn: Optional zero-arg callable performing the caller-
                owned single-flight refresh (§9); when ``None``, an
                UNAUTHENTICATED response is mapped and raised immediately
                with no retry.
            custom_ca: The sole *server*-trust override (§6) — a PEM CA
                bundle, or ``None`` for strict default verification.
            client_cert: Optional PEM client-certificate chain (``str`` or
                ``bytes``) presented for mTLS client authentication
                (CONTRACT.md §6.1); must be given together with
                ``client_key``.
            client_key: Optional PEM private key (``str`` or ``bytes``)
                matching ``client_cert`` (CONTRACT.md §6.1); secret material,
                never logged or exposed via a getter (§7).
        """
        self._tenant_id = tenant_id
        self._refresh_fn = refresh_fn
        # Retained for the get_user_info pre-flight token check (CONTRACT.md
        # §1.1.3) — a no-token call must raise AuthError client-side without a
        # wire call. This is a plain non-blocking cache read, same accessor the
        # interceptor holds; it MUST NOT touch the refresh lock (T-19-13).
        self._token_fn = token_fn

        credentials = build_channel_credentials(custom_ca, client_cert, client_key)
        interceptor = SyncAuthInterceptor(token_fn=token_fn, tenant_id=tenant_id)
        channel = grpc.secure_channel(target, credentials)
        self._channel = grpc.intercept_channel(channel, interceptor)
        # authorization_pb2_grpc.py / userinfo_pb2_grpc.py are generated code
        # with no .pyi stub for the service stub classes (only the message
        # types in the *_pb2.pyi are typed) — pre-existing gap from 19-01's
        # codegen, out of this plan's file scope.
        self._stub = authorization_pb2_grpc.AuthorizationServiceStub(  # type: ignore[no-untyped-call]
            self._channel
        )
        self._userinfo_stub = userinfo_pb2_grpc.UserInfoServiceStub(  # type: ignore[no-untyped-call]
            self._channel
        )
        self._token_stub = token_pb2_grpc.TokenServiceStub(  # type: ignore[no-untyped-call]
            self._channel
        )

    def close(self) -> None:
        """Close the underlying gRPC channel."""
        self._channel.close()

    def validate_token(self, access_token: SecretStr | str) -> TokenValidation:
        """``TokenService/ValidateToken`` — the gRPC-only token-validation
        operation (CONTRACT.md §1.1.1, §10.3, contract 1.51).

        *This client's own* bearer token authenticates the call, through the
        interceptor, exactly as every other RPC on this channel. ``access_token``
        is a **different** credential — the token being inspected — and
        travels in the request message; the two are never the same value by
        default (rule 1).

        A no-token call (this client's own) raises
        :class:`~axiam_sdk._errors.AuthError` client-side, **without** a wire
        call (§1.1 rule 3, via §1.1.1 rule 2) — the interceptor's
        UNAUTHENTICATED would otherwise send the call into the refresh guard
        with nothing to refresh. On UNAUTHENTICATED for the caller's own
        token, invokes the caller-supplied ``refresh_fn`` exactly once then
        retries the RPC exactly once (§9.3), sharing
        :meth:`check_access`'s single-flight-retry path.

        The returned :class:`~axiam_sdk._models.TokenValidation` carries
        **every** field the response defines, ``cnf`` included (rule 3):
        ``valid: true`` means the signature/expiry/tenant check out, and is
        **not** "usable as presented" — call
        :meth:`~axiam_sdk._models.TokenValidation.verify_possession` before
        trusting a result whose ``cnf`` is set (rule 4). A token from
        another tenant decodes as ``valid: False`` with the other fields
        empty, not an error (rule 6).
        """
        if not self._token_fn():
            raise AuthError("no access token available; call login() first")
        wire = token_pb2.ValidateTokenRequest(access_token=_expose(access_token))
        try:
            response = self._token_stub.ValidateToken(wire)
        except grpc.RpcError as exc:
            response = self._retry_after_refresh(exc, lambda: self._token_stub.ValidateToken(wire))
        return _to_validation(cast(token_pb2.ValidateTokenResponse, response))

    def introspect_token(self, access_token: SecretStr | str) -> TokenIntrospection:
        """``TokenService/IntrospectToken`` — the RFC 7662-shaped gRPC-only
        introspection operation (CONTRACT.md §1.1.1, §10.3, contract 1.51).
        See :meth:`validate_token` for the caller-token-vs-inspected-token
        rules, the pre-flight ``AuthError``, and the retry path, which are
        identical here.

        The returned :class:`~axiam_sdk._models.TokenIntrospection` carries
        the full RFC 7662 set plus ``cnf``, ``permissions`` (UMA 2.0, §20)
        and ``ext_exchange_iss`` (X4 cross-domain provenance) — every field
        the response defines (rule 3). ``active: true`` is **not** "usable
        as presented"; call
        :meth:`~axiam_sdk._models.TokenIntrospection.verify_possession`
        before trusting a result whose ``cnf`` is set (rule 4).
        """
        if not self._token_fn():
            raise AuthError("no access token available; call login() first")
        wire = token_pb2.IntrospectTokenRequest(access_token=_expose(access_token))
        try:
            response = self._token_stub.IntrospectToken(wire)
        except grpc.RpcError as exc:
            response = self._retry_after_refresh(
                exc, lambda: self._token_stub.IntrospectToken(wire)
            )
        return _to_introspection(cast(token_pb2.IntrospectTokenResponse, response))

    def check_access(
        self, subject_id: str, action: str, resource_id: str, scope: str | None = None
    ) -> AccessResult:
        """``CheckAccess`` (CONTRACT.md §1). On UNAUTHENTICATED, invokes the
        caller-supplied ``refresh_fn`` exactly once then retries the RPC
        exactly once (§9.3) — a second failure maps via
        ``error_from_grpc_status``."""
        wire = _to_wire(subject_id, action, resource_id, self._tenant_id, scope)
        try:
            response = self._stub.CheckAccess(wire)
        except grpc.RpcError as exc:
            response = self._retry_after_refresh(exc, lambda: self._stub.CheckAccess(wire))
        return _to_decision(response)

    def batch_check(self, checks: list[tuple[str, str, str, str | None]]) -> list[AccessResult]:
        """``BatchCheckAccess`` (CONTRACT.md §1). ``checks`` is a list of
        ``(subject_id, action, resource_id, scope)`` tuples; results are
        returned in the same order. Shares the same UNAUTHENTICATED
        single-flight-retry behavior as :meth:`check_access`."""
        wire = authorization_pb2.BatchCheckAccessRequest(
            requests=[
                _to_wire(subject_id, action, resource_id, self._tenant_id, scope)
                for subject_id, action, resource_id, scope in checks
            ]
        )
        try:
            response = self._stub.BatchCheckAccess(wire)
        except grpc.RpcError as exc:
            response = self._retry_after_refresh(exc, lambda: self._stub.BatchCheckAccess(wire))
        return [_to_decision(result) for result in response.results]

    def get_user_info(self) -> UserInfo:
        """``GetUserInfo`` — the gRPC-only userinfo operation (CONTRACT.md
        §1.1). Identity is derived server-side entirely from the bearer token
        the interceptor attaches (the request body is empty), so this takes no
        arguments and returns the caller's own :class:`~axiam_sdk._models.UserInfo`.

        A no-token call raises :class:`~axiam_sdk._errors.AuthError` client-side
        *without* a wire call (§1.1.3). On UNAUTHENTICATED it invokes the
        caller-supplied ``refresh_fn`` exactly once then retries the RPC exactly
        once (§9.3), sharing the same single-flight-retry path as
        :meth:`check_access`; any other status maps via
        ``error_from_grpc_status``."""
        if not self._token_fn():
            raise AuthError("no access token available; call login() first")
        wire = userinfo_pb2.GetUserInfoRequest()
        try:
            response = self._userinfo_stub.GetUserInfo(wire)
        except grpc.RpcError as exc:
            response = self._retry_after_refresh(exc, lambda: self._userinfo_stub.GetUserInfo(wire))
        return _to_user_info(response)

    def _retry_after_refresh(self, exc: grpc.RpcError, retry: Callable[[], object]) -> object:
        """On UNAUTHENTICATED (and only when a ``refresh_fn`` was supplied),
        call it exactly once, then invoke ``retry`` exactly once (§9.3).

        Any other status code — or a UNAUTHENTICATED with no ``refresh_fn``
        — is mapped and raised immediately via :meth:`_map_error`, with no
        retry. A second failure after the retry also raises via
        :meth:`_map_error`, chained from the retry's own exception.
        """
        call = cast(grpc.Call, exc)
        if self._refresh_fn is not None and call.code() == grpc.StatusCode.UNAUTHENTICATED:
            self._refresh_fn()
            try:
                return retry()
            except grpc.RpcError as retry_exc:
                raise self._map_error(retry_exc) from retry_exc
        raise self._map_error(exc) from exc

    def _map_error(self, exc: grpc.RpcError) -> Exception:
        """Map a raw ``grpc.RpcError`` to the ``AxiamError`` family via
        :func:`~axiam_sdk._errors.error_from_grpc_status` (CONTRACT.md §2),
        substituting a generic message when the server supplied no
        ``details()``."""
        call = cast(grpc.Call, exc)
        return error_from_grpc_status(call.code(), call.details() or "gRPC call failed")


class AsyncAuthzGrpcClient:
    """Async (``grpc.aio``) authorization client for ``CheckAccess``/
    ``BatchCheckAccess`` (CONTRACT.md §1) — a first-class async transport,
    not a thread-pool bridge over the sync client (D-12).
    """

    def __init__(
        self,
        target: str,
        *,
        token_fn: Callable[[], str | None],
        tenant_id: str,
        refresh_fn: AsyncRefreshFn | None = None,
        custom_ca: str | None = None,
        client_cert: str | bytes | None = None,
        client_key: str | bytes | None = None,
    ) -> None:
        """Async twin of :meth:`AuthzGrpcClient.__init__` — opens a
        strict-TLS ``grpc.aio`` secure channel to ``target`` with the async
        auth/tenant interceptor installed. Args are identical except
        ``refresh_fn`` is an async zero-arg callable; ``client_cert``/
        ``client_key`` opt into the same mTLS client identity (CONTRACT.md
        §6.1)."""
        self._tenant_id = tenant_id
        self._refresh_fn = refresh_fn
        # Retained for the get_user_info pre-flight token check (CONTRACT.md
        # §1.1.3); see the sync client's __init__ for the rationale.
        self._token_fn = token_fn

        credentials = build_channel_credentials(custom_ca, client_cert, client_key)
        interceptor = AsyncAuthInterceptor(token_fn=token_fn, tenant_id=tenant_id)
        self._channel = grpc.aio.secure_channel(target, credentials, interceptors=[interceptor])
        self._stub = authorization_pb2_grpc.AuthorizationServiceStub(  # type: ignore[no-untyped-call]
            self._channel
        )
        self._userinfo_stub = userinfo_pb2_grpc.UserInfoServiceStub(  # type: ignore[no-untyped-call]
            self._channel
        )
        self._token_stub = token_pb2_grpc.TokenServiceStub(  # type: ignore[no-untyped-call]
            self._channel
        )

    async def close(self) -> None:
        """Async twin of :meth:`AuthzGrpcClient.close` — closes the
        underlying ``grpc.aio`` channel."""
        await self._channel.close()

    async def validate_token(self, access_token: SecretStr | str) -> TokenValidation:
        """Async twin of :meth:`AuthzGrpcClient.validate_token`."""
        if not self._token_fn():
            raise AuthError("no access token available; call login() first")
        wire = token_pb2.ValidateTokenRequest(access_token=_expose(access_token))
        try:
            response = await self._token_stub.ValidateToken(wire)
        except grpc.RpcError as exc:
            response = await self._retry_after_refresh(
                exc, lambda: self._token_stub.ValidateToken(wire)
            )
        return _to_validation(cast(token_pb2.ValidateTokenResponse, response))

    async def introspect_token(self, access_token: SecretStr | str) -> TokenIntrospection:
        """Async twin of :meth:`AuthzGrpcClient.introspect_token`."""
        if not self._token_fn():
            raise AuthError("no access token available; call login() first")
        wire = token_pb2.IntrospectTokenRequest(access_token=_expose(access_token))
        try:
            response = await self._token_stub.IntrospectToken(wire)
        except grpc.RpcError as exc:
            response = await self._retry_after_refresh(
                exc, lambda: self._token_stub.IntrospectToken(wire)
            )
        return _to_introspection(cast(token_pb2.IntrospectTokenResponse, response))

    async def check_access(
        self, subject_id: str, action: str, resource_id: str, scope: str | None = None
    ) -> AccessResult:
        """Async twin of :meth:`AuthzGrpcClient.check_access`."""
        wire = _to_wire(subject_id, action, resource_id, self._tenant_id, scope)
        try:
            response = await self._stub.CheckAccess(wire)
        except grpc.RpcError as exc:
            response = await self._retry_after_refresh(exc, lambda: self._stub.CheckAccess(wire))
        return _to_decision(response)

    async def batch_check(
        self, checks: list[tuple[str, str, str, str | None]]
    ) -> list[AccessResult]:
        """Async twin of :meth:`AuthzGrpcClient.batch_check`."""
        wire = authorization_pb2.BatchCheckAccessRequest(
            requests=[
                _to_wire(subject_id, action, resource_id, self._tenant_id, scope)
                for subject_id, action, resource_id, scope in checks
            ]
        )
        try:
            response = await self._stub.BatchCheckAccess(wire)
        except grpc.RpcError as exc:
            response = await self._retry_after_refresh(
                exc, lambda: self._stub.BatchCheckAccess(wire)
            )
        return [_to_decision(result) for result in response.results]

    async def get_user_info(self) -> UserInfo:
        """Async twin of :meth:`AuthzGrpcClient.get_user_info` (CONTRACT.md
        §1.1) — pre-flight :class:`~axiam_sdk._errors.AuthError` on a no-token
        call (no wire call), else ``GetUserInfo`` over the shared channel with
        the same await-once-refresh / retry-once UNAUTHENTICATED path as
        :meth:`check_access`."""
        if not self._token_fn():
            raise AuthError("no access token available; call login() first")
        wire = userinfo_pb2.GetUserInfoRequest()
        try:
            response = await self._userinfo_stub.GetUserInfo(wire)
        except grpc.RpcError as exc:
            response = await self._retry_after_refresh(
                exc, lambda: self._userinfo_stub.GetUserInfo(wire)
            )
        return _to_user_info(response)

    async def _retry_after_refresh(
        self, exc: grpc.RpcError, retry: Callable[[], Awaitable[object]]
    ) -> object:
        """Async twin of :meth:`AuthzGrpcClient._retry_after_refresh` — on
        UNAUTHENTICATED (and only when a ``refresh_fn`` was supplied),
        awaits it exactly once, then awaits ``retry`` exactly once (§9.3);
        any other outcome maps and raises via :meth:`_map_error`."""
        aio_exc = cast(grpc.aio.AioRpcError, exc)
        if self._refresh_fn is not None and aio_exc.code() == grpc.StatusCode.UNAUTHENTICATED:
            await self._refresh_fn()
            try:
                return await retry()
            except grpc.RpcError as retry_exc:
                raise self._map_error(retry_exc) from retry_exc
        raise self._map_error(exc) from exc

    def _map_error(self, exc: grpc.RpcError) -> Exception:
        """Map a raw ``grpc.RpcError`` (as ``AioRpcError``) to the
        ``AxiamError`` family via
        :func:`~axiam_sdk._errors.error_from_grpc_status` (CONTRACT.md §2),
        substituting a generic message when the server supplied no
        ``details()``."""
        aio_exc = cast(grpc.aio.AioRpcError, exc)
        return error_from_grpc_status(aio_exc.code(), aio_exc.details() or "gRPC call failed")
