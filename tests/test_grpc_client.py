"""Regression tests for the sync + async gRPC authorization clients
(D-12, CONTRACT.md §1/§6/§9, T-19-12/T-19-14).

Stands up an in-process, self-signed-TLS ``AuthorizationService`` test
server (scriptable to return allowed/denied/UNAUTHENTICATED-once) and
asserts: sync AND async ``check_access``/``batch_check`` succeed over
strict TLS; an UNAUTHENTICATED-then-OK sequence calls ``refresh_fn``
exactly once and retries exactly once; ``PERMISSION_DENIED`` maps to
``AuthzError``; no insecure/TLS-skip channel is ever constructed.
"""

from __future__ import annotations

import datetime
import socket
from collections.abc import Iterator
from concurrent import futures

import grpc
import grpc.aio
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from axiam_sdk._errors import AuthError, AuthzError
from axiam_sdk.grpc.client import AsyncAuthzGrpcClient, AuthzGrpcClient
from axiam_sdk.grpc.gen import (
    authorization_pb2,
    authorization_pb2_grpc,
    userinfo_pb2,
    userinfo_pb2_grpc,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def _generate_self_signed_cert() -> tuple[bytes, bytes]:
    """Generate a throwaway self-signed cert/key pair for localhost, used
    ONLY to stand up the in-process TLS test server below — not a
    production credential."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


class _ScriptedServicer(authorization_pb2_grpc.AuthorizationServiceServicer):
    """A servicer whose CheckAccess/BatchCheckAccess responses (or
    UNAUTHENTICATED-once behavior) are scripted per test."""

    def __init__(self) -> None:
        self.unauthenticated_once = False
        self._already_failed_once = False
        self.deny_permission = False
        self.received_metadata: list[tuple[str, str]] = []
        self.last_request: authorization_pb2.CheckAccessRequest | None = None

    def CheckAccess(self, request, context):  # noqa: N802
        self.received_metadata = list(context.invocation_metadata() or [])
        self.last_request = request
        if self.unauthenticated_once and not self._already_failed_once:
            self._already_failed_once = True
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "token expired")
        if self.deny_permission:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "not allowed")
        allowed = request.action != "deny-me"
        return authorization_pb2.CheckAccessResponse(
            allowed=allowed, deny_reason="" if allowed else "policy denies"
        )

    def BatchCheckAccess(self, request, context):  # noqa: N802
        self.received_metadata = list(context.invocation_metadata() or [])
        if self.unauthenticated_once and not self._already_failed_once:
            self._already_failed_once = True
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "token expired")
        results = [
            authorization_pb2.CheckAccessResponse(
                allowed=r.action != "deny-me",
                deny_reason="" if r.action != "deny-me" else "policy denies",
            )
            for r in request.requests
        ]
        return authorization_pb2.BatchCheckAccessResponse(results=results)


class _UserInfoServicer(userinfo_pb2_grpc.UserInfoServiceServicer):
    """A scriptable ``UserInfoService`` servicer for the get_user_info tests
    (CONTRACT.md §1.1): controls which scope-gated optional claims are
    returned and can fail UNAUTHENTICATED exactly once to exercise the
    single-flight refresh-and-retry path."""

    def __init__(self) -> None:
        self.unauthenticated_once = False
        self._already_failed_once = False
        self.include_email = True
        self.include_username = True
        self.received_metadata: list[tuple[str, str]] = []

    def GetUserInfo(self, request, context):  # noqa: N802
        self.received_metadata = list(context.invocation_metadata() or [])
        if self.unauthenticated_once and not self._already_failed_once:
            self._already_failed_once = True
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "token expired")
        response = userinfo_pb2.GetUserInfoResponse(
            sub="user-uuid", tenant_id="tenant-uuid", org_id="org-uuid"
        )
        if self.include_email:
            response.email = "alice@example.com"
        if self.include_username:
            response.preferred_username = "alice"
        return response


class _TestServer:
    def __init__(self) -> None:
        self.servicer = _ScriptedServicer()
        self.userinfo_servicer = _UserInfoServicer()
        self.cert_pem, self.key_pem = _generate_self_signed_cert()
        self.port = _free_port()
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        authorization_pb2_grpc.add_AuthorizationServiceServicer_to_server(
            self.servicer, self.server
        )
        userinfo_pb2_grpc.add_UserInfoServiceServicer_to_server(self.userinfo_servicer, self.server)
        credentials = grpc.ssl_server_credentials([(self.key_pem, self.cert_pem)])
        self.server.add_secure_port(f"localhost:{self.port}", credentials)

    def start(self) -> None:
        self.server.start()

    def stop(self) -> None:
        self.server.stop(grace=None)

    @property
    def target(self) -> str:
        return f"localhost:{self.port}"


@pytest.fixture
def test_server() -> Iterator[_TestServer]:
    server = _TestServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _write_ca_file(tmp_path, cert_pem: bytes) -> str:
    ca_path = tmp_path / "test-ca.pem"
    ca_path.write_bytes(cert_pem)
    return str(ca_path)


class TestSyncAuthzGrpcClient:
    def test_check_access_allowed(self, test_server: _TestServer, tmp_path) -> None:
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "sync-token",
            tenant_id="tenant-1",
            custom_ca=ca_file,
        )
        try:
            result = client.check_access("user-1", "read", "resource-1")
            assert result.allowed is True
            assert result.reason is None
            assert ("authorization", "Bearer sync-token") in test_server.servicer.received_metadata
            assert ("x-tenant-id", "tenant-1") in test_server.servicer.received_metadata
        finally:
            client.close()

    def test_check_access_forwards_scope(self, test_server: _TestServer, tmp_path) -> None:
        # A non-None scope must be threaded onto the wire request (the
        # `_to_wire` scope branch).
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AuthzGrpcClient(
            test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
        )
        try:
            result = client.check_access("user-1", "read", "resource-1", scope="sub:1")
            assert result.allowed is True
            last = test_server.servicer.last_request
            assert last is not None
            assert last.scope == "sub:1"
        finally:
            client.close()

    def test_check_access_denied(self, test_server: _TestServer, tmp_path) -> None:
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AuthzGrpcClient(
            test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
        )
        try:
            result = client.check_access("user-1", "deny-me", "resource-1")
            assert result.allowed is False
            assert result.reason == "policy denies"
        finally:
            client.close()

    def test_batch_check(self, test_server: _TestServer, tmp_path) -> None:
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AuthzGrpcClient(
            test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
        )
        try:
            results = client.batch_check(
                [
                    ("user-1", "read", "resource-1", None),
                    ("user-1", "deny-me", "resource-2", None),
                ]
            )
            assert results[0].allowed is True
            assert results[1].allowed is False
        finally:
            client.close()

    def test_unauthenticated_triggers_exactly_one_refresh_and_one_retry(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        test_server.servicer.unauthenticated_once = True
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)

        refresh_calls = 0

        def refresh_fn() -> None:
            nonlocal refresh_calls
            refresh_calls += 1

        client = AuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "tok",
            tenant_id="t1",
            refresh_fn=refresh_fn,
            custom_ca=ca_file,
        )
        try:
            result = client.check_access("user-1", "read", "resource-1")
            assert result.allowed is True
            assert refresh_calls == 1, "refresh_fn must be called exactly once"
        finally:
            client.close()

    def test_permission_denied_maps_to_authz_error(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        test_server.servicer.deny_permission = True
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AuthzGrpcClient(
            test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
        )
        try:
            with pytest.raises(AuthzError):
                client.check_access("user-1", "read", "resource-1")
        finally:
            client.close()

    def test_untrusted_server_certificate_is_rejected(self, test_server: _TestServer) -> None:
        """WR-05 (negative TLS path): with NO custom_ca supplied, the client
        verifies against the SYSTEM trust store, which does NOT contain the
        test server's throwaway self-signed cert — so the TLS handshake MUST
        fail. This proves build_channel_credentials/ssl_channel_credentials
        actually performs verification (not a no-op): a regression that
        silently disabled verification would let this RPC succeed, and the
        test would catch it.
        """
        client = AuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "tok",
            tenant_id="t1",
            custom_ca=None,  # <-- deliberately NOT trusting the self-signed cert
        )
        try:
            with pytest.raises(grpc.RpcError) as exc_info:
                # Short deadline so a verification failure surfaces promptly as
                # UNAVAILABLE rather than the test hanging on retries.
                client._stub.CheckAccess(
                    authorization_pb2.CheckAccessRequest(
                        tenant_id="t1", subject_id="u", action="read", resource_id="r"
                    ),
                    timeout=5,
                )
            # A TLS handshake failure surfaces as UNAVAILABLE (transport
            # failure), never OK — the connection must NOT be established.
            assert exc_info.value.code() == grpc.StatusCode.UNAVAILABLE
        finally:
            client.close()

    def test_get_user_info_maps_all_claims(self, test_server: _TestServer, tmp_path) -> None:
        # Full claim set (email + profile scopes present): all five fields map
        # onto UserInfo, and the auth/tenant metadata reaches the server
        # (CONTRACT.md §1.1.2/§1.1.5).
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "sync-token",
            tenant_id="tenant-1",
            custom_ca=ca_file,
        )
        try:
            info = client.get_user_info()
            assert info.sub == "user-uuid"
            assert info.tenant_id == "tenant-uuid"
            assert info.org_id == "org-uuid"
            assert info.email == "alice@example.com"
            assert info.preferred_username == "alice"
            meta = test_server.userinfo_servicer.received_metadata
            assert ("authorization", "Bearer sync-token") in meta
            assert ("x-tenant-id", "tenant-1") in meta
        finally:
            client.close()

    def test_get_user_info_absent_optionals_map_to_none(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        # Neither the email nor profile scope present: the optional proto
        # fields are unset and MUST map to None (not "") — CONTRACT.md §1.1.5.
        test_server.userinfo_servicer.include_email = False
        test_server.userinfo_servicer.include_username = False
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AuthzGrpcClient(
            test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
        )
        try:
            info = client.get_user_info()
            assert info.sub == "user-uuid"
            assert info.email is None
            assert info.preferred_username is None
        finally:
            client.close()

    def test_get_user_info_no_token_raises_without_wire_call(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        # Pre-flight: a no-token call MUST raise AuthError client-side without
        # ever reaching the server (CONTRACT.md §1.1.3).
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AuthzGrpcClient(
            test_server.target, token_fn=lambda: None, tenant_id="t1", custom_ca=ca_file
        )
        try:
            with pytest.raises(AuthError):
                client.get_user_info()
            assert test_server.userinfo_servicer.received_metadata == []
        finally:
            client.close()

    def test_get_user_info_unauthenticated_triggers_exactly_one_refresh_and_one_retry(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        test_server.userinfo_servicer.unauthenticated_once = True
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)

        refresh_calls = 0

        def refresh_fn() -> None:
            nonlocal refresh_calls
            refresh_calls += 1

        client = AuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "tok",
            tenant_id="t1",
            refresh_fn=refresh_fn,
            custom_ca=ca_file,
        )
        try:
            info = client.get_user_info()
            assert info.sub == "user-uuid"
            assert refresh_calls == 1, "refresh_fn must be called exactly once"
        finally:
            client.close()


class TestAsyncAuthzGrpcClient:
    @pytest.mark.asyncio
    async def test_check_access_allowed(self, test_server: _TestServer, tmp_path) -> None:
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AsyncAuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "async-token",
            tenant_id="tenant-2",
            custom_ca=ca_file,
        )
        try:
            result = await client.check_access("user-1", "read", "resource-1")
            assert result.allowed is True
            assert ("authorization", "Bearer async-token") in test_server.servicer.received_metadata
            assert ("x-tenant-id", "tenant-2") in test_server.servicer.received_metadata
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_batch_check(self, test_server: _TestServer, tmp_path) -> None:
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AsyncAuthzGrpcClient(
            test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
        )
        try:
            results = await client.batch_check(
                [
                    ("user-1", "read", "resource-1", None),
                    ("user-1", "deny-me", "resource-2", None),
                ]
            )
            assert results[0].allowed is True
            assert results[1].allowed is False
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_unauthenticated_triggers_exactly_one_refresh_and_one_retry(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        test_server.servicer.unauthenticated_once = True
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)

        refresh_calls = 0

        async def refresh_fn() -> None:
            nonlocal refresh_calls
            refresh_calls += 1

        client = AsyncAuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "tok",
            tenant_id="t1",
            refresh_fn=refresh_fn,
            custom_ca=ca_file,
        )
        try:
            result = await client.check_access("user-1", "read", "resource-1")
            assert result.allowed is True
            assert refresh_calls == 1, "refresh_fn must be called exactly once"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_permission_denied_maps_to_authz_error(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        test_server.servicer.deny_permission = True
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AsyncAuthzGrpcClient(
            test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
        )
        try:
            with pytest.raises(AuthzError):
                await client.check_access("user-1", "read", "resource-1")
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_untrusted_server_certificate_is_rejected(self, test_server: _TestServer) -> None:
        """WR-05 (async negative TLS path): with NO custom_ca, verification
        against the system trust store rejects the throwaway self-signed
        server cert, so the RPC MUST fail with a transport-level TLS error
        (UNAVAILABLE), never succeed."""
        client = AsyncAuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "tok",
            tenant_id="t1",
            custom_ca=None,  # <-- deliberately NOT trusting the self-signed cert
        )
        try:
            with pytest.raises(grpc.aio.AioRpcError) as exc_info:
                await client._stub.CheckAccess(
                    authorization_pb2.CheckAccessRequest(
                        tenant_id="t1", subject_id="u", action="read", resource_id="r"
                    ),
                    timeout=5,
                )
            assert exc_info.value.code() == grpc.StatusCode.UNAVAILABLE
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_user_info_maps_all_claims(self, test_server: _TestServer, tmp_path) -> None:
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AsyncAuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "async-token",
            tenant_id="tenant-2",
            custom_ca=ca_file,
        )
        try:
            info = await client.get_user_info()
            assert info.sub == "user-uuid"
            assert info.tenant_id == "tenant-uuid"
            assert info.org_id == "org-uuid"
            assert info.email == "alice@example.com"
            assert info.preferred_username == "alice"
            meta = test_server.userinfo_servicer.received_metadata
            assert ("authorization", "Bearer async-token") in meta
            assert ("x-tenant-id", "tenant-2") in meta
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_user_info_absent_optionals_map_to_none(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        test_server.userinfo_servicer.include_email = False
        test_server.userinfo_servicer.include_username = False
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AsyncAuthzGrpcClient(
            test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
        )
        try:
            info = await client.get_user_info()
            assert info.email is None
            assert info.preferred_username is None
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_user_info_no_token_raises_without_wire_call(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
        client = AsyncAuthzGrpcClient(
            test_server.target, token_fn=lambda: None, tenant_id="t1", custom_ca=ca_file
        )
        try:
            with pytest.raises(AuthError):
                await client.get_user_info()
            assert test_server.userinfo_servicer.received_metadata == []
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_user_info_unauthenticated_triggers_exactly_one_refresh_and_one_retry(
        self, test_server: _TestServer, tmp_path
    ) -> None:
        test_server.userinfo_servicer.unauthenticated_once = True
        ca_file = _write_ca_file(tmp_path, test_server.cert_pem)

        refresh_calls = 0

        async def refresh_fn() -> None:
            nonlocal refresh_calls
            refresh_calls += 1

        client = AsyncAuthzGrpcClient(
            test_server.target,
            token_fn=lambda: "tok",
            tenant_id="t1",
            refresh_fn=refresh_fn,
            custom_ca=ca_file,
        )
        try:
            info = await client.get_user_info()
            assert info.sub == "user-uuid"
            assert refresh_calls == 1, "refresh_fn must be called exactly once"
        finally:
            await client.close()
