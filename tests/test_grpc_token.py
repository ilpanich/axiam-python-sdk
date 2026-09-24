"""``TokenGrpcClient``-equivalent methods — ``validate_token``/
``introspect_token`` on ``AuthzGrpcClient``/``AsyncAuthzGrpcClient``
(CONTRACT.md §1.1.1, §10.3, contract 1.51).

§8 rule 7 of the dogfooding fix plan requires "the gRPC wrappers read
``cnf``". §10.3's own required tests are the rest of this file: a
``cnf``-bearing response is not treated as a bearer token; an empty
``CnfClaim`` is refused; and — the positive regression — an unbound
response still validates.
"""

from __future__ import annotations

import datetime
import socket
from collections.abc import Iterator
from concurrent import futures

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from axiam_sdk import AuthError
from axiam_sdk.grpc.client import AsyncAuthzGrpcClient, AuthzGrpcClient
from axiam_sdk.grpc.gen import token_pb2, token_pb2_grpc


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return int(s.getsockname()[1])


def _generate_self_signed_cert() -> tuple[bytes, bytes]:
    """Throwaway self-signed cert/key pair for localhost, standing up the
    in-process TLS test server below only — not a production credential."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


class _TokenServicer(token_pb2_grpc.TokenServiceServicer):
    """A scriptable ``TokenService`` servicer: controls the ``cnf``/
    ``token_type`` a response carries, and can fail UNAUTHENTICATED exactly
    once to exercise the single-flight refresh-and-retry path."""

    def __init__(self) -> None:
        self.unauthenticated_once = False
        self._already_failed_once = False
        self.cnf: tuple[str, str] | None = None
        """``(x5t_s256, jkt)`` -- set the ``cnf`` sub-message when not
        ``None``; each half omitted from the message when its string is
        empty (proto3 implicit presence), letting a test build "both empty
        but the message is set" as ``("", "")``."""
        self.received_metadata: list[tuple[str, str]] = []
        self.last_validate_request: token_pb2.ValidateTokenRequest | None = None
        self.last_introspect_request: token_pb2.IntrospectTokenRequest | None = None

    def _maybe_fail_once(self, context: grpc.ServicerContext) -> None:
        if self.unauthenticated_once and not self._already_failed_once:
            self._already_failed_once = True
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "token expired")

    def _cnf_message(self) -> token_pb2.CnfClaim | None:
        if self.cnf is None:
            return None
        x5t_s256, jkt = self.cnf
        return token_pb2.CnfClaim(x5t_s256=x5t_s256, jkt=jkt)

    def ValidateToken(self, request, context):  # noqa: N802
        self.received_metadata = list(context.invocation_metadata() or [])
        self._maybe_fail_once(context)
        self.last_validate_request = request
        response = token_pb2.ValidateTokenResponse(
            valid=True,
            subject_id="subject-uuid",
            tenant_id="tenant-uuid",
            org_id="org-uuid",
            exp=9999999999,
            token_type="Bearer",
        )
        cnf = self._cnf_message()
        if cnf is not None:
            response.cnf.CopyFrom(cnf)
        return response

    def IntrospectToken(self, request, context):  # noqa: N802
        self.received_metadata = list(context.invocation_metadata() or [])
        self._maybe_fail_once(context)
        self.last_introspect_request = request
        response = token_pb2.IntrospectTokenResponse(
            active=True,
            sub="subject-uuid",
            tenant_id="tenant-uuid",
            org_id="org-uuid",
            iss="https://axiam.example.test",
            iat=1,
            exp=9999999999,
            jti="jti-uuid",
            scope="read write",
            client_id="client-1",
            token_type="Bearer",
            ext_exchange_iss="https://foreign-idp.example.test",
        )
        response.permissions.add(resource_id="res-1", resource_scopes=["view"], exp=9999999999)
        cnf = self._cnf_message()
        if cnf is not None:
            response.cnf.CopyFrom(cnf)
        return response


class _TestServer:
    def __init__(self) -> None:
        self.servicer = _TokenServicer()
        self.cert_pem, self.key_pem = _generate_self_signed_cert()
        self.port = _free_port()
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        token_pb2_grpc.add_TokenServiceServicer_to_server(self.servicer, self.server)
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


# ---------------------------------------------------------------------------
# Two tokens kept apart (rule 1): the caller's own token authenticates the
# call (metadata, via the interceptor); the inspected token travels in the
# message and is a DIFFERENT value.
# ---------------------------------------------------------------------------


def test_validate_token_keeps_the_caller_and_inspected_tokens_apart(
    test_server: _TestServer, tmp_path
) -> None:
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AuthzGrpcClient(
        test_server.target, token_fn=lambda: "callers-own-token", tenant_id="t1", custom_ca=ca_file
    )
    try:
        result = client.validate_token("the-inspected-token")
        assert result.valid is True
        assert (
            "authorization",
            "Bearer callers-own-token",
        ) in test_server.servicer.received_metadata
        assert test_server.servicer.last_validate_request.access_token == "the-inspected-token"
    finally:
        client.close()


def test_introspect_token_keeps_the_caller_and_inspected_tokens_apart(
    test_server: _TestServer, tmp_path
) -> None:
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AuthzGrpcClient(
        test_server.target, token_fn=lambda: "callers-own-token", tenant_id="t1", custom_ca=ca_file
    )
    try:
        result = client.introspect_token("the-inspected-token")
        assert result.active is True
        assert (
            "authorization",
            "Bearer callers-own-token",
        ) in test_server.servicer.received_metadata
        assert test_server.servicer.last_introspect_request.access_token == "the-inspected-token"
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Precondition (rule 2, via §1.1 rule 3): no caller token -> AuthError, zero
# wire calls.
# ---------------------------------------------------------------------------


def test_validate_token_no_caller_token_raises_without_wire_call(
    test_server: _TestServer, tmp_path
) -> None:
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AuthzGrpcClient(
        test_server.target, token_fn=lambda: None, tenant_id="t1", custom_ca=ca_file
    )
    try:
        with pytest.raises(AuthError):
            client.validate_token("inspected")
        assert test_server.servicer.received_metadata == []
    finally:
        client.close()


def test_introspect_token_no_caller_token_raises_without_wire_call(
    test_server: _TestServer, tmp_path
) -> None:
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AuthzGrpcClient(
        test_server.target, token_fn=lambda: None, tenant_id="t1", custom_ca=ca_file
    )
    try:
        with pytest.raises(AuthError):
            client.introspect_token("inspected")
        assert test_server.servicer.received_metadata == []
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Rule 3 — every field, cnf included; the positive regression (absent cnf
# still validates)
# ---------------------------------------------------------------------------


def test_validate_token_maps_every_field_with_no_cnf(test_server: _TestServer, tmp_path) -> None:
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AuthzGrpcClient(
        test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
    )
    try:
        result = client.validate_token("inspected")
        assert result.valid is True
        assert result.subject_id == "subject-uuid"
        assert result.tenant_id == "tenant-uuid"
        assert result.org_id == "org-uuid"
        assert result.exp == 9999999999
        assert result.token_type == "Bearer"
        assert result.cnf is None, "the positive regression: an unbound response still validates"
        result.verify_possession()  # must not raise for an unbound token
    finally:
        client.close()


def test_introspect_token_maps_every_field(test_server: _TestServer, tmp_path) -> None:
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AuthzGrpcClient(
        test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
    )
    try:
        result = client.introspect_token("inspected")
        assert result.active is True
        assert result.sub == "subject-uuid"
        assert result.tenant_id == "tenant-uuid"
        assert result.org_id == "org-uuid"
        assert result.iss == "https://axiam.example.test"
        assert result.iat == 1
        assert result.exp == 9999999999
        assert result.jti == "jti-uuid"
        assert result.scope == "read write"
        assert result.client_id == "client-1"
        assert result.token_type == "Bearer"
        assert result.ext_exchange_iss == "https://foreign-idp.example.test"
        assert len(result.permissions) == 1
        assert result.permissions[0].resource_id == "res-1"
        assert result.permissions[0].resource_scopes == ["view"]
        assert result.cnf is None
        result.verify_possession()
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Rules 4/5 — cnf present: not usable as presented; boundness from cnf alone
# ---------------------------------------------------------------------------


def test_validate_token_cnf_bearing_response_is_not_treated_as_a_bearer_token(
    test_server: _TestServer, tmp_path
) -> None:
    """§10.3's required test: a cnf-bearing response is not treated as a
    bearer token. token_type still reads "Bearer" (rule 5) even though the
    token is certificate-bound -- boundness is decided from cnf alone."""
    test_server.servicer.cnf = ("expected-thumbprint", "")
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AuthzGrpcClient(
        test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
    )
    try:
        result = client.validate_token("inspected")
        assert result.token_type == "Bearer", "reported Bearer even though the token is bound"
        assert result.cnf is not None
        assert result.cnf.x5t_s256 == "expected-thumbprint"
        assert result.cnf.jkt is None

        with pytest.raises(AuthError):
            result.verify_possession()  # no evidence supplied
        with pytest.raises(AuthError):
            result.verify_possession(certificate_thumbprint="a-different-thumbprint")
        result.verify_possession(certificate_thumbprint="expected-thumbprint")  # must not raise
    finally:
        client.close()


def test_introspect_token_an_empty_cnf_claim_is_refused(test_server: _TestServer, tmp_path) -> None:
    """§10.3's required test: an empty CnfClaim is refused, not read as
    unbound — proto3's spelling of §10.1 rule 9's "names neither" row."""
    test_server.servicer.cnf = ("", "")
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AuthzGrpcClient(
        test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
    )
    try:
        result = client.introspect_token("inspected")
        assert result.cnf is not None, "the message was set, even with both members empty"
        with pytest.raises(AuthError):
            result.verify_possession(certificate_thumbprint="anything")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# UNAUTHENTICATED -> single-flight refresh, retried exactly once (§9.3)
# ---------------------------------------------------------------------------


def test_validate_token_unauthenticated_triggers_exactly_one_refresh_and_retry(
    test_server: _TestServer, tmp_path
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
        result = client.validate_token("inspected")
        assert result.valid is True
        assert refresh_calls == 1
    finally:
        client.close()


async def test_introspect_token_unauthenticated_triggers_exactly_one_refresh_and_retry_async(
    test_server: _TestServer, tmp_path
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
        result = await client.introspect_token("inspected")
        assert result.active is True
        assert refresh_calls == 1
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Async twins of the core mapping tests
# ---------------------------------------------------------------------------


async def test_async_validate_token_maps_every_field(test_server: _TestServer, tmp_path) -> None:
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AsyncAuthzGrpcClient(
        test_server.target, token_fn=lambda: "tok", tenant_id="t1", custom_ca=ca_file
    )
    try:
        result = await client.validate_token("inspected")
        assert result.valid is True
        assert result.cnf is None
    finally:
        await client.close()


async def test_async_introspect_token_no_caller_token_raises_without_wire_call(
    test_server: _TestServer, tmp_path
) -> None:
    ca_file = _write_ca_file(tmp_path, test_server.cert_pem)
    client = AsyncAuthzGrpcClient(
        test_server.target, token_fn=lambda: None, tenant_id="t1", custom_ca=ca_file
    )
    try:
        with pytest.raises(AuthError):
            await client.introspect_token("inspected")
        assert test_server.servicer.received_metadata == []
    finally:
        await client.close()
