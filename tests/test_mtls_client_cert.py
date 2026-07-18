"""Client-certificate / mutual-TLS (mTLS) tests (CONTRACT.md §6.1).

Proves the SDK can present an X.509 client identity (PEM cert chain + PEM key)
on BOTH transports:

- REST (httpx): an end-to-end handshake against a local ``http.server`` wrapped
  in an ``ssl.SSLContext`` configured ``verify_mode=CERT_REQUIRED`` — a client
  that presents the cert succeeds, one that omits it is rejected at the TLS
  layer. Strict server verification stays on throughout (§6.1 rule 2).
- gRPC: ``build_channel_credentials`` wires the same PEM identity straight into
  ``grpc.ssl_channel_credentials`` (§6.1 rule 4).

Plus construction-error coverage: supplying only one of ``client_cert``/
``client_key`` is a ``ValueError``, and malformed PEM is a ``ValueError``.

All PKI is generated at test time with ``cryptography`` into ``tmp_path`` — no
private key or certificate is ever committed (§6.1 rule 3 / §7).
"""

from __future__ import annotations

import datetime
import http.server
import socket
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import grpc
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from axiam_sdk import AsyncAxiamClient, AxiamClient
from axiam_sdk._session import _Session
from axiam_sdk.grpc._tls import build_channel_credentials


def _free_port() -> int:
    """Reserve and return an ephemeral localhost TCP port for the test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return int(s.getsockname()[1])


def _key_pem(key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key to unencrypted PKCS#8 PEM bytes (test PKI)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a throwaway self-signed CA used to sign both the server and
    client leaf certificates of this test's PKI."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "axiam-test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # OpenSSL 3.5 (Python 3.13 CI) enforces stricter chain rules than older
        # releases: the CA must declare KeyUsage(keyCertSign) and carry a Subject
        # Key Identifier for the leaves' Authority Key Identifier to reference.
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    server: bool,
) -> tuple[bytes, bytes]:
    """Generate a leaf cert/key PEM pair signed by the test CA.

    Args:
        common_name: The leaf subject common name.
        ca_key: The issuing CA private key.
        ca_cert: The issuing CA certificate (supplies the issuer name).
        server: When ``True``, add a ``localhost`` SAN so hostname
            verification passes for the HTTPS test server.

    Returns:
        A ``(cert_pem, key_pem)`` bytes tuple.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
    # SKI + an AKI referencing the issuer CA's key, plus KeyUsage and the matching
    # ExtendedKeyUsage: OpenSSL 3.5 (Python 3.13 CI) requires all of these for
    # chain building (older OpenSSL on 3.11 was lenient).
    eku = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (
        builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM), _key_pem(key)


class _MtlsPki:
    """The generated mTLS PKI for one test run: a CA plus a server leaf and a
    client leaf, materialized where each transport needs it."""

    def __init__(self, tmp_path: Path) -> None:
        """Generate the CA + server + client identities and write the
        server-side and CA files under ``tmp_path``."""
        ca_key, ca_cert = _make_ca()
        self.ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        self.server_cert_pem, self.server_key_pem = _make_leaf(
            "localhost", ca_key, ca_cert, server=True
        )
        self.client_cert_pem, self.client_key_pem = _make_leaf(
            "axiam-device", ca_key, ca_cert, server=False
        )

        self.ca_path = tmp_path / "ca.pem"
        self.ca_path.write_bytes(self.ca_pem)
        self._server_cert_path = tmp_path / "server_cert.pem"
        self._server_cert_path.write_bytes(self.server_cert_pem)
        self._server_key_path = tmp_path / "server_key.pem"
        self._server_key_path.write_bytes(self.server_key_pem)

    def server_ssl_context(self) -> ssl.SSLContext:
        """Build the server-side ``SSLContext`` that REQUIRES a client cert
        signed by the test CA (``verify_mode=CERT_REQUIRED``)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(
            certfile=str(self._server_cert_path), keyfile=str(self._server_key_path)
        )
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=self.ca_pem.decode("ascii"))
        return ctx


class _MtlsHttpsServer:
    """In-process HTTPS server that mandates a client certificate, used to
    prove the SDK actually presents its configured client identity."""

    def __init__(self, pki: _MtlsPki) -> None:
        """Bind the mTLS-requiring HTTPS server on an ephemeral localhost port."""
        self.port = _free_port()

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args: object) -> None:
                return

        class _QuietServer(http.server.HTTPServer):
            def handle_error(self, *args: object) -> None:
                # A client that omits its cert fails the handshake; swallow the
                # server-side traceback so the negative test stays quiet.
                return

        self._httpd = _QuietServer(("localhost", self.port), _Handler)
        self._httpd.socket = pki.server_ssl_context().wrap_socket(
            self._httpd.socket, server_side=True
        )
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        """The ``https://localhost:<port>`` base URL of this server."""
        return f"https://localhost:{self.port}"

    def __enter__(self) -> _MtlsHttpsServer:
        """Start serving in a background thread."""
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        """Stop the server and join its thread."""
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def pki(tmp_path: Path) -> _MtlsPki:
    """Per-test mTLS PKI (CA + server + client identities) under ``tmp_path``."""
    return _MtlsPki(tmp_path)


@pytest.fixture
def mtls_server(pki: _MtlsPki) -> Iterator[_MtlsHttpsServer]:
    """A running mTLS-requiring HTTPS test server."""
    with _MtlsHttpsServer(pki) as server:
        yield server


# --------------------------------------------------------------------------
# REST end-to-end handshake (§6.1) — sync + async
# --------------------------------------------------------------------------


def test_rest_sync_mtls_handshake_succeeds_with_client_cert(
    pki: _MtlsPki, mtls_server: _MtlsHttpsServer
) -> None:
    """A sync ``_Session`` configured with the client identity completes the
    mTLS handshake against a server that requires a client certificate."""
    session = _Session(
        base_url=mtls_server.base_url,
        tenant_slug="acme",
        custom_ca=str(pki.ca_path),
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    assert isinstance(session._verify, ssl.SSLContext)
    try:
        request = session.sync_client.build_request("GET", "/")
        response = session._send_sync(request)
        assert response.status_code == 200
    finally:
        session.close()


def test_rest_sync_without_client_cert_is_rejected(
    pki: _MtlsPki, mtls_server: _MtlsHttpsServer
) -> None:
    """Omitting the client cert against a CERT_REQUIRED server fails at the TLS
    layer — proving the positive test's success is due to the presented
    identity, not an unauthenticated server."""
    session = _Session(
        base_url=mtls_server.base_url,
        tenant_slug="acme",
        custom_ca=str(pki.ca_path),
    )
    try:
        with pytest.raises(httpx.TransportError):
            request = session.sync_client.build_request("GET", "/")
            session._send_sync(request)
    finally:
        session.close()


@pytest.mark.asyncio
async def test_rest_async_mtls_handshake_succeeds_with_client_cert(
    pki: _MtlsPki, mtls_server: _MtlsHttpsServer
) -> None:
    """Async twin of the sync positive handshake test."""
    session = _Session(
        base_url=mtls_server.base_url,
        tenant_slug="acme",
        custom_ca=str(pki.ca_path),
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    try:
        request = session.async_client.build_request("GET", "/")
        response = await session._send_async(request)
        assert response.status_code == 200
    finally:
        await session.aclose()


def test_client_cert_accepts_str_and_bytes(pki: _MtlsPki, mtls_server: _MtlsHttpsServer) -> None:
    """The PEM identity is accepted as ``str`` as well as ``bytes`` (§6.1)."""
    session = _Session(
        base_url=mtls_server.base_url,
        tenant_slug="acme",
        custom_ca=str(pki.ca_path),
        client_cert=pki.client_cert_pem.decode("ascii"),
        client_key=pki.client_key_pem.decode("ascii"),
    )
    try:
        request = session.sync_client.build_request("GET", "/")
        assert session._send_sync(request).status_code == 200
    finally:
        session.close()


def test_inline_pem_custom_ca_with_client_cert(
    pki: _MtlsPki, mtls_server: _MtlsHttpsServer
) -> None:
    """``custom_ca`` may be inline PEM text (not just a path) on the mTLS
    path — it is added to the strict context via ``cadata`` and the handshake
    still succeeds."""
    session = _Session(
        base_url=mtls_server.base_url,
        tenant_slug="acme",
        custom_ca=pki.ca_pem.decode("ascii"),
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    try:
        request = session.sync_client.build_request("GET", "/")
        assert session._send_sync(request).status_code == 200
    finally:
        session.close()


def test_axiam_client_threads_client_cert_into_session(pki: _MtlsPki) -> None:
    """``AxiamClient`` threads ``client_cert``/``client_key`` through to the
    session, whose ``_verify`` becomes a strict ``ssl.SSLContext``."""
    client = AxiamClient(
        base_url="https://example.test",
        tenant_slug="acme",
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    try:
        assert isinstance(client._session._verify, ssl.SSLContext)
        assert client._session._verify.verify_mode == ssl.CERT_REQUIRED
    finally:
        client.close()


def test_async_client_threads_client_cert_into_session(pki: _MtlsPki) -> None:
    """``AsyncAxiamClient`` also threads the identity through to its session."""
    client = AsyncAxiamClient(
        base_url="https://example.test",
        tenant_slug="acme",
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    assert isinstance(client._session._verify, ssl.SSLContext)


def test_private_key_not_in_client_or_session_repr(pki: _MtlsPki) -> None:
    """The secret private key never appears in the client's or session's
    ``repr`` (§6.1 rule 3 / §7)."""
    client = AxiamClient(
        base_url="https://example.test",
        tenant_slug="acme",
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    try:
        key_marker = "PRIVATE KEY"
        assert key_marker not in repr(client)
        assert key_marker not in repr(client._session)
    finally:
        client.close()


# --------------------------------------------------------------------------
# Construction errors (§6.1 rule 1)
# --------------------------------------------------------------------------


def test_only_client_cert_raises(pki: _MtlsPki) -> None:
    """Supplying only ``client_cert`` (no key) is a construction error."""
    with pytest.raises(ValueError, match="together"):
        _Session(
            base_url="https://example.test",
            tenant_slug="acme",
            client_cert=pki.client_cert_pem,
        )


def test_only_client_key_raises(pki: _MtlsPki) -> None:
    """Supplying only ``client_key`` (no cert) is a construction error."""
    with pytest.raises(ValueError, match="together"):
        _Session(
            base_url="https://example.test",
            tenant_slug="acme",
            client_key=pki.client_key_pem,
        )


def test_only_client_cert_raises_via_axiam_client(pki: _MtlsPki) -> None:
    """The pairing rule is enforced through the public ``AxiamClient`` too."""
    with pytest.raises(ValueError, match="together"):
        AxiamClient(
            base_url="https://example.test",
            tenant_slug="acme",
            client_cert=pki.client_cert_pem,
        )


def test_malformed_pem_client_identity_raises() -> None:
    """A non-PEM client identity is rejected at construction time (§6.1)."""
    with pytest.raises(ValueError, match="valid PEM"):
        _Session(
            base_url="https://example.test",
            tenant_slug="acme",
            client_cert="not a certificate",
            client_key="not a key",
        )


# --------------------------------------------------------------------------
# gRPC credentials path (§6.1 rule 4)
# --------------------------------------------------------------------------


def test_grpc_build_credentials_with_client_identity(pki: _MtlsPki) -> None:
    """``build_channel_credentials`` accepts the PEM client identity and
    returns strict channel credentials (never a plaintext/insecure channel)."""
    creds = build_channel_credentials(
        custom_ca=str(pki.ca_path),
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    assert isinstance(creds, grpc.ChannelCredentials)


def test_grpc_build_credentials_accepts_str_identity(pki: _MtlsPki) -> None:
    """The gRPC identity is accepted as ``str`` PEM as well as ``bytes``."""
    creds = build_channel_credentials(
        client_cert=pki.client_cert_pem.decode("ascii"),
        client_key=pki.client_key_pem.decode("ascii"),
    )
    assert isinstance(creds, grpc.ChannelCredentials)


def test_grpc_build_credentials_requires_both_cert_and_key(pki: _MtlsPki) -> None:
    """The gRPC builder enforces the same both-or-neither pairing rule."""
    with pytest.raises(ValueError, match="together"):
        build_channel_credentials(client_cert=pki.client_cert_pem)
