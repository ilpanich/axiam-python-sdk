"""The JWKS fetch honours ``custom_ca`` and the session's mTLS identity (issue #114).

A local HTTPS server, whose certificate only a throwaway test CA signed, serves the JWKS. A
verifier given that CA (path or inline PEM) fetches and verifies; one without it still fails
closed: server verification is never weakened (CONTRACT.md §6, §6.1 rule 2).
"""

from __future__ import annotations

import http.server
import json
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from axiam_sdk import AxiamClient
from axiam_sdk._errors import AuthError
from axiam_sdk._jwks import JwksVerifier
from tests.test_jwks import _make_ed25519_keypair_and_jwk
from tests.test_mtls_client_cert import _free_port, _MtlsPki

_KID = "private-ca-kid"
_TENANT = "tenant-1"


class _JwksHttpsServer:
    """HTTPS server serving one JWKS document, optionally demanding a client certificate."""

    def __init__(self, pki: _MtlsPki, jwk: dict[str, Any], *, require_client_cert: bool) -> None:
        body = json.dumps({"keys": [jwk]}).encode()
        self.port = _free_port()

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                return

        class _QuietServer(http.server.HTTPServer):
            def handle_error(self, *args: object) -> None:
                return

        context = pki.server_ssl_context()
        if not require_client_cert:
            context.verify_mode = ssl.CERT_NONE
        self._httpd = _QuietServer(("localhost", self.port), _Handler)
        self._httpd.socket = context.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"https://localhost:{self.port}"

    @property
    def jwks_url(self) -> str:
        return f"{self.base_url}/oauth2/jwks"

    def __enter__(self) -> _JwksHttpsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def pki(tmp_path: Path) -> _MtlsPki:
    return _MtlsPki(tmp_path)


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    return _make_ed25519_keypair_and_jwk(_KID)


@pytest.fixture
def token(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> str:
    private_key, _jwk = keypair
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    claims = {"sub": "u1", "tenant_id": _TENANT, "exp": time.time() + 600}
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": _KID, "typ": "at+jwt"})


@pytest.fixture
def server(pki: _MtlsPki, keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> Iterator[Any]:
    with _JwksHttpsServer(pki, keypair[1], require_client_cert=False) as srv:
        yield srv


@pytest.fixture
def mtls_server(pki: _MtlsPki, keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> Iterator[Any]:
    with _JwksHttpsServer(pki, keypair[1], require_client_cert=True) as srv:
        yield srv


def _verify(verifier: JwksVerifier, token: str) -> dict[str, Any]:
    return verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_custom_ca_path_trusts_private_ca_for_jwks(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str
) -> None:
    verifier = JwksVerifier(server.base_url, custom_ca=str(pki.ca_path))
    assert _verify(verifier, token)["sub"] == "u1"


def test_custom_ca_inline_pem_trusts_private_ca_for_jwks(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str
) -> None:
    verifier = JwksVerifier(server.base_url, custom_ca=pki.ca_pem.decode("ascii"))
    assert _verify(verifier, token)["sub"] == "u1"


def test_without_custom_ca_the_private_ca_is_not_trusted(
    server: _JwksHttpsServer, token: str
) -> None:
    """Fails closed: no CA given, the system trust store does not know the test CA."""
    verifier = JwksVerifier(server.base_url)
    with pytest.raises(AuthError):
        _verify(verifier, token)


def test_a_different_ca_does_not_trust_the_server(
    tmp_path: Path, server: _JwksHttpsServer, token: str
) -> None:
    (tmp_path / "other").mkdir()
    other = _MtlsPki(tmp_path / "other")
    verifier = JwksVerifier(server.base_url, custom_ca=str(other.ca_path))
    with pytest.raises(AuthError):
        _verify(verifier, token)


def test_axiam_client_passes_custom_ca_to_its_jwks_verifier(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str
) -> None:
    client = AxiamClient(base_url=server.base_url, tenant_slug="acme", custom_ca=str(pki.ca_path))
    verifier = client._verifier_for(server.jwks_url)
    assert _verify(verifier, token)["sub"] == "u1"


def test_axiam_client_verifier_without_custom_ca_fails_closed(
    server: _JwksHttpsServer, token: str
) -> None:
    client = AxiamClient(base_url=server.base_url, tenant_slug="acme")
    with pytest.raises(AuthError):
        _verify(client._verifier_for(server.jwks_url), token)


def test_axiam_client_presents_its_mtls_identity_to_the_jwks_endpoint(
    pki: _MtlsPki, mtls_server: _JwksHttpsServer, token: str
) -> None:
    client = AxiamClient(
        base_url=mtls_server.base_url,
        tenant_slug="acme",
        custom_ca=str(pki.ca_path),
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    assert _verify(client._verifier_for(mtls_server.jwks_url), token)["sub"] == "u1"


def test_mtls_jwks_endpoint_rejects_a_client_without_identity(
    pki: _MtlsPki, mtls_server: _JwksHttpsServer, token: str
) -> None:
    client = AxiamClient(
        base_url=mtls_server.base_url, tenant_slug="acme", custom_ca=str(pki.ca_path)
    )
    with pytest.raises(AuthError):
        _verify(client._verifier_for(mtls_server.jwks_url), token)


def test_django_middleware_reads_axiam_custom_ca_setting(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str
) -> None:
    from django.conf import settings as django_settings

    import tests.test_django_middleware  # noqa: F401  (configures Django settings)
    from axiam_sdk.django.middleware import AxiamAuthMiddleware

    names = {
        "AXIAM_JWKS_BASE_URL": server.base_url,
        "AXIAM_TENANT_SLUG": _TENANT,
        "AXIAM_CUSTOM_CA": str(pki.ca_path),
    }
    saved = {k: getattr(django_settings, k, None) for k in names}
    try:
        for key, value in names.items():
            setattr(django_settings, key, value)
        middleware = AxiamAuthMiddleware(lambda request: None)
        assert _verify(middleware._verifier, token)["sub"] == "u1"
    finally:
        for key, value in saved.items():
            if value is None:
                delattr(django_settings, key)
            else:
                setattr(django_settings, key, value)
