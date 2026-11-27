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

from axiam_sdk import AsyncAxiamClient, AxiamClient
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


def _mtls_client(pki: _MtlsPki, base_url: str) -> AxiamClient:
    return AxiamClient(
        base_url=base_url,
        tenant_slug="acme",
        custom_ca=str(pki.ca_path),
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )


def test_axiam_client_presents_its_mtls_identity_to_a_same_origin_jwks_endpoint(
    pki: _MtlsPki, mtls_server: _JwksHttpsServer, token: str
) -> None:
    client = _mtls_client(pki, mtls_server.base_url)
    assert _verify(client._verifier_for(mtls_server.jwks_url), token)["sub"] == "u1"


def test_mtls_identity_is_not_sent_to_another_origin(
    pki: _MtlsPki, mtls_server: _JwksHttpsServer, token: str
) -> None:
    """The identity goes only to base_url's origin; the CA trust still applies elsewhere."""
    client = _mtls_client(pki, "https://localhost:1")
    assert client._session.jwks_mtls_context(mtls_server.jwks_url) is None
    with pytest.raises(AuthError):  # the server demands the identity, which was withheld
        _verify(client._verifier_for(mtls_server.jwks_url), token)


def test_other_origin_still_trusts_custom_ca(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str
) -> None:
    client = _mtls_client(pki, "https://localhost:1")
    assert _verify(client._verifier_for(server.jwks_url), token)["sub"] == "u1"


def test_hostname_mismatch_is_refused_even_with_the_ca_trusted(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str
) -> None:
    verifier = JwksVerifier(
        f"https://127.0.0.1:{server.port}", custom_ca=str(pki.ca_path)
    )  # the certificate's only SAN is localhost
    with pytest.raises(AuthError):
        _verify(verifier, token)


def test_async_client_reaches_the_custom_ca(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str
) -> None:
    client = AsyncAxiamClient(
        base_url=server.base_url, tenant_slug="acme", custom_ca=str(pki.ca_path)
    )
    assert _verify(client._verifier_for(server.jwks_url), token)["sub"] == "u1"


def test_jwks_verifier_has_no_public_context_parameter() -> None:
    with pytest.raises(TypeError):
        JwksVerifier("https://x.example", ssl_context=ssl.create_default_context())  # type: ignore[call-arg]


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


# --- custom_ca is one rule: a path / inline PEM, or a strict SSLContext ------------------------


def _unverified_context() -> ssl.SSLContext:
    return ssl._create_unverified_context()  # the bypass the rule must refuse


def test_rest_client_refuses_an_unverified_context_as_custom_ca() -> None:
    with pytest.raises(ValueError, match="custom_ca"):
        AxiamClient(
            base_url="https://axiam.example.test",
            tenant_slug="acme",
            custom_ca=_unverified_context(),  # type: ignore[arg-type]
        )


def test_async_client_refuses_an_unverified_context_as_custom_ca() -> None:
    with pytest.raises(ValueError, match="custom_ca"):
        AsyncAxiamClient(
            base_url="https://axiam.example.test",
            tenant_slug="acme",
            custom_ca=_unverified_context(),  # type: ignore[arg-type]
        )


def test_jwks_verifier_refuses_an_unverified_context_as_custom_ca() -> None:
    with pytest.raises(ValueError, match="custom_ca"):
        JwksVerifier("https://axiam.example.test", custom_ca=_unverified_context())  # type: ignore[arg-type]


def test_context_without_hostname_check_is_refused() -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    with pytest.raises(ValueError, match="custom_ca"):
        JwksVerifier("https://axiam.example.test", custom_ca=context)


@pytest.mark.parametrize("bad", [b"/ca.pem", 7, True, object()])
def test_non_str_non_context_custom_ca_is_refused(bad: Any) -> None:
    with pytest.raises(ValueError, match="custom_ca") as caught:
        JwksVerifier("https://axiam.example.test", custom_ca=bad)
    assert "object at" not in str(caught.value)  # the value is never echoed


def test_strict_context_is_accepted_and_trusts_the_private_ca(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str
) -> None:
    context = ssl.create_default_context(cadata=pki.ca_pem.decode("ascii"))
    assert _verify(JwksVerifier(server.base_url, custom_ca=context), token)["sub"] == "u1"
    client = AxiamClient(base_url=server.base_url, tenant_slug="acme", custom_ca=context)
    assert client._session._verify is context
    assert _verify(client._verifier_for(server.jwks_url), token)["sub"] == "u1"


def test_context_custom_ca_cannot_be_combined_with_a_client_identity(pki: _MtlsPki) -> None:
    with pytest.raises(ValueError, match="custom_ca"):
        AxiamClient(
            base_url="https://axiam.example.test",
            tenant_slug="acme",
            custom_ca=ssl.create_default_context(),
            client_cert=pki.client_cert_pem,
            client_key=pki.client_key_pem,
        )


def test_django_middleware_refuses_an_unverified_context_setting(pki: _MtlsPki) -> None:
    from django.conf import settings as django_settings

    import tests.test_django_middleware  # noqa: F401
    from axiam_sdk.django.middleware import AxiamAuthMiddleware

    names = {
        "AXIAM_JWKS_BASE_URL": "https://axiam.example.test",
        "AXIAM_TENANT_SLUG": _TENANT,
        "AXIAM_CUSTOM_CA": _unverified_context(),
    }
    missing = object()
    saved = {k: getattr(django_settings, k, missing) for k in names}
    try:
        for key, value in names.items():
            setattr(django_settings, key, value)
        with pytest.raises(ValueError, match="custom_ca"):
            AxiamAuthMiddleware(lambda request: None)
    finally:
        for key, value in saved.items():
            if value is missing:
                delattr(django_settings, key)
            else:
                setattr(django_settings, key, value)


# --- jwks_mtls_context: the identity goes only to the client's own origin ------------------------


def _session(base_url: str, pki: _MtlsPki) -> Any:
    return _mtls_client(pki, base_url)._session


@pytest.mark.parametrize(
    ("base", "jwks", "same"),
    [
        ("https://axiam.example.test", "https://axiam.example.test/oauth2/jwks", True),
        ("https://axiam.example.test", "HTTPS://AXIAM.Example.TEST/jwks", True),
        ("https://axiam.example.test", "https://axiam.example.test:443/jwks", True),
        ("https://axiam.example.test:443", "https://axiam.example.test/jwks", True),
        ("https://[::1]:8443", "https://[::1]:8443/jwks", True),
        ("https://[::1]:8443", "https://[::1]:8444/jwks", False),
        ("https://axiam.example.test", "https://axiam.example.test./jwks", False),
        ("https://axiam.example.test", "http://axiam.example.test/jwks", False),
        ("https://axiam.example.test", "https://other.example.test/jwks", False),
        ("https://axiam.example.test", "https://axiam.example.test:8443/jwks", False),
    ],
)
def test_jwks_mtls_context_origin_normalization(
    pki: _MtlsPki, base: str, jwks: str, same: bool
) -> None:
    session = _session(base, pki)
    assert (session.jwks_mtls_context(jwks) is not None) is same


def test_jwks_mtls_context_fails_closed_on_an_invalid_url(pki: _MtlsPki) -> None:
    session = _session("https://a.com", pki)
    assert session.jwks_mtls_context("https://a.com:abc/j") is None


# --- every accepted custom_ca form works on the REST path and the JWKS fetch ---------------------


def _rest_get(client: AxiamClient, server: _JwksHttpsServer) -> int:
    request = client._session.sync_client.build_request("GET", "/oauth2/jwks")
    return int(client._session._send_sync(request).status_code)


def _ca_forms(pki: _MtlsPki, tmp_path: Path) -> dict[str, Any]:
    ca_dir = tmp_path / "cadir"
    ca_dir.mkdir()
    # OpenSSL looks a CA up in a directory by its subject-hash file name.
    import subprocess

    digest = subprocess.run(
        ["openssl", "x509", "-noout", "-subject_hash", "-in", str(pki.ca_path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (ca_dir / f"{digest}.0").write_bytes(pki.ca_pem)
    return {
        "path": str(pki.ca_path),
        "directory": str(ca_dir),
        "inline_pem_str": pki.ca_pem.decode("ascii"),
        "pem_bytes": pki.ca_pem,
    }


@pytest.mark.parametrize("form", ["path", "directory", "inline_pem_str", "pem_bytes"])
def test_every_custom_ca_form_works_for_rest_and_jwks(
    pki: _MtlsPki, server: _JwksHttpsServer, token: str, tmp_path: Path, form: str
) -> None:
    ca = _ca_forms(pki, tmp_path)[form]
    client = AxiamClient(base_url=server.base_url, tenant_slug="acme", custom_ca=ca)
    try:
        assert _rest_get(client, server) == 200
    finally:
        client._session.close()
    assert _verify(JwksVerifier(server.base_url, custom_ca=ca), token)["sub"] == "u1"
    assert _verify(client._verifier_for(server.jwks_url), token)["sub"] == "u1"


@pytest.mark.parametrize("bad", [b"not a pem", b"\xff\xfe-----BEGIN CERTIFICATE-----", b""])
def test_non_pem_bytes_custom_ca_is_refused(bad: bytes) -> None:
    with pytest.raises(ValueError, match="custom_ca") as caught:
        JwksVerifier("https://axiam.example.test", custom_ca=bad)
    assert "not a pem" not in str(caught.value)
