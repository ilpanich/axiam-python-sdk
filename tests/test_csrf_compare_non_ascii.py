"""Ride-along (SA-21): the CSRF double-submit comparison is over encoded bytes.

``hmac.compare_digest`` on two ``str`` operands raises ``TypeError`` when either holds a
non-ASCII character, so a request carrying such a header or cookie turned a CSRF refusal (403)
into an unhandled 500. Both guards must compare ``bytes`` and refuse with the ordinary 403.
"""

from __future__ import annotations

import time
from typing import Any

import django
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from django.conf import settings as django_settings
from django.http import HttpResponse
from django.test import RequestFactory
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

if not django_settings.configured:
    django_settings.configure(
        DEBUG=True,
        USE_TZ=True,
        AXIAM_JWKS_BASE_URL="https://axiam.example.test",
        AXIAM_TENANT_SLUG="acme",
    )
    django.setup()

from axiam_sdk._jwks import JwksVerifier  # noqa: E402
from axiam_sdk.django.middleware import AxiamAuthMiddleware  # noqa: E402
from axiam_sdk.fastapi import AxiamUser, require_authenticated_user  # noqa: E402
from tests._oidc_testkit import make_ed25519_keypair_and_jwk  # noqa: E402


@pytest.fixture
def token_and_jwk(monkeypatch) -> tuple[str, dict[str, Any]]:
    key, jwk = make_ed25519_keypair_and_jwk("test-kid-1")
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode(
        {"sub": "user-1", "tenant_id": "acme", "exp": int(time.time()) + 600},
        pem,
        algorithm="EdDSA",
        headers={"kid": "test-kid-1", "typ": "at+jwt"},
    )
    real_init = JwksVerifier.__init__

    def patched_init(self: JwksVerifier, base_url: str, **kwargs: Any) -> None:
        real_init(self, base_url, **kwargs)
        self._client.fetch_data = lambda: {"keys": [jwk]}  # type: ignore[method-assign]

    monkeypatch.setattr(JwksVerifier, "__init__", patched_init)
    return token, jwk


def test_fastapi_non_ascii_csrf_header_is_403_not_500(token_and_jwk) -> None:
    token, _jwk = token_and_jwk
    app = FastAPI()
    verifier = JwksVerifier("https://axiam.example.test")

    @app.post("/me")
    async def me(user: AxiamUser = Depends(require_authenticated_user(verifier, "acme"))):  # noqa: B008
        return {"user_id": user.user_id}

    client = TestClient(app, raise_server_exceptions=False)
    client.cookies.set("axiam_access", token)
    client.cookies.set("axiam_csrf", "abc")
    response = client.post("/me", headers={"X-CSRF-Token": "é".encode()})
    assert response.status_code == 403


def test_fastapi_matching_non_ascii_csrf_pair_does_not_crash(token_and_jwk) -> None:
    from axiam_sdk.fastapi import _assert_csrf_valid

    class _Req:
        headers = {"x-csrf-token": "é"}
        cookies = {"axiam_csrf": "é"}

    _assert_csrf_valid(_Req())  # type: ignore[arg-type]


def test_django_non_ascii_csrf_header_is_403_not_500(token_and_jwk) -> None:
    token, _jwk = token_and_jwk
    middleware = AxiamAuthMiddleware(lambda request: HttpResponse("ok"))
    request = RequestFactory().post(
        "/", HTTP_X_CSRF_TOKEN="é", HTTP_COOKIE=f"axiam_access={token}; axiam_csrf=abc"
    )
    assert middleware(request).status_code == 403
