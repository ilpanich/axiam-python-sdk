"""N15 / D-1 (CONTRACT.md §10, §11.2 rule 11): ``require_role`` reads the token's ``roles``
claim and nothing else, and fails closed when it is absent.

The ``scope`` claim names what the *client* asked for, not what the user holds, so it must never
become the identity's roles. A separate ``require_scope`` guard checks granted scopes. Driven end
to end through the FastAPI dependency and through the Django middleware + decorator, with real
Ed25519-signed tokens.
"""

from __future__ import annotations

import json
import time
from typing import Any

import django
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings as django_settings
from django.http import HttpResponse, JsonResponse
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
from axiam_sdk.django import decorators as django_decorators  # noqa: E402
from axiam_sdk.django.middleware import AxiamAuthMiddleware  # noqa: E402
from axiam_sdk.fastapi import AxiamUser, require_role  # noqa: E402
from tests._oidc_testkit import make_ed25519_keypair_and_jwk  # noqa: E402

BASE_URL = "https://axiam.example.test"


def _token(key: Ed25519PrivateKey, **claims: Any) -> str:
    body: dict[str, Any] = {"sub": "user-1", "tenant_id": "acme", "exp": int(time.time()) + 600}
    body.update(claims)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(body, pem, algorithm="EdDSA", headers={"kid": "test-kid-1", "typ": "at+jwt"})


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    return make_ed25519_keypair_and_jwk("test-kid-1")


@pytest.fixture
def bind_jwks(keypair, monkeypatch) -> JwksVerifier:
    """One verifier for FastAPI; the same fake JWKS bound onto every verifier the Django
    middleware constructs."""
    jwk = keypair[1]
    real_init = JwksVerifier.__init__

    def patched_init(self: JwksVerifier, base_url: str, **kwargs: Any) -> None:
        real_init(self, base_url, **kwargs)
        self._client.fetch_data = lambda: {"keys": [jwk]}  # type: ignore[method-assign]

    monkeypatch.setattr(JwksVerifier, "__init__", patched_init)
    return JwksVerifier(BASE_URL)


# --- FastAPI ---------------------------------------------------------------------------


def _fastapi_client(verifier: JwksVerifier) -> TestClient:
    from axiam_sdk import fastapi as axiam_fastapi

    app = FastAPI()

    @app.get("/admin")
    async def admin(user: AxiamUser = Depends(require_role(verifier, "acme", "admin"))):  # noqa: B008
        return {"user_id": user.user_id, "roles": user.roles}

    require_scope = getattr(axiam_fastapi, "require_scope", None)
    if require_scope is not None:

        @app.get("/scoped")
        async def scoped(user: AxiamUser = Depends(require_scope(verifier, "acme", "admin"))):  # noqa: B008
            return {"user_id": user.user_id}

    return TestClient(app)


def _get(client: TestClient, path: str, token: str) -> Any:
    return client.get(path, headers={"Authorization": f"Bearer {token}"})


def test_fastapi_scope_admin_without_roles_is_403(keypair, bind_jwks) -> None:
    client = _fastapi_client(bind_jwks)
    token = _token(keypair[0], scope="openid admin")
    assert _get(client, "/admin", token).status_code == 403


def test_fastapi_roles_admin_is_200(keypair, bind_jwks) -> None:
    client = _fastapi_client(bind_jwks)
    token = _token(keypair[0], scope="openid", roles=["admin"])
    response = _get(client, "/admin", token)
    assert response.status_code == 200
    assert response.json()["roles"] == ["admin"]


def test_fastapi_roles_absent_fails_closed_even_with_matching_scope(keypair, bind_jwks) -> None:
    client = _fastapi_client(bind_jwks)
    assert _get(client, "/admin", _token(keypair[0])).status_code == 403


@pytest.mark.parametrize("roles", [None, "admin", {"admin": True}, [1, 2]])
def test_fastapi_malformed_roles_claim_fails_closed(keypair, bind_jwks, roles) -> None:
    client = _fastapi_client(bind_jwks)
    token = _token(keypair[0], scope="admin", roles=roles)
    assert _get(client, "/admin", token).status_code == 403


def test_fastapi_require_scope_admits_the_scope_token(keypair, bind_jwks) -> None:
    client = _fastapi_client(bind_jwks)
    token = _token(keypair[0], scope="openid admin")
    assert _get(client, "/scoped", token).status_code == 200


def test_fastapi_require_scope_refuses_a_roles_only_token(keypair, bind_jwks) -> None:
    client = _fastapi_client(bind_jwks)
    token = _token(keypair[0], scope="openid", roles=["admin"])
    assert _get(client, "/scoped", token).status_code == 403


# --- Django ----------------------------------------------------------------------------


def _ok_view(request: Any) -> HttpResponse:
    return JsonResponse({"roles": request.axiam_user.roles})


def _django_call(token: str, guard: Any) -> HttpResponse:
    request = RequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
    middleware = AxiamAuthMiddleware(guard(_ok_view))
    return middleware(request)


def test_django_scope_admin_without_roles_is_403(keypair, bind_jwks) -> None:
    token = _token(keypair[0], scope="openid admin")
    response = _django_call(token, django_decorators.require_role("admin"))
    assert response.status_code == 403


def test_django_roles_admin_is_200(keypair, bind_jwks) -> None:
    token = _token(keypair[0], scope="openid", roles=["admin"])
    response = _django_call(token, django_decorators.require_role("admin"))
    assert response.status_code == 200
    assert json.loads(response.content)["roles"] == ["admin"]


@pytest.mark.parametrize("roles", [None, "admin", {"admin": True}, [1, 2]])
def test_django_malformed_roles_claim_fails_closed(keypair, bind_jwks, roles) -> None:
    token = _token(keypair[0], scope="admin", roles=roles)
    response = _django_call(token, django_decorators.require_role("admin"))
    assert response.status_code == 403


def test_django_require_scope_admits_the_scope_token(keypair, bind_jwks) -> None:
    require_scope = getattr(django_decorators, "require_scope", None)
    assert require_scope is not None, "axiam_sdk.django.decorators.require_scope is missing"
    token = _token(keypair[0], scope="openid admin")
    assert _django_call(token, require_scope("admin")).status_code == 200


def test_django_require_scope_refuses_a_roles_only_token(keypair, bind_jwks) -> None:
    require_scope = getattr(django_decorators, "require_scope", None)
    assert require_scope is not None, "axiam_sdk.django.decorators.require_scope is missing"
    token = _token(keypair[0], scope="openid", roles=["admin"])
    assert _django_call(token, require_scope("admin")).status_code == 403


def test_roles_claim_presence_is_distinguishable_from_an_empty_array(keypair, bind_jwks) -> None:
    """§11.2 rule 11 (b): "no roles claim" and "roles: []" stay distinguishable on the identity."""
    from axiam_sdk.django.middleware import _build_user

    assert _build_user({"sub": "u", "tenant_id": "acme"}).roles_claim_present is False
    assert _build_user({"sub": "u", "tenant_id": "acme", "roles": []}).roles_claim_present is True
    assert (
        _build_user({"sub": "u", "tenant_id": "acme", "roles": "admin"}).roles_claim_present
        is False
    )
    user = _build_user({"sub": "u", "tenant_id": "acme", "scope": "openid  admin", "roles": ["a"]})
    assert user.roles == ["a"]
    assert user.scopes == ["openid", "admin"]
