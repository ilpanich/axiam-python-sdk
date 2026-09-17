"""Regression tests for the FastAPI dependency's half of CONTRACT.md §28 (MCP
resource-server helpers, RFC 9728 + RFC 6750) — §28.9 required tests 3, 4 and
5, plus the off-by-default regression that matters more than all five. Tests
1 and 2 (framework-independent) live in ``test_mcp.py``.

Reuses the in-test Ed25519 keypair + mock JWKS pattern from
``test_fastapi_dependency.py`` and mocks ``/api/v1/authz/check`` via
``respx``, exactly as ``test_fastapi_require_access.py`` does.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from axiam_sdk import AsyncAxiamClient, protected_resource_metadata
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk.fastapi import AxiamUser, require_access, serve_protected_resource_metadata
from axiam_sdk.management import ValidationError

BASE_URL = "https://axiam.example.test"

RESOURCE = "https://mcp.example.com/mcp"
AUTHORIZATION_SERVERS = ["https://axiam.example.com"]
SCOPES_SUPPORTED = ["mcp:read", "mcp:tools"]
METADATA_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
EXPECTED_AUDIENCE = "https://mcp.example.com/mcp"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_ed25519_keypair_and_jwk(kid: str) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk_dict = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw_public),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }
    return private_key, jwk_dict


def _sign_eddsa_token(private_key: Ed25519PrivateKey, kid: str, claims: dict[str, Any]) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": kid})


class _FakeJwksEndpoint:
    def __init__(self, jwk_dicts: list[dict[str, Any]]) -> None:
        self.jwk_dicts = jwk_dicts

    def bind(self, verifier: JwksVerifier) -> None:
        verifier._client.fetch_data = self._fetch_data  # type: ignore[method-assign]

    def _fetch_data(self) -> dict[str, Any]:
        return {"keys": self.jwk_dicts}


@pytest.fixture
def eddsa_keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    return _make_ed25519_keypair_and_jwk("test-kid-1")


def _bound_verifier(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], **kwargs: Any
) -> JwksVerifier:
    _private_key, jwk_dict = eddsa_keypair
    verifier = JwksVerifier(BASE_URL, **kwargs)
    _FakeJwksEndpoint([jwk_dict]).bind(verifier)
    return verifier


def _token(private_key: Ed25519PrivateKey, **claim_overrides: Any) -> str:
    claims: dict[str, Any] = {
        "sub": "user-1",
        "tenant_id": "acme",
        "exp": time.time() + 3600,
        "aud": EXPECTED_AUDIENCE,
    }
    claims.update(claim_overrides)
    return _sign_eddsa_token(private_key, "test-kid-1", claims)


def _metadata() -> Any:
    return protected_resource_metadata(
        resource=RESOURCE,
        authorization_servers=AUTHORIZATION_SERVERS,
        scopes_supported=SCOPES_SUPPORTED,
    )


def _make_mcp_app(verifier: JwksVerifier, client: AsyncAxiamClient) -> FastAPI:
    app = FastAPI()
    serve_protected_resource_metadata(app, _metadata(), verifier)
    dependency = require_access(
        verifier,
        "acme",
        client,
        "documents:read",
        resource_id="11111111-1111-1111-1111-111111111111",
        scope="mcp:tools",
    )

    @app.get("/mcp")
    async def mcp(user: AxiamUser = Depends(dependency)) -> dict[str, object]:  # noqa: B008
        return {"user_id": user.user_id}

    return app


# ---------------------------------------------------------------------------
# §28.9 test 3 — 401 with the challenge
# ---------------------------------------------------------------------------


def test_no_credential_401_carries_vector_1_and_unchanged_body(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    verifier = _bound_verifier(
        eddsa_keypair, expected_audience=EXPECTED_AUDIENCE, resource_metadata_url=METADATA_URL
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_mcp_app(verifier, client)
    test_client = TestClient(app)

    response = test_client.get("/mcp")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == f'Bearer resource_metadata="{METADATA_URL}"'
    assert "error_description" not in response.headers["WWW-Authenticate"]
    # The §10 body is unchanged from what this dependency returns today —
    # FastAPI's own exception handler renders a string `detail` as
    # `{"detail": ...}`.
    assert response.json() == {"detail": "missing authentication credentials"}


def test_expired_token_401_carries_vector_2(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, _jwk = eddsa_keypair
    verifier = _bound_verifier(
        eddsa_keypair, expected_audience=EXPECTED_AUDIENCE, resource_metadata_url=METADATA_URL
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_mcp_app(verifier, client)
    test_client = TestClient(app)
    expired = _token(private_key, exp=time.time() - 3600)

    response = test_client.get("/mcp", headers={"Authorization": f"Bearer {expired}"})

    assert response.status_code == 401
    assert (
        response.headers["WWW-Authenticate"]
        == f'Bearer error="invalid_token", resource_metadata="{METADATA_URL}"'
    )
    assert response.json() == {"detail": "invalid or expired token"}


def test_metadata_document_answers_without_a_credential(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    verifier = _bound_verifier(
        eddsa_keypair, expected_audience=EXPECTED_AUDIENCE, resource_metadata_url=METADATA_URL
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_mcp_app(verifier, client)
    test_client = TestClient(app)

    response = test_client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "resource": RESOURCE,
        "authorization_servers": AUTHORIZATION_SERVERS,
        "scopes_supported": SCOPES_SUPPORTED,
        "bearer_methods_supported": ["header"],
    }


# ---------------------------------------------------------------------------
# §28.9 test 4 — 403 insufficient_scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason_code", "expect_header"),
    [
        pytest.param("no_grant", True, id="no_grant-carries-challenge"),
        pytest.param("denied_by_rule", False, id="denied_by_rule-no-challenge"),
        pytest.param(None, False, id="absent-reason-code-no-challenge"),
        pytest.param("some_future_code", False, id="unrecognised-reason-code-no-challenge"),
    ],
)
def test_403_challenge_depends_on_reason_code(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    respx_mock: respx.MockRouter,
    reason_code: str | None,
    expect_header: bool,
) -> None:
    private_key, _jwk = eddsa_keypair
    verifier = _bound_verifier(
        eddsa_keypair, expected_audience=EXPECTED_AUDIENCE, resource_metadata_url=METADATA_URL
    )
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(
            200, json={"allowed": False, "reason": "no", "reason_code": reason_code}
        )
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_mcp_app(verifier, client)
    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get("/mcp", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "authorization_denied"
    if expect_header:
        assert response.headers["WWW-Authenticate"] == (
            f'Bearer error="insufficient_scope", scope="mcp:tools", '
            f'resource_metadata="{METADATA_URL}"'
        )
    else:
        assert "WWW-Authenticate" not in response.headers


def test_403_no_challenge_when_route_names_no_scope(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    verifier = _bound_verifier(
        eddsa_keypair, expected_audience=EXPECTED_AUDIENCE, resource_metadata_url=METADATA_URL
    )
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(
            200, json={"allowed": False, "reason": "no", "reason_code": "no_grant"}
        )
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = FastAPI()
    serve_protected_resource_metadata(app, _metadata(), verifier)
    dependency = require_access(
        verifier,
        "acme",
        client,
        "documents:read",
        resource_id="11111111-1111-1111-1111-111111111111",
    )

    @app.get("/mcp")
    async def mcp(user: AxiamUser = Depends(dependency)) -> dict[str, object]:  # noqa: B008
        return {"user_id": user.user_id}

    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get("/mcp", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert "WWW-Authenticate" not in response.headers


# ---------------------------------------------------------------------------
# §28.9 test 5 — a token whose aud is not the resource is refused
# ---------------------------------------------------------------------------


def test_wrong_audience_token_is_refused_401(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, _jwk = eddsa_keypair
    verifier = _bound_verifier(
        eddsa_keypair, expected_audience=EXPECTED_AUDIENCE, resource_metadata_url=METADATA_URL
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_mcp_app(verifier, client)
    test_client = TestClient(app)

    other_resource_token = _token(private_key, aud="https://other.example.com/mcp")
    response = test_client.get("/mcp", headers={"Authorization": f"Bearer {other_resource_token}"})
    assert response.status_code == 401
    assert (
        response.headers["WWW-Authenticate"]
        == f'Bearer error="invalid_token", resource_metadata="{METADATA_URL}"'
    )


def test_general_purpose_user_token_is_refused_401(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, _jwk = eddsa_keypair
    verifier = _bound_verifier(
        eddsa_keypair, expected_audience=EXPECTED_AUDIENCE, resource_metadata_url=METADATA_URL
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_mcp_app(verifier, client)
    test_client = TestClient(app)

    axiam_user_token = _token(private_key, aud="axiam:user")
    response = test_client.get("/mcp", headers={"Authorization": f"Bearer {axiam_user_token}"})
    assert response.status_code == 401


def test_matching_audience_token_is_admitted(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    verifier = _bound_verifier(
        eddsa_keypair, expected_audience=EXPECTED_AUDIENCE, resource_metadata_url=METADATA_URL
    )
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_mcp_app(verifier, client)
    test_client = TestClient(app)

    token = _token(private_key, aud=EXPECTED_AUDIENCE)
    response = test_client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_resource_metadata_url_without_expected_audience_fails_at_construction() -> None:
    with pytest.raises(ValidationError):
        JwksVerifier(BASE_URL, resource_metadata_url=METADATA_URL)


def test_serve_protected_resource_metadata_refuses_mismatched_resource_metadata_url(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    verifier = _bound_verifier(
        eddsa_keypair,
        expected_audience=EXPECTED_AUDIENCE,
        resource_metadata_url="https://mcp.example.com/.well-known/oauth-protected-resource/other",
    )
    with pytest.raises(ValidationError):
        serve_protected_resource_metadata(FastAPI(), _metadata(), verifier)


def test_serve_protected_resource_metadata_refuses_mismatched_expected_audience(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    verifier = _bound_verifier(
        eddsa_keypair,
        expected_audience="https://other.example.com/mcp",
        resource_metadata_url=METADATA_URL,
    )
    with pytest.raises(ValidationError):
        serve_protected_resource_metadata(FastAPI(), _metadata(), verifier)


# ---------------------------------------------------------------------------
# The regression that matters more than all five: off by default
# ---------------------------------------------------------------------------


def test_off_by_default_regression_no_header_anywhere(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    respx_mock: respx.MockRouter,
) -> None:
    """With ``resource_metadata_url`` unset, every response is byte-for-byte
    what it was before §28 existed: no ``WWW-Authenticate`` header on the
    200, the 401 or the 403 — asserted as the header's absence, not merely
    the status (CONTRACT.md §28.9's closing regression)."""
    private_key, _jwk = eddsa_keypair
    verifier = _bound_verifier(eddsa_keypair)  # no expected_audience, no resource_metadata_url
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(
            200, json={"allowed": False, "reason": "no", "reason_code": "no_grant"}
        )
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = FastAPI()
    dependency = require_access(
        verifier,
        "acme",
        client,
        "documents:read",
        resource_id="11111111-1111-1111-1111-111111111111",
        scope="mcp:tools",
    )

    @app.get("/mcp")
    async def mcp(user: AxiamUser = Depends(dependency)) -> dict[str, object]:  # noqa: B008
        return {"user_id": user.user_id}

    test_client = TestClient(app)

    no_credential = test_client.get("/mcp")
    assert no_credential.status_code == 401
    assert "WWW-Authenticate" not in no_credential.headers

    expired = _token(private_key, exp=time.time() - 3600)
    bad_token = test_client.get("/mcp", headers={"Authorization": f"Bearer {expired}"})
    assert bad_token.status_code == 401
    assert "WWW-Authenticate" not in bad_token.headers

    token = _token(private_key)
    denied = test_client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert denied.status_code == 403
    assert "WWW-Authenticate" not in denied.headers
