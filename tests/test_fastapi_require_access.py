"""Regression tests for the FastAPI declarative authorization helpers
``require_access``/``require_role`` (CONTRACT.md §11).

Reuses the in-test Ed25519 keypair + mock JWKS pattern from
``test_fastapi_dependency.py`` (no real network fetch for JWKS is ever
attempted) and mocks the ``/api/v1/authz/check`` endpoint via ``respx`` (no
live AXIAM server).

Verifies the full CONTRACT.md §11 matrix:
  - allow (``allowed: true``) -> 200, identity returned to the handler;
  - deny (``allowed: false``) -> 403 ``authorization_denied``;
  - a 403 from the server itself (e.g. missing ``authz:check_as``) is also
    mapped to 403 ``authorization_denied``;
  - unauthenticated (no token) -> 401, no authz call is ever made;
  - a missing/unparseable resource id (bad UUID, or an absent path param) ->
    400 ``invalid_request``, no authz call is ever made;
  - a transport failure calling the authz endpoint (server 500) -> 503
    ``authz_unavailable``, fail closed;
  - ``subject_id`` on the wire is the *authenticated caller's* ``user_id``,
    never the client's own service-account identity;
  - ``scope`` passthrough;
  - no raw token value ever appears in any response body;
  - ``require_access`` rejects ambiguous/missing resource-source
    configuration eagerly, at factory-construction time;
  - ``require_role`` is a local check: 200 with a matching role, 403 without,
    with no authz-endpoint call at all.
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

from axiam_sdk import AsyncAxiamClient
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk.fastapi import AxiamUser, require_access, require_role

BASE_URL = "https://axiam.example.test"


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


@pytest.fixture
def verifier(eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> JwksVerifier:
    _private_key, jwk_dict = eddsa_keypair
    v = JwksVerifier(BASE_URL)
    _FakeJwksEndpoint([jwk_dict]).bind(v)
    return v


def _token(private_key: Ed25519PrivateKey, **claim_overrides: Any) -> str:
    claims = {"sub": "user-1", "tenant_id": "acme", "exp": time.time() + 3600, "scope": "reader"}
    claims.update(claim_overrides)
    return _sign_eddsa_token(private_key, "test-kid-1", claims)


def _make_access_app(
    verifier: JwksVerifier,
    client: AsyncAxiamClient,
    action: str = "documents:read",
    **kwargs: Any,
) -> FastAPI:
    app = FastAPI()
    dependency = require_access(verifier, "acme", client, action, **kwargs)

    @app.get("/docs/{doc_id}")
    async def get_doc(
        doc_id: str,
        user: AxiamUser = Depends(dependency),  # noqa: B008
    ) -> dict[str, object]:
        return {"user_id": user.user_id, "doc_id": doc_id}

    return app


def _make_role_app(verifier: JwksVerifier, *roles: str) -> FastAPI:
    app = FastAPI()
    dependency = require_role(verifier, "acme", *roles)

    @app.get("/admin")
    async def admin(user: AxiamUser = Depends(dependency)) -> dict[str, object]:  # noqa: B008
        return {"user_id": user.user_id}

    return app


RESOURCE_ID = "11111111-1111-1111-1111-111111111111"


def test_allowed_returns_200_and_identity(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(verifier, client, resource_param="doc_id")
    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get(f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"user_id": "user-1", "doc_id": RESOURCE_ID}


def test_subject_id_and_action_on_the_wire(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    """§11.2.2: the check MUST be made for the request's authenticated user
    (subject_id), never the client's own service-account identity."""
    private_key, _jwk = eddsa_keypair
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(verifier, client, "documents:read", resource_param="doc_id")
    test_client = TestClient(app)
    token = _token(private_key, sub="requesting-user-42")

    response = test_client.get(f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    import json

    sent = json.loads(route.calls.last.request.content)
    assert sent["subject_id"] == "requesting-user-42"
    assert sent["action"] == "documents:read"
    assert sent["resource_id"] == RESOURCE_ID
    assert "scope" not in sent


def test_scope_passthrough(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(
        verifier, client, "documents:read", resource_param="doc_id", scope="field:email"
    )
    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get(f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    import json

    sent = json.loads(route.calls.last.request.content)
    assert sent["scope"] == "field:email"


def test_denied_yields_403(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": False, "reason": "no permission"})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(verifier, client, resource_param="doc_id")
    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get(f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "authorization_denied"


def test_server_403_yields_403(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    """A 403 from the server itself (e.g. the client lacks authz:check_as
    for subject_id) maps to AuthzError, which the helper also surfaces as
    403 authorization_denied."""
    private_key, _jwk = eddsa_keypair
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(verifier, client, resource_param="doc_id")
    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get(f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "authorization_denied"


def test_unauthenticated_yields_401_and_no_authz_call(
    verifier: JwksVerifier, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(verifier, client, resource_param="doc_id")
    test_client = TestClient(app)

    response = test_client.get(f"/docs/{RESOURCE_ID}")

    assert response.status_code == 401
    assert not route.called


def test_bad_uuid_resource_param_yields_400_and_no_authz_call(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(verifier, client, resource_param="doc_id")
    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get("/docs/not-a-uuid", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_request"
    assert not route.called


def test_missing_resource_param_yields_400(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], verifier: JwksVerifier
) -> None:
    """A resource_param naming a path parameter absent from THIS route is a
    programming error -> 400, never a silent allow."""
    private_key, _jwk = eddsa_keypair
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = FastAPI()
    dependency = require_access(
        verifier, "acme", client, "documents:read", resource_param="does_not_exist"
    )

    @app.get("/docs/{doc_id}")
    async def get_doc(
        doc_id: str,
        user: AxiamUser = Depends(dependency),  # noqa: B008
    ) -> dict[str, object]:
        return {"user_id": user.user_id}

    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get(f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_request"


def test_network_failure_fails_closed_with_503(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(500, json={"error": "boom"})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(verifier, client, resource_param="doc_id")
    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get(f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 503
    assert response.json()["detail"]["error"] == "authz_unavailable"


def test_literal_resource_id_used_over_param(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    """The static resource_id literal is the highest-precedence resource
    source (§11.2.3)."""
    private_key, _jwk = eddsa_keypair
    literal_id = "22222222-2222-2222-2222-222222222222"
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = FastAPI()
    dependency = require_access(verifier, "acme", client, "documents:read", resource_id=literal_id)

    @app.get("/singleton")
    async def singleton(user: AxiamUser = Depends(dependency)) -> dict[str, object]:  # noqa: B008
        return {"user_id": user.user_id}

    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get("/singleton", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    import json

    sent = json.loads(route.calls.last.request.content)
    assert sent["resource_id"] == literal_id


def test_resolver_callback_used(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    resolved_id = "33333333-3333-3333-3333-333333333333"
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = FastAPI()
    dependency = require_access(
        verifier,
        "acme",
        client,
        "documents:read",
        resolver=lambda request: request.headers.get("x-doc-id", ""),
    )

    @app.get("/via-header")
    async def via_header(user: AxiamUser = Depends(dependency)) -> dict[str, object]:  # noqa: B008
        return {"user_id": user.user_id}

    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get(
        "/via-header",
        headers={"Authorization": f"Bearer {token}", "x-doc-id": resolved_id},
    )

    assert response.status_code == 200
    import json

    sent = json.loads(route.calls.last.request.content)
    assert sent["resource_id"] == resolved_id


def test_resolver_raising_is_400(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], verifier: JwksVerifier
) -> None:
    private_key, _jwk = eddsa_keypair
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = FastAPI()

    def _boom(_request: Any) -> str:
        raise ValueError("no composite key available")

    dependency = require_access(verifier, "acme", client, "documents:read", resolver=_boom)

    @app.get("/via-resolver")
    async def via_resolver(user: AxiamUser = Depends(dependency)) -> dict[str, object]:  # noqa: B008
        return {"user_id": user.user_id}

    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get("/via-resolver", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_request"


def test_require_access_requires_exactly_one_resource_source(verifier: JwksVerifier) -> None:
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")

    with pytest.raises(ValueError, match="exactly one"):
        require_access(verifier, "acme", client, "documents:read")

    with pytest.raises(ValueError, match="exactly one"):
        require_access(
            verifier,
            "acme",
            client,
            "documents:read",
            resource_id="11111111-1111-1111-1111-111111111111",
            resource_param="doc_id",
        )


def test_no_token_value_in_any_response(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": False, "reason": None})
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    app = _make_access_app(verifier, client, resource_param="doc_id")
    test_client = TestClient(app)
    token = _token(private_key)

    response = test_client.get(f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert token not in response.text


# ---------------------------------------------------------------------
# require_role
# ---------------------------------------------------------------------


def test_require_role_allows_matching_role(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], verifier: JwksVerifier
) -> None:
    private_key, _jwk = eddsa_keypair
    app = _make_role_app(verifier, "admin", "auditor")
    test_client = TestClient(app)
    token = _token(private_key, scope="auditor")

    response = test_client.get("/admin", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200


def test_require_role_denies_missing_role(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], verifier: JwksVerifier
) -> None:
    private_key, _jwk = eddsa_keypair
    app = _make_role_app(verifier, "admin")
    test_client = TestClient(app)
    token = _token(private_key, scope="reader")

    response = test_client.get("/admin", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "authorization_denied"


def test_require_role_unauthenticated_yields_401(verifier: JwksVerifier) -> None:
    app = _make_role_app(verifier, "admin")
    test_client = TestClient(app)

    response = test_client.get("/admin")

    assert response.status_code == 401
