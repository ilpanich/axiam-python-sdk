"""Regression tests for the Django middleware/decorators' half of CONTRACT.md
§28 (MCP resource-server helpers, RFC 9728 + RFC 6750) — §28.9 required
tests 3, 4 and 5, plus the off-by-default regression that matters more than
all five. Tests 1 and 2 (framework-independent) live in ``test_mcp.py``.

Reuses the in-test Ed25519 keypair + mock JWKS pattern and the
monkeypatched-``JwksVerifier.__init__`` binding trick from
``test_django_middleware.py``, and the ``request.axiam_user`` / mocked
``check_access`` pattern from ``test_django_decorators.py``. CONTRACT.md
§28's Django-specific settings (``AXIAM_RESOURCE_METADATA_URL``,
``AXIAM_EXPECTED_AUDIENCE``) are supplied per test via
``django.test.override_settings`` rather than the shared module-level
``configure(...)`` call — Django settings are configured exactly once per
process, and turning §28 on for every Django test in this suite by default
would defeat the very byte-for-byte-off-by-default regression §28.9 requires.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import django
import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings as django_settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory, override_settings

if not django_settings.configured:
    django_settings.configure(
        DEBUG=True,
        USE_TZ=True,
        AXIAM_JWKS_BASE_URL="https://axiam.example.test",
        AXIAM_TENANT_SLUG="acme",
    )
    django.setup()

from axiam_sdk import AxiamClient, protected_resource_metadata  # noqa: E402
from axiam_sdk._jwks import JwksVerifier  # noqa: E402
from axiam_sdk.django.decorators import require_access  # noqa: E402
from axiam_sdk.django.mcp import serve_protected_resource_metadata  # noqa: E402
from axiam_sdk.django.middleware import AxiamAuthMiddleware, AxiamUser  # noqa: E402
from axiam_sdk.management import ValidationError  # noqa: E402

BASE_URL = "https://axiam.example.test"

RESOURCE = "https://mcp.example.com/mcp"
AUTHORIZATION_SERVERS = ["https://axiam.example.com"]
SCOPES_SUPPORTED = ["mcp:read", "mcp:tools"]
METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
METADATA_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
EXPECTED_AUDIENCE = "https://mcp.example.com/mcp"
RESOURCE_ID = "11111111-1111-1111-1111-111111111111"

_MCP_SETTINGS = {
    "AXIAM_RESOURCE_METADATA_URL": METADATA_URL,
    "AXIAM_EXPECTED_AUDIENCE": EXPECTED_AUDIENCE,
}


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
def bound_jwks(eddsa_keypair, monkeypatch) -> None:
    """Bind the fake JWKS endpoint onto the real, per-instance verifier a
    freshly constructed ``AxiamAuthMiddleware`` builds internally — same
    monkeypatch-``JwksVerifier.__init__`` trick as ``test_django_middleware.py``,
    so no real network fetch is ever attempted."""
    _private_key, jwk_dict = eddsa_keypair
    endpoint = _FakeJwksEndpoint([jwk_dict])
    real_init = JwksVerifier.__init__

    def patched_init(self: JwksVerifier, base_url: str, **kwargs: Any) -> None:
        real_init(self, base_url, **kwargs)
        endpoint.bind(self)

    monkeypatch.setattr(JwksVerifier, "__init__", patched_init)


def _token(private_key: Ed25519PrivateKey, **claim_overrides: Any) -> str:
    claims: dict[str, Any] = {
        "sub": "user-1",
        "tenant_id": "acme",
        "exp": time.time() + 3600,
        "aud": EXPECTED_AUDIENCE,
    }
    claims.update(claim_overrides)
    return _sign_eddsa_token(private_key, "test-kid-1", claims)


def _sentinel_response(_request: HttpRequest) -> HttpResponse:
    return JsonResponse({"reached": "protected view"})


# ---------------------------------------------------------------------------
# §28.9 test 3 — 401 with the challenge, and the metadata document
# ---------------------------------------------------------------------------


@override_settings(**_MCP_SETTINGS)
def test_no_credential_401_carries_vector_1_and_unchanged_body(bound_jwks: None) -> None:
    middleware = AxiamAuthMiddleware(_sentinel_response)
    request = RequestFactory().get("/mcp")

    response = middleware(request)

    assert response.status_code == 401
    assert response["WWW-Authenticate"] == f'Bearer resource_metadata="{METADATA_URL}"'
    assert json.loads(response.content) == {
        "error": "authentication_failed",
        "message": "missing authentication credentials",
    }


@override_settings(**_MCP_SETTINGS)
def test_expired_token_401_carries_vector_2(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], bound_jwks: None
) -> None:
    private_key, _jwk = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sentinel_response)
    expired = _token(private_key, exp=time.time() - 3600)
    request = RequestFactory().get("/mcp", HTTP_AUTHORIZATION=f"Bearer {expired}")

    response = middleware(request)

    assert response.status_code == 401
    assert (
        response["WWW-Authenticate"]
        == f'Bearer error="invalid_token", resource_metadata="{METADATA_URL}"'
    )
    assert json.loads(response.content) == {
        "error": "authentication_failed",
        "message": "invalid or expired token",
    }


@override_settings(**_MCP_SETTINGS)
def test_metadata_document_answers_without_a_credential_with_guard_global(bound_jwks: None) -> None:
    """A GET of the metadata path with no credential returns 200 and the
    document, with the guard (``AxiamAuthMiddleware``) registered globally —
    i.e. the middleware exempts the path and the request reaches the actual
    ``serve_protected_resource_metadata`` view."""
    urlpatterns: list[Any] = []
    metadata = protected_resource_metadata(
        resource=RESOURCE,
        authorization_servers=AUTHORIZATION_SERVERS,
        scopes_supported=SCOPES_SUPPORTED,
    )
    serve_protected_resource_metadata(
        urlpatterns,
        metadata,
        expected_audience=EXPECTED_AUDIENCE,
        resource_metadata_url=METADATA_URL,
    )
    view = urlpatterns[0].callback

    middleware = AxiamAuthMiddleware(view)
    request = RequestFactory().get(METADATA_PATH)

    response = middleware(request)

    assert response.status_code == 200
    assert response["Content-Type"] == "application/json"
    assert json.loads(response.content) == {
        "resource": RESOURCE,
        "authorization_servers": AUTHORIZATION_SERVERS,
        "scopes_supported": SCOPES_SUPPORTED,
        "bearer_methods_supported": ["header"],
    }


# ---------------------------------------------------------------------------
# §28.9 test 4 — 403 insufficient_scope
# ---------------------------------------------------------------------------


def _authenticated_request(path: str = "/mcp") -> HttpRequest:
    request = RequestFactory().get(path)
    request.axiam_user = AxiamUser(user_id="user-1", tenant_id="acme", roles=[])  # type: ignore[attr-defined]
    return request


def _sync_view(request: HttpRequest) -> HttpResponse:
    return JsonResponse({"user_id": request.axiam_user.user_id})  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("reason_code", "expect_header"),
    [
        pytest.param("no_grant", True, id="no_grant-carries-challenge"),
        pytest.param("denied_by_rule", False, id="denied_by_rule-no-challenge"),
        pytest.param(None, False, id="absent-reason-code-no-challenge"),
        pytest.param("some_future_code", False, id="unrecognised-reason-code-no-challenge"),
    ],
)
@override_settings(**_MCP_SETTINGS)
def test_403_challenge_depends_on_reason_code(
    respx_mock: respx.MockRouter, reason_code: str | None, expect_header: bool
) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(
            200, json={"allowed": False, "reason": "no", "reason_code": reason_code}
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="doc_id", scope="mcp:tools")(
        _sync_view
    )
    request = _authenticated_request()

    response = view(request, doc_id=RESOURCE_ID)

    assert response.status_code == 403
    assert json.loads(response.content)["error"] == "authorization_denied"
    if expect_header:
        assert response["WWW-Authenticate"] == (
            f'Bearer error="insufficient_scope", scope="mcp:tools", '
            f'resource_metadata="{METADATA_URL}"'
        )
    else:
        assert "WWW-Authenticate" not in response


@override_settings(**_MCP_SETTINGS)
def test_403_no_challenge_when_route_names_no_scope(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(
            200, json={"allowed": False, "reason": "no", "reason_code": "no_grant"}
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="doc_id")(_sync_view)
    request = _authenticated_request()

    response = view(request, doc_id=RESOURCE_ID)

    assert response.status_code == 403
    assert "WWW-Authenticate" not in response


# ---------------------------------------------------------------------------
# §28.9 test 5 — a token whose aud is not the resource is refused
# ---------------------------------------------------------------------------


@override_settings(**_MCP_SETTINGS)
def test_wrong_audience_token_is_refused_401(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], bound_jwks: None
) -> None:
    private_key, _jwk = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sentinel_response)
    other_resource_token = _token(private_key, aud="https://other.example.com/mcp")
    request = RequestFactory().get("/mcp", HTTP_AUTHORIZATION=f"Bearer {other_resource_token}")

    response = middleware(request)

    assert response.status_code == 401
    assert (
        response["WWW-Authenticate"]
        == f'Bearer error="invalid_token", resource_metadata="{METADATA_URL}"'
    )


@override_settings(**_MCP_SETTINGS)
def test_general_purpose_user_token_is_refused_401(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], bound_jwks: None
) -> None:
    private_key, _jwk = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sentinel_response)
    axiam_user_token = _token(private_key, aud="axiam:user")
    request = RequestFactory().get("/mcp", HTTP_AUTHORIZATION=f"Bearer {axiam_user_token}")

    response = middleware(request)

    assert response.status_code == 401


@override_settings(**_MCP_SETTINGS)
def test_matching_audience_token_is_admitted(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]], bound_jwks: None
) -> None:
    private_key, _jwk = eddsa_keypair
    middleware = AxiamAuthMiddleware(_sentinel_response)
    token = _token(private_key, aud=EXPECTED_AUDIENCE)
    request = RequestFactory().get("/mcp", HTTP_AUTHORIZATION=f"Bearer {token}")

    response = middleware(request)

    assert response.status_code == 200
    assert request.axiam_user.user_id == "user-1"  # type: ignore[attr-defined]


def test_resource_metadata_url_without_expected_audience_fails_at_construction() -> None:
    with override_settings(AXIAM_RESOURCE_METADATA_URL=METADATA_URL):
        with pytest.raises(ValidationError):
            AxiamAuthMiddleware(_sentinel_response)


def test_serve_protected_resource_metadata_refuses_mismatched_resource_metadata_url() -> None:
    metadata = protected_resource_metadata(
        resource=RESOURCE,
        authorization_servers=AUTHORIZATION_SERVERS,
        scopes_supported=SCOPES_SUPPORTED,
    )
    with pytest.raises(ValidationError):
        serve_protected_resource_metadata(
            [],
            metadata,
            expected_audience=EXPECTED_AUDIENCE,
            resource_metadata_url="https://mcp.example.com/.well-known/oauth-protected-resource/other",
        )


def test_serve_protected_resource_metadata_refuses_mismatched_expected_audience() -> None:
    metadata = protected_resource_metadata(
        resource=RESOURCE,
        authorization_servers=AUTHORIZATION_SERVERS,
        scopes_supported=SCOPES_SUPPORTED,
    )
    with pytest.raises(ValidationError):
        serve_protected_resource_metadata(
            [],
            metadata,
            expected_audience="https://other.example.com/mcp",
            resource_metadata_url=METADATA_URL,
        )


@override_settings(**_MCP_SETTINGS)
def test_missing_middleware_401_from_decorator_carries_challenge() -> None:
    """§28.5 rule 4 names "§11's require_auth/authentication_failed 401" —
    this decorator's own 401, reached when ``AxiamAuthMiddleware`` was never
    installed (or bypassed, as here)."""
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="doc_id", scope="mcp:tools")(
        _sync_view
    )
    request = RequestFactory().get("/mcp")

    response = view(request, doc_id=RESOURCE_ID)

    assert response.status_code == 401
    assert response["WWW-Authenticate"] == f'Bearer resource_metadata="{METADATA_URL}"'


# ---------------------------------------------------------------------------
# The regression that matters more than all five: off by default
# ---------------------------------------------------------------------------


def test_off_by_default_regression_no_header_anywhere(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    bound_jwks: None,
    respx_mock: respx.MockRouter,
) -> None:
    """With ``AXIAM_RESOURCE_METADATA_URL`` unset, every response is
    byte-for-byte what it was before §28 existed: no ``WWW-Authenticate``
    header on the 200, the 401 or the 403 — asserted as the header's
    absence, not merely the status."""
    private_key, _jwk = eddsa_keypair
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(
            200, json={"allowed": False, "reason": "no", "reason_code": "no_grant"}
        )
    )

    middleware = AxiamAuthMiddleware(_sentinel_response)

    no_credential = middleware(RequestFactory().get("/mcp"))
    assert no_credential.status_code == 401
    assert "WWW-Authenticate" not in no_credential

    expired = _token(private_key, exp=time.time() - 3600)
    bad_token = middleware(RequestFactory().get("/mcp", HTTP_AUTHORIZATION=f"Bearer {expired}"))
    assert bad_token.status_code == 401
    assert "WWW-Authenticate" not in bad_token

    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="doc_id", scope="mcp:tools")(
        _sync_view
    )
    request = _authenticated_request()
    denied = view(request, doc_id=RESOURCE_ID)
    assert denied.status_code == 403
    assert "WWW-Authenticate" not in denied
