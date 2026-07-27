"""``oidc_login_router`` tests (CONTRACT.md §12, FastAPI framework glue).

Reuses the shared OIDC test kit for the discovery document / JWKS mock /
ID-token signer, and drives the router end to end through a real FastAPI
``TestClient`` (login redirect -> callback exchange).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from axiam_sdk import AsyncAxiamClient, MemoryOidcStateStore
from axiam_sdk.fastapi import oidc_login_router
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    FakeJwksEndpoint,
    discovery_document,
    make_ed25519_keypair_and_jwk,
    make_id_token_claims,
    sign_id_token,
)

REDIRECT_URI = "https://app.test/oidc/callback"


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


def _build_app(
    client: AsyncAxiamClient, store: MemoryOidcStateStore, **router_kwargs: object
) -> TestClient:
    app = FastAPI()
    app.include_router(
        oidc_login_router(client, redirect_uri=REDIRECT_URI, store=store, **router_kwargs)  # type: ignore[arg-type]
    )
    return TestClient(app, follow_redirects=False)


def test_login_redirects_to_authorization_endpoint_and_saves_state(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    store = MemoryOidcStateStore()
    app = _build_app(client, store)

    response = app.get("/login")

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(f"{BASE_URL}/oauth2/authorize?")
    query = parse_qs(urlsplit(location).query)
    assert query["client_id"] == [CLIENT_ID]
    assert query["redirect_uri"] == [REDIRECT_URI]
    assert store.size == 1


def test_login_preserves_return_to(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    store = MemoryOidcStateStore()
    app = _build_app(client, store)

    response = app.get("/login", params={"return_to": "/dashboard"})
    location = response.headers["location"]
    state = parse_qs(urlsplit(location).query)["state"][0]

    entry = store.consume(state)
    assert entry is not None
    assert entry.return_to == "/dashboard"


def test_login_unavailable_maps_to_503(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        side_effect=httpx.ConnectError("boom")
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    app = _build_app(client, MemoryOidcStateStore())

    response = app.get("/login")

    assert response.status_code == 503
    assert response.json()["detail"]["error"] == "oidc_unavailable"


def _full_login_then_callback(
    respx_mock: respx.MockRouter, **router_kwargs: object
) -> tuple[TestClient, httpx.Response]:
    _mock_discovery(respx_mock)
    private_key, jwk = make_ed25519_keypair_and_jwk()
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    FakeJwksEndpoint([jwk]).bind_to_client(client)
    store = MemoryOidcStateStore()
    router_kwargs.setdefault("tenant_id", "44444444-4444-4444-4444-444444444444")
    app = _build_app(client, store, **router_kwargs)

    login_response = app.get("/login")
    location = login_response.headers["location"]
    query = parse_qs(urlsplit(location).query)
    state = query["state"][0]
    nonce = query["nonce"][0]

    # The real IdP would echo the login's own nonce back inside the ID
    # token — build the mocked token-endpoint response only now that the
    # real nonce oidc_begin generated is known.
    id_token = sign_id_token(private_key, jwk["kid"], make_id_token_claims(nonce=nonce))
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access-1",
                "token_type": "Bearer",
                "expires_in": 900,
                "id_token": id_token,
                "scope": "openid",
            },
        )
    )

    callback_response = app.get("/callback", params={"state": state, "code": "idp-code-1"})
    return app, callback_response


def test_callback_happy_path_returns_json_summary(respx_mock: respx.MockRouter) -> None:
    _app, response = _full_login_then_callback(respx_mock)

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["sub"] == "user-1"
    assert body["expires_in"] == 900


def test_callback_calls_on_success_hook(respx_mock: respx.MockRouter) -> None:
    calls: list[tuple[object, object]] = []

    async def on_success(tokens: object, entry: object) -> None:
        calls.append((tokens, entry))

    _app, response = _full_login_then_callback(respx_mock, on_success=on_success)

    assert response.status_code == 200
    assert len(calls) == 1


def test_callback_redirects_when_success_redirect_configured(
    respx_mock: respx.MockRouter,
) -> None:
    _app, response = _full_login_then_callback(
        respx_mock, success_redirect="https://app.test/dashboard"
    )

    assert response.status_code == 302
    assert response.headers["location"] == "https://app.test/dashboard"


def test_callback_missing_state_or_code_is_400(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    app = _build_app(client, MemoryOidcStateStore())

    response = app.get("/callback", params={"state": "s"})

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_request"


def test_callback_idp_error_is_401(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    app = _build_app(client, MemoryOidcStateStore())

    response = app.get(
        "/callback",
        params={"error": "access_denied", "error_description": "user cancelled"},
    )

    assert response.status_code == 401
    assert response.json()["detail"]["message"] == "access_denied: user cancelled"


def test_callback_unknown_state_is_401(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    app = _build_app(client, MemoryOidcStateStore())

    response = app.get("/callback", params={"state": "never-issued", "code": "c"})

    assert response.status_code == 401
    assert "unknown" in response.json()["detail"]["message"]


def test_callback_replayed_state_is_401() -> None:
    """Single-use consume (§12.3 rule 1): the second use of the same
    state must fail identically to an unknown state."""
    store = MemoryOidcStateStore()
    from pydantic import SecretStr

    from axiam_sdk._oidc_state import OidcStateEntry

    store.save(
        OidcStateEntry(
            state="replay-me",
            nonce="n",
            code_verifier=SecretStr("v"),
            redirect_uri=REDIRECT_URI,
        )
    )
    assert store.consume("replay-me") is not None
    assert store.consume("replay-me") is None


def test_callback_token_exchange_network_error_is_503(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=httpx.ConnectError("boom"))
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    store = MemoryOidcStateStore()
    app = _build_app(client, store, tenant_id="55555555-5555-5555-5555-555555555555")

    login_response = app.get("/login")
    state = parse_qs(urlsplit(login_response.headers["location"]).query)["state"][0]

    response = app.get("/callback", params={"state": state, "code": "c"})

    assert response.status_code == 503
    assert response.json()["detail"]["error"] == "oidc_unavailable"


def test_callback_oauth_protocol_error_is_401(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "code replayed"}
        )
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    store = MemoryOidcStateStore()
    app = _build_app(client, store, tenant_id="66666666-6666-6666-6666-666666666666")

    login_response = app.get("/login")
    state = parse_qs(urlsplit(login_response.headers["location"]).query)["state"][0]

    response = app.get("/callback", params={"state": state, "code": "c"})

    assert response.status_code == 401
    assert response.json()["detail"]["message"] == "invalid_grant: code replayed"
