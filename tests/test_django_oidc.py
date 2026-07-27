"""``oidc_login_views`` tests (CONTRACT.md §12, Django framework glue).

Configures minimal Django settings in-test (guarded, mirroring
``test_django_middleware.py``/``test_django_decorators.py`` so multiple
test modules sharing one process do not double-configure), and drives the
returned ``(login_view, callback_view)`` pair as plain functions against a
``django.test.RequestFactory`` request.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import django
import httpx
import respx
from django.conf import settings as django_settings
from django.http import HttpResponseRedirect, JsonResponse
from django.test import RequestFactory

if not django_settings.configured:
    django_settings.configure(DEBUG=True, USE_TZ=True)
    django.setup()

from axiam_sdk import AxiamClient, MemoryOidcStateStore  # noqa: E402
from axiam_sdk.django.oidc import oidc_login_views  # noqa: E402
from tests._oidc_testkit import (  # noqa: E402
    BASE_URL,
    CLIENT_ID,
    FakeJwksEndpoint,
    discovery_document,
    make_ed25519_keypair_and_jwk,
    make_id_token_claims,
    sign_id_token,
)

REDIRECT_URI = "https://app.test/oidc/callback"
TENANT_ID = "77777777-7777-7777-7777-777777777777"


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


def test_login_view_redirects_and_saves_state(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    store = MemoryOidcStateStore()
    login_view, _callback_view = oidc_login_views(
        client, redirect_uri=REDIRECT_URI, store=store, tenant_id=TENANT_ID
    )

    response = login_view(RequestFactory().get("/oidc/login"))

    assert isinstance(response, HttpResponseRedirect)
    location = response.headers["Location"]
    assert location.startswith(f"{BASE_URL}/oauth2/authorize?")
    query = parse_qs(urlsplit(location).query)
    assert query["client_id"] == [CLIENT_ID]
    assert store.size == 1


def test_login_view_preserves_return_to(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    store = MemoryOidcStateStore()
    login_view, _callback_view = oidc_login_views(
        client, redirect_uri=REDIRECT_URI, store=store, tenant_id=TENANT_ID
    )

    response = login_view(RequestFactory().get("/oidc/login", {"return_to": "/dashboard"}))
    state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]

    entry = store.consume(state)
    assert entry is not None
    assert entry.return_to == "/dashboard"


def test_login_view_unavailable_maps_to_503(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        side_effect=httpx.ConnectError("boom")
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    login_view, _callback_view = oidc_login_views(
        client, redirect_uri=REDIRECT_URI, tenant_id=TENANT_ID
    )

    response = login_view(RequestFactory().get("/oidc/login"))

    assert isinstance(response, JsonResponse)
    assert response.status_code == 503


def _full_login_then_callback(
    respx_mock: respx.MockRouter, **view_kwargs: object
) -> tuple[object, object]:
    _mock_discovery(respx_mock)
    private_key, jwk = make_ed25519_keypair_and_jwk()
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    FakeJwksEndpoint([jwk]).bind_to_client(client)
    store = MemoryOidcStateStore()
    view_kwargs.setdefault("tenant_id", TENANT_ID)
    login_view, callback_view = oidc_login_views(
        client,
        redirect_uri=REDIRECT_URI,
        store=store,
        **view_kwargs,  # type: ignore[arg-type]
    )

    login_response = login_view(RequestFactory().get("/oidc/login"))
    query = parse_qs(urlsplit(login_response.headers["Location"]).query)
    state = query["state"][0]
    nonce = query["nonce"][0]

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

    callback_request = RequestFactory().get(
        "/oidc/callback", {"state": state, "code": "idp-code-1"}
    )
    callback_response = callback_view(callback_request)
    return login_response, callback_response


def test_callback_view_happy_path_returns_json_summary(respx_mock: respx.MockRouter) -> None:
    _login, callback = _full_login_then_callback(respx_mock)

    assert isinstance(callback, JsonResponse)
    assert callback.status_code == 200
    import json

    body = json.loads(callback.content)
    assert body["authenticated"] is True
    assert body["sub"] == "user-1"


def test_callback_view_calls_on_success_hook(respx_mock: respx.MockRouter) -> None:
    calls: list[tuple[object, object]] = []

    def on_success(tokens: object, entry: object) -> None:
        calls.append((tokens, entry))

    _login, callback = _full_login_then_callback(respx_mock, on_success=on_success)

    assert callback.status_code == 200
    assert len(calls) == 1


def test_callback_view_redirects_when_success_redirect_configured(
    respx_mock: respx.MockRouter,
) -> None:
    _login, callback = _full_login_then_callback(
        respx_mock, success_redirect="https://app.test/dashboard"
    )

    assert isinstance(callback, HttpResponseRedirect)
    assert callback.headers["Location"] == "https://app.test/dashboard"


def test_callback_view_missing_state_or_code_is_400() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    _login_view, callback_view = oidc_login_views(
        client, redirect_uri=REDIRECT_URI, tenant_id=TENANT_ID
    )

    response = callback_view(RequestFactory().get("/oidc/callback", {"state": "s"}))

    assert isinstance(response, JsonResponse)
    assert response.status_code == 400


def test_callback_view_idp_error_is_401() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    _login_view, callback_view = oidc_login_views(
        client, redirect_uri=REDIRECT_URI, tenant_id=TENANT_ID
    )

    response = callback_view(
        RequestFactory().get(
            "/oidc/callback", {"error": "access_denied", "error_description": "nope"}
        )
    )

    assert response.status_code == 401


def test_callback_view_unknown_state_is_401() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    _login_view, callback_view = oidc_login_views(
        client, redirect_uri=REDIRECT_URI, tenant_id=TENANT_ID
    )

    response = callback_view(
        RequestFactory().get("/oidc/callback", {"state": "never-issued", "code": "c"})
    )

    assert response.status_code == 401


def test_callback_view_oauth_protocol_error_is_401(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "code replayed"}
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    store = MemoryOidcStateStore()
    login_view, callback_view = oidc_login_views(
        client, redirect_uri=REDIRECT_URI, store=store, tenant_id=TENANT_ID
    )

    login_response = login_view(RequestFactory().get("/oidc/login"))
    state = parse_qs(urlsplit(login_response.headers["Location"]).query)["state"][0]

    response = callback_view(RequestFactory().get("/oidc/callback", {"state": state, "code": "c"}))

    assert response.status_code == 401
    import json

    assert json.loads(response.content)["message"] == "invalid_grant: code replayed"


def test_login_and_callback_share_the_same_default_store(respx_mock: respx.MockRouter) -> None:
    """When no ``store`` is supplied, the same
    :class:`~axiam_sdk.MemoryOidcStateStore` instance backs BOTH returned
    views — a caller who forgot to pass one still gets a working pair."""
    _mock_discovery(respx_mock)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    login_view, callback_view = oidc_login_views(
        client, redirect_uri=REDIRECT_URI, tenant_id=TENANT_ID
    )

    login_response = login_view(RequestFactory().get("/oidc/login"))
    state = parse_qs(urlsplit(login_response.headers["Location"]).query)["state"][0]

    # A broken token endpoint surfaces as 503 only AFTER the store lookup
    # succeeds — proving the state WAS found (i.e. login_view and
    # callback_view share one store instance; an unshared pair would 401
    # with "unknown ... login state" instead).
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=httpx.ConnectError("boom"))
    response = callback_view(RequestFactory().get("/oidc/callback", {"state": state, "code": "c"}))
    assert response.status_code == 503
