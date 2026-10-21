"""No ``axiam_*`` session cookie and no ``X-CSRF-Token`` on ``/oauth2/*`` -- CONTRACT.md
§6.1 rule 11, §12.1 rule 3, §14.6 third paragraph (contract 1.63, #100 item 2); and an
explicit PAT beats an adopted credential on ``/uma2/*`` (#100 item 1).

The control in each test (an ``/api/v1`` request *does* carry the cookie and the CSRF
header) is what makes "nothing at ``/oauth2/*``" mean something.
"""

from __future__ import annotations

import secrets

import httpx
import pytest
import respx
from pydantic import SecretStr

from axiam_sdk import AsyncAxiamClient, AxiamClient, ResourceSet
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    DEVICE_AUTHORIZATION_ENDPOINT,
    DEVICE_CODE,
    device_authorization_response,
    discovery_document,
)

TENANT_ID = "11111111-1111-1111-1111-111111111111"
TOKEN_ENDPOINT = f"{BASE_URL}/oauth2/token"
CONTROL = f"{BASE_URL}/api/v1/auth/session"
HOST = "axiam.example.test"
SESSION_COOKIES = ("axiam_access", "axiam_refresh", "axiam_csrf")
TOKEN_BODY = {"access_token": "t", "token_type": "Bearer", "expires_in": 900}


def _mount(router: respx.MockRouter) -> dict[str, respx.Route]:
    router.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    return {
        "authorize": router.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
            return_value=httpx.Response(200, json=device_authorization_response())
        ),
        "token": router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json=TOKEN_BODY)
        ),
        "control": router.post(CONTROL).mock(return_value=httpx.Response(200, json={})),
    }


def _hold_session(client: AxiamClient | AsyncAxiamClient) -> None:
    """A jar holding the three session cookies and a captured CSRF token."""
    for name in SESSION_COOKIES:
        client._session._cookies.set(name, secrets.token_urlsafe(8), domain=HOST, path="/")
    client._session._csrf_token = secrets.token_urlsafe(8)


def _assert_no_session_state(routes: dict[str, respx.Route]) -> None:
    for name in ("authorize", "token"):
        assert routes[name].call_count >= 1, f"{name} was never reached"
        for call in routes[name].calls:
            headers = call.request.headers
            assert not headers.get("cookie"), f"cookie at {call.request.url.path}"
            assert "x-csrf-token" not in headers, f"CSRF header at {call.request.url.path}"
            assert headers["x-tenant-id"] == "acme"


def _assert_control_carries_both(routes: dict[str, respx.Route]) -> None:
    sent = routes["control"].calls[0].request.headers
    assert all(f"{name}=" in sent["cookie"] for name in SESSION_COOKIES)
    assert "x-csrf-token" in sent


def _client() -> AxiamClient:
    return AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )


def test_device_authorize_poll_and_token_send_no_session_cookie_or_csrf(
    respx_mock: respx.MockRouter,
) -> None:
    routes = _mount(respx_mock)
    client = _client()
    _hold_session(client)

    client._rest_send_sync(
        client._session.sync_client.build_request("POST", "/api/v1/auth/session")
    )
    client.device_authorize(scope="openid", tenant_id=TENANT_ID)
    client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    client.login_client_credentials(tenant_id=TENANT_ID)

    assert routes["token"].call_count == 2
    _assert_no_session_state(routes)
    _assert_control_carries_both(routes)


@pytest.mark.asyncio
async def test_async_device_and_token_requests_send_no_session_cookie_or_csrf(
    respx_mock: respx.MockRouter,
) -> None:
    routes = _mount(respx_mock)
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )
    _hold_session(client)

    await client._rest_send_async(
        client._session.async_client.build_request("POST", "/api/v1/auth/session")
    )
    await client.device_authorize(scope="openid", tenant_id=TENANT_ID)
    await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    await client.login_client_credentials(tenant_id=TENANT_ID)

    _assert_no_session_state(routes)
    _assert_control_carries_both(routes)
    await client.aclose()


def test_an_explicit_pat_wins_over_the_adopted_credential_on_uma2(
    respx_mock: respx.MockRouter,
) -> None:
    pat = secrets.token_urlsafe(16)
    adopted = secrets.token_urlsafe(16)
    route = respx_mock.post(f"{BASE_URL}/uma2/rreg/resource_set").mock(
        return_value=httpx.Response(201, json={"_id": "res-1", "name": "doc"})
    )
    client = _client()
    client._session.adopt_bearer_credential(SecretStr(adopted))

    client.uma_register_resource(pat, ResourceSet(name="doc"))

    sent = route.calls[0].request.headers
    assert sent["authorization"] == f"Bearer {pat}"
    assert adopted not in str(sent)
