"""No ``axiam_*`` session cookie and no ``X-CSRF-Token`` on ``/oauth2/*`` -- CONTRACT.md
§6.1 rule 11, §12.1 rule 3, §14.6 third paragraph (contract 1.63, #100 item 2); and an
explicit PAT beats an adopted credential on ``/uma2/*`` (#100 item 1) and travels without
session state after a cookie login (C163-14).

The session arrives the way a caller's does -- from a mocked ``login()`` that sets
``axiam_access``, ``axiam_refresh`` and ``axiam_csrf`` and returns ``X-CSRF-Token`` -- and the
control (a management ``POST`` that *does* carry the cookie and the CSRF header) is sent
**after** the calls under test, where §14.6 asks for it (C163-08).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable

import httpx
import pytest
import respx
from pydantic import SecretStr

from axiam_sdk import AsyncAxiamClient, AxiamClient, RequestedPermission, ResourceSet
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    DEVICE_AUTHORIZATION_ENDPOINT,
    DEVICE_CODE,
    device_authorization_response,
    discovery_document,
)
from tests.test_client_login import _make_access_token

TENANT_ID = "11111111-1111-1111-1111-111111111111"
TOKEN_ENDPOINT = f"{BASE_URL}/oauth2/token"
LOGIN = f"{BASE_URL}/api/v1/auth/login"
CONTROL = f"{BASE_URL}/api/v1/groups"
CSRF = "csrf-from-login"
TOKEN_BODY = {"access_token": "t", "token_type": "Bearer", "expires_in": 900}


def _login_response(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={"user": {"id": "user-1"}, "session_id": "session-1", "expires_in": 900},
        headers=[
            ("Set-Cookie", f"axiam_access={_make_access_token()}; Path=/; HttpOnly"),
            ("Set-Cookie", "axiam_refresh=refresh-1; Path=/api/v1/auth/refresh; HttpOnly"),
            ("Set-Cookie", f"axiam_csrf={CSRF}; Path=/"),
            ("X-CSRF-Token", CSRF),
        ],
    )


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
        "login": router.post(LOGIN).mock(side_effect=_login_response),
        "control": router.post(CONTROL).mock(return_value=httpx.Response(200, json={})),
    }


def _assert_no_session_state(routes: dict[str, respx.Route]) -> None:
    for name in ("authorize", "token"):
        assert routes[name].call_count >= 1, f"{name} was never reached"
        for call in routes[name].calls:
            headers = call.request.headers
            assert not headers.get("cookie"), f"cookie at {call.request.url.path}"
            assert "x-csrf-token" not in headers, f"CSRF header at {call.request.url.path}"
            assert headers["x-tenant-id"] == "acme"


def _assert_control_carries_both(routes: dict[str, respx.Route]) -> None:
    sent = routes["control"].calls[-1].request.headers
    # ``axiam_refresh`` is scoped to /api/v1/auth/refresh, so a management request
    # carries the other two -- and the echoed CSRF header.
    assert all(f"{name}=" in sent["cookie"] for name in ("axiam_access", "axiam_csrf"))
    assert sent["x-csrf-token"] == CSRF


def _client() -> AxiamClient:
    return AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )


def test_device_authorize_poll_and_token_send_no_session_cookie_or_csrf(
    respx_mock: respx.MockRouter,
) -> None:
    routes = _mount(respx_mock)
    client = _client()

    client.login("user@example.com", "pw")
    client.device_authorize(scope="openid", tenant_id=TENANT_ID)
    client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    client.login_client_credentials(tenant_id=TENANT_ID)
    # The control comes last: §14.6 asks for the *next* management request after the
    # three /oauth2/* calls, so the session is shown to have survived them.
    client._rest_send_sync(client._session.sync_client.build_request("POST", "/api/v1/groups"))

    assert routes["login"].call_count == 1
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

    await client.login("user@example.com", "pw")
    await client.device_authorize(scope="openid", tenant_id=TENANT_ID)
    await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    await client.login_client_credentials(tenant_id=TENANT_ID)
    await client._rest_send_async(
        client._session.async_client.build_request("POST", "/api/v1/groups")
    )

    _assert_no_session_state(routes)
    _assert_control_carries_both(routes)
    await client.aclose()


_UMA_OPERATIONS: list[tuple[str, str, str, Callable[[AxiamClient, str], object]]] = [
    (
        "register",
        "POST",
        "/uma2/rreg/resource_set",
        lambda c, pat: c.uma_register_resource(pat, ResourceSet(name="doc")),
    ),
    (
        "read",
        "GET",
        "/uma2/rreg/resource_set/res-1",
        lambda c, pat: c.uma_read_resource(pat, "res-1"),
    ),
    (
        "update",
        "PUT",
        "/uma2/rreg/resource_set/res-1",
        lambda c, pat: c.uma_update_resource(pat, "res-1", ResourceSet(name="doc")),
    ),
    (
        "delete",
        "DELETE",
        "/uma2/rreg/resource_set/res-1",
        lambda c, pat: c.uma_delete_resource(pat, "res-1"),
    ),
    ("list", "GET", "/uma2/rreg/resource_set", lambda c, pat: c.uma_list_resources(pat)),
    (
        "ticket",
        "POST",
        "/uma2/perm",
        lambda c, pat: c.uma_request_ticket(
            pat, [RequestedPermission(resource_id="res-1", resource_scopes=["read"])]
        ),
    ),
]


@pytest.mark.parametrize(
    ("method", "path", "call"),
    [pytest.param(m, p, c, id=i) for i, m, p, c in _UMA_OPERATIONS],
)
def test_a_pat_on_uma2_travels_without_session_state_after_a_cookie_login(
    respx_mock: respx.MockRouter,
    method: str,
    path: str,
    call: Callable[[AxiamClient, str], object],
) -> None:
    # C163-14: the server reads the cookie before the header, so a PAT beside a cookie
    # login would run as the user session and be refused 403 (§20.2 rule 1).
    routes = _mount(respx_mock)
    uma = respx_mock.route(method=method, url=f"{BASE_URL}{path}").mock(
        return_value=httpx.Response(
            200, json={"_id": "res-1", "name": "doc", "ticket": "tk", "resource_scopes": []}
        )
    )
    pat = secrets.token_urlsafe(16)
    client = _client()
    client.login("user@example.com", "pw")

    call(client, pat)
    client._rest_send_sync(client._session.sync_client.build_request("POST", "/api/v1/groups"))

    sent = uma.calls[0].request.headers
    assert sent["authorization"] == f"Bearer {pat}"
    assert not sent.get("cookie"), "the PAT travels alone: no axiam_* cookie"
    assert "x-csrf-token" not in sent
    _assert_control_carries_both(routes)


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
