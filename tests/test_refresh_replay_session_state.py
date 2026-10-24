"""The replay after a 401 refresh carries the refreshed session, not the stale one --
CONTRACT.md §9.3 (refresh once, then replay once) and §3 (CSRF double-submit); C164-26.

The replay is rebuilt from the original request. Its ``Cookie`` header was merged from the
jar when the original was built, so copying it sent the expired ``axiam_access`` and the old
``axiam_csrf`` next to the new ``X-CSRF-Token`` and the refresh that had just succeeded
still ended in ``401``.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient
from axiam_sdk.management._request import ManagementCall, send_management, send_management_async
from tests._oidc_testkit import BASE_URL
from tests.test_client_login import _make_access_token

LOGIN = f"{BASE_URL}/api/v1/auth/login"
REFRESH = f"{BASE_URL}/api/v1/auth/refresh"
CHECK = f"{BASE_URL}/api/v1/authz/check"
GROUPS = f"{BASE_URL}/api/v1/groups"
OLD = _make_access_token(jti="old")
NEW = _make_access_token(jti="new")


def _mount(router: respx.MockRouter, target: str) -> respx.Route:
    """Login with access OLD and csrf c1; ``target`` answers 401 to OLD and 200 to NEW;
    the refresh rotates both cookies and the ``X-CSRF-Token``."""
    router.post(LOGIN).mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "u"}, "session_id": "s", "expires_in": 900},
            headers=[
                ("Set-Cookie", f"axiam_access={OLD}; Path=/; HttpOnly"),
                ("Set-Cookie", "axiam_csrf=c1; Path=/"),
                ("X-CSRF-Token", "c1"),
            ],
        )
    )
    router.post(REFRESH).mock(
        return_value=httpx.Response(
            200,
            json={"expires_in": 900},
            headers=[
                ("Set-Cookie", f"axiam_access={NEW}; Path=/; HttpOnly"),
                ("Set-Cookie", "axiam_csrf=c2; Path=/"),
                ("X-CSRF-Token", "c2"),
            ],
        )
    )

    def _answer(request: httpx.Request) -> httpx.Response:
        if f"axiam_access={NEW}" in request.headers.get("cookie", ""):
            return httpx.Response(200, json={"allowed": True, "reason": None, "id": "g"})
        return httpx.Response(401, json={"error": "token expired"})

    return router.post(target).mock(side_effect=_answer)


def _assert_replay_is_fresh(route: respx.Route) -> None:
    assert route.call_count == 2
    first, replay = (call.request.headers for call in route.calls)
    assert f"axiam_access={OLD}" in first["cookie"]
    assert f"axiam_access={NEW}" in replay["cookie"]
    assert OLD not in replay["cookie"], "the expired access cookie is not replayed"
    assert "axiam_csrf=c2" in replay["cookie"]
    assert "axiam_csrf=c1" not in replay["cookie"]


def test_check_access_replay_after_refresh_carries_the_new_cookie_and_csrf(
    respx_mock: respx.MockRouter,
) -> None:
    route = _mount(respx_mock, CHECK)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    client.login("user@example.com", "pw")

    assert client.check_access("users:read", "user-42").allowed is True

    _assert_replay_is_fresh(route)
    assert route.calls[1].request.headers["x-csrf-token"] == "c2"


@pytest.mark.asyncio
async def test_async_check_access_replay_after_refresh_carries_the_new_cookie_and_csrf(
    respx_mock: respx.MockRouter,
) -> None:
    route = _mount(respx_mock, CHECK)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    await client.login("user@example.com", "pw")

    assert (await client.check_access("users:read", "user-42")).allowed is True

    _assert_replay_is_fresh(route)
    assert route.calls[1].request.headers["x-csrf-token"] == "c2"
    await client.aclose()


def _create_group() -> ManagementCall:
    return ManagementCall(
        operation="groups.create",
        method="POST",
        path_template="/api/v1/groups",
        path="/api/v1/groups",
        body={"name": "g"},
    )


def test_management_write_replay_after_refresh_carries_the_new_cookie_and_csrf(
    respx_mock: respx.MockRouter,
) -> None:
    route = _mount(respx_mock, GROUPS)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    client.login("user@example.com", "pw")

    send_management(client, _create_group())

    _assert_replay_is_fresh(route)
    assert route.calls[1].request.headers["x-csrf-token"] == "c2"


@pytest.mark.asyncio
async def test_async_management_write_replay_after_refresh_carries_the_new_session(
    respx_mock: respx.MockRouter,
) -> None:
    route = _mount(respx_mock, GROUPS)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    await client.login("user@example.com", "pw")

    await send_management_async(client, _create_group())

    _assert_replay_is_fresh(route)
    assert route.calls[1].request.headers["x-csrf-token"] == "c2"
    await client.aclose()
