"""Extra coverage for the dedicated async surface (``AsyncAxiamClient``,
SDK-Q08).

``test_client_login.py`` already proves the async login / verify_mfa / a
single check_access happy path; this file drives the remaining async-only
call paths that mirror the sync client's ``_client.py`` logic through the
async transport: ``refresh`` (no-token guard + full single-flight flow),
``logout`` (success + error), ``can``, ``batch_check`` ordering, and the
authz 401-refresh-retry-once path. Uses ``respx`` exactly as the sibling
sync tests do (no live services).
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from axiam_sdk import AccessCheck, AsyncAxiamClient, AuthError, AuthzError, NetworkError

BASE_URL = "https://example.test"


def _make_access_token(
    *,
    sub: str = "user-1",
    tenant_id: str = "tenant-uuid-1",
    org_id: str = "org-uuid-1",
    jti: str = "session-uuid-1",
    exp: int = 9999999999,
) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"sub": sub, "tenant_id": tenant_id, "org_id": org_id, "jti": jti, "exp": exp}
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.fake-signature"


def _set_cookie_header(name: str, value: str, path: str = "/") -> tuple[str, str]:
    return ("Set-Cookie", f"{name}={value}; Path={path}; HttpOnly")


async def _login_async(respx_mock: respx.MockRouter) -> AsyncAxiamClient:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie_header("axiam_access", access)],
        )
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    await client.login("user@example.com", "password123")
    return client


# ---------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_refresh_without_login_raises_auth_error() -> None:
    """No ``axiam_access`` cookie yet -> ``refresh()`` raises before any
    network call (mirrors the sync guard)."""
    async with AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(AuthError, match="no access token to refresh"):
            await client.refresh()


@pytest.mark.asyncio
async def test_async_refresh_posts_literal_path(respx_mock: respx.MockRouter) -> None:
    client = await _login_async(respx_mock)
    new_access = _make_access_token(jti="session-uuid-2")
    refresh_route = respx_mock.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
        return_value=httpx.Response(
            200,
            json={"expires_in": 900},
            headers=[_set_cookie_header("axiam_access", new_access, path="/api/v1/auth/refresh")],
        )
    )

    await client.refresh()
    await client.aclose()

    assert refresh_route.called
    assert refresh_route.calls.last.request.url.path == "/api/v1/auth/refresh"


@pytest.mark.asyncio
async def test_async_refresh_401_raises_auth_error(respx_mock: respx.MockRouter) -> None:
    client = await _login_async(respx_mock)
    refresh_route = respx_mock.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
        return_value=httpx.Response(401, json={"error": "refresh token expired"})
    )

    with pytest.raises(AuthError):
        await client.refresh()
    await client.aclose()

    assert refresh_route.call_count == 1


# ---------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_logout_success_resets_refresh_guard(respx_mock: respx.MockRouter) -> None:
    client = await _login_async(respx_mock)
    guard_before = client._session.refresh_guard
    logout_route = respx_mock.post(f"{BASE_URL}/api/v1/auth/logout").mock(
        return_value=httpx.Response(200, json={})
    )

    await client.logout()
    await client.aclose()

    assert logout_route.called
    sent = json.loads(logout_route.calls.last.request.content)
    assert sent["session_id"] == "session-uuid-1"
    # A fresh guard instance replaces the old one after logout.
    assert client._session.refresh_guard is not guard_before


@pytest.mark.asyncio
async def test_async_logout_error_status_raises(respx_mock: respx.MockRouter) -> None:
    client = await _login_async(respx_mock)
    respx_mock.post(f"{BASE_URL}/api/v1/auth/logout").mock(
        return_value=httpx.Response(500, json={"error": "boom"})
    )

    with pytest.raises(NetworkError):
        await client.logout()
    await client.aclose()


# ---------------------------------------------------------------------
# can / batch_check
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_can_returns_bool(respx_mock: respx.MockRouter) -> None:
    client = await _login_async(respx_mock)
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": False, "reason": "denied"})
    )

    allowed = await client.can("users:delete", "user-42")
    await client.aclose()

    assert allowed is False


@pytest.mark.asyncio
async def test_async_batch_check_returns_ordered_results(respx_mock: respx.MockRouter) -> None:
    client = await _login_async(respx_mock)
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check/batch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"allowed": True, "reason": None},
                    {"allowed": False, "reason": "denied"},
                ]
            },
        )
    )

    results = await client.batch_check(
        [
            AccessCheck(action="users:read", resource_id="user-1"),
            AccessCheck(action="users:delete", resource_id="user-2"),
        ]
    )
    await client.aclose()

    assert [r.allowed for r in results] == [True, False]


@pytest.mark.asyncio
async def test_async_check_access_with_scope_sends_scope(respx_mock: respx.MockRouter) -> None:
    client = await _login_async(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )

    result = await client.check_access("users:read", "user-42", scope="field:email")
    await client.aclose()

    assert result.allowed is True
    sent = json.loads(route.calls.last.request.content)
    assert sent["scope"] == "field:email"


# ---------------------------------------------------------------------
# 401 single-flight retry (async)
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_authz_401_triggers_one_refresh_and_one_retry(
    respx_mock: respx.MockRouter,
) -> None:
    client = await _login_async(respx_mock)

    new_access = _make_access_token(jti="session-uuid-refreshed")
    refresh_route = respx_mock.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
        return_value=httpx.Response(
            200,
            json={"expires_in": 900},
            headers=[_set_cookie_header("axiam_access", new_access, path="/api/v1/auth/refresh")],
        )
    )

    check_route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check")
    check_route.side_effect = [
        httpx.Response(401, json={"error": "token expired"}),
        httpx.Response(200, json={"allowed": True, "reason": None}),
    ]

    result = await client.check_access("users:read", "user-42")
    await client.aclose()

    assert result.allowed is True
    assert refresh_route.call_count == 1
    assert check_route.call_count == 2


@pytest.mark.asyncio
async def test_async_authz_403_raises_authz_error(respx_mock: respx.MockRouter) -> None:
    client = await _login_async(respx_mock)
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )

    with pytest.raises(AuthzError):
        await client.check_access("users:delete", "user-42")
    await client.aclose()
