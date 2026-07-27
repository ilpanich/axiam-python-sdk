"""``introspect``/``revoke`` tests (RFC 7662/7009, CONTRACT.md §12.1 note 4):
confidential-client requirement, idempotent revoke, and the §12.3 rule 3
requirement that a 401 here NEVER enters the §9 single-flight refresh
guard."""

from __future__ import annotations

from unittest.mock import MagicMock
from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, NetworkError, OAuthProtocolError
from tests._oidc_testkit import BASE_URL, CLIENT_ID, CLIENT_SECRET, discovery_document

TENANT_ID = "22222222-2222-2222-2222-222222222222"


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


def _form_body(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


# ---------------------------------------------------------------------
# introspect
# ---------------------------------------------------------------------


def test_introspect_happy_path(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/introspect").mock(
        return_value=httpx.Response(
            200,
            json={
                "active": True,
                "sub": "user-1",
                "client_id": CLIENT_ID,
                "scope": "openid profile",
                "token_type": "Bearer",
                "exp": 9999999999,
                "iat": 1000,
            },
        )
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    result = client.introspect(token="some-access-token", tenant_id=TENANT_ID)

    assert result.active is True
    assert result.sub == "user-1"
    assert result.client_id == CLIENT_ID

    request = route.calls.last.request
    assert dict(request.url.params) == {"tenant_id": TENANT_ID}
    form = _form_body(request)
    assert form == {
        "token": "some-access-token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }


def test_introspect_inactive_token(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/introspect").mock(
        return_value=httpx.Response(200, json={"active": False})
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    result = client.introspect(token="unknown-token", tenant_id=TENANT_ID)
    assert result.active is False
    assert result.sub is None


def test_introspect_requires_client_secret() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(AuthError, match="confidential-client"):
        client._introspect_form(token="t", token_type_hint=None)


def test_introspect_401_maps_to_oauth_protocol_error_and_skips_refresh_guard(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/introspect").mock(
        return_value=httpx.Response(
            401, json={"error": "invalid_client", "error_description": "bad credentials"}
        )
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret="wrong-secret"
    )
    guard_spy = MagicMock(wraps=client._session.refresh_guard.refresh_if_needed_sync)
    client._session.refresh_guard.refresh_if_needed_sync = guard_spy  # type: ignore[method-assign]

    with pytest.raises(OAuthProtocolError) as excinfo:
        client.introspect(token="t", tenant_id=TENANT_ID)

    assert str(excinfo.value) == "invalid_client: bad credentials"
    guard_spy.assert_not_called()


@pytest.mark.asyncio
async def test_async_introspect_happy_path(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/introspect").mock(
        return_value=httpx.Response(200, json={"active": True, "sub": "user-1"})
    )
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    result = await client.introspect(token="t", tenant_id=TENANT_ID)
    assert result.active is True


# ---------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------


def test_revoke_returns_none_on_200(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(return_value=httpx.Response(200, json={}))
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    result = client.revoke(token="some-token", tenant_id=TENANT_ID)
    assert result is None


def test_revoke_returns_none_on_204(respx_mock: respx.MockRouter) -> None:
    """CONTRACT.md §12.1 note 5 (corrected in contract 1.5, cross-SDK
    conformance review F-08): any 2xx is success, not only the literal
    ``200`` — a ``204 No Content`` is a perfectly legal revocation
    response and MUST NOT raise."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(return_value=httpx.Response(204))
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    result = client.revoke(token="some-token", tenant_id=TENANT_ID)
    assert result is None


def test_revoke_returns_none_on_202(respx_mock: respx.MockRouter) -> None:
    """F-08: a ``202 Accepted`` is likewise a success 2xx."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(return_value=httpx.Response(202))
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    result = client.revoke(token="some-token", tenant_id=TENANT_ID)
    assert result is None


def test_revoke_is_idempotent_on_an_unknown_token(respx_mock: respx.MockRouter) -> None:
    """RFC 7009: the server answers 200 for unknown/expired/already-revoked
    tokens alike (§12.1 note 5)."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(return_value=httpx.Response(200, json={}))
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    client.revoke(token="never-issued-token", tenant_id=TENANT_ID)
    client.revoke(token="never-issued-token", tenant_id=TENANT_ID)  # still succeeds


def test_revoke_requires_client_secret() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(AuthError, match="confidential-client"):
        client._revoke_form(token="t", token_type_hint=None)


def test_revoke_401_maps_to_oauth_protocol_error_and_skips_refresh_guard(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(
        return_value=httpx.Response(
            401, json={"error": "invalid_client", "error_description": "bad credentials"}
        )
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret="wrong-secret"
    )
    guard_spy = MagicMock(wraps=client._session.refresh_guard.refresh_if_needed_sync)
    client._session.refresh_guard.refresh_if_needed_sync = guard_spy  # type: ignore[method-assign]

    with pytest.raises(OAuthProtocolError):
        client.revoke(token="t", tenant_id=TENANT_ID)

    guard_spy.assert_not_called()


def test_revoke_5xx_stays_a_network_error(respx_mock: respx.MockRouter) -> None:
    """Port-brief-addendum item 20: revoke does not become "success" just
    because RFC 7009 makes it idempotent on 200 — a 5xx is still a
    NetworkError."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(
        return_value=httpx.Response(500, json={"error": "internal"})
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    with pytest.raises(NetworkError):
        client.revoke(token="t", tenant_id=TENANT_ID)


@pytest.mark.asyncio
async def test_async_revoke_happy_path(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(return_value=httpx.Response(200, json={}))
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    assert await client.revoke(token="t", tenant_id=TENANT_ID) is None


@pytest.mark.asyncio
async def test_async_revoke_returns_none_on_204(respx_mock: respx.MockRouter) -> None:
    """F-08 on the async client path: a ``204`` must succeed here too —
    both clients share ``_OidcMixin._handle_revoke_response``, but this
    proves the async transport wiring actually reaches it."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(return_value=httpx.Response(204))
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    assert await client.revoke(token="t", tenant_id=TENANT_ID) is None


@pytest.mark.asyncio
async def test_async_revoke_5xx_stays_a_network_error(respx_mock: respx.MockRouter) -> None:
    """F-08 / port-brief-addendum item 20 on the async client path: a 5xx
    must still raise :class:`NetworkError`, never "success"."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(
        return_value=httpx.Response(500, json={"error": "internal"})
    )
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    with pytest.raises(NetworkError):
        await client.revoke(token="t", tenant_id=TENANT_ID)


@pytest.mark.asyncio
async def test_async_revoke_401_maps_to_oauth_protocol_error_and_skips_refresh_guard(
    respx_mock: respx.MockRouter,
) -> None:
    """F-08 DoD: a 401 with an OAuth2ErrorResponse body must still raise
    ``OAuthProtocolError`` and still never enter the §9 refresh guard, on
    the async client path too."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(
        return_value=httpx.Response(
            401, json={"error": "invalid_client", "error_description": "bad credentials"}
        )
    )
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret="wrong-secret"
    )
    guard_spy = MagicMock(wraps=client._session.refresh_guard.refresh_if_needed_async)
    client._session.refresh_guard.refresh_if_needed_async = guard_spy  # type: ignore[method-assign]

    with pytest.raises(OAuthProtocolError) as excinfo:
        await client.revoke(token="t", tenant_id=TENANT_ID)

    assert str(excinfo.value) == "invalid_client: bad credentials"
    guard_spy.assert_not_called()
