"""``sso_start``/``sso_complete`` tests (CONTRACT.md §12.1, federation SSO
against an upstream IdP)."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, NetworkError
from tests._oidc_testkit import BASE_URL

FEDERATION_CONFIG_ID = "33333333-3333-3333-3333-333333333333"
REDIRECT_URI = "https://app.test/post-login"


def _access_token(*, tenant_id: str = "tenant-uuid-1", org_id: str = "org-uuid-1") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "tenant_id": tenant_id,
                    "org_id": org_id,
                    "jti": "session-1",
                    "exp": 9999999999,
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.sig"


def _set_cookie(name: str, value: str, path: str = "/") -> tuple[str, str]:
    return ("Set-Cookie", f"{name}={value}; Path={path}; HttpOnly")


# ---------------------------------------------------------------------
# sso_start
# ---------------------------------------------------------------------


def test_sso_start_happy_path_with_explicit_context(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/start").mock(
        return_value=httpx.Response(
            200,
            json={
                "authorize_url": "https://idp.example.test/authorize?x=1",
                "state": "federation-state-1",
                "expires_in_secs": 600,
            },
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme-org")

    result = client.sso_start(federation_config_id=FEDERATION_CONFIG_ID, redirect_uri=REDIRECT_URI)

    assert result.authorize_url == "https://idp.example.test/authorize?x=1"
    assert result.state == "federation-state-1"
    assert result.expires_in_secs == 600

    body = json.loads(route.calls.last.request.content)
    assert body["federation_config_id"] == FEDERATION_CONFIG_ID
    assert body["redirect_uri"] == REDIRECT_URI
    assert body["tenant_slug"] == "acme"
    assert body["org_slug"] == "acme-org"
    assert "tenant_id" not in body
    assert "org_id" not in body


def test_sso_start_prefers_uuid_form_when_both_available(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/start").mock(
        return_value=httpx.Response(
            200,
            json={
                "authorize_url": "https://idp.example.test/authorize",
                "state": "s",
                "expires_in_secs": 600,
            },
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_id="org-uuid-1")

    client.sso_start(
        federation_config_id=FEDERATION_CONFIG_ID,
        redirect_uri=REDIRECT_URI,
        tenant_id="tenant-uuid-1",
    )

    body = json.loads(route.calls.last.request.content)
    assert body["tenant_id"] == "tenant-uuid-1"
    assert body["org_id"] == "org-uuid-1"
    assert "tenant_slug" not in body
    assert "org_slug" not in body


def test_sso_start_requires_org_context_client_side_with_no_wire_call(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/start")
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")  # no org_slug/org_id

    with pytest.raises(AuthError, match="organization context"):
        client.sso_start(federation_config_id=FEDERATION_CONFIG_ID, redirect_uri=REDIRECT_URI)

    assert route.call_count == 0


def test_sso_start_error_falls_through_to_generic_mapping_not_oauth_protocol_error(
    respx_mock: respx.MockRouter,
) -> None:
    """Port-brief-addendum item 12: the federation error body shape is
    undocumented — never parsed as an ``OAuth2ErrorResponse``."""
    from axiam_sdk import OAuthProtocolError

    respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/start").mock(
        return_value=httpx.Response(
            401, json={"error": "invalid_config", "message": "no such config"}
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme-org")

    with pytest.raises(AuthError) as excinfo:
        client.sso_start(federation_config_id=FEDERATION_CONFIG_ID, redirect_uri=REDIRECT_URI)
    assert not isinstance(excinfo.value, OAuthProtocolError)


@pytest.mark.asyncio
async def test_async_sso_start_happy_path(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/start").mock(
        return_value=httpx.Response(
            200,
            json={
                "authorize_url": "https://idp.example.test/authorize",
                "state": "s",
                "expires_in_secs": 600,
            },
        )
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme-org")

    result = await client.sso_start(
        federation_config_id=FEDERATION_CONFIG_ID, redirect_uri=REDIRECT_URI
    )
    assert result.state == "s"


# ---------------------------------------------------------------------
# sso_complete
# ---------------------------------------------------------------------


def test_sso_complete_establishes_session_via_set_cookie(respx_mock: respx.MockRouter) -> None:
    access = _access_token()
    respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/callback").mock(
        return_value=httpx.Response(
            200,
            json={
                "user_id": "user-uuid-1",
                "session_id": "session-uuid-1",
                "expires_in": 900,
                "redirect_uri": REDIRECT_URI,
            },
            headers=[
                _set_cookie("axiam_access", access),
                _set_cookie("axiam_refresh", "refresh-1", path="/api/v1/auth/refresh"),
            ],
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    result = client.sso_complete(state="federation-state-1", code="idp-code-1")

    assert result.user_id == "user-uuid-1"
    assert result.session_id == "session-uuid-1"
    assert result.redirect_uri == REDIRECT_URI
    # Same post-login cookie-jar sync login()/verify_mfa() perform.
    assert client._session.cookie_value("axiam_access") == access
    assert client.resolved_org_id() == "org-uuid-1"
    assert client._resolved_tenant_id == "tenant-uuid-1"


def test_sso_complete_body_carries_no_token_material(respx_mock: respx.MockRouter) -> None:
    access = _access_token()
    route = respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/callback").mock(
        return_value=httpx.Response(
            200,
            json={
                "user_id": "u",
                "session_id": "s",
                "expires_in": 900,
                "redirect_uri": REDIRECT_URI,
            },
            headers=[_set_cookie("axiam_access", access)],
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    client.sso_complete(state="st", code="c")

    body = json.loads(route.calls.last.request.content)
    assert set(body.keys()) == {"state", "code"}


def test_sso_complete_missing_cookie_raises_autherror(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/callback").mock(
        return_value=httpx.Response(
            200,
            json={
                "user_id": "u",
                "session_id": "s",
                "expires_in": 900,
                "redirect_uri": REDIRECT_URI,
            },
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    with pytest.raises(AuthError, match="axiam_access"):
        client.sso_complete(state="st", code="c")


def test_sso_complete_network_error_on_5xx(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/callback").mock(
        return_value=httpx.Response(500, json={"error": "boom"})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    with pytest.raises(NetworkError):
        client.sso_complete(state="st", code="c")


@pytest.mark.asyncio
async def test_async_sso_complete_happy_path(respx_mock: respx.MockRouter) -> None:
    access = _access_token()
    respx_mock.post(f"{BASE_URL}/api/v1/auth/federation/oidc/callback").mock(
        return_value=httpx.Response(
            200,
            json={
                "user_id": "u",
                "session_id": "s",
                "expires_in": 900,
                "redirect_uri": REDIRECT_URI,
            },
            headers=[_set_cookie("axiam_access", access)],
        )
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")

    result = await client.sso_complete(state="st", code="c")
    assert result.user_id == "u"
