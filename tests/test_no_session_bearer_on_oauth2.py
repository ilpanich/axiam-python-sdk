"""No session or adopted bearer on ``/oauth2/*`` -- CONTRACT.md §6.1 rule 11,
§12.1 rule 3, §14.6 (contract 1.62 as of ``d25413506``; review finding C162-05).

An SDK never attaches a session's bearer credential, an adopted one (a §6.1
device login's token, a client-credentials adoption) or any other
``Authorization`` header to a request to ``/oauth2/*`` beyond what **that
request's own** client authentication requires -- and nothing at the token,
device-authorization, introspection, revocation, PAR or CIBA endpoints requires
one: the client's credential travels in the form body. The one thing that is not
excluded is a credential the caller hands to a single call (the RFC 7592
``registration_access_token`` of §28.12).

Before this was fixed, ``_apply_bearer_credential`` attached the adopted token to
every request the client's REST choke point sent, ``/oauth2/*`` included. The
control assertion in each test (an ``/api/v1`` request *does* carry the bearer)
is what makes "no header at ``/oauth2/*``" mean something.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl

import httpx
import pytest
import respx
from pydantic import SecretStr

from axiam_sdk import AsyncAxiamClient, AxiamClient, ClientRegistration
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    DEVICE_AUTHORIZATION_ENDPOINT,
    DEVICE_CODE,
    device_authorization_response,
    discovery_document,
)
from tests.management_support import access_token

TENANT_ID = "11111111-1111-1111-1111-111111111111"
TOKEN_ENDPOINT = f"{BASE_URL}/oauth2/token"
INTROSPECT_ENDPOINT = f"{BASE_URL}/oauth2/introspect"
REVOKE_ENDPOINT = f"{BASE_URL}/oauth2/revoke"
CONTROL_PATH = "/api/v1/auth/session"
TOKEN_BODY = {"access_token": "t", "token_type": "Bearer", "expires_in": 900}


def _adopted() -> str:
    """A bearer value generated per run: a literal would be a credential in the repo."""
    return secrets.token_urlsafe(32)


def _mount(router: respx.MockRouter) -> dict[str, respx.Route]:
    """Discovery, the device and token endpoints, the two token-bound endpoints, a
    login route and one ordinary ``/api/v1`` control route."""
    router.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    router.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
        )
    )
    return {
        "authorize": router.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
            return_value=httpx.Response(200, json=device_authorization_response())
        ),
        "token": router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json=TOKEN_BODY)
        ),
        "introspect": router.post(INTROSPECT_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"active": False})
        ),
        "revoke": router.post(REVOKE_ENDPOINT).mock(return_value=httpx.Response(200)),
        "control": router.get(f"{BASE_URL}{CONTROL_PATH}").mock(
            return_value=httpx.Response(200, json={})
        ),
    }


def _client() -> AxiamClient:
    return AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )


def _async_client() -> AsyncAxiamClient:
    return AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )


def _form(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


def _assert_bare(routes: dict[str, respx.Route], names: tuple[str, ...]) -> None:
    for name in names:
        assert routes[name].call_count >= 1, f"{name} was never reached"
        for call in routes[name].calls:
            assert "authorization" not in call.request.headers, (
                f"§14.6 / §12.1 rule 3: no Authorization header at {call.request.url.path}"
            )


@pytest.mark.parametrize("source", ["adopted", "session"])
def test_device_and_token_requests_carry_no_authorization_header(
    respx_mock: respx.MockRouter, source: str
) -> None:
    """After a login and after an adopted credential: ``device_authorize``,
    ``device_poll``, a client-credentials request, a refresh, ``introspect`` and
    ``revoke`` send no ``Authorization`` header; their form still authenticates the client."""
    routes = _mount(respx_mock)
    client = _client()
    adopted = _adopted()
    if source == "session":
        client.login("admin@example.test", "password123")
    else:
        client._session.adopt_bearer_credential(SecretStr(adopted))

    client.device_authorize(scope="openid", tenant_id=TENANT_ID)
    client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    client.login_client_credentials(tenant_id=TENANT_ID)
    client.oidc_refresh(refresh_token="rt-1", tenant_id=TENANT_ID)
    client.introspect(token="tok", tenant_id=TENANT_ID)
    client.revoke(token="tok", tenant_id=TENANT_ID)

    _assert_bare(routes, ("authorize", "token", "introspect", "revoke"))
    assert routes["token"].call_count == 3
    for call in (routes["authorize"].calls[0], *routes["token"].calls):
        assert _form(call.request)["client_secret"] == CLIENT_SECRET
    # The adopted token never appears in an oauth2 request, in any header or the URL.
    if source == "adopted":
        for name in ("authorize", "token", "introspect", "revoke"):
            for call in routes[name].calls:
                assert adopted not in str(call.request.headers)
                assert adopted not in str(call.request.url)


def test_the_adopted_bearer_still_rides_on_the_ordinary_rest_surface(
    respx_mock: respx.MockRouter,
) -> None:
    """The control: the exclusion is the ``/oauth2/*`` path, not the credential."""
    routes = _mount(respx_mock)
    client = _client()
    adopted = _adopted()
    client._session.adopt_bearer_credential(SecretStr(adopted))

    request = client._session.sync_client.build_request("GET", CONTROL_PATH)
    client._rest_send_sync(request)
    client.device_authorize(scope="openid", tenant_id=TENANT_ID)

    assert routes["control"].calls[0].request.headers["authorization"] == f"Bearer {adopted}"
    assert "authorization" not in routes["authorize"].calls[0].request.headers


@pytest.mark.asyncio
async def test_async_client_sends_no_authorization_header_to_oauth2(
    respx_mock: respx.MockRouter,
) -> None:
    """The async twin: the same choke point, the same exclusion, the same control."""
    routes = _mount(respx_mock)
    client = _async_client()
    adopted = _adopted()
    client._session.adopt_bearer_credential(SecretStr(adopted))

    await client.device_authorize(scope="openid", tenant_id=TENANT_ID)
    await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    await client.login_client_credentials(tenant_id=TENANT_ID)
    await client.oidc_refresh(refresh_token="rt-1", tenant_id=TENANT_ID)
    request = client._session.async_client.build_request("GET", CONTROL_PATH)
    await client._rest_send_async(request)

    _assert_bare(routes, ("authorize", "token"))
    assert routes["control"].calls[0].request.headers["authorization"] == f"Bearer {adopted}"
    await client.aclose()


def test_a_registration_call_still_carries_its_own_explicit_token(
    respx_mock: respx.MockRouter,
) -> None:
    """§28.12: the one credential not excluded from ``/oauth2/*`` is the one the caller
    hands to that single call -- and the adopted bearer is not sent in its place."""
    client = _client()
    adopted = _adopted()
    client._session.adopt_bearer_credential(SecretStr(adopted))
    registration_token = _adopted()
    path = "/oauth2/register/dcr-client-1"
    read = respx_mock.get(f"{BASE_URL}{path}").mock(
        return_value=httpx.Response(
            200,
            json={
                "client_id": "dcr-client-1",
                "registration_client_uri": f"{BASE_URL}{path}",
            },
        )
    )

    registration = client.read_client_registration(f"{BASE_URL}{path}", registration_token)

    assert isinstance(registration, ClientRegistration)
    assert read.calls[0].request.headers["authorization"] == f"Bearer {registration_token}"
    assert adopted not in str(read.calls[0].request.headers)
    client.close()
