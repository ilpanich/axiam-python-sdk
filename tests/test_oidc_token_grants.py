"""``oidc_exchange``/``oidc_refresh``/``login_client_credentials`` tests
(CONTRACT.md §12.1): form-encoded body, ``?tenant_id=`` query parameter,
grant-specific field sets, ID-token validation wiring, and
``OAuth2ErrorResponse`` -> ``OAuthProtocolError`` mapping — sync and async.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, OAuthProtocolError
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    FakeJwksEndpoint,
    discovery_document,
    make_ed25519_keypair_and_jwk,
    make_id_token_claims,
    sign_id_token,
)

TENANT_ID = "11111111-1111-1111-1111-111111111111"


def _form_body(request: httpx.Request) -> dict[str, str]:
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    return dict(parse_qsl(request.content.decode()))


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


def _token_response(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "access_token": "access-token-1",
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": "refresh-token-1",
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------
# oidc_exchange — happy path, wire shape, tenant_id query param
# ---------------------------------------------------------------------


def test_oidc_exchange_happy_path_is_form_encoded_with_tenant_id_query(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    token_set = client.oidc_exchange(
        code="auth-code-1",
        code_verifier="verifier-value",
        redirect_uri="https://app.test/cb",
        nonce="nonce-value",
        tenant_id=TENANT_ID,
    )

    assert token_set.access_token.get_secret_value() == "access-token-1"
    assert token_set.token_type == "Bearer"
    assert token_set.expires_in == 900
    assert token_set.refresh_token is not None
    assert token_set.refresh_token.get_secret_value() == "refresh-token-1"
    assert token_set.id_token is None
    assert token_set.id_claims is None

    request = route.calls.last.request
    assert dict(request.url.params) == {"tenant_id": TENANT_ID}
    form = _form_body(request)
    assert form == {
        "grant_type": "authorization_code",
        "code": "auth-code-1",
        "code_verifier": "verifier-value",
        "redirect_uri": "https://app.test/cb",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }


@pytest.mark.asyncio
async def test_async_oidc_exchange_happy_path(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    token_set = await client.oidc_exchange(
        code="auth-code-1",
        code_verifier="verifier-value",
        redirect_uri="https://app.test/cb",
        nonce="nonce-value",
        tenant_id=TENANT_ID,
    )

    assert token_set.access_token.get_secret_value() == "access-token-1"


def test_oidc_exchange_public_client_omits_client_secret(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    client.oidc_exchange(
        code="c",
        code_verifier="v",
        redirect_uri="https://app.test/cb",
        nonce="n",
        tenant_id=TENANT_ID,
    )

    form = _form_body(route.calls.last.request)
    assert "client_secret" not in form


def test_oidc_exchange_validates_id_token(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    private_key, jwk = make_ed25519_keypair_and_jwk()
    id_token = sign_id_token(private_key, jwk["kid"], make_id_token_claims(nonce="expected-nonce"))
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(200, json=_token_response(id_token=id_token, scope="openid"))
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    FakeJwksEndpoint([jwk]).bind_to_client(client)

    token_set = client.oidc_exchange(
        code="c",
        code_verifier="v",
        redirect_uri="https://app.test/cb",
        nonce="expected-nonce",
        tenant_id=TENANT_ID,
    )

    assert token_set.id_token is not None
    assert token_set.id_claims is not None
    assert token_set.id_claims.sub == "user-1"


def test_oidc_exchange_discards_whole_token_set_on_id_token_failure(
    respx_mock: respx.MockRouter,
) -> None:
    """§12.4 rule 7: on ANY validation failure the access/refresh token from
    the same response must never be returned."""
    _mock_discovery(respx_mock)
    private_key, jwk = make_ed25519_keypair_and_jwk()
    id_token = sign_id_token(private_key, jwk["kid"], make_id_token_claims(nonce="wrong-nonce"))
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            200,
            json=_token_response(
                access_token="should-never-be-returned", id_token=id_token, scope="openid"
            ),
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    FakeJwksEndpoint([jwk]).bind_to_client(client)

    with pytest.raises(AuthError) as excinfo:
        client.oidc_exchange(
            code="c",
            code_verifier="v",
            redirect_uri="https://app.test/cb",
            nonce="expected-nonce",
            tenant_id=TENANT_ID,
        )
    assert excinfo.value.reason == "nonce_mismatch"


def test_oidc_exchange_requires_tenant_id() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(AuthError, match="tenant_id"):
        client._resolve_oauth2_tenant_id(None)


def test_oidc_exchange_rejects_a_tenant_slug_where_a_uuid_is_required() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(AuthError, match="UUID"):
        client._resolve_oauth2_tenant_id("not-a-uuid")


# ---------------------------------------------------------------------
# OAuth2ErrorResponse -> OAuthProtocolError
# ---------------------------------------------------------------------


def test_oidc_exchange_400_oauth2_error_maps_to_oauth_protocol_error(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "code expired"}
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    with pytest.raises(OAuthProtocolError) as excinfo:
        client.oidc_exchange(
            code="c",
            code_verifier="v",
            redirect_uri="https://app.test/cb",
            nonce="n",
            tenant_id=TENANT_ID,
        )

    exc = excinfo.value
    assert str(exc) == "invalid_grant: code expired"
    assert exc.error == "invalid_grant"
    assert exc.error_description == "code expired"
    assert isinstance(exc, AuthError), "OAuthProtocolError MUST remain an AuthError subtype"


def test_oauth_protocol_error_is_caught_by_except_autherror(
    respx_mock: respx.MockRouter,
) -> None:
    """Backward compatibility (port-brief-addendum item 17): existing
    ``except AuthError:`` blocks keep working unchanged."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            400, json={"error": "invalid_client", "error_description": "bad client"}
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    caught = False
    try:
        client.oidc_exchange(
            code="c",
            code_verifier="v",
            redirect_uri="https://app.test/cb",
            nonce="n",
            tenant_id=TENANT_ID,
        )
    except AuthError as exc:
        caught = True
        assert isinstance(exc, OAuthProtocolError)
    assert caught


# ---------------------------------------------------------------------
# oidc_refresh
# ---------------------------------------------------------------------


def test_oidc_refresh_is_a_distinct_grant(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(200, json=_token_response(access_token="refreshed-token"))
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    token_set = client.oidc_refresh(refresh_token="old-refresh-token", tenant_id=TENANT_ID)

    assert token_set.access_token.get_secret_value() == "refreshed-token"
    form = _form_body(route.calls.last.request)
    assert form["grant_type"] == "refresh_token"
    assert form["refresh_token"] == "old-refresh-token"
    assert "code" not in form
    assert "code_verifier" not in form


@pytest.mark.asyncio
async def test_async_oidc_refresh_happy_path(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(200, json=_token_response(access_token="refreshed-token"))
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    token_set = await client.oidc_refresh(refresh_token="old-refresh-token", tenant_id=TENANT_ID)
    assert token_set.access_token.get_secret_value() == "refreshed-token"


def test_oidc_refresh_id_token_skips_nonce_check(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    private_key, jwk = make_ed25519_keypair_and_jwk()
    claims = make_id_token_claims()
    del claims["nonce"]
    id_token = sign_id_token(private_key, jwk["kid"], claims)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(200, json=_token_response(id_token=id_token))
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    FakeJwksEndpoint([jwk]).bind_to_client(client)

    token_set = client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)
    assert token_set.id_claims is not None


def test_oidc_refresh_single_flight_collapses_five_concurrent_sync_callers(
    respx_mock: respx.MockRouter,
) -> None:
    """§9 test requirement: N (>=5) concurrent requests against the same
    guard must trigger exactly 1 wire call."""
    import threading

    _mock_discovery(respx_mock)
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        time.sleep(0.02)
        return httpx.Response(200, json=_token_response(access_token="one-refresh-token"))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    results: list[object] = [None] * 6

    def worker(index: int) -> None:
        results[index] = client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert calls["n"] == 1
    for result in results:
        assert result is not None
        assert result.access_token.get_secret_value() == "one-refresh-token"  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_oidc_refresh_single_flight_collapses_five_concurrent_async_callers(
    respx_mock: respx.MockRouter,
) -> None:
    import asyncio

    _mock_discovery(respx_mock)
    calls = {"n": 0}

    async def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await asyncio.sleep(0.02)
        return httpx.Response(200, json=_token_response(access_token="one-refresh-token"))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    results = await asyncio.gather(
        *[client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID) for _ in range(6)]
    )

    assert calls["n"] == 1
    assert all(r.access_token.get_secret_value() == "one-refresh-token" for r in results)


def test_oidc_refresh_runs_inside_the_shared_refresh_guard_lock(
    respx_mock: respx.MockRouter,
) -> None:
    """Port-brief-addendum item 14/17: an oidc_refresh must not interleave
    with a concurrent cookie-session refresh — both serialize on the SAME
    §9 guard lock."""
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    order: list[str] = []
    real_run_exclusive_sync = client._session.refresh_guard.run_exclusive_sync

    def tracking_run_exclusive_sync(fn: object) -> object:
        order.append("enter")
        try:
            return real_run_exclusive_sync(fn)  # type: ignore[arg-type]
        finally:
            order.append("exit")

    client._session.refresh_guard.run_exclusive_sync = tracking_run_exclusive_sync  # type: ignore[method-assign]

    client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)

    assert order == ["enter", "exit"]


# ---------------------------------------------------------------------
# login_client_credentials
# ---------------------------------------------------------------------


def test_login_client_credentials_happy_path(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "service-token", "token_type": "Bearer", "expires_in": 3600},
        )
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    token_set = client.login_client_credentials(tenant_id=TENANT_ID, scope="authz:check")

    assert token_set.access_token.get_secret_value() == "service-token"
    assert token_set.id_token is None
    form = _form_body(route.calls.last.request)
    assert form == {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "authz:check",
    }


def test_login_client_credentials_requires_client_secret() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(AuthError, match="confidential-client"):
        client._client_credentials_form(scope=None)


@pytest.mark.asyncio
async def test_async_login_client_credentials_happy_path(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "service-token", "token_type": "Bearer", "expires_in": 3600},
        )
    )
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    token_set = await client.login_client_credentials(tenant_id=TENANT_ID)
    assert token_set.access_token.get_secret_value() == "service-token"
