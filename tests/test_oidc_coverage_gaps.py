"""Extra coverage for §12 branches not already exercised by the other
``test_oidc_*.py`` files: grant optional-field branches, JWKS-verifier
caching, the sso_start defensive tenant-context branch, and — most
importantly — the single-flight coalescer's FAILURE path (a failing
``oidc_refresh`` wire call must propagate the SAME exception to every
waiting caller, sync and async)."""

from __future__ import annotations

import asyncio
import threading

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, NetworkError
from axiam_sdk._errors import error_from_oauth2_response
from axiam_sdk._jwks import JwksVerifier
from tests._oidc_testkit import BASE_URL, CLIENT_ID, CLIENT_SECRET, discovery_document

TENANT_ID = "88888888-8888-8888-8888-888888888888"


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


# ---------------------------------------------------------------------
# Optional form fields
# ---------------------------------------------------------------------


def test_oidc_refresh_with_scope(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "a", "token_type": "Bearer", "expires_in": 900}
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    client.oidc_refresh(refresh_token="rt", scope="openid profile", tenant_id=TENANT_ID)

    from urllib.parse import parse_qsl

    form = dict(parse_qsl(route.calls.last.request.content.decode()))
    assert form["scope"] == "openid profile"


def test_introspect_with_token_type_hint(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/introspect").mock(
        return_value=httpx.Response(200, json={"active": True})
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    client.introspect(token="t", token_type_hint="refresh_token", tenant_id=TENANT_ID)

    from urllib.parse import parse_qsl

    form = dict(parse_qsl(route.calls.last.request.content.decode()))
    assert form["token_type_hint"] == "refresh_token"


def test_revoke_with_token_type_hint(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/revoke").mock(
        return_value=httpx.Response(200, json={})
    )
    client = AxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    client.revoke(token="t", token_type_hint="access_token", tenant_id=TENANT_ID)

    from urllib.parse import parse_qsl

    form = dict(parse_qsl(route.calls.last.request.content.decode()))
    assert form["token_type_hint"] == "access_token"


# ---------------------------------------------------------------------
# error_from_oauth2_response — non-OAuth2ErrorResponse-shaped body fallback
# ---------------------------------------------------------------------


def test_error_from_oauth2_response_falls_back_on_non_json_body() -> None:
    response = httpx.Response(
        400,
        text="not json at all",
        request=httpx.Request("POST", f"{BASE_URL}/oauth2/token"),
    )
    err = error_from_oauth2_response(400, response, "token request failed")
    assert isinstance(err, NetworkError)


def test_error_from_oauth2_response_falls_back_on_non_dict_json_body() -> None:
    response = httpx.Response(
        400,
        json=["not", "a", "dict"],
        request=httpx.Request("POST", f"{BASE_URL}/oauth2/token"),
    )
    err = error_from_oauth2_response(400, response, "token request failed")
    assert isinstance(err, NetworkError)


def test_error_from_oauth2_response_falls_back_on_partial_oauth2_body() -> None:
    """Only ``error`` present, no ``error_description`` — NOT an
    ``OAuth2ErrorResponse`` shape, so the generic §2 mapping applies."""
    response = httpx.Response(
        401,
        json={"error": "invalid_client"},
        request=httpx.Request("POST", f"{BASE_URL}/oauth2/introspect"),
    )
    err = error_from_oauth2_response(401, response, "introspect request failed")
    assert isinstance(err, AuthError)


# ---------------------------------------------------------------------
# JWKS verifier caching
# ---------------------------------------------------------------------


def test_verifier_for_caches_by_jwks_uri() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    jwks_uri = f"{BASE_URL}/oauth2/jwks"

    first = client._verifier_for(jwks_uri)
    second = client._verifier_for(jwks_uri)

    assert first is second
    assert isinstance(first, JwksVerifier)


# ---------------------------------------------------------------------
# sso_start defensive tenant-context branch (this SDK's tenant_slug is
# always required at construction, so the "no tenant context" branch is
# normally unreachable through the public API — exercised directly here).
# ---------------------------------------------------------------------


def test_sso_start_defensive_missing_tenant_context() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme-org")
    client._session.tenant_slug = ""  # simulate an impossible-via-public-API state

    with pytest.raises(AuthError, match="tenant context"):
        client._sso_start_body(federation_config_id="f", redirect_uri="https://app.test/cb")


# ---------------------------------------------------------------------
# Single-flight FAILURE propagation (both the "doer" and concurrent
# "waiter" code paths) — sync and async.
# ---------------------------------------------------------------------


def test_oidc_refresh_single_flight_failure_propagates_to_all_waiters_sync(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        import time

        time.sleep(0.02)
        return httpx.Response(500, json={"error": "boom"})

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    errors: list[BaseException | None] = [None] * 6

    def worker(index: int) -> None:
        try:
            client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)
        except BaseException as exc:  # noqa: BLE001 - captured for the main thread
            errors[index] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert calls["n"] == 1, "still exactly one wire call despite the failure"
    assert all(isinstance(e, NetworkError) for e in errors)


@pytest.mark.asyncio
async def test_oidc_refresh_single_flight_failure_propagates_to_all_waiters_async(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    calls = {"n": 0}

    async def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await asyncio.sleep(0.02)
        return httpx.Response(500, json={"error": "boom"})

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    async def call() -> BaseException | None:
        try:
            await client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)
        except BaseException as exc:  # noqa: BLE001 - captured for the assertions below
            return exc
        return None

    results = await asyncio.gather(*[call() for _ in range(6)])

    assert calls["n"] == 1
    assert all(isinstance(r, NetworkError) for r in results)
