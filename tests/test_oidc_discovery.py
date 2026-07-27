"""``oidc_discover`` tests (CONTRACT.md §12.1, §12.3 rule 6): fetch, cache
TTL floor, per-origin cache key, and single-flight de-duplication — sync and
async."""

from __future__ import annotations

import asyncio
import threading
import time

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient, NetworkError
from axiam_sdk._oidc import MIN_DISCOVERY_TTL_SECONDS, normalize_origin
from tests._oidc_testkit import BASE_URL, discovery_document


def test_oidc_discover_fetches_and_parses(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    configuration = client.oidc_discover()

    assert route.call_count == 1
    assert configuration.issuer == BASE_URL
    assert configuration.token_endpoint == f"{BASE_URL}/oauth2/token"
    assert configuration.jwks_uri == f"{BASE_URL}/oauth2/jwks"


@pytest.mark.asyncio
async def test_async_oidc_discover_fetches_and_parses(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")

    configuration = await client.oidc_discover()

    assert route.call_count == 1
    assert configuration.issuer == BASE_URL


def test_oidc_discover_serves_second_call_from_cache(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    client.oidc_discover()
    client.oidc_discover()
    client.oidc_discover()

    assert route.call_count == 1


def test_oidc_discover_does_not_reject_issuer_base_url_mismatch(
    respx_mock: respx.MockRouter,
) -> None:
    """§12.3 rule 6: the document's issuer may legitimately differ from the
    base URL behind a proxy — never rejected."""
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(
            200, json=discovery_document(issuer="https://public.proxy.example")
        )
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    configuration = client.oidc_discover()

    assert configuration.issuer == "https://public.proxy.example"


def test_oidc_discover_re_fetches_after_ttl_elapses(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    fake_now = [1_000_000.0]
    monkeypatch.setattr(time, "monotonic", lambda: fake_now[0])

    client.oidc_discover()
    assert route.call_count == 1

    # Just inside the TTL: still cached.
    fake_now[0] += MIN_DISCOVERY_TTL_SECONDS - 1
    client.oidc_discover()
    assert route.call_count == 1

    # Past the TTL: one more fetch.
    fake_now[0] += 2
    client.oidc_discover()
    assert route.call_count == 2


def test_oidc_discover_floors_a_configured_ttl_below_five_minutes(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", oidc_discovery_ttl_seconds=1)

    fake_now = [1_000_000.0]
    monkeypatch.setattr(time, "monotonic", lambda: fake_now[0])

    client.oidc_discover()
    # 10s later the 1s TTL would have expired, but the §12.3 rule 6 5-minute
    # floor means the document is still cached.
    fake_now[0] += 10
    client.oidc_discover()

    assert route.call_count == 1


def test_oidc_discover_clears_in_flight_slot_on_failure(respx_mock: respx.MockRouter) -> None:
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(200, json=discovery_document())

    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    with pytest.raises(NetworkError):
        client.oidc_discover()

    configuration = client.oidc_discover()
    assert calls["n"] == 2
    assert configuration.issuer == BASE_URL


def test_oidc_discover_single_flight_sync(respx_mock: respx.MockRouter) -> None:
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        # A cache-instance-wide lock is held across the ENTIRE fetch (see
        # _DiscoveryCache), so every OTHER concurrent caller blocks before
        # ever issuing its own HTTP request — sleeping here just widens the
        # race window that would expose a bug if that were not true.
        time.sleep(0.02)
        return httpx.Response(200, json=discovery_document())

    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    results: list[object] = [None] * 8

    def worker(index: int) -> None:
        results[index] = client.oidc_discover()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert calls["n"] == 1, "8 concurrent sync callers must collapse to exactly 1 HTTP request"
    for result in results:
        assert result is not None


@pytest.mark.asyncio
async def test_oidc_discover_single_flight_async(respx_mock: respx.MockRouter) -> None:
    calls = {"n": 0}

    async def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await asyncio.sleep(0.02)
        return httpx.Response(200, json=discovery_document())

    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")

    results = await asyncio.gather(*[client.oidc_discover() for _ in range(8)])

    assert calls["n"] == 1, "8 concurrent async callers must collapse to exactly 1 HTTP request"
    assert all(r.issuer == BASE_URL for r in results)


# ---------------------------------------------------------------------
# normalize_origin — the discovery cache key (§12.3 rule 6)
# ---------------------------------------------------------------------


def test_normalize_origin_lowercases_and_makes_port_explicit() -> None:
    assert normalize_origin("HTTPS://IAM.Example.COM/base/path") == "https://iam.example.com:443"
    assert normalize_origin("http://iam.example.com") == "http://iam.example.com:80"


def test_normalize_origin_explicit_default_port_matches_implicit() -> None:
    assert normalize_origin("https://iam.example.com:443/x") == normalize_origin(
        "https://iam.example.com"
    )


def test_normalize_origin_keys_distinct_origins_distinctly() -> None:
    keys = {
        normalize_origin("https://iam.example.com"),
        normalize_origin("http://iam.example.com"),
        normalize_origin("https://iam.example.com:8443"),
        normalize_origin("https://evil.example.com"),
    }
    assert len(keys) == 4


def test_discovery_cache_is_per_client_instance_not_process_global(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    client_a = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    client_b = AxiamClient(base_url=BASE_URL, tenant_slug="acme")

    client_a.oidc_discover()
    client_b.oidc_discover()

    assert route.call_count == 2, "distinct client instances must not share a discovery cache"
