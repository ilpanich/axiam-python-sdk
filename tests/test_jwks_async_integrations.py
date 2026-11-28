"""The async integrations never run the (blocking) JWKS verification on the event loop: an
unknown-``kid`` token on a slow endpoint does not delay a concurrent request whose key is held."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import pytest

from axiam_sdk._jwks import JwksVerifier
from axiam_sdk.django.middleware import AxiamAuthMiddleware
from tests.test_django_middleware import (
    _async_get_response,
    _make_ed25519_keypair_and_jwk,
    _sign_eddsa_token,
)
from tests.test_fastapi_dependency import _make_app

DELAY = 2.0


class _SlowAfterFill:
    """Serves the held set at once the first time, then ``DELAY`` seconds late (blocking)."""

    def __init__(self, jwk: dict[str, Any]) -> None:
        self.jwk = jwk
        self.calls = 0

    def fetch_data(self) -> dict[str, Any]:
        self.calls += 1
        if self.calls > 1:
            time.sleep(DELAY)
        return {"keys": [self.jwk]}


def _tokens() -> tuple[Any, dict[str, Any], str, str]:
    key, jwk = _make_ed25519_keypair_and_jwk("held")
    claims = {"sub": "u", "tenant_id": "acme", "exp": time.time() + 3600}
    return (
        key,
        jwk,
        _sign_eddsa_token(key, "held", claims),
        _sign_eddsa_token(key, "unknown", claims),
    )


@pytest.mark.asyncio
async def test_fastapi_unknown_kid_on_a_slow_endpoint_does_not_delay_a_held_kid_request() -> None:
    _key, jwk, held, unknown = _tokens()
    verifier = JwksVerifier("https://axiam.example.test")
    endpoint = _SlowAfterFill(jwk)
    verifier._client.fetch_data = endpoint.fetch_data  # type: ignore[method-assign]
    verifier.get_signing_key(held)  # fill the cache
    app = _make_app(verifier, configured_tenant="acme")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:

        async def call(token: str) -> tuple[int, float]:
            begun = time.perf_counter()
            response = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
            return response.status_code, time.perf_counter() - begun

        started = time.perf_counter()
        slow = asyncio.create_task(call(unknown))
        await asyncio.sleep(0.3)
        status, _ = await call(held)
        elapsed = time.perf_counter() - started
        assert status == 200
        assert elapsed < DELAY / 2, f"the held-kid request waited {elapsed:.2f}s behind the fetch"
        await slow


@pytest.mark.asyncio
async def test_django_unknown_kid_on_a_slow_endpoint_does_not_delay_a_held_kid_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.test import RequestFactory

    _key, jwk, held, unknown = _tokens()
    endpoint = _SlowAfterFill(jwk)
    real_init = JwksVerifier.__init__

    def patched_init(self: JwksVerifier, base_url: str, **kwargs: Any) -> None:
        real_init(self, base_url, **kwargs)
        self._client.fetch_data = endpoint.fetch_data  # type: ignore[method-assign]

    monkeypatch.setattr(JwksVerifier, "__init__", patched_init)
    middleware = AxiamAuthMiddleware(_async_get_response)
    middleware._verifier.get_signing_key(held)  # fill the cache
    factory = RequestFactory()

    async def call(token: str) -> tuple[int, float]:
        begun = time.perf_counter()
        response = await middleware(factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}"))
        return response.status_code, time.perf_counter() - begun

    started = time.perf_counter()
    slow = asyncio.create_task(call(unknown))
    await asyncio.sleep(0.3)
    status, _ = await call(held)
    elapsed = time.perf_counter() - started
    assert status == 200
    assert elapsed < DELAY / 2, f"the held-kid request waited {elapsed:.2f}s behind the fetch"
    await slow


@pytest.mark.asyncio
async def test_async_client_verify_logout_token_does_not_block_the_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from axiam_sdk import AsyncAxiamClient

    ticks = 0
    done = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not done.is_set():
            ticks += 1
            await asyncio.sleep(0.05)

    client = AsyncAxiamClient(base_url="https://axiam.example.test", tenant_slug="a", org_slug="a")

    def blocking(self: Any, token: str, configuration: Any) -> Any:
        time.sleep(1.0)
        raise RuntimeError("stop")

    monkeypatch.setattr(type(client), "_verify_logout_token_impl", blocking)
    task = asyncio.create_task(ticker())
    with pytest.raises(RuntimeError):
        await client.verify_logout_token("x.y.z", configuration=object())  # type: ignore[arg-type]
    done.set()
    await task
    assert ticks >= 10, "the event loop kept running while the verification ran"


async def _ticks_while(coro: Any) -> int:
    """Run ``coro`` while a ticker counts event-loop turns; return the ticks."""
    ticks = 0
    done = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not done.is_set():
            ticks += 1
            await asyncio.sleep(0.05)

    task = asyncio.create_task(ticker())
    try:
        await coro
    finally:
        done.set()
        await task
    return ticks


def _blocking(*_args: Any, **_kwargs: Any) -> str:
    time.sleep(1.0)
    return "done"


@pytest.mark.asyncio
async def test_async_client_oidc_exchange_validates_off_the_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from axiam_sdk import AsyncAxiamClient

    client = AsyncAxiamClient(base_url="https://axiam.example.test", tenant_slug="a", org_slug="a")
    cls = type(client)

    async def send(self: Any, request: Any) -> Any:
        return httpx.Response(200, json={})

    monkeypatch.setattr(cls, "_rest_send_async", send)
    monkeypatch.setattr(cls, "_exchange_form", lambda self, **kw: {})
    monkeypatch.setattr(cls, "_token_endpoint_url", lambda self, *a, **kw: "https://x.test/t")
    monkeypatch.setattr(cls, "_handle_token_response", _blocking)
    ticks = await _ticks_while(
        client.oidc_exchange(
            code="c",
            code_verifier="v",
            redirect_uri="https://x.test/cb",
            nonce="n",
            configuration=object(),  # type: ignore[arg-type]
        )
    )
    assert ticks >= 10, "the ID-token validation ran on the event loop"


@pytest.mark.asyncio
async def test_async_client_device_poll_validates_off_the_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import axiam_sdk._async_client as module
    from axiam_sdk import AsyncAxiamClient

    client = AsyncAxiamClient(base_url="https://axiam.example.test", tenant_slug="a", org_slug="a")
    cls = type(client)

    async def fake_retry(attempt: Any, **kwargs: Any) -> Any:
        return httpx.Response(200, json={})

    monkeypatch.setattr(module, "retry_async", fake_retry)
    monkeypatch.setattr(cls, "_device_poll_form", lambda self, **kw: {})
    monkeypatch.setattr(cls, "_token_endpoint_url", lambda self, *a, **kw: "https://x.test/t")
    monkeypatch.setattr(cls, "_handle_device_poll_response", _blocking)
    ticks = await _ticks_while(
        client.device_poll(device_code="d", configuration=object())  # type: ignore[arg-type]
    )
    assert ticks >= 10, "the ID-token validation ran on the event loop"
