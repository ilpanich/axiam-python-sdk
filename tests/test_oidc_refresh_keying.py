"""CONTRACT.md §9 / §12: the ``oidc_refresh`` single-flight is keyed **per
refresh token** (issue #115).

Callers presenting the *same* refresh token form one burst (§9 rules 2 and
6a-6d apply per key); a caller presenting a *different* refresh token never
joins that burst and never receives another token's outcome — it gets its own
wire call and its own result. The raw token is never a map key.

Every test asserts the wire-call count, not only the returned values. The
``_after_publish`` seams are test-only (nothing in the SDK assigns them).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import threading
import time
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient
from axiam_sdk._errors import AuthError, OAuthProtocolError
from axiam_sdk._oidc import _AsyncSingleFlight, _refresh_flight_key, _SyncSingleFlight
from tests._oidc_testkit import BASE_URL, CLIENT_ID, discovery_document

TENANT_ID = "22222222-2222-2222-2222-222222222222"
OTHER_TENANT = "33333333-3333-3333-3333-333333333333"
TOKEN_A = "refresh-token-A-raw-value"
TOKEN_B = "refresh-token-B-raw-value"


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


def _presented(request: httpx.Request) -> str:
    return parse_qs(request.content.decode())["refresh_token"][0]


def _answer_for(token: str) -> httpx.Response:
    """A grant whose access token names the refresh token it answers."""
    return httpx.Response(
        200,
        json={
            "access_token": f"access-for-{token}",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": f"rotated-{token}",
        },
    )


def _poll(predicate: Any, what: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.001)


async def _apoll(predicate: Any, what: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.001)


def _assert_no_raw_token(keys: Any) -> None:
    for key in keys:
        assert TOKEN_A not in key and TOKEN_B not in key, "a raw refresh token is a map key"


# --------------------------------------------------------------------
# Key derivation
# --------------------------------------------------------------------


def test_flight_key_is_a_sha256_digest_scoped_by_tenant_and_never_the_token() -> None:
    key = _refresh_flight_key(TOKEN_A, TENANT_ID)
    assert len(key) == 64 and all(c in "0123456789abcdef" for c in key)
    assert TOKEN_A not in key
    assert key == _refresh_flight_key(TOKEN_A, TENANT_ID), "deterministic per (token, tenant)"
    assert key != _refresh_flight_key(TOKEN_B, TENANT_ID), "different token, different key"
    assert key != _refresh_flight_key(TOKEN_A, OTHER_TENANT), "tenant is part of the key"
    hexy = "abcdef01-2345-6789-abcd-ef0123456789"
    assert _refresh_flight_key(TOKEN_A, hexy) == _refresh_flight_key(TOKEN_A, hexy.upper()), (
        "tenant is case-folded"
    )
    assert key != hashlib.sha256(TOKEN_A.encode()).hexdigest(), "tenant is mixed in, not bare"


# --------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------


def test_sync_different_token_during_a_live_flight_gets_its_own_wire_call(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    release = threading.Event()
    seen: list[str] = []

    def responder(request: httpx.Request) -> httpx.Response:
        token = _presented(request)
        seen.append(token)
        if token == TOKEN_A:
            release.wait(5)
        return _answer_for(token)

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    coalescer = client._oidc_refresh_single_flight_sync
    out: dict[str, Any] = {}

    def call(name: str, token: str) -> None:
        out[name] = client.oidc_refresh(refresh_token=token, tenant_id=TENANT_ID)

    ta = threading.Thread(target=call, args=("a", TOKEN_A))
    ta.start()
    _poll(lambda: seen == [TOKEN_A], "A's wire call to start")
    _assert_no_raw_token(coalescer._in_flight.keys())
    tb = threading.Thread(target=call, args=("b", TOKEN_B))
    tb.start()
    # B must have claimed its own slot (it is not parked on A's publication).
    _assert_no_raw_token(coalescer._in_flight.keys())
    _poll(lambda: TOKEN_B in seen, "B's WIRE call while A is still held on the wire")
    assert not release.is_set()
    release.set()
    ta.join(5)
    tb.join(5)

    assert sorted(seen) == [TOKEN_A, TOKEN_B], "two wire calls, one per token"
    assert out["a"].access_token.get_secret_value() == f"access-for-{TOKEN_A}"
    assert out["b"].access_token.get_secret_value() == f"access-for-{TOKEN_B}"
    assert coalescer._in_flight == {}, "every vacated slot is removed"


def test_sync_window_different_token_leads_and_same_token_joins(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    seen: list[str] = []

    def responder(request: httpx.Request) -> httpx.Response:
        token = _presented(request)
        seen.append(token)
        return _answer_for(token)

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    coalescer = client._oidc_refresh_single_flight_sync
    window: dict[str, Any] = {}

    def in_window() -> None:
        coalescer._after_publish = None
        _assert_no_raw_token(coalescer._in_flight.keys())
        window["wire_before"] = len(seen)

        def run(name: str, token: str) -> None:
            window[name] = client.oidc_refresh(refresh_token=token, tenant_id=TENANT_ID)

        same = threading.Thread(target=run, args=("same", TOKEN_A))
        same.start()
        same.join(5)
        window["wire_after_same"] = len(seen)
        other = threading.Thread(target=run, args=("other", TOKEN_B))
        other.start()
        other.join(5)

    coalescer._after_publish = in_window
    leader = client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID)

    assert window["wire_before"] == 1
    assert window["wire_after_same"] == 1, "same token in the window joins (rule 6a)"
    assert window["same"].access_token.get_secret_value() == f"access-for-{TOKEN_A}"
    assert seen == [TOKEN_A, TOKEN_B], "different token in the window: its own wire call"
    assert window["other"].access_token.get_secret_value() == f"access-for-{TOKEN_B}"
    assert leader.access_token.get_secret_value() == f"access-for-{TOKEN_A}"


def test_sync_same_token_after_full_vacate_gets_a_fresh_wire_call(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    seen: list[str] = []

    def responder(request: httpx.Request) -> httpx.Response:
        seen.append(_presented(request))
        return _answer_for(f"{_presented(request)}-{len(seen)}")

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID)
    assert client._oidc_refresh_single_flight_sync._in_flight == {}
    client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID)

    assert seen == [TOKEN_A, TOKEN_A]


def test_sync_a_failed_attempt_never_clears_another_keys_slot() -> None:
    """Rule 6c per key: the vacate is identity-checked within its own key."""
    coalescer = _SyncSingleFlight()
    other_key = _refresh_flight_key(TOKEN_B, TENANT_ID)
    key = _refresh_flight_key(TOKEN_A, TENANT_ID)
    sentinel = object()

    def in_window() -> None:
        coalescer._in_flight[other_key] = sentinel  # type: ignore[assignment]

    coalescer._after_publish = in_window
    with pytest.raises(RuntimeError):
        coalescer.run(key, _raise)
    assert coalescer._in_flight == {other_key: sentinel}, "only A's own slot was removed"


def _raise() -> str:
    raise RuntimeError("boom")


def test_sync_error_does_not_carry_the_raw_token(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant"})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(OAuthProtocolError) as excinfo:
        client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID)
    assert TOKEN_A not in str(excinfo.value) and TOKEN_A not in repr(excinfo.value)
    assert client._oidc_refresh_single_flight_sync._in_flight == {}


# --------------------------------------------------------------------
# Async
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_different_token_during_a_live_flight_gets_its_own_wire_call(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    release = asyncio.Event()
    seen: list[str] = []

    async def responder(request: httpx.Request) -> httpx.Response:
        token = _presented(request)
        seen.append(token)
        if token == TOKEN_A:
            await release.wait()
        return _answer_for(token)

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    coalescer = client._oidc_refresh_single_flight_async

    a = asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID))
    await _apoll(lambda: seen == [TOKEN_A], "A's wire call to start")
    _assert_no_raw_token(coalescer._pending.keys())
    b = asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_B, tenant_id=TENANT_ID))
    _assert_no_raw_token(coalescer._pending.keys())
    await _apoll(lambda: TOKEN_B in seen, "B's WIRE call while A is still held on the wire")
    assert not release.is_set()
    release.set()
    a_set = await a
    b_set = await b

    assert sorted(seen) == [TOKEN_A, TOKEN_B], "two wire calls, one per token"
    assert a_set.access_token.get_secret_value() == f"access-for-{TOKEN_A}"
    assert b_set.access_token.get_secret_value() == f"access-for-{TOKEN_B}"
    await asyncio.sleep(0)
    assert coalescer._pending == {}, "every vacated slot is removed"


@pytest.mark.asyncio
async def test_async_window_different_token_leads_and_same_token_joins() -> None:
    coalescer = _AsyncSingleFlight()
    key_a = _refresh_flight_key(TOKEN_A, TENANT_ID)
    key_b = _refresh_flight_key(TOKEN_B, TENANT_ID)
    calls: list[str] = []
    window: dict[str, Any] = {}

    async def fn_a() -> str:
        calls.append("A")
        return "tokens-A"

    async def fn_b() -> str:
        calls.append("B")
        return "tokens-B"

    async def never() -> str:
        raise AssertionError("a same-token caller inside the window must not lead")

    def in_window() -> None:
        coalescer._after_publish = None
        _assert_no_raw_token(coalescer._pending.keys())
        task_a = coalescer._pending[key_a]
        window["published"] = task_a.done()
        window["same"] = coalescer._claim_or_join(key_a, never)
        window["other"] = coalescer._claim_or_join(key_b, fn_b)
        window["task_a"] = task_a

    coalescer._after_publish = in_window
    assert await coalescer.run(key_a, fn_a) == "tokens-A"

    assert window["published"] is True
    assert window["same"] is window["task_a"], "same token in the window joins (rule 6a)"
    assert window["other"] is not window["task_a"], "different token never joins A's task"
    assert await asyncio.shield(window["other"]) == "tokens-B"
    assert calls == ["A", "B"]
    await asyncio.sleep(0)
    assert coalescer._pending == {}


@pytest.mark.asyncio
async def test_async_same_token_after_full_vacate_gets_a_fresh_wire_call(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    seen: list[str] = []

    async def responder(request: httpx.Request) -> httpx.Response:
        seen.append(_presented(request))
        return _answer_for(f"{_presented(request)}-{len(seen)}")

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    await client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID)
    await asyncio.sleep(0)
    assert client._oidc_refresh_single_flight_async._pending == {}
    await client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID)

    assert seen == [TOKEN_A, TOKEN_A]


@pytest.mark.asyncio
async def test_async_a_cancelled_attempt_never_clears_another_keys_slot() -> None:
    coalescer = _AsyncSingleFlight()
    key_a = _refresh_flight_key(TOKEN_A, TENANT_ID)
    key_b = _refresh_flight_key(TOKEN_B, TENANT_ID)
    release = asyncio.Event()

    async def fn(name: str) -> str:
        await release.wait()
        return name

    first = coalescer._claim_or_join(key_a, lambda: fn("a1"))
    other = coalescer._claim_or_join(key_b, lambda: fn("b"))
    first.cancel()
    await asyncio.sleep(0)
    assert first.cancelled()
    second = coalescer._claim_or_join(key_a, lambda: fn("a2"))
    assert second is not first
    vacated = asyncio.Event()
    first.add_done_callback(lambda _: vacated.set())
    await vacated.wait()

    assert coalescer._pending[key_a] is second, "A's newer attempt survives the old cleanup"
    assert coalescer._pending[key_b] is other, "B's live attempt is untouched"
    release.set()
    assert await asyncio.shield(other) == "b"
    assert await asyncio.shield(second) == "a2"


# --------------------------------------------------------------------
# Tenant is part of the key (§12.3 rule 4); scope is not
# --------------------------------------------------------------------


def _tenant_of(request: httpx.Request) -> str:
    return request.url.params["tenant_id"]


def test_sync_same_token_different_tenant_are_separate_flights(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    release = threading.Event()
    seen: list[str] = []

    def responder(request: httpx.Request) -> httpx.Response:
        seen.append(_tenant_of(request))
        release.wait(5)
        return _answer_for(_tenant_of(request))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    out: dict[str, Any] = {}

    def call(name: str, tenant: str) -> None:
        out[name] = client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=tenant)

    t1 = threading.Thread(target=call, args=("one", TENANT_ID))
    t1.start()
    _poll(lambda: len(seen) == 1, "the first wire call")
    t2 = threading.Thread(target=call, args=("two", OTHER_TENANT))
    t2.start()
    _poll(lambda: len(client._oidc_refresh_single_flight_sync._in_flight) == 2, "a second slot")
    release.set()
    t1.join(5)
    t2.join(5)

    assert sorted(seen) == [TENANT_ID, OTHER_TENANT]
    assert out["one"].access_token.get_secret_value() == f"access-for-{TENANT_ID}"
    assert out["two"].access_token.get_secret_value() == f"access-for-{OTHER_TENANT}"


def test_sync_default_tenant_explicit_or_omitted_is_one_flight_and_scope_is_not_keyed(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    release = threading.Event()
    seen: list[str] = []

    def responder(request: httpx.Request) -> httpx.Response:
        seen.append(_presented(request))
        release.wait(5)
        return _answer_for(TOKEN_A)

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    client._resolved_tenant_id = TENANT_ID  # the client's default tenant
    out: dict[str, Any] = {}

    def call(name: str, **kw: Any) -> None:
        out[name] = client.oidc_refresh(refresh_token=TOKEN_A, **kw)

    threads = [
        threading.Thread(target=call, args=("explicit",), kwargs={"tenant_id": TENANT_ID}),
        threading.Thread(target=call, args=("omitted",)),
        threading.Thread(target=call, args=("scoped",), kwargs={"scope": "openid"}),
    ]
    threads[0].start()
    _poll(lambda: len(seen) == 1, "the wire call")
    threads[1].start()
    threads[2].start()
    time.sleep(0.1)
    release.set()
    for t in threads:
        t.join(5)

    assert seen == [TOKEN_A], "one wire call for the one effective (tenant, token, burst)"
    assert all(out[n].access_token.get_secret_value() == f"access-for-{TOKEN_A}" for n in out)
    assert len(out) == 3


@pytest.mark.asyncio
async def test_async_same_token_different_tenant_are_separate_flights(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    release = asyncio.Event()
    seen: list[str] = []

    async def responder(request: httpx.Request) -> httpx.Response:
        seen.append(_tenant_of(request))
        await release.wait()
        return _answer_for(_tenant_of(request))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    one = asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID))
    await _apoll(lambda: len(seen) == 1, "the first wire call")
    two = asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=OTHER_TENANT))
    await _apoll(lambda: len(client._oidc_refresh_single_flight_async._pending) == 2, "slot")
    release.set()
    one_set, two_set = await one, await two

    assert sorted(seen) == [TENANT_ID, OTHER_TENANT]
    assert one_set.access_token.get_secret_value() == f"access-for-{TENANT_ID}"
    assert two_set.access_token.get_secret_value() == f"access-for-{OTHER_TENANT}"


@pytest.mark.asyncio
async def test_async_default_tenant_explicit_or_omitted_is_one_flight_and_scope_is_not_keyed(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    release = asyncio.Event()
    seen: list[str] = []

    async def responder(request: httpx.Request) -> httpx.Response:
        seen.append(_presented(request))
        await release.wait()
        return _answer_for(TOKEN_A)

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    client._resolved_tenant_id = TENANT_ID
    first = asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID))
    await _apoll(lambda: len(seen) == 1, "the wire call")
    others = [
        asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A)),
        asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A, scope="openid")),
    ]
    await asyncio.sleep(0.05)
    release.set()
    results = await asyncio.gather(first, *others)

    assert seen == [TOKEN_A]
    assert all(r.access_token.get_secret_value() == f"access-for-{TOKEN_A}" for r in results)


def test_sync_tenant_spelling_upper_lower_and_omitted_default_is_one_flight(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    release = threading.Event()
    seen: list[str] = []

    def responder(request: httpx.Request) -> httpx.Response:
        seen.append(_presented(request))
        release.wait(5)
        return _answer_for(TOKEN_A)

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    default = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    client._resolved_tenant_id = default
    out: list[Any] = []
    kwargs: list[dict[str, Any]] = [
        {"tenant_id": default.upper()},
        {"tenant_id": default},
        {},
        {"tenant_id": default.upper()},
    ]

    def call(kw: dict[str, Any]) -> None:
        out.append(client.oidc_refresh(refresh_token=TOKEN_A, **kw))

    threads = [threading.Thread(target=call, args=(kw,)) for kw in kwargs]
    threads[0].start()
    _poll(lambda: len(seen) == 1, "the wire call")
    for t in threads[1:]:
        t.start()
    time.sleep(0.1)
    release.set()
    for t in threads:
        t.join(5)

    assert seen == [TOKEN_A], "one wire call for one effective tenant and token"
    assert len(out) == 4


@pytest.mark.asyncio
async def test_async_tenant_spelling_upper_lower_and_omitted_default_is_one_flight(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    release = asyncio.Event()
    seen: list[str] = []

    async def responder(request: httpx.Request) -> httpx.Response:
        seen.append(_presented(request))
        await release.wait()
        return _answer_for(TOKEN_A)

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    default = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    client._resolved_tenant_id = default
    first = asyncio.create_task(
        client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=default.upper())
    )
    await _apoll(lambda: len(seen) == 1, "the wire call")
    rest = [
        asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=default)),
        asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A)),
        asyncio.create_task(client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=default.upper())),
    ]
    await asyncio.sleep(0.05)
    release.set()
    results = await asyncio.gather(first, *rest)

    assert seen == [TOKEN_A]
    assert len(results) == 4


# --------------------------------------------------------------------
# No thread is ever parked on a lock; one tenant resolution
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_many_distinct_tokens_complete_with_a_small_default_executor(
    respx_mock: respx.MockRouter,
) -> None:
    """Twice the executor size of distinct tokens must all complete: no leader
    may park an executor thread on a lock while the holder needs one."""
    workers = 4
    asyncio.get_running_loop().set_default_executor(concurrent.futures.ThreadPoolExecutor(workers))
    _mock_discovery(respx_mock)

    async def responder(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.02)
        return _answer_for(_presented(request))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    await client.oidc_discover()
    tokens = [f"distinct-{i}" for i in range(workers * 5)]

    results = await asyncio.wait_for(
        asyncio.gather(
            *[client.oidc_refresh(refresh_token=t, tenant_id=TENANT_ID) for t in tokens]
        ),
        timeout=10,
    )

    assert [r.access_token.get_secret_value() for r in results] == [
        f"access-for-{t}" for t in tokens
    ]


def test_sync_default_tenant_change_between_calls_is_two_flights_with_canonical_wire_tenant(
    respx_mock: respx.MockRouter,
) -> None:
    """The key and the wire request use the same canonical tenant: one wire
    call per (token, tenant), and the wire ``tenant_id`` is the lower-case
    hyphenated form whatever the caller's spelling."""
    _mock_discovery(respx_mock)
    release = threading.Event()
    seen: list[tuple[str, str]] = []
    x = "aaaaaaaa-0000-0000-0000-000000000001"
    y = "bbbbbbbb-0000-0000-0000-000000000002"

    def responder(request: httpx.Request) -> httpx.Response:
        token = _presented(request)
        seen.append((token, _tenant_of(request)))
        if token == TOKEN_A:
            release.wait(5)
        return _answer_for(token)

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    client._resolved_tenant_id = x
    holder = threading.Thread(
        target=client.oidc_refresh, kwargs={"refresh_token": TOKEN_A, "tenant_id": x.upper()}
    )
    holder.start()
    _poll(lambda: len(seen) == 1, "A's wire call")
    t1 = threading.Thread(target=client.oidc_refresh, kwargs={"refresh_token": TOKEN_B})
    t1.start()
    _poll(lambda: len(seen) == 2, "B's wire call for tenant x")
    client._resolved_tenant_id = y
    t2 = threading.Thread(target=client.oidc_refresh, kwargs={"refresh_token": TOKEN_B})
    t2.start()
    _poll(lambda: len(seen) == 3, "B's wire call for tenant y")
    release.set()
    for t in (holder, t1, t2):
        t.join(5)

    assert sorted(seen) == sorted([(TOKEN_A, x), (TOKEN_B, x), (TOKEN_B, y)])


def test_oidc_refresh_rejects_a_tenant_with_a_trailing_newline_as_auth_error() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(AuthError):
        client.oidc_refresh(refresh_token=TOKEN_A, tenant_id=TENANT_ID + "\n")
