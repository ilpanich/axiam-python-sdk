"""CONTRACT.md §9 rule 6 (contract 1.6) invariants for ``oidc_refresh``'s
single-flight coalescer — sync (``_SyncSingleFlight``) and async
(``_AsyncSingleFlight``).

Rule 6 makes explicit what §9 rule 2 ("all N callers receive *that one
call's* outcome") always implied, in four mechanism-neutral properties:

* **6a publish-before-vacate** — the outcome must be observable to waiters
  *before* the in-flight slot is cleared, so no caller can ever see "slot
  empty" while a just-settled outcome has not been handed over (that instant
  is indistinguishable from "no refresh ran yet" and starts a **second** wire
  call against an already-consumed single-use refresh token);
* **6b occupancy is not liveness** — "is a refresh on the wire" must be
  tested specifically, never as "the slot is non-empty";
* **6c only the current owner clears its own slot** — identity-checked, so a
  lagging/cancelled attempt cannot clear a *newer* attempt's entry;
* **6d a caller arriving after full settlement gets a fresh refresh**.

Every test here asserts the **wire-call count**, not just returned values.
The two ``_after_publish`` seams these tests use are test-only: nothing in
the SDK ever assigns them (see ``_oidc.py``).
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient
from axiam_sdk._oidc import _AsyncSingleFlight, _SyncSingleFlight
from tests._oidc_testkit import BASE_URL, CLIENT_ID, discovery_document

TENANT_ID = "22222222-2222-2222-2222-222222222222"


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


def _token_response(access_token: str) -> dict[str, object]:
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": f"rotated-{access_token}",
    }


async def _poll_until(predicate: Any, *, what: str, timeout: float = 5.0) -> None:
    """Await until ``predicate()`` is true (the wire call has really started,
    a task has really joined), instead of guessing with a fixed sleep."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.001)


def _poll_sync(predicate: Any, what: str, timeout: float = 5.0) -> None:
    """Block until ``predicate()`` is true (sync twin of :func:`_poll_until`)."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.001)


# =====================================================================
# Sync coalescer
# =====================================================================


def _waiter_generation_round() -> dict[str, Any]:
    """Run one two-generation interleaving against a fresh sync coalescer.

    Generation 1 succeeds and settles; the instant its slot is vacated a
    newly arrived caller legitimately leads generation 2 (rule 6d), which
    fails ``invalid_grant`` — the realistic outcome of replaying the refresh
    token generation 1 just consumed. Generation 1's *waiter* is deliberately
    left lagging, still to be rescheduled, while that happens.

    Returns the ``calls`` log plus each participant's outcome.
    """
    coalescer = _SyncSingleFlight()
    calls: list[str] = []
    calls_lock = threading.Lock()
    gen1_may_finish = threading.Event()
    waiter_parked = threading.Event()
    # A plain flag the newcomer spin-waits on rather than an Event: it must
    # claim the just-vacated slot without waiting for an OS wakeup, which is
    # what keeps the just-released waiter behind it.
    newcomer_may_start = [False]
    gen2_started = threading.Event()
    gen2_may_finish = threading.Event()
    outcomes: dict[str, Any] = {}

    def gen1() -> str:
        with calls_lock:
            calls.append("gen1")
        gen1_may_finish.wait(5)
        return "gen1-tokens"

    def gen2() -> str:
        with calls_lock:
            calls.append("gen2")
        gen2_started.set()
        gen2_may_finish.wait(5)
        raise RuntimeError("invalid_grant: refresh token already consumed")

    def waiter() -> None:
        waiter_parked.set()
        try:
            outcomes["waiter"] = coalescer.run(gen1)
        except BaseException as exc:  # noqa: BLE001 - reported to the main thread
            outcomes["waiter"] = exc

    def newcomer() -> None:
        deadline = time.monotonic() + 5
        while not newcomer_may_start[0] and time.monotonic() < deadline:
            pass
        try:
            outcomes["newcomer"] = coalescer.run(gen2)
        except BaseException as exc:  # noqa: BLE001 - reported to the main thread
            outcomes["newcomer"] = exc

    def leader() -> None:
        try:
            outcomes["leader"] = coalescer.run(gen1)
        except BaseException as exc:  # noqa: BLE001 - reported to the main thread
            outcomes["leader"] = exc
        # The leader's slot is vacated the instant ``run`` returns, so a caller
        # arriving now correctly leads generation 2 (rule 6d). Release it here,
        # while the just-released waiter is still trying to be scheduled.
        newcomer_may_start[0] = True
        gen2_started.wait(5)
        gen2_may_finish.set()

    newcomer_thread = threading.Thread(target=newcomer)
    leader_thread = threading.Thread(target=leader)
    newcomer_thread.start()
    leader_thread.start()
    _poll_sync(lambda: len(calls) >= 1, "generation 1 to reach the wire")
    waiter_thread = threading.Thread(target=waiter)
    waiter_thread.start()
    waiter_parked.wait(5)
    time.sleep(0.05)  # let the waiter really park inside the coalescer
    gen1_may_finish.set()
    for thread in (newcomer_thread, leader_thread, waiter_thread):
        thread.join(5)
        assert not thread.is_alive()
    outcomes["calls"] = calls
    return outcomes


def test_sync_waiter_receives_the_outcome_of_the_burst_it_joined() -> None:
    """§9 rule 2 + rule 6b, sync: a waiter must receive the outcome of the
    attempt **it joined** — never a later burst's.

    Against a coalescer whose waiters re-test *slot occupancy* to decide
    whether "their" refresh is still running (rule 6b's exact failure mode),
    the lagging waiter misreads generation 2's occupancy as its own refresh
    still being in flight and is handed generation 2's ``invalid_grant``
    instead — a successful burst member told to re-authenticate, with the
    rotated refresh token lost.

    Timing-sensitive by nature (it needs the waiter to lag), so the
    interleaving runs ``_ROUNDS`` times and the invariant must hold in every
    round. Measured against the pre-fix coalescer a single round reproduces
    the violation ~82% of the time (49/60), so 12 rounds miss it with
    probability ~1e-9.
    """
    _ROUNDS = 12

    for _ in range(_ROUNDS):
        outcomes = _waiter_generation_round()

        assert outcomes["calls"] == ["gen1", "gen2"], outcomes["calls"]
        assert outcomes["leader"] == "gen1-tokens"
        assert isinstance(outcomes["newcomer"], RuntimeError)
        assert outcomes["waiter"] == "gen1-tokens", (
            "a waiter must receive the outcome of the burst it joined, not a "
            f"later burst's (got {outcomes['waiter']!r})"
        )


def test_sync_caller_landing_in_the_publish_vacate_window_joins(
    respx_mock: respx.MockRouter,
) -> None:
    """§9 rule 6a, sync, end-to-end: a caller whose request lands strictly
    after the outcome is published but before the slot is vacated MUST join
    that outcome — the wire-call count stays at 1.

    ``_after_publish`` pins that window open deterministically; it is a
    test-only seam (never set in production).
    """
    _mock_discovery(respx_mock)
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_token_response("burst-1-token"))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    coalescer = client._oidc_refresh_single_flight_sync
    window: dict[str, Any] = {}

    def in_window() -> None:
        # Runs on the leader's thread, after publication and before the slot
        # is cleared — with no lock held, so a real second caller can (and
        # here does) complete an entire oidc_refresh inside this window.
        coalescer._after_publish = None  # the newcomer must not re-enter here
        window["slot_occupied"] = coalescer._in_flight is not None
        window["published"] = coalescer._in_flight is not None and coalescer._in_flight.is_settled()

        def newcomer() -> None:
            window["newcomer"] = client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)

        thread = threading.Thread(target=newcomer)
        thread.start()
        thread.join(5)
        assert not thread.is_alive()

    coalescer._after_publish = in_window
    leader = client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)

    assert window["slot_occupied"] is True
    assert window["published"] is True, "the outcome must be published before the slot is vacated"
    assert calls["n"] == 1, "a caller in the publish->vacate window must not make a second call"
    assert leader.access_token.get_secret_value() == "burst-1-token"
    assert window["newcomer"].access_token.get_secret_value() == "burst-1-token"


def test_sync_lagging_attempt_does_not_clear_a_newer_attempts_slot() -> None:
    """§9 rule 6c, sync: the slot is cleared only by the attempt that
    created it (identity-checked), so an attempt unwinding after a newer one
    has taken the slot cannot vacate the newer one's entry."""
    coalescer = _SyncSingleFlight()
    newer = object()

    def in_window() -> None:
        # Simulate a newer attempt having claimed the slot while this
        # attempt was unwinding.
        coalescer._in_flight = newer  # type: ignore[assignment]

    coalescer._after_publish = in_window
    assert coalescer.run(lambda: "old-attempt") == "old-attempt"
    assert coalescer._in_flight is newer, "a lagging attempt must not clear a newer attempt's slot"


def test_sync_caller_after_full_settlement_gets_a_fresh_refresh(
    respx_mock: respx.MockRouter,
) -> None:
    """§9 rule 6d, sync: once the slot is vacated the next caller performs
    its own new wire call and receives *that* call's outcome — a settled
    publication is never retained as a one-entry cache."""
    _mock_discovery(respx_mock)
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_token_response(f"token-{calls['n']}"))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    first = client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)
    second = client.oidc_refresh(refresh_token="rotated-token-1", tenant_id=TENANT_ID)

    assert calls["n"] == 2
    assert first.access_token.get_secret_value() == "token-1"
    assert second.access_token.get_secret_value() == "token-2"
    assert client._oidc_refresh_single_flight_sync._in_flight is None


def test_sync_failure_is_shared_and_the_slot_is_vacated() -> None:
    """§9.3 + rule 6a on the failure path: the failure reaches every waiter
    unchanged (no retry), and the slot is vacated afterwards."""
    coalescer = _SyncSingleFlight()
    calls: list[int] = []
    release = threading.Event()
    boom = RuntimeError("refresh endpoint unavailable")
    outcomes: list[BaseException | None] = [None] * 5

    def fn() -> str:
        calls.append(1)
        release.wait(5)
        raise boom

    def worker(index: int) -> None:
        try:
            coalescer.run(fn)
        except BaseException as exc:  # noqa: BLE001 - reported to the main thread
            outcomes[index] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    threads[0].start()
    _poll_sync(lambda: len(calls) == 1, "the single attempt to start")
    for thread in threads[1:]:
        thread.start()
    time.sleep(0.05)
    release.set()
    for thread in threads:
        thread.join(5)

    assert calls == [1], "no retry, exactly one attempt (§9.3)"
    assert all(exc is boom for exc in outcomes), "the same exception object reaches every caller"
    assert coalescer._in_flight is None


# =====================================================================
# Async coalescer
# =====================================================================


@pytest.mark.asyncio
async def test_async_cancelled_joiner_does_not_break_the_burst(
    respx_mock: respx.MockRouter,
) -> None:
    """§9 rules 2 + 6a/6c, async: one joiner being cancelled (a
    ``wait_for`` timeout, a cancelled request task) must not destroy the
    burst's shared publication.

    Against a coalescer whose joiners ``await`` the shared future *directly*,
    cancelling a joiner cancels that future — the leader's own publication
    step then raises ``InvalidStateError`` (losing an already-rotated token
    set) and every other participant gets a spurious ``CancelledError``,
    i.e. the outcome is never published even though the slot was vacated:
    rule 6a's forbidden state.
    """
    _mock_discovery(respx_mock)
    calls = {"n": 0}
    release = asyncio.Event()

    async def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await release.wait()
        return httpx.Response(200, json=_token_response("one-refresh-token"))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    leader = asyncio.create_task(client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID))
    await _poll_until(lambda: calls["n"] == 1, what="the leader's wire call to start")

    doomed = asyncio.create_task(client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID))
    await asyncio.sleep(0)  # let it join the in-flight burst
    doomed.cancel()
    with pytest.raises(asyncio.CancelledError):
        await doomed

    late = asyncio.create_task(client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID))
    await asyncio.sleep(0)  # let it join the (still in-flight) burst too
    release.set()

    leader_tokens = await leader
    late_tokens = await late

    assert calls["n"] == 1, "still exactly one wire call for the burst"
    assert leader_tokens.access_token.get_secret_value() == "one-refresh-token"
    assert late_tokens.access_token.get_secret_value() == "one-refresh-token"


@pytest.mark.asyncio
async def test_async_cancelled_leader_does_not_cancel_the_joiners(
    respx_mock: respx.MockRouter,
) -> None:
    """§9 rules 2 + 6c, async: the caller that *started* the burst being
    cancelled must not tear the shared wire call down under the joiners —
    they still receive that one call's outcome, and no second call is made.
    """
    _mock_discovery(respx_mock)
    calls = {"n": 0}
    release = asyncio.Event()

    async def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await release.wait()
        return httpx.Response(200, json=_token_response("one-refresh-token"))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    leader = asyncio.create_task(client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID))
    await _poll_until(lambda: calls["n"] == 1, what="the leader's wire call to start")
    joiners = [
        asyncio.create_task(client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID))
        for _ in range(3)
    ]
    await asyncio.sleep(0)  # let them join

    leader.cancel()
    with pytest.raises(asyncio.CancelledError):
        await leader
    release.set()

    results = await asyncio.gather(*joiners)

    assert calls["n"] == 1, "the shared wire call must not be re-issued"
    assert all(r.access_token.get_secret_value() == "one-refresh-token" for r in results)


@pytest.mark.asyncio
async def test_async_caller_landing_in_the_publish_vacate_window_joins() -> None:
    """§9 rule 6a, async: a caller landing strictly after the outcome is
    published (the shared task is done) but before the slot is vacated (its
    done callback has not run yet) MUST join that outcome — no second call.

    The window is pinned open by ``_after_publish``, invoked inside the
    slot-clearing done callback; the arriving caller is represented by the
    real election step ``_claim_or_join``, which is exactly what
    ``run`` performs (an ``asyncio.Task`` created here instead would not run
    its first step until after the callback had returned, so it could not
    land *inside* the window at all).
    """
    coalescer = _AsyncSingleFlight()
    calls: list[str] = []
    window: dict[str, Any] = {}

    async def fn() -> str:
        calls.append("wire")
        return "burst-1-token"

    async def never() -> str:
        raise AssertionError("a caller inside the window must not start a wire call")

    def in_window() -> None:
        coalescer._after_publish = None
        task = coalescer._pending
        window["published"] = task is not None and task.done()
        # A caller electing itself right now must be handed the settled task.
        window["joined_task"] = coalescer._claim_or_join(never)
        window["slot_task"] = task

    coalescer._after_publish = in_window
    assert await coalescer.run(fn) == "burst-1-token"

    assert window["published"] is True, "the task must be settled before the slot is cleared"
    assert window["joined_task"] is window["slot_task"], "the arriving caller must join, not lead"
    assert calls == ["wire"], "no second wire call for a caller inside the window"
    assert await asyncio.shield(window["joined_task"]) == "burst-1-token"


@pytest.mark.asyncio
async def test_async_lagging_attempt_does_not_clear_a_newer_attempts_slot() -> None:
    """§9 rule 6c, async: an attempt whose slot-clearing runs *after* a newer
    attempt has claimed the slot must not clear the newer one's entry.

    Built from the reachable shape: a cancelled shared task publishes
    nothing, so the next caller correctly leads a fresh attempt (rule 6b) —
    while the cancelled task's slot-clearing callback is still queued behind
    it.
    """
    coalescer = _AsyncSingleFlight()
    calls: list[str] = []
    release = asyncio.Event()

    def make(name: str) -> Any:
        async def fn() -> str:
            calls.append(name)
            await release.wait()
            return name

        return fn

    first = coalescer._claim_or_join(make("first"))
    await _poll_until(lambda: calls == ["first"], what="the first attempt to start")

    first.cancel()
    await asyncio.sleep(0)
    assert first.cancelled()
    assert coalescer._pending is first, "the cancelled task's slot is not vacated yet"

    # A caller arriving now must lead (a cancelled task publishes nothing).
    second = coalescer._claim_or_join(make("second"))
    assert coalescer._pending is second
    vacated = asyncio.Event()
    first.add_done_callback(lambda _: vacated.set())  # queued after _vacate
    await vacated.wait()

    assert coalescer._pending is second, (
        "the cancelled attempt's cleanup must not clear the newer attempt's slot"
    )
    # ...and because the slot survived, a later caller still joins instead of
    # starting a third wire call.
    assert coalescer._claim_or_join(make("third")) is second
    release.set()
    assert await asyncio.shield(second) == "second"
    assert calls == ["first", "second"]


@pytest.mark.asyncio
async def test_async_caller_after_full_settlement_gets_a_fresh_refresh(
    respx_mock: respx.MockRouter,
) -> None:
    """§9 rule 6d, async: once the burst has fully settled and vacated, a
    later caller performs its own new wire call and gets *its* outcome."""
    _mock_discovery(respx_mock)
    calls = {"n": 0}

    async def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_token_response(f"token-{calls['n']}"))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    first = await client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID)
    await asyncio.sleep(0)  # let the slot's done callback run
    assert client._oidc_refresh_single_flight_async._pending is None
    second = await client.oidc_refresh(refresh_token="rotated-token-1", tenant_id=TENANT_ID)

    assert calls["n"] == 2
    assert first.access_token.get_secret_value() == "token-1"
    assert second.access_token.get_secret_value() == "token-2"


@pytest.mark.asyncio
async def test_async_failure_is_shared_with_no_retry_and_the_slot_is_vacated() -> None:
    """§9.3 + rule 6a on the async failure path: one attempt, the same
    exception object for every participant, slot vacated afterwards."""
    coalescer = _AsyncSingleFlight()
    calls: list[int] = []
    release = asyncio.Event()
    boom = RuntimeError("refresh endpoint unavailable")

    async def fn() -> str:
        calls.append(1)
        await release.wait()
        raise boom

    async def call() -> BaseException | None:
        try:
            await coalescer.run(fn)
        except BaseException as exc:  # noqa: BLE001 - returned for the assertions
            return exc
        return None

    tasks = [asyncio.create_task(call()) for _ in range(5)]
    await _poll_until(lambda: calls == [1], what="the single attempt to start")
    release.set()
    outcomes = await asyncio.gather(*tasks)

    assert calls == [1], "no retry, exactly one attempt (§9.3)"
    assert all(exc is boom for exc in outcomes)
    await asyncio.sleep(0)
    assert coalescer._pending is None


@pytest.mark.asyncio
async def test_async_burst_of_six_makes_one_call_and_shares_it(
    respx_mock: respx.MockRouter,
) -> None:
    """§9 rules 1 + 2 (the baseline burst test) re-asserted against the
    task-based coalescer, with the wire call held open so all six callers are
    provably concurrent rather than merely fast."""
    _mock_discovery(respx_mock)
    calls = {"n": 0}
    release = asyncio.Event()

    async def responder(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await release.wait()
        return httpx.Response(200, json=_token_response("one-refresh-token"))

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=responder)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    tasks = [
        asyncio.create_task(client.oidc_refresh(refresh_token="rt", tenant_id=TENANT_ID))
        for _ in range(6)
    ]
    await _poll_until(lambda: calls["n"] == 1, what="the single wire call to start")
    release.set()
    results = await asyncio.gather(*tasks)

    assert calls["n"] == 1
    assert all(r.access_token.get_secret_value() == "one-refresh-token" for r in results)
