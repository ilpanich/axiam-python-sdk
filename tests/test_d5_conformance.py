"""D5 conformance — CONTRACT.md §16, §17, §18, §19.

These assert through the **public ``check_access`` surface**, not against the
helpers in isolation. That distinction is normative as of contract 1.8.1: the
TypeScript SDK shipped a ``withRetry`` that was exported, unit-tested and green
while no production path called it, so that SDK performed no read-only retries
at all and every test passed. Counting requests on the wire is the only
assertion that would have caught it.

Both the sync and async clients are covered — they are separate classes here,
so a fix applied to one and not the other is a real failure mode.
"""

from __future__ import annotations

import dataclasses

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient
from axiam_sdk._decision_memo import MAX_TTL_MS, DecisionMemo, memo_key
from axiam_sdk._errors import AuthzError, NetworkError
from axiam_sdk._retry import (
    BASE_DELAY_MS,
    MAX_ATTEMPTS,
    MAX_DELAY_MS,
    backoff_ms,
    delay_ms,
)
from axiam_sdk._telemetry import (
    Refresh,
    RequestEnd,
    RequestStart,
    Retry,
    TelemetryDispatcher,
)

BASE_URL = "https://axiam-d5.test"
RESOURCE = "11111111-2222-3333-4444-555555555555"


class _Script:
    """Replays a status script and counts requests reaching the transport.

    Counting on the wire — rather than trusting a helper's return value — is
    what contract 1.8.1 requires of a §16 conformance test, after the
    TypeScript SDK shipped a retry helper no production path called.
    """

    def __init__(self, statuses: list[int], body: dict | None = None) -> None:
        self.statuses = statuses
        self.body = body if body is not None else {"allowed": True, "reason_code": "allowed"}
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        status = self.statuses[min(self.calls - 1, len(self.statuses) - 1)]
        if status == 200:
            return httpx.Response(200, json=self.body)
        return httpx.Response(status, json={"message": "nope"})


def _mount(router: respx.Router, script: _Script) -> None:
    """Route both authz endpoints at *script*."""
    router.post(f"{BASE_URL}/api/v1/authz/check").mock(side_effect=script)
    router.post(f"{BASE_URL}/api/v1/authz/check/batch").mock(side_effect=script)


def _sync_client(**kwargs: object) -> AxiamClient:
    return AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme", **kwargs)  # type: ignore[arg-type]


def _async_client(**kwargs: object) -> AsyncAxiamClient:
    return AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme", **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §16 — the policy table
# ---------------------------------------------------------------------------


def test_backoff_doubles_from_base_and_stops_at_cap() -> None:
    assert backoff_ms(1) == BASE_DELAY_MS
    assert backoff_ms(2) == 400.0
    assert backoff_ms(20) == MAX_DELAY_MS


def test_jitter_is_full_not_partial() -> None:
    """The range is ``[0, backoff]``, not ``backoff ± something``.

    Partial jitter keeps every client's retries clustered around the same
    instant, which is the thundering herd retries are meant to prevent rather
    than cause. Pinning the fraction to its endpoints is what distinguishes the
    two — a random draw would pass under either policy.
    """
    assert delay_ms(1, None, 0.0) == 0.0
    assert delay_ms(1, None, 1.0) == BASE_DELAY_MS
    assert delay_ms(2, None, 0.5) == 200.0


def test_retry_after_is_a_floor_never_a_ceiling() -> None:
    """A ``Retry-After: 0`` cannot shorten the wait.

    The TypeScript SDK's ``retry_after_ms ?? backoff(n)`` made the hint
    *replace* the backoff, so a zero retried immediately and defeated the
    policy. This is the regression that locks that out.
    """
    assert delay_ms(1, 2000.0, 1.0) == 2000.0  # longer hint wins
    assert delay_ms(1, 0.0, 1.0) == BASE_DELAY_MS  # zero cannot shorten
    assert delay_ms(1, 50.0, 0.0) == 50.0  # still floors a zero-jitter wait


@respx.mock
def test_sync_makes_exactly_three_attempts_on_persistent_503(respx_mock: respx.Router) -> None:
    script = _Script([503])
    _mount(respx_mock, script)
    client = _sync_client()
    # The sleeps are real but the policy caps total wait well under a second;
    # a test that really waited the full backoff is a test nobody runs, so the
    # attempt count — not the elapsed time — is what is asserted.
    with pytest.raises(NetworkError):
        client.check_access("read", RESOURCE)
    assert script.calls == MAX_ATTEMPTS


@respx.mock
def test_sync_retries_transient_then_succeeds(respx_mock: respx.Router) -> None:
    script = _Script([503, 200])
    _mount(respx_mock, script)
    client = _sync_client()
    result = client.check_access("read", RESOURCE)
    assert result.allowed is True
    assert script.calls == 2


@respx.mock
def test_sync_does_not_retry_a_decisive_403(respx_mock: respx.Router) -> None:
    """A 403 is an answer, not a transport failure."""
    script = _Script([403])
    _mount(respx_mock, script)
    client = _sync_client()
    with pytest.raises(AuthzError):
        client.check_access("read", RESOURCE)
    assert script.calls == 1


@respx.mock
def test_sync_single_attempt_when_retry_disabled(respx_mock: respx.Router) -> None:
    script = _Script([503])
    _mount(respx_mock, script)
    client = _sync_client(retry_enabled=False)
    with pytest.raises(NetworkError):
        client.check_access("read", RESOURCE)
    assert script.calls == 1


@respx.mock
@pytest.mark.asyncio
async def test_async_makes_exactly_three_attempts_on_persistent_503(
    respx_mock: respx.Router,
) -> None:
    script = _Script([503])
    _mount(respx_mock, script)
    client = _async_client()
    with pytest.raises(NetworkError):
        await client.check_access("read", RESOURCE)
    assert script.calls == MAX_ATTEMPTS
    await client.aclose()


@respx.mock
@pytest.mark.asyncio
async def test_async_retries_transient_then_succeeds(respx_mock: respx.Router) -> None:
    script = _Script([503, 200])
    _mount(respx_mock, script)
    client = _async_client()
    result = await client.check_access("read", RESOURCE)
    assert result.allowed is True
    assert script.calls == 2
    await client.aclose()


# ---------------------------------------------------------------------------
# §17 — decision memo
# ---------------------------------------------------------------------------


@respx.mock
def test_memo_is_off_by_default(respx_mock: respx.Router) -> None:
    """The most important assertion here.

    §11.2 rule 6's ban on decision caching is still the default; a build that
    quietly enabled this would change authorization staleness for every existing
    caller without them asking for it.
    """
    script = _Script([200])
    _mount(respx_mock, script)
    client = _sync_client()
    client.check_access("read", RESOURCE)
    client.check_access("read", RESOURCE)
    assert script.calls == 2


@respx.mock
def test_memo_serves_a_repeat_inside_the_ttl(respx_mock: respx.Router) -> None:
    script = _Script([200])
    _mount(respx_mock, script)
    client = _sync_client(decision_memo_ttl_ms=5000)
    first = client.check_access("read", RESOURCE)
    second = client.check_access("read", RESOURCE)
    assert script.calls == 1
    # §17.1 rule 5: the reason code survives the memo.
    assert second.reason_code == first.reason_code == "allowed"


@respx.mock
def test_memo_caches_denies_exactly_like_allows(respx_mock: respx.Router) -> None:
    """§17.1 rule 4 — asymmetric caching leaks the outcome through latency."""
    script = _Script([200], body={"allowed": False, "reason_code": "denied_by_rule"})
    _mount(respx_mock, script)
    client = _sync_client(decision_memo_ttl_ms=5000)
    client.check_access("read", RESOURCE)
    second = client.check_access("read", RESOURCE)
    assert script.calls == 1
    assert second.allowed is False
    assert second.reason_code == "denied_by_rule"


@respx.mock
def test_memo_never_caches_a_failure(respx_mock: respx.Router) -> None:
    """§17.1 rule 7 — caching a transport error as a deny turns a blip into a
    TTL-long outage."""
    script = _Script([503])
    _mount(respx_mock, script)
    client = _sync_client(decision_memo_ttl_ms=5000, retry_enabled=False)
    for _ in range(2):
        with pytest.raises(NetworkError):
            client.check_access("read", RESOURCE)
    assert script.calls == 2


def test_memo_distinguishes_every_key_component() -> None:
    keys = {
        memo_key("read", "r1"),
        memo_key("write", "r1"),
        memo_key("read", "r2"),
        memo_key("read", "r1", "col-a"),
        memo_key("read", "r1", None, "u1"),
    }
    assert len(keys) == 5
    # An absent scope must never collide with a present empty one.
    assert memo_key("read", "r1") != memo_key("read", "r1", "")


def test_memo_clamps_ttl_rather_than_rejecting() -> None:
    assert DecisionMemo(3_600_000).effective_ttl_ms == MAX_TTL_MS
    assert DecisionMemo(2000).effective_ttl_ms == 2000
    assert DecisionMemo(0).enabled is False


def test_memo_expires_exactly_at_the_ttl() -> None:
    now = [100.0]
    memo = DecisionMemo(5000, now=lambda: now[0])
    memo.set("k", "decision")
    now[0] = 100.0 + 4.999
    assert memo.get("k") == "decision"
    now[0] = 100.0 + 5.0
    assert memo.get("k") is None


# ---------------------------------------------------------------------------
# §18 — deterministic shutdown
# ---------------------------------------------------------------------------


def test_close_is_idempotent() -> None:
    client = _sync_client()
    client.close()
    client.close()


@respx.mock
def test_close_issues_no_network_request(respx_mock: respx.Router) -> None:
    """§18.1 rule 5.

    The server-side session deliberately outlives the client object — that is
    what lets a process restart and resume — so a ``close()`` that logged out
    would silently end every user's session on each deploy. Asserted against the
    wire, because a logout wired into close() succeeds silently.
    """
    script = _Script([200])
    _mount(respx_mock, script)
    client = _sync_client()
    client.close()
    assert script.calls == 0


@respx.mock
def test_use_after_close_raises_rather_than_reconnecting(respx_mock: respx.Router) -> None:
    script = _Script([200])
    _mount(respx_mock, script)
    client = _sync_client()
    client.check_access("read", RESOURCE)
    before = script.calls

    client.close()
    for call in (
        lambda: client.check_access("read", RESOURCE),
        lambda: client.login("u@example.com", "pw"),
        lambda: client.logout(),
    ):
        with pytest.raises(NetworkError, match="closed"):
            call()
    # No attempt reached the transport after close.
    assert script.calls == before


@respx.mock
@pytest.mark.asyncio
async def test_async_use_after_close_raises(respx_mock: respx.Router) -> None:
    script = _Script([200])
    _mount(respx_mock, script)
    client = _async_client()
    await client.aclose()
    with pytest.raises(NetworkError, match="closed"):
        await client.check_access("read", RESOURCE)


# ---------------------------------------------------------------------------
# §19 — telemetry
# ---------------------------------------------------------------------------


@respx.mock
def test_emits_a_request_pair_per_attempt_with_a_retry_between(respx_mock: respx.Router) -> None:
    events: list[object] = []
    script = _Script([503, 200])
    _mount(respx_mock, script)
    client = _sync_client(telemetry_hook=events.append)

    client.check_access("read", RESOURCE)

    kinds = [type(e).__name__ for e in events]
    # One pair per attempt, not per logical call: §19.2 rule 5 exists so a
    # caller can count real wire calls from the events.
    assert kinds == ["RequestStart", "RequestEnd", "Retry", "RequestStart", "RequestEnd"]

    starts = [e for e in events if isinstance(e, RequestStart)]
    assert [e.attempt for e in starts] == [1, 2]
    # The path TEMPLATE, never a substituted URL — a metric label carrying a
    # UUID is a cardinality bomb.
    assert starts[0].path_template == "/api/v1/authz/check"

    ends = [e for e in events if isinstance(e, RequestEnd)]
    assert [e.outcome for e in ends] == ["failure", "success"]


@respx.mock
def test_a_throwing_hook_cannot_fail_the_operation(respx_mock: respx.Router) -> None:
    """§19.2 rule 2 — telemetry is not permitted to fail an authorization check."""

    def explode(_event: object) -> None:
        raise RuntimeError("hook exploded")

    script = _Script([200])
    _mount(respx_mock, script)
    client = _sync_client(telemetry_hook=explode)
    assert client.check_access("read", RESOURCE).allowed is True


@respx.mock
def test_no_event_payload_carries_a_token(respx_mock: respx.Router) -> None:
    """§19.2 rule 3 — this surface exists to be shipped to a metrics backend."""
    events: list[object] = []
    script = _Script([503])
    _mount(respx_mock, script)
    client = _sync_client(telemetry_hook=events.append)
    with pytest.raises(NetworkError):
        client.check_access("read", RESOURCE)

    rendered = repr(events)
    assert "eyJ" not in rendered  # no JWT-shaped string
    assert "authorization" not in rendered.lower()


def test_events_are_frozen_so_a_sink_cannot_mutate_them() -> None:
    """A shared event object a sink could edit would let one hook corrupt
    another's input."""
    event = Retry(operation="check_access", attempt=1, delay_ms=1.0, reason="x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.operation = "mutated"  # type: ignore[misc]


def test_dispatcher_costs_nothing_without_a_hook() -> None:
    dispatcher = TelemetryDispatcher()
    assert dispatcher.installed is False
    dispatcher.emit(Refresh(role="leader", duration_ms=1.0))  # must not raise
