"""Device Authorization Grant — CONTRACT.md §14.

The §14.6 required assertions split across two levels, deliberately:

* **Interval arithmetic** — the interval comes from the response, ``slow_down``
  raises it permanently, polling stops at ``expires_in`` — is asserted against
  ``PollSchedule`` directly. It is pure logic, so it is tested exactly and
  instantly, including cases (a 30-minute grant, three cumulative
  ``slow_down``s) no wall-clock test could reach.

* **Wire behaviour** lives in the integration tests: which answers loop, which
  terminate, how many requests actually go out, and the §14.3 rule 2 ordering
  guarantee. Intervals in these fixtures are 1 s.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, OAuthProtocolError
from axiam_sdk._oidc import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    SLOW_DOWN_INCREMENT_SECONDS,
    PollSchedule,
)
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    DEVICE_AUTHORIZATION_ENDPOINT,
    DEVICE_CODE,
    USER_CODE,
    device_authorization_response,
    discovery_document,
    discovery_document_without_optional_endpoints,
)

TENANT_ID = "11111111-1111-1111-1111-111111111111"


def _form_body(request: httpx.Request) -> dict[str, str]:
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    return dict(parse_qsl(request.content.decode()))


def _mock_discovery(respx_mock: respx.MockRouter, *, full: bool = True) -> None:
    doc = discovery_document() if full else discovery_document_without_optional_endpoints()
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=doc)
    )


def _oauth_error(code: str) -> httpx.Response:
    return httpx.Response(400, json={"error": code, "error_description": f"{code} description"})


def _rate_limited(
    retry_after: str | None = "7",
    body: dict[str, object] | None = None,
) -> httpx.Response:
    """The server's own 429 (contract 1.64 amended): ``{"error": "rate_limit_exceeded"}``
    with no ``error_description``, and a ``Retry-After``."""
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return httpx.Response(
        429,
        json=body if body is not None else {"error": "rate_limit_exceeded"},
        headers=headers,
    )


def _server_error() -> httpx.Response:
    """The server's own 500 at /oauth2/token (§14.2 rule 6, contract 1.64 amended)."""
    return httpx.Response(500, json={"error": "server_error", "error_description": "db"})


def _success() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "access_token": "device-access-token",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": "device-refresh-token",
        },
    )


def _client(**kwargs: object) -> AxiamClient:
    return AxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, **kwargs
    )


# ---------------------------------------------------------------------
# §14.2 arithmetic — PollSchedule
# ---------------------------------------------------------------------


def test_absent_or_zero_interval_falls_back_to_the_rfc_default() -> None:
    assert PollSchedule(0, 600).interval_seconds == DEFAULT_POLL_INTERVAL_SECONDS
    assert PollSchedule(7, 600).interval_seconds == 7


def test_slow_down_is_cumulative_and_never_resets() -> None:
    schedule = PollSchedule(5, 1800)
    schedule.slow_down()
    assert schedule.interval_seconds == 5 + SLOW_DOWN_INCREMENT_SECONDS
    schedule.slow_down()
    assert schedule.interval_seconds == 15

    # Polling on must not undo the raise. This is the rule implementations get
    # wrong: backing off for one round and returning to the original interval
    # earns another `slow_down`, forever.
    schedule.tick()
    schedule.tick()
    assert schedule.interval_seconds == 15


def test_tick_reports_the_deadline_and_stops() -> None:
    schedule = PollSchedule(5, 12)
    assert schedule.tick() is True  # t=5
    assert schedule.tick() is True  # t=10
    assert schedule.tick() is False  # t=15 is past the 12 s deadline


def test_a_slowed_interval_can_exhaust_the_grant_early() -> None:
    schedule = PollSchedule(5, 20)
    assert schedule.tick() is True
    schedule.slow_down()
    schedule.slow_down()
    assert schedule.interval_seconds == 15
    assert schedule.tick() is False


def test_an_interval_equal_to_the_whole_grant_never_polls() -> None:
    assert PollSchedule(30, 30).tick() is False


def test_rate_limited_waits_at_least_retry_after_as_one_interval_and_keeps_the_interval() -> None:
    # §14.2 rule 9 (contract 1.64): the wait replaces one interval, never raises it.
    schedule = PollSchedule(5, 600)
    schedule.rate_limited(12.5)
    assert schedule.tick() is True
    assert schedule.wait_seconds == 12.5
    assert schedule.interval_seconds == 5
    assert schedule.tick() is True
    assert schedule.wait_seconds == 5, "the Retry-After applies to one wait only"


def test_a_retry_after_shorter_than_the_interval_never_shortens_the_wait() -> None:
    schedule = PollSchedule(5, 600)
    schedule.rate_limited(1)
    assert schedule.tick() is True
    assert schedule.wait_seconds == 5
    schedule.rate_limited(None)
    assert schedule.tick() is True
    assert schedule.wait_seconds == 5


def test_a_retry_after_past_the_deadline_ends_the_grant() -> None:
    schedule = PollSchedule(5, 30)
    schedule.rate_limited(60)
    assert schedule.tick() is False


# ---------------------------------------------------------------------
# device_authorize
# ---------------------------------------------------------------------


def test_device_authorize_is_unauthenticated_and_form_encoded(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )

    # Built WITHOUT a client secret: §14.1 says a device that cannot show a
    # browser cannot hold one, and the SDK must not refuse such a client.
    authorization = _client().device_authorize(scope="openid profile", tenant_id=TENANT_ID)

    form = _form_body(route.calls[0].request)
    assert "client_secret" not in form, (
        "§14.1 rule 1 (contract 1.62): a public client sends no credential at device_authorize"
    )
    assert form["scope"] == "openid profile"
    assert "tenant_id" not in form, "§12.1 note 2: tenant_id is never a body field"
    assert route.calls[0].request.url.params["tenant_id"] == TENANT_ID

    assert authorization.user_code == USER_CODE
    assert authorization.interval == 1
    assert authorization.verification_uri_complete == f"{BASE_URL}/device?user_code={USER_CODE}"


def test_absent_interval_defaults_to_five_seconds_not_faster(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response(interval=None))
    )

    authorization = _client().device_authorize(tenant_id=TENANT_ID)

    assert authorization.interval == DEFAULT_POLL_INTERVAL_SECONDS, (
        "§14.2 rule 2: an absent interval defaults to 5 s; an SDK MUST NOT hard-code a faster floor"
    )


def test_device_authorize_errors_when_the_server_advertises_no_endpoint(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock, full=False)

    with pytest.raises(AuthError, match="device_authorization_endpoint"):
        _client().device_authorize(tenant_id=TENANT_ID)


def test_device_code_is_redacted_and_user_code_is_not(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )

    authorization = _client().device_authorize(tenant_id=TENANT_ID)

    assert DEVICE_CODE not in repr(authorization), (
        "§14.5: device_code is a bearer credential and must never render"
    )
    assert DEVICE_CODE not in str(authorization)
    assert authorization.device_code.get_secret_value() == DEVICE_CODE
    # §14.5: user_code is NOT wrapped — it exists to be read aloud, and
    # wrapping it would defeat the one thing it is for.
    assert authorization.user_code == USER_CODE
    assert USER_CODE in repr(authorization)


# ---------------------------------------------------------------------
# §14.2 wire behaviour
# ---------------------------------------------------------------------


def test_authorization_pending_loops_rather_than_raising(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[
            _oauth_error("authorization_pending"),
            _oauth_error("authorization_pending"),
            _success(),
        ]
    )

    tokens = _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert tokens.access_token.get_secret_value() == "device-access-token"


def test_slow_down_is_not_terminal(respx_mock: respx.MockRouter) -> None:
    # The back-off arithmetic is asserted against PollSchedule; what matters
    # here is that `slow_down` is not mistaken for a terminal answer. An SDK
    # that let it fall through would abort a grant the user is still approving.
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_oauth_error("slow_down"), _success()]
    )

    tokens = _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 2
    assert tokens.access_token.get_secret_value() == "device-access-token"


@pytest.mark.parametrize(
    ("code", "other"),
    [("access_denied", "expired_token"), ("expired_token", "access_denied")],
)
def test_access_denied_and_expired_token_are_distinct(
    respx_mock: respx.MockRouter, code: str, other: str
) -> None:
    # §14.2 rule 3: "a human said no" and "nobody answered" are the only two
    # pieces of information the device can act on.
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_oauth_error(code))

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == code
    assert excinfo.value.error != other


def test_invalid_grant_is_terminal(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error("invalid_grant")
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == "invalid_grant"
    assert route.call_count == 1, "a terminal answer stops the loop immediately"


def test_polling_stops_at_expires_in(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    # 2-second grant, 1-second interval: one poll at t=1, then the t=2 tick is
    # the deadline and must not be sent.
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(
            200, json=device_authorization_response(expires_in=2, interval=1)
        )
    )
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error("authorization_pending")
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token", (
        "§14.2 rule 4: reported under the same code the server would have used, "
        "so a caller's branch does not care which side noticed first"
    )
    assert route.call_count == 1, (
        "§14.2 rule 4: the deadline is authoritative — no poll is sent past it "
        "even though the server was still answering authorization_pending"
    )


def test_server_error_mid_poll_is_retried_not_terminal(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[
            _oauth_error("authorization_pending"),
            _server_error(),
            httpx.Response(503, json={"error": "temporarily_unavailable"}),
            httpx.Response(502, text="bad gateway"),
            _success(),
        ]
    )

    tokens = _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 5, "§14.2 rule 6: a server restart must not lose an approved grant"
    assert tokens.access_token.get_secret_value() == "device-access-token"


def test_a_429_on_a_poll_is_waited_out_not_terminal_and_the_interval_is_unchanged(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    # §14.6 (contract 1.64): one poll answered 429 rate_limit_exceeded with a Retry-After,
    # then the tokens. The loop waits at least the Retry-After (a recorded sleep, not a
    # wall-clock one), polls again and completes; the poll after the 429 is scheduled at
    # the interval held before it, not five seconds longer.
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response(interval=2))
    )
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_rate_limited("7"), _oauth_error("authorization_pending"), _success()]
    )

    tokens = _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert tokens.access_token.get_secret_value() == "device-access-token"
    assert sleeps == [2, 7, 2], "first interval, the Retry-After as one interval, then the interval"


def test_a_429_without_a_retry_after_waits_one_interval_and_polls_again(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response(interval=2))
    )
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=[_rate_limited(None), _success()])

    _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert sleeps == [2, 2]


def test_a_retry_after_past_the_deadline_is_capped_and_nothing_is_sent_after_it(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(
            200, json=device_authorization_response(expires_in=10, interval=1)
        )
    )
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_rate_limited("3600"), _success()]
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token"
    assert route.call_count == 1, "§14.2 rule 4: no poll after the deadline"
    assert all(wait <= 10 for wait in sleeps), "the wait is never longer than the grant"


def test_a_single_device_poll_still_raises_the_429_for_a_hand_rolled_loop(
    respx_mock: respx.MockRouter,
) -> None:
    # Only the loop waits; `device_poll` raises (§14.2 rule 9, last sentence).
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_rate_limited("7"))

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert excinfo.value.error == "rate_limit_exceeded"
    assert excinfo.value.retry_after_ms == 7000


# ---------------------------------------------------------------------
# §14.3 device_login
# ---------------------------------------------------------------------


def test_device_login_surfaces_the_user_code_before_the_first_poll(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )

    order: list[str] = []

    def _token_side_effect(_request: httpx.Request) -> httpx.Response:
        order.append("poll")
        return _success()

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=_token_side_effect)

    seen: list[str] = []

    def _on_user_code(authorization: object) -> None:
        order.append("user_code")
        seen.append(authorization.user_code)  # type: ignore[attr-defined]

    _client().device_login(_on_user_code, tenant_id=TENANT_ID)

    # Ordering, not just presence (§14.6).
    assert order == ["user_code", "poll"], (
        "§14.3 rule 2: the caller must have had the chance to display the code "
        "BEFORE polling begins"
    )
    assert seen == [USER_CODE]


def test_successful_device_login_returns_a_token_set_carrying_the_access_token(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_success())

    tokens = _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    # §14.6 as amended by the contract 1.7 errata: the assertion is on the
    # returned token set. This SDK does not adopt (§14.3 rule 4 defers to the
    # §12.1 login_client_credentials MAY, and Python's settled posture there is
    # to leave the tokens with the caller).
    assert tokens.access_token.get_secret_value() == "device-access-token"
    assert tokens.token_type == "Bearer"
    assert tokens.refresh_token is not None


# ---------------------------------------------------------------------
# device_poll standalone
# ---------------------------------------------------------------------


def test_device_poll_surfaces_pending_for_hand_rolled_loops(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error("authorization_pending")
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert excinfo.value.error == "authorization_pending", (
        "a hand-rolled loop sees exactly what device_login sees"
    )


def test_device_poll_sends_the_device_code_grant_type(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_success())

    _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    form = _form_body(route.calls[0].request)
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
    assert form["device_code"] == DEVICE_CODE


# ---------------------------------------------------------------------
# async twin (§14.4: the same three names on AsyncAxiamClient)
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_device_login_awaits_an_async_callback_before_polling(
    respx_mock: respx.MockRouter,
) -> None:
    # A device rendering a QR code may need to await a paint. Polling before
    # that resolves would defeat §14.3 rule 2 as surely as not calling back.
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )

    order: list[str] = []

    def _token_side_effect(_request: httpx.Request) -> httpx.Response:
        order.append("poll")
        return _success()

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=_token_side_effect)

    async def _on_user_code(_authorization: object) -> None:
        import asyncio

        await asyncio.sleep(0.02)
        order.append("user_code")

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    tokens = await client.device_login(_on_user_code, tenant_id=TENANT_ID)

    assert order == ["user_code", "poll"]
    assert tokens.access_token.get_secret_value() == "device-access-token"


@pytest.mark.asyncio
async def test_async_access_denied_is_terminal(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_oauth_error("access_denied"))

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(OAuthProtocolError) as excinfo:
        await client.device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == "access_denied"


@pytest.mark.asyncio
async def test_async_429_on_a_poll_is_waited_out_and_the_interval_is_unchanged(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []

    async def _record(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _record)
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response(interval=2))
    )
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_rate_limited("7"), _oauth_error("authorization_pending"), _success()]
    )

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    tokens = await client.device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert tokens.access_token.get_secret_value() == "device-access-token"
    assert sleeps == [2, 7, 2]


# ---------------------------------------------------------------------
# Contract 1.64 (amended): the status decides, not the body (C164-01, -03, -04, -05, -15)
# ---------------------------------------------------------------------


def _authorize_with(respx_mock: respx.MockRouter, **overrides: object) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response(**overrides))
    )


@pytest.mark.parametrize(
    "body",
    [
        {"error": "rate_limit_exceeded"},
        {"error": "rate_limit_exceeded", "retry_after": 7},
    ],
    ids=["no-description", "with-retry_after-member"],
)
def test_the_servers_own_429_body_is_waited_out_and_the_interval_is_unchanged(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, body: dict[str, object]
) -> None:
    # C164-01: AXIAM's 429 carries no error_description; (b) must still engage.
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    _authorize_with(respx_mock, interval=2)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[
            _rate_limited("7", body),
            _oauth_error("authorization_pending"),
            _success(),
        ]
    )

    tokens = _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert tokens.access_token.get_secret_value() == "device-access-token"
    assert sleeps == [2, 7, 2]


def test_a_bodiless_429_honours_retry_after_as_a_floor(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    _authorize_with(respx_mock, interval=2)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), _success()]
    )

    _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert sleeps == [2, 7]


def test_a_429_that_says_slow_down_does_not_raise_the_interval(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    # C164-04: only the 400 raises the interval; a 429 is the rule-9 wait whatever its body.
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    _authorize_with(respx_mock, interval=2)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[
            httpx.Response(
                429,
                json={"error": "slow_down", "error_description": "x"},
                headers={"Retry-After": "1"},
            ),
            _oauth_error("authorization_pending"),
            _success(),
        ]
    )

    _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert sleeps == [2, 2, 2], "the interval stays at 2; a 400 slow_down is the only raise"


def test_a_429_with_any_other_error_is_still_the_wait_not_terminal(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    _authorize_with(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[
            httpx.Response(429, json={"error": "invalid_grant", "error_description": "x"}),
            _success(),
        ]
    )

    _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 2


def test_a_single_device_poll_raises_a_429_whatever_its_body_names(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            429, json={"error": "slow_down", "error_description": "x"}, headers={"Retry-After": "3"}
        )
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert excinfo.value.error == "rate_limit_exceeded"
    assert excinfo.value.retry_after_ms == 3000


def test_a_5xx_on_a_poll_is_a_network_error_whatever_its_body(
    respx_mock: respx.MockRouter,
) -> None:
    # C164-03: the status is read before the body (§14.2 rule 6).
    from axiam_sdk import NetworkError

    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_server_error())

    with pytest.raises(NetworkError):
        _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)


def test_the_deadline_is_a_clock_not_the_sum_of_the_waits() -> None:
    # C164-05: round trips and the user-code callback count against expires_in.
    now = [100.0]
    schedule = PollSchedule(5, 20, clock=lambda: now[0])
    now[0] += 8  # the callback and a slow request, no sleep at all
    assert schedule.tick() is True  # 12 s left, 5 s wait
    now[0] += 5 + 8  # the wait, plus another slow round trip
    assert schedule.tick() is False, "4 s left, a 5 s wait would poll past the deadline"


@pytest.mark.asyncio
async def test_async_a_retry_after_past_the_deadline_is_capped_and_nothing_is_sent_after_it(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []

    async def _record(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _record)
    _authorize_with(respx_mock, expires_in=10, interval=1)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_rate_limited("3600"), _success()]
    )

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(OAuthProtocolError) as excinfo:
        await client.device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token"
    assert route.call_count == 1
    assert all(wait <= 10 for wait in sleeps)


@pytest.mark.asyncio
async def test_async_a_429_without_a_retry_after_waits_one_interval(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []

    async def _record(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _record)
    _authorize_with(respx_mock, interval=2)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=[_rate_limited(None), _success()])

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    await client.device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert sleeps == [2, 2]


@pytest.mark.asyncio
async def test_async_a_500_with_the_servers_body_and_a_slow_down_429_do_not_end_the_grant(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []

    async def _record(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _record)
    _authorize_with(respx_mock, interval=2)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[
            _server_error(),
            httpx.Response(429, json={"error": "slow_down"}, headers={"Retry-After": "1"}),
            _success(),
        ]
    )

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    await client.device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    # The 500 is retried inside the poll (a short §16 backoff); the interval waits are 2 s.
    assert [wait for wait in sleeps if wait >= 1] == [2, 2]


# ---------------------------------------------------------------------
# C164-25 / contract 1.64 (amended again, C164-35): the poll is §16-retried inside the attempt
# ---------------------------------------------------------------------


def _record_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    return sleeps


def test_a_5xx_on_a_poll_is_retried_inside_the_poll_under_section_16(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps = _record_sleeps(monkeypatch)
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_server_error(), _server_error(), _success()]
    )

    tokens = _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert route.call_count == 3, "the attempt cap of §16.1 is 3 in total"
    assert tokens.access_token.get_secret_value() == "device-access-token"
    assert all(wait < 1 for wait in sleeps), "only §16 backoff, no interval"


def test_device_login_completes_within_one_interval_when_the_poll_recovers_under_section_16(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps = _record_sleeps(monkeypatch)
    _authorize_with(respx_mock, interval=2)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_server_error(), _server_error(), _success()]
    )

    _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert [wait for wait in sleeps if wait >= 1] == [2], "one interval, three requests"


def test_a_third_5xx_in_a_row_exhausts_the_cap_and_device_poll_surfaces_it(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from axiam_sdk import NetworkError

    _record_sleeps(monkeypatch)
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_server_error())

    with pytest.raises(NetworkError):
        _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert route.call_count == 3


def test_a_transport_failure_on_a_poll_is_retried_and_then_a_network_error(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from axiam_sdk import NetworkError

    _record_sleeps(monkeypatch)
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[httpx.ConnectError("down"), _success()]
    )

    tokens = _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    assert route.call_count == 2
    assert tokens.access_token.get_secret_value() == "device-access-token"

    route.mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(NetworkError):
        _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)


def test_a_429_on_a_poll_is_not_retried_inside_the_poll(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _record_sleeps(monkeypatch)
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_rate_limited("1"))

    with pytest.raises(OAuthProtocolError):
        _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert route.call_count == 1, "the wait is the loop's (rule 9), not §16's"


def test_with_retry_disabled_a_5xx_makes_one_request_per_poll(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from axiam_sdk import NetworkError

    _record_sleeps(monkeypatch)
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_server_error())
    client = _client()
    client._retry_enabled = False

    with pytest.raises(NetworkError):
        client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert route.call_count == 1


@pytest.mark.asyncio
async def test_async_a_5xx_on_a_poll_is_retried_inside_the_poll(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _noop(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _noop)
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_server_error(), _server_error(), _success()]
    )

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    tokens = await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert tokens.access_token.get_secret_value() == "device-access-token"
    route.mock(return_value=_rate_limited("1"))
    with pytest.raises(OAuthProtocolError):
        await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    assert route.call_count == 4, "the 429 added exactly one request"


# ---------------------------------------------------------------------
# C164-29: the clock wiring in device_login, through the loop itself
# ---------------------------------------------------------------------


def test_device_login_sends_no_poll_at_or_after_the_deadline_with_a_slow_server(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    monkeypatch.setattr(time, "sleep", lambda s: now.__setitem__(0, now[0] + s))
    _authorize_with(respx_mock, expires_in=10, interval=2)
    sent_at: list[float] = []

    def _slow_pending(_request: httpx.Request) -> httpx.Response:
        sent_at.append(now[0])
        now[0] += 3  # a slow round trip, never slept
        return _oauth_error("authorization_pending")

    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=_slow_pending)

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token"
    assert sent_at == [2, 7], "t=2 and t=7; the next wait would reach t >= 10"
    assert all(t < 10 for t in sent_at)


@pytest.mark.asyncio
async def test_async_device_login_counts_the_user_code_callback_against_the_deadline(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])

    async def _sleep(delay: float) -> None:
        now[0] += delay

    monkeypatch.setattr(asyncio, "sleep", _sleep)
    _authorize_with(respx_mock, expires_in=10, interval=2)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error("authorization_pending")
    )

    async def _slow_callback(_auth: object) -> None:
        now[0] += 7  # the user-code screen takes 7 s

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(OAuthProtocolError) as excinfo:
        await client.device_login(_slow_callback, tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token"
    assert route.call_count == 1, "one poll at t=9; the next wait would pass t=10"


# ---------------------------------------------------------------------
# C164-36: the in-poll §16 retry never goes past the grant's deadline
# ---------------------------------------------------------------------


class _FakeClock:
    """``time.monotonic`` plus ``time.sleep``/``asyncio.sleep`` that advance it."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = 0.0
        monkeypatch.setattr(time, "monotonic", lambda: self.now)
        monkeypatch.setattr(time, "sleep", self.sleep)
        monkeypatch.setattr(asyncio, "sleep", self.async_sleep)
        monkeypatch.setattr("random.random", lambda: 1.0)  # maximum jitter

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    async def async_sleep(self, seconds: float) -> None:
        self.now += seconds


def _sent_at(clock: _FakeClock, answer: Callable[[], httpx.Response]) -> tuple[Any, list[float]]:
    sent: list[float] = []

    def respond(_request: httpx.Request) -> httpx.Response:
        sent.append(clock.now)
        return answer()

    return respond, sent


def test_a_poll_sent_just_before_the_deadline_is_not_retried_after_it(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A 7.9 s on_user_code leaves the first poll at t=9.9 of a 10 s grant; its 500 would be
    # retried at t>=10.1 by the unbounded runner.
    clock = _FakeClock(monkeypatch)
    _authorize_with(respx_mock, expires_in=10, interval=2)
    respond, sent = _sent_at(clock, _server_error)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=respond)

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_login(lambda _auth: clock.sleep(7.9), tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token"
    assert [round(t, 1) for t in sent] == [9.9], "one request, none at or after the deadline"


def test_a_5xx_retry_after_past_the_deadline_sends_nothing_after_it(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _FakeClock(monkeypatch)
    _authorize_with(respx_mock, expires_in=30, interval=5)
    respond, sent = _sent_at(
        clock,
        lambda: httpx.Response(
            503, json={"error": "temporarily_unavailable"}, headers={"Retry-After": "120"}
        ),
    )
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=respond)

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token"
    assert sent and all(t < 30 for t in sent), "no request at or after 30 s"
    assert clock.now < 30, "expired_token by the deadline, not after a 120 s wait"


@pytest.mark.asyncio
async def test_async_a_poll_sent_just_before_the_deadline_is_not_retried_after_it(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _FakeClock(monkeypatch)
    _authorize_with(respx_mock, expires_in=10, interval=2)
    respond, sent = _sent_at(clock, _server_error)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=respond)

    async def slow_callback(_auth: object) -> None:
        clock.now += 7.9

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(OAuthProtocolError) as excinfo:
        await client.device_login(slow_callback, tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token"
    assert [round(t, 1) for t in sent] == [9.9]


@pytest.mark.asyncio
async def test_async_a_5xx_retry_after_past_the_deadline_sends_nothing_after_it(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _FakeClock(monkeypatch)
    _authorize_with(respx_mock, expires_in=30, interval=5)
    respond, sent = _sent_at(
        clock,
        lambda: httpx.Response(503, json={"error": "busy"}, headers={"Retry-After": "120"}),
    )
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(side_effect=respond)

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(OAuthProtocolError) as excinfo:
        await client.device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert excinfo.value.error == "expired_token"
    assert sent and all(t < 30 for t in sent)
    assert clock.now < 30


def test_a_bare_device_poll_keeps_the_unbounded_section_16_budget_and_the_floor(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps = _record_sleeps(monkeypatch)
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[
            httpx.Response(503, json={"error": "busy"}, headers={"Retry-After": "2"}),
            _success(),
        ]
    )

    _client().device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert route.call_count == 2
    assert sleeps[0] >= 2.0, "a 5xx Retry-After is a floor on the in-poll wait (C164-37)"


# ---------------------------------------------------------------------
# C164-38: the async transport case, and the loop-level cases
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_a_transport_failure_twice_then_200_makes_three_requests(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from axiam_sdk import NetworkError

    async def _noop(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _noop)
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[httpx.ConnectError("refused"), httpx.ReadError("reset"), _success()]
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    tokens = await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert tokens.access_token.get_secret_value() == "device-access-token"

    before = route.call_count
    route.mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(NetworkError):
        await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    assert route.call_count - before == 3, "the cap is three attempts in all"


def test_two_transport_failures_then_200_complete_device_login_in_one_interval(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps = _record_sleeps(monkeypatch)
    _authorize_with(respx_mock, interval=2)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[httpx.ConnectError("refused"), httpx.ConnectError("refused"), _success()]
    )

    _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert [wait for wait in sleeps if wait >= 1] == [2]


def test_with_retry_disabled_device_login_makes_one_request_per_poll(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps = _record_sleeps(monkeypatch)
    _authorize_with(respx_mock, interval=2)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        side_effect=[_server_error(), _server_error(), _success()]
    )
    client = _client()
    client._retry_enabled = False

    client.device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 3
    assert sleeps == [2, 2, 2], "one request per poll, an interval each, no §16 wait"
