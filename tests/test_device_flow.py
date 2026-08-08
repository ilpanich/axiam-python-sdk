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
    assert "client_secret" not in form, "§14.1: device_authorize MUST NOT send client_secret"
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
            httpx.Response(500, text="upstream restarting"),
            httpx.Response(503, text="still restarting"),
            _success(),
        ]
    )

    tokens = _client().device_login(lambda _auth: None, tenant_id=TENANT_ID)

    assert route.call_count == 4, "§14.2 rule 6: a server restart must not lose an approved grant"
    assert tokens.access_token.get_secret_value() == "device-access-token"


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
