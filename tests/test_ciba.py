"""CIBA — CONTRACT §33.8's sixteen required tests (nine initiation and polling,
four ping, three signed request), plus the async surface and §21.3.1 vector A.

No credential, key or token literal: the client secret, the ``auth_req_id``,
the notification token and every signing key are generated at run time.
Failure messages print fixed text or offsets, never a secret.
"""

from __future__ import annotations

import base64
import inspect
import json
import re
import secrets
import socket
import threading
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import SecretStr

import axiam_sdk._ciba as ciba_module
from axiam_sdk import (
    AsyncAxiamClient,
    AuthError,
    AxiamClient,
    CibaAccessDeniedError,
    CibaExpiredTokenError,
    CibaInitiateResponse,
    CibaRequestSigner,
    MtlsEndpointAliases,
    NetworkError,
    OAuthProtocolError,
    OidcConfiguration,
)
from axiam_sdk.management import ValidationError
from tests._oidc_testkit import (
    BASE_URL,
    BC_AUTHORIZE_ENDPOINT,
    CLIENT_ID,
    FakeJwksEndpoint,
    client_identity_pem,
    discovery_document,
    make_ed25519_keypair_and_jwk,
    make_id_token_claims,
    sign_id_token,
)

TENANT_ID = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"
TOKEN_ENDPOINT = f"{BASE_URL}/oauth2/token"
CONFIG = OidcConfiguration.model_validate(discovery_document())


def random() -> str:
    """A run-time secret value."""
    return secrets.token_urlsafe(32)


def assert_no_fragment(haystack: str, secret: str) -> None:
    """No 8-character substring of ``secret`` in ``haystack`` (offset-only failure)."""
    for i in range(len(secret) - 7):
        if secret[i : i + 8] in haystack:
            pytest.fail(f"an 8-character fragment of a secret (offset {i}) was rendered")


def make_client(*, secret: str | None = None, mtls: bool = False) -> AxiamClient:
    """A CIBA client: confidential with ``secret``, or ``tls_client_auth``."""
    kwargs: dict[str, Any] = {"base_url": BASE_URL, "tenant_slug": "acme", "client_id": CLIENT_ID}
    if secret is not None:
        kwargs["client_secret"] = secret
    if mtls:
        cert, key = client_identity_pem()
        kwargs["client_cert"] = cert
        kwargs["client_key"] = key
    return AxiamClient(**kwargs)


def form_of(request: httpx.Request) -> dict[str, str]:
    """A form body as a flat dict."""
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def oauth_error(status: int, code: str) -> httpx.Response:
    """An ``OAuth2ErrorResponse`` answer."""
    return httpx.Response(status, json={"error": code, "error_description": f"{code} here"})


def initiate_ok(**extra: Any) -> httpx.Response:
    """A ``CibaInitiateResponse``."""
    body: dict[str, Any] = {"auth_req_id": random(), "expires_in": 120, "interval": 5}
    body.update(extra)
    return httpx.Response(200, json=body)


class TestClock:
    """A clock that never sleeps: ``sleep`` advances it and records the wait."""

    __test__ = False

    def __init__(self) -> None:
        """Start at an arbitrary monotonic reading."""
        self.start = 1000.0
        self.elapsed = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        """The current reading."""
        return self.start + self.elapsed

    def sleep(self, seconds: float) -> None:
        """Advance instead of waiting."""
        self.elapsed += seconds
        self.sleeps.append(seconds)


class AsyncTestClock(TestClock):
    """:class:`TestClock` with an awaitable ``sleep``."""

    __test__ = False

    async def sleep(self, seconds: float) -> None:  # type: ignore[override]
        """Advance instead of waiting."""
        TestClock.sleep(self, seconds)


def initiated(expires_in: int, interval: int, clock: TestClock) -> CibaInitiateResponse:
    """A response received at the clock's start."""
    return CibaInitiateResponse(
        auth_req_id=SecretStr(random()),
        expires_in=expires_in,
        interval=interval,
        received_at=clock.start,
    )


def tokens_with_id_token(client: AxiamClient | AsyncAxiamClient) -> httpx.Response:
    """A ``200`` token set whose ID token validates against a bound JWKS."""
    private_key, jwk = make_ed25519_keypair_and_jwk(kid=f"ciba-{secrets.token_hex(4)}")
    FakeJwksEndpoint([jwk]).bind_to_client(client)
    claims = make_id_token_claims()
    claims.pop("nonce")
    return httpx.Response(
        200,
        json={
            "access_token": random(),
            "token_type": "Bearer",
            "expires_in": 900,
            "scope": "openid profile",
            "id_token": sign_id_token(private_key, jwk["kid"], claims),
        },
    )


def script(router: respx.MockRouter, answers: list[httpx.Response], clock: TestClock | None):
    """Answer the token endpoint from ``answers`` (the last repeats), recording
    each request and the clock reading at it."""
    seen: list[tuple[dict[str, str], float, httpx.Request]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        """The next scripted answer."""
        seen.append((form_of(request), clock.elapsed if clock else 0.0, request))
        return answers[min(len(seen), len(answers)) - 1]

    router.post(TOKEN_ENDPOINT).mock(side_effect=respond)
    return seen


@pytest.fixture
def router():
    """A respx router over every request of the test."""
    with respx.mock(assert_all_called=False) as mock:
        yield mock


# ── 1. Redaction ─────────────────────────────────────────────────────────────


def test_t01_the_three_values_are_on_the_wire_and_in_no_rendering(router: respx.MockRouter) -> None:
    """Notification token, ``auth_req_id``, and an error: wire yes, renderings no."""
    notification = random()
    auth_req_id = random()
    route = router.post(BC_AUTHORIZE_ENDPOINT).mock(
        return_value=initiate_ok(auth_req_id=auth_req_id)
    )
    client = make_client(secret=random())
    response = client.ciba_initiate(
        scope="openid profile",
        login_hint="ada",
        delivery="ping",
        client_notification_token=SecretStr(notification),
        tenant_id=TENANT_ID,
        configuration=CONFIG,
    )
    for rendering in (repr(response), str(response), response.model_dump_json()):
        assert_no_fragment(rendering, auth_req_id)
    if response.auth_req_id.get_secret_value() != auth_req_id:
        pytest.fail("the auth_req_id was not returned")
    if form_of(route.calls[0].request)["client_notification_token"] != notification:
        pytest.fail("the notification token was not on the wire")

    router.routes.clear()
    router.post(BC_AUTHORIZE_ENDPOINT).mock(
        return_value=oauth_error(400, "invalid_binding_message")
    )
    with pytest.raises(OAuthProtocolError) as excinfo:
        client.ciba_initiate(
            scope="openid",
            login_hint="ada",
            delivery="ping",
            client_notification_token=notification,
            tenant_id=TENANT_ID,
            configuration=CONFIG,
        )
    assert excinfo.value.error == "invalid_binding_message"
    assert excinfo.value.error_description == "invalid_binding_message here"
    assert_no_fragment(f"{excinfo.value} {excinfo.value!r}", notification)


# ── 2. Client authentication is mandatory ────────────────────────────────────


def test_t02_no_credential_is_refused_and_one_is_sent_with_tenant_in_the_query(
    router: respx.MockRouter,
) -> None:
    """Public client: ``AuthError``, zero requests. Secret / certificate: sent."""
    initiate = router.post(BC_AUTHORIZE_ENDPOINT).mock(return_value=initiate_ok())
    polls = script(router, [oauth_error(400, "authorization_pending")], None)
    public = make_client()
    with pytest.raises(AuthError):
        public.ciba_initiate(
            scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=CONFIG
        )
    with pytest.raises(AuthError):
        public.ciba_poll(random(), tenant_id=TENANT_ID, configuration=CONFIG)
    count = len(polls)
    assert initiate.call_count == 0 and count == 0

    secret = random()
    client = make_client(secret=secret)
    client.ciba_initiate(
        scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=CONFIG
    )
    with pytest.raises(OAuthProtocolError):
        client.ciba_poll(random(), tenant_id=TENANT_ID, configuration=CONFIG)
    for request in (initiate.calls[0].request, polls[0][2]):
        form = form_of(request)
        assert form["client_id"] == CLIENT_ID
        if form["client_secret"] != secret:
            pytest.fail("the client secret was not sent")
        assert "tenant_id" not in form, "never a body field"
        assert request.url.params["tenant_id"] == TENANT_ID
        assert request.headers["x-tenant-id"] == "acme"

    # A tls_client_auth client: the certificate is the credential.
    make_client(mtls=True).ciba_initiate(
        scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=CONFIG
    )
    form = form_of(initiate.calls[1].request)
    assert form["client_id"] == CLIENT_ID
    assert "client_secret" not in form


# ── 3. The initiate request ──────────────────────────────────────────────────


def test_t03_exactly_the_members_set_are_sent(router: respx.MockRouter) -> None:
    """Minimal and full forms; both hints, neither, and ping without a token refused."""
    route = router.post(BC_AUTHORIZE_ENDPOINT).mock(return_value=initiate_ok())
    client = make_client(secret=random())
    common = {"tenant_id": TENANT_ID, "configuration": CONFIG}
    client.ciba_initiate(scope="openid profile", login_hint="ada", **common)
    token = random()
    client.ciba_initiate(
        scope="openid profile",
        id_token_hint="an.id.token",
        binding_message="W4SCT",
        requested_expiry=120,
        acr_values="urn:axiam:acr:mfa",
        resource="https://api.example.test",
        delivery="ping",
        client_notification_token=token,
        **common,
    )
    minimal = form_of(route.calls[0].request)
    assert sorted(minimal) == ["client_id", "client_secret", "login_hint", "scope"]
    full = form_of(route.calls[1].request)
    assert sorted(full) == [
        "acr_values",
        "binding_message",
        "client_id",
        "client_notification_token",
        "client_secret",
        "id_token_hint",
        "requested_expiry",
        "resource",
        "scope",
    ]
    assert full["requested_expiry"] == "120"
    if full["client_notification_token"] != token:
        pytest.fail("the notification token was not on the wire")
    for forbidden in ("login_hint_token", "user_code", "request_uri", "request"):
        assert forbidden not in full
    signature = inspect.signature(AxiamClient.ciba_initiate).parameters
    for forbidden in ("login_hint_token", "user_code", "request_uri"):
        assert forbidden not in signature, "no parameter exists for it"

    refusals: list[dict[str, Any]] = [
        {"login_hint": "ada", "id_token_hint": "x"},
        {},
        {"login_hint": "ada", "delivery": "ping"},
        {"login_hint": "ada", "delivery": "ping", "client_notification_token": ""},
        {"login_hint": "ada", "client_notification_token": token},
        {"login_hint": "ada", "delivery": "push"},
    ]
    for kwargs in refusals:
        with pytest.raises(ValidationError):
            client.ciba_initiate(scope="openid", **kwargs, **common)
    assert route.call_count == 2


# ── 4. No retry on initiate ──────────────────────────────────────────────────


def test_t04_initiate_is_sent_once_on_503_429_and_a_dropped_connection(
    router: respx.MockRouter,
) -> None:
    """A retry-enabled client sends exactly one request each time."""
    client = make_client(secret=random())
    assert client._retry_enabled
    common = {"tenant_id": TENANT_ID, "configuration": CONFIG}
    route = router.post(BC_AUTHORIZE_ENDPOINT).mock(return_value=httpx.Response(503))
    with pytest.raises(NetworkError):
        client.ciba_initiate(scope="openid", login_hint="ada", **common)
    assert route.call_count == 1
    router.routes.clear()
    route = router.post(BC_AUTHORIZE_ENDPOINT).mock(
        return_value=oauth_error(429, "rate_limit_exceeded")
    )
    with pytest.raises(OAuthProtocolError) as limited:
        client.ciba_initiate(scope="openid", login_hint="ada", **common)
    assert limited.value.error == "rate_limit_exceeded", "§2's /oauth2 row"
    assert route.call_count == 1


def test_t04_a_dropped_connection_is_one_attempt_and_a_network_error() -> None:
    """A raw listener that accepts and hangs up: one connection, no retry."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    accepts = [0]
    stop = threading.Event()

    def serve() -> None:
        """Accept and close, counting."""
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            accepts[0] += 1
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    config = OidcConfiguration.model_validate(
        discovery_document(
            backchannel_authentication_endpoint=f"http://127.0.0.1:{port}/oauth2/bc-authorize"
        )
    )
    client = make_client(secret=random())
    try:
        with pytest.raises(NetworkError):
            client.ciba_initiate(
                scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=config
            )
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)
        client.close()
    assert accepts[0] == 1, "one connection, no retry"


# ── 5. Poll outcomes ─────────────────────────────────────────────────────────


def test_t05_pending_loops_slow_down_persists_and_terminal_answers_are_distinct(
    router: respx.MockRouter,
) -> None:
    """Sleeps 5, 10, 15, 15; then each terminal code after one request."""
    client = make_client(secret=random())
    clock = TestClock()
    seen = script(
        router,
        [
            oauth_error(400, "slow_down"),
            oauth_error(400, "slow_down"),
            oauth_error(400, "authorization_pending"),
            tokens_with_id_token(client),
        ],
        clock,
    )
    request = initiated(600, 5, clock)
    tokens = client.ciba_await(request, tenant_id=TENANT_ID, configuration=CONFIG, clock=clock)
    assert tokens.id_claims is not None
    assert clock.sleeps == [5, 10, 15, 15], "+5 s twice, and pending lowers nothing"
    secret_id = request.auth_req_id.get_secret_value()
    for form, _, _ in seen:
        assert form["grant_type"] == "urn:openid:params:grant-type:ciba"
        if form["auth_req_id"] != secret_id:
            pytest.fail("the auth_req_id was not on the wire")

    for code, expected in (
        ("access_denied", CibaAccessDeniedError),
        ("expired_token", CibaExpiredTokenError),
        ("invalid_grant", OAuthProtocolError),
        ("a_code_nobody_defined", OAuthProtocolError),
    ):
        router.routes.clear()
        clock = TestClock()
        seen = script(router, [oauth_error(400, code)], clock)
        with pytest.raises(OAuthProtocolError) as excinfo:
            client.ciba_await(
                initiated(600, 5, clock), tenant_id=TENANT_ID, configuration=CONFIG, clock=clock
            )
        assert type(excinfo.value) is expected, code
        assert excinfo.value.error == code
        count = len(seen)
        assert count == 1, f"{code} is terminal"
    assert not issubclass(CibaAccessDeniedError, CibaExpiredTokenError)
    assert not issubclass(CibaExpiredTokenError, CibaAccessDeniedError)


def test_t05_an_unknown_answer_without_an_error_member_falls_back_to_section_2(
    router: respx.MockRouter,
) -> None:
    """A bodiless 400 is a terminal ``NetworkError``, polled once."""
    client = make_client(secret=random())
    clock = TestClock()
    seen = script(router, [httpx.Response(400)], clock)
    with pytest.raises(NetworkError):
        client.ciba_await(
            initiated(600, 5, clock), tenant_id=TENANT_ID, configuration=CONFIG, clock=clock
        )
    count = len(seen)
    assert count == 1


# ── 6. The first poll waits ──────────────────────────────────────────────────


def test_t06_the_first_poll_waits_the_interval_or_five_seconds(router: respx.MockRouter) -> None:
    """7 from the response, 5 when absent or zero -- on the injected clock."""
    for interval, expected in ((7, 7), (None, 5), (0, 5)):
        router.routes.clear()
        body: dict[str, Any] = {"auth_req_id": random(), "expires_in": 300}
        if interval is not None:
            body["interval"] = interval
        router.post(BC_AUTHORIZE_ENDPOINT).mock(return_value=httpx.Response(200, json=body))
        clock = TestClock()
        seen = script(router, [oauth_error(400, "access_denied")], clock)
        client = make_client(secret=random())
        response = client.ciba_initiate(
            scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=CONFIG
        )
        assert response.interval == expected
        response = response.model_copy(update={"received_at": clock.start})
        with pytest.raises(CibaAccessDeniedError):
            client.ciba_await(response, tenant_id=TENANT_ID, configuration=CONFIG, clock=clock)
        first_at = seen[0][1]
        assert first_at == expected


# ── 7. Deadline ──────────────────────────────────────────────────────────────


def test_t07_no_request_after_expires_in_and_expired_token_is_raised_locally(
    router: respx.MockRouter,
) -> None:
    """``expires_in`` 12, interval 5: requests at 5 and 10, then local expiry."""
    client = make_client(secret=random())
    clock = TestClock()
    seen = script(router, [oauth_error(400, "authorization_pending")], clock)
    with pytest.raises(CibaExpiredTokenError):
        client.ciba_await(
            initiated(12, 5, clock), tenant_id=TENANT_ID, configuration=CONFIG, clock=clock
        )
    times = [at for _, at, _ in seen]
    assert times == [5, 10], "nothing at 15 s, past the 12 s deadline"


# ── 8. Transient failure is not terminal ─────────────────────────────────────


def test_t08_a_500_and_a_429_mid_loop_are_survived(router: respx.MockRouter) -> None:
    """``pending``, ``500 {"error":"server_error"}`` (retried within the poll --
    a ``5xx`` is transient whatever its body, §34.2 P8), ``429``, then tokens."""
    client = make_client(secret=random())
    clock = TestClock()
    seen = script(
        router,
        [
            oauth_error(400, "authorization_pending"),
            httpx.Response(500, json={"error": "server_error"}),
            oauth_error(429, "rate_limit_exceeded"),
            tokens_with_id_token(client),
        ],
        clock,
    )
    tokens = client.ciba_await(
        initiated(600, 5, clock), tenant_id=TENANT_ID, configuration=CONFIG, clock=clock
    )
    assert tokens.access_token.get_secret_value()
    assert tokens.id_token is not None and tokens.id_claims is not None
    count = len(seen)
    assert count == 4


def test_t08_a_transport_failure_that_outlives_section_16_is_waited_out(
    router: respx.MockRouter,
) -> None:
    """A connection error on every attempt of one poll; the loop polls again."""
    client = make_client(secret=random())
    client._retry_enabled = False
    clock = TestClock()
    answers = iter([httpx.ConnectError("reset"), tokens_with_id_token(client)])

    def respond(request: httpx.Request) -> httpx.Response:
        """A failure, then tokens."""
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    router.post(TOKEN_ENDPOINT).mock(side_effect=respond)
    client.ciba_await(
        initiated(600, 5, clock), tenant_id=TENANT_ID, configuration=CONFIG, clock=clock
    )
    assert clock.sleeps == [5, 5]


# ── 9. Single use ────────────────────────────────────────────────────────────


def test_t09_a_second_redemption_is_invalid_grant_and_not_retried(router: respx.MockRouter) -> None:
    """``200``, then ``invalid_grant``: exactly two requests."""
    client = make_client(secret=random())
    seen = script(router, [tokens_with_id_token(client), oauth_error(400, "invalid_grant")], None)
    auth_req_id = SecretStr(random())
    client.ciba_poll(auth_req_id, tenant_id=TENANT_ID, configuration=CONFIG)
    with pytest.raises(OAuthProtocolError) as excinfo:
        client.ciba_poll(auth_req_id, tenant_id=TENANT_ID, configuration=CONFIG)
    assert excinfo.value.error == "invalid_grant"
    count = len(seen)
    assert count == 2, "no retry of the second"


def test_t09_an_unreadable_200_is_not_retried(router: respx.MockRouter) -> None:
    """The server may already have redeemed: one request, ``NetworkError``."""
    client = make_client(secret=random())
    seen = script(router, [httpx.Response(200, text="<html/>")], None)
    with pytest.raises(NetworkError):
        client.ciba_poll(random(), tenant_id=TENANT_ID, configuration=CONFIG)
    count = len(seen)
    assert count == 1


# ── 10-13. The ping ──────────────────────────────────────────────────────────


def ping_headers(*authorization: str) -> list[tuple[str, str]]:
    """The ping's headers, with ``authorization`` values as given."""
    return [("content-type", "application/json"), *[("Authorization", a) for a in authorization]]


def test_t10_a_valid_ping_returns_its_auth_req_id_in_any_scheme_case() -> None:
    """``Bearer`` in any case; the id comes back wrapped."""
    client = make_client(secret=random())
    token, auth_req_id = random(), random()
    body = json.dumps({"auth_req_id": auth_req_id})
    for scheme in ("Bearer", "bearer", "BEARER"):
        got = client.ciba_handle_ping(
            ping_headers(f"{scheme} {token}"), body.encode(), SecretStr(token)
        )
        assert isinstance(got, SecretStr)
        if got.get_secret_value() != auth_req_id:
            pytest.fail("the ping's auth_req_id was not returned")
        assert_no_fragment(repr(got), auth_req_id)
    # A mapping and a multi-valued header object work too.
    assert client.ciba_handle_ping({"Authorization": f"Bearer {token}"}, body, token)
    multi = httpx.Headers([("authorization", f"Bearer {token}")])
    assert client.ciba_handle_ping(multi, body, token)
    raw = [(b"authorization", f"Bearer {token}".encode())]
    assert client.ciba_handle_ping(raw, body, token)


def test_t11_wrong_absent_empty_duplicate_basic_or_last_char_is_refused() -> None:
    """Every refusal an ``AuthError`` that names no value; constant time, structurally."""
    client = make_client(secret=random())
    token = random()
    last_differs = token[:-1] + ("a" if token[-1] != "a" else "b")
    body = json.dumps({"auth_req_id": random()})
    cases = [
        [f"Bearer {random()}"],
        [],
        [""],
        ["Bearer "],
        ["Bearer"],
        [f"Bearer {token}", f"Bearer {token}"],
        [f"Basic {token}"],
        [f"Bearer {last_differs}"],
        [f"Bearer  {token}"],
    ]
    for case in cases:
        with pytest.raises(AuthError) as excinfo:
            client.ciba_handle_ping(ping_headers(*case), body, SecretStr(token))
        assert_no_fragment(f"{excinfo.value} {excinfo.value!r}", token)
    with pytest.raises(AuthError):
        client.ciba_handle_ping(ping_headers(f"Bearer {token}"), body, "")
    multi = httpx.Headers([("authorization", f"Bearer {token}"), ("authorization", "x")])
    with pytest.raises(AuthError):
        client.ciba_handle_ping(multi, body, token)
    # Python has no timing harness here, so §33.8 test 11 is asserted
    # structurally: the token comparison is `hmac.compare_digest`.
    source = inspect.getsource(ciba_module.handle_ping)
    assert "hmac.compare_digest(" in source


def test_t12_a_malformed_body_is_a_validation_error_and_extras_are_ignored() -> None:
    """Not JSON, no id, an empty or non-string id, not an object: refused."""
    client = make_client(secret=random())
    token = random()
    header = ping_headers(f"Bearer {token}")
    for body in (
        "not json",
        json.dumps({}),
        json.dumps({"auth_req_id": ""}),
        json.dumps({"auth_req_id": 42}),
        json.dumps(["auth_req_id"]),
    ):
        with pytest.raises(ValidationError):
            client.ciba_handle_ping(header, body, token)
    auth_req_id = random()
    got = client.ciba_handle_ping(
        header,
        json.dumps({"auth_req_id": auth_req_id, "status": "approved", "access_token": "x"}),
        token,
    )
    if got.get_secret_value() != auth_req_id:
        pytest.fail("extras were not ignored")


def test_t13_the_ping_helper_makes_no_network_call(router: respx.MockRouter) -> None:
    """The mock records zero requests."""
    client = make_client(secret=random())
    token = random()
    client.ciba_handle_ping(
        ping_headers(f"Bearer {token}"), json.dumps({"auth_req_id": random()}), token
    )
    assert router.calls.call_count == 0


# ── 14-16. The signed form ───────────────────────────────────────────────────


def ed25519_pem() -> tuple[bytes, ed25519.Ed25519PublicKey]:
    """A fresh Ed25519 key as PKCS#8 PEM, and its public half."""
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem, key.public_key()


def ec_pem() -> tuple[bytes, ec.EllipticCurvePublicKey]:
    """A fresh P-256 key as PKCS#8 PEM, and its public half."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem, key.public_key()


def decode_part(part: str) -> dict[str, Any]:
    """A JWS header or payload."""
    return dict(json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))))


def test_t14_the_signed_request_is_one_member_with_the_registered_alg_and_fresh_jti(
    router: respx.MockRouter,
) -> None:
    """Exactly ``request`` beside client auth; alg/kid; claims; fresh jti; ES256 too."""
    route = router.post(BC_AUTHORIZE_ENDPOINT).mock(return_value=initiate_ok())
    secret = random()
    client = make_client(secret=secret)
    pem, public = ed25519_pem()
    signer = CibaRequestSigner("EdDSA", SecretStr(pem.decode()), kid="client-key-1")
    notification = random()
    for _ in range(2):
        client.ciba_initiate(
            scope="openid",
            login_hint="ada",
            binding_message="W4SCT",
            requested_expiry=90,
            delivery="ping",
            client_notification_token=notification,
            signer=signer,
            tenant_id=TENANT_ID,
            configuration=CONFIG,
        )
    jtis = []
    for call in route.calls:
        form = form_of(call.request)
        assert sorted(form) == ["client_id", "client_secret", "request"], "nothing beside it"
        if form["client_secret"] != secret:
            pytest.fail("the client secret was not sent")
        request = form["request"]
        header = decode_part(request.split(".")[0])
        assert header["alg"] == "EdDSA" and header["kid"] == "client-key-1"
        claims = jwt.decode(request, public, algorithms=["EdDSA"], audience=BASE_URL)
        assert claims["iss"] == CLIENT_ID and claims["aud"] == BASE_URL
        assert isinstance(claims["iat"], int)
        assert claims["exp"] > claims["nbf"] and claims["exp"] - claims["nbf"] <= 3600
        assert claims["login_hint"] == "ada" and claims["binding_message"] == "W4SCT"
        assert claims["requested_expiry"] == 90, "a JSON number inside the JWT"
        if claims["client_notification_token"] != notification:
            pytest.fail("the notification token was not inside the request")
        assert len(claims["jti"]) >= 32
        jtis.append(claims["jti"])
    assert jtis[0] != jtis[1], "a fresh jti per request"

    ec_key, ec_public = ec_pem()
    es = CibaRequestSigner("ES256", ec_key)
    assert es.alg == "ES256" and es.kid is None
    client.ciba_initiate(
        scope="openid", login_hint="ada", signer=es, tenant_id=TENANT_ID, configuration=CONFIG
    )
    last = form_of(route.calls[-1].request)["request"]
    assert decode_part(last.split(".")[0])["alg"] == "ES256"
    assert "kid" not in decode_part(last.split(".")[0])
    jwt.decode(last, ec_public, algorithms=["ES256"], audience=BASE_URL)


def test_t15_no_key_or_a_key_for_another_alg_is_refused_before_any_request(
    router: respx.MockRouter,
) -> None:
    """Empty key, mismatched key, unknown algorithm: local ``ValidationError``."""
    route = router.post(BC_AUTHORIZE_ENDPOINT).mock(return_value=initiate_ok())
    ed, _ = ed25519_pem()
    eck, _ = ec_pem()
    for alg, key in (
        ("EdDSA", ""),
        ("ES256", ed),
        ("PS256", eck),
        ("EdDSA", eck),
        ("EdDSA", b"not a key"),
        ("RS256", ed),
        ("none", ed),
    ):
        with pytest.raises(ValidationError):
            CibaRequestSigner(alg, key)  # type: ignore[arg-type]
    # The algorithm and the key are the constructor's two required arguments,
    # so "no algorithm" cannot be written, and ciba_initiate takes no extra
    # form parameter beside a signer.
    params = inspect.signature(CibaRequestSigner).parameters
    assert params["alg"].default is inspect.Parameter.empty
    assert params["private_key"].default is inspect.Parameter.empty
    assert not any(
        p.kind is inspect.Parameter.VAR_KEYWORD
        for p in inspect.signature(AxiamClient.ciba_initiate).parameters.values()
    )
    assert route.call_count == 0


def test_t16_the_key_and_the_request_appear_in_no_rendering(router: respx.MockRouter) -> None:
    """``repr`` of the signer and an initiate error hold neither."""
    route = router.post(BC_AUTHORIZE_ENDPOINT).mock(
        return_value=oauth_error(400, "invalid_request")
    )
    pem, _ = ed25519_pem()
    body_line = pem.decode().splitlines()[1]
    signer = CibaRequestSigner("EdDSA", pem)
    client = make_client(secret=random())
    with pytest.raises(OAuthProtocolError) as excinfo:
        client.ciba_initiate(
            scope="openid",
            login_hint="ada",
            signer=signer,
            tenant_id=TENANT_ID,
            configuration=CONFIG,
        )
    request = form_of(route.calls[0].request)["request"]
    for rendering in (repr(signer), str(signer), f"{excinfo.value} {excinfo.value!r}"):
        assert_no_fragment(rendering, body_line)
        assert_no_fragment(rendering, request)
    assert "EdDSA" in repr(signer)


# ── §21.3.1 vector A, and discovery ──────────────────────────────────────────


def vector_a() -> dict[str, Any]:
    """§21.3.1 vector A, read from the vendored CONTRACT.md."""
    text = (Path(__file__).resolve().parents[1] / "CONTRACT.md").read_text()
    section = text[text.index("**Vector A") :]
    match = re.search(r"```json\n(.*?)\n```", section, re.S)
    assert match is not None
    return dict(json.loads(match.group(1)))


def test_vector_a_carries_seven_aliases_and_ciba_uses_its_alias(router: respx.MockRouter) -> None:
    """An mTLS client's CIBA call goes to the alias, query intact."""
    vector = vector_a()
    assert set(vector["mtls_endpoint_aliases"]) == set(MtlsEndpointAliases.model_fields)
    assert len(vector["mtls_endpoint_aliases"]) == 7
    config = OidcConfiguration.model_validate(discovery_document(**vector))
    alias = config.mtls_endpoint_aliases
    assert alias is not None and alias.backchannel_authentication_endpoint
    mtls = router.post("https://mtls.iam.example.test/oauth2/bc-authorize").mock(
        return_value=initiate_ok()
    )
    front = router.post("https://iam.example.test/oauth2/bc-authorize").mock(
        return_value=initiate_ok()
    )
    make_client(mtls=True).ciba_initiate(
        scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=config
    )
    assert mtls.call_count == 1 and front.call_count == 0
    params = mtls.calls[0].request.url.params
    assert params.get_list("tenant_id") == [TENANT_ID], "displaced, never duplicated"
    make_client(secret=random()).ciba_initiate(
        scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=config
    )
    assert front.call_count == 1, "no certificate, no alias"


def test_a_server_without_ciba_is_refused_locally(router: respx.MockRouter) -> None:
    """No ``backchannel_authentication_endpoint``: ``AuthError``, never a built URL."""
    doc = discovery_document()
    doc.pop("backchannel_authentication_endpoint")
    router.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=doc)
    )
    client = make_client(secret=random())
    with pytest.raises(AuthError, match="does not support CIBA"):
        client.ciba_initiate(scope="openid", login_hint="ada", tenant_id=TENANT_ID)
    full = OidcConfiguration.model_validate(
        discovery_document(
            backchannel_token_delivery_modes_supported=["poll", "ping"],
            backchannel_user_code_parameter_supported=False,
            backchannel_authentication_request_signing_alg_values_supported=[
                "PS256",
                "ES256",
                "EdDSA",
            ],
        )
    )
    assert full.backchannel_token_delivery_modes_supported == ["poll", "ping"]
    assert full.backchannel_user_code_parameter_supported is False


def test_an_unusable_initiate_answer_is_a_network_error(router: respx.MockRouter) -> None:
    """Not JSON, or not a ``CibaInitiateResponse``."""
    client = make_client(secret=random())
    for answer in (
        httpx.Response(200, text="<html/>"),
        httpx.Response(200, json={"auth_req_id": 1, "expires_in": 120}),
        httpx.Response(200, json=["x"]),
    ):
        router.routes.clear()
        router.post(BC_AUTHORIZE_ENDPOINT).mock(return_value=answer)
        with pytest.raises(NetworkError):
            client.ciba_initiate(
                scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=CONFIG
            )


# ── The async client carries the same names ──────────────────────────────────


@pytest.mark.asyncio
async def test_the_async_client_initiates_polls_and_awaits_alike(router: respx.MockRouter) -> None:
    """Initiate (once on 503), await with an async clock, poll, ping."""
    secret = random()
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=secret
    )
    route = router.post(BC_AUTHORIZE_ENDPOINT).mock(return_value=initiate_ok(interval=7))
    response = await client.ciba_initiate(
        scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=CONFIG
    )
    assert response.interval == 7 and route.call_count == 1

    clock = AsyncTestClock()
    seen = script(
        router,
        [
            oauth_error(400, "slow_down"),
            httpx.Response(503, json={"error": "temporarily_unavailable"}),
            oauth_error(429, "rate_limit_exceeded"),
            tokens_with_id_token(client),
        ],
        clock,
    )
    tokens = await client.ciba_await(
        response.model_copy(update={"received_at": clock.start}),
        tenant_id=TENANT_ID,
        configuration=CONFIG,
        clock=clock,
    )
    assert tokens.id_claims is not None
    assert clock.sleeps == [7, 12, 12]
    count = len(seen)
    assert count == 4, "the 503 was retried inside its poll"

    router.routes.clear()
    clock = AsyncTestClock()
    script(router, [oauth_error(400, "authorization_pending")], clock)
    with pytest.raises(CibaExpiredTokenError):
        await client.ciba_await(
            initiated(12, 5, clock), tenant_id=TENANT_ID, configuration=CONFIG, clock=clock
        )
    router.routes.clear()
    script(router, [httpx.Response(200, text="nope")], None)
    with pytest.raises(NetworkError):
        await client.ciba_poll(random(), tenant_id=TENANT_ID, configuration=CONFIG)
    router.routes.clear()
    router.post(TOKEN_ENDPOINT).mock(side_effect=httpx.ConnectError("reset"))
    router.post(BC_AUTHORIZE_ENDPOINT).mock(side_effect=httpx.ConnectError("reset"))
    client._retry_enabled = False
    with pytest.raises(NetworkError):
        await client.ciba_poll(random(), tenant_id=TENANT_ID, configuration=CONFIG)
    with pytest.raises(NetworkError):
        await client.ciba_initiate(
            scope="openid", login_hint="ada", tenant_id=TENANT_ID, configuration=CONFIG
        )

    token = random()
    got = client.ciba_handle_ping(
        ping_headers(f"Bearer {token}"), json.dumps({"auth_req_id": "r"}), token
    )
    assert got.get_secret_value() == "r"

    public = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    with pytest.raises(AuthError):
        await public.ciba_poll(random(), tenant_id=TENANT_ID, configuration=CONFIG)
    await client.aclose()
    await public.aclose()


def test_the_system_clocks_tell_monotonic_time() -> None:
    """The defaults read ``time.monotonic`` and sleep for real (briefly)."""
    from axiam_sdk import SystemCibaClock
    from axiam_sdk._ciba import AsyncSystemCibaClock

    clock = SystemCibaClock()
    before = clock.now()
    clock.sleep(0)
    assert clock.now() >= before
    import asyncio

    async_clock = AsyncSystemCibaClock()
    asyncio.run(async_clock.sleep(0))
    assert async_clock.now() >= before
