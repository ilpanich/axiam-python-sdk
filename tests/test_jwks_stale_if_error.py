"""CONTRACT.md §12.4 rule 2, "Stale-if-error, bounded" (contract 1.69, D-10): a failed JWKS refresh
keeps the held keys until exactly TTL + 300 s after the last successful fetch, then refuses every
token; an empty key set is a failed refresh; the TTL is at most 300 s. The clock is mocked, never
slept."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from jwt.exceptions import PyJWKClientConnectionError

from axiam_sdk._jwks import JwksVerifier
from axiam_sdk._telemetry import ConfigClamped, TelemetryEvent
from tests._oidc_testkit import BASE_URL, make_ed25519_keypair_and_jwk

TTL = 300.0
T0 = 10_000.0


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> float:
        return self.now

    def at(self, offset: float) -> None:
        self.now = T0 + offset


class Endpoint:
    """A counting fake JWKS endpoint with three modes: ``ok``, ``fail`` and ``empty``."""

    def __init__(self, jwks: list[dict[str, Any]]) -> None:
        self.jwks = jwks
        self.mode = "ok"
        self.calls = 0

    def fetch_data(self) -> dict[str, Any]:
        self.calls += 1
        if self.mode == "fail":
            raise PyJWKClientConnectionError("down")
        if self.mode == "empty":
            return {"keys": []}
        return {"keys": self.jwks}


def _token(key: Any, kid: str) -> str:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return jwt.encode({"sub": "u"}, pem, algorithm="EdDSA", headers={"kid": kid})


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(time, "monotonic", fake)
    return fake


def _verifier(endpoint: Endpoint) -> JwksVerifier:
    verifier = JwksVerifier(BASE_URL, jwks_url=f"{BASE_URL}/oauth2/jwks")
    verifier._client.fetch_data = endpoint.fetch_data  # type: ignore[method-assign]
    return verifier


def _accepted(verifier: JwksVerifier, token: str) -> bool:
    try:
        verifier.get_signing_key(token)
    except jwt.PyJWTError:
        return False
    finally:
        _settle(verifier)
    return True


def _settle(verifier: JwksVerifier) -> None:
    """Wait for a background refresh the call started (none on code that fetches inline)."""
    settle = getattr(verifier, "_settle", None)
    if settle is not None:
        settle()


def test_conformance_failing_refresh_keeps_held_keys_until_ttl_plus_300(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held, unknown = _token(key, "held"), _token(key, "unknown")

    assert _accepted(verifier, held)  # t0: the cache is filled
    endpoint.mode = "fail"

    clock.at(TTL + 1)
    calls = endpoint.calls
    assert _accepted(verifier, held), "held kid accepted at TTL + 1 s"
    assert endpoint.calls == calls + 1, "one failed refresh is attempted"

    clock.at(TTL + 250)
    assert not _accepted(verifier, unknown), "an unknown kid is refused at TTL + 250 s"
    assert _accepted(verifier, held), "and the held kid is still accepted"

    clock.at(TTL + 301)
    assert not _accepted(verifier, held), "the held kid is refused at TTL + 301 s"

    endpoint.mode = "ok"
    clock.at(TTL + 301 + 61)  # past the failed-attempt window
    calls = endpoint.calls
    assert _accepted(verifier, held), "accepted again after one successful fetch"
    assert endpoint.calls == calls + 1
    assert _accepted(verifier, held) and endpoint.calls == calls + 1


def test_the_bound_is_exactly_ttl_plus_300(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    endpoint.mode = "fail"
    clock.at(TTL + 300)
    assert _accepted(verifier, held), "held keys verify until exactly TTL + 300 s"
    clock.at(TTL + 300.5)
    assert not _accepted(verifier, held), "and not after"


def test_an_empty_key_set_is_a_failed_refresh_not_a_replacement(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    endpoint.mode = "empty"

    clock.at(TTL + 1)
    calls = endpoint.calls
    assert _accepted(verifier, held), "the held kid is still accepted at TTL + 1 s"
    assert endpoint.calls == calls + 1, "the empty set was fetched and refused"

    clock.at(TTL + 301)
    assert not _accepted(verifier, held), "an empty set never moved the anchor"


def test_an_unknown_kid_refresh_that_fails_never_opens_or_extends_the_stale_window(
    clock: Clock,
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held, unknown = _token(key, "held"), _token(key, "unknown")
    assert _accepted(verifier, held)
    endpoint.mode = "fail"

    clock.at(100)  # inside the TTL: an unknown kid forces a refresh, which fails
    assert not _accepted(verifier, unknown)
    assert _accepted(verifier, held), "the held set stays in place for the kids it holds"
    clock.at(TTL + 300.5)
    assert not _accepted(verifier, held), "the bound still runs from the last successful fetch"


def test_failed_attempts_count_toward_the_unknown_kid_window(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    assert _accepted(verifier, _token(key, "held"))
    endpoint.mode = "fail"
    clock.at(TTL + 1)
    calls = endpoint.calls
    for index in range(50):
        assert not _accepted(verifier, _token(key, f"unknown-{index}"))
    assert endpoint.calls - calls <= 1, "a failing endpoint costs one fetch per window"


def test_a_cold_cache_with_a_failing_endpoint_refuses(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    endpoint.mode = "fail"
    verifier = _verifier(endpoint)
    assert not _accepted(verifier, _token(key, "held"))


# --- the TTL --------------------------------------------------------------------------------------


def test_a_configured_ttl_above_300_is_clamped_and_reported_once(clock: Clock) -> None:
    events: list[TelemetryEvent] = []
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = JwksVerifier(
        BASE_URL,
        jwks_url=f"{BASE_URL}/oauth2/jwks",
        lifespan=3600,
        telemetry_hook=events.append,
    )
    verifier._client.fetch_data = endpoint.fetch_data  # type: ignore[method-assign]
    clamps = [e for e in events if isinstance(e, ConfigClamped)]
    assert len(clamps) == 1
    assert clamps[0].setting == "lifespan"
    assert clamps[0].requested == "3600"
    assert clamps[0].effective == "300"
    assert "§12.4 rule 2" in clamps[0].contract_reference

    held = _token(key, "held")
    assert _accepted(verifier, held)
    clock.at(TTL + 1)
    calls = endpoint.calls
    assert _accepted(verifier, held)
    assert endpoint.calls == calls + 1, "the set was refreshed at 301 s, not 3600 s"


def test_a_smaller_configured_ttl_is_honoured_and_reports_nothing(clock: Clock) -> None:
    events: list[TelemetryEvent] = []
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = JwksVerifier(
        BASE_URL, jwks_url=f"{BASE_URL}/oauth2/jwks", lifespan=60, telemetry_hook=events.append
    )
    verifier._client.fetch_data = endpoint.fetch_data  # type: ignore[method-assign]
    assert events == []
    held = _token(key, "held")
    assert _accepted(verifier, held)
    clock.at(61)
    calls = endpoint.calls
    assert _accepted(verifier, held)
    assert endpoint.calls == calls + 1


# --- the real HTTP path: Cache-Control and the conditional request ----------------------


class _Server:
    def __init__(self, jwk: dict[str, Any]) -> None:
        import json

        outer = self
        self.body = json.dumps({"keys": [jwk]}).encode()
        self.max_age: str | None = "900"
        self.requests: list[dict[str, str | None]] = []
        self.status_override: int | None = None
        self.override_with_body = False
        self.redirect = False
        self.etag = '"v1"'

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.requests.append(
                    {"if_none_match": self.headers.get("If-None-Match"), "path": self.path}
                )
                if outer.redirect and self.path == "/oauth2/jwks":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if outer.status_override is not None:
                    self.send_response(outer.status_override)
                    self.send_header(
                        "Content-Length", str(len(outer.body) if outer.override_with_body else 0)
                    )
                    self.end_headers()
                    if outer.override_with_body:
                        self.wfile.write(outer.body)
                    return
                if self.headers.get("If-None-Match") == '"v1"':
                    self.send_response(304)
                    self.send_header("ETag", '"v1"')
                    if outer.max_age is not None:
                        self.send_header("Cache-Control", f"max-age={outer.max_age}")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("ETag", outer.etag)
                if outer.max_age is not None:
                    self.send_header("Cache-Control", f"max-age={outer.max_age}")
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args: Any) -> None:
                return None

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/oauth2/jwks"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[dict[str, Any]], _Server]]:
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    made: list[_Server] = []

    def build(jwk: dict[str, Any]) -> _Server:
        made.append(_Server(jwk))
        return made[-1]

    yield build
    for item in made:
        item.close()


def test_an_advertised_max_age_above_300_is_clamped_silently(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    events: list[TelemetryEvent] = []
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url, telemetry_hook=events.append)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    assert events == [], "clamping an advertised max-age emits nothing"
    clock.at(TTL - 1)
    assert _accepted(verifier, held) and len(srv.requests) == 1
    clock.at(TTL + 1)
    assert _accepted(verifier, held)
    assert len(srv.requests) == 2, "refreshed past 300 s although max-age=900 was advertised"


def test_a_smaller_advertised_max_age_is_honoured(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    srv.max_age = "30"
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    clock.at(31)
    assert _accepted(verifier, held)
    assert len(srv.requests) == 1, "a TTL-driven refresh waits for the 60 s window"
    clock.at(61)
    assert _accepted(verifier, held)
    assert len(srv.requests) == 2


def test_a_304_to_the_conditional_request_is_a_success_that_moves_the_anchor(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    clock.at(TTL + 1)
    assert _accepted(verifier, held)
    assert srv.requests[-1]["if_none_match"] == '"v1"', "the refresh is conditional"
    # The 304 moved the anchor to TTL + 1: the held keys outlive the first fill's bound.
    srv.status_override = 503
    clock.at(TTL + 1 + TTL + 300)
    assert _accepted(verifier, held)
    clock.at(TTL + 1 + TTL + 301)
    assert not _accepted(verifier, held)


def test_another_status_is_a_failed_refresh(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    srv.status_override = 500
    clock.at(TTL + 1)
    assert _accepted(verifier, held), "a 500 keeps the held keys"
    clock.at(TTL + 301)
    assert not _accepted(verifier, held), "and never moved the anchor"


@pytest.mark.parametrize(
    "document", [{"keys": [{}]}, {"keys": [0]}, {"keys": [None]}, {"keys": []}]
)
def test_a_document_with_no_jwk_object_is_a_failed_refresh(clock: Clock, document: Any) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    endpoint.fetch_data = lambda: document  # type: ignore[method-assign]
    verifier._client.fetch_data = endpoint.fetch_data  # type: ignore[method-assign]
    clock.at(TTL + 1)
    assert _accepted(verifier, held)
    clock.at(TTL + 301)
    assert not _accepted(verifier, held), "the anchor never moved"


def test_twenty_tokens_on_a_cold_cache_with_a_failing_endpoint_cost_one_fetch(
    clock: Clock,
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    endpoint.mode = "fail"
    verifier = _verifier(endpoint)
    for _ in range(20):
        assert not _accepted(verifier, _token(key, "held"))
    assert endpoint.calls == 1


def test_a_clock_moving_backwards_is_refresh_due_never_fresh(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held = _token(key, "held")
    clock.at(100)
    assert _accepted(verifier, held)
    calls = endpoint.calls
    clock.at(50)
    assert _accepted(verifier, held)
    assert endpoint.calls == calls + 1


def test_only_a_200_is_a_successful_fetch_and_a_hostile_etag_is_not_stored(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    srv.status_override = 204
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url)
    assert not _accepted(verifier, _token(key, "held")), "a 204 is not a JWKS fetch"

    from axiam_sdk._jwks import _JwksFetcher

    fetcher = _JwksFetcher(srv.url)
    srv.status_override = None
    srv.etag = "x" * 300
    fetcher.fetch_data()
    assert fetcher.response_etag is None, "an ETag over 256 bytes is never stored"
    srv.etag = '"v1"'
    fetcher.fetch_data()
    assert fetcher.response_etag == '"v1"'


def test_an_unusable_but_well_formed_jwk_counts_and_is_skipped(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    rsa_only = {"keys": [{"kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB"}, {}]}
    verifier._client.fetch_data = lambda: rsa_only  # type: ignore[method-assign]
    clock.at(TTL + 1)
    assert _accepted(verifier, held)  # answered at once; the refresh runs behind it
    assert not _accepted(verifier, held), "a set of well-formed JWKs is a success: it replaces"


# --- review round 1 -------------------------------------------------------------------------------


def test_negative_age_with_a_failed_refresh_refuses_the_held_keys(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held = _token(key, "held")
    clock.at(100)
    assert _accepted(verifier, held)
    endpoint.mode = "fail"
    clock.at(50)
    assert not _accepted(verifier, held), "a clock step back never extends the held keys' life"


def test_keys_as_an_object_is_a_failed_refresh(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = _verifier(endpoint)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    verifier._client.fetch_data = lambda: {"keys": {"kty": "OKP"}}  # type: ignore[method-assign]
    clock.at(TTL + 1)
    assert _accepted(verifier, held), "the held kid is still accepted: the object replaced nothing"
    clock.at(TTL + 2)
    assert _accepted(verifier, held), "and still is after that refresh settled"
    clock.at(TTL + 301)
    assert not _accepted(verifier, held), "and the anchor never moved"


def test_a_203_with_keys_is_a_failed_refresh(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    srv.status_override = 203
    srv.override_with_body = True
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url)
    assert not _accepted(verifier, _token(key, "held"))


def test_a_304_re_reads_its_max_age_and_without_one_keeps_the_previous_ttl(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    srv.max_age = "30"
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url)
    held = _token(key, "held")
    assert _accepted(verifier, held)  # TTL 30
    srv.max_age = "200"
    clock.at(61)
    assert _accepted(verifier, held)  # 304 carrying max-age=200
    assert len(srv.requests) == 2
    clock.at(61 + 150)
    assert _accepted(verifier, held)
    assert len(srv.requests) == 2, "the 304's max-age=200 is the TTL now"

    srv.max_age = None
    clock.at(61 + 201)
    assert _accepted(verifier, held)  # 304 without max-age
    assert len(srv.requests) == 3
    clock.at(61 + 201 + 150)
    assert _accepted(verifier, held)
    assert len(srv.requests) == 3, "age 150 < the kept TTL of 200"
    clock.at(61 + 201 + 201)
    assert _accepted(verifier, held)
    assert len(srv.requests) == 4, "the previous TTL (200) is kept, not reset to 300"


def test_max_age_zero_costs_one_fetch_per_window_not_one_per_verification(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    srv.max_age = "0"
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url)
    held = _token(key, "held")
    for _ in range(100):
        assert _accepted(verifier, held)
    assert len(srv.requests) == 1
    clock.at(61)
    for _ in range(100):
        assert _accepted(verifier, held)
    assert len(srv.requests) == 2, "at most one TTL-driven fetch per 60 s window"


def test_a_hanging_endpoint_does_not_block_a_verification_with_a_usable_held_set() -> None:
    import time as real_time

    key, jwk = make_ed25519_keypair_and_jwk("held")
    gate = threading.Event()
    started = threading.Event()

    class Hanging(Endpoint):
        def fetch_data(self) -> dict[str, Any]:
            self.calls += 1
            if self.calls > 1:
                started.set()
                gate.wait(10)
                raise PyJWKClientConnectionError("down")
            return {"keys": self.jwks}

    endpoint = Hanging([jwk])
    verifier = _verifier(endpoint)
    held = _token(key, "held")
    assert _accepted(verifier, held)
    verifier._anchor -= TTL + 1  # the TTL has passed: a refresh is due
    verifier._last_ttl_attempt = None  # and the fill is outside the window
    begun = real_time.perf_counter()
    verifier.get_signing_key(held)
    verifier.get_signing_key(_token(key, "held"))
    assert real_time.perf_counter() - begun < 2.0, "held-kid verification never waits for a fetch"
    assert started.wait(5), "the refresh is in flight"
    assert endpoint.calls == 2
    gate.set()
    _settle(verifier)


def test_concurrent_callers_on_a_cold_cache_cause_one_fetch() -> None:
    import time as real_time

    key, jwk = make_ed25519_keypair_and_jwk("held")

    class Slow(Endpoint):
        def fetch_data(self) -> dict[str, Any]:
            self.calls += 1
            real_time.sleep(0.2)
            return {"keys": self.jwks}

    endpoint = Slow([jwk])
    verifier = _verifier(endpoint)
    token = _token(key, "held")
    barrier = threading.Barrier(8)
    results: list[bool] = []

    def worker() -> None:
        barrier.wait()
        try:
            verifier.get_signing_key(token)
            results.append(True)
        except jwt.PyJWTError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [True] * 8 and endpoint.calls == 1


def test_a_3xx_is_refused_not_followed(
    clock: Clock, server: Callable[[dict[str, Any]], _Server]
) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    srv = server(jwk)
    srv.redirect = True
    verifier = JwksVerifier(BASE_URL, jwks_url=srv.url)
    assert not _accepted(verifier, _token(key, "held"))
    assert [r["path"] for r in srv.requests] == ["/oauth2/jwks"], "the Location was not fetched"


@pytest.mark.parametrize("second", ["forced", "failed"])
def test_a_forced_or_failed_attempt_also_closes_the_ttl_window(clock: Clock, second: str) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = JwksVerifier(BASE_URL, jwks_url=f"{BASE_URL}/oauth2/jwks", lifespan=30)
    verifier._client.fetch_data = endpoint.fetch_data  # type: ignore[method-assign]
    held = _token(key, "held")
    assert _accepted(verifier, held)  # t0: filled, TTL 30
    if second == "forced":
        clock.at(20)  # inside the TTL: an unknown kid forces a refresh, which succeeds
        assert not _accepted(verifier, _token(key, "unknown"))
        due, free = 50, 85  # due again at 50; the window opened at 20 closes at 80
    else:
        endpoint.mode = "fail"
        clock.at(30)  # due: the TTL-driven refresh fails
        assert _accepted(verifier, held)
        due, free = 50, 95  # the failure at 30 closes the window at 90
    calls = endpoint.calls
    clock.at(due)
    assert _accepted(verifier, held)
    assert endpoint.calls == calls, "no TTL-driven fetch inside the 60 s window"
    clock.at(free)
    assert _accepted(verifier, held)
    assert endpoint.calls == calls + 1, "and one once the window has passed"


class _Drip:
    """A server that sends a valid JWKS head and then drips one byte per ``interval`` seconds."""

    def __init__(self, interval: float, size: int) -> None:
        outer = self
        self.size = size
        self.interval = interval
        self.closed = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(outer.size))
                self.end_headers()
                try:
                    for _ in range(min(outer.size, 200)):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(outer.interval)
                except OSError:
                    pass
                outer.closed.set()

            def log_message(self, *args: Any) -> None:
                return None

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/oauth2/jwks"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def test_a_dripping_endpoint_is_cut_off_at_the_overall_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import axiam_sdk._jwks as jwks_module
    from axiam_sdk._jwks import _JwksFetcher

    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setattr(jwks_module, "_JWKS_FETCH_DEADLINE_SECONDS", 1.0)
    drip = _Drip(interval=0.3, size=100)
    try:
        fetcher = _JwksFetcher(drip.url)
        begun = time.perf_counter()
        with pytest.raises(PyJWKClientConnectionError):
            fetcher.fetch_data()
        assert time.perf_counter() - begun < 3.0, "the fetch ended at the deadline, not at the drip"
    finally:
        drip.close()


class _Big:
    """A server for the size cap: ``valid`` sends real JSON (a JWK padded with a long member) of
    ``size`` bytes without a ``Content-Length``; ``declared`` announces ``size`` bytes up front and
    streams until the client goes away, recording how much it wrote."""

    def __init__(self, mode: str, size: int, jwk: dict[str, Any]) -> None:
        import json as _json

        outer = self
        self.written = 0
        padded = dict(jwk, pad="x" * size)
        document = _json.dumps({"keys": [padded]}).encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if mode == "declared":
                    self.send_header("Content-Length", str(50 * 1024 * 1024))
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    if mode == "valid":
                        self.wfile.write(document)
                        outer.written = len(document)
                    else:
                        while outer.written < 50 * 1024 * 1024:
                            self.wfile.write(b" " * 65536)
                            outer.written += 65536
                except OSError:
                    pass
                self.close_connection = True

            def log_message(self, *args: Any) -> None:
                return None

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/oauth2/jwks"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")


def test_valid_json_over_the_size_cap_is_refused(no_proxy: None) -> None:
    from axiam_sdk._jwks import _JwksFetcher

    _key, jwk = make_ed25519_keypair_and_jwk("held")
    big = _Big("valid", 1024 * 1024 + 4096, jwk)
    try:
        with pytest.raises(PyJWKClientConnectionError):
            _JwksFetcher(big.url).fetch_data()
    finally:
        big.close()


def test_a_declared_length_over_the_cap_is_refused_before_the_body_is_read(
    no_proxy: None,
) -> None:
    from axiam_sdk._jwks import _JwksFetcher

    _key, jwk = make_ed25519_keypair_and_jwk("held")
    big = _Big("declared", 0, jwk)
    try:
        with pytest.raises(PyJWKClientConnectionError):
            _JwksFetcher(big.url).fetch_data()
        time.sleep(0.3)
        assert big.written < 8 * 1024 * 1024, "the client stopped long before 50 MiB"
    finally:
        big.close()


def test_a_forced_refresh_closes_the_ttl_window_even_past_the_ttl(clock: Clock) -> None:
    key, jwk = make_ed25519_keypair_and_jwk("held")
    endpoint = Endpoint([jwk])
    verifier = JwksVerifier(BASE_URL, jwks_url=f"{BASE_URL}/oauth2/jwks", lifespan=30)
    verifier._client.fetch_data = endpoint.fetch_data  # type: ignore[method-assign]
    held = _token(key, "held")
    assert _accepted(verifier, held)  # t0: filled, TTL 30
    endpoint.mode = "fail"
    clock.at(25)  # inside the TTL: an unknown kid forces a refresh, which fails
    assert not _accepted(verifier, _token(key, "unknown"))
    calls = endpoint.calls
    clock.at(65)  # due (65 >= 30); the fill's own window has passed; the forced attempt's has not
    assert _accepted(verifier, held)
    assert endpoint.calls == calls, "the forced attempt at 25 closes the TTL window until 85"
    clock.at(86)
    assert _accepted(verifier, held)
    assert endpoint.calls == calls + 1


def test_a_header_dripping_endpoint_is_abandoned_at_the_deadline(
    no_proxy: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket

    import axiam_sdk._jwks as jwks_module

    monkeypatch.setattr(jwks_module, "_JWKS_FETCH_DEADLINE_SECONDS", 1.0)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=drip, args=(conn,), daemon=True).start()

    def drip(conn: socket.socket) -> None:
        try:
            conn.recv(4096)
            for byte in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 200:
                if stop.is_set():
                    return
                conn.sendall(bytes([byte]))
                time.sleep(0.25)
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{listener.getsockname()[1]}/oauth2/jwks"
        verifier = JwksVerifier(BASE_URL, jwks_url=url)
        key, _jwk = make_ed25519_keypair_and_jwk("held")
        begun = time.perf_counter()
        assert not _accepted(verifier, _token(key, "held"))
        assert time.perf_counter() - begun < 4.0, "abandoned near the 1 s deadline"
        assert verifier._inflight is None, "the refresh finished and cleared its in-flight mark"
    finally:
        stop.set()
        listener.close()


# --- the https path (real endpoints are https) and the CONNECT-tunnel path ----------------------


def _self_signed(hostname: str) -> tuple[bytes, bytes]:
    """A self-signed certificate (PEM) and key (PEM) valid for ``hostname`` only."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.UTC)
    names: list[x509.GeneralName] = [x509.DNSName(hostname)]
    if hostname == "localhost":
        names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class _TlsServer:
    """A TLS JWKS server; ``drip`` makes it send header bytes slowly instead of answering."""

    def __init__(
        self, tmp_path: Any, hostname: str, jwk: dict[str, Any], drip: bool = False
    ) -> None:
        import json as _json
        import socket
        import ssl

        self.cert_pem, key_pem = _self_signed(hostname)
        cert_file, key_file = tmp_path / "c.pem", tmp_path / "k.pem"
        cert_file.write_bytes(self.cert_pem)
        key_file.write_bytes(key_pem)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_file, key_file)
        self.body = _json.dumps({"keys": [jwk]}).encode()
        self.drip = drip
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def client_context(self) -> Any:
        import ssl

        ctx = ssl.create_default_context(cadata=self.cert_pem.decode())
        return ctx  # hostname verification stays ON

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: Any) -> None:
        try:
            tls = self.context.wrap_socket(conn, server_side=True)
            tls.recv(4096)
            if self.drip:
                for byte in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 200:
                    if self.stop.is_set():
                        return
                    tls.sendall(bytes([byte]))
                    time.sleep(0.25)
            else:
                head = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                    + b"Content-Length: %d\r\n\r\n" % len(self.body)
                )
                tls.sendall(head + self.body)
            tls.close()
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.stop.set()
        self.listener.close()


@pytest.fixture
def tls(no_proxy: None, tmp_path: Any) -> Iterator[Callable[..., _TlsServer]]:
    made: list[_TlsServer] = []

    def build(hostname: str, jwk: dict[str, Any], drip: bool = False) -> _TlsServer:
        made.append(_TlsServer(tmp_path, hostname, jwk, drip))
        return made[-1]

    yield build
    for item in made:
        item.close()


def test_https_fetch_succeeds_with_hostname_verification_on(
    tls: Callable[..., _TlsServer],
) -> None:
    from axiam_sdk._jwks import _JwksFetcher

    _key, jwk = make_ed25519_keypair_and_jwk("held")
    server = tls("localhost", jwk)
    fetcher = _JwksFetcher(f"https://localhost:{server.port}/oauth2/jwks")
    fetcher.ssl_context = server.client_context()
    assert fetcher.fetch_data()["keys"][0]["kid"] == "held"


def test_https_certificate_for_the_wrong_hostname_is_refused(
    tls: Callable[..., _TlsServer],
) -> None:
    from axiam_sdk._jwks import _JwksFetcher

    _key, jwk = make_ed25519_keypair_and_jwk("held")
    server = tls("other.test", jwk)
    fetcher = _JwksFetcher(f"https://localhost:{server.port}/oauth2/jwks")
    fetcher.ssl_context = server.client_context()
    with pytest.raises(PyJWKClientConnectionError):
        fetcher.fetch_data()


def test_https_header_drip_is_abandoned_at_the_deadline(
    tls: Callable[..., _TlsServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    import axiam_sdk._jwks as jwks_module
    from axiam_sdk._jwks import _JwksFetcher

    monkeypatch.setattr(jwks_module, "_JWKS_FETCH_DEADLINE_SECONDS", 1.0)
    _key, jwk = make_ed25519_keypair_and_jwk("held")
    server = tls("localhost", jwk, drip=True)
    fetcher = _JwksFetcher(f"https://localhost:{server.port}/oauth2/jwks")
    fetcher.ssl_context = server.client_context()
    begun = time.perf_counter()
    with pytest.raises(PyJWKClientConnectionError):
        fetcher.fetch_data()
    assert time.perf_counter() - begun < 4.0


def test_https_through_a_connect_proxy_still_works(
    tls: Callable[..., _TlsServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket

    from axiam_sdk._jwks import _JwksFetcher

    _key, jwk = make_ed25519_keypair_and_jwk("held")
    server = tls("localhost", jwk)
    seen: list[str] = []
    proxy = socket.socket()
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(4)

    def pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (src, dst):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(conn: socket.socket) -> None:
        request = b""
        while b"\r\n\r\n" not in request:
            request += conn.recv(4096)
        line = request.split(b"\r\n", 1)[0].decode()
        seen.append(line)
        host, _, port = line.split()[1].partition(":")
        upstream = socket.create_connection((host, int(port)))
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        threading.Thread(target=pipe, args=(upstream, conn), daemon=True).start()
        pipe(conn, upstream)

    def accept() -> None:
        while True:
            try:
                conn, _ = proxy.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv("https_proxy", f"http://127.0.0.1:{proxy.getsockname()[1]}")
    try:
        fetcher = _JwksFetcher(f"https://localhost:{server.port}/oauth2/jwks")
        fetcher.ssl_context = server.client_context()
        assert fetcher.fetch_data()["keys"][0]["kid"] == "held"
        assert seen and seen[0].startswith(f"CONNECT localhost:{server.port} "), seen
    finally:
        proxy.close()
