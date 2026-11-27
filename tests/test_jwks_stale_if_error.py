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


def test_a_body_over_the_size_cap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from axiam_sdk._jwks import _JwksFetcher

    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    drip = _Drip(interval=0.0, size=2 * 1024 * 1024)
    try:
        with pytest.raises(PyJWKClientConnectionError):
            _JwksFetcher(drip.url).fetch_data()
    finally:
        drip.close()
