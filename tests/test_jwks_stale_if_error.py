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
    return True


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
        self.etag = '"v1"'

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.requests.append({"if_none_match": self.headers.get("If-None-Match")})
                if outer.status_override is not None:
                    self.send_response(outer.status_override)
                    self.end_headers()
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
    assert not _accepted(verifier, held), "a set of well-formed JWKs is a success: it replaces"
