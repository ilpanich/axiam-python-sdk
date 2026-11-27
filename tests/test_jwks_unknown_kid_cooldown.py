"""CONTRACT.md §12.4 rule 2 / §12.7.3 rule 1 (1.69): an unknown ``kid`` costs at most one JWKS
re-fetch per cooldown window, and the cache survives it."""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from axiam_sdk._errors import AuthError
from axiam_sdk._jwks import JwksVerifier
from tests._oidc_testkit import (
    BASE_URL,
    FakeJwksEndpoint,
    make_ed25519_keypair_and_jwk,
    make_logout_token_claims,
)


def _token(key, kid: str | None, claims=None) -> str:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    headers = {"kid": kid} if kid else {"typ": "logout+jwt"}
    return jwt.encode(
        claims or {"sub": "u", "exp": int(time.time()) + 300},
        pem,
        algorithm="EdDSA",
        headers=headers,
    )


def _verifier(jwks):
    verifier = JwksVerifier(BASE_URL, jwks_url=f"{BASE_URL}/oauth2/jwks")
    endpoint = FakeJwksEndpoint(jwks)
    verifier._client.fetch_data = endpoint._fetch_data  # type: ignore[method-assign]
    endpoint._client = verifier._client
    return verifier, endpoint


def test_fifty_unknown_kids_cost_at_most_one_fetch_and_the_cache_survives() -> None:
    key, jwk = make_ed25519_keypair_and_jwk("good")
    verifier, endpoint = _verifier([jwk])
    good = _token(key, "good")
    verifier.get_signing_key(good)  # warm the cache
    warm = endpoint.call_count

    for index in range(50):
        with pytest.raises(jwt.PyJWTError):
            verifier.get_signing_key(_token(key, f"unknown-{index}"))
    assert endpoint.call_count - warm <= 1, "fifty unknown kids in one window: at most one fetch"

    after_unknown = endpoint.call_count
    for _ in range(10):
        verifier.get_signing_key(good)
    assert endpoint.call_count == after_unknown, "the cache survives: valid tokens cost no fetch"


def test_a_rotated_key_is_accepted_after_one_fetch() -> None:
    old_key, old_jwk = make_ed25519_keypair_and_jwk("old")
    new_key, new_jwk = make_ed25519_keypair_and_jwk("new")
    verifier, endpoint = _verifier([old_jwk])
    verifier.get_signing_key(_token(old_key, "old"))
    warm = endpoint.call_count

    endpoint.jwk_dicts = [old_jwk, new_jwk]
    assert verifier.get_signing_key(_token(new_key, "new")).key_id == "new"
    assert endpoint.call_count == warm + 1


def test_logout_token_unknown_kids_are_cooled_down_too() -> None:
    key, jwk = make_ed25519_keypair_and_jwk("good")
    verifier, endpoint = _verifier([jwk])
    verifier.get_signing_key(_token(key, "good"))
    warm = endpoint.call_count
    for index in range(50):
        token = _token(key, f"unknown-{index}", make_logout_token_claims())
        with pytest.raises(AuthError) as excinfo:
            verifier.verify_logout_token_signature(token)
        assert excinfo.value.reason == "unknown_kid"
    assert endpoint.call_count - warm <= 1


def test_logout_reason_codes_are_never_none() -> None:
    key, jwk = make_ed25519_keypair_and_jwk("good")
    verifier, _endpoint = _verifier([jwk])
    cases = {
        "not.a.jwt": "invalid_alg",
        _token(key, "good", {"sub": "u", "exp": int(time.time()) - 100}): "token_expired",
        _token(key, "good", {"sub": "u", "iat": int(time.time()) + 3600}): "token_expired",
        _token(key, "good", {"sub": "u", "iat": "not-a-number"}): "token_expired",
        _token(make_ed25519_keypair_and_jwk("x")[0], "good"): "invalid_signature",
    }
    for token, reason in cases.items():
        with pytest.raises(AuthError) as excinfo:
            verifier.verify_logout_token_signature(token)
        assert excinfo.value.reason == reason, token


def test_an_outage_on_a_cold_cache_costs_at_most_one_fetch_per_window() -> None:
    key, jwk = make_ed25519_keypair_and_jwk("good")
    verifier = JwksVerifier(BASE_URL, jwks_url=f"{BASE_URL}/oauth2/jwks")
    calls = 0
    up = False

    def fetch() -> dict:
        nonlocal calls
        calls += 1
        if not up:
            raise jwt.PyJWKClientConnectionError("endpoint down")
        data = {"keys": [jwk]}
        return data

    verifier._client.fetch_data = fetch  # type: ignore[method-assign]
    token = _token(key, "good")

    for _ in range(50):
        with pytest.raises(jwt.PyJWTError):
            verifier.get_signing_key(token)
    assert calls <= 1, "fifty verifications during an outage: at most one fetch per window"

    up = True
    verifier._last_attempt = None  # the window has passed
    assert verifier.get_signing_key(token).key_id == "good"
