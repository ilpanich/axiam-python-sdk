"""ID-token validation tests (CONTRACT.md §12.4) — one test per failure
mode, using the contract's exact reason codes, plus the happy path.

Mirrors ``test_jwks.py``'s mock-JWKS pattern: a real Ed25519 keypair, a fake
``fetch_data`` bound onto the verifier's internal ``PyJWKClient`` (which
fetches via ``urllib.request``, not ``httpx``) so no real network fetch is
ever attempted.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from axiam_sdk import AuthError
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk._oidc_idtoken import (
    check_id_token_claims,
    validate_id_token,
)

ISSUER = "https://axiam.example.test"
CLIENT_ID = "rp-client-1"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_ed25519_keypair_and_jwk(kid: str) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk_dict = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw_public),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }
    return private_key, jwk_dict


def _sign(private_key: Ed25519PrivateKey, kid: str | None, claims: dict[str, Any]) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(claims, pem, algorithm="EdDSA", headers=headers)


class _FakeJwksEndpoint:
    """See ``test_jwks.py``'s docstring for why this mock seam is correct."""

    def __init__(self, jwk_dicts: list[dict[str, Any]]) -> None:
        self.jwk_dicts = jwk_dicts
        self.call_count = 0
        self._client: Any = None

    def bind(self, verifier: JwksVerifier) -> None:
        self._client = verifier._client
        verifier._client.fetch_data = self._fetch_data  # type: ignore[method-assign]

    def _fetch_data(self) -> dict[str, Any]:
        self.call_count += 1
        data = {"keys": self.jwk_dicts}
        if self._client is not None and self._client.jwk_set_cache is not None:
            self._client.jwk_set_cache.put(data)
        return data


def _make_verifier(jwk_dicts: list[dict[str, Any]]) -> tuple[JwksVerifier, _FakeJwksEndpoint]:
    verifier = JwksVerifier("https://axiam.example.test")
    endpoint = _FakeJwksEndpoint(jwk_dicts)
    endpoint.bind(verifier)
    return verifier, endpoint


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    return _make_ed25519_keypair_and_jwk("id-token-kid-1")


def _base_claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "user-1",
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "nonce": "expected-nonce",
    }
    claims.update(overrides)
    return claims


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_valid_id_token_validates_successfully(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims())

    claims = validate_id_token(
        token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
    )

    assert claims.iss == ISSUER
    assert claims.sub == "user-1"
    assert claims.aud == CLIENT_ID
    assert claims.nonce == "expected-nonce"


def test_unknown_claims_are_preserved(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims(email="user@example.test"))

    claims = validate_id_token(
        token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
    )

    assert claims.model_extra is not None
    assert claims.model_extra["email"] == "user@example.test"


# ---------------------------------------------------------------------
# §12.4 rule 1 — invalid_alg (including alg: none)
# ---------------------------------------------------------------------


def test_invalid_alg_hs256_is_rejected(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> None:
    _private_key, jwk = keypair
    verifier, endpoint = _make_verifier([jwk])
    token = jwt.encode(_base_claims(), "some-hmac-secret-long-enough", algorithm="HS256")

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "invalid_alg"
    assert endpoint.call_count == 0, "no JWKS fetch for a rejected alg"


def test_invalid_alg_none_is_rejected(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> None:
    _private_key, jwk = keypair
    verifier, endpoint = _make_verifier([jwk])
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(_base_claims()).encode())
    none_token = f"{header}.{payload}."

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            none_token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "invalid_alg"
    assert endpoint.call_count == 0


# ---------------------------------------------------------------------
# §12.4 rule 2 — unknown_kid (including "no kid at all")
# ---------------------------------------------------------------------


def test_unknown_kid_after_one_refetch_fails(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, _jwk = keypair
    _other_private_key, stale_jwk = _make_ed25519_keypair_and_jwk("stale-kid")
    verifier, endpoint = _make_verifier([stale_jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims())

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "unknown_kid"
    assert endpoint.call_count >= 1


def test_missing_kid_header_is_unknown_kid(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, None, _base_claims())

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "unknown_kid"


# ---------------------------------------------------------------------
# §12.4 rule 2 — invalid_signature
# ---------------------------------------------------------------------


def test_invalid_signature_is_rejected(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> None:
    _private_key, jwk = keypair
    forged_key, _forged_jwk = _make_ed25519_keypair_and_jwk("id-token-kid-1")
    verifier, _endpoint = _make_verifier([jwk])
    forged_token = _sign(forged_key, "id-token-kid-1", _base_claims())

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            forged_token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "invalid_signature"


# ---------------------------------------------------------------------
# §12.4 rule 3 — invalid_issuer
# ---------------------------------------------------------------------


def test_invalid_issuer_is_rejected(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims(iss="https://not-axiam.test"))

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "invalid_issuer"


# ---------------------------------------------------------------------
# §12.4 rule 4 — invalid_audience
# ---------------------------------------------------------------------


def test_invalid_audience_missing_client_id_is_rejected(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims(aud="someone-else"))

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "invalid_audience"


def test_invalid_audience_multiple_without_azp_is_rejected(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims(aud=[CLIENT_ID, "other-client"]))

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "invalid_audience"


def test_valid_audience_multiple_with_matching_azp_succeeds(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(
        private_key,
        "id-token-kid-1",
        _base_claims(aud=[CLIENT_ID, "other-client"], azp=CLIENT_ID),
    )

    claims = validate_id_token(
        token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
    )
    assert claims.azp == CLIENT_ID


# ---------------------------------------------------------------------
# §12.4 rule 5 — token_expired (exp missing/past, iat future, nbf future)
# ---------------------------------------------------------------------


def test_expired_token_is_rejected(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims(exp=int(time.time()) - 3600))

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "token_expired"


def test_missing_exp_is_rejected_as_expired(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    claims = _base_claims()
    del claims["exp"]
    token = _sign(private_key, "id-token-kid-1", claims)

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "token_expired"


def test_missing_iat_is_rejected_as_expired(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    claims = _base_claims()
    del claims["iat"]
    token = _sign(private_key, "id-token-kid-1", claims)

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "token_expired"


def test_future_iat_is_rejected_as_expired(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims(iat=int(time.time()) + 3600))

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "token_expired"


def test_future_nbf_is_rejected_as_expired(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims(nbf=int(time.time()) + 3600))

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "token_expired"


def test_clock_skew_is_clamped_to_60_seconds() -> None:
    """§12.4 rule 5: skew MUST NOT be configurable above 60s."""
    from axiam_sdk._oidc_idtoken import resolve_clock_skew_sec

    assert resolve_clock_skew_sec(3600) == 60.0
    assert resolve_clock_skew_sec(-10) == 0.0
    assert resolve_clock_skew_sec(None) == 60.0


# ---------------------------------------------------------------------
# §12.4 rule 6 — nonce_mismatch
# ---------------------------------------------------------------------


def test_nonce_mismatch_is_rejected(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    token = _sign(private_key, "id-token-kid-1", _base_claims(nonce="attacker-supplied"))

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "nonce_mismatch"


def test_missing_nonce_when_required_is_rejected(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    claims = _base_claims()
    del claims["nonce"]
    token = _sign(private_key, "id-token-kid-1", claims)

    with pytest.raises(AuthError) as excinfo:
        validate_id_token(
            token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce"
        )

    assert excinfo.value.reason == "nonce_mismatch"


def test_nonce_check_is_skipped_when_no_nonce_expected(
    keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
) -> None:
    """Rule 6 is skipped for oidc_refresh / login_client_credentials
    (``nonce=None``) — OIDC Core §12.2 does not require a nonce there."""
    private_key, jwk = keypair
    verifier, _endpoint = _make_verifier([jwk])
    claims = _base_claims()
    del claims["nonce"]
    token = _sign(private_key, "id-token-kid-1", claims)

    claims_out = validate_id_token(token, verifier, issuer=ISSUER, client_id=CLIENT_ID, nonce=None)
    assert claims_out.nonce is None


# ---------------------------------------------------------------------
# check_id_token_claims — pure unit tests with an injectable clock
# ---------------------------------------------------------------------


def test_check_id_token_claims_injectable_now() -> None:
    claims = _base_claims(exp=1000, iat=900)
    result = check_id_token_claims(
        claims, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce", now=950
    )
    assert result.sub == "user-1"


def test_check_id_token_claims_rejects_when_now_past_exp() -> None:
    claims = _base_claims(exp=1000, iat=900)
    with pytest.raises(AuthError) as excinfo:
        check_id_token_claims(
            claims, issuer=ISSUER, client_id=CLIENT_ID, nonce="expected-nonce", now=2000
        )
    assert excinfo.value.reason == "token_expired"
