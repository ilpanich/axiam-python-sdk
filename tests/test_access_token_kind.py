"""CONTRACT.md §10.1 rules 10-12 (contract 1.68; N14, N10, D-7): the access-token
verification path refuses every token AXIAM signs that is not an access token.

AXIAM signs the MFA challenge, the MFA setup token and the WebAuthn ceremony state with the
access-token key. They carry ``sub``, ``tenant_id``, ``iss`` and ``exp`` and no ``aud``, so a
verifier with no expected audience (the default) must refuse them on three independent
grounds, each tested here on its own:

* rule 10 -- a ``typ`` header that is not ``at+jwt``;
* rule 11 -- a ``purpose`` claim, whatever the header says;
* rule 12 -- a header with no ``kid`` (no "only key in the set" fallback).

Every token below is otherwise valid: signed by the JWKS key, for the configured tenant,
unexpired, and checked by a verifier configured with no expected audience.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from axiam_sdk._errors import AuthError
from axiam_sdk._jwks import JwksVerifier
from tests._oidc_testkit import make_ed25519_keypair_and_jwk

BASE_URL = "https://axiam.example.test"
TENANT = "acme"
NIL_UUID = "00000000-0000-0000-0000-000000000000"


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "sub": "user-1",
        "tenant_id": TENANT,
        "iss": BASE_URL,
        "exp": int(time.time()) + 300,
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    return make_ed25519_keypair_and_jwk("test-kid-1")


@pytest.fixture
def verifier(keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> JwksVerifier:
    # No expected audience, no expected issuer: the default configuration N14 is about.
    v = JwksVerifier(BASE_URL)
    v._client.fetch_data = lambda: {"keys": [keypair[1]]}  # type: ignore[method-assign]
    return v


def _mint(
    key: Ed25519PrivateKey,
    claims: dict[str, Any],
    *,
    kid: str | None = "test-kid-1",
    typ: str | None = None,
) -> str:
    headers: dict[str, Any] = {}
    if kid is not None:
        headers["kid"] = kid
    # PyJWT writes ``typ: JWT`` unless told otherwise; ``None`` removes the member.
    headers["typ"] = typ
    return jwt.encode(claims, _pem(key), algorithm="EdDSA", headers=headers or None)


# --- positives -------------------------------------------------------------------------


def test_normal_access_token_passes(keypair, verifier) -> None:
    token = _mint(keypair[0], _claims(), typ="at+jwt")
    assert verifier.verify_access_token(token, expected_tenant_id=TENANT)["sub"] == "user-1"


@pytest.mark.parametrize("typ", ["at+jwt", "AT+JWT", "application/at+jwt", None])
def test_typ_at_jwt_variants_and_absent_typ_verify(keypair, verifier, typ) -> None:
    token = _mint(keypair[0], _claims(), typ=typ)
    assert verifier.verify_access_token(token, expected_tenant_id=TENANT)["tenant_id"] == TENANT


# --- rule 10: typ ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "typ",
    ["JWT", "axiam-mfa-challenge+jwt", "axiam-webauthn-state+jwt", "logout+jwt", "secevent+jwt"],
)
def test_rule_10_foreign_typ_is_refused(keypair, verifier, typ) -> None:
    token = _mint(keypair[0], _claims(), typ=typ)
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=TENANT)


def test_rule_10_applies_on_every_access_token_entry_point(keypair, verifier) -> None:
    token = _mint(keypair[0], _claims(), typ="axiam-mfa-challenge+jwt")
    with pytest.raises(AuthError):
        verifier.verify_with_proofs(token, expected_tenant_id=TENANT)
    with pytest.raises(AuthError):
        verifier.verify_sender_constrained(
            token, expected_tenant_id=TENANT, presented_thumbprint=None
        )


# --- rule 11: purpose ------------------------------------------------------------------


@pytest.mark.parametrize("purpose", ["mfa_challenge", "mfa_setup", "", None])
def test_rule_11_purpose_claim_is_refused_whatever_typ_says(keypair, verifier, purpose) -> None:
    token = _mint(keypair[0], _claims(purpose=purpose), typ="at+jwt")
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=TENANT)


def test_rule_11_webauthn_state_shape_is_refused(keypair, verifier) -> None:
    token = _mint(
        keypair[0],
        _claims(sub=NIL_UUID, purpose="webauthn_authenticate_discoverable"),
        typ=None,
    )
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=TENANT)


# --- rule 12: kid ----------------------------------------------------------------------
# NOT REPRODUCED in this SDK (SA-21): PyJWT's PyJWKClient never falls back to "the only key
# in the set" -- a header with no kid raises PyJWKClientError, which the verifier maps to
# AuthError. These two tests pin that existing behaviour; no production code was added.


def test_rule_12_kidless_token_is_refused_against_a_one_key_jwks(keypair, verifier) -> None:
    token = _mint(keypair[0], _claims(), kid=None, typ="at+jwt")
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=TENANT)


def test_rule_12_kidless_token_is_refused_even_with_no_typ(keypair, verifier) -> None:
    token = _mint(keypair[0], _claims(), kid=None, typ=None)
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=TENANT)


# --- scope: the other token paths are NOT subject to the three rules -------------------


def test_signature_only_primitive_is_exempt(keypair, verifier) -> None:
    token = _mint(keypair[0], _claims(purpose="mfa_challenge"), typ="JWT")
    # Named ``_unchecked``: it is not a guard, and rules 10-12 do not apply to it.
    assert verifier.verify_signature_only_unchecked(token)["sub"] == "user-1"
