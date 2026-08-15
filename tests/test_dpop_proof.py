"""CONTRACT.md §21.7.2 — DPoP proof verification, all ten checks.

Each check gets a negative test, because §21.7.2's whole premise is that a
verifier missing one of them still reports success. A test that only proves a
good proof passes would not distinguish this module from ``return True``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as gen_rsa

from axiam_sdk._dpop import (
    DPOP_IAT_LEEWAY_SECONDS,
    InMemoryJtiStore,
    access_token_hash,
    canonical_htu,
    jwk_thumbprint_s256,
    verify_dpop_proof,
)
from axiam_sdk._errors import AuthError

_METHOD = "POST"
_URI = "https://rs.example.com/v1/things"
_TOKEN = "eyJhbGciOiJFZERTQSJ9.e30.sig"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _ed25519_jwk() -> tuple[Any, dict[str, str]]:
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes_raw()
    return key, {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw)}


def _make_proof(
    signing_key: Any,
    jwk: dict[str, Any],
    *,
    alg: str = "EdDSA",
    typ: str = "dpop+jwt",
    claims: dict[str, Any] | None = None,
    header_extra: dict[str, Any] | None = None,
) -> str:
    body = {
        "htm": _METHOD,
        "htu": _URI,
        "iat": int(time.time()),
        "jti": _b64u(hashlib.sha256(str(time.time_ns()).encode()).digest())[:16],
        "ath": access_token_hash(_TOKEN),
    }
    if claims:
        body.update(claims)
        for k, v in list(claims.items()):
            if v is None:
                body.pop(k, None)
    header = {"typ": typ, "jwk": jwk}
    if header_extra:
        header.update(header_extra)
    return jwt.encode(body, signing_key, algorithm=alg, headers=header)


@pytest.fixture()
def store() -> InMemoryJtiStore:
    return InMemoryJtiStore()


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_well_formed_proof_verifies_and_returns_its_thumbprint(store: InMemoryJtiStore) -> None:
    key, jwk = _ed25519_jwk()
    jkt = verify_dpop_proof(
        _make_proof(key, jwk),
        http_method=_METHOD,
        http_uri=_URI,
        access_token=_TOKEN,
        jti_store=store,
    )
    # Returning the thumbprint rather than True is what lets a guard pass a
    # value onward that could only have come from a verified proof.
    assert jkt == jwk_thumbprint_s256(jwk)
    assert len(jkt) == 43


def test_the_query_string_is_stripped_from_both_sides_of_htu(store: InMemoryJtiStore) -> None:
    key, jwk = _ed25519_jwk()
    proof = _make_proof(key, jwk, claims={"htu": _URI})
    verify_dpop_proof(
        proof,
        http_method=_METHOD,
        http_uri=f"{_URI}?page=2#frag",
        access_token=_TOKEN,
        jti_store=store,
    )


def test_all_three_permitted_algorithms_verify(store: InMemoryJtiStore) -> None:
    ec = generate_private_key(SECP256R1())
    nums = ec.public_key().public_numbers()
    ec_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }
    verify_dpop_proof(
        _make_proof(ec, ec_jwk, alg="ES256"),
        http_method=_METHOD,
        http_uri=_URI,
        access_token=_TOKEN,
        jti_store=store,
    )

    rsa = gen_rsa(public_exponent=65537, key_size=2048)
    rnums = rsa.public_key().public_numbers()
    rsa_jwk = {
        "kty": "RSA",
        "n": _b64u(rnums.n.to_bytes((rnums.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(rnums.e.to_bytes((rnums.e.bit_length() + 7) // 8, "big")),
    }
    verify_dpop_proof(
        _make_proof(rsa, rsa_jwk, alg="PS256"),
        http_method=_METHOD,
        http_uri=_URI,
        access_token=_TOKEN,
        jti_store=store,
    )


# ---------------------------------------------------------------------------
# One negative test per check
# ---------------------------------------------------------------------------


def test_check1_a_proof_without_the_dpop_typ_is_refused(store: InMemoryJtiStore) -> None:
    """Without pinning typ, any other JWT signed by the same key — an access
    token, an ID token — is replayable as a proof.
    """
    key, jwk = _ed25519_jwk()
    with pytest.raises(AuthError, match="typ"):
        verify_dpop_proof(
            _make_proof(key, jwk, typ="JWT"),
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_check1_the_typ_comparison_is_case_insensitive(store: InMemoryJtiStore) -> None:
    key, jwk = _ed25519_jwk()
    verify_dpop_proof(
        _make_proof(key, jwk, typ="DPoP+JWT"),
        http_method=_METHOD,
        http_uri=_URI,
        access_token=_TOKEN,
        jti_store=store,
    )


def test_check2_the_header_alg_is_never_believed(store: InMemoryJtiStore) -> None:
    """The public-key-as-HMAC-secret attack, run for real.

    The attacker holds no private key. They take the *public* key out of a
    proof they observed, use its raw bytes as an HMAC secret, sign a proof of
    their own with ``HS256``, and embed the same public ``jwk``. A verifier
    that reads ``alg`` from the header computes HMAC with that public key,
    gets a match, and reports success — the signature is valid, just not
    proof of anything.

    This module derives ``EdDSA`` from ``kty: OKP`` and never tries HMAC at
    all, so the forgery has nothing to verify against.
    """
    _, jwk = _ed25519_jwk()
    public_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")

    forged = jwt.encode(
        {
            "htm": _METHOD,
            "htu": _URI,
            "iat": int(time.time()),
            "jti": "forged-jti",
            "ath": access_token_hash(_TOKEN),
        },
        public_bytes,
        algorithm="HS256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
    # The forgery is internally consistent — HMAC with the embedded key does
    # verify. Proving that first is what makes the rejection below meaningful.
    assert jwt.decode(forged, public_bytes, algorithms=["HS256"])["jti"] == "forged-jti"

    with pytest.raises(AuthError):
        verify_dpop_proof(
            forged,
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_check2_an_unpermitted_key_type_is_refused(store: InMemoryJtiStore) -> None:
    key, jwk = _ed25519_jwk()
    p521 = {"kty": "EC", "crv": "P-521", "x": "AA", "y": "AA"}
    proof = _make_proof(key, jwk)
    tampered = ".".join(
        [
            _b64u(json.dumps({"typ": "dpop+jwt", "jwk": p521}).encode()),
            proof.split(".")[1],
            proof.split(".")[2],
        ]
    )
    with pytest.raises(AuthError, match="not permitted"):
        verify_dpop_proof(
            tampered,
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_check3_a_proof_with_no_jwk_or_a_bad_signature_is_refused(
    store: InMemoryJtiStore,
) -> None:
    key, jwk = _ed25519_jwk()
    proof = _make_proof(key, jwk)

    no_jwk = ".".join(
        [
            _b64u(json.dumps({"typ": "dpop+jwt"}).encode()),
            proof.split(".")[1],
            proof.split(".")[2],
        ]
    )
    with pytest.raises(AuthError, match="public 'jwk'"):
        verify_dpop_proof(
            no_jwk,
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )

    # A proof signed by a DIFFERENT key than the one it embeds.
    other_key, _ = _ed25519_jwk()
    forged = _make_proof(other_key, jwk)
    with pytest.raises(AuthError, match="signature or claims"):
        verify_dpop_proof(
            forged,
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_check4_private_key_material_in_the_jwk_is_refused(store: InMemoryJtiStore) -> None:
    """RFC 9449 §4.3. Checked against the RAW header JSON, because many JWK
    libraries silently drop these members when parsing into a public-key type
    — the check would then pass because the library hid the evidence.
    """
    key, jwk = _ed25519_jwk()
    for member in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"):
        leaky = {**jwk, member: "c2VjcmV0"}
        proof = _make_proof(key, jwk)
        tampered = ".".join(
            [
                _b64u(json.dumps({"typ": "dpop+jwt", "jwk": leaky}).encode()),
                proof.split(".")[1],
                proof.split(".")[2],
            ]
        )
        with pytest.raises(AuthError, match="private key material"):
            verify_dpop_proof(
                tampered,
                http_method=_METHOD,
                http_uri=_URI,
                access_token=_TOKEN,
                jti_store=store,
            )


def test_check5_a_proof_minted_for_another_method_is_refused(store: InMemoryJtiStore) -> None:
    key, jwk = _ed25519_jwk()
    with pytest.raises(AuthError, match="htm"):
        verify_dpop_proof(
            _make_proof(key, jwk, claims={"htm": "GET"}),
            http_method="POST",
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_check6_a_proof_minted_for_another_uri_is_refused(store: InMemoryJtiStore) -> None:
    key, jwk = _ed25519_jwk()
    with pytest.raises(AuthError, match="htu"):
        verify_dpop_proof(
            _make_proof(key, jwk, claims={"htu": "https://rs.example.com/v1/other"}),
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_check6_htu_is_compared_without_normalisation() -> None:
    """A normalising comparison is where two unequal URIs become equal. Only
    query and fragment come off; case, default ports and trailing slashes are
    left exactly as they are.
    """
    assert canonical_htu("https://a.example/p?q=1#f") == "https://a.example/p"
    assert canonical_htu("https://A.example/P") != canonical_htu("https://a.example/p")
    assert canonical_htu("https://a.example:443/p") != canonical_htu("https://a.example/p")
    assert canonical_htu("https://a.example/p/") != canonical_htu("https://a.example/p")


def test_check7_a_stale_or_future_proof_is_refused(store: InMemoryJtiStore) -> None:
    """Both directions. A proof from the future is as suspect as a stale one:
    it is how a one-sided skew allowance becomes a long-lived proof.
    """
    key, jwk = _ed25519_jwk()
    now = time.time()

    stale = _make_proof(key, jwk, claims={"iat": int(now - DPOP_IAT_LEEWAY_SECONDS - 5)})
    with pytest.raises(AuthError, match="freshness window"):
        verify_dpop_proof(
            stale,
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
            now=now,
        )

    future = _make_proof(key, jwk, claims={"iat": int(now + DPOP_IAT_LEEWAY_SECONDS + 5)})
    with pytest.raises(AuthError, match="freshness window"):
        verify_dpop_proof(
            future,
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
            now=now,
        )


def test_check8_a_replayed_proof_is_refused(store: InMemoryJtiStore) -> None:
    """Freshness bounds the window; the jti guard is what makes the window
    unusable. Without this the same proof works repeatedly for a full minute.
    """
    key, jwk = _ed25519_jwk()
    proof = _make_proof(key, jwk)
    kwargs: dict[str, Any] = {
        "http_method": _METHOD,
        "http_uri": _URI,
        "access_token": _TOKEN,
        "jti_store": store,
    }
    verify_dpop_proof(proof, **kwargs)
    with pytest.raises(AuthError, match="replay"):
        verify_dpop_proof(proof, **kwargs)


def test_check8_the_jti_is_only_claimed_after_the_other_checks_pass(
    store: InMemoryJtiStore,
) -> None:
    """The jti claim is a mutation, so it runs last. Claiming it earlier would
    let an attacker burn arbitrary jti values out of the store using proofs
    that were never going to verify — turning the replay guard into a
    denial-of-service surface against legitimate proofs.
    """
    key, jwk = _ed25519_jwk()
    doomed = _make_proof(key, jwk, claims={"htm": "GET"})
    jti = jwt.decode(doomed, options={"verify_signature": False})["jti"]

    with pytest.raises(AuthError, match="htm"):
        verify_dpop_proof(
            doomed,
            http_method="POST",
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )

    # That jti is still unused, so a genuine proof carrying it still works.
    assert store.claim(jti, time.time() + 60) is True


def test_check9_a_proof_aimed_at_another_token_is_refused(store: InMemoryJtiStore) -> None:
    """Without ath, a proof captured on one request can be re-aimed at a
    different token held by the same key.
    """
    key, jwk = _ed25519_jwk()
    with pytest.raises(AuthError, match="ath"):
        verify_dpop_proof(
            _make_proof(key, jwk, claims={"ath": access_token_hash("some.other.token")}),
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_check9_a_proof_with_no_ath_at_all_is_refused(store: InMemoryJtiStore) -> None:
    key, jwk = _ed25519_jwk()
    with pytest.raises(AuthError):
        verify_dpop_proof(
            _make_proof(key, jwk, claims={"ath": None}),
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_check10_a_proof_by_the_wrong_key_is_refused(store: InMemoryJtiStore) -> None:
    """This is the step that ties the proof to the token; the other nine are
    what make the proof mean anything.
    """
    key, jwk = _ed25519_jwk()
    _, other_jwk = _ed25519_jwk()
    with pytest.raises(AuthError, match="cnf.jkt"):
        verify_dpop_proof(
            _make_proof(key, jwk),
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
            expected_jkt=jwk_thumbprint_s256(other_jwk),
        )


# ---------------------------------------------------------------------------
# Thumbprint and framing
# ---------------------------------------------------------------------------


def test_the_thumbprint_matches_rfc7638_appendix_a() -> None:
    """The RFC's own worked example. A thumbprint implementation that is
    self-consistent but wrong agrees with itself on every round trip, so the
    only useful test is against a published vector.
    """
    rfc_key = {
        "kty": "RSA",
        "n": (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
            "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
            "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
            "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
            "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
            "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        ),
        "e": "AQAB",
    }
    assert jwk_thumbprint_s256(rfc_key) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_thumbprint_ignores_members_outside_the_rfc7638_set() -> None:
    """kid/use/alg/x5c are excluded by the spec — which is exactly what makes
    the thumbprint stable across two different encodings of the same key.
    """
    _, jwk = _ed25519_jwk()
    decorated = {**jwk, "kid": "abc", "use": "sig", "alg": "EdDSA", "x5c": ["zz"]}
    assert jwk_thumbprint_s256(decorated) == jwk_thumbprint_s256(jwk)


def test_a_header_carrying_two_proofs_is_refused(store: InMemoryJtiStore) -> None:
    """RFC 9449 §4.2 makes exactly one the rule. Rejecting beats picking the
    first, which is how a verifier and a downstream parser end up reading
    different proofs.
    """
    key, jwk = _ed25519_jwk()
    proof = _make_proof(key, jwk)
    with pytest.raises(AuthError, match="exactly one proof"):
        verify_dpop_proof(
            f"{proof},{proof}",
            http_method=_METHOD,
            http_uri=_URI,
            access_token=_TOKEN,
            jti_store=store,
        )


def test_a_malformed_proof_is_refused_without_raising_something_else(
    store: InMemoryJtiStore,
) -> None:
    for junk in ("", "not-a-jwt", "a.b", "a.b.c.d", "!!!.###.$$$"):
        with pytest.raises(AuthError):
            verify_dpop_proof(
                junk,
                http_method=_METHOD,
                http_uri=_URI,
                access_token=_TOKEN,
                jti_store=store,
            )
