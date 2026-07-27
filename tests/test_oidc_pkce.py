"""PKCE + CSPRNG primitive tests (CONTRACT.md §12.1, RFC 7636)."""

from __future__ import annotations

import re

from axiam_sdk._oidc_pkce import (
    CODE_CHALLENGE_METHOD_S256,
    compute_code_challenge,
    generate_code_verifier,
    random_url_safe_token,
)

_UNRESERVED_RE = re.compile(r"^[A-Za-z0-9\-._~]+$")


def test_rfc7636_appendix_b_vector() -> None:
    """The mandatory RFC 7636 Appendix B test vector (CONTRACT.md §12.1
    rule 3): every SDK MUST include this exact vector as a unit test."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert compute_code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_code_challenge_method_is_s256_only() -> None:
    assert CODE_CHALLENGE_METHOD_S256 == "S256"


def test_random_url_safe_token_has_no_padding() -> None:
    token = random_url_safe_token()
    assert "=" not in token


def test_random_url_safe_token_default_entropy_is_at_least_128_bits() -> None:
    """§12.1 rule 1: state/nonce MUST be >= 16 bytes (128 bits); this SDK's
    default is 32 bytes, which base64url-encodes to 43 chars (no padding)."""
    token = random_url_safe_token()
    # 32 raw bytes -> 43 base64url chars (ceil(32*8/6) with no padding).
    assert len(token) == 43


def test_random_url_safe_token_is_unique_across_calls() -> None:
    tokens = {random_url_safe_token() for _ in range(200)}
    assert len(tokens) == 200


def test_generate_code_verifier_is_43_chars_from_unreserved_set() -> None:
    """RFC 7636 §4.1: 43-128 chars from ``[A-Za-z0-9-._~]``; the RECOMMENDED
    construction (32 CSPRNG bytes, base64url, unpadded) yields exactly 43."""
    verifier = generate_code_verifier()
    assert 43 <= len(verifier) <= 128
    assert _UNRESERVED_RE.match(verifier)


def test_generate_code_verifier_is_unique_across_calls() -> None:
    verifiers = {generate_code_verifier() for _ in range(200)}
    assert len(verifiers) == 200


def test_compute_code_challenge_is_deterministic() -> None:
    verifier = generate_code_verifier()
    assert compute_code_challenge(verifier) == compute_code_challenge(verifier)


def test_compute_code_challenge_has_no_padding() -> None:
    challenge = compute_code_challenge(generate_code_verifier())
    assert "=" not in challenge
