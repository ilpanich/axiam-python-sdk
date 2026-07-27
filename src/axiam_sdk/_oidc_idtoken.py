"""ID-token validation — CONTRACT.md §12.4, OIDC Core §3.1.3.7.

Rules 1-2 (algorithm allowlist, ``kid`` lookup, Ed25519 verification, single
JWKS re-fetch) reuse :class:`~axiam_sdk._jwks.JwksVerifier` — the SAME
verifier the §10 middleware already uses (§12 forbids forking it). Rules 3-6
(issuer, audience, time, nonce) are pure claim checks with no network
involvement, so both halves can be unit-tested independently — mirrors the
split between ``the TypeScript SDK's src/node/jwks.ts`` and
``src/node/oidcIdToken.ts``.

Every failure raises :class:`~axiam_sdk._errors.AuthError` carrying one of
the seven stable reason codes CONTRACT.md §12.3 rule 3 defines. Rule 7
(all-or-nothing discard) is enforced by the caller (``_oidc.py``): a
response whose ID token fails here never yields an
:class:`~axiam_sdk._models.OidcTokenSet`, so the access/refresh token from
the same response is discarded with it.
"""

from __future__ import annotations

import hmac
import time
from typing import Any

import jwt
from jwt.exceptions import PyJWTError

from axiam_sdk._errors import AuthError
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk._models import IdTokenClaims

#: Reject the JOSE header ``alg`` unless it is exactly this value (rule 1).
ID_TOKEN_ALG = "EdDSA"

#: Maximum (and default) permitted clock skew in seconds for ID-token time
#: claims. CONTRACT.md §12.4 rule 5 caps this at 60s and forbids any
#: configuration above the bound.
MAX_CLOCK_SKEW_SEC = 60.0


def id_token_auth_error(reason: str, message: str) -> AuthError:
    """Build the :class:`AuthError` for a §12.4 failure: a stable
    machine-readable ``reason`` code (:attr:`AuthError.reason`) plus a
    human-readable message that — per §12.3 rule 3 and §2's construction
    rules — never embeds the token, a claim value that could carry secret
    material, or the expected nonce."""
    return AuthError(f"id_token validation failed ({reason}): {message}", reason=reason)


def resolve_clock_skew_sec(clock_skew_sec: float | None) -> float:
    """Resolve the effective clock skew: the caller's value clamped into
    ``[0, MAX_CLOCK_SKEW_SEC]``, or the maximum when unset."""
    if clock_skew_sec is None:
        return MAX_CLOCK_SKEW_SEC
    return min(max(clock_skew_sec, 0.0), MAX_CLOCK_SKEW_SEC)


def constant_time_equals(a: str, b: str) -> bool:
    """Constant-time string equality for the ``nonce`` comparison §12.4
    rule 6 requires."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def assert_id_token_alg(alg: object) -> None:
    """§12.4 rule 1 — algorithm check, run against the JOSE **header** and
    BEFORE any signature work, so the token can never select its own
    verification algorithm. ``none`` is rejected by the same equality test
    as every other non-``EdDSA`` value; it gets no special case."""
    if alg != ID_TOKEN_ALG:
        got = f"{alg!r}" if isinstance(alg, str) else "no alg header"
        raise id_token_auth_error("invalid_alg", f'expected alg "{ID_TOKEN_ALG}", got {got}')


def verify_id_token_signature(verifier: JwksVerifier, token: str) -> dict[str, Any]:
    """§12.4 rules 1-2 — verify an ID token's EdDSA signature against
    ``verifier``'s JWKS, returning the decoded (but not yet claim-checked)
    payload.

    Time-based claims (``exp``/``iat``/``nbf``) are intentionally left
    unverified by ``jwt.decode`` here: CONTRACT.md §12.4 rule 5 has its own
    exact clock-skew semantics (a hard 60s ceiling, ``exp`` treated as
    required), which :func:`check_id_token_claims` enforces explicitly
    rather than deferring to PyJWT's own defaults.
    """
    header = jwt.get_unverified_header(token)
    assert_id_token_alg(header.get("alg"))

    try:
        signing_key = verifier.get_signing_key(token)
    except PyJWTError as exc:
        # Unknown kid, no kid header at all (port-brief-addendum item 12),
        # or an empty/malformed keyset after the verifier's own single
        # forced re-fetch — all resolve to unknown_kid.
        raise id_token_auth_error("unknown_kid", "no JWKS key matches the token's kid") from exc

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=[ID_TOKEN_ALG],
            options={
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "verify_aud": False,
                "verify_iss": False,
                "require": [],
            },
        )
    except PyJWTError as exc:
        raise id_token_auth_error(
            "invalid_signature", "ID token signature verification failed"
        ) from exc
    return claims


def check_id_token_claims(
    claims: dict[str, Any],
    *,
    issuer: str,
    client_id: str,
    nonce: str | None,
    clock_skew_sec: float | None = None,
    now: float | None = None,
) -> IdTokenClaims:
    """§12.4 rules 3-6 — issuer, audience, time, and nonce checks over an
    already-signature-verified claim set. Returns the validated
    :class:`~axiam_sdk._models.IdTokenClaims` on success; raises the
    matching :class:`AuthError` reason code on the first failure.

    Args:
        claims: The verified JWT payload.
        issuer: The discovery document's ``issuer`` — the authoritative
            value to compare ``iss`` against (never the client base URL).
        client_id: The relying party's own ``client_id``, matched against
            ``aud``/``azp``.
        nonce: The nonce from ``oidc_begin``, mandatory for ``oidc_exchange``.
            ``None`` for ``oidc_refresh``/``login_client_credentials``, which
            skip rule 6 entirely (OIDC Core §12.2 does not require a nonce in
            a refresh-issued ID token).
        clock_skew_sec: Permitted clock skew, clamped to
            ``[0, MAX_CLOCK_SKEW_SEC]``.
        now: Current time in epoch seconds — injectable so tests can pin it.
    """
    skew = resolve_clock_skew_sec(clock_skew_sec)
    now_sec = now if now is not None else time.time()

    # Rule 3 — exact string comparison. No normalization, no trailing-slash
    # tolerance, no prefix matching (CONTRACT.md §12.3 rule 6).
    iss = claims.get("iss")
    if iss != issuer:
        raise id_token_auth_error(
            "invalid_issuer", "iss does not equal the discovery document issuer"
        )

    # Rule 4 — aud must contain our client_id; with multiple audiences an
    # azp claim must be present and equal to it.
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if client_id not in audiences:
        raise id_token_auth_error("invalid_audience", "aud does not contain this client_id")
    if len(audiences) > 1 and claims.get("azp") != client_id:
        raise id_token_auth_error(
            "invalid_audience",
            "aud holds multiple audiences and azp is absent or does not equal this client_id",
        )

    # Rule 5 — exp must be in the future, iat must not be in the future, nbf
    # is honored when present; all within `skew` seconds. `exp` is treated
    # as REQUIRED: a token with no expiry could never satisfy "exp must be
    # in the future", so its absence is an expiry failure rather than a
    # free pass (port-brief-addendum item 11).
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise id_token_auth_error("token_expired", "exp claim is missing or not a number")
    if exp + skew <= now_sec:
        raise id_token_auth_error("token_expired", "exp is in the past")

    iat = claims.get("iat")
    if not isinstance(iat, (int, float)):
        raise id_token_auth_error("token_expired", "iat claim is missing or not a number")
    if iat - skew > now_sec:
        raise id_token_auth_error("token_expired", "iat is in the future")

    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and nbf - skew > now_sec:
        raise id_token_auth_error("token_expired", "nbf is in the future")

    # Rule 6 — mandatory for oidc_exchange, skipped when the caller supplied
    # no expected nonce (oidc_refresh / login_client_credentials).
    if nonce is not None:
        claim_nonce = claims.get("nonce")
        if not isinstance(claim_nonce, str) or not constant_time_equals(claim_nonce, nonce):
            raise id_token_auth_error(
                "nonce_mismatch", "nonce claim is absent or does not match the request nonce"
            )

    return IdTokenClaims.model_validate(claims)


def validate_id_token(
    id_token: str,
    verifier: JwksVerifier,
    *,
    issuer: str,
    client_id: str,
    nonce: str | None,
    clock_skew_sec: float | None = None,
    now: float | None = None,
) -> IdTokenClaims:
    """Run the full CONTRACT.md §12.4 checklist (rules 1-6) against
    ``id_token``, in order: signature (:func:`verify_id_token_signature`)
    then claims (:func:`check_id_token_claims`). Rule 7 (all-or-nothing
    discard) is the caller's responsibility (``_oidc.py``)."""
    claims = verify_id_token_signature(verifier, id_token)
    return check_id_token_claims(
        claims,
        issuer=issuer,
        client_id=client_id,
        nonce=nonce,
        clock_skew_sec=clock_skew_sec,
        now=now,
    )
