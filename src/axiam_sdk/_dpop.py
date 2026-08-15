"""DPoP proof verification — CONTRACT.md §21.7.2 (RFC 9449), contract 1.16.

This module implements the resource-server half of DPoP: given the ``DPoP``
header a caller presented, decide whether it is a valid proof of possession for
*this* request and *this* access token, and return the key thumbprint that
:func:`axiam_sdk._jwks.verify_token_binding` then matches against the token's
``cnf.jkt``.

Why this lives in the SDK at all
--------------------------------

§21.7.2 is a ten-check list, and the contract is blunt about partial
implementations: *"Partial verification is worse than none, because it produces
a guard that reports success."* Nine of the ten checks are the kind that look
optional until someone builds an attack out of the one that was skipped — so
they belong in one audited place rather than in every application that guards
an endpoint.

The two checks most often missing, and what they cost:

``typ``
    Without pinning ``typ`` to ``dpop+jwt``, any *other* JWT signed by the same
    key — an access token, an ID token — is replayable as a proof.

``ath``
    Without it, a proof captured on one request can be re-aimed at a different
    token held by the same key. ``ath`` is what binds the proof to the token
    rather than merely to the key.

The algorithm is taken from the embedded ``jwk``, never from the header
---------------------------------------------------------------------

``alg: none`` and RSA-public-key-as-HMAC-secret are the same bug wearing
different clothes: *the token told the verifier how to check the token*. This
module derives the expected algorithm from the key's own ``kty``/``crv`` and
passes that single algorithm to the decoder. The header's ``alg`` is never
consulted — not compared, not read.

Replay
------

``iat`` freshness bounds the window; the ``jti`` guard is what makes the window
unusable. A :class:`JtiStore` is therefore **required** — there is no default
that silently skips it. :class:`InMemoryJtiStore` is correct for a single
process; a multi-process deployment needs a shared one (Redis, memcached, a
database table) or each worker gets its own replay window.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from collections.abc import Mapping
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

import jwt

from ._errors import AuthError

#: §21.7.2 check 7 — the ``iat`` acceptance window, applied in **both**
#: directions. RFC 9449 recommends a small window and does not fix a number;
#: 60 s is the contract's RECOMMENDED value. A named constant because a bare
#: ``60`` three call-frames deep is a number nobody ever revisits.
DPOP_IAT_LEEWAY_SECONDS = 60

#: The three algorithms §21.7.2 check 2 permits. HMAC families are absent on
#: purpose: a symmetric "proof" verifiable with a key the verifier also holds
#: proves possession of nothing.
_PERMITTED_ALGS = frozenset({"PS256", "ES256", "EdDSA"})

#: RFC 9449 §4.3 — private key material that must never appear in a proof's
#: embedded public ``jwk``. ``k`` is the symmetric-key member; its presence
#: means the "public key" is a shared secret.
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

#: RFC 7638 §3.2 — the members that participate in a thumbprint, per key type,
#: and the lexicographic order they must be serialised in.
_THUMBPRINT_MEMBERS: Mapping[str, tuple[str, ...]] = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
}


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment that may have had its padding stripped."""
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded base64url (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class JtiStore(Protocol):
    """§21.7.2 check 8 — single-use ``jti`` tracking.

    One method, and its contract is the whole point: :meth:`claim` must be
    atomic. A ``contains?``-then-``add`` pair read as two calls is a race two
    concurrent replays of the same proof can both win.
    """

    def claim(self, jti: str, expires_at: float) -> bool:
        """Record ``jti`` as used until ``expires_at``.

        Returns ``True`` if this is the first time it has been seen, ``False``
        if it is a replay.
        """
        ...


class InMemoryJtiStore:
    """A :class:`JtiStore` for a single process.

    .. warning::
       Per-process, therefore per-worker. Four Gunicorn workers give an
       attacker four chances to replay a proof inside its freshness window,
       and a restart clears the window entirely. Any deployment running more
       than one process needs a shared store.
    """

    def __init__(self) -> None:
        """Create an empty store."""
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, jti: str, expires_at: float) -> bool:
        """Record ``jti`` as used until ``expires_at``.

        Returns ``True`` if this is the first sighting, ``False`` if it is a
        replay.
        """
        now = time.time()
        with self._lock:
            # Prune under the same lock as the insert. Entries are only ever
            # valid for the freshness window, so this stays small without a
            # background sweeper.
            if len(self._seen) > 128:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            if self._seen.get(jti, 0.0) > now:
                return False
            self._seen[jti] = expires_at
            return True


def jwk_thumbprint_s256(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint of a JWK — the ``jkt``.

    Only the members RFC 7638 names for the key type take part, serialised as
    compact JSON with lexicographically sorted keys. Members outside that set
    (``kid``, ``use``, ``alg``, ``x5c``) are excluded by the spec, which is
    what makes the thumbprint stable across two encodings of the same key.

    Raises:
        AuthError: if the key type is unknown or a required member is missing.
    """
    kty = jwk.get("kty")
    if not isinstance(kty, str) or kty not in _THUMBPRINT_MEMBERS:
        raise AuthError(f"DPoP proof jwk has an unsupported kty: {kty!r}")

    canonical: dict[str, str] = {}
    for member in _THUMBPRINT_MEMBERS[kty]:
        value = jwk.get(member)
        if not isinstance(value, str) or not value:
            raise AuthError(f"DPoP proof jwk is missing the required member {member!r}")
        canonical[member] = value

    # separators= matters: RFC 7638 requires no whitespace. sort_keys is
    # redundant given the tuples above are already ordered, and kept as a
    # belt-and-braces against someone reordering them.
    serialized = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    return _b64url_encode(hashlib.sha256(serialized.encode("utf-8")).digest())


def access_token_hash(access_token: str) -> str:
    """The ``ath`` claim value for ``access_token`` — RFC 9449 §4.2.

    base64url-unpadded SHA-256 over the token's **ASCII** bytes, i.e. over the
    compact JWT string exactly as it travelled in the ``Authorization`` header,
    not over anything decoded from it.
    """
    return _b64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())


def _expected_alg(jwk: Mapping[str, Any]) -> str:
    """§21.7.2 check 2 — derive the algorithm from the key itself.

    This function is the reason ``alg`` in the proof header is never read: the
    key's own type determines how a signature over it can be checked, and that
    is not a matter the presenter gets an opinion on.
    """
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    if kty == "RSA":
        return "PS256"
    if kty == "EC" and crv == "P-256":
        return "ES256"
    if kty == "OKP" and crv == "Ed25519":
        return "EdDSA"
    raise AuthError(
        f"DPoP proof key type is not permitted by CONTRACT.md §21.7.2 "
        f"(kty={kty!r}, crv={crv!r}; permitted: {sorted(_PERMITTED_ALGS)})"
    )


def _raw_header(proof: str) -> Mapping[str, Any]:
    """The proof's header as **raw JSON**.

    §21.7.2 check 4 insists the private-material check run against this rather
    than against a parsed key object, because many JWK libraries quietly drop
    ``d``/``p``/``q`` when parsing into a public-key type — the check would
    then pass by virtue of the library having hidden the evidence.
    """
    segments = proof.split(".")
    if len(segments) != 3:
        raise AuthError("DPoP proof is not a compact JWS with three segments")
    try:
        header = json.loads(_b64url_decode(segments[0]))
    except (ValueError, TypeError) as exc:
        raise AuthError("DPoP proof header is not valid base64url JSON") from exc
    if not isinstance(header, dict):
        raise AuthError("DPoP proof header is not a JSON object")
    return header


def canonical_htu(uri: str) -> str:
    """The ``htu`` comparison form — §21.7.2 check 6.

    Query and fragment removed, and **nothing else**. No case folding, no
    default-port elision, no percent-decoding, no trailing-slash fixing: a
    normalising comparison is precisely where two unequal URIs become equal,
    and an attacker who can find such a pair can aim a proof at an endpoint it
    was not minted for.
    """
    parts = urlsplit(uri)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def verify_dpop_proof(
    proof: str,
    *,
    http_method: str,
    http_uri: str,
    access_token: str,
    jti_store: JtiStore,
    expected_jkt: str | None = None,
    leeway_seconds: int = DPOP_IAT_LEEWAY_SECONDS,
    now: float | None = None,
) -> str:
    """Verify a DPoP proof against this request — all ten §21.7.2 checks.

    Returns the proof key's RFC 7638 thumbprint (``jkt``) on success. Feed that
    to :func:`axiam_sdk._jwks.verify_token_binding` as ``dpop_thumbprint``;
    returning it rather than a bare ``True`` is deliberate, so the value a guard
    passes onward can only have come from a proof that actually verified.

    Every argument is required for a reason — each one is an input to a check
    that cannot be made without it. There is no "just check the signature"
    mode, because that is the partial verification the contract calls worse
    than none.

    Args:
        proof: The raw ``DPoP`` header value.
        http_method: The request method, e.g. ``"POST"``.
        http_uri: The full request URI. Query and fragment are stripped here,
            so passing the URI with its query string is fine and expected.
        access_token: The access token from the ``Authorization`` header,
            exactly as it arrived — this is hashed for the ``ath`` check.
        jti_store: Replay guard. Required; see :class:`InMemoryJtiStore` for
            the single-process implementation and its deployment caveat.
        expected_jkt: The token's ``cnf.jkt``, when the caller has it. Supplying
            it performs check 10 here; omitting it means the caller must do
            that comparison itself, which
            :func:`~axiam_sdk._jwks.verify_token_binding` does.
        leeway_seconds: The ``iat`` window, both directions.
        now: Override for the current time, for tests.

    Raises:
        AuthError: on any failing check.
    """
    if not proof or not isinstance(proof, str):
        raise AuthError("DPoP proof is missing or empty")
    # A second proof in the same header is ambiguous, and RFC 9449 §4.2 makes
    # exactly one the rule. Rejecting beats picking the first, which is how a
    # verifier and a downstream parser end up reading different proofs.
    if "," in proof or " " in proof.strip():
        raise AuthError("DPoP header must carry exactly one proof")

    header = _raw_header(proof)

    # Check 1 — typ. First, because it is what stops any other JWT signed by
    # the same key from standing in as a proof.
    typ = header.get("typ")
    if not isinstance(typ, str) or typ.lower() != "dpop+jwt":
        raise AuthError(f"DPoP proof typ header must be 'dpop+jwt', got {typ!r}")

    # Check 3 (first half) — the header carries a public jwk.
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise AuthError("DPoP proof header must carry a public 'jwk'")

    # Check 4 — no private material, tested against the raw header JSON.
    present_private = _PRIVATE_JWK_MEMBERS.intersection(jwk)
    if present_private:
        raise AuthError(
            f"DPoP proof jwk carries private key material "
            f"({', '.join(sorted(present_private))}) — RFC 9449 §4.3"
        )

    # Check 2 — algorithm from the key, never from the header.
    alg = _expected_alg(jwk)

    # Check 3 (second half) — the signature verifies under that key.
    try:
        key = jwt.PyJWK(dict(jwk), algorithm=alg).key
    except Exception as exc:  # PyJWK raises a variety of types
        raise AuthError(f"DPoP proof jwk is not a usable public key: {exc}") from exc

    try:
        claims = jwt.decode(
            proof,
            key=key,
            # Single-element allowlist derived above. Never the header's alg,
            # and never a wildcard.
            algorithms=[alg],
            options={
                "require": ["htm", "htu", "iat", "jti", "ath"],
                "verify_aud": False,
                # PyJWT's own iat check is one-directional — it rejects a
                # future iat and ignores a stale one — and it consults the
                # wall clock rather than this call's `now`. Check 7 below is
                # the single authority for freshness; leaving both enabled
                # would mean two windows disagreeing about the same claim.
                "verify_iat": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise AuthError(f"DPoP proof signature or claims are invalid: {exc}") from exc

    # Check 5 — htm.
    htm = claims.get("htm")
    if not isinstance(htm, str) or htm != http_method:
        raise AuthError(f"DPoP proof htm {htm!r} does not match request method {http_method!r}")

    # Check 6 — htu, compared without normalisation beyond stripping query and
    # fragment from BOTH sides.
    htu = claims.get("htu")
    expected_htu = canonical_htu(http_uri)
    if not isinstance(htu, str) or canonical_htu(htu) != expected_htu:
        raise AuthError(f"DPoP proof htu {htu!r} does not match request URI {expected_htu!r}")

    # Check 7 — iat freshness, in both directions. A proof from the future is
    # as suspect as a stale one: it is how a clock-skew allowance gets turned
    # into a long-lived proof.
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        raise AuthError("DPoP proof iat must be a number")
    current = time.time() if now is None else now
    if abs(current - float(iat)) > leeway_seconds:
        raise AuthError(f"DPoP proof iat is outside the {leeway_seconds}s freshness window")

    # Check 9 — ath ties the proof to this specific access token.
    ath = claims.get("ath")
    if not isinstance(ath, str) or not ath:
        raise AuthError("DPoP proof is missing the ath claim")
    if not hmac.compare_digest(ath, access_token_hash(access_token)):
        raise AuthError("DPoP proof ath does not match the presented access token")

    # Check 10 — the thumbprint that ties the proof to the token's cnf.
    jkt = jwk_thumbprint_s256(jwk)
    if expected_jkt is not None and not hmac.compare_digest(jkt, expected_jkt):
        raise AuthError("DPoP proof key does not match the token's cnf.jkt")

    # Check 8 — jti single-use. LAST on purpose: claiming a jti is a mutation,
    # and doing it before the cheap checks would let an attacker burn arbitrary
    # jti values out of the store with proofs that were never going to verify.
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise AuthError("DPoP proof is missing a non-empty jti")
    if not jti_store.claim(jti, float(iat) + leeway_seconds):
        raise AuthError("DPoP proof jti has already been used (replay)")

    return jkt
