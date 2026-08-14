"""Local JWKS fetch/cache/verification (D-16/CF-07).

Verifies AXIAM access tokens locally against the organization-wide EdDSA
JWKS, using PyJWT's :class:`~jwt.PyJWKClient`. Mirrors
``the Go SDK's internal/jwks/verifier.go`` and ``the Rust SDK's src/token/jwks.rs``.

Endpoint: ``GET {base_url}/oauth2/jwks`` — a single, organization-wide
endpoint serving exactly one Ed25519 key today. This is NOT a generic OIDC
discovery-style JWKS path, and it is NOT tenant-scoped.

Security-critical invariant (algorithm-confusion defense, D-16): the token's
``alg`` header is checked against an explicit EdDSA-only allowlist BEFORE any
keyset lookup — the token's own ``alg`` header never selects the
verification algorithm. ``jwt.decode`` is always called with an explicit single-element EdDSA
algorithm allowlist (never a wildcard/unset algorithms argument, and never an
alg inferred from the token itself).

Two entry points, deliberately named apart (CONTRACT.md §10.1):

* :meth:`JwksVerifier.verify_access_token` is **the** guard entry point. It
  applies the complete §10.1 minimum local-verification set — signature with
  ``alg`` pinned to EdDSA before key lookup, a **required** numeric ``exp``,
  ``nbf`` when present, a **required** ``tenant_id`` asserted against the
  caller's configured tenant, and ``iss``/``aud`` whenever this verifier was
  configured with an expected value — all under a bounded, named clock skew.
* :meth:`JwksVerifier.verify_signature_only_unchecked` is the raw
  signature-only primitive §10.1 permits for integrators writing their own
  policy. Its name states the omission at the call site; the SDK's own guards
  never route through it.

PyJWT caveat this module exists to close (the ``SEC-080`` defect): PyJWT
"validates ``exp`` by default", but that default only applies when the claim
is *present* — ``jwt.decode`` happily accepts a token carrying **no** ``exp``
at all, i.e. a permanent credential. It also accepts a ``exp`` supplied as a
numeric *string* (it coerces with ``int()``). Both are closed here by an
explicit ``require`` list plus a post-decode JSON-type assertion.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import threading
import time
from collections.abc import Mapping
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import MissingRequiredClaimError, PyJWTError
from jwt.types import Options

from axiam_sdk._errors import AuthError

_LOGGER = logging.getLogger(__name__)

#: Canonical 8-4-4-4-12 hex UUID shape. Shape only — no version/variant check.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

# The AXIAM JWKS endpoint path — organization-wide, not tenant-scoped
# (D-16). This is NOT a generic OIDC discovery-style `/.well-known/jwks.json`
# path; do not substitute one.
JWKS_PATH = "/oauth2/jwks"

# Normal (non-forced) cache TTL, matching the Rust/Go references'
# JWKS_CACHE_TTL / maxCacheInterval.
_DEFAULT_LIFESPAN_SECONDS = 300

# Minimum interval between forced refetches triggered by an unknown `kid`,
# to avoid a hostile/rotating-kid token stream hammering the JWKS endpoint
# (matches the Rust reference's FORCED_REFETCH_MIN_INTERVAL / Go's
# minRefetchInterval). PyJWKClient has no built-in rate limit for forced
# refetches, so it is implemented here at the wrapper level.
_FORCED_REFETCH_MIN_INTERVAL_SECONDS = 60

#: CONTRACT.md §10.1 rule 7 — the RECOMMENDED clock-skew leeway applied to
#: BOTH ``exp`` and ``nbf``. A named constant, never an inline literal.
DEFAULT_CLOCK_SKEW_SECONDS = 60

#: CONTRACT.md §10.1 rule 7 — the hard upper bound on an operator-supplied
#: ``clock_skew_seconds``. The leeway MUST NOT be configurable to an
#: unbounded value, so anything above this (or below zero) is rejected at
#: construction time rather than silently widening the acceptance window.
#:
#: Lowered 300 -> 60 (§13.4 observation 5). 300s satisfied rule 7 — it was named
#: and bounded — but it was 5x the recommended leeway and 5x what every sibling
#: SDK fixes its value at, so an operator could widen the window on an expired
#: token to five minutes and still be "conformant". The ceiling now equals the
#: recommendation, matching the C++ SDK, which is the only other SDK that
#: enforces a ceiling rather than fixing the value outright.
MAX_CLOCK_SKEW_SECONDS = 60

#: The audience a §10 guard in front of a user-facing resource server SHOULD
#: expect (CONTRACT.md §10.1 rule 6). Exported for callers to pass as
#: ``expected_audience``; never applied implicitly — rule 6 is conditional on
#: the SDK being *configured* with an expected value.
RECOMMENDED_RESOURCE_SERVER_AUDIENCE = "axiam:user"


class JwksVerifier:
    """Fetches, caches, and locally verifies AXIAM access tokens against the
    organization-wide EdDSA JWKS."""

    def __init__(
        self,
        base_url: str,
        *,
        lifespan: int = _DEFAULT_LIFESPAN_SECONDS,
        jwks_url: str | None = None,
        expected_issuer: str | None = None,
        expected_audience: str | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> None:
        """Build a verifier against ``{base_url}{JWKS_PATH}``, or against an
        explicit ``jwks_url`` when supplied.

        Args:
            base_url: The AXIAM server's base URL; ``JWKS_PATH`` is appended
                after stripping any trailing slash. Ignored when
                ``jwks_url`` is supplied.
            lifespan: Normal (non-forced) JWKS cache TTL in seconds, passed
                through to :class:`~jwt.PyJWKClient`'s ``cache_jwk_set``
                lifespan (default :data:`_DEFAULT_LIFESPAN_SECONDS`).
            jwks_url: An explicit, full JWKS document URL, overriding the
                ``{base_url}{JWKS_PATH}`` derivation. Used by the OIDC
                relying-party helpers (CONTRACT.md §12.3 rule 6), which read
                ``jwks_uri`` from the discovery document rather than
                hardcoding ``/oauth2/jwks`` — the discovery document's
                ``jwks_uri`` may legitimately differ from
                ``{base_url}{JWKS_PATH}`` (e.g. behind a proxy).
            expected_issuer: The ``iss`` value every locally-verified access
                token must carry (CONTRACT.md §10.1 rule 5). **Optional and
                unset by default** — rule 5 is conditional, so no issuer is
                ever assumed or hardcoded; when left ``None`` the ``iss``
                claim is not checked, and when supplied a mismatch (or an
                absent ``iss``) is rejected.
            expected_audience: The value that must appear in the ``aud``
                claim (CONTRACT.md §10.1 rule 6). Same conditional shape as
                ``expected_issuer``; a guard fronting a user-facing resource
                server should pass
                :data:`RECOMMENDED_RESOURCE_SERVER_AUDIENCE`.
            clock_skew_seconds: Leeway applied to BOTH ``exp`` and ``nbf``
                (CONTRACT.md §10.1 rule 7), defaulting to the RECOMMENDED
                :data:`DEFAULT_CLOCK_SKEW_SECONDS`. Bounded to
                ``0 .. MAX_CLOCK_SKEW_SECONDS``.

        Raises:
            ValueError: if ``clock_skew_seconds`` is negative or exceeds
                :data:`MAX_CLOCK_SKEW_SECONDS` — §10.1 rule 7 forbids an
                operator-settable unbounded leeway.
        """
        if not 0 <= clock_skew_seconds <= MAX_CLOCK_SKEW_SECONDS:
            raise ValueError(
                "clock_skew_seconds must be between 0 and "
                f"{MAX_CLOCK_SKEW_SECONDS} seconds (CONTRACT.md §10.1 rule 7)"
            )
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._clock_skew_seconds = clock_skew_seconds
        resolved_jwks_url = jwks_url if jwks_url is not None else base_url.rstrip("/") + JWKS_PATH
        # The per-key LRU cache (opt-in via a separate constructor flag,
        # intentionally left at its default/disabled state here) has no
        # TTL/expiration (Pattern 5 Pitfall); relying solely on the TTL'd
        # jwk_set_cache (cache_jwk_set=True) avoids serving a rotated/revoked
        # key indefinitely.
        self._client = PyJWKClient(resolved_jwks_url, cache_jwk_set=True, lifespan=lifespan)
        self._last_forced_refetch: float | None = None
        self._refetch_lock = threading.Lock()
        # §13.4 observation 6 — latches the slug-vs-UUID diagnostic to one
        # emission, so a stream of bad tokens cannot turn it into a log flood.
        self._slug_comparand_warned = False

    def verify_signature_only_unchecked(self, token: str) -> dict[str, Any]:
        """Verify ``token``'s EdDSA signature against the cached JWKS and
        return the decoded claims — **signature only**.

        This is the raw primitive CONTRACT.md §10.1 permits for integrators
        deliberately implementing their own policy. The ``_unchecked`` suffix
        is the contract's reference spelling and is load-bearing: this method
        does NOT check ``exp``, ``nbf``, ``tenant_id``, ``iss``, or ``aud``,
        and a caller that stops here has no guard at all. Route SDK guards
        through :meth:`verify_access_token` instead.

        Rejects any token whose header ``alg`` is not ``EdDSA`` BEFORE any
        keyset lookup is attempted (algorithm-confusion defense, §10.1 rule 1).

        Args:
            token: The compact-serialized JWS to verify.

        Returns:
            The decoded claims dict, once the signature has verified.

        Raises:
            ValueError: if the header ``alg`` is not exactly ``EdDSA``.
            jwt.exceptions.PyJWTError: on any signature/key-resolution failure.
        """
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "EdDSA":
            raise ValueError(f"unexpected alg {header.get('alg')!r}: only EdDSA is accepted")

        signing_key = self._get_signing_key(token)

        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA"],
            options={"require": ["sub"]},
        )

    def verify_logout_token_signature(self, token: str) -> dict[str, Any]:
        """Verify a back-channel logout token's signature (CONTRACT.md
        §12.7.3 check 1) and return its claims.

        Distinct from :meth:`verify_signature_only_unchecked` for one reason:
        that method requires a ``sub`` claim, and a logout token legitimately
        carries only ``sid``. Everything else is shared — the same
        ``_get_signing_key`` path, so there is no second key-fetching route,
        which is what §12.7.3 requires.

        Applies the same ``alg``/``kid`` discipline as the §12.4 ID-token
        path: EdDSA is pinned before any keyset lookup, and a token with no
        ``kid`` is rejected outright rather than falling back to "the only
        published key" — that fallback would defeat key rotation.

        Claim checks (``iss``/``aud``/``events``/``nonce``/``sid``/``sub``/
        freshness) are the caller's, in ``_oidc.py``, so each failure gets its
        own message.

        Args:
            token: The compact-serialized logout token.

        Returns:
            The decoded claims dict, once the signature has verified.

        Raises:
            ValueError: if ``alg`` is not EdDSA or the header carries no ``kid``.
            jwt.exceptions.PyJWTError: on any signature/key-resolution failure.
        """
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "EdDSA":
            raise ValueError(f"unexpected alg {header.get('alg')!r}: only EdDSA is accepted")
        if not header.get("kid"):
            raise ValueError("logout token carries no kid header")

        signing_key = self._get_signing_key(token)

        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA"],
            # No `require`: a logout token names `sid` OR `sub`, and which one
            # is present is checked by the caller with its own message.
            # `aud` is checked there too, so PyJWT's own audience check is off
            # rather than duplicated under a less specific error.
            options={"verify_aud": False},
        )

    def verify_access_token(self, token: str, *, expected_tenant_id: str | None) -> dict[str, Any]:
        """Apply the **complete** CONTRACT.md §10.1 minimum local-verification
        set to ``token`` and return its claims. This is the documented guard
        entry point; every SDK route guard and middleware goes through it.

        The seven rules, in order:

        1. ``alg`` pinned to ``EdDSA`` and checked BEFORE any keyset lookup,
           so ``alg: none`` and HS-family confusion are rejected without ever
           consulting a key.
        2. ``exp`` is REQUIRED and must be a JSON number. An absent ``exp``
           is a permanent credential, never "no expiry constraint"; a
           numeric-string ``exp`` (which PyJWT would silently coerce) is a
           wrong-typed claim and is rejected too.
        3. ``nbf`` is honoured when present and may be absent.
        4. ``tenant_id`` is REQUIRED and must equal ``expected_tenant_id``.
           With no configured tenant to compare against, this fails closed —
           the JWKS trust anchor is organization-wide, so signature validity
           alone does not bound a token to a tenant.
        5. ``iss`` is checked only when this verifier was built with an
           ``expected_issuer``.
        6. ``aud`` is checked only when this verifier was built with an
           ``expected_audience``.
        7. Rules 2 and 3 allow the bounded, named ``clock_skew_seconds``
           leeway (default :data:`DEFAULT_CLOCK_SKEW_SECONDS`).

        Fail-closed throughout: a required claim that is absent, unparseable,
        or of the wrong JSON type causes rejection.

        Args:
            token: The compact-serialized access token presented by the caller.
            expected_tenant_id: The tenant this deployment serves. ``None`` or
                empty is a configuration error and fails closed (rule 4).

        Returns:
            The decoded claims dict, once every rule above has passed.

        Raises:
            AuthError: on any rule violation — the single failure type
                callers map to HTTP 401 (CONTRACT.md §2/§10).
        """
        if not isinstance(expected_tenant_id, str) or not expected_tenant_id:
            # Rule 4, fail-closed half: no configured tenant means there is
            # nothing to assert the token against, which is a rejection, not
            # a skipped check.
            raise AuthError("no configured tenant to assert the token's tenant_id against")

        # Rule 1 — pin the algorithm before any key lookup.
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise AuthError("malformed token header") from exc
        if header.get("alg") != "EdDSA":
            raise AuthError(f"unexpected alg {header.get('alg')!r}: only EdDSA is accepted")

        try:
            signing_key = self._get_signing_key(token)
        except PyJWTError as exc:
            raise AuthError("no JWKS key matches the token") from exc

        # Rules 2/3/4/5/6 — everything PyJWT can enforce, enforced explicitly
        # rather than left to defaults. `require` is what closes the SEC-080
        # gap; PyJWT's own `Options` docstring states it outright: "Some
        # claims, such as exp ... will only be verified if present ... make
        # sure to include them in the require param".
        required = ["sub", "exp", "tenant_id"]
        if self._expected_issuer is not None:
            required.append("iss")
        if self._expected_audience is not None:
            required.append("aud")
        options: Options = {
            "verify_exp": True,
            "verify_nbf": True,
            # Rule 6 is CONDITIONAL: with no expected audience configured
            # there is no check. PyJWT would otherwise reject an `aud`-bearing
            # token outright when no `audience=` argument is supplied.
            "verify_aud": self._expected_audience is not None,
            "require": required,
        }

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["EdDSA"],
                leeway=self._clock_skew_seconds,
                options=options,
                issuer=self._expected_issuer,
                audience=self._expected_audience,
            )
        except MissingRequiredClaimError as exc:
            raise AuthError(f"token is missing the required {exc.claim} claim") from exc
        except PyJWTError as exc:
            raise AuthError("invalid or expired token") from exc
        except (TypeError, ValueError) as exc:
            # PyJWT coerces `exp`/`nbf` with `int()` and lets a TypeError out
            # for a claim of a wholly unexpected JSON type (a list, an
            # object). Fail closed with the standard rejection rather than
            # letting it surface as an unhandled 500 in a caller's guard.
            raise AuthError("token claims are malformed") from exc

        # Rules 2/3, JSON-type half. PyJWT coerces `exp`/`nbf` with `int()`,
        # so a string "9999999999" passes its own check; §10.1 requires the
        # claim to be a JSON number, and a bool is not one either.
        self._assert_numeric_claim(claims, "exp", required=True)
        self._assert_numeric_claim(claims, "nbf", required=False)

        # Rule 4, assertion half.
        tenant_id = claims.get("tenant_id")
        if not isinstance(tenant_id, str) or tenant_id != expected_tenant_id:
            self._warn_once_if_comparand_looks_like_a_slug(tenant_id, expected_tenant_id)
            raise AuthError("token tenant_id does not match the configured tenant")

        return claims

    def verify_sender_constrained(
        self,
        token: str,
        *,
        expected_tenant_id: str | None,
        presented_thumbprint: str | None,
    ) -> dict[str, Any]:
        """:meth:`verify_access_token` plus CONTRACT.md §10.1 **rule 9** — the
        sender constraint (RFC 8705 §3, contract 1.15).

        This is the guard entry point for a resource server that accepts
        **certificate-bound** access tokens. Pass the ``x5t#S256`` thumbprint of
        the client certificate on the current connection, or ``None`` if there
        is none; :func:`certificate_thumbprint_s256` computes it from DER bytes.

        A separate method rather than a parameter on
        :meth:`verify_access_token` because the two have different *inputs*:
        most integrations have no transport-level certificate to offer, and
        folding the thumbprint in would force every caller to thread a ``None``
        they do not have — which reads as "no certificate" and rejects every
        bound token.

        **An unbound token is still accepted** here, with or without a
        certificate. Rule 9 constrains tokens that claim a constraint; it does
        not make certificates mandatory.

        Args:
            token: The compact-serialized access token presented by the caller.
            expected_tenant_id: As :meth:`verify_access_token`.
            presented_thumbprint: The RFC 8705 §3.1 ``x5t#S256`` of the peer
                certificate on this connection, or ``None``.

        Returns:
            The decoded claims dict.

        Raises:
            AuthError: everything :meth:`verify_access_token` raises, plus the
                three rejecting rows of :func:`verify_certificate_binding`.
        """
        claims = self.verify_access_token(token, expected_tenant_id=expected_tenant_id)
        verify_certificate_binding(claims, presented_thumbprint)
        return claims

    def _warn_once_if_comparand_looks_like_a_slug(self, claimed: object, expected: str) -> None:
        """Name the slug-vs-UUID misconfiguration explicitly (§13.4 observation 6).

        AXIAM access tokens carry the tenant **UUID** in ``tenant_id``, but this
        SDK's client is commonly configured with a tenant **slug**. A guard handed
        that slug rejects 100% of traffic — fail-closed and safe, but it presents
        as "every token is invalid" with nothing pointing at the cause, which is a
        miserable thing to debug.

        Deliberately:

        * **once per verifier**, so it is a configuration diagnostic and not a
          log-flood sink an attacker can drive with bad tokens;
        * keyed on the **shape of the operator-configured value**, never on
          anything the caller supplies, so it cannot be triggered on demand;
        * emitted **after** the rejection is decided — it only ever explains a
          failure, and the verification outcome is byte-for-byte unchanged.

        A UUID-vs-UUID mismatch is a genuine cross-tenant rejection and stays
        silent.
        """
        if self._slug_comparand_warned:
            return
        if not isinstance(claimed, str):
            return
        if not _UUID_RE.match(claimed) or _UUID_RE.match(expected):
            return

        self._slug_comparand_warned = True
        _LOGGER.warning(
            "AXIAM: the tenant this guard was configured with (%r) is not a UUID, but "
            "access tokens carry the tenant UUID in their `tenant_id` claim, so this "
            "guard will reject every request. Configure it with the tenant UUID, not "
            "the slug. (CONTRACT.md §10.1 rule 4; logged once per verifier, and it "
            "does not affect the rejection itself.)",
            expected,
        )

    @staticmethod
    def _assert_numeric_claim(claims: dict[str, Any], name: str, *, required: bool) -> None:
        """Assert ``claims[name]`` is a real JSON number (CONTRACT.md §10.1
        "wrong JSON type MUST cause rejection").

        Args:
            claims: The decoded claims dict.
            name: The claim to type-check (``exp`` or ``nbf``).
            required: When ``True``, an absent claim is itself a rejection.

        Raises:
            AuthError: if the claim is absent while required, or present with
                a non-numeric type (``bool`` included — ``isinstance(True,
                int)`` is ``True`` in Python, so it is excluded explicitly).
        """
        value = claims.get(name)
        if value is None:
            if required:
                raise AuthError(f"token is missing the required {name} claim")
            return
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise AuthError(f"token {name} claim is not a JSON number")

    def get_signing_key(self, token: str) -> Any:
        """Public wrapper around :meth:`_get_signing_key` (CONTRACT.md
        §12.4 rule 2): the unknown-``kid``-triggers-one-forced-refetch
        resolution logic, exposed for the OIDC ID-token validation checklist
        (``_oidc_idtoken.py``), which needs the raw signing key without
        going through :meth:`verify_signature_only_unchecked`'s fixed
        ``require: ["sub"]`` decode
        step — §12 extends this verifier rather than forking it."""
        return self._get_signing_key(token)

    def _get_signing_key(self, token: str) -> Any:
        """Resolve the signing key for *token*, single-flighted through
        ``_refetch_lock`` so a burst of concurrent callers against a cold
        or stale cache — forced-refetch or not — collapses to exactly one
        network fetch (D-08/D-09, PERF-03).

        The lock spans the ENTIRE lookup-and-fetch sequence, not merely the
        "should-I-invalidate" decision (the pre-existing TOCTOU gap this
        closes): every waiter, once it acquires the lock, first retries
        against whatever a prior lock-holder may have already
        fetched/repaired before ever triggering another fetch itself.
        """
        with self._refetch_lock:
            try:
                return self._client.get_signing_key_from_jwt(token)
            except PyJWTError:
                # Unknown kid, a stale in-TTL cache after key rotation, or
                # an empty/malformed keyset response (e.g. a rotation
                # window where the new key has not yet propagated).
                # PyJWTError is the common base of both PyJWKClientError
                # (unknown kid) and PyJWKSetError (empty/invalid keyset) —
                # both failure modes warrant the same forced-refetch
                # response below.
                pass

            now = time.monotonic()
            if (
                self._last_forced_refetch is not None
                and now - self._last_forced_refetch < _FORCED_REFETCH_MIN_INTERVAL_SECONDS
            ):
                # Rate-limited: another caller already forced a refetch
                # recently (while we waited for the lock, or just before
                # us) — surface whatever the current cache yields rather
                # than hammering the endpoint again.
                return self._client.get_signing_key_from_jwt(token)

            # Force exactly one rate-limited refetch, then retry once. A
            # second failure propagates to the caller.
            self._client.jwk_set_cache = None
            self._last_forced_refetch = now
            return self._client.get_signing_key_from_jwt(token)


def verify_certificate_binding(
    claims: Mapping[str, Any],
    presented_thumbprint: str | None,
) -> None:
    """CONTRACT.md §10.1 **rule 9** — enforce a token's sender constraint
    against the certificate the caller presented on **this** connection
    (RFC 8705 §3 / RFC 7800, contract 1.15).

    A token carrying ``cnf`` is **not** a bearer token. Accepting one without
    proving the caller holds the named key converts it straight back into one,
    discarding the whole protection the operator turned on — which is why this
    is a rule and not a recommendation.

    ``presented_thumbprint`` is the RFC 8705 §3.1 ``x5t#S256`` of the peer
    certificate: base64url, **unpadded**, SHA-256 over the **DER** encoding.
    :func:`certificate_thumbprint_s256` computes it from DER bytes.

    The four cases:

    ===========================  ==========================  ==========
    token's ``cnf``              ``presented_thumbprint``    result
    ===========================  ==========================  ==========
    absent                       anything                    returns
    ``x5t#S256``                 equal                       returns
    ``x5t#S256``                 different, or ``None``      raises
    present, no ``x5t#S256``     anything                    raises
    ===========================  ==========================  ==========

    The first row is why adopting this rule breaks nothing: an unbound token is
    still accepted whether or not a certificate is present. The last row is the
    one that is easy to get wrong — a ``cnf`` naming a method this SDK cannot
    check is an *unverifiable constraint*, never *no constraint*. Read the
    other way, a sender-constrained token silently degrades to a bearer token
    the day a newer AXIAM issues a confirmation this SDK predates.

    .. warning::
       **The thumbprint must come from the transport.** Take it from the TLS
       peer certificate, or from a value a *trusted* terminating proxy
       forwarded over a channel your application controls. Never from a
       caller-settable request header: a forgeable input makes the whole
       mechanism decorative.

    Args:
        claims: The verified claims dict.
        presented_thumbprint: The peer certificate's ``x5t#S256``, or ``None``.

    Raises:
        AuthError: on any of the three rejecting rows.
    """
    cnf = claims.get("cnf")
    if cnf is None:
        return
    if not isinstance(cnf, Mapping):
        raise AuthError("token cnf claim is malformed")

    expected = cnf.get("x5t#S256")
    if not isinstance(expected, str) or not expected:
        raise AuthError(
            "token carries a cnf confirmation naming a method this SDK cannot verify "
            "(CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an absent one)"
        )
    if presented_thumbprint is None:
        raise AuthError("token is certificate-bound but no client certificate was presented")
    # Constant-time. The thumbprint is usually public — it derives from a
    # certificate sent in the clear during the handshake — so this is defence
    # in depth. It matters most for a self-signed client, where the registered
    # thumbprint is the whole credential.
    if not hmac.compare_digest(expected, presented_thumbprint):
        raise AuthError("token is bound to a different client certificate than the one presented")


def certificate_thumbprint_s256(der: bytes) -> str:
    """Compute the RFC 8705 §3.1 ``x5t#S256`` thumbprint of a DER client
    certificate: base64url-encoded SHA-256, **without** padding.

    Unpadded is not a style choice — RFC 7515 §2 defines base64url in JOSE as
    omitting ``=``, and a padded value will not compare equal to what AXIAM put
    in the token.

    Args:
        der: The DER encoding of the peer's leaf certificate. Under the stdlib
            ``ssl`` module this is ``sock.getpeercert(binary_form=True)``.

    Returns:
        The 43-character base64url thumbprint.
    """
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode("ascii")
