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

Several entry points, deliberately named apart (CONTRACT.md §10.1):

* :meth:`JwksVerifier.verify_access_token` is **the** guard entry point. It
  applies the complete §10.1 minimum local-verification set — signature with
  ``alg`` pinned to EdDSA before key lookup, a **required** numeric ``exp``,
  ``nbf`` when present, a **required** ``tenant_id`` asserted against the
  caller's configured tenant, ``iss``/``aud`` whenever this verifier was
  configured with an expected value, all under a bounded, named clock skew —
  **and rule 9**, applied with no transport evidence, so a token carrying
  ``cnf`` (certificate- or DPoP-bound) is refused outright rather than
  silently accepted as an ordinary bearer credential.
* :meth:`JwksVerifier.verify_with_proofs` is the entry point for a resource
  server that DOES have transport evidence (a peer certificate, a verified
  DPoP proof, or both) and wants to *accept* a properly-proven
  sender-constrained token rather than refuse every bound one.
  :meth:`JwksVerifier.verify_sender_constrained` is its certificate-only
  shape, for transports that can only ever produce a certificate thumbprint.
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
import http.client
import json
import logging
import math
import re
import threading
import time
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.error import HTTPError, URLError

import jwt
from jwt import PyJWK, PyJWKClient
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidIssuedAtError,
    MissingRequiredClaimError,
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWTError,
)
from jwt.types import Options

from axiam_sdk._errors import AuthError
from axiam_sdk._mcp import McpGuardChallenges, mcp_guard_challenges
from axiam_sdk._revocation_feed import RevocationFeed
from axiam_sdk._telemetry import ConfigClamped, TelemetryDispatcher, TelemetryHook

_LOGGER = logging.getLogger(__name__)

#: Canonical 8-4-4-4-12 hex UUID shape. Shape only — no version/variant check.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

# The AXIAM JWKS endpoint path — organization-wide, not tenant-scoped
# (D-16). This is NOT a generic OIDC discovery-style `/.well-known/jwks.json`
# path; do not substitute one.
JWKS_PATH = "/oauth2/jwks"

# Default JWKS cache TTL, matching the Rust/Go references' JWKS_CACHE_TTL / maxCacheInterval.
_DEFAULT_LIFESPAN_SECONDS = 300

#: CONTRACT.md §12.4 rule 2 (contract 1.69, D-10): the TTL is at most this, whether configured or
#: advertised by ``Cache-Control: max-age``; a larger value is clamped down, never honoured.
MAX_JWKS_TTL_SECONDS = 300

#: CONTRACT.md §12.4 rule 2: how long past the TTL, measured from the last SUCCESSFUL fetch, the
#: held keys keep verifying while every refresh fails. After TTL + this, every token is refused
#: until a fetch succeeds.
JWKS_MAX_STALE_SECONDS = 300

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


def _is_access_token_typ(typ: object) -> bool:
    """CONTRACT.md §10.1 rule 10: ``typ`` is ``at+jwt`` (RFC 9068 §2.1),
    compared ASCII case-insensitively, with or without the ``application/``
    prefix (RFC 7515 §4.1.9) — exactly as the server compares it."""
    if not isinstance(typ, str) or not typ.isascii():
        return False
    lowered = typ.lower()
    if lowered.startswith("application/"):
        lowered = lowered[len("application/") :]
    return lowered == "at+jwt"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect: a JWKS URL is used as configured."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        """Decline to follow the redirect."""
        return None


def _max_age(cache_control: str | None) -> int | None:
    """The ``max-age`` of a ``Cache-Control`` header value, or ``None`` when absent or invalid."""
    if not cache_control:
        return None
    for directive in cache_control.split(","):
        name, _, value = directive.strip().partition("=")
        if name.strip().lower() == "max-age":
            value = value.strip().strip('"')
            return int(value) if value.isascii() and value.isdigit() else None
    return None


class _JwksFetcher(PyJWKClient):
    """:class:`~jwt.PyJWKClient`'s HTTP fetch, used here ONLY as the transport: the cache, the TTL,
    the stale bound and the refresh window are :class:`JwksVerifier`'s (CONTRACT.md §12.4 rule 2).

    Adds what the contract needs of the fetch: the conditional request (``If-None-Match`` with the
    held set's ``ETag``) and the response's ``Cache-Control: max-age``, both reported through
    attributes that :meth:`JwksVerifier._refresh` reads after each call.
    """

    def __init__(self, uri: str) -> None:
        """Build a fetcher for ``uri`` with no PyJWT-side cache."""
        super().__init__(uri, cache_jwk_set=False)
        #: ``ETag`` of the held set, sent as ``If-None-Match``.
        self.etag: str | None = None
        #: Set by the last ``fetch_data``: the response's ``ETag`` / ``max-age``, and whether the
        #: answer was a ``304 Not Modified``. ``None`` / ``False`` when it reported none (also the
        #: case when a test replaces ``fetch_data``).
        self.response_etag: str | None = None
        self.response_max_age: int | None = None
        self.not_modified = False

    def reset_response(self) -> None:
        """Forget what the previous fetch reported."""
        self.response_etag = None
        self.response_max_age = None
        self.not_modified = False

    def fetch_data(self) -> Any:
        """Fetch the JWKS document; ``None`` for a ``304`` answering the conditional request."""
        headers = dict(self.headers)
        if self.etag is not None:
            headers["If-None-Match"] = self.etag
        try:
            request = urllib.request.Request(url=self.uri, headers=headers)
            handlers: list[Any] = [_NoRedirect()]
            if self.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(request, timeout=self.timeout) as response:
                if response.status != 200:  # only a 200 (not any 2xx) is a fetch
                    raise PyJWKClientConnectionError("the JWKS endpoint did not answer 200")
                etag = response.headers.get("ETag")
                if etag is not None and (
                    len(etag.encode("utf-8", "replace")) > 256
                    or any(ord(c) < 0x20 or ord(c) == 0x7F for c in etag)
                ):
                    etag = None  # never stored or echoed
                self.response_etag = etag
                self.response_max_age = _max_age(response.headers.get("Cache-Control"))
                document = json.load(response)
        except HTTPError as exc:
            try:
                if exc.code == 304 and self.etag is not None:
                    self.not_modified = True
                    self.response_max_age = _max_age(exc.headers.get("Cache-Control"))
                    return None
            finally:
                exc.close()
            raise PyJWKClientConnectionError("the JWKS endpoint answered with an error") from None
        except (URLError, TimeoutError, http.client.HTTPException, ValueError) as exc:
            raise PyJWKClientConnectionError("the JWKS endpoint could not be read") from exc
        return self._as_jwk_set_payload(document)


class JwksVerifier:
    """Fetches, caches, and locally verifies AXIAM access tokens against the
    organization-wide EdDSA JWKS.

    The cache follows CONTRACT.md §12.4 rule 2 (contract 1.69): its age runs from the last
    successful fetch (a ``200`` with at least one key, or a ``304`` to the conditional request);
    its TTL is configured or the response's ``Cache-Control: max-age``, 300 s by default and at
    most 300 s; a failed refresh (transport error, other status, non-JWKS body, an empty key set)
    never replaces the held keys or moves the age, and the held keys verify until exactly TTL +
    300 s after that last success, after which every token is refused until a fetch succeeds.
    """

    def __init__(
        self,
        base_url: str,
        *,
        lifespan: float | None = None,
        jwks_url: str | None = None,
        expected_issuer: str | None = None,
        expected_audience: str | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
        revocation_feed: RevocationFeed | None = None,
        resource_metadata_url: str | None = None,
        telemetry_hook: TelemetryHook | None = None,
    ) -> None:
        """Build a verifier against ``{base_url}{JWKS_PATH}``, or against an
        explicit ``jwks_url`` when supplied.

        Args:
            base_url: The AXIAM server's base URL; ``JWKS_PATH`` is appended
                after stripping any trailing slash. Ignored when
                ``jwks_url`` is supplied.
            lifespan: JWKS cache TTL in seconds. **Unset by default**: the
                response's ``Cache-Control: max-age`` is used, else 300 s. At
                most :data:`MAX_JWKS_TTL_SECONDS` (300 s) either way: a larger
                value is clamped down, and a larger *configured* one emits one
                ``config_clamped`` event through ``telemetry_hook`` (CONTRACT.md
                §12.4 rule 2, §19 rule 6); clamping an advertised ``max-age``
                emits nothing.
            telemetry_hook: Optional §19 hook; receives the ``ConfigClamped``
                event for a clamped ``lifespan``.
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
            revocation_feed: CONTRACT.md §10.4 (contract 1.44) — the optional
                session-revocation feed. **Unset by default**, and with it
                unset this verifier behaves exactly as it did before 1.44: a
                revoked session's access token verifies locally until it
                expires, which is the §10.2 posture this narrows rather than
                replaces. It is never a control — a feed that cannot be read
                denies nothing, every §10.1 rule still decides first, and a
                token with no ``sid`` is never matched against it.
            clock_skew_seconds: Leeway applied to BOTH ``exp`` and ``nbf``
                (CONTRACT.md §10.1 rule 7), defaulting to the RECOMMENDED
                :data:`DEFAULT_CLOCK_SKEW_SECONDS`. Bounded to
                ``0 .. MAX_CLOCK_SKEW_SECONDS``.
            resource_metadata_url: CONTRACT.md §28.5 — the URL of this
                resource server's RFC 9728 protected-resource metadata
                document, as derived by
                :func:`~axiam_sdk.protected_resource_metadata`. **Unset by
                default**, and with it unset every guard built from this
                verifier behaves byte-for-byte as it did before §28
                existed: no ``WWW-Authenticate`` header on any response, no
                status changed, no body changed. Setting it is what turns
                §28 on, and it REQUIRES ``expected_audience`` to also be
                set — a resource server that publishes "tokens for me carry
                this ``aud``" and does not check ``aud`` has published a
                claim it does not honour.

        Raises:
            ValueError: if ``clock_skew_seconds`` is negative or exceeds
                :data:`MAX_CLOCK_SKEW_SECONDS` — §10.1 rule 7 forbids an
                operator-settable unbounded leeway.
            ValidationError: if ``resource_metadata_url`` is set without
                ``expected_audience`` (CONTRACT.md §28.5 rule 2), or if
                either is outside RFC 6750's syntax.
        """
        if lifespan is not None and not (math.isfinite(lifespan) and lifespan > 0):
            raise ValueError("lifespan must be a positive number of seconds")
        if not 0 <= clock_skew_seconds <= MAX_CLOCK_SKEW_SECONDS:
            raise ValueError(
                "clock_skew_seconds must be between 0 and "
                f"{MAX_CLOCK_SKEW_SECONDS} seconds (CONTRACT.md §10.1 rule 7)"
            )
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._clock_skew_seconds = clock_skew_seconds
        self._revocation_feed = revocation_feed
        self._resource_metadata_url = resource_metadata_url
        # §28.5 rule 2: validated eagerly, at construction — before the first
        # request rather than as a surprise on the first guard built from
        # this verifier. Discarded here; guard factories rebuild it (cheaply
        # — pure string operations, no network I/O) with their own operation
        # name and, where relevant, their route's own `scope`.
        mcp_guard_challenges(expected_audience, resource_metadata_url, "JwksVerifier")
        resolved_jwks_url = jwks_url if jwks_url is not None else base_url.rstrip("/") + JWKS_PATH
        # The fetcher is only the HTTP transport. The cache lives below, because PyJWT's cache
        # drops the held set at its TTL and cannot keep it through a failed refresh, which is
        # exactly what §12.4 rule 2 (stale-if-error, bounded) requires.
        self._client = _JwksFetcher(resolved_jwks_url)
        #: A configured TTL, clamped to the contract's 300 s; ``None`` = use the advertised one.
        self._configured_ttl: float | None = None
        if lifespan is not None:
            self._configured_ttl = min(float(lifespan), float(MAX_JWKS_TTL_SECONDS))
            if lifespan > MAX_JWKS_TTL_SECONDS:
                TelemetryDispatcher(telemetry_hook).emit(
                    ConfigClamped(
                        setting="lifespan",
                        requested=f"{lifespan:g}",
                        effective=str(MAX_JWKS_TTL_SECONDS),
                        contract_reference="§12.4 rule 2",
                    )
                )
        #: The held signing keys, the instant of the last SUCCESSFUL fetch (the age's anchor) and
        #: the TTL in force since it.
        self._held: list[PyJWK] | None = None
        self._anchor: float = 0.0
        self._ttl: float = (
            self._configured_ttl if self._configured_ttl is not None else _DEFAULT_LIFESPAN_SECONDS
        )
        #: When a refresh was last attempted and either failed or was forced by an unknown
        #: ``kid``; opens the 60 s window in which no further refresh is attempted.
        self._last_attempt: float | None = None
        #: ``ETag`` of the held set, for the conditional refresh.
        self._etag_of_held: str | None = None
        self._refetch_lock = threading.Lock()
        # §13.4 observation 6 — latches the slug-vs-UUID diagnostic to one
        # emission, so a stream of bad tokens cannot turn it into a log flood.
        self._slug_comparand_warned = False

    @property
    def expected_audience(self) -> str | None:
        """§10.1 row 6's expected audience, as configured at construction —
        readable so :func:`~axiam_sdk.fastapi.serve_protected_resource_metadata`
        can cross-check it against a §28 document's ``resource`` (§28.5
        rule 3)."""
        return self._expected_audience

    @property
    def resource_metadata_url(self) -> str | None:
        """CONTRACT.md §28.5's option, as configured at construction. ``None``
        when §28 is off."""
        return self._resource_metadata_url

    def mcp_challenges(self, operation: str, scope: str | None = None) -> McpGuardChallenges | None:
        """CONTRACT.md §28.5 — this verifier's precomputed §28 challenge
        values for a guard named ``operation`` and, where the route names
        one, its ``scope``.

        Called by every FastAPI guard factory (``require_authenticated_user``,
        ``require_access``, ``require_role``) at factory-construction time —
        route-setup time, never per-request. Returns ``None`` when
        :attr:`resource_metadata_url` is unset, which is how "§28 is off"
        stays byte-for-byte indistinguishable from "§28 is absent" (§28.5
        rule 1).
        """
        return mcp_guard_challenges(
            self._expected_audience, self._resource_metadata_url, operation, scope
        )

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
            AuthError: with ``reason`` ``invalid_alg`` (``alg`` is not EdDSA), ``unknown_kid``
                (no ``kid``, or no JWKS key matches it; at most one re-fetch per 60 s window,
                the cache survives it) ``token_expired`` or ``invalid_signature``.
        """
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise AuthError(
                "logout token validation failed (invalid_alg): malformed token header",
                reason="invalid_alg",
            ) from exc
        if header.get("alg") != "EdDSA":
            raise AuthError(
                "logout token validation failed (invalid_alg): only EdDSA is accepted",
                reason="invalid_alg",
            )
        # §12.7.3 rule 1 (contract 1.69): the key is selected by ``kid`` and by nothing else.
        # A token with no ``kid`` (a pre-1.69 server's) is refused before any key lookup, so a
        # one-key JWKS cannot make it verify.
        if not header.get("kid"):
            raise AuthError(
                "logout token validation failed (unknown_kid): the token carries no kid",
                reason="unknown_kid",
            )

        try:
            signing_key = self._get_signing_key(token)
        except PyJWTError as exc:
            # Unknown kid, or an empty/malformed keyset after the verifier's one rate-limited
            # forced re-fetch.
            raise AuthError(
                "logout token validation failed (unknown_kid): no JWKS key matches the token's kid",
                reason="unknown_kid",
            ) from exc

        try:
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
        except (ExpiredSignatureError, ImmatureSignatureError, InvalidIssuedAtError) as exc:
            raise AuthError(
                "logout token validation failed (token_expired): outside its validity window",
                reason="token_expired",
            ) from exc
        except PyJWTError as exc:
            raise AuthError(
                "logout token validation failed (invalid_signature): the token is not valid",
                reason="invalid_signature",
            ) from exc

    def _verify_claims(self, token: str, *, expected_tenant_id: str | None) -> dict[str, Any]:
        """CONTRACT.md §10.1 rules **1-8** — everything except the sender
        constraint, which every caller of this private method still owes
        (rule 9). Shared by :meth:`verify_access_token` (which applies rule 9
        with no evidence, so any ``cnf``-bearing token is refused) and
        :meth:`verify_with_proofs` (which applies it with the caller's
        evidence) — one implementation of rules 1-8, never two to keep in
        sync.

        The eight rules, in order:

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

        # Rule 10 (contract 1.68, N14): a header that names a ``typ`` must name
        # an access token. Absent ``typ`` is not rejected by this rule.
        if "typ" in header and not _is_access_token_typ(header["typ"]):
            raise AuthError("token typ is not an access token (at+jwt)")

        # Rule 12 (contract 1.68): the key is selected by ``kid`` and by nothing
        # else. ``_get_signing_key`` reads the ``kid`` from the header and refuses
        # a token with none (no "only key in the set" fallback), so no explicit
        # check is needed here; ``test_access_token_kind`` pins that behaviour.
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

        # Rule 11 (contract 1.68, N14): a ``purpose`` member marks an MFA
        # challenge, MFA setup or WebAuthn state token, which AXIAM signs with
        # this same key. Read from the verified payload itself, whatever its
        # value (``null`` included) and whatever ``typ`` says.
        if "purpose" in claims:
            raise AuthError("token carries a purpose claim and is not an access token")

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

        # CONTRACT.md §10.4 rules 4 and 6 (contract 1.44). Runs LAST: every
        # §10.1 rule has already decided, and the feed can only turn an accept
        # into a reject. A token with no `sid` names no session and is never
        # matched — there is no fallback to `jti`, which would match nothing
        # while looking like it worked.
        if self._revocation_feed is not None:
            sid = claims.get("sid")
            if isinstance(sid, str) and sid and self._revocation_feed.is_revoked(sid):
                raise AuthError(
                    "the session behind this access token has been revoked (CONTRACT.md §10.4)"
                )

        return claims

    def verify_access_token(self, token: str, *, expected_tenant_id: str | None) -> dict[str, Any]:
        """Apply the **complete** CONTRACT.md §10.1 minimum local-verification
        set — rules 1-8 (:meth:`_verify_claims`) **plus rule 9** — to
        ``token`` and return its claims. This is the documented guard entry
        point; every SDK route guard and middleware goes through it
        (``fastapi.require_auth``/``require_user``/``require_access``, the
        Django middleware, the §11/§28 guards).

        **Rule 9 is applied with no transport evidence**, because this call
        site has none to offer: a token carrying ``cnf`` is refused outright
        (CONTRACT.md §10.1 rule 9 — "a token carrying `cnf` is not a bearer
        token, and MUST NOT be accepted as one"). This is deliberately a
        fix, not a new feature: before it, this entry point verified rules
        1-8 and returned, silently accepting a certificate-bound or
        DPoP-bound token as an ordinary bearer credential — exactly the
        ``SEC-071``/``SEC-080`` shape rule 9 exists to close, and load-bearing
        now that §6.1's device login mints certificate-bound tokens by
        default (contract 1.51): a device token lifted off a device would
        otherwise open every guarded route this SDK's guards protect.

        An unbound token (no ``cnf`` claim at all) is unaffected either way
        — rule 9's whole point is "constrains tokens that claim a
        constraint; it does not make certificates mandatory." A resource
        server that wants to *accept* a sender-constrained token, having
        proven the caller holds the confirmed key, calls
        :meth:`verify_with_proofs` instead, supplying that evidence.

        Args:
            token: The compact-serialized access token presented by the caller.
            expected_tenant_id: The tenant this deployment serves. ``None`` or
                empty is a configuration error and fails closed (rule 4).

        Returns:
            The decoded claims dict, once every rule 1-9 has passed.

        Raises:
            AuthError: on any rule violation — the single failure type
                callers map to HTTP 401 (CONTRACT.md §2/§10).
        """
        claims = self._verify_claims(token, expected_tenant_id=expected_tenant_id)
        verify_token_binding(claims, certificate_thumbprint=None, dpop_thumbprint=None)
        return claims

    def verify_with_proofs(
        self,
        token: str,
        *,
        expected_tenant_id: str | None,
        certificate_thumbprint: str | None = None,
        dpop_thumbprint: str | None = None,
    ) -> dict[str, Any]:
        """:meth:`_verify_claims`'s rules 1-8 plus the **full** CONTRACT.md
        §10.1 rule 9 (RFC 8705 §3 / RFC 9449 §6, contract 1.16) — with
        transport evidence, so a properly-proven sender-constrained token is
        *accepted* rather than refused outright.

        This is the guard entry point for a resource server that accepts
        certificate-bound **and/or** DPoP-bound access tokens. Pass
        whichever evidence this connection/request actually has; either or
        both may be ``None``, in which case a token bound by that method is
        refused (an unverifiable constraint is never read as unconstrained
        — CONTRACT.md §10.1 rule 9's three weight-bearing rows). An unbound
        token is accepted regardless of what evidence is or is not supplied.

        :meth:`verify_sender_constrained` is the certificate-only shape of
        this call, kept for the transports that can only ever produce a
        certificate thumbprint; this is the one to use otherwise.

        Args:
            token: The compact-serialized access token presented by the caller.
            expected_tenant_id: As :meth:`verify_access_token`.
            certificate_thumbprint: The RFC 8705 §3.1 ``x5t#S256`` of the peer
                certificate on this connection, or ``None``.
            dpop_thumbprint: The ``jkt`` of a DPoP proof **this caller has
                already verified** for this request, or ``None`` — never a
                thumbprint read off an unverified proof (§21.7).

        Returns:
            The decoded claims dict.

        Raises:
            AuthError: everything :meth:`_verify_claims` raises, plus the
                rejecting rows of :func:`verify_token_binding`.
        """
        claims = self._verify_claims(token, expected_tenant_id=expected_tenant_id)
        verify_token_binding(
            claims,
            certificate_thumbprint=certificate_thumbprint,
            dpop_thumbprint=dpop_thumbprint,
        )
        return claims

    def verify_sender_constrained(
        self,
        token: str,
        *,
        expected_tenant_id: str | None,
        presented_thumbprint: str | None,
    ) -> dict[str, Any]:
        """:meth:`_verify_claims`'s rules 1-8 plus CONTRACT.md §10.1
        **rule 9**'s certificate half (RFC 8705 §3, contract 1.15) — the
        certificate-only shape of :meth:`verify_with_proofs`, kept for
        transports that can only ever produce a certificate thumbprint.

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
        claims = self._verify_claims(token, expected_tenant_id=expected_tenant_id)
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

        CONTRACT.md §12.4 rule 2 (contract 1.69): within the TTL the held set answers with no
        fetch; past it a refresh is due, at most one attempt per 60 s window, a failed attempt
        included. A failed refresh keeps the held keys, which verify until exactly TTL + 300 s
        after the last successful fetch; then every token is refused until a fetch succeeds. An
        unknown ``kid`` is one forced refresh per window, and when it fails the token is refused
        and the held set and the age are untouched.
        """
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise PyJWKClientError("the token carries no kid")
        with self._refetch_lock:
            now = time.monotonic()
            refreshed = False
            age = now - self._anchor
            if self._held is None or age < 0 or age >= self._ttl:  # age < 0: the clock moved back
                if self._may_attempt(now):
                    refreshed = self._refresh(now, forced=False)
            if self._held is None:
                raise PyJWKClientError("the JWKS endpoint is unavailable")
            age = now - self._anchor
            if age < 0 or age > self._ttl + JWKS_MAX_STALE_SECONDS:
                # Past the bound: held keys are never used, whatever the cause.
                raise PyJWKClientError("the JWKS is stale and could not be refreshed")

            cached = PyJWKClient.match_kid(self._held, kid)
            if cached is not None:
                return cached
            if refreshed or not self._may_attempt(now):
                # The set was just fetched, or the window is closed: the kid is unknown.
                raise PyJWKClientError("no JWKS key matches the token's kid")

            # One re-fetch per window; its failure counts toward that window and changes nothing
            # else.
            if self._refresh(now, forced=True) and self._held is not None:
                fresh = PyJWKClient.match_kid(self._held, kid)
                if fresh is not None:
                    return fresh
            raise PyJWKClientError("no JWKS key matches the token's kid")

    def _may_attempt(self, now: float) -> bool:
        """Whether the 60 s refresh window is open (no failed or forced attempt inside it)."""
        return (
            self._last_attempt is None
            or now - self._last_attempt >= _FORCED_REFETCH_MIN_INTERVAL_SECONDS
        )

    def _refresh(self, now: float, *, forced: bool) -> bool:
        """Fetch the JWKS and report whether it SUCCEEDED (§12.4 rule 2): a ``200`` holding at
        least one signing key, or a ``304`` to the conditional request. Only a success replaces the
        held keys and moves the anchor; anything else (transport error, other status, a body that
        is not a JWKS, an empty key set) leaves both alone and opens the refresh window."""
        client = self._client
        client.reset_response()
        client.etag = self._etag_of_held
        try:
            data = client.fetch_data()
            if data is None:
                if not client.not_modified or self._held is None:
                    raise PyJWKClientError("no JWKS document")
                keys = self._held
            else:
                entries = data.get("keys")
                if not isinstance(entries, list):
                    raise PyJWKClientError("not a JWKS document")
                jwks = [e for e in entries if isinstance(e, dict) and isinstance(e.get("kty"), str)]
                if not jwks:
                    raise PyJWKClientError("not a JWKS document")
                keys = []
                for entry in jwks:  # an unusable but well-formed JWK counts, and is skipped
                    try:
                        key = PyJWK.from_dict(entry)
                    except Exception:  # noqa: BLE001
                        continue
                    if key.public_key_use in ("sig", None) and key.key_id:
                        keys.append(key)
        except Exception:  # noqa: BLE001 -- every failure is a failed refresh, never an escape
            self._last_attempt = now
            return False
        if forced:
            self._last_attempt = now
        self._held = keys
        self._anchor = now
        self._etag_of_held = client.response_etag if data is not None else self._etag_of_held
        advertised = client.response_max_age
        if self._configured_ttl is not None:
            self._ttl = self._configured_ttl
        elif advertised is not None:
            self._ttl = float(min(advertised, MAX_JWKS_TTL_SECONDS))
        elif data is not None:
            self._ttl = float(_DEFAULT_LIFESPAN_SECONDS)
        return True


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

    This is the **narrow** entry point, kept for transports that can only ever
    produce a certificate thumbprint. It refuses a DPoP-bound token outright
    rather than ignoring the ``jkt`` it cannot check — see
    :func:`verify_token_binding` for the full rule.

    The five cases:

    ===========================  ==========================  ==========
    token's ``cnf``              ``presented_thumbprint``    result
    ===========================  ==========================  ==========
    absent                       anything                    returns
    ``x5t#S256``                 equal                       returns
    ``x5t#S256``                 different, or ``None``      raises
    names ``jkt`` (1.16)         anything                    raises
    present, names neither       anything                    raises
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
        # Includes the DPoP case: this entry point has no proof to check, so a
        # ``jkt``-bound token is refused rather than silently downgraded.
        raise AuthError(
            "token carries a cnf confirmation naming a method this entry point cannot verify "
            "(CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an absent one; "
            "use verify_token_binding for DPoP)"
        )
    # A token naming BOTH methods is a conjunction (contract 1.16): this
    # function can establish one half and must not answer for the whole.
    # Refusing here is what stops "check whichever we can".
    jkt = cnf.get("jkt")
    if isinstance(jkt, str) and jkt:
        raise AuthError(
            "token names both a certificate and a DPoP key; both must hold "
            "(CONTRACT.md §10.1 rule 9) — use verify_token_binding"
        )
    if presented_thumbprint is None:
        raise AuthError("token is certificate-bound but no client certificate was presented")
    # Constant-time. The thumbprint is usually public — it derives from a
    # certificate sent in the clear during the handshake — so this is defence
    # in depth. It matters most for a self-signed client, where the registered
    # thumbprint is the whole credential.
    if not hmac.compare_digest(expected, presented_thumbprint):
        raise AuthError("token is bound to a different client certificate than the one presented")


def verify_token_binding(
    claims: Mapping[str, Any],
    *,
    certificate_thumbprint: str | None = None,
    dpop_thumbprint: str | None = None,
) -> None:
    """CONTRACT.md §10.1 **rule 9** — enforce a token's sender constraint
    against **every** proof the caller presented (contract 1.16).

    This is the full rule, and the one to use unless your transport genuinely
    cannot produce a DPoP thumbprint.

    Keyword-only on purpose: two same-typed optional thumbprints are exactly
    the pair a positional call transposes silently, and transposing them would
    check each proof against the wrong confirmation.

    The ten cases:

    =========================  ==============  ==========  ==========
    token's ``cnf``            certificate     DPoP        result
    =========================  ==============  ==========  ==========
    absent                     anything        anything    returns
    ``x5t#S256``               equal           ignored     returns
    ``x5t#S256``               different       ignored     raises
    ``x5t#S256``               ``None``        ignored     raises
    ``jkt``                    ignored         equal       returns
    ``jkt``                    ignored         different   raises
    ``jkt``                    ignored         ``None``    raises
    both                       equal           equal       returns
    both                       wrong/missing   —           raises
    present, names neither     anything        anything    raises
    =========================  ==============  ==========  ==========

    Two rows carry the weight. **Both named is a conjunction**: an operator who
    turned on two constraints asked for two, and satisfying the more convenient
    one is not compliance. **Names neither is a refusal**: a confirmation this
    SDK cannot interpret is an unverifiable constraint, and reading it as
    "unconstrained" is the exact downgrade rule 9 exists to prevent. That
    includes an *empty* ``cnf`` — also how proto3 delivers an empty
    ``CnfClaim`` over gRPC (§10.3 rule 3).

    .. warning::
       This function compares thumbprints; it does **not** verify proofs.
       Supply ``dpop_thumbprint`` only after checking the proof's signature,
       ``htm``, ``htu``, ``iat`` and ``jti`` for *this* request. A thumbprint
       lifted off an unverified proof would let a proof captured from any
       other endpoint authorize this one.

    Args:
        claims: The verified claims dict.
        certificate_thumbprint: The peer certificate's ``x5t#S256``, or ``None``.
        dpop_thumbprint: The ``jkt`` of an **already verified** DPoP proof, or
            ``None``.

    Raises:
        AuthError: on any rejecting row.
    """
    cnf = claims.get("cnf")
    # The fast path, and the common one. First on purpose: an unbound token is
    # accepted with no proofs at all, which is what keeps existing deployments
    # working when a guard adopts this rule.
    if cnf is None:
        return
    if not isinstance(cnf, Mapping):
        raise AuthError("token cnf claim is malformed")

    expected_cert = cnf.get("x5t#S256")
    expected_cert = expected_cert if isinstance(expected_cert, str) and expected_cert else None
    expected_jkt = cnf.get("jkt")
    expected_jkt = expected_jkt if isinstance(expected_jkt, str) and expected_jkt else None

    if expected_cert is None and expected_jkt is None:
        raise AuthError(
            "token carries a cnf confirmation naming no method this SDK can verify "
            "(CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an absent one)"
        )

    # Each arm that applies must pass. Two independent checks rather than a
    # branch on the pair, precisely so "both named" needs no case of its own —
    # it is simply where both run.
    if expected_cert is not None:
        if certificate_thumbprint is None:
            raise AuthError("token is certificate-bound but no client certificate was presented")
        if not hmac.compare_digest(expected_cert, certificate_thumbprint):
            raise AuthError(
                "token is bound to a different client certificate than the one presented"
            )

    if expected_jkt is not None:
        if dpop_thumbprint is None:
            raise AuthError("token is DPoP-bound but no verified DPoP proof was presented")
        if not hmac.compare_digest(expected_jkt, dpop_thumbprint):
            raise AuthError("token is bound to a different DPoP key than the one presented")


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
