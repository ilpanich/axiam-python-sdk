"""CONTRACT.md §10.1 minimum local-verification set — conformance tests.

Every §10.1 rule gets a positive case (proving the suite is non-vacuous) and
the required negative cases, exercised at BOTH surfaces that turn a token into
an identity locally: :meth:`~axiam_sdk._jwks.JwksVerifier.verify_access_token`
itself, the FastAPI ``Depends(require_authenticated_user)`` dependency, and the
Django ``AxiamAuthMiddleware``.

The required negative set (§10.1, verbatim): expired token; token with **no**
``exp``; token with a non-numeric ``exp``; token whose ``nbf`` is in the
future; token for a **different tenant**; token with no ``tenant_id``; and
``alg: none`` plus an HS-signed token bearing an EdDSA key id. Because this SDK
now supports issuer/audience configuration, a mismatch case for each is
included too.

Why this file exists rather than trusting PyJWT's defaults (the ``SEC-080``
defect, reproduced empirically against PyJWT 2.13): PyJWT validates ``exp``
"by default", but that default only fires when the claim is PRESENT — a token
carrying no ``exp`` at all decodes cleanly and is a permanent credential. PyJWT
also coerces ``exp`` with ``int()``, so a numeric *string* passes its check.
Both are closed by ``verify_access_token``, and both are asserted here.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any

import django
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings as django_settings
from django.http import HttpResponse
from django.test import RequestFactory
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

if not django_settings.configured:
    django_settings.configure(
        DEBUG=True,
        USE_TZ=True,
        AXIAM_JWKS_BASE_URL="https://axiam.example.test",
        AXIAM_TENANT_SLUG="acme",
    )
    django.setup()

from axiam_sdk._errors import AuthError  # noqa: E402
from axiam_sdk._jwks import (  # noqa: E402
    DEFAULT_CLOCK_SKEW_SECONDS,
    MAX_CLOCK_SKEW_SECONDS,
    RECOMMENDED_RESOURCE_SERVER_AUDIENCE,
    JwksVerifier,
)
from axiam_sdk.django.middleware import AxiamAuthMiddleware  # noqa: E402
from axiam_sdk.fastapi import AxiamUser, require_authenticated_user  # noqa: E402

_TENANT = "acme"
_OTHER_TENANT = "other-tenant"
_KID = "test-kid-1"


def _b64url(data: bytes) -> str:
    """URL-safe, unpadded base64 of ``data`` (JWK ``x`` encoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_ed25519_keypair_and_jwk(kid: str) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    """Generate an Ed25519 keypair plus the matching public JWK dict."""
    private_key = Ed25519PrivateKey.generate()
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw_public),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }


def _sign(private_key: Ed25519PrivateKey, claims: dict[str, Any]) -> str:
    """Sign ``claims`` as an EdDSA JWS carrying the fixture ``kid`` header."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": _KID})


def _unsigned_alg_none(claims: dict[str, Any]) -> str:
    """Hand-assemble an ``alg: none`` token with the fixture ``kid`` and an
    empty signature — ``jwt.encode`` will not emit one."""
    header = _b64url(b'{"alg":"none","typ":"JWT","kid":"' + _KID.encode() + b'"}')
    import json

    payload = _b64url(json.dumps(claims).encode())
    return f"{header}.{payload}."


class _FakeJwksEndpoint:
    """Stands in for ``GET /oauth2/jwks``; counts fetches so a test can prove
    a rejection happened WITHOUT any key lookup (§10.1 rule 1)."""

    def __init__(self, jwk_dicts: list[dict[str, Any]]) -> None:
        """Serve ``jwk_dicts`` as the keyset, starting at zero fetches."""
        self.jwk_dicts = jwk_dicts
        self.call_count = 0

    def bind(self, verifier: JwksVerifier) -> None:
        """Redirect ``verifier``'s PyJWKClient at this in-process fake."""
        verifier._client.fetch_data = self._fetch_data  # type: ignore[method-assign]

    def _fetch_data(self) -> dict[str, Any]:
        """Return the keyset, counting the call."""
        self.call_count += 1
        return {"keys": self.jwk_dicts}


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    """An Ed25519 signing key plus its published JWK."""
    return _make_ed25519_keypair_and_jwk(_KID)


@pytest.fixture
def valid_claims() -> dict[str, Any]:
    """A fully §10.1-conformant claim set: numeric ``exp`` in the future,
    matching ``tenant_id``, and a ``sub``."""
    return {"sub": "user-1", "tenant_id": _TENANT, "exp": time.time() + 3600}


def _verifier(jwk_dict: dict[str, Any], **kwargs: Any) -> tuple[JwksVerifier, _FakeJwksEndpoint]:
    """Build a verifier bound to a fake JWKS endpoint serving ``jwk_dict``."""
    verifier = JwksVerifier("https://axiam.example.test", **kwargs)
    endpoint = _FakeJwksEndpoint([jwk_dict])
    endpoint.bind(verifier)
    return verifier, endpoint


# --- Rule 1: signature, alg pinned to EdDSA BEFORE key lookup --------------


def test_valid_token_is_accepted(keypair, valid_claims) -> None:
    """Non-vacuity anchor: the fully-conformant token IS accepted, so every
    rejection below is attributable to the rule under test."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    claims = verifier.verify_access_token(
        _sign(private_key, valid_claims), expected_tenant_id=_TENANT
    )
    assert claims["sub"] == "user-1"
    assert claims["tenant_id"] == _TENANT


def test_alg_none_is_rejected_without_any_key_lookup(keypair, valid_claims) -> None:
    """§10.1 rule 1: ``alg: none`` MUST be rejected without consulting a key."""
    _private_key, jwk_dict = keypair
    verifier, endpoint = _verifier(jwk_dict)
    with pytest.raises(AuthError, match="only EdDSA is accepted"):
        verifier.verify_access_token(_unsigned_alg_none(valid_claims), expected_tenant_id=_TENANT)
    assert endpoint.call_count == 0


def test_hs256_token_bearing_an_eddsa_kid_is_rejected_without_key_lookup(
    keypair, valid_claims
) -> None:
    """§10.1 rule 1: HS-family confusion — an HS256 token whose ``kid`` names
    the published EdDSA key MUST be rejected before any key lookup, so the
    Ed25519 public key can never be pressed into service as an HMAC secret."""
    _private_key, jwk_dict = keypair
    verifier, endpoint = _verifier(jwk_dict)
    hs_token = jwt.encode(
        valid_claims, "not-really-a-secret-key-32-bytes!", algorithm="HS256", headers={"kid": _KID}
    )
    with pytest.raises(AuthError, match="only EdDSA is accepted"):
        verifier.verify_access_token(hs_token, expected_tenant_id=_TENANT)
    assert endpoint.call_count == 0


def test_token_signed_by_a_foreign_key_is_rejected(keypair, valid_claims) -> None:
    """§10.1 rule 1: a well-formed EdDSA token signed by a key that is not the
    published one MUST fail signature verification."""
    _private_key, jwk_dict = keypair
    foreign_key, _foreign_jwk = _make_ed25519_keypair_and_jwk(_KID)
    verifier, _endpoint = _verifier(jwk_dict)
    with pytest.raises(AuthError):
        verifier.verify_access_token(_sign(foreign_key, valid_claims), expected_tenant_id=_TENANT)


def test_unparsable_token_is_rejected_as_auth_error(keypair) -> None:
    """§10.1 fail-closed: garbage that is not a JWT at all must surface as the
    ordinary rejection, never as an unhandled library exception in a guard."""
    _private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    with pytest.raises(AuthError, match="malformed token header"):
        verifier.verify_access_token("this-is-not-a-jwt", expected_tenant_id=_TENANT)


def test_token_with_an_unknown_kid_is_rejected(keypair, valid_claims) -> None:
    """§10.1 rule 1: a token whose ``kid`` names no published key is rejected
    after the single bounded forced refetch, as an ``AuthError``."""
    _private_key, jwk_dict = keypair
    other_key, _other_jwk = _make_ed25519_keypair_and_jwk("some-other-kid")
    verifier, _endpoint = _verifier(jwk_dict)
    with pytest.raises(AuthError, match="no JWKS key matches"):
        verifier.verify_access_token(
            jwt.encode(
                valid_claims,
                other_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
                algorithm="EdDSA",
                headers={"kid": "some-other-kid"},
            ),
            expected_tenant_id=_TENANT,
        )


# --- Rule 2: exp REQUIRED and numeric --------------------------------------


def test_expired_token_is_rejected(keypair, valid_claims) -> None:
    """§10.1 rule 2: an ``exp`` in the past (beyond the skew) MUST be rejected."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "exp": time.time() - 3600})
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_token_with_no_exp_is_rejected(keypair, valid_claims) -> None:
    """§10.1 rule 2, the SEC-080 case: a token with NO ``exp`` is a permanent
    credential. PyJWT accepts it (its verify_exp default only fires when the
    claim is present); ``verify_access_token`` MUST NOT."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    claims = {k: v for k, v in valid_claims.items() if k != "exp"}
    with pytest.raises(AuthError, match="missing the required exp claim"):
        verifier.verify_access_token(_sign(private_key, claims), expected_tenant_id=_TENANT)


def test_pyjwt_alone_would_accept_a_token_with_no_exp(keypair, valid_claims) -> None:
    """Pins the library gap this SDK compensates for: the SAME no-``exp``
    token that ``verify_access_token`` rejects above is happily decoded by a
    bare ``jwt.decode`` with PyJWT's defaults. If a future PyJWT tightens
    this, the test fails loudly rather than leaving dead defensive code."""
    private_key, jwk_dict = keypair
    claims = {k: v for k, v in valid_claims.items() if k != "exp"}
    token = _sign(private_key, claims)
    decoded = jwt.decode(token, private_key.public_key(), algorithms=["EdDSA"])
    assert "exp" not in decoded


@pytest.mark.parametrize("bad_exp", ["not-a-number", "9999999999", True, None, [1], {"a": 1}])
def test_non_numeric_exp_is_rejected(keypair, valid_claims, bad_exp) -> None:
    """§10.1 rule 2 / fail-closed: an ``exp`` of the wrong JSON type MUST be
    rejected — including the numeric *string* ``"9999999999"``, which PyJWT
    silently coerces with ``int()``, and ``True``, which is an ``int``
    subclass in Python."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "exp": bad_exp})
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


# --- Rule 3: nbf honoured when present -------------------------------------


def test_future_nbf_is_rejected(keypair, valid_claims) -> None:
    """§10.1 rule 3: a token whose ``nbf`` is in the future (beyond the skew)
    MUST be rejected."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "nbf": time.time() + 3600})
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_absent_nbf_is_valid(keypair, valid_claims) -> None:
    """§10.1 rule 3: an absent ``nbf`` is valid — the rule is conditional."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    assert "nbf" not in valid_claims
    assert verifier.verify_access_token(
        _sign(private_key, valid_claims), expected_tenant_id=_TENANT
    )


def test_non_numeric_nbf_is_rejected(keypair, valid_claims) -> None:
    """§10.1 fail-closed: a present-but-wrong-typed ``nbf`` MUST be rejected
    rather than treated as absent."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "nbf": "soon"})
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


# --- Rule 4: tenant_id REQUIRED and asserted -------------------------------


def test_different_tenant_is_rejected(keypair, valid_claims) -> None:
    """§10.1 rule 4: the org-wide JWKS means a signature-valid token may
    belong to another tenant; it MUST be rejected."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "tenant_id": _OTHER_TENANT})
    with pytest.raises(AuthError, match="tenant_id does not match"):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_token_with_no_tenant_id_is_rejected(keypair, valid_claims) -> None:
    """§10.1 rule 4: an absent ``tenant_id`` fails closed — "nothing to
    check" is not success."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    claims = {k: v for k, v in valid_claims.items() if k != "tenant_id"}
    with pytest.raises(AuthError):
        verifier.verify_access_token(_sign(private_key, claims), expected_tenant_id=_TENANT)


@pytest.mark.parametrize("no_tenant", [None, ""])
def test_no_configured_tenant_fails_closed(keypair, valid_claims, no_tenant) -> None:
    """§10.1 rule 4: with NO configured tenant to compare against, the guard
    MUST fail closed rather than skip the comparison."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    with pytest.raises(AuthError, match="no configured tenant"):
        verifier.verify_access_token(_sign(private_key, valid_claims), expected_tenant_id=no_tenant)


def test_non_string_tenant_id_is_rejected(keypair, valid_claims) -> None:
    """§10.1 fail-closed: a ``tenant_id`` of the wrong JSON type is rejected."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "tenant_id": 42})
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


# --- Rules 5 & 6: iss / aud, conditional on configuration ------------------


def test_issuer_not_configured_means_no_issuer_check(keypair, valid_claims) -> None:
    """§10.1 rule 5 is CONDITIONAL: with no expected issuer configured, an
    arbitrary (or absent) ``iss`` is not checked."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "iss": "https://whoever.example"})
    assert verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_configured_issuer_accepts_a_match(keypair, valid_claims) -> None:
    """§10.1 rule 5, non-vacuity: the matching ``iss`` is accepted."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict, expected_issuer="https://axiam.example.test")
    token = _sign(private_key, {**valid_claims, "iss": "https://axiam.example.test"})
    assert verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_configured_issuer_rejects_a_mismatch(keypair, valid_claims) -> None:
    """§10.1 rule 5: a configured issuer MUST reject a mismatched ``iss``."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict, expected_issuer="https://axiam.example.test")
    token = _sign(private_key, {**valid_claims, "iss": "https://evil.example"})
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_configured_issuer_rejects_an_absent_iss(keypair, valid_claims) -> None:
    """§10.1 fail-closed: with an issuer configured, an absent ``iss`` is a
    rejection, not a skipped check."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict, expected_issuer="https://axiam.example.test")
    with pytest.raises(AuthError):
        verifier.verify_access_token(_sign(private_key, valid_claims), expected_tenant_id=_TENANT)


def test_audience_not_configured_means_no_audience_check(keypair, valid_claims) -> None:
    """§10.1 rule 6 is CONDITIONAL: with no expected audience configured, a
    token carrying an arbitrary ``aud`` is still accepted (PyJWT on its own
    would reject an ``aud``-bearing token here — this SDK must not)."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "aud": "some-other-api"})
    assert verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_configured_audience_accepts_a_match(keypair, valid_claims) -> None:
    """§10.1 rule 6, non-vacuity: the recommended ``axiam:user`` audience is
    accepted when configured and present."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(
        jwk_dict, expected_audience=RECOMMENDED_RESOURCE_SERVER_AUDIENCE
    )
    token = _sign(private_key, {**valid_claims, "aud": [RECOMMENDED_RESOURCE_SERVER_AUDIENCE, "x"]})
    assert verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_configured_audience_rejects_a_mismatch(keypair, valid_claims) -> None:
    """§10.1 rule 6: a configured audience MUST reject a token whose ``aud``
    does not contain it."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(
        jwk_dict, expected_audience=RECOMMENDED_RESOURCE_SERVER_AUDIENCE
    )
    token = _sign(private_key, {**valid_claims, "aud": "someone-else"})
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_configured_audience_rejects_an_absent_aud(keypair, valid_claims) -> None:
    """§10.1 fail-closed: with an audience configured, an absent ``aud`` is a
    rejection."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(
        jwk_dict, expected_audience=RECOMMENDED_RESOURCE_SERVER_AUDIENCE
    )
    with pytest.raises(AuthError):
        verifier.verify_access_token(_sign(private_key, valid_claims), expected_tenant_id=_TENANT)


# --- Rule 7: named, bounded clock skew -------------------------------------


def test_default_clock_skew_is_the_recommended_sixty_seconds() -> None:
    """§10.1 rule 7: the leeway is a NAMED constant at the RECOMMENDED value."""
    assert DEFAULT_CLOCK_SKEW_SECONDS == 60


def test_clock_skew_absorbs_a_just_expired_token(keypair, valid_claims) -> None:
    """§10.1 rule 7: the leeway applies to ``exp``."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "exp": time.time() - 10})
    assert verifier.verify_access_token(token, expected_tenant_id=_TENANT)


def test_clock_skew_absorbs_a_just_future_nbf(keypair, valid_claims) -> None:
    """§10.1 rule 7: the same leeway applies to ``nbf``."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "nbf": time.time() + 10})
    assert verifier.verify_access_token(token, expected_tenant_id=_TENANT)


@pytest.mark.parametrize("bad_skew", [-1, MAX_CLOCK_SKEW_SECONDS + 1, 10**9])
def test_clock_skew_cannot_be_configured_unbounded(bad_skew) -> None:
    """§10.1 rule 7: the leeway MUST NOT be operator-settable to an unbounded
    value — out-of-range configuration is refused at construction time."""
    with pytest.raises(ValueError, match="clock_skew_seconds"):
        JwksVerifier("https://axiam.example.test", clock_skew_seconds=bad_skew)


def test_clock_skew_may_be_tightened_to_zero(keypair, valid_claims) -> None:
    """Rule 7 bounds the leeway from above, not below: an operator may pin it
    to zero, and a just-expired token is then rejected."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict, clock_skew_seconds=0)
    token = _sign(private_key, {**valid_claims, "exp": time.time() - 10})
    with pytest.raises(AuthError):
        verifier.verify_access_token(token, expected_tenant_id=_TENANT)


# --- The signature-only primitive stays available, and stays obvious -------


def test_signature_only_primitive_is_named_to_advertise_its_omission(keypair, valid_claims) -> None:
    """§10.1: a raw signature-only primitive MAY be exposed for integrators
    writing their own policy, but its name must make the omission obvious.
    It accepts a token with no ``exp`` and a foreign ``tenant_id`` — which is
    exactly why the SDK's own guards never call it."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {"sub": "user-1", "tenant_id": _OTHER_TENANT})
    assert verifier.verify_signature_only_unchecked(token)["sub"] == "user-1"
    assert not hasattr(verifier, "verify"), "the ambiguously-named verify() must not come back"


def test_numeric_claim_assertion_is_independent_of_pyjwt() -> None:
    """The ``exp``/``nbf`` JSON-type assertion is a defence-in-depth layer that
    does NOT delegate to PyJWT's ``require``/``verify_exp``: the SEC-071/SEC-080
    lesson is that each layer looked complete in isolation. Exercised directly
    so the layer is proven on its own, not merely via the paths PyJWT happens
    to reject first."""
    assert JwksVerifier._assert_numeric_claim({"exp": 1}, "exp", required=True) is None
    assert JwksVerifier._assert_numeric_claim({}, "nbf", required=False) is None
    with pytest.raises(AuthError, match="missing the required exp claim"):
        JwksVerifier._assert_numeric_claim({}, "exp", required=True)
    with pytest.raises(AuthError, match="not a JSON number"):
        JwksVerifier._assert_numeric_claim({"exp": "1"}, "exp", required=True)


# --- The same set, enforced through the two framework guards ---------------


def _negative_tokens(
    private_key: Ed25519PrivateKey, valid_claims: dict[str, Any]
) -> dict[str, str]:
    """The §10.1 required negative set, as signed/assembled tokens."""
    return {
        "expired": _sign(private_key, {**valid_claims, "exp": time.time() - 3600}),
        "no_exp": _sign(private_key, {k: v for k, v in valid_claims.items() if k != "exp"}),
        "non_numeric_exp": _sign(private_key, {**valid_claims, "exp": "not-a-number"}),
        "numeric_string_exp": _sign(private_key, {**valid_claims, "exp": "9999999999"}),
        "future_nbf": _sign(private_key, {**valid_claims, "nbf": time.time() + 3600}),
        "other_tenant": _sign(private_key, {**valid_claims, "tenant_id": _OTHER_TENANT}),
        "no_tenant_id": _sign(
            private_key, {k: v for k, v in valid_claims.items() if k != "tenant_id"}
        ),
        "alg_none": _unsigned_alg_none(valid_claims),
        "hs_with_eddsa_kid": jwt.encode(
            valid_claims,
            "not-really-a-secret-key-32-bytes!",
            algorithm="HS256",
            headers={"kid": _KID},
        ),
    }


def test_fastapi_dependency_rejects_the_whole_negative_set(keypair, valid_claims) -> None:
    """§10.1 applied at the FastAPI ``Depends(require_authenticated_user)``
    surface: the conformant token is accepted, every required negative case
    yields 401, and no response echoes the token."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)

    app = FastAPI()
    dependency = require_authenticated_user(verifier, _TENANT)

    @app.get("/me")
    async def me(user: AxiamUser = Depends(dependency)):  # noqa: B008 (idiomatic FastAPI DI)
        """Echo the injected identity."""
        return {"user_id": user.user_id}

    client = TestClient(app)

    good = _sign(private_key, valid_claims)
    assert client.get("/me", headers={"Authorization": f"Bearer {good}"}).status_code == 200

    for name, token in _negative_tokens(private_key, valid_claims).items():
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401, f"{name} was not rejected"
        assert token not in response.text, f"{name} echoed the token back"


def _sync_get_response(request: Any) -> HttpResponse:
    """Trivial downstream Django view proving the middleware called through."""
    return HttpResponse("ok")


def test_django_middleware_rejects_the_whole_negative_set(
    keypair, valid_claims, monkeypatch
) -> None:
    """§10.1 applied at the Django ``AxiamAuthMiddleware`` surface: same
    conformant-accepted / negative-set-rejected assertions as FastAPI."""
    private_key, jwk_dict = keypair
    endpoint = _FakeJwksEndpoint([jwk_dict])
    real_init = JwksVerifier.__init__

    def patched_init(self: JwksVerifier, base_url: str, **kwargs: Any) -> None:
        """Bind the fake JWKS endpoint onto every verifier constructed."""
        real_init(self, base_url, **kwargs)
        endpoint.bind(self)

    monkeypatch.setattr(JwksVerifier, "__init__", patched_init)

    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()

    good = _sign(private_key, valid_claims)
    accepted = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {good}")
    assert middleware(accepted).status_code == 200
    assert accepted.axiam_user.tenant_id == _TENANT

    for name, token in _negative_tokens(private_key, valid_claims).items():
        request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = middleware(request)
        assert response.status_code == 401, f"{name} was not rejected"
        assert not hasattr(request, "axiam_user"), f"{name} attached an identity"


def test_django_middleware_honours_configured_issuer_and_audience(
    keypair, valid_claims, monkeypatch
) -> None:
    """§10.1 rules 5-6 wired through Django settings: with
    ``AXIAM_EXPECTED_ISSUER``/``AXIAM_EXPECTED_AUDIENCE`` set, a matching
    token is accepted and a mismatched one is 401'd."""
    private_key, jwk_dict = keypair
    endpoint = _FakeJwksEndpoint([jwk_dict])
    real_init = JwksVerifier.__init__

    def patched_init(self: JwksVerifier, base_url: str, **kwargs: Any) -> None:
        """Bind the fake JWKS endpoint onto every verifier constructed."""
        real_init(self, base_url, **kwargs)
        endpoint.bind(self)

    monkeypatch.setattr(JwksVerifier, "__init__", patched_init)
    monkeypatch.setattr(
        django_settings, "AXIAM_EXPECTED_ISSUER", "https://axiam.example.test", raising=False
    )
    monkeypatch.setattr(
        django_settings,
        "AXIAM_EXPECTED_AUDIENCE",
        RECOMMENDED_RESOURCE_SERVER_AUDIENCE,
        raising=False,
    )

    middleware = AxiamAuthMiddleware(_sync_get_response)
    factory = RequestFactory()

    matching = _sign(
        private_key,
        {
            **valid_claims,
            "iss": "https://axiam.example.test",
            "aud": RECOMMENDED_RESOURCE_SERVER_AUDIENCE,
        },
    )
    assert middleware(factory.get("/", HTTP_AUTHORIZATION=f"Bearer {matching}")).status_code == 200

    for bad in (
        {"iss": "https://evil.example", "aud": RECOMMENDED_RESOURCE_SERVER_AUDIENCE},
        {"iss": "https://axiam.example.test", "aud": "someone-else"},
        {"iss": "https://axiam.example.test"},
    ):
        token = _sign(private_key, {**valid_claims, **bad})
        response = middleware(factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}"))
        assert response.status_code == 401, f"{bad} was not rejected"


def test_django_middleware_rejects_an_unbounded_configured_skew(monkeypatch) -> None:
    """§10.1 rule 7 wired through Django settings: an out-of-bound
    ``AXIAM_CLOCK_SKEW_SECONDS`` refuses to construct the middleware rather
    than silently widening the acceptance window."""
    monkeypatch.setattr(django_settings, "AXIAM_CLOCK_SKEW_SECONDS", 10**9, raising=False)
    with pytest.raises(ValueError, match="clock_skew_seconds"):
        AxiamAuthMiddleware(_sync_get_response)


# --- §13.4 observation 5: the skew ceiling matches the recommendation -------


def test_skew_ceiling_equals_the_recommended_leeway() -> None:
    """§13.4 observation 5. 300s satisfied rule 7 — it was named and bounded —
    but it was 5x the RECOMMENDED leeway and 5x what every sibling SDK fixes its
    value at, so an operator could widen the acceptance window on an expired
    token to five minutes and still be "conformant". The ceiling now equals the
    recommendation."""
    assert MAX_CLOCK_SKEW_SECONDS == 60
    assert MAX_CLOCK_SKEW_SECONDS == DEFAULT_CLOCK_SKEW_SECONDS


def test_the_old_ceiling_is_now_refused() -> None:
    """The specific value the observation objected to must no longer construct."""
    with pytest.raises(ValueError, match="clock_skew_seconds"):
        JwksVerifier("https://axiam.example.test", clock_skew_seconds=300)


# --- §13.4 observation 6: slug-vs-UUID comparand diagnostic ----------------
#
# AXIAM tokens carry the tenant UUID in `tenant_id`, but this SDK's client is
# commonly configured with a tenant slug. A guard handed that slug rejects 100%
# of traffic — fail-closed and safe, but it presents as "every token is invalid"
# with nothing pointing at the cause.

_UUID_TENANT = "11111111-2222-3333-4444-555555555555"


def test_slug_comparand_is_diagnosed_with_an_actionable_message(
    keypair, valid_claims, caplog
) -> None:
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "tenant_id": _UUID_TENANT})

    with caplog.at_level(logging.WARNING):
        with pytest.raises(AuthError):
            verifier.verify_access_token(token, expected_tenant_id="acme-tenant")

    warnings = [r for r in caplog.records if "acme-tenant" in r.getMessage()]
    assert len(warnings) == 1
    assert "not a UUID" in warnings[0].getMessage()


def test_the_diagnostic_is_emitted_once_per_verifier(keypair, valid_claims, caplog) -> None:
    """It must be a configuration diagnostic, not a log-flood lever an attacker
    can drive by replaying bad tokens."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "tenant_id": _UUID_TENANT})

    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            with pytest.raises(AuthError):
                verifier.verify_access_token(token, expected_tenant_id="acme-tenant")

    assert len([r for r in caplog.records if "acme-tenant" in r.getMessage()]) == 1


def test_a_genuine_cross_tenant_rejection_stays_silent(keypair, valid_claims, caplog) -> None:
    """UUID vs UUID is a real cross-tenant rejection and must never be reported
    as a configuration error."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "tenant_id": _UUID_TENANT})

    with caplog.at_level(logging.WARNING):
        with pytest.raises(AuthError):
            verifier.verify_access_token(
                token, expected_tenant_id="99999999-8888-7777-6666-555555555555"
            )

    assert [r for r in caplog.records if "not a UUID" in r.getMessage()] == []


def test_the_diagnostic_does_not_change_the_verification_outcome(
    keypair, valid_claims, caplog
) -> None:
    """It only ever explains a failure — a correctly-configured guard still
    accepts, and still says nothing."""
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)
    token = _sign(private_key, {**valid_claims, "tenant_id": _UUID_TENANT})

    with caplog.at_level(logging.WARNING):
        claims = verifier.verify_access_token(token, expected_tenant_id=_UUID_TENANT)

    assert claims["tenant_id"] == _UUID_TENANT
    assert [r for r in caplog.records if "not a UUID" in r.getMessage()] == []


# --- CONTRACT.md §10.1 rule 8: the decision is about the caller token --------
#
# Rules 1-7 ask whether the token is good; rule 8 asks whether it is the token
# the decision is about. SEC-085 satisfied all seven and was still an
# authentication bypass, because the PHP guard routed a failed verification into
# a second, successful one against the application's own session.
#
# This SDK is structurally safe from that shape: the guard is handed a verifier
# and a configured tenant, never a logged-in client session, so there is no
# second credential in scope to substitute. These tests pin that property rather
# than assume it — the guardrail §15.3.1 asks for.


def test_the_guard_verifies_the_caller_token_and_no_other(keypair, valid_claims) -> None:
    private_key, jwk_dict = keypair
    verifier, _endpoint = _verifier(jwk_dict)

    expired = _sign(private_key, {**valid_claims, "exp": time.time() - 3600})
    healthy = _sign(private_key, valid_claims)

    seen: list[str] = []
    real_verify = verifier.verify_access_token

    def recording(token: str, *, expected_tenant_id: str | None):
        seen.append(token)
        return real_verify(token, expected_tenant_id=expected_tenant_id)

    verifier.verify_access_token = recording  # type: ignore[method-assign]

    with pytest.raises(AuthError):
        verifier.verify_access_token(expired, expected_tenant_id=_TENANT)

    assert seen == [expired]
    assert healthy not in seen, (
        "a failed verification must not be followed by one against another credential"
    )


def test_the_guard_signature_exposes_no_second_credential() -> None:
    """The shape of SEC-085: PHP's guard reached a stateful session through the
    client it held. Keep the guard's parameters free of anything like that."""
    import inspect as _inspect

    from axiam_sdk.fastapi import _authenticate

    params = set(_inspect.signature(_authenticate).parameters)
    assert params == {"request", "verifier", "configured_tenant"}, (
        "the guard must take only the request, a verifier and the configured "
        f"tenant; a client/session parameter would make rule 8 violable: {params}"
    )
