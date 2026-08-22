"""Shared OIDC test fixtures/helpers (CONTRACT.md §12) — reused across
``test_oidc_*.py``, mirroring ``the TypeScript SDK's test/node/oidcTestKit.ts``.

NOT a test module itself (no ``test_`` prefix, collected by nothing) — pure
helpers: a discovery-document builder, an Ed25519 keypair + JWKS-mock
fixture pair (same mock seam ``test_jwks.py`` uses — a fake ``fetch_data``
bound onto the verifier's internal ``PyJWKClient``, since it fetches via
``urllib.request`` rather than ``httpx``), and an ID-token signer.
"""

from __future__ import annotations

import base64
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from axiam_sdk._jwks import JwksVerifier

BASE_URL = "https://axiam.example.test"
CLIENT_ID = "rp-client-1"
CLIENT_SECRET = "rp-client-secret-1"
JWKS_URI = f"{BASE_URL}/oauth2/jwks"
DEVICE_AUTHORIZATION_ENDPOINT = f"{BASE_URL}/oauth2/device_authorization"
END_SESSION_ENDPOINT = f"{BASE_URL}/oauth2/end_session"
PAR_ENDPOINT = f"{BASE_URL}/oauth2/par"
DEVICE_CODE = "device-code-value"
USER_CODE = "WDJB-MJHT"
LOGOUT_SID = "session-abc"
LOGOUT_JTI = "logout-token-jti-1"
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def discovery_document(**overrides: Any) -> dict[str, Any]:
    """Build a wire-shaped ``OidcDiscoveryDocument`` JSON body, with every
    required field populated to a sane default; ``overrides`` replace
    individual fields (e.g. a non-default ``issuer`` behind a proxy)."""
    doc: dict[str, Any] = {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth2/authorize",
        "token_endpoint": f"{BASE_URL}/oauth2/token",
        "userinfo_endpoint": f"{BASE_URL}/oauth2/userinfo",
        "jwks_uri": JWKS_URI,
        "revocation_endpoint": f"{BASE_URL}/oauth2/revoke",
        "introspection_endpoint": f"{BASE_URL}/oauth2/introspect",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "device_authorization_endpoint": DEVICE_AUTHORIZATION_ENDPOINT,
        "end_session_endpoint": END_SESSION_ENDPOINT,
        "pushed_authorization_request_endpoint": PAR_ENDPOINT,
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
    }
    doc.update(overrides)
    return doc


def discovery_document_without_optional_endpoints(**overrides: Any) -> dict[str, Any]:
    """A discovery document with the §14/§12.7 endpoints deliberately absent —
    the shape an older AXIAM, or a third-party OP without those features,
    publishes. Used to assert the SDK errors rather than concatenating a URL
    onto the issuer (§12.7.2 rule 1)."""
    doc = discovery_document(**overrides)
    doc.pop("device_authorization_endpoint", None)
    doc.pop("end_session_endpoint", None)
    doc.pop("pushed_authorization_request_endpoint", None)
    return doc


def device_authorization_response(**overrides: Any) -> dict[str, Any]:
    """A wire-shaped ``DeviceAuthorizationResponse`` body."""
    body: dict[str, Any] = {
        "device_code": DEVICE_CODE,
        "user_code": USER_CODE,
        "verification_uri": f"{BASE_URL}/device",
        "verification_uri_complete": f"{BASE_URL}/device?user_code={USER_CODE}",
        "expires_in": 30,
        "interval": 1,
    }
    body.update(overrides)
    return body


def make_logout_token_claims(**overrides: Any) -> dict[str, Any]:
    """Build a VALID back-channel logout claim set; ``overrides`` break
    exactly one §12.7.3 rule per negative test.

    Pass ``sid=None``/``sub=None`` to omit a claim entirely.
    """
    import time

    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": BASE_URL,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 120,
        "jti": LOGOUT_JTI,
        "sid": LOGOUT_SID,
        "sub": "user-1",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_ed25519_keypair_and_jwk(
    kid: str = "test-kid-1",
) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    """Generate a fresh Ed25519 keypair plus its public JWK representation."""
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


def sign_id_token(private_key: Ed25519PrivateKey, kid: str, claims: dict[str, Any]) -> str:
    """Sign ``claims`` as an EdDSA-signed ID token with the given ``kid``."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": kid})


class FakeJwksEndpoint:
    """Tracks calls to a fake JWKS fetch, bound onto a verifier's internal
    ``PyJWKClient.fetch_data`` (see ``test_jwks.py`` for the rationale — no
    real network fetch is ever attempted)."""

    def __init__(self, jwk_dicts: list[dict[str, Any]]) -> None:
        self.jwk_dicts = jwk_dicts
        self.call_count = 0
        self._client: Any = None

    def bind_to_client(self, oidc_owner: Any, jwks_uri: str = JWKS_URI) -> None:
        """Bind this fake endpoint as the ``jwks_uri`` verifier's fetch
        source on an ``AxiamClient``/``AsyncAxiamClient`` instance —
        pre-seeds the mixin's verifier cache so ``_verifier_for`` reuses
        THIS bound verifier rather than building a real one."""
        verifier = JwksVerifier(jwks_uri, jwks_url=jwks_uri)
        self._client = verifier._client
        verifier._client.fetch_data = self._fetch_data  # type: ignore[method-assign]
        oidc_owner._jwks_verifiers[jwks_uri] = verifier

    def _fetch_data(self) -> dict[str, Any]:
        self.call_count += 1
        data = {"keys": self.jwk_dicts}
        if self._client is not None and self._client.jwk_set_cache is not None:
            self._client.jwk_set_cache.put(data)
        return data


def make_id_token_claims(**overrides: Any) -> dict[str, Any]:
    """Build a valid base ID-token claim set for ``BASE_URL``/``CLIENT_ID``;
    ``overrides`` replace individual claims for negative-path tests."""
    import time

    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": BASE_URL,
        "sub": "user-1",
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "nonce": "the-request-nonce",
    }
    claims.update(overrides)
    return claims
