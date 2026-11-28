"""CONTRACT.md §12.7.3 rule 1 and §12.7.6 (contract 1.69; server #880): a back-channel logout
token carries a ``kid`` and is verified by it.

The fixture is **server-shaped**: its header is exactly ``{"alg":"EdDSA","typ":"logout+jwt",
"kid":"<kid>"}`` (the signer adds nothing the server does not send), its claims are the server's
(``iss``, ``aud``, ``iat``, ``exp``, ``jti``, ``sid``, ``sub``, ``events``), and it is verified
against a JWKS holding **two** Ed25519 keys with the signing key *not* first, so a verifier that
takes the first or only key fails.
"""

from __future__ import annotations

from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient
from axiam_sdk._oidc_idtoken import verify_id_token_signature
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    JWKS_URI,
    FakeJwksEndpoint,
    discovery_document,
    make_ed25519_keypair_and_jwk,
    make_id_token_claims,
    make_logout_token_claims,
)

TENANT = "acme"


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _mint(key: Ed25519PrivateKey, claims: dict[str, Any], headers: dict[str, Any]) -> str:
    token = jwt.encode(claims, _pem(key), algorithm="EdDSA", headers=headers)
    return token


def server_shaped_logout_token(key: Ed25519PrivateKey, kid: str | None) -> str:
    """``{"alg":"EdDSA","typ":"logout+jwt","kid":kid}`` and nothing else; with ``kid=None`` the
    pre-1.69 shape (no ``kid`` member at all)."""
    headers: dict[str, Any] = {"typ": "logout+jwt"}
    if kid is not None:
        headers["kid"] = kid
    token = _mint(key, make_logout_token_claims(), headers)
    expected = {"alg", "typ"} | ({"kid"} if kid is not None else set())
    assert set(jwt.get_unverified_header(token)) == expected, "the fixture must add nothing"
    return token


@pytest.fixture
def keys() -> dict[str, Any]:
    """A rotated JWKS: the key that signs is the SECOND one."""
    old_key, old_jwk = make_ed25519_keypair_and_jwk("rotated-out-kid")
    signing_key, signing_jwk = make_ed25519_keypair_and_jwk("signing-kid")
    return {
        "signing_key": signing_key,
        "signing_jwk": signing_jwk,
        "two_key_jwks": [old_jwk, signing_jwk],
    }


def _client(jwks: list[dict[str, Any]], respx_mock: respx.MockRouter) -> tuple[AxiamClient, Any]:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT, client_id=CLIENT_ID)
    endpoint = FakeJwksEndpoint(jwks)
    endpoint.bind_to_client(client)
    return client, endpoint


def test_a_server_shaped_logout_token_verifies_against_a_two_key_jwks(
    keys: dict[str, Any], respx_mock: respx.MockRouter
) -> None:
    client, _endpoint = _client(keys["two_key_jwks"], respx_mock)
    token = server_shaped_logout_token(keys["signing_key"], "signing-kid")

    verified = client.verify_logout_token(token)

    assert (verified.sid, verified.sub) == ("session-abc", "user-1")
    assert verified.jti


def test_a_logout_token_verifies_with_the_async_client_too(
    keys: dict[str, Any], respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug=TENANT, client_id=CLIENT_ID)
    FakeJwksEndpoint(keys["two_key_jwks"]).bind_to_client(client)
    token = server_shaped_logout_token(keys["signing_key"], "signing-kid")

    import asyncio

    verified = asyncio.run(client.verify_logout_token(token))

    assert verified.jti


def test_a_kidless_logout_token_is_refused_as_unknown_kid_even_against_a_one_key_jwks(
    keys: dict[str, Any], respx_mock: respx.MockRouter
) -> None:
    """The key that signed it IS the only key published: a single-key fallback would accept
    it, and the rule forbids that (pre-1.69 servers sent no ``kid``)."""
    client, _endpoint = _client([keys["signing_jwk"]], respx_mock)
    token = server_shaped_logout_token(keys["signing_key"], None)

    with pytest.raises(AuthError) as excinfo:
        client.verify_logout_token(token)

    assert excinfo.value.reason == "unknown_kid"


def test_an_unknown_kid_is_refused_as_unknown_kid(
    keys: dict[str, Any], respx_mock: respx.MockRouter
) -> None:
    client, _endpoint = _client(keys["two_key_jwks"], respx_mock)
    token = server_shaped_logout_token(keys["signing_key"], "some-other-kid")

    with pytest.raises(AuthError) as excinfo:
        client.verify_logout_token(token)

    assert excinfo.value.reason == "unknown_kid"
    assert "some-other-kid" not in str(excinfo.value), "no token-derived value in the message"


def test_a_bad_signature_is_invalid_signature_not_unknown_kid(
    keys: dict[str, Any], respx_mock: respx.MockRouter
) -> None:
    client, _endpoint = _client(keys["two_key_jwks"], respx_mock)
    impostor, _ = make_ed25519_keypair_and_jwk("signing-kid")
    token = server_shaped_logout_token(impostor, "signing-kid")

    with pytest.raises(AuthError) as excinfo:
        client.verify_logout_token(token)

    assert excinfo.value.reason == "invalid_signature"


# --- rules 10 and 11 of §10.1 stay off the logout and the ID-token paths -----------------------


def test_rules_10_and_11_do_not_apply_to_the_logout_and_id_token_paths(
    keys: dict[str, Any], respx_mock: respx.MockRouter
) -> None:
    client, _endpoint = _client(keys["two_key_jwks"], respx_mock)
    verifier = client._verifier_for(JWKS_URI)

    # A server-shaped logout token (typ logout+jwt) verifies on its own path ...
    logout = server_shaped_logout_token(keys["signing_key"], "signing-kid")
    assert client.verify_logout_token(logout).jti

    # ... and an ID token (typ JWT, what PyJWT writes by default) verifies through the verifier
    # the access-token guard shares.
    id_token = _mint(
        keys["signing_key"], make_id_token_claims(), {"kid": "signing-kid", "typ": "JWT"}
    )
    assert verify_id_token_signature(verifier, id_token)["sub"] == "user-1"

    # The access-token guard, on the same verifier, refuses both: rule 10 on the typ ...
    with pytest.raises(AuthError, match="typ"):
        verifier.verify_access_token(logout, expected_tenant_id=TENANT)
    with pytest.raises(AuthError, match="typ"):
        verifier.verify_access_token(id_token, expected_tenant_id=TENANT)
