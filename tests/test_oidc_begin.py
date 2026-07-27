"""``oidc_begin`` tests (CONTRACT.md §12.1) — pure local computation, no
network I/O. Covers the eight owned query parameters, S256-only PKCE,
state/nonce entropy + uniqueness, scope normalization, and the
extra_params override guard (a programming error, not the auth-error
taxonomy)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from axiam_sdk import AuthError, AxiamClient
from axiam_sdk._models import OidcConfiguration
from tests._oidc_testkit import BASE_URL, CLIENT_ID, discovery_document

REDIRECT_URI = "https://app.test/callback"


def _client(**kwargs: object) -> AxiamClient:
    return AxiamClient(base_url=BASE_URL, tenant_slug="acme", **kwargs)  # type: ignore[arg-type]


def _configuration() -> OidcConfiguration:
    return OidcConfiguration.model_validate(discovery_document())


def test_oidc_begin_requires_client_id() -> None:
    client = _client()
    with pytest.raises(AuthError):
        client.oidc_begin(configuration=_configuration(), redirect_uri=REDIRECT_URI)


def test_oidc_begin_url_has_exactly_the_eight_owned_params() -> None:
    client = _client(client_id=CLIENT_ID)
    request = client.oidc_begin(configuration=_configuration(), redirect_uri=REDIRECT_URI)

    parsed = urlsplit(request.url)
    query = parse_qs(parsed.query)

    assert (
        parsed.scheme + "://" + parsed.netloc + parsed.path
        == _configuration().authorization_endpoint
    )
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["redirect_uri"] == [REDIRECT_URI]
    assert query["scope"] == ["openid"]
    assert query["state"] == [request.state]
    assert query["nonce"] == [request.nonce]
    assert query["code_challenge_method"] == ["S256"]
    assert "code_challenge" in query
    assert set(query.keys()) == {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    }


def test_oidc_begin_code_challenge_method_is_always_s256() -> None:
    """§12.1 rule 3: S256 only — `plain` is never reachable."""
    client = _client(client_id=CLIENT_ID)
    for _ in range(10):
        request = client.oidc_begin(configuration=_configuration(), redirect_uri=REDIRECT_URI)
        parsed = urlsplit(request.url)
        query = parse_qs(parsed.query)
        assert query["code_challenge_method"] == ["S256"]


def test_oidc_begin_scope_always_includes_openid() -> None:
    client = _client(client_id=CLIENT_ID)
    request = client.oidc_begin(
        configuration=_configuration(), redirect_uri=REDIRECT_URI, scope="profile email"
    )
    query = parse_qs(urlsplit(request.url).query)
    assert query["scope"] == ["openid profile email"]


def test_oidc_begin_scope_accepts_list_and_dedupes() -> None:
    client = _client(client_id=CLIENT_ID)
    request = client.oidc_begin(
        configuration=_configuration(),
        redirect_uri=REDIRECT_URI,
        scope=["openid", "profile", "openid"],
    )
    query = parse_qs(urlsplit(request.url).query)
    assert query["scope"] == ["openid profile"]


def test_oidc_begin_spaces_are_percent_encoded_as_percent20_not_plus() -> None:
    client = _client(client_id=CLIENT_ID)
    request = client.oidc_begin(
        configuration=_configuration(), redirect_uri=REDIRECT_URI, scope="profile email"
    )
    assert "%20" in request.url
    assert "+" not in request.url


def test_oidc_begin_extra_params_are_added() -> None:
    client = _client(client_id=CLIENT_ID)
    request = client.oidc_begin(
        configuration=_configuration(),
        redirect_uri=REDIRECT_URI,
        extra_params={"prompt": "login", "login_hint": "user@example.test"},
    )
    query = parse_qs(urlsplit(request.url).query)
    assert query["prompt"] == ["login"]
    assert query["login_hint"] == ["user@example.test"]


@pytest.mark.parametrize(
    "reserved_key",
    [
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ],
)
def test_oidc_begin_extra_params_cannot_override_owned_params(reserved_key: str) -> None:
    """Port-brief-addendum item 9: this is a programming error, raised as
    ``ValueError`` — NOT the auth-error taxonomy."""
    client = _client(client_id=CLIENT_ID)
    with pytest.raises(ValueError, match=reserved_key):
        client.oidc_begin(
            configuration=_configuration(),
            redirect_uri=REDIRECT_URI,
            extra_params={reserved_key: "attacker-value"},
        )


def test_oidc_begin_state_and_nonce_are_url_safe_and_unpadded() -> None:
    client = _client(client_id=CLIENT_ID)
    request = client.oidc_begin(configuration=_configuration(), redirect_uri=REDIRECT_URI)
    assert "=" not in request.state
    assert "=" not in request.nonce
    assert len(request.state) >= 22  # >=128 bits base64url-encoded, unpadded
    assert len(request.nonce) >= 22


def test_oidc_begin_state_and_nonce_are_unique_across_calls() -> None:
    """>=128-bit entropy + uniqueness (a hard test requirement)."""
    client = _client(client_id=CLIENT_ID)
    states = set()
    nonces = set()
    for _ in range(200):
        request = client.oidc_begin(configuration=_configuration(), redirect_uri=REDIRECT_URI)
        states.add(request.state)
        nonces.add(request.nonce)
    assert len(states) == 200
    assert len(nonces) == 200
    assert states.isdisjoint(nonces)


def test_oidc_begin_code_verifier_is_sensitive_wrapped() -> None:
    client = _client(client_id=CLIENT_ID)
    request = client.oidc_begin(configuration=_configuration(), redirect_uri=REDIRECT_URI)
    assert str(request.code_verifier) == "**********"
    assert request.code_verifier.get_secret_value()


def test_oidc_begin_url_uses_authorization_endpoint_from_discovery_document() -> None:
    """§12.1 rule 5: never hardcoded — always the discovery document's
    ``authorization_endpoint``."""
    client = _client(client_id=CLIENT_ID)
    config = OidcConfiguration.model_validate(
        discovery_document(authorization_endpoint="https://proxy.example.test/authz")
    )
    request = client.oidc_begin(configuration=config, redirect_uri=REDIRECT_URI)
    assert request.url.startswith("https://proxy.example.test/authz?")


@pytest.mark.asyncio
async def test_async_oidc_begin_has_the_same_behavior() -> None:
    from axiam_sdk import AsyncAxiamClient

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    request = await client.oidc_begin(configuration=_configuration(), redirect_uri=REDIRECT_URI)
    query = parse_qs(urlsplit(request.url).query)
    assert query["client_id"] == [CLIENT_ID]
    assert query["code_challenge_method"] == ["S256"]
