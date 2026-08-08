"""RP-initiated and back-channel logout — CONTRACT.md §12.7.

The §12.7.6 required tests. The ``verify_logout_token`` half carries the
security weight: its input arrives unsolicited, from the network, and
instructs the RP to terminate a session — so each rejection test names the
attack it prevents rather than merely asserting an error.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    END_SESSION_ENDPOINT,
    LOGOUT_JTI,
    LOGOUT_SID,
    FakeJwksEndpoint,
    discovery_document,
    discovery_document_without_optional_endpoints,
    make_ed25519_keypair_and_jwk,
    make_id_token_claims,
    make_logout_token_claims,
    sign_id_token,
)

ID_TOKEN = "the-users-id-token"


def _mock_discovery(respx_mock: respx.MockRouter, *, full: bool = True) -> None:
    doc = discovery_document() if full else discovery_document_without_optional_endpoints()
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=doc)
    )


def _client() -> AxiamClient:
    return AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query)


# ---------------------------------------------------------------------
# §12.7.2 logout_url
# ---------------------------------------------------------------------


def test_logout_url_uses_the_discovered_endpoint(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)

    url = _client().logout_url(id_token=ID_TOKEN)

    # §12.7.2 rule 1: the endpoint comes from discovery. Code that builds
    # `{issuer}/oauth2/end_session` works against AXIAM and breaks against
    # every other OP the same application is pointed at.
    assert url.startswith(END_SESSION_ENDPOINT)
    assert _query(url)["id_token_hint"] == [ID_TOKEN]


def test_logout_url_omits_what_was_not_supplied(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)

    bare = _query(_client().logout_url(id_token=ID_TOKEN))
    assert "post_logout_redirect_uri" not in bare
    assert "state" not in bare

    full = _query(
        _client().logout_url(
            id_token=ID_TOKEN,
            post_logout_redirect_uri="https://app.example.com/bye",
            state="caller-generated-state",
        )
    )
    assert full["post_logout_redirect_uri"] == ["https://app.example.com/bye"]
    assert full["state"] == ["caller-generated-state"], (
        "§12.7.2 rule 2: state is passed through unmodified — the SDK never "
        "invents one, because the value only means something to the caller"
    )


def test_logout_url_does_not_prevalidate_the_redirect(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)

    # §12.7.2 rule 3: the allow-list lives in the client's server-side
    # registration. A client-side copy would drift and reject a URI an operator
    # had just registered, so an arbitrary URI must pass through.
    url = _client().logout_url(
        id_token=ID_TOKEN, post_logout_redirect_uri="https://somewhere-else.example/x"
    )

    assert _query(url)["post_logout_redirect_uri"] == ["https://somewhere-else.example/x"]


def test_logout_url_errors_when_no_end_session_endpoint(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock, full=False)

    with pytest.raises(AuthError, match="end_session_endpoint"):
        _client().logout_url(id_token=ID_TOKEN)


def test_logout_url_does_not_leak_the_id_token_into_an_error(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock, full=False)

    with pytest.raises(AuthError) as excinfo:
        _client().logout_url(id_token="super-secret-id-token")

    assert "super-secret-id-token" not in str(excinfo.value)


# ---------------------------------------------------------------------
# §12.7.3 verify_logout_token
# ---------------------------------------------------------------------


def _fixture(
    respx_mock: respx.MockRouter, kid: str = "logout-kid"
) -> tuple[AxiamClient, object, str]:
    """Mount discovery, bind a fake JWKS, and return (client, key, kid)."""
    _mock_discovery(respx_mock)
    private_key, jwk = make_ed25519_keypair_and_jwk(kid)
    client = _client()
    FakeJwksEndpoint([jwk]).bind_to_client(client)
    return client, private_key, kid


def test_a_valid_logout_token_surfaces_sid_sub_and_jti(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    token = sign_id_token(key, kid, make_logout_token_claims())

    verified = client.verify_logout_token(token)

    # §12.7.3: not a bare bool. The RP has to know WHICH session to end, and a
    # verifier that only says "valid" forces the caller to re-parse the token
    # themselves with none of these checks.
    assert verified.sid == LOGOUT_SID
    assert verified.sub == "user-1"
    assert verified.jti == LOGOUT_JTI


def test_an_id_token_replayed_as_a_logout_token_is_rejected(
    respx_mock: respx.MockRouter,
) -> None:
    # The attack rules 3 and 4 exist to stop, asserted with a real,
    # otherwise-valid ID token rather than a synthetic mutation: correctly
    # signed by a published key, right issuer and audience, unexpired. Only the
    # missing `events` and the present `nonce` distinguish it.
    client, key, kid = _fixture(respx_mock)
    id_token = sign_id_token(key, kid, make_id_token_claims())

    with pytest.raises(AuthError):
        client.verify_logout_token(id_token)


def test_a_token_without_events_is_rejected(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    claims = make_logout_token_claims()
    del claims["events"]
    token = sign_id_token(key, kid, claims)

    with pytest.raises(AuthError, match="events"):
        client.verify_logout_token(token)


def test_a_token_carrying_some_other_event_is_rejected(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    token = sign_id_token(
        key,
        kid,
        make_logout_token_claims(events={"http://schemas.openid.net/event/some-other-thing": {}}),
    )

    with pytest.raises(AuthError, match="events"):
        client.verify_logout_token(token)


def test_a_nonce_is_rejected_not_ignored(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    token = sign_id_token(key, kid, make_logout_token_claims(nonce="n-0S6_WzA2Mj"))

    with pytest.raises(AuthError, match="nonce"):
        client.verify_logout_token(token)


def test_a_token_naming_neither_sid_nor_sub_is_rejected(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    token = sign_id_token(key, kid, make_logout_token_claims(sid=None, sub=None))

    with pytest.raises(AuthError, match="identifies no session"):
        client.verify_logout_token(token)


def test_sub_only_is_accepted_but_sid_is_preferred(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)

    sub_only = sign_id_token(key, kid, make_logout_token_claims(sid=None))
    verified = client.verify_logout_token(sub_only)
    assert verified.sid is None
    assert verified.sub == "user-1"

    # With `sid` present the RP must end THAT session only — falling back to
    # "every session for sub" is over-reach the server itself refuses.
    both = client.verify_logout_token(sign_id_token(key, kid, make_logout_token_claims()))
    assert both.sid == LOGOUT_SID


def test_a_token_for_another_client_is_rejected(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    token = sign_id_token(key, kid, make_logout_token_claims(aud="some-other-rp"))

    with pytest.raises(AuthError, match="audience"):
        client.verify_logout_token(token)


def test_a_token_from_another_issuer_is_rejected(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    token = sign_id_token(key, kid, make_logout_token_claims(iss="https://evil.example.com"))

    with pytest.raises(AuthError, match="issuer"):
        client.verify_logout_token(token)


def test_a_token_signed_by_an_unpublished_key_is_rejected(
    respx_mock: respx.MockRouter,
) -> None:
    client, _key, _kid = _fixture(respx_mock)
    rogue_key, _rogue_jwk = make_ed25519_keypair_and_jwk("rogue-kid")
    token = sign_id_token(rogue_key, "rogue-kid", make_logout_token_claims())

    # The signature is what makes the token a statement rather than a request.
    with pytest.raises(AuthError):
        client.verify_logout_token(token)


def test_an_expired_token_is_rejected(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    now = int(time.time())
    token = sign_id_token(key, kid, make_logout_token_claims(exp=now - 600, iat=now - 700))

    # A long-lived logout token is a replayable session-termination command.
    with pytest.raises(AuthError, match="expired"):
        client.verify_logout_token(token)


def test_a_stale_but_unexpired_token_is_rejected(respx_mock: respx.MockRouter) -> None:
    client, key, kid = _fixture(respx_mock)
    now = int(time.time())
    # exp still in the future, but issued days ago — a captured delivery being
    # replayed rather than a live one.
    token = sign_id_token(key, kid, make_logout_token_claims(iat=now - 86_400, exp=now + 600))

    with pytest.raises(AuthError, match="too old"):
        client.verify_logout_token(token)


def test_verifying_the_same_token_twice_does_not_raise(respx_mock: respx.MockRouter) -> None:
    # §12.7.3 rule 7. Delivery is at-least-once with retry, so a valid token
    # legitimately arrives twice — that is a retry, not an attack. An SDK that
    # dedupped internally would have no durable store and would silently drop a
    # real second logout after a restart, so `jti` is surfaced for the RP to
    # dedup on and never consumed here.
    client, key, kid = _fixture(respx_mock)
    token = sign_id_token(key, kid, make_logout_token_claims())

    first = client.verify_logout_token(token)
    second = client.verify_logout_token(token)

    assert first == second
    assert first.jti == LOGOUT_JTI


def test_a_verification_failure_never_echoes_the_token(respx_mock: respx.MockRouter) -> None:
    client, _key, _kid = _fixture(respx_mock)
    rogue_key, _rogue_jwk = make_ed25519_keypair_and_jwk("rogue-kid")
    token = sign_id_token(rogue_key, "rogue-kid", make_logout_token_claims())

    with pytest.raises(AuthError) as excinfo:
        client.verify_logout_token(token)

    assert token not in str(excinfo.value)


# ---------------------------------------------------------------------
# async twin (§12.7.4)
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_verify_logout_token_matches_the_sync_result(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    private_key, jwk = make_ed25519_keypair_and_jwk("logout-kid")
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
    FakeJwksEndpoint([jwk]).bind_to_client(client)
    token = sign_id_token(private_key, "logout-kid", make_logout_token_claims())

    verified = await client.verify_logout_token(token)

    assert verified.sid == LOGOUT_SID
    assert verified.jti == LOGOUT_JTI


@pytest.mark.asyncio
async def test_async_logout_url_carries_the_hint(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    url = await client.logout_url(id_token=ID_TOKEN)

    assert _query(url)["id_token_hint"] == [ID_TOKEN]
