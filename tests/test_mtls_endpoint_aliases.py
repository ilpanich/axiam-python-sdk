"""RFC 8705 §5 ``mtls_endpoint_aliases`` — CONTRACT.md §21.3 rule 2 (contract 1.40).

The rule has one sentence and three named ways to get it wrong, and this
module is organised around them rather than around the SDK's method list:

* a call going over mTLS prefers the alias;
* a call NOT going over mTLS keeps the top-level entry;
* an ABSENT member means "no separate mTLS host", never "unsupported";
* only the six listed endpoints are ever aliased — not
  ``authorization_endpoint``, ``end_session_endpoint`` or ``jwks_uri``;
* ``issuer`` is not an endpoint, does not move, and still governs ``iss``
  validation by exact string for a token minted at an alias host.

"Over mTLS" here is the §6.1 client identity on the session: configure a
certificate and every request this client makes presents it. ``respx``
intercepts above the socket, so no handshake runs — what is under test is
*which URL the SDK chooses*, which the configured identity and the document
decide, not the socket.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from axiam_sdk import AuthError, AxiamClient, MtlsEndpointAliases
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    MTLS_BASE_URL,
    MTLS_DEVICE_AUTHORIZATION_ENDPOINT,
    MTLS_INTROSPECT_ENDPOINT,
    MTLS_PAR_ENDPOINT,
    MTLS_REVOKE_ENDPOINT,
    MTLS_TOKEN_ENDPOINT,
    client_identity_pem,
    device_authorization_response,
    discovery_document,
    discovery_document_with_aliases,
    mtls_endpoint_aliases,
)

TENANT_ID = "11111111-2222-3333-4444-555555555555"
CODE_VERIFIER = "v" * 43
NONCE = "the-request-nonce"


def _client(*, mtls: bool, with_secret: bool = True) -> AxiamClient:
    """An ``AxiamClient`` against the mocked origin, optionally carrying a
    §6.1 client identity so §21.3 rule 2 applies to every call it makes."""
    kwargs: dict[str, object] = {
        "base_url": BASE_URL,
        "tenant_slug": "acme",
        "client_id": CLIENT_ID,
    }
    if with_secret:
        kwargs["client_secret"] = CLIENT_SECRET
    if mtls:
        cert_pem, key_pem = client_identity_pem()
        kwargs["client_cert"] = cert_pem
        kwargs["client_key"] = key_pem
    return AxiamClient(**kwargs)  # type: ignore[arg-type]


def _mount(respx_mock: respx.MockRouter, document: dict[str, object]) -> dict[str, respx.Route]:
    """Serve discovery, and mount every OAuth2 POST endpoint on BOTH origins.

    Both get the full set, so choosing the wrong host is a *recorded* call
    rather than a routing failure — the assertion then names the host used.
    """
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=document)
    )
    bodies: dict[str, dict[str, object]] = {
        "/oauth2/token": {
            "access_token": "access-token-value",
            "token_type": "Bearer",
            "expires_in": 900,
        },
        "/oauth2/introspect": {"active": True},
        "/oauth2/revoke": {},
        "/oauth2/device_authorization": device_authorization_response(),
        "/oauth2/par": {"request_uri": "urn:ietf:params:oauth:request_uri:x", "expires_in": 60},
    }
    # RFC 9126 §2.2 specifies Created for a successful push, and the SDK
    # asserts exactly that — 200 here would fail every PAR test for a reason
    # that has nothing to do with which host was chosen.
    status = {"/oauth2/par": 201}
    routes: dict[str, respx.Route] = {}
    for path, body in bodies.items():
        for origin in (BASE_URL, MTLS_BASE_URL):
            routes[f"{origin}{path}"] = respx_mock.post(f"{origin}{path}").mock(
                return_value=httpx.Response(status.get(path, 200), json=body)
            )
    return routes


def _called(routes: dict[str, respx.Route], url: str) -> int:
    return routes[url].call_count


# ── The document round-trips the member ────────────────────────────────────


def test_discovery_exposes_the_aliases_when_published(respx_mock: respx.MockRouter) -> None:
    _mount(respx_mock, discovery_document_with_aliases())
    configuration = _client(mtls=False).oidc_discover()

    assert configuration.mtls_endpoint_aliases == MtlsEndpointAliases(**mtls_endpoint_aliases())
    # Alongside, never instead of: the conventional entries are untouched.
    assert configuration.token_endpoint == f"{BASE_URL}/oauth2/token"


def test_an_absent_member_parses_to_none_rather_than_failing(respx_mock: respx.MockRouter) -> None:
    _mount(respx_mock, discovery_document())
    configuration = _client(mtls=True).oidc_discover()

    assert configuration.mtls_endpoint_aliases is None


def test_the_member_round_trips_and_absence_serialises_as_absent(
    respx_mock: respx.MockRouter,
) -> None:
    _mount(respx_mock, discovery_document_with_aliases())
    with_aliases = _client(mtls=False).oidc_discover()

    dumped = with_aliases.model_dump(exclude_none=True)
    assert dumped["mtls_endpoint_aliases"] == mtls_endpoint_aliases()

    respx_mock.reset()
    _mount(respx_mock, discovery_document())
    without = _client(mtls=False).oidc_discover()
    # The server omits the key rather than writing `null`; so does this model.
    assert "mtls_endpoint_aliases" not in without.model_dump(exclude_none=True)


# ── A call over mTLS prefers the alias ─────────────────────────────────────


def test_the_token_endpoint_call_goes_to_the_alias_host(respx_mock: respx.MockRouter) -> None:
    routes = _mount(respx_mock, discovery_document_with_aliases())
    client = _client(mtls=True)

    client.oidc_exchange(
        code="authorization-code-value",
        code_verifier=CODE_VERIFIER,
        redirect_uri="https://app.example.com/auth/callback",
        nonce=NONCE,
        tenant_id=TENANT_ID,
    )

    assert _called(routes, MTLS_TOKEN_ENDPOINT) == 1
    assert _called(routes, f"{BASE_URL}/oauth2/token") == 0


def test_introspect_revoke_device_and_par_all_use_their_aliases(
    respx_mock: respx.MockRouter,
) -> None:
    routes = _mount(respx_mock, discovery_document_with_aliases())
    client = _client(mtls=True)

    client.introspect(token="access-token-value", tenant_id=TENANT_ID)
    client.revoke(token="access-token-value", tenant_id=TENANT_ID)
    client.device_authorize(tenant_id=TENANT_ID)
    configuration = client.oidc_discover()
    request = client.oidc_begin(
        configuration=configuration,
        redirect_uri="https://app.example.com/auth/callback",
        scope="openid",
    )
    client.oidc_par(
        request=request,
        redirect_uri="https://app.example.com/auth/callback",
        scope="openid",
        tenant_id=TENANT_ID,
    )

    for alias in (
        MTLS_INTROSPECT_ENDPOINT,
        MTLS_REVOKE_ENDPOINT,
        MTLS_DEVICE_AUTHORIZATION_ENDPOINT,
        MTLS_PAR_ENDPOINT,
    ):
        assert _called(routes, alias) == 1, alias
        assert _called(routes, alias.replace(MTLS_BASE_URL, BASE_URL)) == 0, alias


def test_the_alias_url_keeps_the_mandatory_tenant_id_parameter(
    respx_mock: respx.MockRouter,
) -> None:
    routes = _mount(respx_mock, discovery_document_with_aliases())

    _client(mtls=True).login_client_credentials(tenant_id=TENANT_ID)

    call = routes[MTLS_TOKEN_ENDPOINT].calls[0]
    assert call.request.url.params["tenant_id"] == TENANT_ID


# ── Consequence 1: absence means "no separate host" ────────────────────────


def test_an_mtls_client_with_no_aliases_keeps_the_top_level_endpoints(
    respx_mock: respx.MockRouter,
) -> None:
    routes = _mount(respx_mock, discovery_document())
    client = _client(mtls=True)

    # Not an error, and not the alias origin: a deployment running
    # `client_auth = optional` on one listener serves both populations at the
    # conventional endpoints and correctly publishes nothing.
    client.introspect(token="access-token-value", tenant_id=TENANT_ID)

    assert _called(routes, f"{BASE_URL}/oauth2/introspect") == 1
    assert _called(routes, MTLS_INTROSPECT_ENDPOINT) == 0


def test_a_client_not_doing_mtls_keeps_the_top_level_endpoints(
    respx_mock: respx.MockRouter,
) -> None:
    routes = _mount(respx_mock, discovery_document_with_aliases())

    _client(mtls=False).revoke(token="access-token-value", tenant_id=TENANT_ID)

    assert _called(routes, f"{BASE_URL}/oauth2/revoke") == 1
    assert _called(routes, MTLS_REVOKE_ENDPOINT) == 0


def test_a_partial_alias_object_falls_back_per_endpoint(respx_mock: respx.MockRouter) -> None:
    # RFC 8705 §5 does not require an OP to alias all six, and the shape of
    # this member must never be why a client stops working: an object naming
    # only `token_endpoint` is a valid document, and every endpoint it does
    # not name falls back to the top-level entry.
    document = discovery_document(mtls_endpoint_aliases={"token_endpoint": MTLS_TOKEN_ENDPOINT})
    routes = _mount(respx_mock, document)
    client = _client(mtls=True)

    client.login_client_credentials(tenant_id=TENANT_ID)
    client.introspect(token="access-token-value", tenant_id=TENANT_ID)

    assert _called(routes, MTLS_TOKEN_ENDPOINT) == 1
    assert _called(routes, f"{BASE_URL}/oauth2/introspect") == 1
    assert _called(routes, MTLS_INTROSPECT_ENDPOINT) == 0


def test_an_unsupported_grant_is_still_reported_when_neither_level_names_it(
    respx_mock: respx.MockRouter,
) -> None:
    aliases = mtls_endpoint_aliases()
    del aliases["device_authorization_endpoint"]
    document = discovery_document(mtls_endpoint_aliases=aliases)
    del document["device_authorization_endpoint"]
    _mount(respx_mock, document)

    # Neither level names the endpoint, so the answer is still "this server
    # does not support the device grant" — never a URL built by concatenation.
    with pytest.raises(AuthError):
        _client(mtls=True).device_authorize(tenant_id=TENANT_ID)


# ── Consequence 2: no alias is ever synthesised ────────────────────────────


def test_the_front_channel_and_jwks_endpoints_are_never_aliased(
    respx_mock: respx.MockRouter,
) -> None:
    _mount(respx_mock, discovery_document_with_aliases())
    client = _client(mtls=True)
    configuration = client.oidc_discover()

    # A browser sent to an mTLS host raises a native certificate-chooser
    # dialog most users cannot answer, and jwks_uri is public key material
    # that gains nothing from a handshake.
    request = client.oidc_begin(
        configuration=configuration,
        redirect_uri="https://app.example.com/auth/callback",
        scope="openid",
    )
    assert request.url.startswith(f"{BASE_URL}/oauth2/authorize")

    logout = client.logout_url(configuration=configuration, id_token="not-a-real-token")
    assert logout.startswith(f"{BASE_URL}/oauth2/end_session")

    assert configuration.jwks_uri == f"{BASE_URL}/oauth2/jwks"


def test_the_alias_model_carries_only_the_six_aliasable_endpoints() -> None:
    # Naming them as a closed set is what makes authorization_endpoint,
    # end_session_endpoint and jwks_uri unrepresentable rather than merely
    # unused. A seventh field here would be an alias the SDK could synthesise.
    assert set(MtlsEndpointAliases.model_fields) == {
        "token_endpoint",
        "userinfo_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
        "device_authorization_endpoint",
        "pushed_authorization_request_endpoint",
    }


# ── Consequence 3: issuer is never aliased ─────────────────────────────────


def test_the_issuer_does_not_move_with_the_endpoints(respx_mock: respx.MockRouter) -> None:
    _mount(respx_mock, discovery_document_with_aliases())

    configuration = _client(mtls=True).oidc_discover()

    # §12.4 rule 3 compares `iss` against THIS value by exact string, for
    # every token — including one minted at an alias endpoint. An SDK that
    # derived an expected issuer from the host it called would reject every
    # token it obtains over mTLS.
    assert configuration.issuer == BASE_URL
    assert configuration.issuer != MTLS_BASE_URL
