"""UMA 2.0 — CONTRACT.md §20.7 required assertions.

Most of §20, like §15, is a list of things an SDK must not helpfully do, so
most of these tests assert an absence. The centrepiece is §20.2 rule 6: a
permission ticket must never be retried.

That rule is the one §16 exception in the contract, and the only way to assert
it is to count requests. A ticket is consumed *before* the request is
evaluated, so a failed exchange has already spent it — and under concurrency a
retry is precisely the second redemption that ilpanich/axiam#302's measured
residual describes. "Exactly one request" is a security assertion here, not a
performance one.

Every test is named after the thing it stops.
"""

from __future__ import annotations

from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from axiam_sdk import (
    AuthzError,
    AxiamClient,
    NetworkError,
    OAuthProtocolError,
    RequestedPermission,
    ResourceSet,
    uma_challenge_header,
    uma_parse_challenge,
)
from tests._oidc_testkit import BASE_URL, CLIENT_ID, CLIENT_SECRET, discovery_document

TENANT_ID = "11111111-1111-1111-1111-111111111111"
PAT = "pat-token-value"
TICKET = "ticket-value"
CLAIM_TOKEN = "claim-token-value"
RESOURCE_ID = "99999999-8888-7777-6666-555555555555"


def _form_body(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


def _client() -> AxiamClient:
    return AxiamClient(
        base_url=BASE_URL,
        tenant_slug="acme",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )


def _rpt_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={"access_token": "rpt-value", "token_type": "Bearer", "expires_in": 300},
    )


# ---------------------------------------------------------------------
# §20.2 rule 6 — the ticket grant is never retried
# ---------------------------------------------------------------------


def test_a_5xx_on_the_ticket_grant_is_not_retried(respx_mock: respx.MockRouter) -> None:
    """The §16 exception: the ticket is spent whether or not the exchange
    succeeded, so a retry cannot succeed — and it is the concurrent redemption
    ilpanich/axiam#302 measures."""
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=httpx.Response(500))

    with pytest.raises(NetworkError):
        _client().uma_exchange_ticket(ticket=TICKET, claim_token=CLAIM_TOKEN, tenant_id=TENANT_ID)

    assert route.call_count == 1, (
        "the ticket grant must issue exactly one request — retrying a spent "
        "ticket is the concurrent redemption ilpanich/axiam#302 describes"
    )


def test_invalid_grant_is_not_retried(respx_mock: respx.MockRouter) -> None:
    """``invalid_grant`` is what a replayed ticket gets. The retry could not
    succeed, and attempting it is the bug."""
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "permission ticket is invalid, expired, or already used",
            },
        )
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().uma_exchange_ticket(ticket=TICKET, claim_token=CLAIM_TOKEN, tenant_id=TENANT_ID)

    assert excinfo.value.error == "invalid_grant"
    assert route.call_count == 1


def test_access_denied_surfaces_as_itself_and_is_not_auto_narrowed(
    respx_mock: respx.MockRouter,
) -> None:
    """``access_denied`` arrives as **403** on this grant (UMA 2.0 §3.3.6),
    unlike RFC 8628's, which is a 400. The SDK dispatches on the ``error``
    field, so the code reaches the caller either way — and the refusal is not
    auto-narrowed into a smaller ticket request (§20.2 rule 3)."""
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=httpx.Response(
            403,
            json={
                "error": "access_denied",
                "error_description": (
                    "the requesting party is not authorized for every requested permission"
                ),
            },
        )
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().uma_exchange_ticket(ticket=TICKET, claim_token=CLAIM_TOKEN, tenant_id=TENANT_ID)

    assert excinfo.value.error == "access_denied", (
        "the 403 must not be flattened into a generic authorization error"
    )
    assert route.call_count == 1, "a refused ticket must not be re-requested with fewer scopes"


# ---------------------------------------------------------------------
# The ticket grant's wire shape
# ---------------------------------------------------------------------


def test_the_grant_sends_the_required_claim_token_and_format(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_rpt_response())

    rpt = _client().uma_exchange_ticket(ticket=TICKET, claim_token=CLAIM_TOKEN, tenant_id=TENANT_ID)

    form = _form_body(route.calls[0].request)
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:uma-ticket"
    assert form["ticket"] == TICKET
    assert form["claim_token"] == CLAIM_TOKEN
    assert form["claim_token_format"] == "urn:ietf:params:oauth:token-type:access_token"
    assert form["client_secret"] == CLIENT_SECRET
    assert rpt.access_token.get_secret_value() == "rpt-value"
    assert rpt.expires_in == 300


def test_the_rpt_model_cannot_carry_a_refresh_token() -> None:
    """§20.2 rule 5: the grant issues none, so the model has no field for one —
    an application that wants a fresh RPT re-runs the grant."""
    from axiam_sdk import RequestingPartyToken

    assert "refresh_token" not in RequestingPartyToken.model_fields


# ---------------------------------------------------------------------
# The Protection API
# ---------------------------------------------------------------------


def test_a_registered_id_is_usable_as_a_ticket_resource_id(
    respx_mock: respx.MockRouter,
) -> None:
    """The UMA ``_id`` **is** the AXIAM resource id — there is no parallel
    identifier to translate through."""
    respx_mock.post(f"{BASE_URL}/uma2/rreg/resource_set").mock(
        return_value=httpx.Response(
            201,
            json={
                "_id": RESOURCE_ID,
                "name": "invoice-7",
                "type": "document",
                "resource_scopes": ["view"],
            },
        )
    )
    perm_route = respx_mock.post(f"{BASE_URL}/uma2/perm").mock(
        return_value=httpx.Response(201, json={"ticket": TICKET})
    )

    client = _client()
    registered = client.uma_register_resource(
        PAT, ResourceSet(name="invoice-7", type="document", resource_scopes=["view"])
    )
    assert registered.id == RESOURCE_ID

    ticket = client.uma_request_ticket(
        PAT, [RequestedPermission(resource_id=registered.id, resource_scopes=["view"])]
    )

    assert ticket.get_secret_value() == TICKET
    import json

    assert json.loads(perm_route.calls[0].request.content) == [
        {"resource_id": RESOURCE_ID, "resource_scopes": ["view"]}
    ]


def test_the_pat_is_sent_as_a_bearer_token(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}/uma2/perm").mock(
        return_value=httpx.Response(201, json={"ticket": TICKET})
    )

    _client().uma_request_ticket(
        PAT, [RequestedPermission(resource_id=RESOURCE_ID, resource_scopes=["view"])]
    )

    assert route.calls[0].request.headers["authorization"] == f"Bearer {PAT}"


def test_an_update_sends_only_the_scopes_given_and_does_not_read_first(
    respx_mock: respx.MockRouter,
) -> None:
    """§20.2 rule 8: an update replaces the scope list. No GET is mocked, so a
    read-modify-write implementation would fail here rather than pass
    quietly."""
    route = respx_mock.put(f"{BASE_URL}/uma2/rreg/resource_set/{RESOURCE_ID}").mock(
        return_value=httpx.Response(
            200,
            json={
                "_id": RESOURCE_ID,
                "name": "invoice-7",
                "type": "document",
                "resource_scopes": ["view"],
            },
        )
    )

    _client().uma_update_resource(
        PAT,
        RESOURCE_ID,
        ResourceSet(name="invoice-7", type="document", resource_scopes=["view"]),
    )

    import json

    body = json.loads(route.calls[0].request.content)
    assert body["resource_scopes"] == ["view"]


def test_an_update_that_drops_every_scope_still_sends_the_key(
    respx_mock: respx.MockRouter,
) -> None:
    """Omitting the key would leave the server's copy untouched, which would
    make clearing a scope set impossible through the SDK."""
    route = respx_mock.put(f"{BASE_URL}/uma2/rreg/resource_set/{RESOURCE_ID}").mock(
        return_value=httpx.Response(
            200, json={"_id": RESOURCE_ID, "name": "invoice-7", "resource_scopes": []}
        )
    )

    _client().uma_update_resource(PAT, RESOURCE_ID, ResourceSet(name="invoice-7"))

    import json

    body = json.loads(route.calls[0].request.content)
    assert body["resource_scopes"] == []


def test_a_non_pat_refusal_reaches_the_caller(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}/uma2/perm").mock(
        return_value=httpx.Response(
            403,
            json={
                "error": "authorization_denied",
                "message": "the protection API requires the 'uma_protection' scope",
            },
        )
    )

    with pytest.raises(AuthzError):
        _client().uma_request_ticket(
            "not-a-pat",
            [RequestedPermission(resource_id=RESOURCE_ID, resource_scopes=["view"])],
        )

    assert route.call_count == 1


def test_the_listing_returns_ids(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/uma2/rreg/resource_set").mock(
        return_value=httpx.Response(200, json=[RESOURCE_ID])
    )

    assert _client().uma_list_resources(PAT) == [RESOURCE_ID]


# ---------------------------------------------------------------------
# §20.3 the challenge helpers
# ---------------------------------------------------------------------


def test_parses_a_well_formed_challenge() -> None:
    parsed = uma_parse_challenge(
        f'UMA realm="example", as_uri="https://id.example", ticket="{TICKET}"'
    )
    assert parsed is not None
    assert parsed.realm == "example"
    assert parsed.as_uri == "https://id.example"
    assert parsed.ticket is not None
    assert parsed.ticket.get_secret_value() == TICKET


def test_rejects_a_scheme_that_merely_starts_with_uma() -> None:
    assert uma_parse_challenge('Bearer realm="example"') is None
    assert uma_parse_challenge('UMAX realm="example"') is None


def test_parsing_a_challenge_performs_no_exchange(respx_mock: respx.MockRouter) -> None:
    """§20.3: the ``as_uri`` names an authorization server this client has not
    chosen to trust. respx raises on any unmocked request, so an accidental
    exchange fails this test rather than passing quietly."""
    parsed = uma_parse_challenge(f'UMA realm="example", as_uri="{BASE_URL}", ticket="{TICKET}"')
    assert parsed is not None
    assert len(respx_mock.calls) == 0


def test_the_challenge_round_trips_through_the_emit_half() -> None:
    header = uma_challenge_header("example", "https://id.example", TICKET)
    parsed = uma_parse_challenge(header)
    assert parsed is not None
    assert parsed.as_uri == "https://id.example"
    assert parsed.ticket is not None
    assert parsed.ticket.get_secret_value() == TICKET


def test_the_ticket_is_redacted_in_repr() -> None:
    """§20.6: the ticket's 60-second life is exactly what invites logging it."""
    parsed = uma_parse_challenge('UMA ticket="super-secret-ticket"')
    assert parsed is not None
    assert "super-secret-ticket" not in repr(parsed)
