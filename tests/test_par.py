"""Pushed Authorization Requests — CONTRACT.md §26 (RFC 9126).

The first test is the one this section exists for: the endpoint answers
**201**, and a success predicate written ``== 200`` treats every successful
push as a failure while passing every other assertion here.
"""

from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlparse

import httpx
import pytest
import respx

from axiam_sdk import (
    AsyncAxiamClient,
    AuthError,
    AxiamClient,
    OAuthProtocolError,
    OidcConfiguration,
)
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    PAR_ENDPOINT,
    discovery_document,
    discovery_document_without_optional_endpoints,
)

CLIENT_SECRET = "rp-secret-value"  # noqa: S105
REDIRECT_URI = "https://app.example.com/auth/callback"
TENANT_ID = "11111111-1111-1111-1111-111111111111"
REQUEST_URI = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"


def _client(**kwargs: Any) -> AxiamClient:
    return AxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL,
        tenant_slug=TENANT_ID,
        client_id=CLIENT_ID,
        **kwargs,
    )


def _created() -> httpx.Response:
    # RFC 9126 §2.2 — Created, not OK.
    return httpx.Response(201, json={"request_uri": REQUEST_URI, "expires_in": 90})


def _config() -> OidcConfiguration:
    return OidcConfiguration.model_validate(discovery_document())


def _push(client: AxiamClient | None = None, **par_kwargs: Any) -> Any:
    client = client or _client(client_secret=CLIENT_SECRET)
    config = _config()
    request = client.oidc_begin(
        configuration=config, redirect_uri=REDIRECT_URI, scope="openid profile"
    )
    par_kwargs.setdefault("tenant_id", TENANT_ID)
    pushed = client.oidc_par(
        request=request,
        redirect_uri=REDIRECT_URI,
        scope="openid profile",
        configuration=config,
        **par_kwargs,
    )
    return request, pushed


# ---------------------------------------------------------------------------
# §26.1 — the 201 and the wire shape
# ---------------------------------------------------------------------------


@respx.mock
def test_201_is_treated_as_success() -> None:
    respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _request, pushed = _push()
    assert pushed.request_uri.get_secret_value() == REQUEST_URI
    assert pushed.expires_in == 90


@respx.mock
def test_the_push_is_form_encoded_with_tenant_id_in_the_query() -> None:
    route = respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _push()

    sent = route.calls[0].request
    assert "application/x-www-form-urlencoded" in sent.headers["content-type"]
    assert parse_qs(urlparse(str(sent.url)).query)["tenant_id"] == [TENANT_ID]
    form = dict(parse_qsl(sent.content.decode()))
    assert "tenant_id" not in form


@respx.mock
def test_the_push_carries_exactly_the_parameters_rule_1_names() -> None:
    route = respx.post(PAR_ENDPOINT).mock(return_value=_created())
    request, _pushed = _push()

    form = dict(parse_qsl(route.calls[0].request.content.decode()))
    assert form["client_id"] == CLIENT_ID
    assert form["response_type"] == "code"
    assert form["redirect_uri"] == REDIRECT_URI
    assert form["scope"] == "openid profile"
    assert form["state"] == request.state
    assert form["nonce"] == request.nonce
    assert form["code_challenge_method"] == "S256"
    assert form["client_secret"] == CLIENT_SECRET


@respx.mock
def test_a_public_client_omits_client_secret_rather_than_sending_an_empty_one() -> None:
    route = respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _push(_client())
    assert "client_secret" not in dict(parse_qsl(route.calls[0].request.content.decode()))


@respx.mock
def test_openid_is_added_when_the_caller_omits_it() -> None:
    route = respx.post(PAR_ENDPOINT).mock(return_value=_created())
    client = _client(client_secret=CLIENT_SECRET)
    config = _config()
    request = client.oidc_begin(configuration=config, redirect_uri=REDIRECT_URI)
    client.oidc_par(
        request=request,
        redirect_uri=REDIRECT_URI,
        scope="profile",
        configuration=config,
        tenant_id=TENANT_ID,
    )
    form = dict(parse_qsl(route.calls[0].request.content.decode()))
    assert form["scope"] == "openid profile"


@respx.mock
def test_an_op_without_a_par_endpoint_errors_rather_than_concatenating() -> None:
    route = respx.post(PAR_ENDPOINT)
    client = _client(client_secret=CLIENT_SECRET)
    config = OidcConfiguration.model_validate(discovery_document_without_optional_endpoints())
    request = client.oidc_begin(configuration=config, redirect_uri=REDIRECT_URI)

    with pytest.raises(AuthError):
        client.oidc_par(
            request=request,
            redirect_uri=REDIRECT_URI,
            configuration=config,
            tenant_id=TENANT_ID,
        )
    assert route.call_count == 0


# ---------------------------------------------------------------------------
# §26.2 rule 2 — the redirect URL carries exactly two parameters
# ---------------------------------------------------------------------------


@respx.mock
def test_the_authorization_url_carries_client_id_and_request_uri_and_nothing_else() -> None:
    respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _request, pushed = _push()

    query = parse_qs(urlparse(pushed.authorization_url).query)
    # Asserted on the FULL parameter set, not on the presence of the two: the
    # server refuses a request mixing a request_uri with inline authorization
    # parameters rather than merging them, and re-adding them "for
    # compatibility" restores the parameter-confusion attack that prevents.
    assert sorted(query.keys()) == ["client_id", "request_uri"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["request_uri"] == [REQUEST_URI]


@respx.mock
def test_the_authorization_url_uses_the_discovery_documents_endpoint() -> None:
    respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _request, pushed = _push()
    assert pushed.authorization_url.startswith(f"{BASE_URL}/oauth2/authorize")


# ---------------------------------------------------------------------------
# §26.2 rules 1 and 6 — one generator, one code_verifier
# ---------------------------------------------------------------------------


@respx.mock
def test_state_nonce_and_verifier_come_from_oidc_begin_unchanged() -> None:
    respx.post(PAR_ENDPOINT).mock(return_value=_created())
    request, pushed = _push()

    assert pushed.state == request.state
    assert pushed.nonce == request.nonce
    # The same verifier, so there is exactly one value to keep and no second
    # place for the two to disagree (§26.2 rule 6).
    assert pushed.code_verifier.get_secret_value() == request.code_verifier.get_secret_value()


@respx.mock
def test_the_pushed_challenge_derives_from_that_same_verifier() -> None:
    route = respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _request, pushed = _push()

    import base64

    expected = (
        base64.urlsafe_b64encode(
            hashlib.sha256(pushed.code_verifier.get_secret_value().encode()).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    form = dict(parse_qsl(route.calls[0].request.content.decode()))
    assert form["code_challenge"] == expected


# ---------------------------------------------------------------------------
# §26.2 rule 4 / §26.3 — retries and errors
# ---------------------------------------------------------------------------


@respx.mock
def test_a_5xx_is_not_retried_it_is_a_post_that_creates_state() -> None:
    route = respx.post(PAR_ENDPOINT).mock(return_value=httpx.Response(503))
    with pytest.raises(Exception):  # noqa: B017 - the count is the assertion
        _push()
    assert route.call_count == 1


@respx.mock
def test_a_transport_failure_is_not_retried_either() -> None:
    route = respx.post(PAR_ENDPOINT).mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(Exception):  # noqa: B017
        _push()
    assert route.call_count == 1


@respx.mock
def test_invalid_client_maps_through_the_shared_oauth2_mapper() -> None:
    respx.post(PAR_ENDPOINT).mock(
        return_value=httpx.Response(
            401,
            json={"error": "invalid_client", "error_description": "client auth failed"},
        )
    )
    with pytest.raises(OAuthProtocolError) as excinfo:
        _push()
    assert excinfo.value.error == "invalid_client"


@respx.mock
def test_invalid_request_maps_the_same_way() -> None:
    respx.post(PAR_ENDPOINT).mock(
        return_value=httpx.Response(
            400,
            json={"error": "invalid_request", "error_description": "redirect_uri unknown"},
        )
    )
    with pytest.raises(OAuthProtocolError) as excinfo:
        _push()
    assert excinfo.value.error == "invalid_request"


@respx.mock
def test_a_slug_only_client_raises_client_side_with_no_wire_call() -> None:
    route = respx.post(PAR_ENDPOINT)
    client = AxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL, tenant_slug="acme", org_slug="globex", client_id=CLIENT_ID
    )
    config = _config()
    request = client.oidc_begin(configuration=config, redirect_uri=REDIRECT_URI)
    with pytest.raises(AuthError):
        client.oidc_par(request=request, redirect_uri=REDIRECT_URI, configuration=config)
    assert route.call_count == 0


# ---------------------------------------------------------------------------
# §26.5 — sensitivity
# ---------------------------------------------------------------------------


@respx.mock
def test_request_uri_is_secret_but_still_reaches_the_redirect() -> None:
    respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _request, pushed = _push()

    surfaces = f"{pushed!r}{pushed}{pushed.model_dump_json()}"
    assert REQUEST_URI not in surfaces
    # …but it must reach the redirect URL, which is the point of it.
    assert "request_uri=" in pushed.authorization_url


@respx.mock
def test_the_verifier_and_client_secret_stay_out_of_serialization() -> None:
    respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _request, pushed = _push()

    serialized = pushed.model_dump_json()
    assert pushed.code_verifier.get_secret_value() not in serialized
    assert CLIENT_SECRET not in serialized


@respx.mock
def test_state_nonce_and_expiry_stay_readable_they_are_not_secrets() -> None:
    respx.post(PAR_ENDPOINT).mock(return_value=_created())
    _request, pushed = _push()
    assert isinstance(pushed.state, str)
    assert isinstance(pushed.nonce, str)
    assert pushed.expires_in == 90


# ---------------------------------------------------------------------------
# The async twin
# ---------------------------------------------------------------------------


@respx.mock
async def test_async_par() -> None:
    respx.post(PAR_ENDPOINT).mock(return_value=_created())
    client = AsyncAxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL,
        tenant_slug=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )
    config = _config()
    request = await client.oidc_begin(
        configuration=config, redirect_uri=REDIRECT_URI, scope="openid"
    )
    pushed = await client.oidc_par(
        request=request,
        redirect_uri=REDIRECT_URI,
        scope="openid",
        configuration=config,
        tenant_id=TENANT_ID,
    )
    assert pushed.request_uri.get_secret_value() == REQUEST_URI
    assert sorted(parse_qs(urlparse(pushed.authorization_url).query)) == [
        "client_id",
        "request_uri",
    ]
