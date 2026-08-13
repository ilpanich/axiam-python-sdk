"""Token Exchange (RFC 8693) — CONTRACT.md §15.

Most of §15 is a list of things an SDK must *not* helpfully do, so most of
these tests assert an absence: no defaulted ``actor_token``, no auto-narrow
after ``invalid_scope``, no synthesised refresh token, no adoption.
"""

from __future__ import annotations

from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from axiam_sdk import (
    ACCESS_TOKEN_TYPE,
    JWT_TOKEN_TYPE,
    AsyncAxiamClient,
    AuthError,
    AxiamClient,
    OAuthProtocolError,
)
from tests._oidc_testkit import BASE_URL, CLIENT_ID, CLIENT_SECRET, discovery_document

TENANT_ID = "11111111-1111-1111-1111-111111111111"
SUBJECT_TOKEN = "subject-token-value"
ACTOR_TOKEN = "actor-token-value"
ISSUED_TOKEN = "issued-narrow-token"


def _form_body(request: httpx.Request) -> dict[str, str]:
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    return dict(parse_qsl(request.content.decode()))


def _mock_discovery(respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )


def _exchange_response(**overrides: object) -> httpx.Response:
    body: dict[str, object] = {
        "access_token": ISSUED_TOKEN,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "orders:read",
    }
    body.update(overrides)
    return httpx.Response(200, json=body)


def _oauth_error(code: str) -> httpx.Response:
    return httpx.Response(400, json={"error": code, "error_description": f"{code} description"})


def _client(*, with_secret: bool = True) -> AxiamClient:
    return AxiamClient(
        base_url=BASE_URL,
        tenant_slug="acme",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET if with_secret else None,
    )


# ---------------------------------------------------------------------
# §15.1 wire shape
# ---------------------------------------------------------------------


def test_exchange_sends_the_rfc_8693_grant_and_authenticates(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_exchange_response())

    result = _client().token_exchange(
        subject_token=SUBJECT_TOKEN,
        subject_token_type=ACCESS_TOKEN_TYPE,
        scopes=["orders:read", "orders:write"],
        audience="orders-service",
        tenant_id=TENANT_ID,
    )

    form = _form_body(route.calls[0].request)
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert form["subject_token"] == SUBJECT_TOKEN
    assert form["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    assert form["scope"] == "orders:read orders:write"
    assert form["audience"] == "orders-service"
    assert form["client_secret"] == CLIENT_SECRET, (
        "§15.1: the exchanging client is confidential and authenticates"
    )

    assert result.access_token.get_secret_value() == ISSUED_TOKEN
    assert result.issued_token_type == "urn:ietf:params:oauth:token-type:access_token", (
        "§15.2 rule 6: issued_token_type is surfaced, not dropped"
    )


def test_a_public_client_fails_before_any_wire_call(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    # No token-endpoint route: reaching the wire would fail with respx's own
    # "not mocked" error rather than the AuthError we expect.

    with pytest.raises(AuthError, match="client_secret"):
        _client(with_secret=False).token_exchange(
            subject_token=SUBJECT_TOKEN, tenant_id=TENANT_ID, subject_token_type=ACCESS_TOKEN_TYPE
        )


# ---------------------------------------------------------------------
# §15.2 rule 1 — delegation vs impersonation
# ---------------------------------------------------------------------


def test_absent_actor_token_is_sent_as_absent_never_defaulted(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_exchange_response())

    _client().token_exchange(
        subject_token=SUBJECT_TOKEN, tenant_id=TENANT_ID, subject_token_type=ACCESS_TOKEN_TYPE
    )

    form = _form_body(route.calls[0].request)
    assert "actor_token" not in form, (
        "§15.2 rule 1: passing no actor token asks for IMPERSONATION. An SDK "
        "that helpfully substituted its own session token would silently turn "
        "that into a delegation — a different operation with different risk."
    )
    assert "actor_token_type" not in form


def test_actor_token_and_its_type_are_sent_as_a_pair(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_exchange_response())

    _client().token_exchange(
        subject_token=SUBJECT_TOKEN,
        actor_token=ACTOR_TOKEN,
        tenant_id=TENANT_ID,
        subject_token_type=ACCESS_TOKEN_TYPE,
    )

    form = _form_body(route.calls[0].request)
    assert form["actor_token"] == ACTOR_TOKEN
    assert form["actor_token_type"] == "urn:ietf:params:oauth:token-type:access_token", (
        "RFC 8693 §2.1 requires the pair; the type alone is a malformed request"
    )


# ---------------------------------------------------------------------
# §15.2 rules 2-3 and §15.3 — refusals surface unchanged
# ---------------------------------------------------------------------


def test_invalid_scope_is_not_retried_with_fewer_scopes(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error("invalid_scope")
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().token_exchange(
            subject_token=SUBJECT_TOKEN,
            subject_token_type=ACCESS_TOKEN_TYPE,
            scopes=["orders:read", "orders:admin"],
            tenant_id=TENANT_ID,
        )

    assert excinfo.value.error == "invalid_scope"
    assert route.call_count == 1, (
        "§15.2 rule 3: the server refuses rather than silently narrowing so the "
        "caller finds out HERE. Auto-narrowing and re-sending would hide it."
    )


def test_unauthorized_client_is_surfaced_verbatim_and_not_downgraded(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error("unauthorized_client")
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().token_exchange(
            subject_token=SUBJECT_TOKEN, tenant_id=TENANT_ID, subject_token_type=ACCESS_TOKEN_TYPE
        )

    assert excinfo.value.error == "unauthorized_client"
    assert route.call_count == 1, "no retry"
    assert "actor_token" not in _form_body(route.calls[0].request), (
        "§15.2 rule 2: an SDK that reworked the impersonation into a delegation "
        "would be sending a request the caller did not write"
    )


@pytest.mark.parametrize(
    "code",
    [
        "invalid_request",
        "invalid_grant",
        "invalid_scope",
        "invalid_target",
        "unauthorized_client",
        "invalid_client",
    ],
)
def test_the_six_error_codes_reach_the_caller_unchanged(
    respx_mock: respx.MockRouter, code: str
) -> None:
    # Including cross-tenant, which the server deliberately collapses into
    # `invalid_grant` — the SDK must not re-derive the distinction it withheld
    # (that is a tenant-enumeration signal).
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_oauth_error(code))

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().token_exchange(
            subject_token=SUBJECT_TOKEN, tenant_id=TENANT_ID, subject_token_type=ACCESS_TOKEN_TYPE
        )

    assert excinfo.value.error == code
    assert isinstance(excinfo.value, AuthError), (
        "§15.3 extends §2: an OAuth2ErrorResponse is an auth failure"
    )


# ---------------------------------------------------------------------
# §15.2 rules 4-7 — what the result is, and is not
# ---------------------------------------------------------------------


def test_a_server_sent_refresh_token_is_not_surfaced(respx_mock: respx.MockRouter) -> None:
    # Deliberately hostile fixture: RFC 8693 issues no refresh token, so the
    # model has no field for one and there is nothing to synthesise.
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_exchange_response(refresh_token="should-not-exist")
    )

    result = _client().token_exchange(
        subject_token=SUBJECT_TOKEN, tenant_id=TENANT_ID, subject_token_type=ACCESS_TOKEN_TYPE
    )

    assert not hasattr(result, "refresh_token")
    assert "should-not-exist" not in repr(result)


def test_the_granted_scope_is_readable_when_narrower_than_requested(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_exchange_response(scope="orders:read")
    )

    result = _client().token_exchange(
        subject_token=SUBJECT_TOKEN,
        subject_token_type=ACCESS_TOKEN_TYPE,
        scopes=["orders:read", "orders:write"],
        tenant_id=TENANT_ID,
    )

    assert result.scope == "orders:read", (
        "§15.2 rule 7: the response scope is the GRANTED set and may be narrower "
        "than requested even on success — applications must be able to read what "
        "they actually got"
    )


def test_tokens_are_redacted(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_exchange_response())

    result = _client().token_exchange(
        subject_token=SUBJECT_TOKEN, tenant_id=TENANT_ID, subject_token_type=ACCESS_TOKEN_TYPE
    )

    assert ISSUED_TOKEN not in repr(result), "§15.5: the issued token is a bearer credential"
    assert ISSUED_TOKEN not in str(result)
    assert result.access_token.get_secret_value() == ISSUED_TOKEN


def test_a_failed_exchange_never_echoes_the_subject_token(
    respx_mock: respx.MockRouter,
) -> None:
    # §15.5 calls this out specifically: an exchange failure is exactly when a
    # naive implementation logs the request body.
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_oauth_error("invalid_grant"))

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().token_exchange(
            subject_token=SUBJECT_TOKEN,
            actor_token=ACTOR_TOKEN,
            tenant_id=TENANT_ID,
            subject_token_type=ACCESS_TOKEN_TYPE,
        )

    rendered = f"{excinfo.value}{excinfo.value!r}"
    assert SUBJECT_TOKEN not in rendered
    assert ACTOR_TOKEN not in rendered


# ---------------------------------------------------------------------
# async twin (§15.4)
# ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_token_exchange_matches_the_sync_wire_shape(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_exchange_response())

    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )
    result = await client.token_exchange(
        subject_token=SUBJECT_TOKEN, tenant_id=TENANT_ID, subject_token_type=ACCESS_TOKEN_TYPE
    )

    form = _form_body(route.calls[0].request)
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert "actor_token" not in form
    assert result.access_token.get_secret_value() == ISSUED_TOKEN


# ---------------------------------------------------------------------
# §15.7 — external-IdP subject tokens (X4)
#
# No new operation: the same ``token_exchange`` carries a partner IdP's token.
# What changes is which subject tokens the server accepts and what its refusals
# mean, so these tests are about not getting in the way of either.
# ---------------------------------------------------------------------

#: A token minted by a partner's IdP. Opaque to the SDK — deliberately not a
#: well-formed JWT, because nothing here may decode it.
EXTERNAL_SUBJECT_TOKEN = "partner-idp-subject-token"

#: The one normative ``error_description`` (§15.7). It means "fix the AXIAM
#: trust configuration", not "fix your token".
ISSUER_NOT_CONFIGURED = "the subject token's issuer is not configured for token exchange"


def _oauth_error_with_description(code: str, description: str) -> httpx.Response:
    return httpx.Response(400, json={"error": code, "error_description": description})


def test_external_subject_token_type_is_sent_verbatim(respx_mock: respx.MockRouter) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_exchange_response(scope="read:orders")
    )

    result = _client().token_exchange(
        subject_token=EXTERNAL_SUBJECT_TOKEN,
        subject_token_type=JWT_TOKEN_TYPE,
        scopes=["read:orders"],
        audience="https://orders.internal",
        tenant_id=TENANT_ID,
    )

    form = _form_body(route.calls[0].request)
    # The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK must
    # not inspect the subject token to pick this, and must not override it.
    assert form["subject_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
    assert form["subject_token"] == EXTERNAL_SUBJECT_TOKEN
    # Delegation across a trust boundary is unsupported; nothing may add one.
    assert "actor_token" not in form

    # The cross-domain path is not a different result shape, and §15.2
    # rules 6-7 still hold.
    assert result.access_token.get_secret_value() == ISSUED_TOKEN
    assert result.issued_token_type == "urn:ietf:params:oauth:token-type:access_token"
    assert result.scope == "read:orders"


def test_subject_token_type_is_never_inferred_from_the_token(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_exchange_response())

    # A subject token that *looks* exactly like a JWT, presented as an access
    # token. An SDK that sniffed the token would "correct" this to …:jwt; §15.7
    # says it must not look, so what the caller named is what goes out. Being
    # able to hold this wrong is the point: only the caller knows.
    jwt_shaped = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig"
    _client().token_exchange(
        subject_token=jwt_shaped, tenant_id=TENANT_ID, subject_token_type=ACCESS_TOKEN_TYPE
    )

    form = _form_body(route.calls[0].request)
    assert form["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token", (
        "§15.7: the token's shape must not pick the type"
    )


def test_an_omitted_subject_token_type_never_reaches_the_wire(
    respx_mock: respx.MockRouter,
) -> None:
    """§15.1: the type is required and has no default.

    Python refuses the call before any of the SDK's own code runs — which is the
    enforcement §15.7 asks for, so it gets an assertion. Silently sending
    ``…:access_token`` would be the SDK choosing on the caller's behalf; and for
    a caller who actually held a refresh token it would trade the
    ``invalid_request`` that *names* the type for a generic ``invalid_grant``.
    """
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_exchange_response())

    with pytest.raises(TypeError, match="subject_token_type"):
        _client().token_exchange(  # type: ignore[call-arg]
            subject_token=SUBJECT_TOKEN, tenant_id=TENANT_ID
        )

    assert route.call_count == 0, "no request may be sent for a call that never had a type"


def test_actor_token_with_an_external_subject_token_is_refused_without_retry(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error_with_description(
            "invalid_request", "actor_token is not supported for an external subject token"
        )
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().token_exchange(
            subject_token=EXTERNAL_SUBJECT_TOKEN,
            subject_token_type=JWT_TOKEN_TYPE,
            actor_token=ACTOR_TOKEN,
            tenant_id=TENANT_ID,
        )

    assert excinfo.value.error == "invalid_request"
    # §15.7: no retry, and no rewriting. Dropping the actor token and
    # re-sending would turn a delegation the caller asked for into an
    # impersonation they did not.
    assert route.call_count == 1
    form = _form_body(route.calls[0].request)
    assert form["actor_token"] == ACTOR_TOKEN, "the request must be sent as written"
    assert form["subject_token_type"] == "urn:ietf:params:oauth:token-type:jwt"


@pytest.mark.parametrize(
    "refused",
    [
        "urn:ietf:params:oauth:token-type:refresh_token",
        "urn:ietf:params:oauth:token-type:id_token",
    ],
)
def test_a_refused_subject_token_type_is_never_retried_as_another(
    respx_mock: respx.MockRouter, refused: str
) -> None:
    # A refresh token is a re-authentication credential and an ID token is an
    # assertion to a client about a login; neither is a bearer credential for
    # an API, so both are refused BY NAME. Retrying as …:jwt would present one
    # as if it were.
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error_with_description(
            "invalid_request", f"unsupported subject_token_type {refused}"
        )
    )

    with pytest.raises(OAuthProtocolError):
        _client().token_exchange(
            subject_token=EXTERNAL_SUBJECT_TOKEN,
            subject_token_type=refused,
            tenant_id=TENANT_ID,
        )

    assert route.call_count == 1
    assert _form_body(route.calls[0].request)["subject_token_type"] == refused


def test_issuer_not_configured_description_reaches_the_caller_intact(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_discovery(respx_mock)
    respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
        return_value=_oauth_error_with_description("invalid_grant", ISSUER_NOT_CONFIGURED)
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        _client().token_exchange(
            subject_token=EXTERNAL_SUBJECT_TOKEN,
            subject_token_type=JWT_TOKEN_TYPE,
            tenant_id=TENANT_ID,
        )

    assert excinfo.value.error == "invalid_grant"
    # This is the ONLY distinguishable external failure, and the whole point of
    # it is that an integrator can tell "fix the AXIAM trust config" from "fix
    # your token". Truncating or rewording it destroys that.
    assert excinfo.value.error_description == ISSUER_NOT_CONFIGURED


def test_no_helper_re_exchanges_an_externally_exchanged_token(
    respx_mock: respx.MockRouter,
) -> None:
    # Tokens minted from an external subject token carry ``ext_exchange``, and
    # BOTH exchange paths refuse a subject token bearing it: exchanges do not
    # compose. The SDK's part is to never feed a result back in by itself.
    _mock_discovery(respx_mock)
    route = respx_mock.post(f"{BASE_URL}/oauth2/token").mock(return_value=_exchange_response())

    client = _client()
    result = client.token_exchange(
        subject_token=EXTERNAL_SUBJECT_TOKEN,
        subject_token_type=JWT_TOKEN_TYPE,
        tenant_id=TENANT_ID,
    )

    # Exactly one exchange happened: nothing looped the result back in.
    assert route.call_count == 1
    assert result.access_token.get_secret_value() == ISSUED_TOKEN
    # §15.2 rule 5 restated for the cross-domain path: had the result been
    # adopted into the §4 cookie jar, every later call would carry it — and the
    # next exchange would carry it as a *subject* token, which is exactly the
    # re-exchange §15.7 forbids, arrived at by accident rather than by
    # decision.
    assert not any(
        ISSUED_TOKEN in (cookie or "") for cookie in client._session.sync_client.cookies.values()
    )
