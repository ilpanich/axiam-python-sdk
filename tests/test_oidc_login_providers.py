"""The four public "Sign in with X" operations added by contract 1.38 —
``sso_providers``, ``sso_start_oauth2``, ``sso_complete_oauth2`` and
``sso_complete_handoff`` (CONTRACT.md §12.1).

Two kinds of assertion live here, and both are needed.

The **wire-shape** tests read the vendored ``openapi.json`` and assert the
method, path, content type and — for ``sso_providers`` — the *parameter
location* the server declares, then assert that what this SDK actually puts on
the wire matches. Asserting only against the mock would pin the SDK to the
test's own idea of the endpoint; asserting only against the spec would not
notice an SDK that agrees with the spec and calls something else.

The **rule** tests cover the four §12.1 notes easiest to get quietly wrong:
note 9 (an empty provider list is a success, not a not-found), note 10
(``protocol`` selects the start operation), note 12 (a handoff ``401`` is
terminal and is never retried) and rule 12a (a ``400`` from a start call is a
configuration refusal, not something to retry).

Every operation is asserted on **both** clients: §12.2 requires the same
snake_case names on ``AxiamClient`` and ``AsyncAxiamClient``.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from axiam_sdk import (
    HANDOFF_CODE_TTL_SECONDS,
    HANDOFF_QUERY_PARAM,
    PROTOCOL_OAUTH2,
    PROTOCOL_OIDC_CONNECT,
    PROTOCOL_SAML,
    AsyncAxiamClient,
    AuthError,
    AxiamClient,
    NetworkError,
)
from tests._oidc_testkit import BASE_URL

CONFIG_ID = "44444444-4444-4444-4444-444444444444"
REDIRECT_URI = "https://app.test/post-login"

PROVIDERS_PATH = "/api/v1/auth/federation/providers"
OIDC_START_PATH = "/api/v1/auth/federation/oidc/start"
OAUTH2_START_PATH = "/api/v1/auth/federation/oauth2/start"
OAUTH2_CALLBACK_PATH = "/api/v1/auth/federation/oauth2/callback"
HANDOFF_PATH = "/api/v1/auth/federation/handoff"

SPEC: dict[str, Any] = json.loads(
    (Path(__file__).resolve().parents[1] / "openapi.json").read_text(encoding="utf-8")
)


def _access_token(*, tenant_id: str = "tenant-uuid-1", org_id: str = "org-uuid-1") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "tenant_id": tenant_id,
                    "org_id": org_id,
                    "jti": "session-1",
                    "exp": 9999999999,
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.sig"


def _session_response() -> httpx.Response:
    """A ``200`` delivering the session as ``Set-Cookie``, exactly as
    ``POST /api/v1/auth/login`` does (§12.1 note 6, §4)."""
    return httpx.Response(
        200,
        json={
            "user_id": "99999999-8888-7777-6666-555555555555",
            "session_id": "12121212-3434-5656-7878-909090909090",
            "expires_in": 900,
            "redirect_uri": REDIRECT_URI,
        },
        headers=[
            ("Set-Cookie", f"axiam_access={_access_token()}; Path=/; HttpOnly"),
            ("Set-Cookie", "axiam_refresh=federation-refresh; Path=/; HttpOnly"),
            ("Set-Cookie", "axiam_csrf=federation-csrf; Path=/"),
        ],
    )


def _provider(config_id: str, kind: str, protocol: str) -> dict[str, Any]:
    return {
        "id": config_id,
        "provider_kind": kind,
        "display_name": kind,
        "protocol": protocol,
        "has_bundled_mark": True,
        "inherited": False,
    }


def _client() -> AxiamClient:
    return AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme-org")


def _async_client() -> AsyncAxiamClient:
    return AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme-org")


# ---------------------------------------------------------------------
# Wire shape, against openapi.json
# ---------------------------------------------------------------------


def test_openapi_declares_sso_providers_as_a_get_with_no_body() -> None:
    """§12.1: a ``GET``, no request body, answering
    ``PublicFederationProvidersResponse``."""
    operation = SPEC["paths"][PROVIDERS_PATH]["get"]
    assert "requestBody" not in operation
    assert (
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        == "#/components/schemas/PublicFederationProvidersResponse"
    )


@pytest.mark.parametrize(
    ("path", "request_schema", "response_schema"),
    [
        (OAUTH2_START_PATH, "OAuth2StartRequest", "OAuth2StartResponse"),
        (OAUTH2_CALLBACK_PATH, "OAuth2CallbackRequest", "SsoLoginSuccessResponse"),
        (HANDOFF_PATH, "SsoHandoffRequest", "SsoLoginSuccessResponse"),
    ],
)
def test_openapi_declares_the_three_posts(
    path: str, request_schema: str, response_schema: str
) -> None:
    """Each of the three is a ``POST`` taking ``application/json`` with the
    schema §12.1 names, and answering the one §12.1 names."""
    operation = SPEC["paths"][path]["post"]
    body = operation["requestBody"]["content"]["application/json"]
    assert body["schema"]["$ref"] == f"#/components/schemas/{request_schema}"
    assert (
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        == f"#/components/schemas/{response_schema}"
    )


def test_openapi_puts_the_provider_identifiers_in_the_query_string() -> None:
    """§12.1: ``org_slug``/``org_id`` and the optional tenant pair are **query**
    parameters.

    Asserted because the neighbouring start operations take the same four
    identifiers in a JSON *body*, and the two are one copy-paste apart.
    """
    params = SPEC["paths"][PROVIDERS_PATH]["get"]["parameters"]
    assert all(p["in"] == "query" for p in params), params
    assert sorted(p["name"] for p in params) == [
        "org_id",
        "org_slug",
        "tenant_id",
        "tenant_slug",
    ]


def test_openapi_public_provider_shape_matches_the_sdk_model() -> None:
    """Six required fields plus the nullable ``button_icon``, and none of the
    configuration a narrowed admin response would have leaked (§12.1 note 9)."""
    schema = SPEC["components"]["schemas"]["PublicFederationProvider"]
    assert sorted(schema["required"]) == [
        "display_name",
        "has_bundled_mark",
        "id",
        "inherited",
        "protocol",
        "provider_kind",
    ]
    properties = schema["properties"]
    assert "null" in properties["button_icon"]["type"]
    for absent in ("client_id", "client_secret", "metadata_url", "token_endpoint"):
        assert absent not in properties


@pytest.mark.parametrize("schema_name", ["OAuth2StartRequest", "OAuth2StartResponse"])
def test_openapi_oauth2_start_carries_no_pkce_material(schema_name: str) -> None:
    """§12.1 note 11: the verifier is generated and held server-side, so
    neither schema carries PKCE material and neither may the SDK."""
    properties = SPEC["components"]["schemas"][schema_name]["properties"]
    for pkce in ("code_verifier", "code_challenge", "code_challenge_method"):
        assert pkce not in properties


def test_openapi_handoff_request_is_just_the_code() -> None:
    """§12.1 note 12."""
    schema = SPEC["components"]["schemas"]["SsoHandoffRequest"]
    assert list(schema["properties"]) == ["code"]
    assert schema["required"] == ["code"]


# ---------------------------------------------------------------------
# sso_providers — wire shape and §12.1 note 9
# ---------------------------------------------------------------------


def test_sso_providers_sends_the_identifiers_as_query_parameters(
    respx_mock: respx.MockRouter,
) -> None:
    """The SDK half of the location assertion: query string, and no body."""
    route = respx_mock.get(f"{BASE_URL}{PROVIDERS_PATH}").mock(
        return_value=httpx.Response(200, json={"providers": []})
    )
    _client().sso_providers(org_slug="other-org", tenant_slug="engineering")

    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.params["org_slug"] == "other-org"
    assert request.url.params["tenant_slug"] == "engineering"
    assert request.content == b""


def test_sso_providers_defaults_the_workspace_to_the_client_context(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.get(f"{BASE_URL}{PROVIDERS_PATH}").mock(
        return_value=httpx.Response(200, json={"providers": []})
    )
    _client().sso_providers()

    params = route.calls.last.request.url.params
    assert params["org_slug"] == "acme-org"
    assert params["tenant_slug"] == "acme"


def test_an_empty_provider_list_is_a_success_not_an_error(
    respx_mock: respx.MockRouter,
) -> None:
    """§12.1 note 9. The three cases the endpoint makes indistinguishable —
    unknown organization, known-but-empty, and no workspace named — are all
    ordinary successes.

    Mapping any of them to an error would restore the two-valued answer the
    empty list removes, and with it the organization-slug oracle.
    """
    respx_mock.get(f"{BASE_URL}{PROVIDERS_PATH}").mock(
        return_value=httpx.Response(200, json={"providers": []})
    )
    client = _client()

    for kwargs in (
        {"org_slug": "no-such-organization"},
        {"org_slug": "acme-org", "tenant_slug": "acme"},
        {},
    ):
        result = client.sso_providers(**kwargs)  # type: ignore[arg-type]
        assert result.providers == []


def test_sso_providers_sends_the_request_even_with_no_workspace_at_all(
    respx_mock: respx.MockRouter,
) -> None:
    """Unlike ``sso_start``/``sso_start_oauth2``, a request that resolves no
    workspace is **sent** rather than refused client-side.

    A client-side refusal would be the same two-valued answer by another
    route: `400` for "you named nothing" against `200 []` for an unknown slug
    is exactly the oracle note 9 removes.
    """
    route = respx_mock.get(f"{BASE_URL}{PROVIDERS_PATH}").mock(
        return_value=httpx.Response(200, json={"providers": []})
    )
    result = AxiamClient(base_url=BASE_URL, tenant_slug="acme").sso_providers()

    assert route.call_count == 1
    assert result.providers == []


def test_sso_providers_maps_every_field_including_the_nullable_button_icon(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.get(f"{BASE_URL}{PROVIDERS_PATH}").mock(
        return_value=httpx.Response(
            200,
            json={
                "providers": [
                    {
                        "id": "33333333-3333-3333-3333-333333333333",
                        "provider_kind": "google",
                        "display_name": "Google",
                        "protocol": PROTOCOL_OIDC_CONNECT,
                        "has_bundled_mark": True,
                        "inherited": True,
                        "button_icon": None,
                    },
                    {
                        "id": "44444444-4444-4444-4444-444444444444",
                        "provider_kind": "generic_oauth2",
                        "display_name": "Acme SSO",
                        "protocol": PROTOCOL_OAUTH2,
                        "has_bundled_mark": False,
                        "inherited": False,
                        "button_icon": "data:image/png;base64,iVBORw0KGgo=",
                    },
                ]
            },
        )
    )
    providers = _client().sso_providers().providers

    assert providers[0].provider_kind == "google"
    assert providers[0].protocol == PROTOCOL_OIDC_CONNECT
    assert providers[0].has_bundled_mark is True
    # `inherited` is reported so an admin surface can show that a provider is
    # not the tenant's to edit; nothing here computes it (§12.1 note 13).
    assert providers[0].inherited is True
    assert providers[0].button_icon is None

    assert providers[1].protocol == PROTOCOL_OAUTH2
    assert providers[1].has_bundled_mark is False
    assert providers[1].button_icon == "data:image/png;base64,iVBORw0KGgo="


@pytest.mark.asyncio
async def test_sso_providers_async_twin_has_the_same_name_and_behaviour(
    respx_mock: respx.MockRouter,
) -> None:
    """§12.2: the same snake_case name on ``AsyncAxiamClient``, and the same
    empty-list-is-a-success rule."""
    respx_mock.get(f"{BASE_URL}{PROVIDERS_PATH}").mock(
        return_value=httpx.Response(200, json={"providers": []})
    )
    async with _async_client() as client:
        result = await client.sso_providers()
    assert result.providers == []


# ---------------------------------------------------------------------
# §12.1 note 10 — `protocol` selects the start operation
# ---------------------------------------------------------------------


def test_protocol_selects_the_start_operation_for_all_three_branches(
    respx_mock: respx.MockRouter,
) -> None:
    """All three branches, asserted on which endpoint the resulting call
    reached.

    ``provider_kind`` is deliberately misleading in this fixture: the ``Saml``
    row is ``google``, the kind whose OIDC connector everybody assumes. A
    dispatch that read the kind would send it to the OIDC start endpoint and
    be caught by the call-count assertions below.
    """
    respx_mock.get(f"{BASE_URL}{PROVIDERS_PATH}").mock(
        return_value=httpx.Response(
            200,
            json={
                "providers": [
                    _provider(
                        "55555555-5555-5555-5555-555555555555",
                        "microsoft",
                        PROTOCOL_OIDC_CONNECT,
                    ),
                    _provider("66666666-6666-6666-6666-666666666666", "github", PROTOCOL_OAUTH2),
                    _provider("77777777-7777-7777-7777-777777777777", "google", PROTOCOL_SAML),
                ]
            },
        )
    )
    start_body = {
        "authorize_url": "https://upstream.test/authorize",
        "state": "dispatch-state",
        "expires_in_secs": 600,
    }
    oidc_route = respx_mock.post(f"{BASE_URL}{OIDC_START_PATH}").mock(
        return_value=httpx.Response(200, json=start_body)
    )
    oauth2_route = respx_mock.post(f"{BASE_URL}{OAUTH2_START_PATH}").mock(
        return_value=httpx.Response(200, json=start_body)
    )

    client = _client()
    saml_seen = False
    for provider in client.sso_providers().providers:
        if provider.protocol == PROTOCOL_OIDC_CONNECT:
            client.sso_start(federation_config_id=provider.id, redirect_uri=REDIRECT_URI)
        elif provider.protocol == PROTOCOL_OAUTH2:
            client.sso_start_oauth2(federation_config_id=provider.id, redirect_uri=REDIRECT_URI)
        elif provider.protocol == PROTOCOL_SAML:
            # Saml goes to the SAML login endpoint, which §12.1 note 10 says is
            # NOT a §12 vocabulary operation. The branch exists so that a Saml
            # provider is never quietly handed to one of the other two.
            saml_seen = True
        else:  # pragma: no cover - the fixture has no fourth protocol
            raise AssertionError(f"unknown protocol {provider.protocol}")

    assert saml_seen
    assert oidc_route.call_count == 1
    assert oauth2_route.call_count == 1


# ---------------------------------------------------------------------
# sso_start_oauth2
# ---------------------------------------------------------------------


def test_sso_start_oauth2_posts_the_body_and_sends_no_pkce(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.post(f"{BASE_URL}{OAUTH2_START_PATH}").mock(
        return_value=httpx.Response(
            200,
            json={
                "authorize_url": "https://github.com/login/oauth/authorize?state=abc",
                "state": "abc",
                "expires_in_secs": 600,
            },
        )
    )
    result = _client().sso_start_oauth2(federation_config_id=CONFIG_ID, redirect_uri=REDIRECT_URI)

    request = route.calls.last.request
    assert request.headers["content-type"].startswith("application/json")
    body = json.loads(request.content)
    assert body == {
        "federation_config_id": CONFIG_ID,
        "redirect_uri": REDIRECT_URI,
        "tenant_slug": "acme",
        "org_slug": "acme-org",
    }
    # §12.1 note 11: the verifier is server-side. Its absence is the contract.
    for pkce in ("code_verifier", "code_challenge", "code_challenge_method"):
        assert pkce not in body
    assert result.state == "abc"
    assert result.expires_in_secs == 600


def test_sso_start_oauth2_refuses_client_side_without_org_context(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.post(f"{BASE_URL}{OAUTH2_START_PATH}")

    with pytest.raises(AuthError, match="organization context"):
        AxiamClient(base_url=BASE_URL, tenant_slug="acme").sso_start_oauth2(
            federation_config_id=CONFIG_ID, redirect_uri=REDIRECT_URI
        )

    assert route.call_count == 0


@pytest.mark.asyncio
async def test_sso_start_oauth2_async_twin(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}{OAUTH2_START_PATH}").mock(
        return_value=httpx.Response(
            200,
            json={
                "authorize_url": "https://github.com/login/oauth/authorize",
                "state": "abc",
                "expires_in_secs": 600,
            },
        )
    )
    async with _async_client() as client:
        result = await client.sso_start_oauth2(
            federation_config_id=CONFIG_ID, redirect_uri=REDIRECT_URI
        )
    assert result.state == "abc"


# ---------------------------------------------------------------------
# §12.1 rule 12a — a 400 from a start call is a configuration refusal
# ---------------------------------------------------------------------


@pytest.mark.parametrize("path", [OIDC_START_PATH, OAUTH2_START_PATH])
def test_a_400_from_a_start_call_is_a_configuration_error_and_is_not_retried(
    path: str, respx_mock: respx.MockRouter
) -> None:
    """On the SAML and Apple flows the identity provider never validates the
    SPA ``redirect_uri``, so the server confines it to its own issuer origin
    plus ``AXIAM__AUTH__SSO_SPA_ORIGINS`` and answers ``400`` otherwise.

    That ``400`` is a **configuration** refusal — §2's ``400`` row, whose
    taxonomy member in this SDK is ``NetworkError`` ("malformed request / SDK
    programming error"), as distinct from the ``AuthError`` a ``401`` gets. It
    must not be retried: the deployment will refuse the same origin every
    time.

    Asserted on both start operations, because Apple arrives over the OIDC one
    and a caller can reach the refusal from either entry point.
    """
    route = respx_mock.post(f"{BASE_URL}{path}").mock(
        return_value=httpx.Response(
            400, text="redirect_uri origin is not permitted for this deployment"
        )
    )
    client = _client()
    call = client.sso_start if path == OIDC_START_PATH else client.sso_start_oauth2

    with pytest.raises(NetworkError):
        call(federation_config_id=CONFIG_ID, redirect_uri="https://attacker.example/")

    assert route.call_count == 1


def test_a_401_from_a_start_call_stays_an_auth_error(
    respx_mock: respx.MockRouter,
) -> None:
    """The uniform "unknown workspace or provider" answer is a *different*
    taxonomy member from the rule-12a ``400``. Asserted so the two cannot
    quietly collapse into one."""
    respx_mock.post(f"{BASE_URL}{OAUTH2_START_PATH}").mock(
        return_value=httpx.Response(401, text="unauthorized")
    )

    with pytest.raises(AuthError):
        _client().sso_start_oauth2(federation_config_id=CONFIG_ID, redirect_uri=REDIRECT_URI)


# ---------------------------------------------------------------------
# The two completions, and §12.1 note 12
# ---------------------------------------------------------------------


def test_sso_complete_oauth2_posts_state_and_code_and_absorbs_the_session(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.post(f"{BASE_URL}{OAUTH2_CALLBACK_PATH}").mock(
        return_value=_session_response()
    )
    result = _client().sso_complete_oauth2(state="abc", code="provider-code")

    assert json.loads(route.calls.last.request.content) == {
        "state": "abc",
        "code": "provider-code",
    }
    assert result.user_id == "99999999-8888-7777-6666-555555555555"
    assert result.redirect_uri == REDIRECT_URI
    # §12.1 note 6: the success body carries no token material at all.
    assert set(result.model_dump()) == {
        "user_id",
        "session_id",
        "expires_in",
        "redirect_uri",
    }


def test_sso_complete_handoff_posts_just_the_code(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}{HANDOFF_PATH}").mock(return_value=_session_response())
    result = _client().sso_complete_handoff(code="handoff-code")

    assert json.loads(route.calls.last.request.content) == {"code": "handoff-code"}
    assert result.session_id == "12121212-3434-5656-7878-909090909090"


def test_a_handoff_401_is_terminal_and_is_not_retried(
    respx_mock: respx.MockRouter,
) -> None:
    """§12.1 note 12. Unknown, expired and already-redeemed all answer the same
    ``401``, on purpose. The code is spent either way, so a retry cannot
    succeed and would only widen the window in which it sits in a log."""
    route = respx_mock.post(f"{BASE_URL}{HANDOFF_PATH}").mock(
        return_value=httpx.Response(401, text="unauthorized")
    )

    with pytest.raises(AuthError):
        _client().sso_complete_handoff(code="spent-or-expired-or-never-existed")

    assert route.call_count == 1


@pytest.mark.asyncio
async def test_the_completions_async_twins(respx_mock: respx.MockRouter) -> None:
    """§12.2: same names on ``AsyncAxiamClient``, including the terminal
    handoff ``401``."""
    respx_mock.post(f"{BASE_URL}{OAUTH2_CALLBACK_PATH}").mock(return_value=_session_response())
    handoff = respx_mock.post(f"{BASE_URL}{HANDOFF_PATH}").mock(
        return_value=httpx.Response(401, text="unauthorized")
    )

    async with _async_client() as client:
        result = await client.sso_complete_oauth2(state="abc", code="c")
        assert result.expires_in == 900

        with pytest.raises(AuthError):
            await client.sso_complete_handoff(code="spent")

    assert handoff.call_count == 1


def test_the_handoff_parameter_and_ttl_are_what_the_contract_says() -> None:
    """The two values a caller codes against: it reads the code out of
    ``?axiam_handoff=`` and has 60 seconds to spend it."""
    assert HANDOFF_QUERY_PARAM == "axiam_handoff"
    assert HANDOFF_CODE_TTL_SECONDS == 60
