"""Native sign-in with a provider ID token -- CONTRACT.md §37 (contract 1.65).

The thirteen tests of §37.9, by the contract's names, each run on the sync and
the async client (the same method name on both, §37.5). The wire is mocked with
``respx``; nothing here reaches a network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import traceback
from typing import Any, Literal
from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from axiam_sdk import (
    AsyncAxiamClient,
    AuthError,
    AxiamClient,
    NetworkError,
    OAuthProtocolError,
    OidcConfiguration,
    ProviderNonce,
)
from axiam_sdk._oidc import PROVIDER_ID_TOKEN_GRANT_TYPE
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    FakeJwksEndpoint,
    discovery_document,
    make_ed25519_keypair_and_jwk,
    make_id_token_claims,
    sign_id_token,
)

Mode = Literal["sync", "async"]
MODES: list[Mode] = ["sync", "async"]

TENANT_ID = "11111111-1111-1111-1111-111111111111"
TOKEN_URL = f"{BASE_URL}/oauth2/token"
CLIENT_SECRET = "rp-secret-value"  # noqa: S105 - test fixture
PROVIDER_UUID = "22222222-2222-2222-2222-222222222222"

#: §37.4's fixed vector: SHA-256 of the ASCII string.
RAW_NONCE = "n-0S6_WzA2Mj"
RAW_NONCE_SHA256 = "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19"

GENERIC_INVALID_GRANT = "the provider ID token is not acceptable"


def _b64(obj: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


#: A fixture "provider" ID token whose payload carries the nonce *hash* (what a
#: real provider token carries). It is opaque to the SDK, which never reads it.
PROVIDER_ID_TOKEN = ".".join(
    [
        _b64({"alg": "RS256", "kid": "k"}),
        _b64({"iss": "https://accounts.example", "aud": "app", "nonce": RAW_NONCE_SHA256}),
        "c2lnbmF0dXJlLWZpeHR1cmU",
    ]
)


def _form(request: httpx.Request) -> dict[str, str]:
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    return dict(parse_qsl(request.content.decode(), keep_blank_values=True))


def _config() -> OidcConfiguration:
    return OidcConfiguration.model_validate(discovery_document())


def _token_response(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "access_token": "access-token-1",
        "token_type": "Bearer",
        "expires_in": 900,
    }
    body.update(overrides)
    return body


def _client(mode: Mode, **kwargs: Any) -> AxiamClient | AsyncAxiamClient:
    kwargs.setdefault("tenant_slug", TENANT_ID)
    cls = AxiamClient if mode == "sync" else AsyncAxiamClient
    return cls(base_url=BASE_URL, client_id=CLIENT_ID, **kwargs)  # type: ignore[arg-type]


async def _login(
    client: AxiamClient | AsyncAxiamClient,
    provider: str = PROVIDER_UUID,
    id_token: Any = PROVIDER_ID_TOKEN,
    nonce: Any = RAW_NONCE,
    **kwargs: Any,
) -> Any:
    """Call ``login_with_provider_id_token`` on either client. ``configuration`` is
    always passed, so the only request a test records is the token request."""
    kwargs.setdefault("configuration", _config())
    kwargs.setdefault("tenant_id", TENANT_ID)
    result = client.login_with_provider_id_token(provider, id_token, nonce, **kwargs)
    if isinstance(client, AsyncAxiamClient):
        return await result  # type: ignore[misc]
    return result


def _oauth_error(status: int, error: str, description: str = "refused", **headers: str) -> Any:
    return httpx.Response(
        status, json={"error": error, "error_description": description}, headers=headers
    )


# ---------------------------------------------------------------------------
# 1. request_body_exact
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_request_body_exact(mode: Mode, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = _client(mode)

    await _login(client, scopes=["openid", "profile"], resource="https://api.example.test")

    assert len(route.calls) == 1
    request = route.calls.last.request
    assert dict(request.url.params) == {"tenant_id": TENANT_ID}
    form = _form(request)
    assert set(form) == {
        "grant_type",
        "client_id",
        "provider",
        "id_token",
        "nonce",
        "scope",
        "resource",
    }
    assert form["grant_type"] == "urn:axiam:params:oauth:grant-type:provider-id-token"
    assert form["grant_type"] == PROVIDER_ID_TOKEN_GRANT_TYPE
    assert form["client_id"] == CLIENT_ID
    assert form["provider"] == PROVIDER_UUID
    assert form["id_token"] == PROVIDER_ID_TOKEN
    assert form["scope"] == "openid profile"
    assert form["resource"] == "https://api.example.test"
    for header in ("authorization", "cookie", "x-csrf-token"):
        assert header not in request.headers, header

    # No scopes and no resource: neither key, and `openid` is not added.
    await _login(client)
    bare = _form(route.calls.last.request)
    assert set(bare) == {"grant_type", "client_id", "provider", "id_token", "nonce"}
    assert "scope" not in bare
    assert "openid" not in route.calls.last.request.content.decode()

    # An empty list of scopes is "none named": never `scope=`.
    await _login(client, scopes=[])
    assert "scope" not in _form(route.calls.last.request)


@pytest.mark.parametrize("mode", MODES)
async def test_request_goes_to_the_discovered_token_endpoint_with_tenant_in_query(
    mode: Mode, respx_mock: respx.MockRouter
) -> None:
    """Without an injected ``configuration`` the helper discovers like every §12
    operation, then makes the one token request."""
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = _client(mode)

    result = client.login_with_provider_id_token(
        PROVIDER_UUID, PROVIDER_ID_TOKEN, RAW_NONCE, tenant_id=TENANT_ID
    )
    if isinstance(client, AsyncAxiamClient):
        result = await result

    assert len(route.calls) == 1
    assert result.access_token.get_secret_value() == "access-token-1"


# ---------------------------------------------------------------------------
# 2. raw_nonce_sent_not_hash
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_raw_nonce_sent_not_hash(mode: Mode, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )

    await _login(_client(mode), nonce=RAW_NONCE)

    request = route.calls.last.request
    assert _form(request)["nonce"] == RAW_NONCE
    body = request.content.decode()
    assert RAW_NONCE_SHA256 not in body
    # The fixture token's payload carries the hash; the helper did not read it.
    claim = json.loads(base64.urlsafe_b64decode(PROVIDER_ID_TOKEN.split(".")[1] + "==").decode())[
        "nonce"
    ]
    assert claim == RAW_NONCE_SHA256
    assert claim not in body


@pytest.mark.parametrize("mode", MODES)
async def test_raw_nonce_is_sent_byte_for_byte_whatever_its_case(
    mode: Mode, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )

    for nonce in ("MiXeD-Case_Nonce.0~", " leading and trailing  "):
        await _login(_client(mode), nonce=nonce)
        assert _form(route.calls.last.request)["nonce"] == nonce


# ---------------------------------------------------------------------------
# 3. provider_sent_verbatim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_provider_sent_verbatim(mode: Mode, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = _client(mode)

    for provider in (PROVIDER_UUID, "Corp-Okta", "google", PROVIDER_UUID.upper(), " pad "):
        await _login(client, provider=provider)
        assert _form(route.calls.last.request)["provider"] == provider

    # One request per call: no sso_providers lookup, no discovery fetch.
    assert len(route.calls) == 5
    assert len(respx_mock.calls) == 5


# ---------------------------------------------------------------------------
# 4. public_client_sends_client_id_only / confidential_client_sends_its_credential
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_public_client_sends_client_id_only(mode: Mode, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )

    await _login(_client(mode))  # no client_secret: a public client

    request = route.calls.last.request
    form = _form(request)
    assert form["client_id"] == CLIENT_ID
    assert "client_secret" not in form
    assert "client_assertion" not in form
    assert "authorization" not in request.headers


@pytest.mark.parametrize("auth_method", ["client_secret_post", "client_secret_basic"])
@pytest.mark.parametrize("mode", MODES)
async def test_confidential_client_sends_its_credential(
    mode: Mode, auth_method: str, respx_mock: respx.MockRouter
) -> None:
    """The secret goes in the body, never a Basic header, whichever method the
    server's discovery document names."""
    document = discovery_document(token_endpoint_auth_methods_supported=[auth_method])
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )

    await _login(
        _client(mode, client_secret=CLIENT_SECRET),
        configuration=OidcConfiguration.model_validate(document),
    )

    request = route.calls.last.request
    assert _form(request)["client_secret"] == CLIENT_SECRET
    assert "authorization" not in request.headers


# ---------------------------------------------------------------------------
# 5. empty_inputs_refused_locally
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("field", ["provider", "id_token", "nonce"])
async def test_empty_inputs_refused_locally(
    mode: Mode, field: str, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    inputs: dict[str, Any] = {
        "provider": PROVIDER_UUID,
        "id_token": PROVIDER_ID_TOKEN,
        "nonce": RAW_NONCE,
    }
    inputs[field] = ""

    with pytest.raises(ValueError, match=field):
        await _login(_client(mode), **inputs)

    assert len(route.calls) == 0
    assert len(respx_mock.calls) == 0


@pytest.mark.parametrize("mode", MODES)
async def test_empty_inputs_refused_locally_for_wrapped_secrets_and_the_nonce_bound(
    mode: Mode, respx_mock: respx.MockRouter
) -> None:
    from pydantic import SecretStr

    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = _client(mode)

    with pytest.raises(ValueError, match="id_token"):
        await _login(client, id_token=SecretStr(""))
    with pytest.raises(ValueError, match="nonce"):
        await _login(client, nonce=SecretStr(""))
    # 512 bytes is the server's bound: 513 is refused locally (a MAY), 512 is sent.
    with pytest.raises(ValueError, match="nonce"):
        await _login(client, nonce="a" * 513)
    assert len(route.calls) == 0

    await _login(client, nonce="a" * 512)
    assert len(route.calls) == 1


@pytest.mark.parametrize("mode", MODES)
async def test_slug_only_client_refused_locally_with_no_request(
    mode: Mode, respx_mock: respx.MockRouter
) -> None:
    """§12.3 rule 4: with no tenant UUID the helper raises the taxonomy error
    client-side, before even discovery."""
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = _client(mode, tenant_slug="acme")

    with pytest.raises(AuthError, match="tenant_id"):
        await _login(client, tenant_id=None)
    with pytest.raises(AuthError, match="UUID"):
        await _login(client, tenant_id="acme")

    assert len(route.calls) == 0
    assert len(respx_mock.calls) == 0


@pytest.mark.parametrize("mode", MODES)
async def test_missing_client_id_refused_locally(mode: Mode, respx_mock: respx.MockRouter) -> None:
    cls = AxiamClient if mode == "sync" else AsyncAxiamClient
    client = cls(base_url=BASE_URL, tenant_slug=TENANT_ID)  # type: ignore[arg-type]

    with pytest.raises(AuthError, match="client_id"):
        await _login(client)

    assert len(respx_mock.calls) == 0


# ---------------------------------------------------------------------------
# 6. generic_invalid_grant_mapped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_generic_invalid_grant_mapped(mode: Mode, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=_oauth_error(400, "invalid_grant", GENERIC_INVALID_GRANT)
    )
    client = _client(mode)

    with pytest.raises(OAuthProtocolError) as excinfo:
        await _login(client)

    error = excinfo.value
    assert error.error == "invalid_grant"
    assert error.error_description == GENERIC_INVALID_GRANT
    assert str(error) == f"invalid_grant: {GENERIC_INVALID_GRANT}"
    assert len(route.calls) == 1, "no retry"
    assert len(respx_mock.calls) == 1, "no helper re-sends it with a regenerated nonce"
    # The §9 guard was not entered: no refresh was recorded on the shared guard.
    assert client._session.refresh_guard.cached_access_token() is None


# ---------------------------------------------------------------------------
# 7. consent_required_mapped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_consent_required_mapped(mode: Mode, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=_oauth_error(400, "consent_required", "consent is required")
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        await _login(_client(mode), scopes=["openid", "profile"])

    assert excinfo.value.error == "consent_required"
    assert len(route.calls) == 1
    assert len(respx_mock.calls) == 1, "nothing falls back to another grant or a browser flow"


# ---------------------------------------------------------------------------
# 8. client_and_scope_refusals_surfaced
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("status", "error", "headers"),
    [
        (400, "unauthorized_client", {}),
        (401, "invalid_client", {"WWW-Authenticate": 'Basic realm="axiam"'}),
        (400, "invalid_scope", {}),
        (400, "invalid_target", {}),
    ],
)
async def test_client_and_scope_refusals_surfaced(
    mode: Mode, status: int, error: str, headers: dict[str, str], respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=_oauth_error(status, error, "the server's own text", **headers)
    )
    client = _client(mode)

    with pytest.raises(OAuthProtocolError) as excinfo:
        await _login(client, scopes=["openid", "address"], resource="https://api.example.test")

    assert excinfo.value.error == error
    assert excinfo.value.error_description == "the server's own text"
    assert len(route.calls) == 1, "one request: not narrowed and re-sent, not retried unbound"
    assert len(respx_mock.calls) == 1
    # A 401 never enters the §9 guard: nothing was refreshed or cached.
    assert client._session.refresh_guard.cached_access_token() is None


# ---------------------------------------------------------------------------
# 9. rate_limit_with_retry_after_mapped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_rate_limit_with_retry_after_mapped(mode: Mode, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=_oauth_error(429, "rate_limit_exceeded", "slow down", **{"Retry-After": "7"})
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        await _login(_client(mode))

    assert excinfo.value.error == "rate_limit_exceeded"
    assert excinfo.value.retry_after_ms == 7000
    assert len(route.calls) == 1


# ---------------------------------------------------------------------------
# 10. server_error_not_retried
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_server_error_not_retried(mode: Mode, respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=_oauth_error(500, "server_error", "the datastore is unavailable")
    )
    with pytest.raises(OAuthProtocolError) as excinfo:
        await _login(_client(mode))
    assert excinfo.value.error == "server_error"
    assert len(route.calls) == 1

    # A 500 with no OAuth2ErrorResponse body is a NetworkError, still one request.
    before = len(route.calls)
    route.mock(return_value=httpx.Response(500))
    with pytest.raises(NetworkError):
        await _login(_client(mode))
    assert len(route.calls) - before == 1

    # A transport failure after the request is sent: NetworkError, one request.
    before = len(route.calls)
    route.mock(side_effect=httpx.ReadTimeout("read timed out"))
    with pytest.raises(NetworkError):
        await _login(_client(mode))
    assert len(route.calls) - before == 1


# ---------------------------------------------------------------------------
# 11. result_is_the_ordinary_token_set
# ---------------------------------------------------------------------------


def _signed_id_token(nonce: str) -> tuple[str, dict[str, Any]]:
    private_key, jwk = make_ed25519_keypair_and_jwk()
    token = sign_id_token(private_key, jwk["kid"], make_id_token_claims(nonce=nonce))
    return token, jwk


@pytest.mark.parametrize("mode", MODES)
async def test_result_is_the_ordinary_token_set(mode: Mode, respx_mock: respx.MockRouter) -> None:
    id_token, jwk = _signed_id_token(RAW_NONCE)  # AXIAM's token carries the RAW nonce
    respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json=_token_response(
                token_type="DPoP",
                refresh_token="refresh-token-1",
                id_token=id_token,
                scope="openid profile",
            ),
        )
    )
    client = _client(mode)
    FakeJwksEndpoint([jwk]).bind_to_client(client)

    tokens = await _login(client, scopes=["openid", "profile"])

    assert tokens.token_type == "DPoP", "read, not assumed to be Bearer"
    assert tokens.scope == "openid profile"
    assert tokens.access_token.get_secret_value() == "access-token-1"
    assert tokens.refresh_token is not None
    assert tokens.refresh_token.get_secret_value() == "refresh-token-1"
    assert tokens.id_token is not None
    assert tokens.id_claims is not None
    assert tokens.id_claims.nonce == RAW_NONCE
    # Redacted renderings (§12.5).
    assert "access-token-1" not in repr(tokens) + str(tokens) + tokens.model_dump_json()

    # A 200 without refresh_token and id_token decodes with both absent.
    respx_mock.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=_token_response()))
    bare = await _login(client)
    assert bare.refresh_token is None
    assert bare.id_token is None
    assert bare.id_claims is None

    # Existing posture (device_login / login_client_credentials): returned, not
    # adopted -- the client sends no bearer credential afterwards.
    probe = client._session.sync_client.build_request("GET", f"{BASE_URL}/api/v1/ping")
    client._apply_bearer_credential(probe)
    assert "authorization" not in probe.headers


@pytest.mark.parametrize("mode", MODES)
async def test_id_token_is_validated_with_the_raw_nonce_and_a_mismatch_discards_the_set(
    mode: Mode, respx_mock: respx.MockRouter
) -> None:
    # The claim carries the HASH (as the provider's would): not what AXIAM issues.
    id_token, jwk = _signed_id_token(RAW_NONCE_SHA256)
    respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json=_token_response(
                access_token="must-never-be-returned", id_token=id_token, scope="openid"
            ),
        )
    )
    client = _client(mode)
    FakeJwksEndpoint([jwk]).bind_to_client(client)

    with pytest.raises(AuthError) as excinfo:
        await _login(client, scopes=["openid"])

    assert getattr(excinfo.value, "reason", None) == "nonce_mismatch" or "nonce" in str(
        excinfo.value
    )
    assert "must-never-be-returned" not in str(excinfo.value)
    assert RAW_NONCE not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 12. no_secret_in_logs_or_errors
# ---------------------------------------------------------------------------

#: Fixture values distinctive enough that no other string contains them.
SECRET_ID_TOKEN = "provider-id-token-FIXTURE-8f1c2a"  # noqa: S105
SECRET_NONCE = "raw-nonce-FIXTURE-3d9e7b"


def _failure_responses() -> list[tuple[str, Any]]:
    return [
        ("invalid_grant", _oauth_error(400, "invalid_grant", GENERIC_INVALID_GRANT)),
        ("consent_required", _oauth_error(400, "consent_required")),
        ("unauthorized_client", _oauth_error(400, "unauthorized_client")),
        ("invalid_client", _oauth_error(401, "invalid_client", **{"WWW-Authenticate": "Basic"})),
        ("invalid_scope", _oauth_error(400, "invalid_scope")),
        ("invalid_target", _oauth_error(400, "invalid_target")),
        ("rate_limit", _oauth_error(429, "rate_limit_exceeded", **{"Retry-After": "7"})),
        ("server_error", _oauth_error(500, "server_error", "datastore unavailable")),
        ("server_error_no_body", httpx.Response(500)),
        ("transport", httpx.ConnectError("connection reset")),
    ]


def _everything_about(exc: BaseException) -> str:
    """Every rendering of an error a caller or a log handler could reach."""
    return "\n".join(
        [
            str(exc),
            repr(exc),
            "".join(traceback.format_exception(exc)),
            repr(getattr(exc, "__dict__", {})),
            repr(exc.args),
            repr(exc.__cause__),
            repr(exc.__context__),
        ]
    )


@pytest.mark.parametrize("mode", MODES)
async def test_no_secret_in_logs_or_errors(
    mode: Mode, respx_mock: respx.MockRouter, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    events: list[object] = []
    sdk_logger = logging.getLogger("axiam_sdk.test_native_sign_in")
    sdk_logger.setLevel(logging.DEBUG)
    client = _client(mode, logger=sdk_logger, telemetry_hook=events.append)
    route = respx_mock.post(TOKEN_URL)
    rendered: list[str] = []

    # Failures of tests 5 to 10.
    for name, outcome in _failure_responses():
        if isinstance(outcome, Exception):
            route.mock(side_effect=outcome)
        else:
            route.mock(return_value=outcome)
        with pytest.raises(Exception) as excinfo:  # noqa: PT011 - the class varies by case
            await _login(client, id_token=SECRET_ID_TOKEN, nonce=SECRET_NONCE)
        rendered.append(f"{name}\n{_everything_about(excinfo.value)}")

    # Test 5: the local refusals (an empty value of each, and the oversize nonce).
    for field in ("provider", "id_token", "nonce"):
        inputs: dict[str, Any] = {
            "provider": PROVIDER_UUID,
            "id_token": SECRET_ID_TOKEN,
            "nonce": SECRET_NONCE,
        }
        inputs[field] = ""
        with pytest.raises(ValueError) as value_error:
            await _login(client, **inputs)
        rendered.append(_everything_about(value_error.value))
    with pytest.raises(ValueError) as too_long:
        await _login(client, id_token=SECRET_ID_TOKEN, nonce=SECRET_NONCE * 100)
    rendered.append(_everything_about(too_long.value))
    with pytest.raises(AuthError) as slug_only:
        await _login(client, id_token=SECRET_ID_TOKEN, nonce=SECRET_NONCE, tenant_id=None)
    rendered.append(_everything_about(slug_only.value))

    # A §12.4 failure on an otherwise successful response.
    id_token, jwk = _signed_id_token("some-other-nonce")
    FakeJwksEndpoint([jwk]).bind_to_client(client)
    route.mock(
        return_value=httpx.Response(200, json=_token_response(id_token=id_token, scope="openid"))
    )
    with pytest.raises(AuthError) as mismatch:
        await _login(client, id_token=SECRET_ID_TOKEN, nonce=SECRET_NONCE, scopes=["openid"])
    rendered.append(_everything_about(mismatch.value))

    # The success path.
    route.mock(return_value=httpx.Response(200, json=_token_response()))
    result = await _login(client, id_token=SECRET_ID_TOKEN, nonce=SECRET_NONCE)
    rendered.append(repr(result) + str(result) + result.model_dump_json())

    haystack = "\n".join(rendered + [r.getMessage() for r in caplog.records] + [caplog.text])
    haystack += "\n".join(repr(event) for event in events)
    haystack += repr(vars(client).keys()) + repr(
        {k: v for k, v in vars(client).items() if k != "_session"}
    )
    for secret in (SECRET_ID_TOKEN, SECRET_NONCE):
        assert secret not in haystack
    # And the client kept neither.
    for value in vars(client).values():
        assert SECRET_ID_TOKEN not in repr(value)
        assert SECRET_NONCE not in repr(value)


@pytest.mark.parametrize("mode", MODES)
async def test_no_secret_in_logs_or_errors_when_the_inputs_are_wrapped(
    mode: Mode, respx_mock: respx.MockRouter, caplog: pytest.LogCaptureFixture
) -> None:
    from pydantic import SecretStr

    caplog.set_level(logging.DEBUG)
    respx_mock.post(TOKEN_URL).mock(
        return_value=_oauth_error(400, "invalid_grant", GENERIC_INVALID_GRANT)
    )

    with pytest.raises(OAuthProtocolError) as excinfo:
        await _login(
            _client(mode), id_token=SecretStr(SECRET_ID_TOKEN), nonce=SecretStr(SECRET_NONCE)
        )

    haystack = _everything_about(excinfo.value) + caplog.text
    assert SECRET_ID_TOKEN not in haystack
    assert SECRET_NONCE not in haystack
    # SecretStr is accepted: the wire carried the unwrapped values.
    sent = _form(respx_mock.calls.last.request)
    assert sent["id_token"] == SECRET_ID_TOKEN
    assert sent["nonce"] == SECRET_NONCE


# ---------------------------------------------------------------------------
# 13. native_nonce_pair
# ---------------------------------------------------------------------------


def _base64url_decode(value: str) -> bytes:
    assert "=" not in value, "base64url without padding"
    assert set(value) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@pytest.mark.parametrize("mode", MODES)
def test_native_nonce_pair(mode: Mode, caplog: pytest.LogCaptureFixture) -> None:
    client = _client(mode)

    first = client.native_nonce()  # synchronous on both clients: no network, no await
    second = client.native_nonce()

    assert isinstance(first, ProviderNonce)
    raw = first.raw.get_secret_value()
    assert len(_base64url_decode(raw)) >= 32
    assert len(first.hashed) == 64
    assert first.hashed == first.hashed.lower()
    assert set(first.hashed) <= set("0123456789abcdef")
    assert first.hashed == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert (first.raw.get_secret_value(), first.hashed) != (
        second.raw.get_secret_value(),
        second.hashed,
    )
    # `raw` is wrapped; `hashed` is a plain string.
    assert raw not in repr(first) + str(first) + first.model_dump_json()
    assert raw not in str(first.model_dump(mode="json"))
    assert first.hashed in repr(first)
    assert type(first.hashed) is str
    assert type(first.raw).__name__ == "SecretStr"


def test_native_nonce_fixed_vector() -> None:
    """The vector tests the hashing step only; `raw` itself is random."""
    from axiam_sdk._oidc_pkce import hash_native_nonce

    assert hash_native_nonce(RAW_NONCE) == RAW_NONCE_SHA256


@pytest.mark.parametrize("mode", MODES)
async def test_native_nonce_makes_no_request_and_feeds_the_login(
    mode: Mode, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=_token_response())
    )
    client = _client(mode)

    pair = client.native_nonce()
    assert len(respx_mock.calls) == 0

    await _login(client, nonce=pair.raw)
    sent = _form(route.calls.last.request)["nonce"]
    assert sent == pair.raw.get_secret_value()
    assert hashlib.sha256(sent.encode()).hexdigest() == pair.hashed
