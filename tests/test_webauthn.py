"""§24 WebAuthn relying-party layer — the CONTRACT.md §24.8 test set.

Every assertion maps to a named requirement in §24.8. Two are worth reading
twice:

* ``test_register_start_does_not_retry_503`` asserts on the **request count**,
  not on the exception type, because §24.4 rule 2 regresses the moment someone
  tidies a retry predicate — and a type assertion would still pass.
* ``test_state_token_is_never_parsed`` hands the SDK a state token that is not
  a JWT at all. If anything decoded one, this is where it would fail.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
import respx

from axiam_sdk import (
    AsyncAxiamClient,
    AuthError,
    AuthzError,
    AxiamClient,
    WebauthnChallenge,
    WebauthnFailure,
    WebauthnWorkspace,
    classify_webauthn_error,
    webauthn_error_message,
    webauthn_request_json,
)

BASE_URL = "https://axiam.test"
W = f"{BASE_URL}/api/v1/auth/webauthn"

STATE_TOKEN = "state-token-fixture-value-do-not-log"  # noqa: S105
CHALLENGE_TOKEN = "challenge-token-fixture-do-not-log"  # noqa: S105
ACCESS_TOKEN = "access-token-fixture-do-not-log"  # noqa: S105
REFRESH_TOKEN = "refresh-token-fixture-do-not-log"  # noqa: S105

# Deliberately "unusual but valid": every optional field populated, so the
# pass-through assertion has something to catch an over-eager implementation
# dropping. A minimal fixture would prove nothing.
CREATION_CHALLENGE: dict[str, Any] = {
    "publicKey": {
        "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
        "rp": {"id": "axiam.test", "name": "AXIAM Test"},
        "user": {"id": "dXNlci1oYW5kbGU", "name": "alice", "displayName": "Alice"},
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -8},
            {"type": "public-key", "alg": -257},
        ],
        "timeout": 60000,
        "excludeCredentials": [
            {"id": "ZXhpc3Rpbmc", "type": "public-key", "transports": ["usb", "nfc"]}
        ],
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": True,
            "userVerification": "required",
        },
        "attestation": "direct",
        "extensions": {"credProps": True},
    }
}

MINIMAL_CREATION_CHALLENGE: dict[str, Any] = {
    "publicKey": {
        "challenge": "bWluaW1hbA",
        "rp": {"name": "AXIAM Test"},
        "user": {"id": "dQ", "name": "bob", "displayName": "Bob"},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }
}

REQUEST_CHALLENGE: dict[str, Any] = {
    "publicKey": {
        "challenge": "YXV0aC1jaGFsbGVuZ2U",
        "rpId": "axiam.test",
        "allowCredentials": [{"id": "ZXhpc3Rpbmc", "type": "public-key"}],
        "userVerification": "required",
    }
}

DISCOVERABLE_CHALLENGE: dict[str, Any] = {
    "publicKey": {
        "challenge": "ZGlzY292ZXJhYmxl",
        "rpId": "axiam.test",
        "allowCredentials": [],
        "userVerification": "required",
    }
}

REGISTRATION_RESPONSE: dict[str, Any] = {
    "id": "bmV3LWNyZWQ",
    "rawId": "bmV3LWNyZWQ",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
        "attestationObject": "o2NmbXRkbm9uZQ",
        "transports": ["internal"],
        # An unknown key the SDK must carry rather than strip.
        "vendorSpecific": "must-survive",
    },
    "type": "public-key",
    "clientExtensionResults": {"credProps": {"rk": True}},
}

AUTHENTICATION_RESPONSE: dict[str, Any] = {
    "id": "bmV3LWNyZWQ",
    "rawId": "bmV3LWNyZWQ",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
        "authenticatorData": "YXV0aC1kYXRh",
        "signature": "c2ln",
        "userHandle": "dXNlci1oYW5kbGU",
    },
    "type": "public-key",
    "clientExtensionResults": {},
}

CREDENTIAL_WIRE = {
    "id": "11111111-1111-1111-1111-111111111111",
    "credential_id": "bmV3LWNyZWQ",
    "name": "Alice's laptop",
    "credential_type": "passkey",
    "created_at": "2026-08-22T10:00:00Z",
    "last_used_at": None,
}


def _login_wire() -> dict[str, Any]:
    return {
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "session_id": "22222222-2222-2222-2222-222222222222",
        "expires_in": 900,
    }


def _client(**kwargs: Any) -> AxiamClient:
    return AxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL, tenant_slug="acme", org_slug="globex", **kwargs
    )


def _signed_in(client: AxiamClient) -> AxiamClient:
    """Seed the access cookie — what the SDK reads as "signed in" (§24.1)."""
    client._session._cookies.set("axiam_access", "seeded-access", domain="axiam.test")
    return client


ORG_ID = "33333333-3333-3333-3333-333333333333"
TENANT_ID = "44444444-4444-4444-4444-444444444444"


def _access_token() -> str:
    """A structurally valid unsigned JWT.

    ``_absorb_session_cookies`` decodes the payload for the org/tenant claims,
    so it has to parse — the signature is never checked on this path.
    """
    header = base64.urlsafe_b64encode(b'{"alg":"EdDSA","typ":"JWT"}').rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps({"org_id": ORG_ID, "tenant_id": TENANT_ID, "exp": 9999999999}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.fake-signature"


def _with_session_cookies(body: dict[str, Any]) -> httpx.Response:
    """A ``200`` carrying the cookie triple a completed passkey sign-in sets.

    The server started setting these with contract 1.28 — before that, a
    passkey sign-in returned tokens in the body and left the caller with no
    session at all.
    """
    access = _access_token()
    return httpx.Response(
        200,
        json=body,
        headers=[
            ("Set-Cookie", f"axiam_access={access}; Path=/; HttpOnly"),
            ("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/api/v1/auth/refresh; HttpOnly"),
            ("Set-Cookie", "axiam_csrf=csrf-token-1; Path=/"),
            ("X-CSRF-Token", "csrf-token-1"),
        ],
    )


# ---------------------------------------------------------------------------
# §24.0 — options and responses pass through untouched
# ---------------------------------------------------------------------------


@respx.mock
def test_options_pass_through_structurally_unchanged() -> None:
    respx.post(f"{W}/register/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": CREATION_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    challenge = _signed_in(_client()).webauthn_register_start()
    # Structural equality, not a spot-check: the failure mode this guards is an
    # SDK that quietly drops the one option it did not recognize.
    assert challenge.challenge == CREATION_CHALLENGE


@respx.mock
def test_no_field_is_synthesized_when_the_server_omitted_it() -> None:
    respx.post(f"{W}/register/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": MINIMAL_CREATION_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    challenge = _signed_in(_client()).webauthn_register_start()
    assert "authenticatorSelection" not in challenge.challenge["publicKey"]
    assert "timeout" not in challenge.challenge["publicKey"]
    assert challenge.challenge == MINIMAL_CREATION_CHALLENGE


@respx.mock
def test_authenticator_response_is_sent_back_verbatim() -> None:
    route = respx.post(f"{W}/register/finish").mock(
        return_value=httpx.Response(201, json=CREDENTIAL_WIRE)
    )
    _signed_in(_client()).webauthn_register_finish(
        state_token=STATE_TOKEN, credential_name="laptop", response=REGISTRATION_RESPONSE
    )
    sent = json.loads(route.calls[0].request.content)
    assert sent["response"] == REGISTRATION_RESPONSE


@respx.mock
def test_assertion_response_is_preserved_byte_for_byte() -> None:
    route = respx.post(f"{W}/authenticate/finish").mock(
        return_value=_with_session_cookies(_login_wire())
    )
    _client().webauthn_authenticate_finish(
        state_token=STATE_TOKEN, response=AUTHENTICATION_RESPONSE
    )
    sent = json.loads(route.calls[0].request.content)
    assert sent["response"] == AUTHENTICATION_RESPONSE


# ---------------------------------------------------------------------------
# §24.1 — preconditions and workspace resolution
# ---------------------------------------------------------------------------


@respx.mock
def test_register_start_without_a_session_makes_no_wire_call() -> None:
    route = respx.post(f"{W}/register/start")
    with pytest.raises(AuthError):
        _client().webauthn_register_start()
    # Asserted on the transport, not on the exception type alone.
    assert route.call_count == 0


@respx.mock
def test_register_finish_without_a_session_makes_no_wire_call() -> None:
    route = respx.post(f"{W}/register/finish")
    with pytest.raises(AuthError):
        _client().webauthn_register_finish(
            state_token=STATE_TOKEN, credential_name="x", response=REGISTRATION_RESPONSE
        )
    assert route.call_count == 0


@respx.mock
def test_discoverable_workspace_comes_from_the_client_in_slug_form() -> None:
    route = respx.post(f"{W}/authenticate/discoverable/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": DISCOVERABLE_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    _client().webauthn_discoverable_start()
    assert json.loads(route.calls[0].request.content) == {
        "org_slug": "globex",
        "tenant_slug": "acme",
    }


@respx.mock
def test_discoverable_workspace_can_be_overridden() -> None:
    route = respx.post(f"{W}/authenticate/discoverable/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": DISCOVERABLE_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    _client().webauthn_discoverable_start(
        workspace=WebauthnWorkspace(
            org_id="33333333-3333-3333-3333-333333333333", tenant_slug="other"
        )
    )
    body = json.loads(route.calls[0].request.content)
    assert body["org_id"] == "33333333-3333-3333-3333-333333333333"
    assert body["tenant_slug"] == "other"


@respx.mock
def test_discoverable_start_without_an_org_raises_client_side() -> None:
    route = respx.post(f"{W}/authenticate/discoverable/start")
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")  # type: ignore[arg-type]
    with pytest.raises(AuthError, match="organization"):
        client.webauthn_discoverable_start()
    assert route.call_count == 0


# ---------------------------------------------------------------------------
# §24.2 — two distinct flows
# ---------------------------------------------------------------------------


@respx.mock
def test_second_factor_start_sends_only_the_challenge_token() -> None:
    route = respx.post(f"{W}/authenticate/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": REQUEST_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    _client().webauthn_authenticate_start(challenge_token=CHALLENGE_TOKEN)
    assert json.loads(route.calls[0].request.content) == {"challenge_token": CHALLENGE_TOKEN}


@respx.mock
def test_discoverable_start_never_sends_a_challenge_token() -> None:
    route = respx.post(f"{W}/authenticate/discoverable/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": DISCOVERABLE_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    _client().webauthn_discoverable_start()
    assert "challenge_token" not in json.loads(route.calls[0].request.content)


@respx.mock
def test_discoverable_finish_reaches_its_own_endpoint() -> None:
    discoverable = respx.post(f"{W}/authenticate/discoverable/finish").mock(
        return_value=_with_session_cookies(_login_wire())
    )
    username_bound = respx.post(f"{W}/authenticate/finish")
    _client().webauthn_discoverable_finish(
        state_token=STATE_TOKEN, response=AUTHENTICATION_RESPONSE
    )
    assert discoverable.call_count == 1
    assert username_bound.call_count == 0


# ---------------------------------------------------------------------------
# §24.3 — credential adoption
# ---------------------------------------------------------------------------


@respx.mock
def test_a_completed_sign_in_adopts_the_session() -> None:
    respx.post(f"{W}/authenticate/finish").mock(return_value=_with_session_cookies(_login_wire()))
    client = _client()
    result = client.webauthn_authenticate_finish(
        state_token=STATE_TOKEN, response=AUTHENTICATION_RESPONSE
    )
    # The client's own state — not merely that a token came back. §24.3 rule 1
    # exists because returning a token set without adopting it would make this
    # the one way to log in that does not log you in.
    assert client._session.cookie_value("axiam_access")
    assert client.resolved_org_id() == ORG_ID
    assert result.access_token.get_secret_value() == ACCESS_TOKEN
    assert result.expires_in == 900


@respx.mock
def test_sign_in_clears_the_decision_memo() -> None:
    respx.post(f"{W}/authenticate/finish").mock(return_value=_with_session_cookies(_login_wire()))
    respx.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True})
    )
    client = _client(decision_memo_ttl_ms=60_000)
    _signed_in(client)
    client.check_access(action="read", resource_id="doc:1")
    assert len(client._decision_memo) > 0

    client.webauthn_authenticate_finish(state_token=STATE_TOKEN, response=AUTHENTICATION_RESPONSE)
    assert len(client._decision_memo) == 0


@respx.mock
def test_register_finish_returns_the_credential_and_adopts_nothing() -> None:
    respx.post(f"{W}/register/finish").mock(return_value=httpx.Response(201, json=CREDENTIAL_WIRE))
    credential = _signed_in(_client()).webauthn_register_finish(
        state_token=STATE_TOKEN, credential_name="laptop", response=REGISTRATION_RESPONSE
    )
    assert credential.credential_id == "bmV3LWNyZWQ"
    assert credential.credential_type == "passkey"
    assert credential.last_used_at is None


# ---------------------------------------------------------------------------
# §24.4 — error taxonomy
# ---------------------------------------------------------------------------


@respx.mock
def test_register_start_does_not_retry_503() -> None:
    route = respx.post(f"{W}/register/start").mock(
        return_value=httpx.Response(503, json={"message": "FIDO metadata unavailable"})
    )
    with pytest.raises(Exception):  # noqa: B017 - any taxonomy error; the count is the point
        _signed_in(_client()).webauthn_register_start()
    # §24.4 rule 2. Asserted on the request count: a 503 here is a server
    # CONFIGURATION state, retrying changes nothing, and this regresses
    # silently the moment the retry predicate is tidied.
    assert route.call_count == 1


@respx.mock
def test_403_from_register_finish_is_an_authorization_error() -> None:
    respx.post(f"{W}/register/finish").mock(
        return_value=httpx.Response(403, json={"message": "not FIDO certified"})
    )
    with pytest.raises(AuthzError):
        _signed_in(_client()).webauthn_register_finish(
            state_token=STATE_TOKEN, credential_name="key", response=REGISTRATION_RESPONSE
        )


@respx.mock
def test_failed_assertion_is_an_authentication_error() -> None:
    respx.post(f"{W}/authenticate/finish").mock(
        return_value=httpx.Response(401, json={"message": "assertion failed"})
    )
    with pytest.raises(AuthError):
        _client().webauthn_authenticate_finish(
            state_token=STATE_TOKEN, response=AUTHENTICATION_RESPONSE
        )


# ---------------------------------------------------------------------------
# §24.5 — the state token is opaque, and secret
# ---------------------------------------------------------------------------


@respx.mock
def test_state_token_is_never_parsed() -> None:
    # Not a JWT, not three dot-separated segments, not base64 anything. If the
    # SDK decoded state tokens at all, this would fail — which is exactly the
    # assertion §24.8 asks for.
    not_a_jwt = "this-is-not-a-jwt-and-never-will-be"
    route = respx.post(f"{W}/authenticate/finish").mock(
        return_value=_with_session_cookies(_login_wire())
    )
    _client().webauthn_authenticate_finish(state_token=not_a_jwt, response=AUTHENTICATION_RESPONSE)
    assert json.loads(route.calls[0].request.content)["state_token"] == not_a_jwt


@respx.mock
def test_state_token_and_returned_tokens_never_serialize() -> None:
    respx.post(f"{W}/register/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": CREATION_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    respx.post(f"{W}/authenticate/finish").mock(return_value=_with_session_cookies(_login_wire()))
    challenge = _signed_in(_client()).webauthn_register_start()
    login = _client().webauthn_authenticate_finish(
        state_token=STATE_TOKEN, response=AUTHENTICATION_RESPONSE
    )

    surfaces = "".join(
        [
            repr(challenge),
            str(challenge),
            challenge.model_dump_json(),
            repr(login),
            str(login),
            login.model_dump_json(),
        ]
    )
    for secret in (STATE_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN):
        assert secret not in surfaces


# ---------------------------------------------------------------------------
# §24.6a — the JSON bridge
# ---------------------------------------------------------------------------


@respx.mock
def test_request_json_round_trips_a_creation_challenge() -> None:
    respx.post(f"{W}/register/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": CREATION_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    challenge = _signed_in(_client()).webauthn_register_start()
    # The string an Android app hands to CreatePublicKeyCredentialRequest, and
    # a browser to PublicKeyCredential.parseCreationOptionsFromJSON.
    assert json.loads(webauthn_request_json(challenge)) == CREATION_CHALLENGE["publicKey"]


def test_request_json_omits_the_publicKey_wrapper() -> None:
    challenge = WebauthnChallenge(challenge=DISCOVERABLE_CHALLENGE, state_token=STATE_TOKEN)  # type: ignore[arg-type]
    parsed = json.loads(webauthn_request_json(challenge))
    assert "publicKey" not in parsed
    assert parsed["allowCredentials"] == []


@respx.mock
def test_finish_accepts_the_platform_response_json_string() -> None:
    route = respx.post(f"{W}/authenticate/finish").mock(
        return_value=_with_session_cookies(_login_wire())
    )
    _client().webauthn_authenticate_finish(
        state_token=STATE_TOKEN, response=json.dumps(AUTHENTICATION_RESPONSE)
    )
    assert json.loads(route.calls[0].request.content)["response"] == AUTHENTICATION_RESPONSE


@respx.mock
def test_a_malformed_response_string_is_refused_before_any_wire_call() -> None:
    route = respx.post(f"{W}/authenticate/finish")
    with pytest.raises(TypeError):
        _client().webauthn_authenticate_finish(state_token=STATE_TOKEN, response="{not json")
    assert route.call_count == 0


# ---------------------------------------------------------------------------
# §24.6b rule 5 — the classification, usable with no authenticator in sight
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("NotAllowedError", WebauthnFailure.CANCELLED),
        ("InvalidStateError", WebauthnFailure.ALREADY_REGISTERED),
        ("AbortError", WebauthnFailure.TIMEOUT),
        ("NotSupportedError", WebauthnFailure.UNSUPPORTED),
        ("SecurityError", WebauthnFailure.UNSUPPORTED),
        ("SomethingElseError", WebauthnFailure.UNKNOWN),
        # An Android CreateCredentialException or an ASAuthorizationError code
        # relayed to a Python service as a bare name (§24.6b rule 5's last line).
        ("canceled", WebauthnFailure.CANCELLED),
    ],
)
def test_classification(name: str, expected: WebauthnFailure) -> None:
    assert classify_webauthn_error(name) == expected


def test_already_registered_is_distinguishable_from_cancelled() -> None:
    invalid = classify_webauthn_error("InvalidStateError")
    cancelled = classify_webauthn_error("NotAllowedError")
    assert invalid != cancelled
    # The only classification whose remedy is a different device.
    assert "different device" in webauthn_error_message(invalid)


def test_cancelled_copy_does_not_accuse_the_user() -> None:
    # The same name covers a silent timeout, and the spec will not say which.
    assert "cancelled or timed out" in webauthn_error_message(WebauthnFailure.CANCELLED)


@pytest.mark.parametrize("value", [None, 0, "", [], {}, object()])
def test_classification_never_raises(value: object) -> None:
    assert classify_webauthn_error(value) == WebauthnFailure.UNKNOWN


# ---------------------------------------------------------------------------
# The async twins carry the same behaviour
# ---------------------------------------------------------------------------


@respx.mock
async def test_async_sign_in_adopts_the_session() -> None:
    respx.post(f"{W}/authenticate/discoverable/start").mock(
        return_value=httpx.Response(
            200, json={"challenge": DISCOVERABLE_CHALLENGE, "state_token": STATE_TOKEN}
        )
    )
    respx.post(f"{W}/authenticate/discoverable/finish").mock(
        return_value=_with_session_cookies(_login_wire())
    )
    client = AsyncAxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL, tenant_slug="acme", org_slug="globex"
    )
    challenge = await client.webauthn_discoverable_start()
    result = await client.webauthn_discoverable_finish(
        state_token=challenge.state_token, response=AUTHENTICATION_RESPONSE
    )
    assert client._session.cookie_value("axiam_access")
    assert result.access_token.get_secret_value() == ACCESS_TOKEN


@respx.mock
async def test_async_register_requires_a_session() -> None:
    route = respx.post(f"{W}/register/start")
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")  # type: ignore[arg-type]
    with pytest.raises(AuthError):
        await client.webauthn_register_start()
    assert route.call_count == 0
