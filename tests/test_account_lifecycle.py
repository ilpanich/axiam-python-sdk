"""§25 account lifecycle and MFA enrolment — the CONTRACT.md §25.6 test set.

The assertion worth reading is ``test_secret_never_serializes``: it scans for
the secret **value**, not the field name, which is what catches ``totp_uri`` —
the field that actually reaches a log, because it is the one a caller passes to
a QR renderer, and the one that silently contains the secret it sits beside.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AuthzError, AxiamClient

BASE_URL = "https://axiam.test"
A = f"{BASE_URL}/api/v1/auth"

SECRET = "JBSWY3DPEHPK3PXPSECRETVALUE"
TOTP_URI = f"otpauth://totp/AXIAM:alice@example.com?secret={SECRET}&issuer=AXIAM"
SETUP_TOKEN = "setup-token-value-do-not-log"  # noqa: S105
RESET_TOKEN = "reset-token-value-do-not-log"  # noqa: S105
ORG_ID = "33333333-3333-3333-3333-333333333333"
TENANT_ID = "44444444-4444-4444-4444-444444444444"

ENROLL_BODY = {"secret_base32": SECRET, "totp_uri": TOTP_URI}


def _access_token() -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"EdDSA","typ":"JWT"}').rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps({"org_id": ORG_ID, "tenant_id": TENANT_ID, "exp": 9999999999}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.fake-signature"


def _session_response(body: dict[str, Any]) -> httpx.Response:
    return httpx.Response(
        200,
        json=body,
        headers=[
            ("Set-Cookie", f"axiam_access={_access_token()}; Path=/; HttpOnly"),
            ("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/api/v1/auth/refresh; HttpOnly"),
            ("X-CSRF-Token", "csrf-token-1"),
        ],
    )


def _client(**kwargs: Any) -> AxiamClient:
    return AxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL, tenant_slug="acme", org_slug="globex", **kwargs
    )


LOGIN_SUCCESS = {
    "user": {"id": "u1", "username": "alice", "email": "alice@example.com"},
    "session_id": "s1",
    "expires_in": 900,
}


# ---------------------------------------------------------------------------
# §25.2 rule 1 — login's third outcome (the breaking change)
# ---------------------------------------------------------------------------


@respx.mock
def test_login_surfaces_the_setup_branch_as_an_outcome() -> None:
    respx.post(f"{A}/login").mock(
        return_value=httpx.Response(
            403, json={"mfa_setup_required": True, "setup_token": SETUP_TOKEN}
        )
    )
    result = _client().login("alice@example.com", "pw")

    assert result.mfa_setup_required is True
    assert result.mfa_required is False
    assert result.setup_token is not None
    assert result.setup_token.get_secret_value() == SETUP_TOKEN


@respx.mock
def test_a_genuine_403_still_raises() -> None:
    # Matched on the body's discriminant, not on the status: a real
    # authorization failure is also a 403 and must not be read as a setup
    # branch just because it shares a status code.
    respx.post(f"{A}/login").mock(
        return_value=httpx.Response(403, json={"message": "tenant suspended"})
    )
    with pytest.raises(AuthzError):
        _client().login("alice@example.com", "pw")


@respx.mock
def test_the_setup_token_does_not_serialize() -> None:
    respx.post(f"{A}/login").mock(
        return_value=httpx.Response(
            403, json={"mfa_setup_required": True, "setup_token": SETUP_TOKEN}
        )
    )
    result = _client().login("alice@example.com", "pw")
    assert SETUP_TOKEN not in f"{result!r}{result}{result.model_dump_json()}"


# ---------------------------------------------------------------------------
# MFA enrolment
# ---------------------------------------------------------------------------


@respx.mock
def test_mfa_enroll_returns_the_secret_and_uri() -> None:
    respx.post(f"{A}/mfa/enroll").mock(return_value=httpx.Response(200, json=ENROLL_BODY))
    enrolment = _client().mfa_enroll()
    assert enrolment.secret_base32.get_secret_value() == SECRET
    assert SECRET in enrolment.totp_uri.get_secret_value()


@respx.mock
def test_secret_never_serializes_scanned_by_value() -> None:
    respx.post(f"{A}/mfa/enroll").mock(return_value=httpx.Response(200, json=ENROLL_BODY))
    enrolment = _client().mfa_enroll()

    surfaces = "".join(
        [
            repr(enrolment),
            str(enrolment),
            enrolment.model_dump_json(),
            str(enrolment.secret_base32),
            str(enrolment.totp_uri),
        ]
    )
    # Scanning for the VALUE, not the field name. `totp_uri` contains the
    # secret, so an SDK that wrapped only `secret_base32` fails right here.
    assert SECRET not in surfaces


@respx.mock
def test_mfa_confirm_activates_the_factor() -> None:
    respx.post(f"{A}/mfa/confirm").mock(
        return_value=httpx.Response(200, json={"mfa_enabled": True})
    )
    assert _client().mfa_confirm(totp_code="123456") is True


@respx.mock
def test_mfa_confirm_raises_on_a_wrong_code() -> None:
    respx.post(f"{A}/mfa/confirm").mock(
        return_value=httpx.Response(401, json={"message": "invalid code"})
    )
    with pytest.raises(AuthError):
        _client().mfa_confirm(totp_code="000000")


@respx.mock
def test_mfa_enroll_does_not_clear_the_decision_memo() -> None:
    respx.post(f"{A}/mfa/enroll").mock(return_value=httpx.Response(200, json=ENROLL_BODY))
    respx.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True})
    )
    client = _client(decision_memo_ttl_ms=60_000)
    client.check_access(action="read", resource_id="doc:1")
    before = len(client._decision_memo)
    assert before > 0

    client.mfa_enroll()
    # §25.2 rule 3: the subject has not changed, and discarding a warm memo on
    # an unrelated profile action costs a round trip on every later check.
    assert len(client._decision_memo) == before


@respx.mock
def test_mfa_setup_confirm_does_clear_it_and_adopts_the_session() -> None:
    respx.post(f"{A}/mfa/setup/confirm").mock(return_value=_session_response(LOGIN_SUCCESS))
    respx.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True})
    )
    client = _client(decision_memo_ttl_ms=60_000)
    client.check_access(action="read", resource_id="doc:1")
    assert len(client._decision_memo) > 0

    result = client.mfa_setup_confirm(setup_token=SETUP_TOKEN, totp_code="123456")
    assert len(client._decision_memo) == 0
    assert result.mfa_required is False
    assert client._session.cookie_value("axiam_access")


@respx.mock
def test_the_forced_path_runs_end_to_end_from_the_login_outcome() -> None:
    respx.post(f"{A}/login").mock(
        return_value=httpx.Response(
            403, json={"mfa_setup_required": True, "setup_token": SETUP_TOKEN}
        )
    )
    enroll = respx.post(f"{A}/mfa/setup/enroll").mock(
        return_value=httpx.Response(200, json=ENROLL_BODY)
    )
    respx.post(f"{A}/mfa/setup/confirm").mock(return_value=_session_response(LOGIN_SUCCESS))

    client = _client()
    login = client.login("alice@example.com", "pw")
    assert login.setup_token is not None

    enrolment = client.mfa_setup_enroll(setup_token=login.setup_token)
    assert enrolment.secret_base32.get_secret_value() == SECRET
    assert json.loads(enroll.calls[0].request.content) == {"setup_token": SETUP_TOKEN}

    done = client.mfa_setup_confirm(setup_token=login.setup_token, totp_code="123456")
    assert done.mfa_required is False


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------


@respx.mock
def test_verify_email_sends_the_token_in_the_body_not_the_query() -> None:
    route = respx.post(f"{A}/verify-email").mock(return_value=httpx.Response(200))
    _client().verify_email(token="verify-tok", tenant_id=TENANT_ID)

    request = route.calls[0].request
    assert json.loads(request.content) == {"token": "verify-tok", "tenant_id": TENANT_ID}
    assert "token=" not in str(request.url)


@respx.mock
def test_resend_verification() -> None:
    route = respx.post(f"{A}/resend-verification").mock(return_value=httpx.Response(200))
    _client().resend_verification(email="alice@example.com", tenant_id=TENANT_ID)
    assert json.loads(route.calls[0].request.content) == {
        "email": "alice@example.com",
        "tenant_id": TENANT_ID,
    }


# ---------------------------------------------------------------------------
# §25.4 — password reset
# ---------------------------------------------------------------------------


@respx.mock
def test_request_reset_resolves_for_an_unknown_address() -> None:
    # The uniform response is the whole mechanism; an SDK that surfaced a
    # "no such user" signal would rebuild the enumeration oracle it prevents.
    respx.post(f"{A}/reset").mock(return_value=httpx.Response(200))
    assert _client().request_password_reset(email="nobody@example.com") is None


@respx.mock
def test_request_reset_fills_the_workspace_from_the_client() -> None:
    route = respx.post(f"{A}/reset").mock(return_value=httpx.Response(200))
    _client().request_password_reset(email="alice@example.com")
    assert json.loads(route.calls[0].request.content) == {
        "email": "alice@example.com",
        "org_slug": "globex",
        "tenant_slug": "acme",
    }


@respx.mock
def test_reset_context_returns_the_opaque_policy_and_no_identity() -> None:
    respx.get(f"{A}/reset/context").mock(
        return_value=httpx.Response(200, json={"opaque": {"mode": "required"}})
    )
    context = _client().password_reset_context(token=RESET_TOKEN)
    assert context.opaque == {"mode": "required"}
    # Contract 1.26 removed the username. Assert the shape, so reintroducing
    # one downstream fails here rather than in a security review.
    assert set(context.model_dump().keys()) == {"opaque"}


@respx.mock
def test_reset_context_404_is_one_indistinguishable_failure() -> None:
    respx.get(f"{A}/reset/context").mock(return_value=httpx.Response(404))
    with pytest.raises(Exception):  # noqa: B017 - unknown/expired/consumed are not distinguished
        _client().password_reset_context(token="some-other-token")


@respx.mock
def test_confirm_reset_sends_the_opaque_record_when_there_is_one() -> None:
    route = respx.post(f"{A}/reset/confirm").mock(return_value=httpx.Response(200))
    _client().confirm_password_reset(
        token=RESET_TOKEN,
        new_password="new-password",
        tenant_id=TENANT_ID,
        opaque={"registration_record": "abc"},
    )
    assert json.loads(route.calls[0].request.content)["opaque"] == {"registration_record": "abc"}


@respx.mock
def test_confirm_reset_omits_opaque_entirely_when_there_is_none() -> None:
    route = respx.post(f"{A}/reset/confirm").mock(return_value=httpx.Response(200))
    _client().confirm_password_reset(
        token=RESET_TOKEN, new_password="new-password", tenant_id=TENANT_ID
    )
    assert "opaque" not in json.loads(route.calls[0].request.content)


# ---------------------------------------------------------------------------
# The async twins
# ---------------------------------------------------------------------------


@respx.mock
async def test_async_mfa_enroll_and_confirm() -> None:
    respx.post(f"{A}/mfa/enroll").mock(return_value=httpx.Response(200, json=ENROLL_BODY))
    respx.post(f"{A}/mfa/confirm").mock(
        return_value=httpx.Response(200, json={"mfa_enabled": True})
    )
    client = AsyncAxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL, tenant_slug="acme", org_slug="globex"
    )
    enrolment = await client.mfa_enroll()
    assert enrolment.secret_base32.get_secret_value() == SECRET
    assert await client.mfa_confirm(totp_code="123456") is True


@respx.mock
async def test_async_login_surfaces_the_setup_branch() -> None:
    respx.post(f"{A}/login").mock(
        return_value=httpx.Response(
            403, json={"mfa_setup_required": True, "setup_token": SETUP_TOKEN}
        )
    )
    client = AsyncAxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL, tenant_slug="acme", org_slug="globex"
    )
    result = await client.login("alice@example.com", "pw")
    assert result.mfa_setup_required is True


def _async_client(**kwargs: Any) -> AsyncAxiamClient:
    return AsyncAxiamClient(  # type: ignore[arg-type]
        base_url=BASE_URL, tenant_slug="acme", org_slug="globex", **kwargs
    )


@respx.mock
async def test_async_forced_enrolment_runs_end_to_end() -> None:
    respx.post(f"{A}/login").mock(
        return_value=httpx.Response(
            403, json={"mfa_setup_required": True, "setup_token": SETUP_TOKEN}
        )
    )
    enroll = respx.post(f"{A}/mfa/setup/enroll").mock(
        return_value=httpx.Response(200, json=ENROLL_BODY)
    )
    respx.post(f"{A}/mfa/setup/confirm").mock(return_value=_session_response(LOGIN_SUCCESS))
    client = _async_client()

    outcome = await client.login("alice@example.com", "pw")
    assert outcome.mfa_setup_required is True
    assert outcome.setup_token is not None

    enrolment = await client.mfa_setup_enroll(setup_token=outcome.setup_token)
    assert enrolment.secret_base32.get_secret_value() == SECRET
    assert json.loads(enroll.calls[0].request.content)["setup_token"] == SETUP_TOKEN

    # §25.2 rule 2: this IS the completion of the interrupted login, so it
    # adopts credentials the same way login does.
    result = await client.mfa_setup_confirm(setup_token=SETUP_TOKEN, totp_code="123456")
    assert result.mfa_required is False
    assert client._session.cookie_value("axiam_access")


@respx.mock
async def test_async_verify_email_and_resend() -> None:
    verify = respx.post(f"{A}/verify-email").mock(return_value=httpx.Response(200))
    resend = respx.post(f"{A}/resend-verification").mock(return_value=httpx.Response(204))
    client = _async_client()

    await client.verify_email(token=RESET_TOKEN, tenant_id=TENANT_ID)
    await client.resend_verification(email="alice@example.com", tenant_id=TENANT_ID)

    # The token is a body field, not a query parameter: a URL reaches proxy
    # logs and browser history, and this one is a bearer credential.
    assert "token" not in dict(verify.calls[0].request.url.params)
    assert json.loads(verify.calls[0].request.content)["token"] == RESET_TOKEN
    assert json.loads(resend.calls[0].request.content) == {
        "email": "alice@example.com",
        "tenant_id": TENANT_ID,
    }


@respx.mock
async def test_async_password_reset_round_trip() -> None:
    request_route = respx.post(f"{A}/reset").mock(return_value=httpx.Response(200))
    respx.get(f"{A}/reset/context").mock(
        return_value=httpx.Response(200, json={"opaque": {"mode": "required"}})
    )
    confirm = respx.post(f"{A}/reset/confirm").mock(return_value=httpx.Response(200))
    client = _async_client()

    await client.request_password_reset(email="alice@example.com")
    # The workspace is filled from the client when the caller omits it.
    assert json.loads(request_route.calls[0].request.content) == {
        "email": "alice@example.com",
        "org_slug": "globex",
        "tenant_slug": "acme",
    }

    context = await client.password_reset_context(token=RESET_TOKEN)
    assert context.opaque == {"mode": "required"}
    assert set(context.model_dump().keys()) == {"opaque"}

    await client.confirm_password_reset(
        token=RESET_TOKEN,
        new_password="new-password",
        tenant_id=TENANT_ID,
        opaque={"registration_record": "abc"},
    )
    assert json.loads(confirm.calls[0].request.content)["opaque"] == {"registration_record": "abc"}
