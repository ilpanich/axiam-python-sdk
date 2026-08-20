"""``login_opaque`` / ``opaque_enrollment`` on both clients (CONTRACT.md §23).

The protocol itself is ``libaxiam_opaque_ffi``'s and is covered by
``test_opaque_binding.py``. What is tested here is the part the SDK owns: what
goes on the wire (and, more importantly, what does NOT), which failures are
``AuthError`` and which are ``NetworkError``, and that the sync and async
clients agree on every one of those answers — they share ``_AxiamClientBase``
precisely so they cannot drift, and a test that only exercised one would let
that sharing quietly stop being true.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, NetworkError, _opaque
from tests._opaque_fake import FakeOpaqueLibrary

BASE_URL = "https://example.test"
LOGIN_START = f"{BASE_URL}/api/v1/auth/opaque/login/start"
LOGIN_FINISH = f"{BASE_URL}/api/v1/auth/opaque/login/finish"
REGISTER_START = f"{BASE_URL}/api/v1/auth/opaque/register/start"

ARGON2ID = {"ksf": "argon2id", "memory_kib": 19456, "iterations": 2, "parallelism": 1}

#: Minted per run rather than written down: nothing here depends on the value,
#: and a literal that reads like a credential is a finding for every secret
#: scanner that looks at this repository.
PASSWORD = f"correct-{secrets.token_hex(8)}"
OTHER_PASSWORD = f"incorrect-{secrets.token_hex(8)}"
USER = "ada@example.test"


def _access_token() -> str:
    """A structurally-valid unsigned JWT. The session layer decodes claims from
    the access cookie, so a login that succeeded at the protocol level still
    fails downstream without one — and would read as an OPAQUE failure."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "tenant_id": "tenant-uuid-1",
                    "org_id": "org-uuid-1",
                    "jti": "session-uuid-1",
                    "exp": 9999999999,
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.fake-signature"


def _session_cookies() -> list[tuple[str, str]]:
    return [
        ("Set-Cookie", f"axiam_access={_access_token()}; Path=/; HttpOnly"),
        ("Set-Cookie", "axiam_refresh=refresh-token; Path=/; HttpOnly"),
    ]


def _started(**overrides: Any) -> dict[str, Any]:
    body = {"opaque_session": "session-handle", "ke2": "ke2-hex", **ARGON2ID}
    body.update(overrides)
    return body


@pytest.fixture
def lib() -> Iterator[FakeOpaqueLibrary]:
    fake = FakeOpaqueLibrary()
    _opaque._set_for_tests(fake)
    try:
        yield fake
    finally:
        _opaque._reset_for_tests()


@pytest.fixture
def absent() -> Iterator[None]:
    _opaque._reset_for_tests()
    _opaque._set_for_tests(None)
    try:
        yield
    finally:
        _opaque._reset_for_tests()


def _client() -> AxiamClient:
    return AxiamClient(base_url=BASE_URL, tenant_slug="acme")


def _async_client() -> AsyncAxiamClient:
    return AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")


# ---------------------------------------------------------------------
# What crosses the wire
# ---------------------------------------------------------------------


@respx.mock
def test_login_start_carries_ke1_and_no_password(lib: FakeOpaqueLibrary) -> None:
    route = respx.post(LOGIN_START).mock(
        return_value=httpx.Response(200, json=_started()),
    )
    respx.post(LOGIN_FINISH).mock(
        return_value=httpx.Response(200, json={"mfa_required": False}, headers=_session_cookies()),
    )

    with _client() as client:
        client.login_opaque(USER, PASSWORD)

    body = json.loads(route.calls[0].request.content)
    # The entire point of the exchange. A body that still carried `password`
    # would be SRP's failure mode with extra steps.
    assert "password" not in body
    assert body["username_or_email"] == USER
    assert body["tenant_slug"] == "acme"
    assert bytes.fromhex(body["ke1"]) == b"ke1:" + PASSWORD.encode()


@respx.mock
def test_register_start_names_no_account_at_all(lib: FakeOpaqueLibrary) -> None:
    route = respx.post(REGISTER_START).mock(
        return_value=httpx.Response(
            200, json={"opaque_session": "s", "registration_response": "resp-hex", **ARGON2ID}
        ),
    )

    with _client() as client:
        enrollment = client.opaque_enrollment(PASSWORD)

    body = json.loads(route.calls[0].request.content)
    assert "password" not in body
    # No username either: a record binds to a credential identifier the server
    # chooses, which is why a later rename cannot invalidate a credential.
    assert "username_or_email" not in body
    assert body["tenant_slug"] == "acme"
    assert bytes.fromhex(body["registration_request"]) == b"req:" + PASSWORD.encode()

    assert enrollment["opaque_session"] == "s"
    assert bytes.fromhex(enrollment["registration_record"]).startswith(
        b"record:" + PASSWORD.encode() + b":resp-hex:"
    )


@respx.mock
def test_login_finish_sends_the_session_handle_the_server_issued(
    lib: FakeOpaqueLibrary,
) -> None:
    respx.post(LOGIN_START).mock(
        return_value=httpx.Response(200, json=_started(opaque_session="handle-42")),
    )
    finish = respx.post(LOGIN_FINISH).mock(
        return_value=httpx.Response(200, json={"mfa_required": False}, headers=_session_cookies()),
    )

    with _client() as client:
        client.login_opaque(USER, PASSWORD)

    body = json.loads(finish.calls[0].request.content)
    assert body["opaque_session"] == "handle-42"
    assert bytes.fromhex(body["ke3"]).startswith(b"ke3:" + PASSWORD.encode() + b":ke2-hex:")


@respx.mock
def test_the_server_named_ksf_is_the_one_used(lib: FakeOpaqueLibrary) -> None:
    # §23.4 rule 2: never local defaults. A credential enrolled under one cost
    # keeps working after a tenant raises its policy, so a client that guessed
    # would derive a different randomized password and fail against a good
    # record.
    respx.post(LOGIN_START).mock(
        return_value=httpx.Response(
            200,
            json={
                "opaque_session": "s",
                "ke2": "ke2-hex",
                "ksf": "scrypt",
                "log_n": 15,
                "r": 8,
                "p": 1,
            },
        ),
    )
    finish = respx.post(LOGIN_FINISH).mock(
        return_value=httpx.Response(200, json={"mfa_required": False}, headers=_session_cookies()),
    )

    with _client() as client:
        client.login_opaque(USER, PASSWORD)

    # The fake encodes the ksf handle it was given, and derives it from the
    # parameters: scrypt handles are 0xb000 + log_n + r + p.
    expected = f":{0xB000 + 15 + 8 + 1:x}".encode()
    assert bytes.fromhex(json.loads(finish.calls[0].request.content)["ke3"]).endswith(expected)


# ---------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------


@respx.mock
def test_a_successful_login_returns_the_same_shape_as_login(lib: FakeOpaqueLibrary) -> None:
    respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
    respx.post(LOGIN_FINISH).mock(
        return_value=httpx.Response(200, json={"mfa_required": False}, headers=_session_cookies()),
    )

    with _client() as client:
        result = client.login_opaque(USER, PASSWORD)

    assert result.mfa_required is False
    assert result.tenant_id == "acme"


@respx.mock
def test_mfa_required_survives_the_opaque_path(lib: FakeOpaqueLibrary) -> None:
    # One result handler must serve both login paths, so the second phase has
    # to arrive here exactly as it does from login().
    respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
    respx.post(LOGIN_FINISH).mock(
        return_value=httpx.Response(
            202, json={"mfa_required": True, "challenge_token": "mfa-token-1"}
        ),
    )

    with _client() as client:
        result = client.login_opaque(USER, PASSWORD)

    assert result.mfa_required is True
    assert result.mfa_token is not None
    assert result.mfa_token.get_secret_value() == "mfa-token-1"


# ---------------------------------------------------------------------
# Failures — which exception, and why it matters
# ---------------------------------------------------------------------


@respx.mock
def test_a_disabled_tenant_is_a_networkerror_a_caller_can_fall_back_from(
    lib: FakeOpaqueLibrary,
) -> None:
    # A 404 is a property of the tenant, not of the credentials. As an AuthError
    # it would be shown as "invalid password" and send a user to reset a working
    # one, while stopping the application falling back to login().
    respx.post(LOGIN_START).mock(return_value=httpx.Response(404))

    with _client() as client, pytest.raises(NetworkError, match="opaque_mode is disabled"):
        client.login_opaque(USER, PASSWORD)


@respx.mock
def test_a_disabled_tenant_is_reported_the_same_way_at_enrolment(
    lib: FakeOpaqueLibrary,
) -> None:
    respx.post(REGISTER_START).mock(return_value=httpx.Response(404))

    with _client() as client, pytest.raises(NetworkError, match="opaque_mode is disabled"):
        client.opaque_enrollment(PASSWORD)


@respx.mock
def test_a_401_at_login_start_is_an_autherror(lib: FakeOpaqueLibrary) -> None:
    respx.post(LOGIN_START).mock(return_value=httpx.Response(401))

    with _client() as client, pytest.raises(AuthError):
        client.login_opaque(USER, PASSWORD)


@respx.mock
def test_a_wrong_password_never_reaches_login_finish(lib: FakeOpaqueLibrary) -> None:
    # §23.4 rule 7. The envelope failing to open IS the authentication check,
    # and sending anything afterwards would ask the server to decide something
    # the client has already decided.
    lib.fail.add("login_finish")
    respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
    finish = respx.post(LOGIN_FINISH).mock(return_value=httpx.Response(200, json={}))

    with _client() as client, pytest.raises(AuthError):
        client.login_opaque(USER, OTHER_PASSWORD)

    assert finish.call_count == 0


@respx.mock
def test_an_unsupported_ksf_is_a_configuration_error_not_a_bad_password(
    lib: FakeOpaqueLibrary,
) -> None:
    respx.post(LOGIN_START).mock(
        return_value=httpx.Response(200, json={"opaque_session": "s", "ke2": "x", "ksf": "bcrypt"}),
    )
    finish = respx.post(LOGIN_FINISH).mock(return_value=httpx.Response(200, json={}))

    with _client() as client, pytest.raises(NetworkError, match="bcrypt"):
        client.login_opaque(USER, PASSWORD)

    assert finish.call_count == 0


@respx.mock
def test_a_start_response_without_ke2_is_a_malformed_response(lib: FakeOpaqueLibrary) -> None:
    respx.post(LOGIN_START).mock(
        return_value=httpx.Response(200, json={"opaque_session": "s", **ARGON2ID}),
    )

    with _client() as client, pytest.raises(NetworkError, match="no `ke2`"):
        client.login_opaque(USER, PASSWORD)


@respx.mock
def test_an_unexpected_library_exception_becomes_an_autherror(lib: FakeOpaqueLibrary) -> None:
    # Anything the binding did not declare — a ctypes.ArgumentError, say — is
    # still a login that did not complete. It must arrive as an AuthError with
    # the original chained, not as a bare traceback out of a ctypes call.
    import ctypes

    lib.raises["login_finish"] = ctypes.ArgumentError("argument 2: wrong type")
    respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
    finish = respx.post(LOGIN_FINISH).mock(return_value=httpx.Response(200, json={}))

    with _client() as client, pytest.raises(AuthError) as excinfo:
        client.login_opaque(USER, PASSWORD)

    assert isinstance(excinfo.value.__cause__, ctypes.ArgumentError)
    assert finish.call_count == 0


@respx.mock
def test_a_5xx_at_login_finish_is_a_networkerror(lib: FakeOpaqueLibrary) -> None:
    respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
    respx.post(LOGIN_FINISH).mock(return_value=httpx.Response(503))

    with _client() as client, pytest.raises(NetworkError):
        client.login_opaque(USER, PASSWORD)


def test_an_absent_library_is_reported_before_any_request(absent: None) -> None:
    with respx.mock:
        start = respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
        with _client() as client, pytest.raises(NetworkError, match="libaxiam_opaque_ffi"):
            client.login_opaque(USER, PASSWORD)
        assert start.call_count == 0


# ---------------------------------------------------------------------
# Availability (§23.2)
# ---------------------------------------------------------------------


def test_opaque_available_reports_true_when_the_library_is_there(lib: FakeOpaqueLibrary) -> None:
    with _client() as client:
        assert client.opaque_available() is True


def test_opaque_available_reports_false_rather_than_raising(absent: None) -> None:
    with _client() as client:
        assert client.opaque_available() is False


# ---------------------------------------------------------------------
# The async client answers identically
# ---------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_login_opaque_matches_the_sync_client(lib: FakeOpaqueLibrary) -> None:
    start = respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
    finish = respx.post(LOGIN_FINISH).mock(
        return_value=httpx.Response(200, json={"mfa_required": False}, headers=_session_cookies()),
    )

    async with _async_client() as client:
        result = await client.login_opaque(USER, PASSWORD)

    assert result.mfa_required is False
    assert "password" not in json.loads(start.calls[0].request.content)
    assert bytes.fromhex(json.loads(finish.calls[0].request.content)["ke3"]).startswith(b"ke3:")


@pytest.mark.asyncio
@respx.mock
async def test_async_enrollment_matches_the_sync_client(lib: FakeOpaqueLibrary) -> None:
    route = respx.post(REGISTER_START).mock(
        return_value=httpx.Response(
            200, json={"opaque_session": "s", "registration_response": "resp-hex", **ARGON2ID}
        ),
    )

    async with _async_client() as client:
        enrollment = await client.opaque_enrollment(PASSWORD)

    body = json.loads(route.calls[0].request.content)
    assert "password" not in body and "username_or_email" not in body
    assert bytes.fromhex(enrollment["registration_record"]).startswith(
        b"record:" + PASSWORD.encode()
    )


@pytest.mark.asyncio
@respx.mock
async def test_async_disabled_tenant_is_a_networkerror(lib: FakeOpaqueLibrary) -> None:
    respx.post(LOGIN_START).mock(return_value=httpx.Response(404))

    async with _async_client() as client:
        with pytest.raises(NetworkError, match="opaque_mode is disabled"):
            await client.login_opaque(USER, PASSWORD)


@pytest.mark.asyncio
@respx.mock
async def test_async_wrong_password_never_reaches_login_finish(lib: FakeOpaqueLibrary) -> None:
    lib.fail.add("login_finish")
    respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
    finish = respx.post(LOGIN_FINISH).mock(return_value=httpx.Response(200, json={}))

    async with _async_client() as client:
        with pytest.raises(AuthError):
            await client.login_opaque(USER, OTHER_PASSWORD)

    assert finish.call_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_async_enrollment_disabled_tenant(lib: FakeOpaqueLibrary) -> None:
    respx.post(REGISTER_START).mock(return_value=httpx.Response(404))

    async with _async_client() as client:
        with pytest.raises(NetworkError, match="opaque_mode is disabled"):
            await client.opaque_enrollment(PASSWORD)


@pytest.mark.asyncio
@respx.mock
async def test_async_5xx_at_login_finish_is_a_networkerror(lib: FakeOpaqueLibrary) -> None:
    respx.post(LOGIN_START).mock(return_value=httpx.Response(200, json=_started()))
    respx.post(LOGIN_FINISH).mock(return_value=httpx.Response(503))

    async with _async_client() as client:
        with pytest.raises(NetworkError):
            await client.login_opaque(USER, PASSWORD)
