"""CONTRACT.md §6.1 rules 6-10 (contract 1.51) — ``authenticate_device()``,
the mTLS device login.

§8 rule 7 of the dogfooding fix plan requires ``authenticate_device()`` to be
unreachable without a certificate. This file also pins the reference's other
recorded behaviours: a device token withholds a stale cookie, there is no
refresh attempt on a later 401, and a 429 is not an authentication failure
and is not retried.
"""

from __future__ import annotations

import datetime

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, DeviceToken, NetworkError
from tests.management_support import access_token

BASE_URL = "https://device.test"
TENANT_SLUG = "acme"
DEVICE_AUTH_PATH = "/api/v1/auth/device"


def _self_signed_identity() -> tuple[bytes, bytes]:
    """A throwaway self-signed RSA leaf cert/key PEM pair.

    Never presented over a real TLS handshake here — respx intercepts at the
    httpx transport, below the socket — but ``ssl.SSLContext.load_cert_chain``
    still parses it for real when the client is constructed, so it must be
    genuinely valid PEM, not a placeholder string.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device-001")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


CERT_PEM, KEY_PEM = _self_signed_identity()


def _device_client() -> AxiamClient:
    return AxiamClient(
        base_url=BASE_URL, tenant_slug=TENANT_SLUG, client_cert=CERT_PEM, client_key=KEY_PEM
    )


def _async_device_client() -> AsyncAxiamClient:
    return AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug=TENANT_SLUG, client_cert=CERT_PEM, client_key=KEY_PEM
    )


# ---------------------------------------------------------------------------
# Rule 7 — reachable only on a client configured with a certificate
# ---------------------------------------------------------------------------


def test_unreachable_without_a_client_certificate_zero_wire_calls() -> None:
    with respx.mock(assert_all_called=False) as router:
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        with pytest.raises(AuthError, match="client certificate"):
            client.authenticate_device()
        assert len(router.calls) == 0
        client.close()


async def test_unreachable_without_a_client_certificate_zero_wire_calls_async() -> None:
    with respx.mock(assert_all_called=False) as router:
        client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        with pytest.raises(AuthError, match="client certificate"):
            await client.authenticate_device()
        assert len(router.calls) == 0
        await client.aclose()


# ---------------------------------------------------------------------------
# Rule 6 — one call, no body, three fields back, adopted as the credential
# ---------------------------------------------------------------------------


def test_authenticate_device_returns_a_typed_token_and_sends_no_body() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200, json={"access_token": "dev-token-1", "token_type": "Bearer", "expires_in": 900}
            )
        )
        with _device_client() as client:
            token = client.authenticate_device()
            assert isinstance(token, DeviceToken)
            assert token.access_token.get_secret_value() == "dev-token-1"
            assert token.token_type == "Bearer"
            assert token.expires_in == 900
            assert route.calls.last.request.content == b""


async def test_authenticate_device_returns_a_typed_token_async() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200, json={"access_token": "dev-token-2", "token_type": "Bearer", "expires_in": 900}
            )
        )
        async with _async_device_client() as client:
            token = await client.authenticate_device()
            assert token.access_token.get_secret_value() == "dev-token-2"


def test_the_adopted_token_is_secret() -> None:
    """§7: the raw value is never reachable except through the one explicit
    accessor."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "super-secret", "token_type": "Bearer", "expires_in": 900},
            )
        )
        with _device_client() as client:
            token = client.authenticate_device()
            assert "super-secret" not in repr(token)
            assert "super-secret" not in str(token)


def test_authenticate_device_adopts_the_token_as_the_bearer_credential() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200, json={"access_token": "dev-token-3", "token_type": "Bearer", "expires_in": 900}
            )
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        with _device_client() as client:
            client.authenticate_device()
            client.check_access("read", "11111111-1111-4111-8111-111111111111")
            sent = check_route.calls.last.request
            assert sent.headers["Authorization"] == "Bearer dev-token-3"


# ---------------------------------------------------------------------------
# A device token withholds a stale cookie
# ---------------------------------------------------------------------------


def test_a_device_token_withholds_a_stale_cookie() -> None:
    """The server reads the ``axiam_access`` cookie before the
    ``Authorization`` header. A cookie left from an earlier session (a
    previous ``login()`` on the same client) must not ride along on a
    request sent under the device credential, or the request would run as
    that earlier session's principal instead of the device's."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            return_value=httpx.Response(
                200,
                json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200, json={"access_token": "dev-token-4", "token_type": "Bearer", "expires_in": 900}
            )
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        with _device_client() as client:
            client.login("a@example.test", "password123")
            client.authenticate_device()
            client.check_access("read", "11111111-1111-4111-8111-111111111111")
            sent = check_route.calls.last.request
            assert sent.headers["Authorization"] == "Bearer dev-token-4"
            assert sent.headers.get("Cookie", "") == "", (
                "the earlier session's cookie must not survive the device login"
            )


async def test_a_device_token_withholds_a_stale_cookie_async() -> None:
    """Async twin of the above."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            return_value=httpx.Response(
                200,
                json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "dev-token-4a", "token_type": "Bearer", "expires_in": 900},
            )
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        async with _async_device_client() as client:
            await client.login("a@example.test", "password123")
            await client.authenticate_device()
            await client.check_access("read", "11111111-1111-4111-8111-111111111111")
            sent = check_route.calls.last.request
            assert sent.headers["Authorization"] == "Bearer dev-token-4a"
            assert sent.headers.get("Cookie", "") == "", (
                "the earlier session's cookie must not survive the device login"
            )


# ---------------------------------------------------------------------------
# The device-login POST itself carries no cookie (CONTRACT §6.1; the POST
# is a login in its own right, and the server reads axiam_access before
# Authorization).
# ---------------------------------------------------------------------------


def test_the_device_login_post_itself_carries_no_stale_cookie() -> None:
    """This is the actual defect: unlike every *later* request under the
    device credential (which ``_apply_bearer_credential`` protects once a
    bearer token is adopted), the device-login POST itself runs BEFORE any
    bearer token exists, so the belt-and-suspenders empty ``Cookie`` header
    that protects every other request never fires for this one call --
    the httpx client's own cookie jar attaches the earlier session's
    ``axiam_access`` cookie at ``build_request`` time and nothing
    overrides it. Asserted at the transport boundary (the request respx
    actually saw), not on a mock above the cookie-attaching layer."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            return_value=httpx.Response(
                200,
                json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        device_route = router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200, json={"access_token": "dev-token-6", "token_type": "Bearer", "expires_in": 900}
            )
        )
        with _device_client() as client:
            client.login("a@example.test", "password123")
            client.authenticate_device()
            sent = device_route.calls.last.request
            assert sent.headers.get("Cookie", "") == "", (
                "the device-login POST must carry no cookie from a prior session"
            )


async def test_the_device_login_post_itself_carries_no_stale_cookie_async() -> None:
    """Async twin of the above."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            return_value=httpx.Response(
                200,
                json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        device_route = router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "dev-token-6a", "token_type": "Bearer", "expires_in": 900},
            )
        )
        async with _async_device_client() as client:
            await client.login("a@example.test", "password123")
            await client.authenticate_device()
            sent = device_route.calls.last.request
            assert sent.headers.get("Cookie", "") == "", (
                "the device-login POST must carry no cookie from a prior session"
            )


# ---------------------------------------------------------------------------
# A refused device login leaves the prior session exactly as it was
# ---------------------------------------------------------------------------


def test_a_refused_device_login_leaves_the_prior_session_untouched() -> None:
    """A 401 refusal must not clear the jar or the decision memo: a
    following ordinary request still authenticates as the earlier
    session's principal, exactly as if ``authenticate_device()`` had never
    been called."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            return_value=httpx.Response(
                200,
                json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                401,
                json={
                    "error": "authentication_failed",
                    "message": "the presented certificate is unbound",
                },
            )
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        with _device_client() as client:
            client.login("a@example.test", "password123")
            with pytest.raises(AuthError):
                client.authenticate_device()
            client.check_access("read", "11111111-1111-4111-8111-111111111111")
            sent = check_route.calls.last.request
            assert "axiam_access" in sent.headers.get("Cookie", ""), (
                "a refused device login must not clear the prior session's cookie jar"
            )
            assert "Authorization" not in sent.headers, (
                "a refused device login must not adopt a bearer credential"
            )


async def test_a_refused_device_login_leaves_the_prior_session_untouched_async() -> None:
    """Async twin of the above."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            return_value=httpx.Response(
                200,
                json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                401,
                json={
                    "error": "authentication_failed",
                    "message": "the presented certificate is unbound",
                },
            )
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        async with _async_device_client() as client:
            await client.login("a@example.test", "password123")
            with pytest.raises(AuthError):
                await client.authenticate_device()
            await client.check_access("read", "11111111-1111-4111-8111-111111111111")
            sent = check_route.calls.last.request
            assert "axiam_access" in sent.headers.get("Cookie", ""), (
                "a refused device login must not clear the prior session's cookie jar"
            )
            assert "Authorization" not in sent.headers, (
                "a refused device login must not adopt a bearer credential"
            )


# ---------------------------------------------------------------------------
# No refresh on a later 401
# ---------------------------------------------------------------------------


def test_no_refresh_attempt_on_a_later_401() -> None:
    """There is no refresh token (D-6). A later 401 on the device credential
    is surfaced as AuthError, and no refresh wire call is attempted."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                200, json={"access_token": "dev-token-5", "token_type": "Bearer", "expires_in": 900}
            )
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(401, json={"error": "authentication_failed"})
        )
        refresh_route = router.post(f"{BASE_URL}/api/v1/auth/refresh")
        with _device_client() as client:
            client.authenticate_device()
            with pytest.raises(AuthError):
                client.check_access("read", "11111111-1111-4111-8111-111111111111")
            assert check_route.call_count == 1, "no retry after the failed refresh"
            assert refresh_route.call_count == 0, "the refresh guard makes zero wire calls"


# ---------------------------------------------------------------------------
# Rule 8 — every refusal is a 401 -> AuthError, verbatim message; a 429 is
# not an authentication failure and is not retried
# ---------------------------------------------------------------------------


def test_a_401_refusal_is_autherror_with_the_servers_verbatim_message() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                401,
                json={
                    "error": "authentication_failed",
                    "message": "the presented certificate is not bound to a service account",
                },
            )
        )
        with _device_client() as client:
            with pytest.raises(AuthError, match="not bound to a service account"):
                client.authenticate_device()


def test_a_429_is_a_network_error_not_an_auth_error_and_is_not_retried() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(
                429, json={"error": "rate_limit_exceeded"}, headers={"Retry-After": "1"}
            )
        )
        with _device_client() as client:
            with pytest.raises(NetworkError):
                client.authenticate_device()
            assert route.call_count == 1, "a 429 on this operation is not retried"
