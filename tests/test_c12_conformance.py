"""CONTRACT 1.52 (C-12 conformance review) — Python SDK fixes.

Findings covered (`c12-findings.md`, "## Python"):

- **N4.7** — a held device credential (§6.1 rule 6) satisfies §27.4 rule 1's
  management session precondition; a client that authenticated with
  ``authenticate_device()`` and never held a cookie session at all must
  still reach the management API.
- **N4.4** — the device credential is released by the next
  session-establishing call (``login``, here), and by ``logout``.
- **N5.3** — the §5.2 rule 1 acting-tenant gate is one gate PER SESSION,
  not per handle: a login performed through any handle changes what every
  handle sharing that session gates ``acting_tenant()`` on.
- **N5.1** — ``X-Axiam-Tenant`` and a held bearer credential never reach a
  host other than the client's configured base URL, at the real request
  boundary (a discovered ``/oauth2`` endpoint on another host).

Also covers two CONTRACT 1.52 N4 violations this review found but that are
not in this SDK's findings list (checked because the wave instructions
require every SDK to be checked against every N1-N6 rule, listed or not):

- **N4.5** (§6.1 rule 5, "never refreshed") — a 401 on the device
  credential entered the §9 refresh guard exactly like a cookie-session
  401 (only the management/authz call sites gate 401-triggers-refresh; the
  choke point itself does not), so the caller saw the refresh guard's own
  "no access token to refresh" ``AuthError`` instead of the server's 401.
  Also found: the same held credential could not even be used to
  ``logout()`` — ``_session_id_for_logout`` read only the cookie jar.
- **N4.2** (§6.1 rule 8, "malformed 200") — a 200 response with no usable
  ``access_token`` was adopted as-is (an empty/absent bearer credential),
  rather than refused client-side with no state change.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AuthzError, AxiamClient, NetworkError
from tests._oidc_testkit import CLIENT_ID, CLIENT_SECRET, client_identity_pem, discovery_document
from tests.management_support import access_token

BASE_URL = "https://c12.test"
TENANT_SLUG = "acme"
DEVICE_AUTH_PATH = "/api/v1/auth/device"
TENANT_A = "11111111-1111-4111-8111-111111111111"
RESOURCE_ID = "22222222-2222-4222-8222-222222222222"

CERT_PEM, KEY_PEM = client_identity_pem()


def _device_client() -> AxiamClient:
    return AxiamClient(
        base_url=BASE_URL, tenant_slug=TENANT_SLUG, client_cert=CERT_PEM, client_key=KEY_PEM
    )


def _async_device_client() -> AsyncAxiamClient:
    return AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug=TENANT_SLUG, client_cert=CERT_PEM, client_key=KEY_PEM
    )


def _device_login_response(token: str = "dev-token") -> httpx.Response:
    return httpx.Response(
        200, json={"access_token": token, "token_type": "Bearer", "expires_in": 900}
    )


def _login_response(
    *, organization_level: bool = False, reachable_tenant_ids=None
) -> httpx.Response:
    user: dict[str, object] = {"id": "user-1", "organization_level": organization_level}
    if reachable_tenant_ids is not None:
        user["reachable_tenant_ids"] = reachable_tenant_ids
    return httpx.Response(
        200,
        json={"user": user, "session_id": "s1", "expires_in": 900},
        headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
    )


def _users_page() -> dict[str, object]:
    return {"items": [], "total": 0, "offset": 0, "limit": 50}


# ---------------------------------------------------------------------------
# N4.7 — a management call reaches the wire under a held device credential
# ---------------------------------------------------------------------------


def test_management_call_reaches_the_wire_with_the_device_bearer() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response("dev-mgmt-1")
        )
        route = router.get(f"{BASE_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=_users_page())
        )
        with _device_client() as client:
            client.authenticate_device()
            client.users.list()
            sent = route.calls.last.request
            assert sent.headers["Authorization"] == "Bearer dev-mgmt-1"


async def test_management_call_reaches_the_wire_with_the_device_bearer_async() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response("dev-mgmt-1a")
        )
        route = router.get(f"{BASE_URL}/api/v1/users").mock(
            return_value=httpx.Response(200, json=_users_page())
        )
        async with _async_device_client() as client:
            await client.authenticate_device()
            await client.users.list()
            sent = route.calls.last.request
            assert sent.headers["Authorization"] == "Bearer dev-mgmt-1a"


# ---------------------------------------------------------------------------
# N4.4 — a login after a device login replaces the credential
# ---------------------------------------------------------------------------


def test_a_login_after_a_device_login_sends_the_logins_cookie_and_no_bearer() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response("dev-2")
        )
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(return_value=_login_response())
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        with _device_client() as client:
            client.authenticate_device()
            client.login("a@example.test", "password123")
            client.check_access("read", RESOURCE_ID)
            sent = check_route.calls.last.request
            assert "Authorization" not in sent.headers, (
                "the device credential must not survive a login"
            )
            assert "axiam_access=" in sent.headers.get("Cookie", ""), (
                "the login's own cookie must ride"
            )


async def test_a_login_after_a_device_login_sends_the_logins_cookie_and_no_bearer_async() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response("dev-2a")
        )
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(return_value=_login_response())
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        async with _async_device_client() as client:
            await client.authenticate_device()
            await client.login("a@example.test", "password123")
            await client.check_access("read", RESOURCE_ID)
            sent = check_route.calls.last.request
            assert "Authorization" not in sent.headers
            assert "axiam_access=" in sent.headers.get("Cookie", "")


# ---------------------------------------------------------------------------
# N4.4 — logout clears a held device credential (and can be called under one)
# ---------------------------------------------------------------------------


def test_logout_clears_a_held_device_credential() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response(access_token())
        )
        logout_route = router.post(f"{BASE_URL}/api/v1/auth/logout").mock(
            return_value=httpx.Response(204)
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        with _device_client() as client:
            client.authenticate_device()
            client.logout()  # N4 rule 3: logout itself is sent WITH the device credential
            assert logout_route.calls.last.request.headers["Authorization"].startswith("Bearer ")

            client.check_access("read", RESOURCE_ID)
            sent = check_route.calls.last.request
            assert "Authorization" not in sent.headers, "logout must release the device credential"


async def test_logout_clears_a_held_device_credential_async() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response(access_token())
        )
        logout_route = router.post(f"{BASE_URL}/api/v1/auth/logout").mock(
            return_value=httpx.Response(204)
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        async with _async_device_client() as client:
            await client.authenticate_device()
            await client.logout()
            assert logout_route.calls.last.request.headers["Authorization"].startswith("Bearer ")

            await client.check_access("read", RESOURCE_ID)
            sent = check_route.calls.last.request
            assert "Authorization" not in sent.headers


# ---------------------------------------------------------------------------
# N5.3 — one acting-tenant gate per session, not per handle
# ---------------------------------------------------------------------------


def test_the_acting_tenant_gate_is_shared_across_every_handle_over_one_session() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            side_effect=[
                _login_response(organization_level=True, reachable_tenant_ids=[TENANT_A]),
                _login_response(organization_level=False),
            ]
        )
        with AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG) as client:
            client.login("root@example.test", "password123")
            handle = client.acting_tenant(TENANT_A)  # organization-level, reaches TENANT_A: allowed

            # A DIFFERENT login, performed through `handle`, not `client`.
            handle.login("ordinary@example.test", "password123")

            # The gate is shared: `client` must see the ordinary principal's
            # reach too, even though the login that reported it was never
            # called through `client` itself.
            with pytest.raises(AuthzError):
                client.acting_tenant(TENANT_A)


async def test_the_acting_tenant_gate_is_shared_across_every_handle_over_one_session_async() -> (
    None
):
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            side_effect=[
                _login_response(organization_level=True, reachable_tenant_ids=[TENANT_A]),
                _login_response(organization_level=False),
            ]
        )
        async with AsyncAxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG) as client:
            await client.login("root@example.test", "password123")
            handle = client.acting_tenant(TENANT_A)

            await handle.login("ordinary@example.test", "password123")

            with pytest.raises(AuthzError):
                client.acting_tenant(TENANT_A)


def test_the_acting_tenant_gate_is_not_shared_across_two_independent_clients() -> None:
    """The I4 twin of the N5.3 fix: the gate is per *session*, not global —
    two separate `AxiamClient` instances (two separate sessions) must not
    see each other's login, or the fix would have over-reached from
    "per handle" all the way to "per process"."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/v1/auth/login").mock(
            return_value=_login_response(organization_level=False)
        )
        client_a = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client_b = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        try:
            client_a.login("ordinary@example.test", "password123")  # organization_level: False

            # `client_b` is a wholly separate session that never logged in:
            # its gate is still unknown, so it sends the header regardless
            # and lets the server's 403 answer -- it must NOT inherit
            # `client_a`'s refusal.
            handle = client_b.acting_tenant(TENANT_A)
            assert handle.acting_tenant_id == TENANT_A
        finally:
            client_a.close()
            client_b.close()


# ---------------------------------------------------------------------------
# N5.1 — X-Axiam-Tenant / the bearer credential never reach an off-origin host
# ---------------------------------------------------------------------------


def test_acting_tenant_and_bearer_credential_do_not_reach_an_off_origin_host() -> None:
    """Real boundary: an OIDC discovery document MAY legitimately advertise
    a ``token_endpoint`` on a different host, and ``login_client_credentials``
    posts to exactly that URL — the natural place a credential could leak
    cross-origin."""
    foreign_token_endpoint = "https://issuer.other-host.test/oauth2/token"
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response("dev-off-1")
        )
        router.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(
                200, json=discovery_document(issuer=BASE_URL, token_endpoint=foreign_token_endpoint)
            )
        )
        foreign_route = router.post(foreign_token_endpoint).mock(
            return_value=httpx.Response(
                200, json={"access_token": "svc-1", "token_type": "Bearer", "expires_in": 3600}
            )
        )
        same_host_route = router.get(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(
                200, json={"items": [], "total": 0, "offset": 0, "limit": 50}
            )
        )
        client = AxiamClient(
            base_url=BASE_URL,
            tenant_slug=TENANT_SLUG,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            client_cert=CERT_PEM,
            client_key=KEY_PEM,
            acting_tenant=TENANT_A,
        )
        try:
            client.authenticate_device()
            client.login_client_credentials(scope="authz:check", tenant_id=TENANT_A)

            foreign_sent = foreign_route.calls.last.request
            assert "X-Axiam-Tenant" not in foreign_sent.headers
            assert "Authorization" not in foreign_sent.headers
            assert "X-Tenant-ID" not in foreign_sent.headers

            client.resources.list()
            same_host_sent = same_host_route.calls.last.request
            assert same_host_sent.headers["X-Axiam-Tenant"] == TENANT_A
            assert same_host_sent.headers["Authorization"] == "Bearer dev-off-1"
        finally:
            client.close()


async def test_acting_tenant_and_bearer_credential_do_not_reach_an_off_origin_host_async() -> None:
    foreign_token_endpoint = "https://issuer.other-host.test/oauth2/token"
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response("dev-off-1a")
        )
        router.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(
                200, json=discovery_document(issuer=BASE_URL, token_endpoint=foreign_token_endpoint)
            )
        )
        foreign_route = router.post(foreign_token_endpoint).mock(
            return_value=httpx.Response(
                200, json={"access_token": "svc-1a", "token_type": "Bearer", "expires_in": 3600}
            )
        )
        same_host_route = router.get(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(
                200, json={"items": [], "total": 0, "offset": 0, "limit": 50}
            )
        )
        client = AsyncAxiamClient(
            base_url=BASE_URL,
            tenant_slug=TENANT_SLUG,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            client_cert=CERT_PEM,
            client_key=KEY_PEM,
            acting_tenant=TENANT_A,
        )
        try:
            await client.authenticate_device()
            await client.login_client_credentials(scope="authz:check", tenant_id=TENANT_A)

            foreign_sent = foreign_route.calls.last.request
            assert "X-Axiam-Tenant" not in foreign_sent.headers
            assert "Authorization" not in foreign_sent.headers
            assert "X-Tenant-ID" not in foreign_sent.headers

            await client.resources.list()
            same_host_sent = same_host_route.calls.last.request
            assert same_host_sent.headers["X-Axiam-Tenant"] == TENANT_A
            assert same_host_sent.headers["Authorization"] == "Bearer dev-off-1a"
        finally:
            await client.aclose()


# ---------------------------------------------------------------------------
# N4.5 (found independently) — a device credential is never refreshed, and
# its 401 surfaces the SERVER's message, never the refresh guard's.
# ---------------------------------------------------------------------------


def test_a_401_under_the_device_credential_surfaces_the_servers_message() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=_device_login_response("dev-401")
        )
        router.get(f"{BASE_URL}/api/v1/users").mock(
            return_value=httpx.Response(
                401, json={"error": "authentication_failed", "message": "device credential revoked"}
            )
        )
        refresh_route = router.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
            return_value=httpx.Response(200, json={"expires_in": 900})
        )
        with _device_client() as client:
            client.authenticate_device()
            with pytest.raises(AuthError, match="device credential revoked"):
                client.users.list()
            assert refresh_route.call_count == 0, "a device credential must never be refreshed"


# ---------------------------------------------------------------------------
# N4.2 (found independently) — a malformed 200 device-login response is
# refused client-side, with no credential adopted.
# ---------------------------------------------------------------------------


def test_a_malformed_200_on_device_login_is_refused_and_adopts_no_credential() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            return_value=httpx.Response(200, json={"token_type": "Bearer", "expires_in": 900})
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        with _device_client() as client:
            with pytest.raises(NetworkError, match="malformed"):
                client.authenticate_device()
            client.check_access("read", RESOURCE_ID)
            sent = check_route.calls.last.request
            assert "Authorization" not in sent.headers, (
                "no credential must be adopted from a malformed 200"
            )


# ---------------------------------------------------------------------------
# N4.4 twin — "another device login" (N4 rule 4) also replaces the credential
# ---------------------------------------------------------------------------


def test_a_second_device_login_replaces_the_first() -> None:
    """The I4 twin of the N4.4 fix, at the case `adopt_bearer_credential`
    already handled correctly before this review (a second
    `authenticate_device()` call): still works after moving the release
    logic into `_absorb_session_cookies`/`logout` alongside it."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}{DEVICE_AUTH_PATH}").mock(
            side_effect=[_device_login_response("dev-first"), _device_login_response("dev-second")]
        )
        check_route = router.post(f"{BASE_URL}/api/v1/authz/check").mock(
            return_value=httpx.Response(200, json={"allowed": True})
        )
        with _device_client() as client:
            client.authenticate_device()
            client.authenticate_device()
            client.check_access("read", RESOURCE_ID)
            sent = check_route.calls.last.request
            assert sent.headers["Authorization"] == "Bearer dev-second"
