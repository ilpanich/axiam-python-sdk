"""CONTRACT.md §5.2 rule 1 / §5.2.3 rule 4 — the acting tenant,
``X-Axiam-Tenant`` (contract 1.51).

§8 rule 7 of the dogfooding fix plan requires: the header is sent when set
and absent when not (the I4 twin); this file also pins the reference's other
choices recorded in its "For C-12" list — the §17 memo key includes the
acting tenant, and a session that completes without a user object (here:
``logout``, standing in for OPAQUE/SSO/WebAuthn/the forced MFA setup, all of
which land on the same ``_absorb_session_cookies`` reset) is read as "holds
no login result" rather than "not organization-level".
"""

from __future__ import annotations

import uuid

import httpx
import pytest
import respx

from axiam_sdk import AuthzError, AxiamClient, NetworkError
from axiam_sdk._client import ACTING_TENANT_HEADER
from tests.management_support import (
    BASE_URL,
    TENANT_SLUG,
    mount_json,
    mount_login_as,
    with_async_client,
    with_client,
)

TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "22222222-2222-4222-8222-222222222222"


def _resources_page() -> dict[str, object]:
    return {"items": [], "total": 0, "offset": 0, "limit": 50}


# ---------------------------------------------------------------------------
# The header is sent when set, and absent when not (the I4 twin) — management
# ---------------------------------------------------------------------------


def test_management_call_carries_the_header_when_acting_tenant_is_set() -> None:
    with with_client(acting_tenant=TENANT_A) as (router, client):
        route = mount_json(router, "GET", "/api/v1/resources", 200, _resources_page())
        client.resources.list()
        sent = route.calls.last.request
        assert sent.headers[ACTING_TENANT_HEADER] == TENANT_A
        assert sent.headers["X-Tenant-ID"] == TENANT_SLUG, "§5 rule 2 is unaffected"


def test_management_call_sends_no_header_when_acting_tenant_is_unset() -> None:
    """The I4 twin: a client that never asked for one sends byte-for-byte
    what it sent before contract 1.51."""
    with with_client() as (router, client):
        route = mount_json(router, "GET", "/api/v1/resources", 200, _resources_page())
        client.resources.list()
        sent = route.calls.last.request
        assert ACTING_TENANT_HEADER not in sent.headers


async def test_management_call_carries_the_header_when_acting_tenant_is_set_async() -> None:
    async with with_async_client(acting_tenant=TENANT_A) as (router, client):
        route = mount_json(router, "GET", "/api/v1/resources", 200, _resources_page())
        await client.resources.list()
        sent = route.calls.last.request
        assert sent.headers[ACTING_TENANT_HEADER] == TENANT_A


async def test_management_call_sends_no_header_when_acting_tenant_is_unset_async() -> None:
    async with with_async_client() as (router, client):
        route = mount_json(router, "GET", "/api/v1/resources", 200, _resources_page())
        await client.resources.list()
        sent = route.calls.last.request
        assert ACTING_TENANT_HEADER not in sent.headers


# ---------------------------------------------------------------------------
# check_access / batch_check
# ---------------------------------------------------------------------------


def test_check_access_carries_the_header_when_set() -> None:
    with with_client(acting_tenant=TENANT_A) as (router, client):
        route = mount_json(router, "POST", "/api/v1/authz/check", 200, {"allowed": True})
        client.check_access("read", str(uuid.uuid4()))
        assert route.calls.last.request.headers[ACTING_TENANT_HEADER] == TENANT_A


def test_check_access_sends_no_header_when_unset() -> None:
    with with_client() as (router, client):
        route = mount_json(router, "POST", "/api/v1/authz/check", 200, {"allowed": True})
        client.check_access("read", str(uuid.uuid4()))
        assert ACTING_TENANT_HEADER not in route.calls.last.request.headers


# ---------------------------------------------------------------------------
# refresh / logout
# ---------------------------------------------------------------------------


def test_refresh_carries_the_header_when_set() -> None:
    with with_client(acting_tenant=TENANT_A) as (router, client):
        route = mount_json(router, "POST", "/api/v1/auth/refresh", 200, {"expires_in": 900})
        client.refresh()
        assert route.calls.last.request.headers[ACTING_TENANT_HEADER] == TENANT_A


def test_refresh_sends_no_header_when_unset() -> None:
    with with_client() as (router, client):
        route = mount_json(router, "POST", "/api/v1/auth/refresh", 200, {"expires_in": 900})
        client.refresh()
        assert ACTING_TENANT_HEADER not in route.calls.last.request.headers


def test_logout_carries_the_header_when_set() -> None:
    with with_client(acting_tenant=TENANT_A) as (router, client):
        route = mount_json(router, "POST", "/api/v1/auth/logout", 200, None)
        client.logout()
        assert route.calls.last.request.headers[ACTING_TENANT_HEADER] == TENANT_A


def test_logout_sends_no_header_when_unset() -> None:
    with with_client() as (router, client):
        route = mount_json(router, "POST", "/api/v1/auth/logout", 200, None)
        client.logout()
        assert ACTING_TENANT_HEADER not in route.calls.last.request.headers


# ---------------------------------------------------------------------------
# Self-service calls — §5.2.2 rule 4: sent "as normal", the server decides
# ---------------------------------------------------------------------------


def test_a_self_service_call_carries_the_header_when_set() -> None:
    with with_client(acting_tenant=TENANT_A) as (router, client):
        route = mount_json(router, "POST", "/api/v1/users/me/resend-verification", 204, None)
        client.resend_own_verification()
        assert route.calls.last.request.headers[ACTING_TENANT_HEADER] == TENANT_A


def test_a_self_service_call_sends_no_header_when_unset() -> None:
    with with_client() as (router, client):
        route = mount_json(router, "POST", "/api/v1/users/me/resend-verification", 204, None)
        client.resend_own_verification()
        assert ACTING_TENANT_HEADER not in route.calls.last.request.headers


# ---------------------------------------------------------------------------
# clear_acting_tenant / a new handle leaves self unchanged
# ---------------------------------------------------------------------------


def test_clear_acting_tenant_stops_sending_the_header() -> None:
    with with_client(acting_tenant=TENANT_A) as (router, client):
        cleared = client.clear_acting_tenant()
        assert cleared.acting_tenant_id is None
        route = mount_json(router, "GET", "/api/v1/resources", 200, _resources_page())
        cleared.resources.list()
        assert ACTING_TENANT_HEADER not in route.calls.last.request.headers
        # `self` is unchanged.
        assert client.acting_tenant_id == TENANT_A


def test_acting_tenant_returns_a_new_handle_and_leaves_self_unchanged() -> None:
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=True)
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("a@example.test", "password123")
        handle = client.acting_tenant(TENANT_A)
        assert handle is not client
        assert handle.acting_tenant_id == TENANT_A
        assert client.acting_tenant_id is None
        client.close()


# ---------------------------------------------------------------------------
# Non-UUID refusal — client-side, zero wire calls
# ---------------------------------------------------------------------------


def test_construction_refuses_a_non_uuid_acting_tenant() -> None:
    with pytest.raises(NetworkError, match="UUID"):
        AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG, acting_tenant="acme-tenant")


def test_acting_tenant_call_refuses_a_non_uuid_with_zero_wire_calls() -> None:
    with with_client() as (router, client):
        calls_before = len(router.calls)
        with pytest.raises(NetworkError, match="UUID"):
            client.acting_tenant("not-a-uuid")
        assert len(router.calls) == calls_before


# ---------------------------------------------------------------------------
# Gating (§5.2 rule 1 / §5.2.3 rule 4) — once a login result is held
# ---------------------------------------------------------------------------


def test_acting_tenant_refuses_client_side_when_not_organization_level() -> None:
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=False)
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("a@example.test", "password123")
        calls_before = len(router.calls)
        with pytest.raises(AuthzError, match="organization-level"):
            client.acting_tenant(TENANT_A)
        assert len(router.calls) == calls_before, "refused with zero wire calls"
        client.close()


def test_acting_tenant_allows_organization_level_with_no_restriction() -> None:
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=True)
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("a@example.test", "password123")
        handle = client.acting_tenant(TENANT_A)
        assert handle.acting_tenant_id == TENANT_A
        client.close()


def test_acting_tenant_refuses_a_tenant_outside_reachable_tenant_ids() -> None:
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=True, reachable_tenant_ids=[TENANT_B])
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("a@example.test", "password123")
        calls_before = len(router.calls)
        with pytest.raises(AuthzError, match="reachable_tenant_ids"):
            client.acting_tenant(TENANT_A)
        assert len(router.calls) == calls_before
        # But the tenant that IS reachable is allowed.
        handle = client.acting_tenant(TENANT_B)
        assert handle.acting_tenant_id == TENANT_B
        client.close()


def test_a_client_holding_no_login_result_is_not_gated() -> None:
    """A client that never held a login result (constructed, never
    ``login()``ed — the service-account/injected-token/device-login case)
    has nothing to gate on: the header is sent and the server's 403 is the
    answer, per §5.2 rule 1."""
    client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
    try:
        handle = client.acting_tenant(TENANT_A)
        assert handle.acting_tenant_id == TENANT_A
    finally:
        client.close()


def test_logout_resets_the_gate_to_unknown_not_to_false() -> None:
    """After ``logout``, the principal scope is forgotten entirely (`None`),
    not remembered as "not organization-level" — exactly like a session that
    completes with no user object (OPAQUE, SSO, WebAuthn, the forced MFA
    setup all reach the same reset in ``_absorb_session_cookies``, which this
    pins through the one session-ending path every login-completing flow
    also passes through)."""
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=False)
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("a@example.test", "password123")
        with pytest.raises(AuthzError):
            client.acting_tenant(TENANT_A)

        mount_json(router, "POST", "/api/v1/auth/logout", 200, None)
        client.logout()

        # No login result held any more -- nothing to gate on.
        handle = client.acting_tenant(TENANT_A)
        assert handle.acting_tenant_id == TENANT_A
        client.close()


# ---------------------------------------------------------------------------
# The §17 decision memo is keyed on the acting tenant ("For C-12" question 2)
# ---------------------------------------------------------------------------


def test_the_decision_memo_key_includes_the_acting_tenant() -> None:
    """Two handles acting on different tenants share one memo (one
    ``_decision_memo`` on the shared session), and the server can answer the
    same ``(subject_id, resource_id, action, scope)`` question differently
    per tenant. Without the acting tenant in the key, tenant A's memoized
    answer would be served back for tenant B within the TTL."""
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=True)
        client = AxiamClient(
            base_url=BASE_URL, tenant_slug=TENANT_SLUG, decision_memo_ttl_ms=5000.0
        )
        client.login("a@example.test", "password123")

        resource_id = str(uuid.uuid4())
        route = router.post(f"{BASE_URL}/api/v1/authz/check")
        route.side_effect = [
            httpx.Response(200, json={"allowed": True}),
            httpx.Response(200, json={"allowed": False}),
        ]

        a = client.acting_tenant(TENANT_A)
        b = client.acting_tenant(TENANT_B)

        result_a = a.check_access("read", resource_id)
        result_b = b.check_access("read", resource_id)
        assert result_a.allowed is True
        assert result_b.allowed is False, "a distinct tenant must not hit A's memoized entry"

        # Repeating each inside the TTL makes no further wire call — a real
        # memo hit, not two calls that happened to answer as expected.
        assert route.call_count == 2
        assert a.check_access("read", resource_id).allowed is True
        assert b.check_access("read", resource_id).allowed is False
        assert route.call_count == 2

        client.close()
