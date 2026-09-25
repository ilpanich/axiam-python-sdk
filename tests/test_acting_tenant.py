"""CONTRACT.md §5.2 rule 1 / §5.2.3 rule 4 — the acting tenant,
``X-Axiam-Tenant`` (contract 1.51).

§8 rule 7 of the dogfooding fix plan requires: the header is sent when set
and absent when not (the I4 twin); this file also pins the reference's other
choices recorded in its "For C-12" list — the §17 memo key includes the
acting tenant, and a session that completes without a user object is read as
"holds no login result" rather than "not organization-level". That "without a
user object" set is **not** every session-establishing path: ``login``,
``verify_mfa``, ``login_opaque`` and ``mfa_setup_confirm`` all report the
principal's reach (their responses carry the same user object, through the
same ``_handle_login_response``), and gate ``acting_tenant()`` accordingly —
pinned below by the OPAQUE and forced-MFA-setup cases. ``logout`` (used
below to stand in for the paths that genuinely carry no user object — a
WebAuthn *authentication*, an SSO completion, the mTLS device login, all of
which land on the same ``_absorb_session_cookies`` reset with no follow-up
set) resets a *held* result to unknown rather than clearing it to "not
organization-level".
"""

from __future__ import annotations

import secrets
import uuid

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthzError, AxiamClient, NetworkError, _opaque
from axiam_sdk._client import (
    ACTING_TENANT_HEADER,
    OPAQUE_LOGIN_FINISH_PATH,
    OPAQUE_LOGIN_START_PATH,
)
from tests._opaque_fake import FakeOpaqueLibrary
from tests.management_support import (
    BASE_URL,
    TENANT_SLUG,
    access_token,
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
    not remembered as "not organization-level" — the same reset a WebAuthn
    authentication, an SSO completion or the mTLS device login apply, all of
    which (like ``logout``) complete or end a session with no user object.
    OPAQUE, the forced MFA setup and a WebAuthn *setup* are different: see
    ``test_login_opaque_with_organization_level_false_gates_acting_tenant``
    and its neighbours below, which pin that those DO carry the gate."""
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


# ---------------------------------------------------------------------------
# "For C-12" question 5, corrected: OPAQUE, the forced MFA setup and a
# WebAuthn setup DO gate acting_tenant() -- their responses carry the same
# user object login/verify_mfa's do, through the same
# _handle_login_response. Only a WebAuthn *authentication*, an SSO
# completion and the mTLS device login (and an injected token / a service
# account) hold nothing to gate on. Orchestrator review of commit 073b224.
# ---------------------------------------------------------------------------

_OPAQUE_ARGON2ID = {"ksf": "argon2id", "memory_kib": 19456, "iterations": 2, "parallelism": 1}
_OPAQUE_PASSWORD = f"correct-{secrets.token_hex(8)}"


@pytest.fixture
def opaque_lib():
    fake = FakeOpaqueLibrary()
    _opaque._set_for_tests(fake)
    try:
        yield fake
    finally:
        _opaque._reset_for_tests()


def _opaque_login_started(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "opaque_session": "session-handle",
        "ke2": "ke2-hex",
        **_OPAQUE_ARGON2ID,
    }
    body.update(overrides)
    return body


def _mount_opaque_login(router: respx.MockRouter, *, organization_level: bool) -> None:
    router.post(f"{BASE_URL}{OPAQUE_LOGIN_START_PATH}").mock(
        return_value=httpx.Response(200, json=_opaque_login_started())
    )
    router.post(f"{BASE_URL}{OPAQUE_LOGIN_FINISH_PATH}").mock(
        return_value=httpx.Response(
            200,
            json={
                "user": {"id": "user-1", "organization_level": organization_level},
                "session_id": "s1",
                "expires_in": 900,
            },
            headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
        )
    )


def test_login_opaque_with_organization_level_false_gates_acting_tenant(opaque_lib) -> None:
    """login_opaque's finish response carries the same ``user`` object
    login's does, through the same ``_handle_login_response`` -- so it gates
    ``acting_tenant()`` exactly as a password login does, unlike the Rust
    reference (whose OPAQUE path resets to unknown)."""
    with respx.mock(assert_all_called=False) as router:
        _mount_opaque_login(router, organization_level=False)
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login_opaque("a@example.test", _OPAQUE_PASSWORD)
        calls_before = len(router.calls)
        with pytest.raises(AuthzError, match="organization-level"):
            client.acting_tenant(TENANT_A)
        assert len(router.calls) == calls_before, "refused with zero wire calls"
        client.close()


async def test_login_opaque_with_organization_level_false_gates_acting_tenant_async(
    opaque_lib,
) -> None:
    with respx.mock(assert_all_called=False) as router:
        _mount_opaque_login(router, organization_level=False)
        client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        await client.login_opaque("a@example.test", _OPAQUE_PASSWORD)
        calls_before = len(router.calls)
        with pytest.raises(AuthzError, match="organization-level"):
            client.acting_tenant(TENANT_A)
        assert len(router.calls) == calls_before, "refused with zero wire calls"
        await client.aclose()


def _mount_mfa_setup_confirm(router: respx.MockRouter, *, organization_level: bool) -> None:
    router.post(f"{BASE_URL}/api/v1/auth/mfa/setup/confirm").mock(
        return_value=httpx.Response(
            200,
            json={
                "user": {"id": "user-1", "organization_level": organization_level},
                "session_id": "s1",
                "expires_in": 900,
            },
            headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
        )
    )


def test_mfa_setup_confirm_with_organization_level_false_gates_acting_tenant() -> None:
    """The forced-MFA-setup completion routes through
    ``_handle_login_response`` exactly as ``login_opaque`` does -- same
    gate, for the same reason."""
    with respx.mock(assert_all_called=False) as router:
        _mount_mfa_setup_confirm(router, organization_level=False)
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.mfa_setup_confirm(setup_token="setup-token-1", totp_code="123456")
        calls_before = len(router.calls)
        with pytest.raises(AuthzError, match="organization-level"):
            client.acting_tenant(TENANT_A)
        assert len(router.calls) == calls_before, "refused with zero wire calls"
        client.close()


async def test_mfa_setup_confirm_with_organization_level_false_gates_acting_tenant_async() -> None:
    with respx.mock(assert_all_called=False) as router:
        _mount_mfa_setup_confirm(router, organization_level=False)
        client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        await client.mfa_setup_confirm(setup_token="setup-token-1", totp_code="123456")
        calls_before = len(router.calls)
        with pytest.raises(AuthzError, match="organization-level"):
            client.acting_tenant(TENANT_A)
        assert len(router.calls) == calls_before, "refused with zero wire calls"
        await client.aclose()


def test_an_sso_completion_after_an_org_level_false_login_resets_the_stale_gate() -> None:
    """The stale-principal case "For C-12" question 5 warns about: a HELD
    org-level=false login result must not survive past a LATER
    session-establishing call that carries no user object at all. SSO
    completion (like a WebAuthn authentication or the device login) lands on
    ``_absorb_session_cookies`` with no follow-up set, so the gate resets to
    "nothing to gate on" and the header is sent regardless -- not "still not
    organization-level"."""
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=False)
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("a@example.test", "password123")
        with pytest.raises(AuthzError):
            client.acting_tenant(TENANT_A)

        router.post(f"{BASE_URL}/api/v1/auth/federation/oidc/callback").mock(
            return_value=httpx.Response(
                200,
                json={
                    "user_id": "user-2",
                    "session_id": "s2",
                    "expires_in": 900,
                    "redirect_uri": "https://app.test/post-login",
                },
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        client.sso_complete(state="federation-state-1", code="idp-code-1")

        handle = client.acting_tenant(TENANT_A)
        assert handle.acting_tenant_id == TENANT_A
        client.close()


async def test_an_sso_completion_after_an_org_level_false_login_resets_the_stale_gate_async() -> (
    None
):
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=False)
        client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        await client.login("a@example.test", "password123")
        with pytest.raises(AuthzError):
            client.acting_tenant(TENANT_A)

        router.post(f"{BASE_URL}/api/v1/auth/federation/oidc/callback").mock(
            return_value=httpx.Response(
                200,
                json={
                    "user_id": "user-2",
                    "session_id": "s2",
                    "expires_in": 900,
                    "redirect_uri": "https://app.test/post-login",
                },
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        await client.sso_complete(state="federation-state-1", code="idp-code-1")

        handle = client.acting_tenant(TENANT_A)
        assert handle.acting_tenant_id == TENANT_A
        await client.aclose()


# CONTRACT 1.52 N5.6 (C-12): tenant ids compare as UUIDs, never as strings.
# The server writes `reachable_tenant_ids` in lower case; a caller may pass
# the same UUID in upper case, which `acting_tenant()`'s UUID check accepts.
# The all-digit constants above cannot show this, so these use hex letters.
TENANT_HEX = "abcdef01-2345-4678-9abc-def012345678"


def test_reach_is_decided_on_uuids_not_on_letter_case() -> None:
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=True, reachable_tenant_ids=[TENANT_HEX])
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("a@example.test", "password123")
        handle = client.acting_tenant(TENANT_HEX.upper())
        assert handle.acting_tenant_id is not None
        assert handle.acting_tenant_id.lower() == TENANT_HEX
        client.close()


def test_reach_still_refuses_an_unreachable_tenant_in_any_case() -> None:
    with respx.mock(assert_all_called=False) as router:
        mount_login_as(router, organization_level=True, reachable_tenant_ids=[TENANT_HEX])
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("a@example.test", "password123")
        with pytest.raises(AuthzError, match="reachable_tenant_ids"):
            client.acting_tenant(TENANT_A.upper())
        client.close()
