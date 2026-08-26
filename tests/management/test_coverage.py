"""The §27 paths the semantics suites reach past, exercised deliberately.

Nothing here is incidental: each case covers a branch that is easy to get wrong
and would otherwise ship untested — the 401-then-refresh retry, an error body
that is not JSON, the wire conversion of the value kinds pydantic hands back as
objects, the scoped async handles, and every ``update`` branch of the reconciler.
"""

from __future__ import annotations

import datetime
import json
import uuid
from enum import Enum

import httpx
import pytest
import respx

from axiam_sdk.management._errors import parse_field_errors
from axiam_sdk.management._page import Page, PageRequest, page_of, page_query
from axiam_sdk.management._wire import _expose
from axiam_sdk.management.manifest import (
    GroupSpec,
    ManagementManifest,
    PermissionSpec,
    ResourceSpec,
    RoleSpec,
    UserSpec,
)
from axiam_sdk.management.models import UserResponse
from tests.management.test_manifest import ROLE_ID, _page, _role
from tests.management_support import (
    BASE_URL,
    ORG_ID,
    TENANT_ID,
    access_token,
    with_async_client,
    with_client,
)

# ---------------------------------------------------------------------------
# Error-body parsing
# ---------------------------------------------------------------------------


def test_field_errors_of_an_unrecognised_body_are_empty() -> None:
    """Failing to parse an error body must not replace a useful message."""
    assert parse_field_errors(None) == []
    assert parse_field_errors("just a string") == []
    assert parse_field_errors({"errors": 42}) == []
    assert parse_field_errors({"errors": [{"no_field": "x"}]}) == []
    assert parse_field_errors({"errors": {"field": 42}}) == []


# ---------------------------------------------------------------------------
# Page helpers
# ---------------------------------------------------------------------------


def test_page_query_omits_an_unset_limit_rather_than_sending_zero() -> None:
    """The server reads ``limit=0`` as "none", which returns an empty page."""
    assert page_query(None) == {"offset": "0", "limit": None}
    assert page_query(PageRequest(offset=4, limit=2)) == {"offset": "4", "limit": "2"}


def test_page_of_a_malformed_envelope_is_empty_rather_than_an_error() -> None:
    """A body that is not an envelope yields no items, not a crash mid-parse."""
    page = page_of("not an envelope", UserResponse)
    assert page.items == []
    assert page.total == 0


def test_has_more_is_false_on_an_empty_page() -> None:
    """An empty page ends the walk however optimistic ``total`` is."""
    assert Page[UserResponse](items=[], total=99, offset=0, limit=10).has_more() is False


# ---------------------------------------------------------------------------
# Wire conversion
# ---------------------------------------------------------------------------


class _Colour(Enum):
    """A stand-in enum, to prove ``_expose`` unwraps by value."""

    RED = "red"


def test_expose_renders_the_kinds_model_dump_leaves_as_objects() -> None:
    """``model_dump`` in python mode hands back objects JSON cannot carry."""
    when = datetime.datetime(2026, 8, 26, tzinfo=datetime.UTC)
    identifier = uuid.UUID("11111111-1111-4111-8111-111111111111")
    assert _expose(_Colour.RED) == "red"
    assert _expose(identifier) == "11111111-1111-4111-8111-111111111111"
    assert _expose(when) == "2026-08-26T00:00:00+00:00"
    assert _expose(datetime.date(2026, 8, 26)) == "2026-08-26"
    assert _expose([{"k": _Colour.RED}]) == [{"k": "red"}]


# ---------------------------------------------------------------------------
# The request path
# ---------------------------------------------------------------------------


def test_a_401_refreshes_once_and_retries_the_call() -> None:
    """§9.3's refresh-then-retry-once applies here as it does everywhere else."""
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        """401 first, then the real answer."""
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(401, json={"message": "expired"})
        return httpx.Response(200, json={"items": [], "total": 0, "offset": 0, "limit": 50})

    with with_client() as (router, client):
        router.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
            return_value=httpx.Response(
                200,
                json={"expires_in": 900},
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        router.get(f"{BASE_URL}/api/v1/users").mock(side_effect=responder)

        page = client.users.list()
        assert page.total == 0
        assert calls["n"] == 2


@pytest.mark.asyncio
async def test_a_401_refreshes_once_on_the_async_path_too() -> None:
    """The async twin shares the semantics, not the code."""
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        """401 first, then the real answer."""
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(401, json={"message": "expired"})
        return httpx.Response(200, json={"items": [], "total": 0, "offset": 0, "limit": 50})

    async with with_async_client() as (router, client):
        router.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
            return_value=httpx.Response(
                200,
                json={"expires_in": 900},
                headers=[("Set-Cookie", f"axiam_access={access_token()}; Path=/; HttpOnly")],
            )
        )
        router.get(f"{BASE_URL}/api/v1/users").mock(side_effect=responder)

        page = await client.users.list()
        assert page.total == 0
        assert calls["n"] == 2


def test_a_plain_text_error_body_reaches_the_message() -> None:
    """A body that is not JSON is still worth showing the caller."""
    from axiam_sdk.management import NotFoundError

    with with_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/users/{ORG_ID}").mock(
            return_value=httpx.Response(404, text="no such user, plainly")
        )
        with pytest.raises(NotFoundError, match="no such user, plainly"):
            client.users.get(ORG_ID)


def test_a_204_parses_to_none_rather_than_a_json_error() -> None:
    """Twenty-odd operations answer 204; parsing an empty body would raise."""
    with with_client() as (router, client):
        router.delete(f"{BASE_URL}/api/v1/users/{ORG_ID}").mock(return_value=httpx.Response(204))
        assert client.users.delete(ORG_ID) is None


# ---------------------------------------------------------------------------
# Scoped async handles
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_async_handles_are_scopable_too() -> None:
    """``in_org`` / ``for_tenant`` exist on both forms, or one of them is a trap."""
    other_org = "44444444-4444-4444-8444-444444444444"
    other_tenant = "55555555-5555-4555-8555-555555555555"
    async with with_async_client() as (_router, client):
        assert client.organizations.in_org(other_org) is not client.organizations
        assert client.tenants.in_org(other_org) is not client.tenants
        assert client.ca_certificates.in_org(other_org) is not client.ca_certificates
        assert client.settings.in_org(other_org) is not client.settings
        assert client.settings.for_tenant(other_tenant) is not client.settings
        assert client.webauthn_policy.for_tenant(other_tenant) is not client.webauthn_policy
        assert client.email_config.for_tenant(other_tenant) is not client.email_config


def test_the_sync_handles_are_scopable_on_every_namespace_that_needs_it() -> None:
    """The same set, on the sync side."""
    other_org = "44444444-4444-4444-8444-444444444444"
    other_tenant = "55555555-5555-4555-8555-555555555555"
    with with_client() as (_router, client):
        assert client.tenants.in_org(other_org) is not client.tenants
        assert client.ca_certificates.in_org(other_org) is not client.ca_certificates
        assert client.settings.in_org(other_org) is not client.settings
        assert client.settings.for_tenant(other_tenant) is not client.settings
        assert client.webauthn_policy.for_tenant(other_tenant) is not client.webauthn_policy
        assert client.email_config.for_tenant(other_tenant) is not client.email_config


# ---------------------------------------------------------------------------
# Every update branch of the reconciler
# ---------------------------------------------------------------------------

DRIFTED = ManagementManifest(
    resources=(ResourceSpec(key="docs", name="documents", resource_type="folder"),),
    permissions=(PermissionSpec(key="read", action="document:read", description="Read now"),),
    roles=(RoleSpec(key="editor", name="Editor", description="Edits now"),),
    groups=(GroupSpec(key="staff", name="Staff", description="Everyone now"),),
    users=(UserSpec(key="alice", username="alice", email="alice-new@example.test"),),
)
"""A manifest that differs from the fixture tenant in every updatable field."""

RESOURCE_ID = "77777777-7777-4777-8777-777777777777"
"""The resource id the drifted fixture holds."""

PERMISSION_ID = "88888888-8888-4888-8888-888888888888"
"""The permission id the drifted fixture holds."""

GROUP_ID = "99999999-9999-4999-8999-999999999999"
"""The group id the drifted fixture holds."""

USER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
"""The user id the drifted fixture holds."""


def mount_drifted_tenant(router: respx.MockRouter) -> None:
    """A tenant holding one of everything, each drifted from ``DRIFTED``."""
    stamps = {"created_at": "2026-08-26T00:00:00Z", "updated_at": "2026-08-26T00:00:00Z"}
    router.get(f"{BASE_URL}/api/v1/resources").mock(
        return_value=httpx.Response(
            200,
            json=_page(
                [
                    {
                        "id": RESOURCE_ID,
                        "name": "documents",
                        "resource_type": "collection",
                        "parent_id": None,
                        "metadata": {},
                        "tenant_id": TENANT_ID,
                        **stamps,
                    }
                ]
            ),
        )
    )
    router.get(f"{BASE_URL}/api/v1/resources/{RESOURCE_ID}/scopes").mock(
        return_value=httpx.Response(200, json=[])
    )
    router.get(f"{BASE_URL}/api/v1/permissions").mock(
        return_value=httpx.Response(
            200,
            json=_page(
                [
                    {
                        "id": PERMISSION_ID,
                        "action": "document:read",
                        "description": "Read before",
                        "tenant_id": TENANT_ID,
                        **stamps,
                    }
                ]
            ),
        )
    )
    router.get(f"{BASE_URL}/api/v1/roles").mock(
        return_value=httpx.Response(200, json=_page([_role(ROLE_ID, "Editor", "Edits before")]))
    )
    for sub in ("permissions", "users", "groups"):
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/{sub}").mock(
            return_value=httpx.Response(200, json=[])
        )
    router.get(f"{BASE_URL}/api/v1/groups").mock(
        return_value=httpx.Response(
            200,
            json=_page(
                [
                    {
                        "id": GROUP_ID,
                        "name": "Staff",
                        "description": "Everyone before",
                        "metadata": {},
                        "tenant_id": TENANT_ID,
                        **stamps,
                    }
                ]
            ),
        )
    )
    router.get(f"{BASE_URL}/api/v1/groups/{GROUP_ID}/members").mock(
        return_value=httpx.Response(200, json=_page([]))
    )
    router.get(f"{BASE_URL}/api/v1/users").mock(
        return_value=httpx.Response(
            200,
            json=_page(
                [
                    {
                        "id": USER_ID,
                        "username": "alice",
                        "email": "alice-before@example.test",
                        "email_verified": True,
                        "failed_login_attempts": 0,
                        "is_locked": False,
                        "metadata": {},
                        "mfa_enabled": False,
                        "status": "Active",
                        "tenant_id": TENANT_ID,
                        **stamps,
                    }
                ]
            ),
        )
    )


def mount_updates(router: respx.MockRouter) -> dict[str, respx.Route]:
    """Accept every ``PUT`` the drifted manifest implies."""
    stamps = {"created_at": "2026-08-26T00:00:00Z", "updated_at": "2026-08-26T00:00:00Z"}
    return {
        "resource": router.put(f"{BASE_URL}/api/v1/resources/{RESOURCE_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": RESOURCE_ID,
                    "name": "documents",
                    "resource_type": "folder",
                    "parent_id": None,
                    "metadata": {},
                    "tenant_id": TENANT_ID,
                    **stamps,
                },
            )
        ),
        "permission": router.put(f"{BASE_URL}/api/v1/permissions/{PERMISSION_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": PERMISSION_ID,
                    "action": "document:read",
                    "description": "Read now",
                    "tenant_id": TENANT_ID,
                    **stamps,
                },
            )
        ),
        "role": router.put(f"{BASE_URL}/api/v1/roles/{ROLE_ID}").mock(
            return_value=httpx.Response(200, json=_role(ROLE_ID, "Editor", "Edits now"))
        ),
        "group": router.put(f"{BASE_URL}/api/v1/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": GROUP_ID,
                    "name": "Staff",
                    "description": "Everyone now",
                    "metadata": {},
                    "tenant_id": TENANT_ID,
                    **stamps,
                },
            )
        ),
        "user": router.put(f"{BASE_URL}/api/v1/users/{USER_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": USER_ID,
                    "username": "alice",
                    "email": "alice-new@example.test",
                    "email_verified": True,
                    "failed_login_attempts": 0,
                    "is_locked": False,
                    "metadata": {},
                    "mfa_enabled": False,
                    "status": "Active",
                    "tenant_id": TENANT_ID,
                    **stamps,
                },
            )
        ),
    }


def test_every_drifted_kind_is_updated() -> None:
    """Drift in a field the manifest states is an update, for every kind of thing."""
    with with_client() as (router, client):
        mount_drifted_tenant(router)
        routes = mount_updates(router)

        plan = client.manifest.plan(DRIFTED)
        assert {a.target for a in plan.changes()} == {
            "resource",
            "permission",
            "role",
            "group",
            "user",
        }

        report = client.manifest.apply(DRIFTED)
        assert report.is_complete()
        assert report.changed_count() == 5
        assert all(route.call_count == 1 for route in routes.values())
        sent = json.loads(routes["user"].calls[0].request.content)
        assert set(sent) == {"email"}


@pytest.mark.asyncio
async def test_every_drifted_kind_is_updated_on_the_async_path() -> None:
    """The async ``_run`` has its own branch per kind, and they are exercised."""
    async with with_async_client() as (router, client):
        mount_drifted_tenant(router)
        routes = mount_updates(router)

        report = await client.manifest.apply(DRIFTED)
        assert report.is_complete()
        assert report.changed_count() == 5
        assert all(route.call_count == 1 for route in routes.values())
