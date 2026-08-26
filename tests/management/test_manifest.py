"""CONTRACT §27.6 — the declarative layer's reconciler.

The rules under test, in order: ``plan`` writes nothing and is stable across
runs; validation precedes every request; ordering is derived; drift is an update
and omission is never a deletion; ``apply`` converges, and stops at the first
failure while reporting what it did not attempt.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from pydantic import SecretStr

from axiam_sdk import NetworkError
from axiam_sdk.management.manifest import (
    GrantSpec,
    GroupSpec,
    ManagementManifest,
    PermissionSpec,
    ResourceSpec,
    RoleSpec,
    ScopeSpec,
    UserSpec,
)
from tests.management_support import BASE_URL, TENANT_ID, with_async_client, with_client

EMPTY_PAGE = {"items": [], "total": 0, "offset": 0, "limit": 200}
"""What every planning read answers on a tenant with nothing in it."""


def mount_empty_tenant(router: respx.MockRouter) -> None:
    """Answer every planning read with an empty tenant."""
    for path in ("resources", "permissions", "roles", "groups", "users"):
        router.get(f"{BASE_URL}/api/v1/{path}").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )


def sample_manifest() -> ManagementManifest:
    """A small manifest touching every kind the reconciler handles."""
    return ManagementManifest(
        resources=(
            ResourceSpec(
                key="docs",
                name="documents",
                resource_type="collection",
                scopes=(ScopeSpec(key="draft", name="draft", description="Unpublished"),),
            ),
            ResourceSpec(key="archive", name="archive", resource_type="collection", parent="docs"),
        ),
        permissions=(PermissionSpec(key="read", action="document:read", description="Read"),),
        roles=(
            RoleSpec(
                key="editor",
                name="Editor",
                description="Edits documents",
                grants=(GrantSpec(permission="read", scopes=("draft",)),),
            ),
        ),
        groups=(GroupSpec(key="staff", name="Staff", description="Everyone", roles=("editor",)),),
        users=(
            UserSpec(
                key="alice",
                username="alice",
                email="alice@example.test",
                initial_password=SecretStr("correct-horse-battery"),
                roles=("editor",),
                groups=("staff",),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Rule 1 — plan writes nothing
# ---------------------------------------------------------------------------


def test_plan_issues_no_write() -> None:
    """Every request a plan makes is a read."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        client.manifest.plan(sample_manifest())

        methods = {call.request.method for call in router.calls}
        assert methods <= {"GET", "POST"}
        assert not [
            call
            for call in router.calls
            if call.request.method != "GET" and "/auth/login" not in call.request.url.path
        ]


def test_plan_is_stable_across_runs() -> None:
    """§27.6 rule 8: a plan that reorders between runs cannot be diffed."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        manifest = sample_manifest()
        first = client.manifest.plan(manifest)
        second = client.manifest.plan(manifest)
        assert first == second


# ---------------------------------------------------------------------------
# Rule 5 — derived ordering
# ---------------------------------------------------------------------------


def test_a_parent_resource_is_ordered_before_its_child() -> None:
    """A child cannot be created before the parent it names."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        plan = client.manifest.plan(
            ManagementManifest(
                resources=(
                    ResourceSpec(key="child", name="child", resource_type="c", parent="parent"),
                    ResourceSpec(key="parent", name="parent", resource_type="c"),
                )
            )
        )
        keys = [a.key for a in plan.actions if a.target == "resource"]
        assert keys.index("parent") < keys.index("child")


def test_producers_are_ordered_before_consumers() -> None:
    """Roles precede grants; users and groups precede the bindings between them."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        plan = client.manifest.plan(sample_manifest())
        targets = [a.target for a in plan.actions]
        assert targets.index("permission") < targets.index("role-grant")
        assert targets.index("role") < targets.index("role-grant")
        assert targets.index("group") < targets.index("group-role")
        assert targets.index("user") < targets.index("user-role")
        assert targets.index("user") < targets.index("group-member")


# ---------------------------------------------------------------------------
# Rule 2 — validation precedes every request
# ---------------------------------------------------------------------------


def test_a_dangling_reference_is_refused_before_calling() -> None:
    """The manifest names a permission nobody declared."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        before = len(router.calls)
        with pytest.raises(NetworkError, match="which no permission declares"):
            client.manifest.plan(
                ManagementManifest(
                    roles=(
                        RoleSpec(
                            key="editor",
                            name="Editor",
                            description="Edits",
                            grants=(GrantSpec(permission="nope"),),
                        ),
                    )
                )
            )
        assert len(router.calls) == before


def test_a_resource_cycle_is_refused_rather_than_looped() -> None:
    """A cycle has no creation order; discovering that by hanging is worse."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        with pytest.raises(NetworkError, match="cycle"):
            client.manifest.plan(
                ManagementManifest(
                    resources=(
                        ResourceSpec(key="a", name="a", resource_type="c", parent="b"),
                        ResourceSpec(key="b", name="b", resource_type="c", parent="a"),
                    )
                )
            )


def test_a_duplicate_key_is_refused() -> None:
    """Two specs claiming one key make every reference to it ambiguous."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        with pytest.raises(NetworkError, match="declared more than once"):
            client.manifest.plan(
                ManagementManifest(
                    permissions=(
                        PermissionSpec(key="read", action="a:read", description="A"),
                        PermissionSpec(key="read", action="b:read", description="B"),
                    )
                )
            )


def test_every_problem_is_reported_not_just_the_first() -> None:
    """Fixing one problem at a time is a slow way to learn about four."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        with pytest.raises(NetworkError) as caught:
            client.manifest.plan(
                ManagementManifest(
                    roles=(
                        RoleSpec(
                            key="r",
                            name="R",
                            description="R",
                            grants=(GrantSpec(permission="missing", scopes=("nope",)),),
                        ),
                    ),
                    groups=(GroupSpec(key="g", name="G", description="G", roles=("absent",)),),
                )
            )
        assert "3 problem(s)" in str(caught.value)


def test_a_user_that_must_be_created_needs_a_password_before_any_request() -> None:
    """§27.6 rule 1: not halfway through an apply."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        with pytest.raises(NetworkError, match="no initial_password"):
            client.manifest.plan(
                ManagementManifest(
                    users=(UserSpec(key="bob", username="bob", email="bob@example.test"),)
                )
            )


# ---------------------------------------------------------------------------
# Rules 3 and 4 — drift and pruning
# ---------------------------------------------------------------------------


def _page(items: list[dict[str, object]]) -> dict[str, object]:
    """A single-page envelope carrying ``items``."""
    return {"items": items, "total": len(items), "offset": 0, "limit": 200}


def _role(role_id: str, name: str, description: str, is_global: bool = False) -> dict[str, object]:
    """A role response body."""
    return {
        "id": role_id,
        "name": name,
        "description": description,
        "is_global": is_global,
        "tenant_id": TENANT_ID,
        "created_at": "2026-08-26T00:00:00Z",
        "updated_at": "2026-08-26T00:00:00Z",
    }


ROLE_ID = "66666666-6666-4666-8666-666666666666"
"""The role id the converged-tenant fixtures use."""


def mount_tenant_with_one_role(router: respx.MockRouter, description: str) -> None:
    """A tenant holding exactly one role, with the given description."""
    for path in ("resources", "permissions", "groups", "users"):
        router.get(f"{BASE_URL}/api/v1/{path}").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
    router.get(f"{BASE_URL}/api/v1/roles").mock(
        return_value=httpx.Response(200, json=_page([_role(ROLE_ID, "Editor", description)]))
    )
    for sub in ("permissions", "users", "groups"):
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/{sub}").mock(
            return_value=httpx.Response(200, json=[])
        )


ONE_ROLE = ManagementManifest(
    roles=(RoleSpec(key="editor", name="Editor", description="Edits documents"),)
)
"""A manifest declaring the one role the fixtures above hold."""


def test_a_converged_tenant_plans_nothing() -> None:
    """§27.6 rule 6: nothing to do is the normal steady state."""
    with with_client() as (router, client):
        mount_tenant_with_one_role(router, "Edits documents")
        plan = client.manifest.plan(ONE_ROLE)
        assert plan.is_converged()
        assert plan.actions and all(a.change == "no-change" for a in plan.actions)


def test_a_drifted_field_the_manifest_states_is_an_update() -> None:
    """The manifest describes the shape; a description that differs is drift."""
    with with_client() as (router, client):
        mount_tenant_with_one_role(router, "something else")
        plan = client.manifest.plan(ONE_ROLE)
        assert [(a.change, a.target) for a in plan.changes()] == [("update", "role")]


def test_a_role_the_manifest_omits_is_never_deleted() -> None:
    """§27.6 rule 4: a manifest describes what should exist, not what should not."""
    with with_client() as (router, client):
        mount_tenant_with_one_role(router, "Edits documents")
        plan = client.manifest.plan(ManagementManifest())
        assert plan.actions == ()
        assert plan.is_converged()


# ---------------------------------------------------------------------------
# Rules 6 and 7 — apply
# ---------------------------------------------------------------------------

CREATED_IDS = {
    "resources": "aaaaaaaa-0000-4000-8000-000000000001",
    "scopes": "aaaaaaaa-0000-4000-8000-000000000002",
    "permissions": "aaaaaaaa-0000-4000-8000-000000000003",
    "roles": "aaaaaaaa-0000-4000-8000-000000000004",
    "groups": "aaaaaaaa-0000-4000-8000-000000000005",
    "users": "aaaaaaaa-0000-4000-8000-000000000006",
}
"""Ids the mocked creates hand back, so later steps have something to bind."""


def mount_creates(router: respx.MockRouter) -> None:
    """Accept every create and binding the sample manifest needs."""
    router.post(f"{BASE_URL}/api/v1/resources").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": CREATED_IDS["resources"],
                "name": "documents",
                "resource_type": "collection",
                "parent_id": None,
                "metadata": {},
                "tenant_id": TENANT_ID,
                "created_at": "2026-08-26T00:00:00Z",
                "updated_at": "2026-08-26T00:00:00Z",
            },
        )
    )
    router.post(url__regex=r".*/resources/[^/]+/scopes$").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": CREATED_IDS["scopes"],
                "name": "draft",
                "description": "Unpublished",
                "resource_id": CREATED_IDS["resources"],
                "tenant_id": TENANT_ID,
                "created_at": "2026-08-26T00:00:00Z",
                "updated_at": "2026-08-26T00:00:00Z",
            },
        )
    )
    router.post(f"{BASE_URL}/api/v1/permissions").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": CREATED_IDS["permissions"],
                "action": "document:read",
                "description": "Read",
                "tenant_id": TENANT_ID,
                "created_at": "2026-08-26T00:00:00Z",
                "updated_at": "2026-08-26T00:00:00Z",
            },
        )
    )
    router.post(f"{BASE_URL}/api/v1/roles").mock(
        return_value=httpx.Response(
            201, json=_role(CREATED_IDS["roles"], "Editor", "Edits documents")
        )
    )
    router.post(f"{BASE_URL}/api/v1/groups").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": CREATED_IDS["groups"],
                "name": "Staff",
                "description": "Everyone",
                "metadata": {},
                "tenant_id": TENANT_ID,
                "created_at": "2026-08-26T00:00:00Z",
                "updated_at": "2026-08-26T00:00:00Z",
            },
        )
    )
    router.post(f"{BASE_URL}/api/v1/users").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": CREATED_IDS["users"],
                "username": "alice",
                "email": "alice@example.test",
                "email_verified": False,
                "failed_login_attempts": 0,
                "is_locked": False,
                "metadata": {},
                "mfa_enabled": False,
                "status": "Active",
                "tenant_id": TENANT_ID,
                "created_at": "2026-08-26T00:00:00Z",
                "updated_at": "2026-08-26T00:00:00Z",
            },
        )
    )
    router.post(url__regex=r".*/roles/[^/]+/(permissions|users|groups)$").mock(
        return_value=httpx.Response(204)
    )
    router.post(url__regex=r".*/groups/[^/]+/members$").mock(return_value=httpx.Response(204))


def test_apply_creates_everything_and_reports_an_outcome_for_every_step() -> None:
    """Every planned step is accounted for, in plan order."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        mount_creates(router)
        report = client.manifest.apply(sample_manifest())

        assert report.is_complete()
        assert report.failure() is None
        assert all(s.outcome.status == "created" for s in report.steps)
        assert report.changed_count() == len(report.steps)


def test_apply_stops_at_the_first_failure_and_says_what_was_not_attempted() -> None:
    """§27.6 rule 7: there is no transaction, and this report does not pretend."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        mount_creates(router)
        router.post(f"{BASE_URL}/api/v1/permissions").mock(
            return_value=httpx.Response(409, json={"message": "already exists"})
        )

        report = client.manifest.apply(sample_manifest())

        assert not report.is_complete()
        failure = report.failure()
        assert failure is not None
        assert failure.action.target == "permission"

        statuses = [s.outcome.status for s in report.steps]
        assert "failed" in statuses
        assert statuses[statuses.index("failed") + 1 :] == ["not-attempted"] * (
            len(statuses) - statuses.index("failed") - 1
        )


def test_applying_an_empty_manifest_is_clean() -> None:
    """Nothing declared means nothing planned and nothing sent."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        report = client.manifest.apply(ManagementManifest())
        assert report.steps == ()
        assert report.is_complete()
        assert report.changed_count() == 0


def test_a_password_is_never_sent_for_a_user_that_already_exists() -> None:
    """A config file mentioning a password is not a request to reset one."""
    with with_client() as (router, client):
        for path in ("resources", "permissions", "roles", "groups"):
            router.get(f"{BASE_URL}/api/v1/{path}").mock(
                return_value=httpx.Response(200, json=EMPTY_PAGE)
            )
        router.get(f"{BASE_URL}/api/v1/users").mock(
            return_value=httpx.Response(
                200,
                json=_page(
                    [
                        {
                            "id": CREATED_IDS["users"],
                            "username": "alice",
                            "email": "alice@example.test",
                            "email_verified": True,
                            "failed_login_attempts": 0,
                            "is_locked": False,
                            "metadata": {},
                            "mfa_enabled": False,
                            "status": "Active",
                            "tenant_id": TENANT_ID,
                            "created_at": "2026-08-26T00:00:00Z",
                            "updated_at": "2026-08-26T00:00:00Z",
                        }
                    ]
                ),
            )
        )
        created = router.post(f"{BASE_URL}/api/v1/users")

        report = client.manifest.apply(
            ManagementManifest(
                users=(
                    UserSpec(
                        key="alice",
                        username="alice",
                        email="alice@example.test",
                        initial_password=SecretStr("would-be-a-reset"),
                    ),
                )
            )
        )

        assert created.call_count == 0
        assert [s.outcome.status for s in report.steps] == ["unchanged"]


@pytest.mark.asyncio
async def test_the_async_reconciler_plans_the_same_thing() -> None:
    """The deciding half is shared; only the I/O is written twice."""
    with with_client() as (router, client):
        mount_empty_tenant(router)
        expected = client.manifest.plan(sample_manifest())

    async with with_async_client() as (router, aclient):
        mount_empty_tenant(router)
        actual = await aclient.manifest.plan(sample_manifest())

    assert actual == expected


@pytest.mark.asyncio
async def test_the_async_reconciler_applies_and_reports() -> None:
    """The async apply reports the same outcome shape as the sync one."""
    async with with_async_client() as (router, client):
        mount_empty_tenant(router)
        mount_creates(router)
        report = await client.manifest.apply(sample_manifest())
        assert report.is_complete()
        assert report.changed_count() == len(report.steps)
