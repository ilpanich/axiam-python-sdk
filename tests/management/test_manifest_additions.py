"""CONTRACT §27.6.1 — the manifest additions of the dogfooding remediation
(contract 1.51): ``resources[].metadata``, the two-shape role binding
(``ScopedRoleBinding`` with ``inherit``), and ``service_accounts``.

Covers every assertion §27.9's "Manifest additions" list names, alongside
rule 6's idempotence test.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from axiam_sdk import NetworkError
from axiam_sdk.management.manifest import (
    GrantSpec,
    GroupSpec,
    ManagementManifest,
    PermissionSpec,
    ResourceSpec,
    RoleSpec,
    ScopedRoleBinding,
    ScopeSpec,
    ServiceAccountSpec,
    UserSpec,
)
from tests.management_support import BASE_URL, TENANT_ID, with_async_client, with_client

EMPTY_PAGE = {"items": [], "total": 0, "offset": 0, "limit": 200}
STAMPS = {"created_at": "2026-08-26T00:00:00Z", "updated_at": "2026-08-26T00:00:00Z"}

RESOURCE_ID = "77777777-7777-4777-8777-777777777771"
OTHER_RESOURCE_ID = "77777777-7777-4777-8777-777777777772"
ROLE_ID = "66666666-6666-4666-8666-666666666666"
GROUP_ID = "55555555-5555-4555-8555-555555555555"
SA_ID = "44444444-4444-4444-8444-444444444444"
OTHER_SA_ID = "44444444-4444-4444-8444-444444444445"
USER_ID = "33333333-3333-4333-8333-333333333331"
PERMISSION_ID = "22222222-2222-4222-8222-222222222221"


def _page(items: list[dict[str, object]]) -> dict[str, object]:
    return {"items": items, "total": len(items), "offset": 0, "limit": 200}


def _resource(
    resource_id: str, name: str, resource_type: str, metadata: object, parent_id: str | None = None
) -> dict[str, object]:
    return {
        "id": resource_id,
        "name": name,
        "resource_type": resource_type,
        "parent_id": parent_id,
        "metadata": metadata,
        "tenant_id": TENANT_ID,
        **STAMPS,
    }


def _role(role_id: str, name: str, description: str, is_global: bool = False) -> dict[str, object]:
    return {
        "id": role_id,
        "name": name,
        "description": description,
        "is_global": is_global,
        "tenant_id": TENANT_ID,
        **STAMPS,
    }


def _group(group_id: str, name: str, description: str) -> dict[str, object]:
    return {
        "id": group_id,
        "name": name,
        "description": description,
        "metadata": {},
        "tenant_id": TENANT_ID,
        **STAMPS,
    }


def _service_account(sa_id: str, name: str, description: str | None = None) -> dict[str, object]:
    return {
        "id": sa_id,
        "client_id": f"client-{sa_id}",
        "name": name,
        "description": description,
        "status": "Active",
        "tenant_id": TENANT_ID,
        **STAMPS,
    }


def _permission(permission_id: str, action: str, description: str) -> dict[str, object]:
    return {
        "id": permission_id,
        "action": action,
        "description": description,
        "tenant_id": TENANT_ID,
        **STAMPS,
    }


def _user(user_id: str, username: str, email: str) -> dict[str, object]:
    return {
        "id": user_id,
        "username": username,
        "email": email,
        "email_verified": True,
        "failed_login_attempts": 0,
        "is_locked": False,
        "metadata": {},
        "mfa_enabled": False,
        "status": "Active",
        "tenant_id": TENANT_ID,
        **STAMPS,
    }


def _empty_tenant(
    router: respx.MockRouter, *, resources: list[dict[str, object]] | None = None
) -> None:
    resources = resources or []
    router.get(f"{BASE_URL}/api/v1/resources").mock(
        return_value=httpx.Response(200, json=_page(resources))
    )
    for path in ("permissions", "roles", "groups", "users", "service-accounts"):
        router.get(f"{BASE_URL}/api/v1/{path}").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
    for resource in resources:
        router.get(f"{BASE_URL}/api/v1/resources/{resource['id']}/scopes").mock(
            return_value=httpx.Response(200, json=[])
        )


# ---------------------------------------------------------------------------
# resources[].metadata (addition 1)
# ---------------------------------------------------------------------------


def test_metadata_round_trips_through_apply_then_plan() -> None:
    """``apply`` of a resource with metadata, then ``plan``, is all NoChange."""
    manifest = ManagementManifest(
        resources=(
            ResourceSpec(
                key="docs", name="documents", resource_type="collection", metadata={"owner": "core"}
            ),
        )
    )
    with with_client() as (router, client):
        _empty_tenant(router)
        router.post(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(
                201, json=_resource(RESOURCE_ID, "documents", "collection", {"owner": "core"})
            )
        )
        report = client.manifest.apply(manifest)
        assert report.is_complete()
        sent = json.loads(router.calls[-1].request.content)
        assert sent["metadata"] == {"owner": "core"}

    with with_client() as (router, client):
        _empty_tenant(
            router, resources=[_resource(RESOURCE_ID, "documents", "collection", {"owner": "core"})]
        )
        plan = client.manifest.plan(manifest)
        assert plan.is_converged()


def test_a_changed_metadata_key_yields_an_update_carrying_the_whole_object() -> None:
    manifest = ManagementManifest(
        resources=(
            ResourceSpec(
                key="docs",
                name="documents",
                resource_type="collection",
                metadata={"owner": "core", "tier": "gold"},
            ),
        )
    )
    with with_client() as (router, client):
        _empty_tenant(
            router, resources=[_resource(RESOURCE_ID, "documents", "collection", {"owner": "core"})]
        )
        route = router.put(f"{BASE_URL}/api/v1/resources/{RESOURCE_ID}").mock(
            return_value=httpx.Response(
                200,
                json=_resource(
                    RESOURCE_ID, "documents", "collection", {"owner": "core", "tier": "gold"}
                ),
            )
        )
        plan = client.manifest.plan(manifest)
        assert [(a.change, a.target) for a in plan.changes()] == [("update", "resource")]

        report = client.manifest.apply(manifest)
        assert report.is_complete()
        sent = json.loads(route.calls[-1].request.content)
        assert sent == {"metadata": {"owner": "core", "tier": "gold"}}, (
            "the whole object, never a key-by-key merge"
        )


def test_an_unstated_metadata_is_silent_not_a_clear() -> None:
    """§27.6 rule 3: a spec that never mentions metadata is silent about it,
    never an assertion that it should be emptied."""
    manifest = ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),)
    )
    with with_client() as (router, client):
        _empty_tenant(
            router, resources=[_resource(RESOURCE_ID, "documents", "collection", {"owner": "core"})]
        )
        plan = client.manifest.plan(manifest)
        assert plan.is_converged(), "no metadata stated means no opinion about it"


def test_a_stated_empty_object_matches_what_the_server_stores_for_none() -> None:
    manifest = ManagementManifest(
        resources=(
            ResourceSpec(key="docs", name="documents", resource_type="collection", metadata={}),
        )
    )
    with with_client() as (router, client):
        _empty_tenant(router, resources=[_resource(RESOURCE_ID, "documents", "collection", {})])
        plan = client.manifest.plan(manifest)
        assert plan.is_converged()


# ---------------------------------------------------------------------------
# Two-shape role binding (addition 2)
# ---------------------------------------------------------------------------


def _tenant_with_one_role_group_and_resource(router: respx.MockRouter) -> None:
    _empty_tenant(router, resources=[_resource(RESOURCE_ID, "documents", "collection", {})])
    router.get(f"{BASE_URL}/api/v1/roles").mock(
        return_value=httpx.Response(200, json=_page([_role(ROLE_ID, "Editor", "Edits")]))
    )
    router.get(f"{BASE_URL}/api/v1/groups").mock(
        return_value=httpx.Response(200, json=_page([_group(GROUP_ID, "Staff", "Everyone")]))
    )
    router.get(f"{BASE_URL}/api/v1/groups/{GROUP_ID}/members").mock(
        return_value=httpx.Response(200, json=_page([]))
    )
    for sub in ("permissions", "users", "service-accounts"):
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/{sub}").mock(
            return_value=httpx.Response(200, json=[])
        )


def _manifest_with_scoped_binding(*, inherit: bool | None) -> ManagementManifest:
    kwargs = {} if inherit is None else {"inherit": inherit}
    return ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
        roles=(RoleSpec(key="editor", name="Editor", description="Edits"),),
        groups=(
            GroupSpec(
                key="staff",
                name="Staff",
                description="Everyone",
                roles=(ScopedRoleBinding(role="editor", resource="docs", **kwargs),),
            ),
        ),
    )


def test_a_resource_scoped_binding_with_inherit_false_sends_resource_id_and_inherit() -> None:
    with with_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(200, json=[])
        )
        route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(204)
        )
        report = client.manifest.apply(_manifest_with_scoped_binding(inherit=False))
        assert report.is_complete()
        sent = json.loads(route.calls[-1].request.content)
        assert sent == {"group_id": GROUP_ID, "resource_id": RESOURCE_ID, "inherit": False}


def test_the_same_binding_with_inherit_omitted_sends_no_inherit_key() -> None:
    """Rule 1: the key is sent only when it is False -- an inheritable
    binding's body stays byte-for-byte a pre-1.51 body."""
    with with_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(200, json=[])
        )
        route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(204)
        )
        report = client.manifest.apply(_manifest_with_scoped_binding(inherit=None))
        assert report.is_complete()
        sent = json.loads(route.calls[-1].request.content)
        assert set(sent) == {"group_id", "resource_id"}, "no inherit key when it is not stated"


def test_changing_a_bindings_resource_is_unassign_then_assign_in_order() -> None:
    """Changing a binding's resource is an unassign followed by an assign,
    in that order, and the server's tenant_scope survives the change."""
    with with_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": ["99999999-9999-4999-8999-999999999999"],
                    }
                ],
            )
        )
        unassign_route = router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(204)
        )

        # resource "docs" (RESOURCE_ID) != the server's OTHER_RESOURCE_ID.
        manifest = _manifest_with_scoped_binding(inherit=None)
        plan = client.manifest.plan(manifest)
        assert [(a.change, a.target) for a in plan.changes()] == [("update", "group-role")]

        report = client.manifest.apply(manifest)
        assert report.is_complete()
        assert unassign_route.called and assign_route.called
        # Ordering: the DELETE happened before the POST, in the global call
        # sequence restricted to the two routes under test (not merely
        # within each route's own call list, and not confused by the
        # unrelated POST /auth/login the with_client() fixture makes first).
        relevant = [
            call.request.method
            for call in router.calls
            if call.request.method in ("DELETE", "POST")
            and (
                call.request.url.path.endswith(f"/roles/{ROLE_ID}/groups")
                or call.request.url.path.endswith(f"/roles/{ROLE_ID}/groups/{GROUP_ID}")
            )
        ]
        assert relevant == ["DELETE", "POST"]
        sent = json.loads(assign_route.calls[-1].request.content)
        assert sent["resource_id"] == RESOURCE_ID
        assert sent["tenant_scope"] == ["99999999-9999-4999-8999-999999999999"]


def test_a_failed_rebind_restores_the_previous_binding_and_reports_both_outcomes() -> None:
    with with_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),  # the new assign fails
            httpx.Response(204),  # the restore succeeds
        ]

        manifest = _manifest_with_scoped_binding(inherit=None)
        report = client.manifest.apply(manifest)
        assert not report.is_complete()
        failure = report.failure()
        assert failure is not None
        assert "restored" in failure.message
        assert assign_route.call_count == 2
        restore_body = json.loads(assign_route.calls[1].request.content)
        assert restore_body["resource_id"] == OTHER_RESOURCE_ID


def _failed_step(report: object) -> object:
    """The one step of ``report.steps`` whose outcome is ``failed``."""
    for step in report.steps:  # type: ignore[attr-defined]
        if step.outcome.status == "failed":
            return step
    raise AssertionError("no failed step in this report")


def test_a_failed_rebind_reports_restore_succeeded_as_a_structured_field() -> None:
    """CONTRACT §27.6.1: "If the assign fails, the SDK MUST attempt to
    assign the previous binding again ... and report both outcomes." The
    restore outcome must be a structured field on ``StepOutcome``, not only
    embedded in the failure message string -- every other SDK (TypeScript's
    ``restoreSucceeded``, Java's ``StepOutcome.restored``, C#'s
    ``RestoreSucceeded``, Rust's ``BindingUpdateFailed { restore, .. }``)
    exposes it that way."""
    with with_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),  # the new assign fails
            httpx.Response(204),  # the restore succeeds
        ]

        report = client.manifest.apply(_manifest_with_scoped_binding(inherit=None))
        assert not report.is_complete()
        failed = _failed_step(report)
        assert failed.outcome.restore_succeeded is True  # type: ignore[attr-defined]
        assert failed.outcome.restore_error is None  # type: ignore[attr-defined]
        # The message stays exactly as before -- this is additive, not a
        # replacement of the prose.
        assert "restored" in (failed.outcome.message or "")  # type: ignore[attr-defined]

        # The twin, in the same report: every step whose assign did NOT
        # fail (here, the no-op resource/role/group steps that precede the
        # rebind) carries no restore information at all.
        for step in report.steps:
            if step is not failed:
                assert step.outcome.restore_succeeded is None
                assert step.outcome.restore_error is None


def test_a_failed_rebind_whose_restore_also_fails_reports_restore_error() -> None:
    """When even the restore attempt fails, ``restore_succeeded`` is
    ``False`` and ``restore_error`` carries the restore's own error --
    the twin of the succeeding-restore case above."""
    with with_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal, first"}),
            httpx.Response(500, json={"error": "internal, second"}),
        ]

        report = client.manifest.apply(_manifest_with_scoped_binding(inherit=None))
        assert not report.is_complete()
        failed = _failed_step(report)
        assert failed.outcome.restore_succeeded is False  # type: ignore[attr-defined]
        assert failed.outcome.restore_error is not None  # type: ignore[attr-defined]
        assert "internal, second" in failed.outcome.restore_error  # type: ignore[attr-defined]
        assert "NOT restored" in (failed.outcome.message or "")  # type: ignore[attr-defined]


async def test_a_failed_rebind_reports_restore_succeeded_as_a_structured_field_async() -> None:
    """Async twin of the sync structured-restore test above."""
    async with with_async_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(204),
        ]

        report = await client.manifest.apply(_manifest_with_scoped_binding(inherit=None))
        assert not report.is_complete()
        failed = _failed_step(report)
        assert failed.outcome.restore_succeeded is True  # type: ignore[attr-defined]
        assert failed.outcome.restore_error is None  # type: ignore[attr-defined]


def test_a_manifest_binding_one_role_to_one_subject_twice_is_rejected_before_any_request() -> None:
    manifest = ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
        roles=(RoleSpec(key="editor", name="Editor", description="Edits"),),
        groups=(
            GroupSpec(
                key="staff",
                name="Staff",
                description="Everyone",
                roles=("editor", ScopedRoleBinding(role="editor", resource="docs")),
            ),
        ),
    )
    with with_client() as (router, client):
        with pytest.raises(NetworkError, match="at most once"):
            client.manifest.plan(manifest)
        assert len(router.calls) == 1, "only the with_client() fixture's own login call"


# ---------------------------------------------------------------------------
# service_accounts (addition 3)
# ---------------------------------------------------------------------------


def test_service_account_create_outcome_carries_the_secret_even_when_a_later_action_fails() -> None:
    """The outcome is returned even when a LATER action of the same apply
    fails (§27.5 rule 5). Ordering (§27.6 rule 5) puts service accounts
    before service-account/role bindings, so a role bound to this same
    service account is a later step in the same apply."""
    manifest = ManagementManifest(
        roles=(RoleSpec(key="editor", name="Editor", description="Edits"),),
        service_accounts=(
            ServiceAccountSpec(key="bot", name="ci-bot", description="CI", roles=("editor",)),
        ),
    )
    with with_client() as (router, client):
        _empty_tenant(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(200, json=[])
        )
        router.get(f"{BASE_URL}/api/v1/roles").mock(
            return_value=httpx.Response(200, json=_page([_role(ROLE_ID, "Editor", "Edits")]))
        )
        for sub in ("permissions", "users", "groups"):
            router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/{sub}").mock(
                return_value=httpx.Response(200, json=[])
            )
        router.post(f"{BASE_URL}/api/v1/service-accounts").mock(
            return_value=httpx.Response(
                201,
                json={
                    **_service_account(SA_ID, "ci-bot", "CI"),
                    "client_secret": "s3cr3t-once",
                },
            )
        )
        # The LATER step -- binding the role to the just-created service
        # account -- fails.
        router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(500, json={"error": "internal"})
        )

        report = client.manifest.apply(manifest)
        assert not report.is_complete()
        secret = report.client_secret("bot")
        assert secret is not None
        assert secret.get_secret_value() == "s3cr3t-once"
        assert "s3cr3t-once" not in repr(report), "§7: never reachable via repr/str"


def test_a_second_apply_is_no_change_and_never_calls_rotate_secret() -> None:
    manifest = ManagementManifest(
        service_accounts=(ServiceAccountSpec(key="bot", name="ci-bot", description="CI"),)
    )
    with with_client() as (router, client):
        _empty_tenant(router)
        # Now the account already exists on the server.
        router.get(f"{BASE_URL}/api/v1/service-accounts").mock(
            return_value=httpx.Response(200, json=_page([_service_account(SA_ID, "ci-bot", "CI")]))
        )
        rotate_route = router.post(f"{BASE_URL}/api/v1/service-accounts/{SA_ID}/rotate-secret")

        plan = client.manifest.plan(manifest)
        assert plan.is_converged()
        report = client.manifest.apply(manifest)
        assert report.is_complete()
        assert report.changed_count() == 0
        assert rotate_route.call_count == 0
        assert report.client_secret("bot") is None


def test_two_existing_service_accounts_with_a_stated_name_fail_plan_before_any_write() -> None:
    manifest = ManagementManifest(service_accounts=(ServiceAccountSpec(key="bot", name="ci-bot"),))
    with with_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
        for path in ("permissions", "roles", "groups", "users"):
            router.get(f"{BASE_URL}/api/v1/{path}").mock(
                return_value=httpx.Response(200, json=EMPTY_PAGE)
            )
        router.get(f"{BASE_URL}/api/v1/service-accounts").mock(
            return_value=httpx.Response(
                200,
                json=_page(
                    [
                        _service_account("44444444-4444-4444-8444-444444444441", "ci-bot"),
                        _service_account("44444444-4444-4444-8444-444444444442", "ci-bot"),
                    ]
                ),
            )
        )
        calls_before = len(router.calls)
        with pytest.raises(NetworkError, match="matches 2 existing accounts"):
            client.manifest.plan(manifest)
        # plan() reads state (GETs only) before the ambiguity check runs;
        # the point under test is that NO WRITE was attempted.
        assert all(call.request.method == "GET" for call in router.calls[calls_before:])


async def test_service_account_binding_round_trips_on_the_async_path() -> None:
    manifest = ManagementManifest(
        roles=(RoleSpec(key="editor", name="Editor", description="Edits"),),
        service_accounts=(
            ServiceAccountSpec(key="bot", name="ci-bot", description="CI", roles=("editor",)),
        ),
    )
    async with with_async_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
        for path in ("permissions", "groups", "users"):
            router.get(f"{BASE_URL}/api/v1/{path}").mock(
                return_value=httpx.Response(200, json=EMPTY_PAGE)
            )
        router.get(f"{BASE_URL}/api/v1/roles").mock(
            return_value=httpx.Response(200, json=_page([_role(ROLE_ID, "Editor", "Edits")]))
        )
        for sub in ("permissions", "users", "groups"):
            router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/{sub}").mock(
                return_value=httpx.Response(200, json=[])
            )
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(200, json=[])
        )
        router.get(f"{BASE_URL}/api/v1/service-accounts").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
        router.post(f"{BASE_URL}/api/v1/service-accounts").mock(
            return_value=httpx.Response(
                201,
                json={**_service_account(SA_ID, "ci-bot", "CI"), "client_secret": "async-secret"},
            )
        )
        bind_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(204)
        )

        report = await client.manifest.apply(manifest)
        assert report.is_complete()
        assert report.client_secret("bot") is not None
        sent = json.loads(bind_route.calls[-1].request.content)
        assert sent == {"service_account_id": SA_ID}


# ---------------------------------------------------------------------------
# Idempotence across every kind at once, and the reconciler's remaining
# drift/no-change/rebind branches (contract 1.51 coverage floor, §8 rule 7).
# ---------------------------------------------------------------------------


def test_a_fully_converged_tenant_with_every_kind_plans_nothing_new() -> None:
    """Rule 6's idempotence extended past resource/role/group/user/service-
    account (already covered by ``test_a_converged_tenant_plans_nothing`` and
    ``test_a_second_apply_is_no_change_and_never_calls_rotate_secret``) to a
    scope, a permission, a role grant, a plain (unscoped) role/group binding
    and a group membership that already match the manifest: every one of
    those is NoChange too, not just the kinds the other idempotence tests
    exercise."""
    manifest = ManagementManifest(
        resources=(
            ResourceSpec(
                key="docs",
                name="documents",
                resource_type="collection",
                scopes=(ScopeSpec(key="draft", name="draft", description="Unpublished"),),
            ),
        ),
        permissions=(PermissionSpec(key="read", action="document:read", description="Read"),),
        roles=(
            RoleSpec(
                key="editor",
                name="Editor",
                description="Edits",
                grants=(GrantSpec(permission="read"),),
            ),
        ),
        groups=(GroupSpec(key="staff", name="Staff", description="Everyone", roles=("editor",)),),
        users=(
            UserSpec(key="alice", username="alice", email="alice@example.test", groups=("staff",)),
        ),
    )
    with with_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(
                200, json=_page([_resource(RESOURCE_ID, "documents", "collection", {})])
            )
        )
        router.get(f"{BASE_URL}/api/v1/resources/{RESOURCE_ID}/scopes").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": "88888888-8888-4888-8888-888888888888",
                        "name": "draft",
                        "description": "Unpublished",
                        "resource_id": RESOURCE_ID,
                        "tenant_id": TENANT_ID,
                        **STAMPS,
                    }
                ],
            )
        )
        router.get(f"{BASE_URL}/api/v1/permissions").mock(
            return_value=httpx.Response(
                200, json=_page([_permission(PERMISSION_ID, "document:read", "Read")])
            )
        )
        router.get(f"{BASE_URL}/api/v1/roles").mock(
            return_value=httpx.Response(200, json=_page([_role(ROLE_ID, "Editor", "Edits")]))
        )
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/permissions").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "effect": "Allow",
                        "permission": _permission(PERMISSION_ID, "document:read", "Read"),
                        "scope_ids": [],
                        "scopes": [],
                    }
                ],
            )
        )
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": None,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        for sub in ("users", "service-accounts"):
            router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/{sub}").mock(
                return_value=httpx.Response(200, json=[])
            )
        router.get(f"{BASE_URL}/api/v1/groups").mock(
            return_value=httpx.Response(200, json=_page([_group(GROUP_ID, "Staff", "Everyone")]))
        )
        router.get(f"{BASE_URL}/api/v1/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(
                200, json=_page([_user(USER_ID, "alice", "alice@example.test")])
            )
        )
        router.get(f"{BASE_URL}/api/v1/users").mock(
            return_value=httpx.Response(
                200, json=_page([_user(USER_ID, "alice", "alice@example.test")])
            )
        )
        router.get(f"{BASE_URL}/api/v1/service-accounts").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )

        plan = client.manifest.plan(manifest)
        assert plan.actions and all(a.change == "no-change" for a in plan.actions)
        assert plan.is_converged()


def test_a_drifted_service_account_description_is_updated() -> None:
    """The service account's own ``update`` branch, added by contract 1.51
    alongside the create/no-change siblings the other service-account tests
    already cover."""
    manifest = ManagementManifest(
        service_accounts=(ServiceAccountSpec(key="bot", name="ci-bot", description="CI now"),)
    )
    with with_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
        for path in ("permissions", "roles", "groups", "users"):
            router.get(f"{BASE_URL}/api/v1/{path}").mock(
                return_value=httpx.Response(200, json=EMPTY_PAGE)
            )
        router.get(f"{BASE_URL}/api/v1/service-accounts").mock(
            return_value=httpx.Response(
                200, json=_page([_service_account(SA_ID, "ci-bot", "CI before")])
            )
        )
        route = router.put(f"{BASE_URL}/api/v1/service-accounts/{SA_ID}").mock(
            return_value=httpx.Response(200, json=_service_account(SA_ID, "ci-bot", "CI now"))
        )

        plan = client.manifest.plan(manifest)
        assert [(a.change, a.target) for a in plan.changes()] == [("update", "service-account")]

        report = client.manifest.apply(manifest)
        assert report.is_complete()
        sent = json.loads(route.calls[-1].request.content)
        assert sent == {"description": "CI now"}


async def test_a_drifted_service_account_description_is_updated_on_the_async_path() -> None:
    manifest = ManagementManifest(
        service_accounts=(ServiceAccountSpec(key="bot", name="ci-bot", description="CI now"),)
    )
    async with with_async_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
        for path in ("permissions", "roles", "groups", "users"):
            router.get(f"{BASE_URL}/api/v1/{path}").mock(
                return_value=httpx.Response(200, json=EMPTY_PAGE)
            )
        router.get(f"{BASE_URL}/api/v1/service-accounts").mock(
            return_value=httpx.Response(
                200, json=_page([_service_account(SA_ID, "ci-bot", "CI before")])
            )
        )
        route = router.put(f"{BASE_URL}/api/v1/service-accounts/{SA_ID}").mock(
            return_value=httpx.Response(200, json=_service_account(SA_ID, "ci-bot", "CI now"))
        )

        report = await client.manifest.apply(manifest)
        assert report.is_complete()
        sent = json.loads(route.calls[-1].request.content)
        assert sent == {"description": "CI now"}


# ---------------------------------------------------------------------------
# rebind-role, the user and service-account subject kinds (the group kind
# is already covered above) -- sync and async, happy path and both failure
# shapes.
# ---------------------------------------------------------------------------


def _tenant_with_one_role_user_and_resource(router: respx.MockRouter) -> None:
    router.get(f"{BASE_URL}/api/v1/resources").mock(
        return_value=httpx.Response(
            200, json=_page([_resource(RESOURCE_ID, "documents", "collection", {})])
        )
    )
    router.get(f"{BASE_URL}/api/v1/resources/{RESOURCE_ID}/scopes").mock(
        return_value=httpx.Response(200, json=[])
    )
    for path in ("permissions", "groups", "service-accounts"):
        router.get(f"{BASE_URL}/api/v1/{path}").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
    router.get(f"{BASE_URL}/api/v1/roles").mock(
        return_value=httpx.Response(200, json=_page([_role(ROLE_ID, "Editor", "Edits")]))
    )
    router.get(f"{BASE_URL}/api/v1/users").mock(
        return_value=httpx.Response(
            200, json=_page([_user(USER_ID, "alice", "alice@example.test")])
        )
    )
    for sub in ("permissions", "groups", "service-accounts"):
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/{sub}").mock(
            return_value=httpx.Response(200, json=[])
        )


def _manifest_with_scoped_user_binding(*, inherit: bool | None) -> ManagementManifest:
    kwargs = {} if inherit is None else {"inherit": inherit}
    return ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
        roles=(RoleSpec(key="editor", name="Editor", description="Edits"),),
        users=(
            UserSpec(
                key="alice",
                username="alice",
                email="alice@example.test",
                roles=(ScopedRoleBinding(role="editor", resource="docs", **kwargs),),
            ),
        ),
    )


def test_rebind_of_a_user_binding_succeeds() -> None:
    """The ``user`` subject-kind branch of ``_rebind_role``: a direct user
    binding gets the same unassign-then-assign treatment a group binding
    does."""
    with with_client() as (router, client):
        _tenant_with_one_role_user_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "user": _user(USER_ID, "alice", "alice@example.test"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        unassign_route = router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users/{USER_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users").mock(
            return_value=httpx.Response(204)
        )

        report = client.manifest.apply(_manifest_with_scoped_user_binding(inherit=None))
        assert report.is_complete()
        assert unassign_route.called
        sent = json.loads(assign_route.calls[-1].request.content)
        assert sent["user_id"] == USER_ID
        assert sent["resource_id"] == RESOURCE_ID


def test_a_failed_user_rebind_restores_the_previous_binding() -> None:
    with with_client() as (router, client):
        _tenant_with_one_role_user_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "user": _user(USER_ID, "alice", "alice@example.test"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users/{USER_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(204),
        ]

        report = client.manifest.apply(_manifest_with_scoped_user_binding(inherit=None))
        assert not report.is_complete()
        failure = report.failure()
        assert failure is not None
        assert "restored" in failure.message
        assert assign_route.call_count == 2
        restore_body = json.loads(assign_route.calls[1].request.content)
        assert restore_body["resource_id"] == OTHER_RESOURCE_ID


def _tenant_with_one_role_service_account_and_resource(router: respx.MockRouter) -> None:
    router.get(f"{BASE_URL}/api/v1/resources").mock(
        return_value=httpx.Response(
            200, json=_page([_resource(RESOURCE_ID, "documents", "collection", {})])
        )
    )
    router.get(f"{BASE_URL}/api/v1/resources/{RESOURCE_ID}/scopes").mock(
        return_value=httpx.Response(200, json=[])
    )
    for path in ("permissions", "groups", "users"):
        router.get(f"{BASE_URL}/api/v1/{path}").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
    router.get(f"{BASE_URL}/api/v1/roles").mock(
        return_value=httpx.Response(200, json=_page([_role(ROLE_ID, "Editor", "Edits")]))
    )
    router.get(f"{BASE_URL}/api/v1/service-accounts").mock(
        return_value=httpx.Response(200, json=_page([_service_account(SA_ID, "ci-bot", "CI")]))
    )
    for sub in ("permissions", "groups", "users"):
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/{sub}").mock(
            return_value=httpx.Response(200, json=[])
        )


def _manifest_with_scoped_sa_binding(*, inherit: bool | None) -> ManagementManifest:
    kwargs = {} if inherit is None else {"inherit": inherit}
    return ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
        roles=(RoleSpec(key="editor", name="Editor", description="Edits"),),
        service_accounts=(
            ServiceAccountSpec(
                key="bot",
                name="ci-bot",
                description="CI",
                roles=(ScopedRoleBinding(role="editor", resource="docs", **kwargs),),
            ),
        ),
    )


def test_rebind_of_a_service_account_binding_succeeds() -> None:
    """The ``service_account`` subject-kind branch of ``_rebind_role``."""
    with with_client() as (router, client):
        _tenant_with_one_role_service_account_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "service_account": _service_account(SA_ID, "ci-bot", "CI"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        unassign_route = router.delete(
            f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts/{SA_ID}"
        ).mock(return_value=httpx.Response(204))
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(204)
        )

        report = client.manifest.apply(_manifest_with_scoped_sa_binding(inherit=None))
        assert report.is_complete()
        assert unassign_route.called
        sent = json.loads(assign_route.calls[-1].request.content)
        assert sent["service_account_id"] == SA_ID
        assert sent["resource_id"] == RESOURCE_ID


def test_a_failed_service_account_rebind_restores_the_previous_binding() -> None:
    with with_client() as (router, client):
        _tenant_with_one_role_service_account_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "service_account": _service_account(SA_ID, "ci-bot", "CI"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts/{SA_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(204),
        ]

        report = client.manifest.apply(_manifest_with_scoped_sa_binding(inherit=None))
        assert not report.is_complete()
        failure = report.failure()
        assert failure is not None
        assert "restored" in failure.message
        assert assign_route.call_count == 2


def test_a_group_rebind_that_also_fails_to_restore_reports_it_was_not_restored() -> None:
    """When even the restore attempt fails, the failure message says so
    plainly -- the subject is left holding no such role at all."""
    with with_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(500, json={"error": "internal"}),
        ]

        report = client.manifest.apply(_manifest_with_scoped_binding(inherit=None))
        assert not report.is_complete()
        failure = report.failure()
        assert failure is not None
        assert "NOT restored" in failure.message
        assert assign_route.call_count == 2


async def test_rebind_of_a_group_binding_succeeds_on_the_async_path() -> None:
    async with with_async_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": ["99999999-9999-4999-8999-999999999999"],
                    }
                ],
            )
        )
        unassign_route = router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(204)
        )

        report = await client.manifest.apply(_manifest_with_scoped_binding(inherit=None))
        assert report.is_complete()
        assert unassign_route.called
        sent = json.loads(assign_route.calls[-1].request.content)
        assert sent["resource_id"] == RESOURCE_ID
        assert sent["tenant_scope"] == ["99999999-9999-4999-8999-999999999999"]


async def test_a_failed_rebind_restores_the_previous_binding_on_the_async_path() -> None:
    async with with_async_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(204),
        ]

        report = await client.manifest.apply(_manifest_with_scoped_binding(inherit=None))
        assert not report.is_complete()
        failure = report.failure()
        assert failure is not None
        assert "restored" in failure.message
        assert assign_route.call_count == 2


async def test_apply_stops_after_a_failure_and_marks_a_later_step_not_attempted_async() -> None:
    """§27.6 rule 7 on the async ``_execute``: a step after the failing one
    is reported ``not-attempted``, never silently skipped."""
    manifest = ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
        permissions=(PermissionSpec(key="read", action="document:read", description="Read"),),
    )
    async with with_async_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
        for path in ("permissions", "roles", "groups", "users", "service-accounts"):
            router.get(f"{BASE_URL}/api/v1/{path}").mock(
                return_value=httpx.Response(200, json=EMPTY_PAGE)
            )
        router.post(f"{BASE_URL}/api/v1/resources").mock(
            return_value=httpx.Response(500, json={"error": "internal"})
        )
        create_permission_route = router.post(f"{BASE_URL}/api/v1/permissions")

        report = await client.manifest.apply(manifest)
        assert not report.is_complete()
        statuses = [step.outcome.status for step in report.steps]
        assert "failed" in statuses
        assert "not-attempted" in statuses
        assert create_permission_route.call_count == 0


async def test_rebind_of_a_user_binding_succeeds_on_the_async_path() -> None:
    async with with_async_client() as (router, client):
        _tenant_with_one_role_user_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "user": _user(USER_ID, "alice", "alice@example.test"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        unassign_route = router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users/{USER_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users").mock(
            return_value=httpx.Response(204)
        )

        report = await client.manifest.apply(_manifest_with_scoped_user_binding(inherit=None))
        assert report.is_complete()
        assert unassign_route.called
        sent = json.loads(assign_route.calls[-1].request.content)
        assert sent["user_id"] == USER_ID
        assert sent["resource_id"] == RESOURCE_ID


async def test_a_failed_user_rebind_restores_the_previous_binding_on_the_async_path() -> None:
    async with with_async_client() as (router, client):
        _tenant_with_one_role_user_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "user": _user(USER_ID, "alice", "alice@example.test"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users/{USER_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/users")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(204),
        ]

        report = await client.manifest.apply(_manifest_with_scoped_user_binding(inherit=None))
        assert not report.is_complete()
        failure = report.failure()
        assert failure is not None
        assert "restored" in failure.message
        assert assign_route.call_count == 2


async def test_rebind_of_a_service_account_binding_succeeds_on_the_async_path() -> None:
    async with with_async_client() as (router, client):
        _tenant_with_one_role_service_account_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "service_account": _service_account(SA_ID, "ci-bot", "CI"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        unassign_route = router.delete(
            f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts/{SA_ID}"
        ).mock(return_value=httpx.Response(204))
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(204)
        )

        report = await client.manifest.apply(_manifest_with_scoped_sa_binding(inherit=None))
        assert report.is_complete()
        assert unassign_route.called
        sent = json.loads(assign_route.calls[-1].request.content)
        assert sent["service_account_id"] == SA_ID
        assert sent["resource_id"] == RESOURCE_ID


async def test_a_failed_sa_rebind_restores_the_previous_binding_on_the_async_path() -> None:
    async with with_async_client() as (router, client):
        _tenant_with_one_role_service_account_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "service_account": _service_account(SA_ID, "ci-bot", "CI"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts/{SA_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/service-accounts")
        assign_route.side_effect = [
            httpx.Response(500, json={"error": "internal"}),
            httpx.Response(204),
        ]

        report = await client.manifest.apply(_manifest_with_scoped_sa_binding(inherit=None))
        assert not report.is_complete()
        failure = report.failure()
        assert failure is not None
        assert "restored" in failure.message
        assert assign_route.call_count == 2


# ---------------------------------------------------------------------------
# The global-role + inherit=False refusal (§27.6.1 addition 2's last rule,
# the MAY C-12 question 6 decided client-side, matching the Rust reference),
# and the plain-binding-over-a-scoped-assignment reconciliation (matching
# the Rust reference's a_plain_binding_over_a_scoped_assignment_is_an_update).
# ---------------------------------------------------------------------------


def test_a_global_role_bound_with_inherit_false_is_refused_before_any_request() -> None:
    """The server refuses a global role bound with ``inherit: false`` with a
    400 (a global role ignores resource scope in the first place); this SDK
    checks it client-side, before any request -- like the duplicate-role
    check, not merely before any *write*."""
    manifest = ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
        roles=(RoleSpec(key="editor", name="Editor", description="Edits", is_global=True),),
        groups=(
            GroupSpec(
                key="staff",
                name="Staff",
                description="Everyone",
                roles=(ScopedRoleBinding(role="editor", resource="docs", inherit=False),),
            ),
        ),
    )
    with with_client() as (router, client):
        with pytest.raises(NetworkError, match=r"binds global role 'editor' with inherit=False"):
            client.manifest.plan(manifest)
        assert len(router.calls) == 1, "only the with_client() fixture's own login call"


async def test_a_global_role_bound_with_inherit_false_is_refused_before_any_request_async() -> None:
    manifest = ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
        roles=(RoleSpec(key="editor", name="Editor", description="Edits", is_global=True),),
        groups=(
            GroupSpec(
                key="staff",
                name="Staff",
                description="Everyone",
                roles=(ScopedRoleBinding(role="editor", resource="docs", inherit=False),),
            ),
        ),
    )
    async with with_async_client() as (router, client):
        with pytest.raises(NetworkError, match=r"binds global role 'editor' with inherit=False"):
            await client.manifest.plan(manifest)
        assert len(router.calls) == 1, "only the with_async_client() fixture's own login call"


def test_the_same_global_role_bound_plainly_has_no_such_refusal() -> None:
    """I4 twin: the plain (unscoped) shape names no resource, so it raises
    no inherit=False question at all -- plan() and apply() both proceed."""
    manifest = ManagementManifest(
        roles=(RoleSpec(key="editor", name="Editor", description="Edits", is_global=True),),
        groups=(GroupSpec(key="staff", name="Staff", description="Everyone", roles=("editor",)),),
    )
    with with_client() as (router, client):
        _empty_tenant(router)
        router.post(f"{BASE_URL}/api/v1/roles").mock(
            return_value=httpx.Response(201, json=_role(ROLE_ID, "Editor", "Edits", is_global=True))
        )
        router.post(f"{BASE_URL}/api/v1/groups").mock(
            return_value=httpx.Response(201, json=_group(GROUP_ID, "Staff", "Everyone"))
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(204)
        )

        plan = client.manifest.plan(manifest)
        assert [(a.change, a.target) for a in plan.changes()] == [
            ("create", "role"),
            ("create", "group"),
            ("create", "group-role"),
        ]

        report = client.manifest.apply(manifest)
        assert report.is_complete()
        assert assign_route.called


def test_a_plain_binding_over_a_scoped_assignment_is_an_update() -> None:
    """A manifest's plain (unscoped) binding over a server assignment that
    carries a ``resource_id`` is an ``Update``, not ``NoChange``: the plain
    shape states "no resource", so the next apply unassigns and re-assigns
    it tenant-wide -- mirroring the Rust reference's
    ``a_plain_binding_over_a_scoped_assignment_is_an_update``."""
    manifest = ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
        roles=(RoleSpec(key="editor", name="Editor", description="Edits"),),
        groups=(GroupSpec(key="staff", name="Staff", description="Everyone", roles=("editor",)),),
    )
    with with_client() as (router, client):
        _tenant_with_one_role_group_and_resource(router)
        router.get(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "group": _group(GROUP_ID, "Staff", "Everyone"),
                        "resource_id": OTHER_RESOURCE_ID,
                        "inherit": True,
                        "tenant_scope": None,
                    }
                ],
            )
        )
        unassign_route = router.delete(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )
        assign_route = router.post(f"{BASE_URL}/api/v1/roles/{ROLE_ID}/groups").mock(
            return_value=httpx.Response(204)
        )

        plan = client.manifest.plan(manifest)
        assert [(a.change, a.target) for a in plan.changes()] == [("update", "group-role")]

        report = client.manifest.apply(manifest)
        assert report.is_complete()
        assert unassign_route.called
        sent = json.loads(assign_route.calls[-1].request.content)
        assert set(sent) == {"group_id"}, "the plain shape rebinds with no resource_id at all"
