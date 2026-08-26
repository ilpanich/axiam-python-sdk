"""Reconciling a manifest against a live tenant — CONTRACT.md §27.6.

The split here is deliberate. Everything that *decides* — matching specs against
the tenant's current state, ordering the work, resolving manifest keys to server
ids — is pure and lives in :func:`_compute`, so ``plan`` and ``apply`` cannot
disagree about what would happen: ``apply`` runs exactly the steps ``plan``
reported. Only reading the snapshot and running a step touch the network, and
those are the two things that exist in a sync and an async form.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from axiam_sdk.management import models
from axiam_sdk.management._page import PageRequest
from axiam_sdk.management.manifest._plan import (
    AppliedStep,
    ApplyReport,
    Change,
    ManagementPlan,
    PlannedAction,
    StepOutcome,
    Target,
    topological_order,
    validate,
)
from axiam_sdk.management.manifest._spec import ManagementManifest, ResourceSpec

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk._async_client import AsyncAxiamClient
    from axiam_sdk._client import AxiamClient

__all__ = ["AsyncManifestApi", "ManifestApi"]

PLAN_PAGE = PageRequest(limit=200)
"""How many items a planning read asks for per page."""


@dataclass
class Resolved:
    """Manifest keys resolved to server ids, filled in during planning and applying."""

    resources: dict[str, str] = field(default_factory=dict)
    """Resource key to resource id."""

    scopes: dict[str, str] = field(default_factory=dict)
    """Scope key to scope id."""

    permissions: dict[str, str] = field(default_factory=dict)
    """Permission key to permission id."""

    roles: dict[str, str] = field(default_factory=dict)
    """Role key to role id."""

    groups: dict[str, str] = field(default_factory=dict)
    """Group key to group id."""

    users: dict[str, str] = field(default_factory=dict)
    """User key to user id."""


@dataclass
class Snapshot:
    """The current state a plan is computed against."""

    resources: list[models.Resource] = field(default_factory=list)
    """Every resource in the tenant."""

    scopes: dict[str, list[models.Scope]] = field(default_factory=dict)
    """Scopes, keyed by resource id, for the resources the manifest could match."""

    permissions: list[models.Permission] = field(default_factory=list)
    """Every permission in the tenant."""

    roles: list[models.Role] = field(default_factory=list)
    """Every role in the tenant."""

    groups: list[models.Group] = field(default_factory=list)
    """Every group in the tenant."""

    users: list[models.UserResponse] = field(default_factory=list)
    """Every user in the tenant."""

    role_grants: dict[str, list[str]] = field(default_factory=dict)
    """Granted permission ids, keyed by role id."""

    role_users: dict[str, list[str]] = field(default_factory=dict)
    """Assigned user ids, keyed by role id."""

    role_groups: dict[str, list[str]] = field(default_factory=dict)
    """Assigned group ids, keyed by role id."""

    group_members: dict[str, list[str]] = field(default_factory=dict)
    """Member user ids, keyed by group id."""


@dataclass(frozen=True)
class Step:
    """One executable step, carrying manifest keys rather than ids.

    Ids are deliberately absent: a step that creates a child resource is planned
    before its parent exists, so it can only name the parent by key and resolve
    it when the parent's own step has run.
    """

    kind: str
    """Which operation to run, e.g. ``create-resource``."""

    key: str
    """The manifest key this step acts on."""

    payload: dict[str, Any] = field(default_factory=dict)
    """Everything else the step needs, by name."""


def _compute(
    manifest: ManagementManifest, snapshot: Snapshot, resolved: Resolved
) -> list[tuple[PlannedAction, Step]]:
    """The ordered steps that would reconcile ``manifest``, and what each would do.

    Pure: it reads ``snapshot``, fills ``resolved`` with the ids of things that
    already exist, and returns the work. Nothing here touches the network, which
    is what lets ``plan`` promise it writes nothing.
    """
    out: list[tuple[PlannedAction, Step]] = []

    def push(change: Change, target: Target, key: str, summary: str, step: Step) -> None:
        """Record one planned action and the step that would carry it out."""
        out.append((PlannedAction(change, target, key, summary), step))

    specs = {r.key: r for r in manifest.resources}
    for key in topological_order(manifest):
        spec: ResourceSpec = specs[key]
        parent_pending = spec.parent is not None and spec.parent not in resolved.resources
        parent_id = resolved.resources.get(spec.parent) if spec.parent else None
        # A child whose parent is itself pending cannot already exist, so matching
        # it against a root of the same name would be wrong.
        existing = (
            None
            if parent_pending
            else next(
                (r for r in snapshot.resources if r.name == spec.name and r.parent_id == parent_id),
                None,
            )
        )
        summary = f"resource {spec.name!r} ({spec.resource_type})"
        if existing is not None:
            resolved.resources[key] = existing.id
            if existing.resource_type != spec.resource_type:
                push(
                    "update",
                    "resource",
                    key,
                    summary,
                    Step("update-resource", key, {"resource_type": spec.resource_type}),
                )
            else:
                push("no-change", "resource", key, summary, Step("noop", key))
        else:
            push(
                "create",
                "resource",
                key,
                summary,
                Step(
                    "create-resource",
                    key,
                    {"name": spec.name, "resource_type": spec.resource_type, "parent": spec.parent},
                ),
            )

    for spec in manifest.resources:
        resource_id = resolved.resources.get(spec.key)
        current = snapshot.scopes.get(resource_id, []) if resource_id else []
        for scope in spec.scopes:
            found = next((s for s in current if s.name == scope.name), None)
            summary = f"scope {scope.name!r} under resource {spec.name!r}"
            if found is not None:
                resolved.scopes[scope.key] = found.id
                push("no-change", "scope", scope.key, summary, Step("noop", scope.key))
            else:
                push(
                    "create",
                    "scope",
                    scope.key,
                    summary,
                    Step(
                        "create-scope",
                        scope.key,
                        {
                            "resource": spec.key,
                            "name": scope.name,
                            "description": scope.description,
                        },
                    ),
                )

    for permission in manifest.permissions:
        found_permission = next(
            (p for p in snapshot.permissions if p.action == permission.action), None
        )
        summary = f"permission {permission.action!r}"
        if found_permission is not None:
            resolved.permissions[permission.key] = found_permission.id
            if found_permission.description != permission.description:
                push(
                    "update",
                    "permission",
                    permission.key,
                    summary,
                    Step(
                        "update-permission", permission.key, {"description": permission.description}
                    ),
                )
            else:
                push(
                    "no-change", "permission", permission.key, summary, Step("noop", permission.key)
                )
        else:
            push(
                "create",
                "permission",
                permission.key,
                summary,
                Step(
                    "create-permission",
                    permission.key,
                    {"action": permission.action, "description": permission.description},
                ),
            )

    for role in manifest.roles:
        found_role = next((r for r in snapshot.roles if r.name == role.name), None)
        summary = f"role {role.name!r}"
        if found_role is not None:
            resolved.roles[role.key] = found_role.id
            if found_role.description != role.description or found_role.is_global != role.is_global:
                push(
                    "update",
                    "role",
                    role.key,
                    summary,
                    Step(
                        "update-role",
                        role.key,
                        {"description": role.description, "is_global": role.is_global},
                    ),
                )
            else:
                push("no-change", "role", role.key, summary, Step("noop", role.key))
        else:
            push(
                "create",
                "role",
                role.key,
                summary,
                Step(
                    "create-role",
                    role.key,
                    {
                        "name": role.name,
                        "description": role.description,
                        "is_global": role.is_global,
                    },
                ),
            )

    for role in manifest.roles:
        role_id = resolved.roles.get(role.key)
        granted = snapshot.role_grants.get(role_id, []) if role_id else []
        for grant in role.grants:
            permission_id = resolved.permissions.get(grant.permission)
            summary = f"grant {grant.permission!r} to role {role.name!r}"
            if permission_id is not None and permission_id in granted:
                push("no-change", "role-grant", role.key, summary, Step("noop", role.key))
            else:
                push(
                    "create",
                    "role-grant",
                    role.key,
                    summary,
                    Step(
                        "grant-permission",
                        role.key,
                        {
                            "role": role.key,
                            "permission": grant.permission,
                            "effect": grant.effect,
                            "scopes": list(grant.scopes),
                        },
                    ),
                )

    for group in manifest.groups:
        found_group = next((g for g in snapshot.groups if g.name == group.name), None)
        summary = f"group {group.name!r}"
        if found_group is not None:
            resolved.groups[group.key] = found_group.id
            if found_group.description != group.description:
                push(
                    "update",
                    "group",
                    group.key,
                    summary,
                    Step("update-group", group.key, {"description": group.description}),
                )
            else:
                push("no-change", "group", group.key, summary, Step("noop", group.key))
        else:
            push(
                "create",
                "group",
                group.key,
                summary,
                Step(
                    "create-group",
                    group.key,
                    {"name": group.name, "description": group.description},
                ),
            )

    for group in manifest.groups:
        for role_key in group.roles:
            role_id = resolved.roles.get(role_key)
            group_id = resolved.groups.get(group.key)
            assigned = snapshot.role_groups.get(role_id, []) if role_id else []
            summary = f"role {role_key!r} on group {group.name!r}"
            if group_id is not None and group_id in assigned:
                push("no-change", "group-role", group.key, summary, Step("noop", group.key))
            else:
                push(
                    "create",
                    "group-role",
                    group.key,
                    summary,
                    Step("assign-role-to-group", group.key, {"role": role_key, "group": group.key}),
                )

    for user in manifest.users:
        found_user = next((u for u in snapshot.users if u.username == user.username), None)
        summary = f"user {user.username!r}"
        if found_user is not None:
            resolved.users[user.key] = found_user.id
            if found_user.email != user.email:
                push(
                    "update",
                    "user",
                    user.key,
                    summary,
                    Step("update-user", user.key, {"email": user.email}),
                )
            else:
                push("no-change", "user", user.key, summary, Step("noop", user.key))
        else:
            push(
                "create",
                "user",
                user.key,
                summary,
                Step(
                    "create-user",
                    user.key,
                    {
                        "username": user.username,
                        "email": user.email,
                        "password": user.initial_password,
                    },
                ),
            )

    for user in manifest.users:
        for role_key in user.roles:
            role_id = resolved.roles.get(role_key)
            user_id = resolved.users.get(user.key)
            assigned = snapshot.role_users.get(role_id, []) if role_id else []
            summary = f"role {role_key!r} on user {user.username!r}"
            if user_id is not None and user_id in assigned:
                push("no-change", "user-role", user.key, summary, Step("noop", user.key))
            else:
                push(
                    "create",
                    "user-role",
                    user.key,
                    summary,
                    Step("assign-role-to-user", user.key, {"role": role_key, "user": user.key}),
                )

    for user in manifest.users:
        for group_key in user.groups:
            group_id = resolved.groups.get(group_key)
            user_id = resolved.users.get(user.key)
            members = snapshot.group_members.get(group_id, []) if group_id else []
            summary = f"user {user.username!r} in group {group_key!r}"
            if user_id is not None and user_id in members:
                push("no-change", "group-member", user.key, summary, Step("noop", user.key))
            else:
                push(
                    "create",
                    "group-member",
                    user.key,
                    summary,
                    Step("add-group-member", user.key, {"group": group_key, "user": user.key}),
                )

    return out


def _needs_password(manifest: ManagementManifest, steps: list[tuple[PlannedAction, Step]]) -> None:
    """Refuse before any request when a user must be created with no password.

    §27.6 rule 1: discovering this halfway through an apply leaves the tenant
    part-reconciled, and the fix — supply the password — is one a caller could
    have been told about before anything was written.

    Raises:
        NetworkError: naming every user that would be created without one.
    """
    from axiam_sdk._errors import NetworkError

    missing = [
        step.key
        for _, step in steps
        if step.kind == "create-user" and step.payload.get("password") is None
    ]
    if missing:
        joined = ", ".join(repr(k) for k in missing)
        raise NetworkError(
            f"manifest would create {len(missing)} user(s) with no initial_password: {joined}. "
            f"A user cannot be created without one, and this is refused before any request "
            f"rather than part-way through an apply (§27.6 rule 1)."
        )


def _wanted_scope_resources(manifest: ManagementManifest, snapshot: Snapshot) -> list[str]:
    """Resource ids worth a scope read: only the ones the manifest could match.

    A tenant with a thousand resources should not cost a thousand scope reads to
    plan five.
    """
    names = {r.name for r in manifest.resources}
    return [r.id for r in snapshot.resources if r.name in names]


def _wanted_role_ids(manifest: ManagementManifest, snapshot: Snapshot) -> list[str]:
    """Role ids the manifest names, so binding reads stay proportional to it."""
    names = {r.name for r in manifest.roles}
    return [r.id for r in snapshot.roles if r.name in names]


def _wanted_group_ids(manifest: ManagementManifest, snapshot: Snapshot) -> list[str]:
    """Group ids the manifest names, so membership reads stay proportional to it."""
    names = {g.name for g in manifest.groups}
    return [g.id for g in snapshot.groups if g.name in names]


class ManifestApi:
    """The declarative-management handle, reached as ``client.manifest``."""

    def __init__(self, client: AxiamClient) -> None:
        """Bind the handle to ``client``."""
        self._client = client

    def plan(self, manifest: ManagementManifest) -> ManagementPlan:
        """What reconciling ``manifest`` would do. **Issues no writes.**"""
        validate(manifest)
        snapshot = self._read(manifest)
        steps = _compute(manifest, snapshot, Resolved())
        _needs_password(manifest, steps)
        return ManagementPlan(tuple(action for action, _ in steps))

    def apply(self, manifest: ManagementManifest) -> ApplyReport:
        """Reconcile ``manifest``, stopping at the first failure.

        Re-running after fixing the cause is the recovery path, and is safe:
        applying twice converges (§27.6 rule 6).
        """
        validate(manifest)
        snapshot = self._read(manifest)
        resolved = Resolved()
        steps = _compute(manifest, snapshot, resolved)
        _needs_password(manifest, steps)
        return self._execute(steps, resolved)

    def _read(self, manifest: ManagementManifest) -> Snapshot:
        """Read the tenant state a plan is computed against."""
        c = self._client
        snapshot = Snapshot(
            resources=c.resources.list_all(PLAN_PAGE),
            permissions=c.permissions.list_all(PLAN_PAGE),
            roles=c.roles.list_all(PLAN_PAGE),
            groups=c.groups.list_all(PLAN_PAGE),
            users=c.users.list_all(PLAN_PAGE),
        )
        for resource_id in _wanted_scope_resources(manifest, snapshot):
            snapshot.scopes[resource_id] = c.scopes.list(resource_id)
        for role_id in _wanted_role_ids(manifest, snapshot):
            snapshot.role_grants[role_id] = [
                g.permission.id for g in c.roles.list_permissions(role_id)
            ]
            snapshot.role_users[role_id] = [a.user.id for a in c.roles.list_users(role_id)]
            snapshot.role_groups[role_id] = [a.group.id for a in c.roles.list_groups(role_id)]
        for group_id in _wanted_group_ids(manifest, snapshot):
            snapshot.group_members[group_id] = [
                u.id for u in c.groups.list_members_all(group_id, PLAN_PAGE)
            ]
        return snapshot

    def _execute(self, steps: list[tuple[PlannedAction, Step]], resolved: Resolved) -> ApplyReport:
        """Run every step in order, stopping at the first failure (§27.6 rule 7)."""
        applied: list[AppliedStep] = []
        stopped = False
        for action, step in steps:
            if stopped:
                applied.append(AppliedStep(action, StepOutcome("not-attempted")))
                continue
            if step.kind == "noop":
                applied.append(AppliedStep(action, StepOutcome("unchanged")))
                continue
            try:
                self._run(step, resolved)
            except Exception as err:  # noqa: BLE001 — reported, not swallowed.
                applied.append(AppliedStep(action, StepOutcome("failed", str(err))))
                stopped = True
                continue
            applied.append(
                AppliedStep(
                    action, StepOutcome("updated" if step.kind.startswith("update") else "created")
                )
            )
        return ApplyReport(tuple(applied))

    def _run(self, step: Step, r: Resolved) -> None:
        """Carry out one step, recording any id it mints."""
        c = self._client
        p = step.payload
        if step.kind == "create-resource":
            parent = r.resources.get(p["parent"]) if p["parent"] else None
            created = c.resources.create(
                models.CreateResourceRequest(
                    name=p["name"], resource_type=p["resource_type"], parent_id=parent
                )
            )
            r.resources[step.key] = created.id
        elif step.kind == "update-resource":
            c.resources.update(
                r.resources[step.key],
                models.UpdateResourceRequest(resource_type=p["resource_type"]),
            )
        elif step.kind == "create-scope":
            created_scope = c.scopes.create(
                r.resources[p["resource"]],
                models.CreateScopeRequest(name=p["name"], description=p["description"]),
            )
            r.scopes[step.key] = created_scope.id
        elif step.kind == "create-permission":
            created_permission = c.permissions.create(
                models.CreatePermissionRequest(action=p["action"], description=p["description"])
            )
            r.permissions[step.key] = created_permission.id
        elif step.kind == "update-permission":
            c.permissions.update(
                r.permissions[step.key],
                models.UpdatePermissionRequest(description=p["description"]),
            )
        elif step.kind == "create-role":
            created_role = c.roles.create(
                models.CreateRoleRequest(
                    name=p["name"], description=p["description"], is_global=p["is_global"]
                )
            )
            r.roles[step.key] = created_role.id
        elif step.kind == "update-role":
            c.roles.update(
                r.roles[step.key],
                models.UpdateRole(description=p["description"], is_global=p["is_global"]),
            )
        elif step.kind == "grant-permission":
            c.roles.grant_permission(
                r.roles[p["role"]],
                models.GrantPermissionRequest(
                    permission_id=r.permissions[p["permission"]],
                    effect=p["effect"],
                    scope_ids=[r.scopes[s] for s in p["scopes"]],
                ),
            )
        elif step.kind == "create-group":
            created_group = c.groups.create(
                models.CreateGroupRequest(name=p["name"], description=p["description"])
            )
            r.groups[step.key] = created_group.id
        elif step.kind == "update-group":
            c.groups.update(r.groups[step.key], models.UpdateGroup(description=p["description"]))
        elif step.kind == "assign-role-to-group":
            c.roles.assign_to_group(
                r.roles[p["role"]],
                models.AssignRoleToGroupRequest(group_id=r.groups[p["group"]]),
            )
        elif step.kind == "create-user":
            created_user = c.users.create(
                models.CreateUserRequest(
                    username=p["username"], email=p["email"], password=p["password"]
                )
            )
            r.users[step.key] = created_user.id
        elif step.kind == "update-user":
            c.users.update(r.users[step.key], models.UpdateUserRequest(email=p["email"]))
        elif step.kind == "assign-role-to-user":
            c.roles.assign_to_user(
                r.roles[p["role"]], models.AssignRoleToUserRequest(user_id=r.users[p["user"]])
            )
        elif step.kind == "add-group-member":
            c.groups.add_member(
                r.groups[p["group"]], models.AddMemberRequest(user_id=r.users[p["user"]])
            )
        else:  # pragma: no cover - every kind _compute emits is handled above.
            raise AssertionError(f"unknown manifest step {step.kind!r}")


class AsyncManifestApi:
    """The declarative-management handle for the async client.

    A separate class rather than a shared one with two runners, exactly as
    :class:`~axiam_sdk.AsyncAxiamClient` is separate from
    :class:`~axiam_sdk.AxiamClient`: the deciding half — :func:`_compute`,
    :func:`validate`, the ordering — is shared, and only the I/O is written
    twice.
    """

    def __init__(self, client: AsyncAxiamClient) -> None:
        """Bind the handle to ``client``."""
        self._client = client

    async def plan(self, manifest: ManagementManifest) -> ManagementPlan:
        """What reconciling ``manifest`` would do. **Issues no writes.**"""
        validate(manifest)
        snapshot = await self._read(manifest)
        steps = _compute(manifest, snapshot, Resolved())
        _needs_password(manifest, steps)
        return ManagementPlan(tuple(action for action, _ in steps))

    async def apply(self, manifest: ManagementManifest) -> ApplyReport:
        """Reconcile ``manifest``, stopping at the first failure."""
        validate(manifest)
        snapshot = await self._read(manifest)
        resolved = Resolved()
        steps = _compute(manifest, snapshot, resolved)
        _needs_password(manifest, steps)
        return await self._execute(steps, resolved)

    async def _read(self, manifest: ManagementManifest) -> Snapshot:
        """Read the tenant state a plan is computed against."""
        c = self._client
        snapshot = Snapshot(
            resources=await c.resources.list_all(PLAN_PAGE),
            permissions=await c.permissions.list_all(PLAN_PAGE),
            roles=await c.roles.list_all(PLAN_PAGE),
            groups=await c.groups.list_all(PLAN_PAGE),
            users=await c.users.list_all(PLAN_PAGE),
        )
        for resource_id in _wanted_scope_resources(manifest, snapshot):
            snapshot.scopes[resource_id] = await c.scopes.list(resource_id)
        for role_id in _wanted_role_ids(manifest, snapshot):
            snapshot.role_grants[role_id] = [
                g.permission.id for g in await c.roles.list_permissions(role_id)
            ]
            snapshot.role_users[role_id] = [a.user.id for a in await c.roles.list_users(role_id)]
            snapshot.role_groups[role_id] = [a.group.id for a in await c.roles.list_groups(role_id)]
        for group_id in _wanted_group_ids(manifest, snapshot):
            snapshot.group_members[group_id] = [
                u.id for u in await c.groups.list_members_all(group_id, PLAN_PAGE)
            ]
        return snapshot

    async def _execute(
        self, steps: list[tuple[PlannedAction, Step]], resolved: Resolved
    ) -> ApplyReport:
        """Run every step in order, stopping at the first failure (§27.6 rule 7)."""
        applied: list[AppliedStep] = []
        stopped = False
        for action, step in steps:
            if stopped:
                applied.append(AppliedStep(action, StepOutcome("not-attempted")))
                continue
            if step.kind == "noop":
                applied.append(AppliedStep(action, StepOutcome("unchanged")))
                continue
            try:
                await self._run(step, resolved)
            except Exception as err:  # noqa: BLE001 — reported, not swallowed.
                applied.append(AppliedStep(action, StepOutcome("failed", str(err))))
                stopped = True
                continue
            applied.append(
                AppliedStep(
                    action, StepOutcome("updated" if step.kind.startswith("update") else "created")
                )
            )
        return ApplyReport(tuple(applied))

    async def _run(self, step: Step, r: Resolved) -> None:
        """Carry out one step, recording any id it mints."""
        c = self._client
        p = step.payload
        if step.kind == "create-resource":
            parent = r.resources.get(p["parent"]) if p["parent"] else None
            created = await c.resources.create(
                models.CreateResourceRequest(
                    name=p["name"], resource_type=p["resource_type"], parent_id=parent
                )
            )
            r.resources[step.key] = created.id
        elif step.kind == "update-resource":
            await c.resources.update(
                r.resources[step.key],
                models.UpdateResourceRequest(resource_type=p["resource_type"]),
            )
        elif step.kind == "create-scope":
            created_scope = await c.scopes.create(
                r.resources[p["resource"]],
                models.CreateScopeRequest(name=p["name"], description=p["description"]),
            )
            r.scopes[step.key] = created_scope.id
        elif step.kind == "create-permission":
            created_permission = await c.permissions.create(
                models.CreatePermissionRequest(action=p["action"], description=p["description"])
            )
            r.permissions[step.key] = created_permission.id
        elif step.kind == "update-permission":
            await c.permissions.update(
                r.permissions[step.key],
                models.UpdatePermissionRequest(description=p["description"]),
            )
        elif step.kind == "create-role":
            created_role = await c.roles.create(
                models.CreateRoleRequest(
                    name=p["name"], description=p["description"], is_global=p["is_global"]
                )
            )
            r.roles[step.key] = created_role.id
        elif step.kind == "update-role":
            await c.roles.update(
                r.roles[step.key],
                models.UpdateRole(description=p["description"], is_global=p["is_global"]),
            )
        elif step.kind == "grant-permission":
            await c.roles.grant_permission(
                r.roles[p["role"]],
                models.GrantPermissionRequest(
                    permission_id=r.permissions[p["permission"]],
                    effect=p["effect"],
                    scope_ids=[r.scopes[s] for s in p["scopes"]],
                ),
            )
        elif step.kind == "create-group":
            created_group = await c.groups.create(
                models.CreateGroupRequest(name=p["name"], description=p["description"])
            )
            r.groups[step.key] = created_group.id
        elif step.kind == "update-group":
            await c.groups.update(
                r.groups[step.key], models.UpdateGroup(description=p["description"])
            )
        elif step.kind == "assign-role-to-group":
            await c.roles.assign_to_group(
                r.roles[p["role"]],
                models.AssignRoleToGroupRequest(group_id=r.groups[p["group"]]),
            )
        elif step.kind == "create-user":
            created_user = await c.users.create(
                models.CreateUserRequest(
                    username=p["username"], email=p["email"], password=p["password"]
                )
            )
            r.users[step.key] = created_user.id
        elif step.kind == "update-user":
            await c.users.update(r.users[step.key], models.UpdateUserRequest(email=p["email"]))
        elif step.kind == "assign-role-to-user":
            await c.roles.assign_to_user(
                r.roles[p["role"]], models.AssignRoleToUserRequest(user_id=r.users[p["user"]])
            )
        elif step.kind == "add-group-member":
            await c.groups.add_member(
                r.groups[p["group"]], models.AddMemberRequest(user_id=r.users[p["user"]])
            )
        else:  # pragma: no cover - every kind _compute emits is handled above.
            raise AssertionError(f"unknown manifest step {step.kind!r}")
