"""Reconciling a manifest against a live tenant — CONTRACT.md §27.6, §27.6.1.

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

from pydantic import SecretStr

from axiam_sdk._errors import NetworkError
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
    resource_key,
    role_key,
    topological_order,
    validate,
)
from axiam_sdk.management.manifest._spec import (
    ManagementManifest,
    ResourceSpec,
    RoleBinding,
    ScopedRoleBinding,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk._async_client import AsyncAxiamClient
    from axiam_sdk._client import AxiamClient

__all__ = ["AsyncManifestApi", "ManifestApi"]

PLAN_PAGE = PageRequest(limit=200)
"""How many items a planning read asks for per page."""


class _RebindFailed(NetworkError):
    """Raised by ``_rebind_role`` when the new assign fails after the old
    binding has already been unassigned. Carries the restore attempt's
    outcome as structured attributes — not only inside the message string —
    so ``_execute`` can put ``restore_succeeded``/``restore_error`` on the
    ``StepOutcome`` (CONTRACT §27.6.1: "report both outcomes")."""

    def __init__(self, message: str, *, restore_succeeded: bool, restore_error: str | None) -> None:
        """Build the exception with ``message`` plus the restore attempt's
        own outcome, exposed as :attr:`restore_succeeded`/
        :attr:`restore_error` for :func:`_failed_outcome` to read."""
        super().__init__(message)
        self.restore_succeeded = restore_succeeded
        self.restore_error = restore_error


def _failed_outcome(err: Exception) -> StepOutcome:
    """The ``StepOutcome`` for a step that raised ``err``. A
    :class:`_RebindFailed` additionally carries its restore attempt's
    outcome as structured fields (§27.6.1); every other failure leaves them
    ``None``, as before."""
    if isinstance(err, _RebindFailed):
        return StepOutcome(
            "failed",
            str(err),
            restore_succeeded=err.restore_succeeded,
            restore_error=err.restore_error,
        )
    return StepOutcome("failed", str(err))


_SUBJECT_KINDS = ("group", "user", "service_account")
"""The three kinds of subject a :data:`RoleBinding` can bind a role to."""


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

    service_accounts: dict[str, str] = field(default_factory=dict)
    """Service account key to service account id (CONTRACT §27.6.1
    addition 3, contract 1.51)."""


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

    service_accounts: list[models.ServiceAccountResponse] = field(default_factory=list)
    """Every service account in the tenant (CONTRACT §27.6.1 addition 3,
    contract 1.51) — read in full, not filtered by the manifest's names, so
    an ambiguous ``name`` (the server enforces no uniqueness on it) can be
    detected before any write."""

    role_grants: dict[str, list[str]] = field(default_factory=dict)
    """Granted permission ids, keyed by role id."""

    role_user_bindings: dict[str, list[models.RoleUserAssignment]] = field(default_factory=dict)
    """The full role-side user-assignment listing, keyed by role id — not
    just ids: reconciling ``resource_id``/``inherit``/``tenant_scope``
    (CONTRACT §27.6.1 addition 2) needs the whole assignment."""

    role_group_bindings: dict[str, list[models.RoleGroupAssignment]] = field(default_factory=dict)
    """As :attr:`role_user_bindings`, for groups."""

    role_service_account_bindings: dict[str, list[models.RoleServiceAccountAssignment]] = field(
        default_factory=dict
    )
    """As :attr:`role_user_bindings`, for service accounts (CONTRACT
    §27.6.1 addition 3)."""

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


def _metadata_differs(existing: Any, stated: dict[str, Any] | None) -> bool:
    """Whether an ``Update`` must carry ``metadata`` (CONTRACT §27.6.1
    addition 1): ``stated is None`` means the spec is silent, never a
    request to clear it (rule 3). Otherwise it is JSON equality of the
    *whole* object against the server's value — never a key-by-key merge,
    or ``apply`` could never remove a key."""
    return stated is not None and stated != existing


def _inherit_wire(inherit: bool) -> bool | None:
    """CONTRACT §27.6.1 addition 2 rule: ``inherit`` reaches the wire only
    as ``False`` — an inheritable binding's body stays byte-for-byte a
    pre-1.51 body."""
    return False if not inherit else None


def _binding_resource_and_inherit(
    binding: RoleBinding, resolved: Resolved
) -> tuple[str | None, bool]:
    """The resolved resource id (or ``None``) and the stated ``inherit`` a
    :data:`RoleBinding` names — the shape both the plan comparison and the
    wire-request builders need."""
    if isinstance(binding, ScopedRoleBinding):
        return resolved.resources.get(binding.resource), binding.inherit
    return None, True


def _existing_binding(bindings: list[Any], subject_id: str | None, attr: str) -> Any | None:
    """The one existing assignment naming ``subject_id`` on ``attr`` (e.g.
    ``"group"``/``"user"``/``"service_account"``), or ``None``. At most one
    can exist: the server keys assignments on ``(subject, role)`` with no
    resource component (``has_role`` is ``UNIQUE(in, out)``)."""
    if subject_id is None:
        return None
    for assignment in bindings:
        subject = getattr(assignment, attr)
        if subject.id == subject_id:
            return assignment
    return None


def _plan_role_binding(
    push: Any,
    subject_kind: str,
    subject_key: str,
    subject_id: str | None,
    subject_name: str,
    binding: RoleBinding,
    resolved: Resolved,
    existing_bindings: list[Any],
    subject_attr: str,
    target: Target,
) -> None:
    """The reconciliation :func:`_compute` shares for a group/user/service-
    account's one role binding (CONTRACT §27.6.1 addition 2, contract 1.51).

    The natural key is ``(subject, role)``; the resource and ``inherit`` are
    fields on it. ``NoChange`` when the server's assignment of that role
    names the same resource (``None`` for the plain shape) and the same
    ``inherit``; ``Update`` (an unassign-then-assign, with restore on
    failure — carried out by the ``rebind-role`` step) otherwise; ``Create``
    (``assign-role-to-<kind>``) when no such assignment exists yet — which
    is also the case while the subject or the role is itself still pending
    creation earlier in this same ``apply``.
    """
    rk = role_key(binding)
    role_id = resolved.roles.get(rk)
    resource_k = resource_key(binding)
    stated_resource_id, stated_inherit = _binding_resource_and_inherit(binding, resolved)
    summary = f"role {rk!r} on {subject_kind} {subject_name!r}"

    existing = (
        _existing_binding(existing_bindings, subject_id, subject_attr)
        if role_id is not None
        else None
    )

    if existing is None:
        push(
            "create",
            target,
            subject_key,
            summary,
            Step(
                f"assign-role-to-{subject_kind}",
                subject_key,
                {
                    "role": rk,
                    "subject": subject_key,
                    "resource": resource_k,
                    "inherit": stated_inherit,
                },
            ),
        )
        return

    if existing.resource_id == stated_resource_id and existing.inherit == stated_inherit:
        push("no-change", target, subject_key, summary, Step("noop", subject_key))
        return

    push(
        "update",
        target,
        subject_key,
        summary,
        Step(
            "rebind-role",
            subject_key,
            {
                "subject_kind": subject_kind,
                "role": rk,
                "subject": subject_key,
                "resource": resource_k,
                "inherit": stated_inherit,
                "previous_resource_id": existing.resource_id,
                "previous_inherit": existing.inherit,
                "tenant_scope": existing.tenant_scope,
            },
        ),
    )


def _compute(
    manifest: ManagementManifest, snapshot: Snapshot, resolved: Resolved
) -> list[tuple[PlannedAction, Step]]:
    """The ordered steps that would reconcile ``manifest``, and what each would do.

    Pure: it reads ``snapshot``, fills ``resolved`` with the ids of things that
    already exist, and returns the work. Nothing here touches the network, which
    is what lets ``plan`` promise it writes nothing.

    Ordering (CONTRACT §27.6 rule 5, extended by §27.6.1 for contract 1.51):
    resources -> scopes -> permissions -> roles -> role/permission grants ->
    groups -> group/role bindings -> users -> user/role bindings ->
    service accounts -> service-account/role bindings -> (group members,
    this SDK's own extra step, last).
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
            update_fields: dict[str, Any] = {}
            if existing.resource_type != spec.resource_type:
                update_fields["resource_type"] = spec.resource_type
            if _metadata_differs(existing.metadata, spec.metadata):
                update_fields["metadata"] = spec.metadata
            if update_fields:
                push(
                    "update",
                    "resource",
                    key,
                    summary,
                    Step("update-resource", key, update_fields),
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
                    {
                        "name": spec.name,
                        "resource_type": spec.resource_type,
                        "parent": spec.parent,
                        "metadata": spec.metadata,
                    },
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
        group_id = resolved.groups.get(group.key)
        for binding in group.roles:
            role_id = resolved.roles.get(role_key(binding))
            group_bindings: list[Any] = (
                snapshot.role_group_bindings.get(role_id, []) if role_id else []
            )
            _plan_role_binding(
                push,
                "group",
                group.key,
                group_id,
                group.name,
                binding,
                resolved,
                group_bindings,
                "group",
                "group-role",
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
        user_id = resolved.users.get(user.key)
        for binding in user.roles:
            role_id = resolved.roles.get(role_key(binding))
            user_bindings: list[Any] = (
                snapshot.role_user_bindings.get(role_id, []) if role_id else []
            )
            _plan_role_binding(
                push,
                "user",
                user.key,
                user_id,
                user.username,
                binding,
                resolved,
                user_bindings,
                "user",
                "user-role",
            )

    for service_account in manifest.service_accounts:
        matches = [s for s in snapshot.service_accounts if s.name == service_account.name]
        summary = f"service account {service_account.name!r}"
        if len(matches) == 1:
            found_sa = matches[0]
            resolved.service_accounts[service_account.key] = found_sa.id
            if found_sa.description != service_account.description:
                push(
                    "update",
                    "service-account",
                    service_account.key,
                    summary,
                    Step(
                        "update-service-account",
                        service_account.key,
                        {"description": service_account.description},
                    ),
                )
            else:
                push(
                    "no-change",
                    "service-account",
                    service_account.key,
                    summary,
                    Step("noop", service_account.key),
                )
        elif len(matches) == 0:
            push(
                "create",
                "service-account",
                service_account.key,
                summary,
                Step(
                    "create-service-account",
                    service_account.key,
                    {"name": service_account.name, "description": service_account.description},
                ),
            )
        # len(matches) > 1 is an ambiguous name — _no_ambiguous_service_accounts
        # rejects the manifest before any step here runs, so this branch is
        # unreachable by the time steps are ever executed.

    for service_account in manifest.service_accounts:
        service_account_id = resolved.service_accounts.get(service_account.key)
        for binding in service_account.roles:
            role_id = resolved.roles.get(role_key(binding))
            sa_bindings: list[Any] = (
                snapshot.role_service_account_bindings.get(role_id, []) if role_id else []
            )
            _plan_role_binding(
                push,
                "service_account",
                service_account.key,
                service_account_id,
                service_account.name,
                binding,
                resolved,
                sa_bindings,
                "service_account",
                "service-account-role",
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


def _no_ambiguous_service_accounts(manifest: ManagementManifest, snapshot: Snapshot) -> None:
    """Refuse before any request when a manifest's ``service_accounts[].name``
    matches more than one existing account (CONTRACT §27.6.1 addition 3,
    contract 1.51): the server enforces uniqueness only on ``client_id``, so
    picking one of several same-named accounts would reconcile an arbitrary
    one.

    Raises:
        NetworkError: naming every ambiguous ``service_accounts`` spec.
    """
    problems = []
    for spec in manifest.service_accounts:
        matches = [s for s in snapshot.service_accounts if s.name == spec.name]
        if len(matches) > 1:
            problems.append(
                f"service account {spec.key!r} names {spec.name!r}, which matches "
                f"{len(matches)} existing accounts — only client_id is unique, so plan "
                f"cannot pick one (CONTRACT §27.6.1 addition 3)"
            )
    if problems:
        raise NetworkError(
            f"manifest is not reconcilable ({len(problems)} problem(s)): " + "; ".join(problems)
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


def _status_of(step: Step) -> str:
    """``created``/``updated``/``unchanged``, from the step's own kind."""
    if step.kind.startswith("update") or step.kind == "rebind-role":
        return "updated"
    return "created"


def _resource_step_id(resolved: Resolved, key: str | None) -> str | None:
    """A resource id resolved from a step payload's manifest key, or
    ``None`` for the plain (no-resource) binding shape."""
    return resolved.resources[key] if key else None


def _assign_kwargs(
    id_field: str,
    subject_id: str,
    resource_id: str | None,
    inherit_wire: bool | None,
    tenant_scope: list[str] | None,
) -> dict[str, Any]:
    """The kwargs for an ``AssignRoleTo*Request``, omitting ``resource_id``/
    ``inherit``/``tenant_scope`` entirely when they are ``None`` rather than
    passing them explicitly.

    Pydantic's ``model_fields_set`` (what ``to_wire()``'s ``exclude_unset``
    reads) marks a field "set" the moment the constructor receives it as a
    kwarg — even as ``None`` — so passing ``resource_id=None`` here would
    still serialize ``"resource_id": null`` on the wire. A plain (no-
    resource) binding's assign request must stay byte-for-byte what it was
    before contract 1.51 (§27.6.1 addition 2 rule 1), which means these
    three keys must be ABSENT from the kwargs entirely, not merely ``None``
    valued.
    """
    kwargs: dict[str, Any] = {id_field: subject_id}
    if resource_id is not None:
        kwargs["resource_id"] = resource_id
    if inherit_wire is not None:
        kwargs["inherit"] = inherit_wire
    if tenant_scope is not None:
        kwargs["tenant_scope"] = tenant_scope
    return kwargs


def _create_resource_request(p: dict[str, Any], parent: str | None) -> models.CreateResourceRequest:
    """Build a ``CreateResourceRequest`` that OMITS ``metadata`` when the
    spec never stated one, rather than sending it explicitly as ``null``
    (CONTRACT §27.6.1 addition 1: "omitted means silent, as for any other
    field" — ``to_wire()``'s ``exclude_unset`` only omits a field the
    constructor was never given, so a bare ``metadata=None`` kwarg would
    still serialize as ``"metadata": null``)."""
    kwargs: dict[str, Any] = {
        "name": p["name"],
        "resource_type": p["resource_type"],
        "parent_id": parent,
    }
    if p["metadata"] is not None:
        kwargs["metadata"] = p["metadata"]
    return models.CreateResourceRequest(**kwargs)


class ManifestApi:
    """The declarative-management handle, reached as ``client.manifest``."""

    def __init__(self, client: AxiamClient) -> None:
        """Bind the handle to ``client``."""
        self._client = client

    def plan(self, manifest: ManagementManifest) -> ManagementPlan:
        """What reconciling ``manifest`` would do. **Issues no writes.**"""
        validate(manifest)
        snapshot = self._read(manifest)
        _no_ambiguous_service_accounts(manifest, snapshot)
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
        _no_ambiguous_service_accounts(manifest, snapshot)
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
            service_accounts=c.service_accounts.list_all(PLAN_PAGE),
        )
        for resource_id in _wanted_scope_resources(manifest, snapshot):
            snapshot.scopes[resource_id] = c.scopes.list(resource_id)
        for role_id in _wanted_role_ids(manifest, snapshot):
            snapshot.role_grants[role_id] = [
                g.permission.id for g in c.roles.list_permissions(role_id)
            ]
            snapshot.role_user_bindings[role_id] = c.roles.list_users(role_id)
            snapshot.role_group_bindings[role_id] = c.roles.list_groups(role_id)
            snapshot.role_service_account_bindings[role_id] = c.roles.list_service_accounts(role_id)
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
                secret = self._run(step, resolved)
            except Exception as err:  # noqa: BLE001 — reported, not swallowed.
                applied.append(AppliedStep(action, _failed_outcome(err)))
                stopped = True
                continue
            applied.append(
                AppliedStep(action, StepOutcome(_status_of(step), client_secret=secret))  # type: ignore[arg-type]
            )
        return ApplyReport(tuple(applied))

    def _run(self, step: Step, r: Resolved) -> SecretStr | None:
        """Carry out one step, recording any id it mints. Returns the
        one-time ``client_secret`` for a ``create-service-account`` step,
        ``None`` for every other kind (§27.5 rule 5)."""
        c = self._client
        p = step.payload
        if step.kind == "create-resource":
            parent = r.resources.get(p["parent"]) if p["parent"] else None
            created = c.resources.create(_create_resource_request(p, parent))
            r.resources[step.key] = created.id
        elif step.kind == "update-resource":
            c.resources.update(r.resources[step.key], models.UpdateResourceRequest(**p))
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
        elif step.kind == "create-user":
            created_user = c.users.create(
                models.CreateUserRequest(
                    username=p["username"], email=p["email"], password=p["password"]
                )
            )
            r.users[step.key] = created_user.id
        elif step.kind == "update-user":
            c.users.update(r.users[step.key], models.UpdateUserRequest(email=p["email"]))
        elif step.kind == "create-service-account":
            created_sa = c.service_accounts.create(
                models.CreateServiceAccountRequest(name=p["name"], description=p["description"])
            )
            r.service_accounts[step.key] = created_sa.id
            return created_sa.client_secret
        elif step.kind == "update-service-account":
            c.service_accounts.update(
                r.service_accounts[step.key],
                models.UpdateServiceAccount(description=p["description"]),
            )
        elif step.kind == "assign-role-to-group":
            c.roles.assign_to_group(
                r.roles[p["role"]],
                models.AssignRoleToGroupRequest(
                    **_assign_kwargs(
                        "group_id",
                        r.groups[p["subject"]],
                        _resource_step_id(r, p["resource"]),
                        _inherit_wire(p["inherit"]),
                        None,
                    )
                ),
            )
        elif step.kind == "assign-role-to-user":
            c.roles.assign_to_user(
                r.roles[p["role"]],
                models.AssignRoleToUserRequest(
                    **_assign_kwargs(
                        "user_id",
                        r.users[p["subject"]],
                        _resource_step_id(r, p["resource"]),
                        _inherit_wire(p["inherit"]),
                        None,
                    )
                ),
            )
        elif step.kind == "assign-role-to-service_account":
            c.roles.assign_to_service_account(
                r.roles[p["role"]],
                models.AssignRoleToServiceAccountRequest(
                    **_assign_kwargs(
                        "service_account_id",
                        r.service_accounts[p["subject"]],
                        _resource_step_id(r, p["resource"]),
                        _inherit_wire(p["inherit"]),
                        None,
                    )
                ),
            )
        elif step.kind == "rebind-role":
            self._rebind_role(p, r)
        elif step.kind == "add-group-member":
            c.groups.add_member(
                r.groups[p["group"]], models.AddMemberRequest(user_id=r.users[p["user"]])
            )
        else:  # pragma: no cover - every kind _compute emits is handled above.
            raise AssertionError(f"unknown manifest step {step.kind!r}")
        return None

    def _rebind_role(self, p: dict[str, Any], r: Resolved) -> None:
        """``rebind-role``: unassign, then assign the new shape — CONTRACT
        §27.6.1's "there is no update endpoint" rule. If the assign fails,
        re-assign the previous binding (same resource, same ``inherit``) and
        report both outcomes; ``tenant_scope`` is carried across unchanged
        either way, so a re-assignment never silently widens an
        organization-level account's reach (§5.2.3)."""
        c = self._client
        subject_kind = p["subject_kind"]
        role_id = r.roles[p["role"]]
        new_resource_id = _resource_step_id(r, p["resource"])
        new_inherit_wire = _inherit_wire(p["inherit"])
        previous_resource_id = p["previous_resource_id"]
        previous_inherit_wire = _inherit_wire(p["previous_inherit"])
        tenant_scope = p["tenant_scope"]

        # Three explicit branches rather than a dispatch table: each subject
        # kind's assign request is a genuinely different type
        # (AssignRoleToGroupRequest / ...ToUserRequest /
        # ...ToServiceAccountRequest), so there is no single callable shape
        # to look up generically without losing static typing.
        assign_err: Exception | None = None
        restore_err: Exception | None = None
        restored = False
        if subject_kind == "group":
            group_id = r.groups[p["subject"]]
            c.roles.unassign_from_group(role_id, group_id, previous_resource_id)
            try:
                c.roles.assign_to_group(
                    role_id,
                    models.AssignRoleToGroupRequest(
                        **_assign_kwargs(
                            "group_id", group_id, new_resource_id, new_inherit_wire, tenant_scope
                        )
                    ),
                )
            except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                assign_err = err
                try:
                    c.roles.assign_to_group(
                        role_id,
                        models.AssignRoleToGroupRequest(
                            **_assign_kwargs(
                                "group_id",
                                group_id,
                                previous_resource_id,
                                previous_inherit_wire,
                                tenant_scope,
                            )
                        ),
                    )
                    restored = True
                except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                    restored = False
                    restore_err = err
        elif subject_kind == "user":
            user_id = r.users[p["subject"]]
            c.roles.unassign_from_user(role_id, user_id, previous_resource_id)
            try:
                c.roles.assign_to_user(
                    role_id,
                    models.AssignRoleToUserRequest(
                        **_assign_kwargs(
                            "user_id", user_id, new_resource_id, new_inherit_wire, tenant_scope
                        )
                    ),
                )
            except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                assign_err = err
                try:
                    c.roles.assign_to_user(
                        role_id,
                        models.AssignRoleToUserRequest(
                            **_assign_kwargs(
                                "user_id",
                                user_id,
                                previous_resource_id,
                                previous_inherit_wire,
                                tenant_scope,
                            )
                        ),
                    )
                    restored = True
                except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                    restored = False
                    restore_err = err
        else:
            service_account_id = r.service_accounts[p["subject"]]
            c.roles.unassign_from_service_account(role_id, service_account_id, previous_resource_id)
            try:
                c.roles.assign_to_service_account(
                    role_id,
                    models.AssignRoleToServiceAccountRequest(
                        **_assign_kwargs(
                            "service_account_id",
                            service_account_id,
                            new_resource_id,
                            new_inherit_wire,
                            tenant_scope,
                        )
                    ),
                )
            except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                assign_err = err
                try:
                    c.roles.assign_to_service_account(
                        role_id,
                        models.AssignRoleToServiceAccountRequest(
                            **_assign_kwargs(
                                "service_account_id",
                                service_account_id,
                                previous_resource_id,
                                previous_inherit_wire,
                                tenant_scope,
                            )
                        ),
                    )
                    restored = True
                except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                    restored = False
                    restore_err = err

        if assign_err is not None:
            restored_word = (
                "restored" if restored else "NOT restored — the subject now holds no such role"
            )
            raise _RebindFailed(
                f"rebinding role failed: {assign_err}; the previous binding was {restored_word}",
                restore_succeeded=restored,
                restore_error=None if restored else str(restore_err),
            ) from assign_err


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
        _no_ambiguous_service_accounts(manifest, snapshot)
        steps = _compute(manifest, snapshot, Resolved())
        _needs_password(manifest, steps)
        return ManagementPlan(tuple(action for action, _ in steps))

    async def apply(self, manifest: ManagementManifest) -> ApplyReport:
        """Reconcile ``manifest``, stopping at the first failure."""
        validate(manifest)
        snapshot = await self._read(manifest)
        _no_ambiguous_service_accounts(manifest, snapshot)
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
            service_accounts=await c.service_accounts.list_all(PLAN_PAGE),
        )
        for resource_id in _wanted_scope_resources(manifest, snapshot):
            snapshot.scopes[resource_id] = await c.scopes.list(resource_id)
        for role_id in _wanted_role_ids(manifest, snapshot):
            snapshot.role_grants[role_id] = [
                g.permission.id for g in await c.roles.list_permissions(role_id)
            ]
            snapshot.role_user_bindings[role_id] = await c.roles.list_users(role_id)
            snapshot.role_group_bindings[role_id] = await c.roles.list_groups(role_id)
            snapshot.role_service_account_bindings[role_id] = await c.roles.list_service_accounts(
                role_id
            )
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
                secret = await self._run(step, resolved)
            except Exception as err:  # noqa: BLE001 — reported, not swallowed.
                applied.append(AppliedStep(action, _failed_outcome(err)))
                stopped = True
                continue
            applied.append(
                AppliedStep(action, StepOutcome(_status_of(step), client_secret=secret))  # type: ignore[arg-type]
            )
        return ApplyReport(tuple(applied))

    async def _run(self, step: Step, r: Resolved) -> SecretStr | None:
        """Carry out one step, recording any id it mints. Returns the
        one-time ``client_secret`` for a ``create-service-account`` step,
        ``None`` for every other kind (§27.5 rule 5)."""
        c = self._client
        p = step.payload
        if step.kind == "create-resource":
            parent = r.resources.get(p["parent"]) if p["parent"] else None
            created = await c.resources.create(_create_resource_request(p, parent))
            r.resources[step.key] = created.id
        elif step.kind == "update-resource":
            await c.resources.update(r.resources[step.key], models.UpdateResourceRequest(**p))
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
        elif step.kind == "create-user":
            created_user = await c.users.create(
                models.CreateUserRequest(
                    username=p["username"], email=p["email"], password=p["password"]
                )
            )
            r.users[step.key] = created_user.id
        elif step.kind == "update-user":
            await c.users.update(r.users[step.key], models.UpdateUserRequest(email=p["email"]))
        elif step.kind == "create-service-account":
            created_sa = await c.service_accounts.create(
                models.CreateServiceAccountRequest(name=p["name"], description=p["description"])
            )
            r.service_accounts[step.key] = created_sa.id
            return created_sa.client_secret
        elif step.kind == "update-service-account":
            await c.service_accounts.update(
                r.service_accounts[step.key],
                models.UpdateServiceAccount(description=p["description"]),
            )
        elif step.kind == "assign-role-to-group":
            await c.roles.assign_to_group(
                r.roles[p["role"]],
                models.AssignRoleToGroupRequest(
                    **_assign_kwargs(
                        "group_id",
                        r.groups[p["subject"]],
                        _resource_step_id(r, p["resource"]),
                        _inherit_wire(p["inherit"]),
                        None,
                    )
                ),
            )
        elif step.kind == "assign-role-to-user":
            await c.roles.assign_to_user(
                r.roles[p["role"]],
                models.AssignRoleToUserRequest(
                    **_assign_kwargs(
                        "user_id",
                        r.users[p["subject"]],
                        _resource_step_id(r, p["resource"]),
                        _inherit_wire(p["inherit"]),
                        None,
                    )
                ),
            )
        elif step.kind == "assign-role-to-service_account":
            await c.roles.assign_to_service_account(
                r.roles[p["role"]],
                models.AssignRoleToServiceAccountRequest(
                    **_assign_kwargs(
                        "service_account_id",
                        r.service_accounts[p["subject"]],
                        _resource_step_id(r, p["resource"]),
                        _inherit_wire(p["inherit"]),
                        None,
                    )
                ),
            )
        elif step.kind == "rebind-role":
            await self._rebind_role(p, r)
        elif step.kind == "add-group-member":
            await c.groups.add_member(
                r.groups[p["group"]], models.AddMemberRequest(user_id=r.users[p["user"]])
            )
        else:  # pragma: no cover - every kind _compute emits is handled above.
            raise AssertionError(f"unknown manifest step {step.kind!r}")
        return None

    async def _rebind_role(self, p: dict[str, Any], r: Resolved) -> None:
        """Async twin of :meth:`ManifestApi._rebind_role`."""
        c = self._client
        subject_kind = p["subject_kind"]
        role_id = r.roles[p["role"]]
        new_resource_id = _resource_step_id(r, p["resource"])
        new_inherit_wire = _inherit_wire(p["inherit"])
        previous_resource_id = p["previous_resource_id"]
        previous_inherit_wire = _inherit_wire(p["previous_inherit"])
        tenant_scope = p["tenant_scope"]

        assign_err: Exception | None = None
        restore_err: Exception | None = None
        restored = False
        if subject_kind == "group":
            group_id = r.groups[p["subject"]]
            await c.roles.unassign_from_group(role_id, group_id, previous_resource_id)
            try:
                await c.roles.assign_to_group(
                    role_id,
                    models.AssignRoleToGroupRequest(
                        **_assign_kwargs(
                            "group_id", group_id, new_resource_id, new_inherit_wire, tenant_scope
                        )
                    ),
                )
            except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                assign_err = err
                try:
                    await c.roles.assign_to_group(
                        role_id,
                        models.AssignRoleToGroupRequest(
                            **_assign_kwargs(
                                "group_id",
                                group_id,
                                previous_resource_id,
                                previous_inherit_wire,
                                tenant_scope,
                            )
                        ),
                    )
                    restored = True
                except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                    restored = False
                    restore_err = err
        elif subject_kind == "user":
            user_id = r.users[p["subject"]]
            await c.roles.unassign_from_user(role_id, user_id, previous_resource_id)
            try:
                await c.roles.assign_to_user(
                    role_id,
                    models.AssignRoleToUserRequest(
                        **_assign_kwargs(
                            "user_id", user_id, new_resource_id, new_inherit_wire, tenant_scope
                        )
                    ),
                )
            except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                assign_err = err
                try:
                    await c.roles.assign_to_user(
                        role_id,
                        models.AssignRoleToUserRequest(
                            **_assign_kwargs(
                                "user_id",
                                user_id,
                                previous_resource_id,
                                previous_inherit_wire,
                                tenant_scope,
                            )
                        ),
                    )
                    restored = True
                except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                    restored = False
                    restore_err = err
        else:
            service_account_id = r.service_accounts[p["subject"]]
            await c.roles.unassign_from_service_account(
                role_id, service_account_id, previous_resource_id
            )
            try:
                await c.roles.assign_to_service_account(
                    role_id,
                    models.AssignRoleToServiceAccountRequest(
                        **_assign_kwargs(
                            "service_account_id",
                            service_account_id,
                            new_resource_id,
                            new_inherit_wire,
                            tenant_scope,
                        )
                    ),
                )
            except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                assign_err = err
                try:
                    await c.roles.assign_to_service_account(
                        role_id,
                        models.AssignRoleToServiceAccountRequest(
                            **_assign_kwargs(
                                "service_account_id",
                                service_account_id,
                                previous_resource_id,
                                previous_inherit_wire,
                                tenant_scope,
                            )
                        ),
                    )
                    restored = True
                except Exception as err:  # noqa: BLE001 — reported below, not swallowed.
                    restored = False
                    restore_err = err

        if assign_err is not None:
            restored_word = (
                "restored" if restored else "NOT restored — the subject now holds no such role"
            )
            raise _RebindFailed(
                f"rebinding role failed: {assign_err}; the previous binding was {restored_word}",
                restore_succeeded=restored,
                restore_error=None if restored else str(restore_err),
            ) from assign_err
