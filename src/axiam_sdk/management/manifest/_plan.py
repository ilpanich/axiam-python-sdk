"""The plan a manifest reconciles to — CONTRACT.md §27.6."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import SecretStr

from axiam_sdk._errors import NetworkError
from axiam_sdk.management.manifest._spec import (
    ManagementManifest,
    RoleBinding,
    RoleSpec,
    ScopedRoleBinding,
)

__all__ = [
    "AppliedStep",
    "ApplyReport",
    "ManagementPlan",
    "ManifestFailure",
    "PlannedAction",
    "StepOutcome",
]

Change = Literal["create", "update", "no-change"]
"""Whether reconciling one spec would create, update, or do nothing."""

Target = Literal[
    "resource",
    "scope",
    "permission",
    "role",
    "role-grant",
    "group",
    "group-role",
    "user",
    "user-role",
    "group-member",
    "service-account",
    "service-account-role",
]
"""Which part of the manifest an action came from."""

Status = Literal["created", "updated", "unchanged", "failed", "not-attempted"]
"""What actually became of one planned step."""


@dataclass(frozen=True)
class PlannedAction:
    """One step of a plan."""

    change: Change
    """Whether this step creates, updates, or does nothing."""

    target: Target
    """What kind of thing it acts on."""

    key: str
    """The manifest key it came from, for a human reading the plan."""

    summary: str
    """A one-line description, stable across runs so plans can be diffed."""


@dataclass(frozen=True)
class ManagementPlan:
    """The ordered set of actions that would reconcile a manifest.

    Ordering is derived, not incidental: resources (parents before children),
    then scopes, permissions, roles, role grants, groups, group bindings, users,
    and finally the user bindings that need all of the above to exist. Two plans
    over unchanged state are equal, in the same order (§27.6 rule 8) — a plan
    that reorders between runs cannot be diffed, and diffing it is most of the
    reason it exists.
    """

    actions: tuple[PlannedAction, ...] = field(default_factory=tuple)
    """Every step, including the no-ops."""

    def changes(self) -> list[PlannedAction]:
        """The steps of this plan that would actually change something."""
        return [a for a in self.actions if a.change != "no-change"]

    def is_converged(self) -> bool:
        """Whether applying this plan would change nothing.

        This is the §27.6 rule 6 acceptance test: ``apply`` then ``plan`` must
        land here, or the SDK has a drift-detection bug.
        """
        return not self.changes()


@dataclass(frozen=True)
class StepOutcome:
    """What actually happened to one planned step."""

    status: Status
    """``created``, ``updated``, ``unchanged``, ``failed`` or ``not-attempted``."""

    message: str | None = None
    """The error the server or transport gave, on a ``failed`` step only."""

    client_secret: SecretStr | None = None
    """The one-time ``client_secret`` (§27.5 rule 5, contract 1.51) — set
    only on a ``service_accounts`` spec's ``Create`` outcome, and only
    there: ``Update``/``NoChange`` never carry one, and ``apply`` never
    calls ``rotate_secret`` to reconcile. Carried here rather than dropped,
    even when a *later* action of the same ``apply`` fails: this is the
    only moment the plaintext exists, and §27.6 rule 7 already requires
    every attempted action's outcome reported — losing this one would mint
    a credential nobody could ever use.
    """


@dataclass(frozen=True)
class AppliedStep:
    """One planned step paired with what became of it."""

    action: PlannedAction
    """The step, exactly as ``plan`` reported it."""

    outcome: StepOutcome
    """What actually happened when it ran — or did not."""


@dataclass(frozen=True)
class ManifestFailure:
    """The step that stopped an apply, and why."""

    action: PlannedAction
    """The step that failed. Everything before it has already happened."""

    message: str
    """The error the server or transport gave."""


@dataclass(frozen=True)
class ApplyReport:
    """The result of applying a manifest.

    **There is no transaction here and this type does not pretend there is**
    (§27.6 rule 7). These are independent HTTP endpoints; nothing spans them. If
    step 12 of 30 fails, steps 1–11 have happened and will not be undone — so
    every step's outcome is reported, execution stops at the first failure rather
    than continuing blindly, and there is no ``rollback`` because this SDK could
    not honour one. Fix the cause and re-apply: rule 6's idempotence is what
    makes that safe.
    """

    steps: tuple[AppliedStep, ...] = field(default_factory=tuple)
    """Each planned step paired with what became of it, in plan order."""

    def failure(self) -> ManifestFailure | None:
        """The failing step, if the apply stopped early."""
        for step in self.steps:
            if step.outcome.status == "failed":
                return ManifestFailure(step.action, step.outcome.message or "")
        return None

    def is_complete(self) -> bool:
        """Whether every step that was meant to run did."""
        return self.failure() is None

    def changed_count(self) -> int:
        """How many steps actually changed something."""
        return sum(1 for s in self.steps if s.outcome.status in ("created", "updated"))

    def client_secret(self, manifest_key: str) -> SecretStr | None:
        """The one-time ``client_secret`` an ``apply`` minted for the
        ``service_accounts`` spec carrying ``manifest_key``, if that spec's
        step was a ``Create`` (§27.5 rule 5) — the only place it is ever
        returned. ``None`` for an ``Update``/``NoChange`` outcome, a step
        that never ran (``not-attempted``), or a key this report has no
        step for."""
        for step in self.steps:
            if step.action.key == manifest_key and step.outcome.client_secret is not None:
                return step.outcome.client_secret
        return None


def validate(manifest: ManagementManifest) -> None:
    """Reject a manifest that cannot be reconciled, before any request is made.

    §27.6 rules 2 and 5 both land here. Every failure this catches would
    otherwise surface halfway through an apply, with part of the tenant already
    changed — which is the expensive moment to learn that a role refers to a
    permission nobody declared.

    Raises:
        NetworkError: naming every problem found, not just the first.
    """
    problems: list[str] = []
    resource_keys = {r.key for r in manifest.resources}
    scope_keys = {s.key for r in manifest.resources for s in r.scopes}
    permission_keys = {p.key for p in manifest.permissions}
    role_keys = {r.key for r in manifest.roles}
    group_keys = {g.key for g in manifest.groups}
    role_by_key = {r.key: r for r in manifest.roles}

    _duplicates("resource", [r.key for r in manifest.resources], problems)
    _duplicates("scope", [s.key for r in manifest.resources for s in r.scopes], problems)
    _duplicates("permission", [p.key for p in manifest.permissions], problems)
    _duplicates("role", [r.key for r in manifest.roles], problems)
    _duplicates("group", [g.key for g in manifest.groups], problems)
    _duplicates("user", [u.key for u in manifest.users], problems)
    _duplicates("service_account", [s.key for s in manifest.service_accounts], problems)

    for resource in manifest.resources:
        if resource.parent and resource.parent not in resource_keys:
            problems.append(
                f"resource {resource.key!r} names parent {resource.parent!r}, which no "
                f"resource declares"
            )
    for role in manifest.roles:
        for grant in role.grants:
            if grant.permission not in permission_keys:
                problems.append(
                    f"role {role.key!r} grants permission {grant.permission!r}, which no "
                    f"permission declares"
                )
            for scope in grant.scopes:
                if scope not in scope_keys:
                    problems.append(
                        f"role {role.key!r} scopes a grant to {scope!r}, which no scope declares"
                    )
    for group in manifest.groups:
        _validate_role_bindings(
            "group", group.key, group.roles, role_keys, resource_keys, role_by_key, problems
        )
    for user in manifest.users:
        _validate_role_bindings(
            "user", user.key, user.roles, role_keys, resource_keys, role_by_key, problems
        )
        for group_key in user.groups:
            if group_key not in group_keys:
                problems.append(
                    f"user {user.key!r} is in group {group_key!r}, which no group declares"
                )
    for service_account in manifest.service_accounts:
        _validate_role_bindings(
            "service_account",
            service_account.key,
            service_account.roles,
            role_keys,
            resource_keys,
            role_by_key,
            problems,
        )

    try:
        topological_order(manifest)
    except NetworkError as err:
        problems.append(err.message)

    if problems:
        raise NetworkError(
            f"manifest is not reconcilable ({len(problems)} problem(s)): " + "; ".join(problems)
        )


def _duplicates(kind: str, keys: list[str], problems: list[str]) -> None:
    """Record every key of ``kind`` declared more than once."""
    seen: set[str] = set()
    for key in keys:
        if key in seen:
            problems.append(f"{kind} key {key!r} is declared more than once")
        seen.add(key)


def role_key(binding: RoleBinding) -> str:
    """The ``key`` of the role a :data:`RoleBinding` names, whichever shape
    it is."""
    return binding if isinstance(binding, str) else binding.role


def resource_key(binding: RoleBinding) -> str | None:
    """The ``key`` of the resource a :data:`RoleBinding` is scoped to, or
    ``None`` for the plain (no-resource) shape."""
    return None if isinstance(binding, str) else binding.resource


def _validate_role_bindings(
    kind: str,
    subject_key: str,
    bindings: tuple[RoleBinding, ...],
    role_keys: set[str],
    resource_keys: set[str],
    role_by_key: dict[str, RoleSpec],
    problems: list[str],
) -> None:
    """The checks every ``roles[]`` list needs, shared by groups, users and
    service accounts (CONTRACT §27.6.1, contract 1.51):

    - every named role and resource actually exists in the manifest;
    - **a subject holds a role at most once** (§27.6.1: the server keys
      assignments on ``(subject, role)`` with no resource component, so a
      manifest binding one role to one subject twice — plain, scoped, or
      one of each — describes a state the server cannot hold, and is
      rejected before any request);
    - a global role bound with ``inherit: false`` is refused by the server
      with 400 (§27.6.1 addition 2's last rule); this SDK checks it
      client-side, matching the Rust reference's choice among the two the
      contract leaves open (MAY).
    """
    seen_roles: set[str] = set()
    for binding in bindings:
        rk = role_key(binding)
        rname = f"{kind} {subject_key!r}"
        if rk not in role_keys:
            problems.append(f"{rname} is assigned role {rk!r}, which no role declares")
        if rk in seen_roles:
            problems.append(
                f"{rname} binds role {rk!r} more than once — a subject holds a role at "
                f"most once (CONTRACT §27.6.1); the server keys assignments on "
                f"(subject, role) with no resource component"
            )
        seen_roles.add(rk)

        if isinstance(binding, ScopedRoleBinding):
            if binding.resource not in resource_keys:
                problems.append(
                    f"{rname} binds role {rk!r} at resource {binding.resource!r}, which no "
                    f"resource declares"
                )
            if not binding.inherit:
                role = role_by_key.get(rk)
                if role is not None and role.is_global:
                    problems.append(
                        f"{rname} binds global role {rk!r} with inherit=False, which the "
                        f"server refuses with 400 (a global role ignores resource scope)"
                    )


def topological_order(manifest: ManagementManifest) -> list[str]:
    """Resource keys ordered so a parent always precedes its children.

    Raises on a cycle rather than looping: a resource graph with a cycle has no
    valid creation order, and discovering that by hanging is worse than
    discovering it by message.

    Raises:
        NetworkError: when the parent graph has a cycle.
    """
    parents = {r.key: r.parent for r in manifest.resources}
    order: list[str] = []
    placed: set[str] = set()

    # Iterate the manifest's own order so the result is stable run to run
    # (§27.6 rule 8), rather than a mapping order that is not.
    for resource in manifest.resources:
        chain: list[str] = []
        guard: set[str] = set()
        cursor: str | None = resource.key
        while cursor is not None and cursor not in placed:
            if cursor in guard:
                raise NetworkError(
                    f"resource parent graph has a cycle through {cursor!r}; there is no order "
                    f"in which these can be created"
                )
            guard.add(cursor)
            chain.append(cursor)
            cursor = parents.get(cursor)
        for key in reversed(chain):
            if key not in placed:
                placed.add(key)
                order.append(key)
    return order
