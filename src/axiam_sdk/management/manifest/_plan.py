"""The plan a manifest reconciles to — CONTRACT.md §27.6."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from axiam_sdk._errors import NetworkError
from axiam_sdk.management.manifest._spec import ManagementManifest

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

    _duplicates("resource", [r.key for r in manifest.resources], problems)
    _duplicates("scope", [s.key for r in manifest.resources for s in r.scopes], problems)
    _duplicates("permission", [p.key for p in manifest.permissions], problems)
    _duplicates("role", [r.key for r in manifest.roles], problems)
    _duplicates("group", [g.key for g in manifest.groups], problems)
    _duplicates("user", [u.key for u in manifest.users], problems)

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
        for role_key in group.roles:
            if role_key not in role_keys:
                problems.append(
                    f"group {group.key!r} is assigned role {role_key!r}, which no role declares"
                )
    for user in manifest.users:
        for role_key in user.roles:
            if role_key not in role_keys:
                problems.append(
                    f"user {user.key!r} is assigned role {role_key!r}, which no role declares"
                )
        for group_key in user.groups:
            if group_key not in group_keys:
                problems.append(
                    f"user {user.key!r} is in group {group_key!r}, which no group declares"
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
