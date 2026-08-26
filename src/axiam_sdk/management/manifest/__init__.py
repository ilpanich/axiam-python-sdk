"""Declarative management — CONTRACT.md §27.6 and §27.7.

Two ways to say what a tenant should look like, one reconciler behind both::

    from axiam_sdk.management.manifest import ManagementManifest, ResourceSpec

    shape = ManagementManifest(
        resources=(ResourceSpec(key="docs", name="documents", resource_type="collection"),),
    )
    plan = client.manifest.plan(shape)   # reads only
    if not plan.is_converged():
        report = client.manifest.apply(shape)

``plan`` writes nothing, ``apply`` stops at the first failure and reports what it
did and did not attempt, and applying twice converges. There is no ``rollback``:
these are independent HTTP endpoints and nothing spans them (§27.6 rule 7).
"""

from __future__ import annotations

from axiam_sdk.management.manifest._declarative import (
    axiam_grant,
    axiam_group,
    axiam_permission,
    axiam_resource,
    axiam_role,
    axiam_scope,
    axiam_user,
    collect_manifest,
    define_manifest,
)
from axiam_sdk.management.manifest._engine import AsyncManifestApi, ManifestApi
from axiam_sdk.management.manifest._plan import (
    AppliedStep,
    ApplyReport,
    ManagementPlan,
    ManifestFailure,
    PlannedAction,
    StepOutcome,
)
from axiam_sdk.management.manifest._spec import (
    GrantSpec,
    GroupSpec,
    ManagementManifest,
    PermissionSpec,
    ResourceSpec,
    RoleSpec,
    ScopeSpec,
    UserSpec,
)

__all__ = [
    "AppliedStep",
    "ApplyReport",
    "AsyncManifestApi",
    "GrantSpec",
    "GroupSpec",
    "ManagementManifest",
    "ManagementPlan",
    "ManifestApi",
    "ManifestFailure",
    "PermissionSpec",
    "PlannedAction",
    "ResourceSpec",
    "RoleSpec",
    "ScopeSpec",
    "StepOutcome",
    "UserSpec",
    "axiam_grant",
    "axiam_group",
    "axiam_permission",
    "axiam_resource",
    "axiam_role",
    "axiam_scope",
    "axiam_user",
    "collect_manifest",
    "define_manifest",
]
