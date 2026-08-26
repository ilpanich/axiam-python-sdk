"""Declarative management — describe a tenant's shape, then reconcile it (§27.6).

``plan`` reads and writes nothing. ``apply`` runs the plan it just reported,
stops at the first failure, and tells you which steps never ran. There is no
``rollback``: these are independent HTTP endpoints, nothing spans them, and an
SDK that offered one could not honour it (§27.6 rule 7). Fix the cause and
re-apply -- applying twice converges, which is what makes that safe.

    AXIAM_URL=https://axiam.example.com \\
    AXIAM_TENANT=acme \\
    AXIAM_ADMIN=admin@example.com \\
    AXIAM_ADMIN_PASSWORD=... \\
    python examples/management_manifest.py [--apply]
"""

from __future__ import annotations

import os
import sys

from pydantic import SecretStr

from axiam_sdk import AxiamClient, NetworkError
from axiam_sdk.management.manifest import (
    GrantSpec,
    GroupSpec,
    PermissionSpec,
    ResourceSpec,
    RoleSpec,
    ScopeSpec,
    UserSpec,
    define_manifest,
)

BASE_URL = os.environ.get("AXIAM_URL", "https://axiam.example.com")
TENANT_SLUG = os.environ.get("AXIAM_TENANT", "acme")
ADMIN = os.environ.get("AXIAM_ADMIN", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("AXIAM_ADMIN_PASSWORD", "")

# Built at import time, and validated at import time: `define_manifest` checks
# the cross-references here and now, so a dangling key or a cycle in the
# resource parents fails where the manifest is *written* rather than on the
# first plan against a live tenant, possibly weeks later.
#
# Every spec carries a manifest-local `key`. Nothing here can name a UUID,
# because none of it exists yet -- resolving those keys against the tenant's
# current state is exactly what `plan` does.
TENANT_SHAPE = define_manifest(
    resources=[
        ResourceSpec(
            key="docs",
            name="documents",
            resource_type="collection",
            scopes=(
                ScopeSpec(key="draft", name="draft", description="Unpublished drafts"),
                ScopeSpec(key="published", name="published", description="Live documents"),
            ),
        ),
        ResourceSpec(
            key="archive",
            name="archive",
            resource_type="collection",
            parent="docs",  # ordering is derived; a parent always precedes its children
        ),
    ],
    permissions=[
        PermissionSpec(key="read", action="document:read", description="Read a document"),
        PermissionSpec(key="write", action="document:write", description="Edit a document"),
        PermissionSpec(key="purge", action="document:purge", description="Permanently delete"),
    ],
    roles=[
        RoleSpec(
            key="reader",
            name="Reader",
            description="Reads published documents",
            grants=(GrantSpec(permission="read", scopes=("published",)),),
        ),
        RoleSpec(
            key="editor",
            name="Editor",
            description="Edits drafts and reads everything",
            grants=(
                GrantSpec(permission="read"),
                GrantSpec(permission="write", scopes=("draft",)),
                # A deny grant overrides EVERY allow, at any depth of the
                # resource hierarchy and at equal specificity -- AXIAM's RBAC
                # engine is deny-override, not most-specific-wins. An editor
                # who is also somehow granted `purge` still cannot purge.
                GrantSpec(permission="purge", effect="deny"),
            ),
        ),
    ],
    groups=[
        GroupSpec(key="staff", name="Staff", description="Everyone in the org", roles=("reader",)),
    ],
    users=[
        UserSpec(
            key="alice",
            username="alice",
            email="alice@example.test",
            # Used ONLY if this user has to be created. A manifest describes
            # shape, and silently resetting a live account's password because a
            # config file mentions one is not a shape change.
            initial_password=SecretStr(os.environ.get("ALICE_PASSWORD", "")),
            roles=("editor",),
            groups=("staff",),
        ),
    ],
)


def main() -> int:
    """Plan, print the diff, and apply it if asked."""
    with AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG) as client:
        client.login(ADMIN, ADMIN_PASSWORD)

        try:
            plan = client.manifest.plan(TENANT_SHAPE)
        except NetworkError as err:
            # Validation precedes every request (§27.6 rule 2), and reports
            # every problem rather than the first -- fixing them one at a time
            # is a slow way to learn about four.
            print(err, file=sys.stderr)
            return 1

        changes = plan.changes()
        if not changes:
            # Two plans over unchanged state are equal, in the same order
            # (§27.6 rule 8), which is what makes a plan diffable.
            print("converged: nothing to do")
            return 0

        print(f"{len(changes)} change(s) of {len(plan.actions)} step(s):")
        for action in changes:
            print(f"  {action.change:<10} {action.target:<13} {action.summary}")

        if "--apply" not in sys.argv:
            print("\nre-run with --apply to reconcile")
            return 0

        report = client.manifest.apply(TENANT_SHAPE)
        for step in report.steps:
            print(f"  {step.outcome.status:<15} {step.action.summary}")

        failure = report.failure()
        if failure is not None:
            # Everything before this step has already happened and will not be
            # undone. Fix the cause and re-apply.
            print(f"\nstopped at {failure.action.summary}: {failure.message}", file=sys.stderr)
            return 1

        print(f"\napplied {report.changed_count()} change(s)")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
