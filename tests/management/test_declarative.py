"""CONTRACT §27.7 — the declarative forms, in Python's idiom.

Both forms lower to the same manifest and go through the same ``plan``/``apply``.
What is tested here is that they agree, that they validate where the manifest is
*written* rather than on the first plan, and that a decorator with nothing to
attach to is a mistake heard about at assembly.
"""

from __future__ import annotations

import pytest
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

# ---------------------------------------------------------------------------
# define_manifest
# ---------------------------------------------------------------------------


def test_define_manifest_returns_the_manifest() -> None:
    """The value form is a plain manifest, with nothing wrapped around it."""
    manifest = define_manifest(
        permissions=[PermissionSpec(key="read", action="document:read", description="Read")]
    )
    assert isinstance(manifest, ManagementManifest)
    assert manifest.permissions[0].key == "read"


def test_define_manifest_throws_at_declaration_on_a_dangling_reference() -> None:
    """Not on the first plan against a live tenant, which may be much later."""
    with pytest.raises(NetworkError, match="which no permission declares"):
        define_manifest(
            roles=[
                RoleSpec(
                    key="editor",
                    name="Editor",
                    description="Edits",
                    grants=(GrantSpec(permission="nope"),),
                )
            ]
        )


def test_define_manifest_throws_at_declaration_on_a_resource_cycle() -> None:
    """A cycle is as much a declaration-time mistake as a dangling key."""
    with pytest.raises(NetworkError, match="cycle"):
        define_manifest(
            resources=[
                ResourceSpec(key="a", name="a", resource_type="c", parent="b"),
                ResourceSpec(key="b", name="b", resource_type="c", parent="a"),
            ]
        )


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

DOCS = ResourceSpec(key="docs", name="documents", resource_type="collection")
"""The resource the decorated and literal forms both declare."""

DRAFT = ScopeSpec(key="draft", name="draft", description="Unpublished")
"""The scope both forms declare beneath it."""

READ = PermissionSpec(key="read", action="document:read", description="Read")
"""The permission both forms declare."""

EDITOR = RoleSpec(key="editor", name="Editor", description="Edits documents")
"""The role both forms declare."""

GRANT = GrantSpec(permission="read", scopes=("draft",))
"""The grant both forms attach to it."""

STAFF = GroupSpec(key="staff", name="Staff", description="Everyone", roles=("editor",))
"""The group both forms declare."""

ALICE = UserSpec(
    key="alice",
    username="alice",
    email="alice@example.test",
    initial_password=SecretStr("correct-horse-battery"),
    roles=("editor",),
    groups=("staff",),
)
"""The user both forms declare."""


@axiam_resource(DOCS)
@axiam_scope(DRAFT)
class Documents:
    """A resource and the scope beneath it, declared on one class."""


@axiam_permission(READ)
class ReadDocument:
    """A permission on its own class."""


@axiam_role(EDITOR)
@axiam_grant(GRANT)
class Editor:
    """A role and the grant attached to it."""


@axiam_group(STAFF)
class Staff:
    """A group."""


@axiam_user(ALICE)
class Alice:
    """A user."""


def test_decorators_assemble_the_same_manifest_the_value_form_would() -> None:
    """Two spellings of one thing must not be two things."""
    collected = collect_manifest(Documents, ReadDocument, Editor, Staff, Alice)
    literal = define_manifest(
        resources=[
            ResourceSpec(key="docs", name="documents", resource_type="collection", scopes=(DRAFT,))
        ],
        permissions=[READ],
        roles=[
            RoleSpec(key="editor", name="Editor", description="Edits documents", grants=(GRANT,))
        ],
        groups=[STAFF],
        users=[ALICE],
    )
    assert collected == literal


def test_decorator_order_does_not_matter() -> None:
    """Each decorator only records; ``collect_manifest`` does the assembling."""

    @axiam_scope(DRAFT)
    @axiam_resource(DOCS)
    class Reversed:
        """The same two decorators, the other way up."""

    assert collect_manifest(Reversed) == collect_manifest(Documents)


def test_a_subclass_does_not_inherit_its_parents_declarations() -> None:
    """Otherwise one resource would be contributed twice, silently."""

    class Subclass(Documents):
        """Inherits from a decorated class but declares nothing itself."""

    with pytest.raises(TypeError, match="carries no AXIAM manifest decorator"):
        collect_manifest(Subclass)


def test_a_class_carrying_no_decorator_is_rejected() -> None:
    """Passing the wrong class is a mistake worth naming."""

    class Undecorated:
        """No manifest decorator at all."""

    with pytest.raises(TypeError, match="carries no AXIAM manifest decorator"):
        collect_manifest(Undecorated)


def test_a_scope_with_no_resource_to_live_in_is_rejected() -> None:
    """A scope always sits beneath a resource; there is nowhere else to put it."""

    @axiam_scope(DRAFT)
    class Orphan:
        """A scope with no resource on the same class."""

    with pytest.raises(TypeError, match="no resource with @axiam_resource"):
        collect_manifest(Orphan)


def test_a_grant_with_no_role_to_attach_to_is_rejected() -> None:
    """A grant is a role's grant; without one it attaches to nothing."""

    @axiam_grant(GRANT)
    class Loose:
        """A grant with no role on the same class."""

    with pytest.raises(TypeError, match="no role with @axiam_role"):
        collect_manifest(Loose)


def test_decorating_something_that_is_not_a_class_is_rejected() -> None:
    """These are class decorators; applying one to a function is a mistake."""

    def not_a_class() -> None:
        """A function, which declares nothing."""

    with pytest.raises(TypeError, match="applies to classes only"):
        axiam_resource(DOCS)(not_a_class)  # type: ignore[arg-type]


def test_the_assembled_manifest_is_validated() -> None:
    """Assembly is the moment the cross-references can first be checked."""

    @axiam_role(RoleSpec(key="r", name="R", description="R"))
    @axiam_grant(GrantSpec(permission="undeclared"))
    class Broken:
        """A role granting a permission nobody declares."""

    with pytest.raises(NetworkError, match="which no permission declares"):
        collect_manifest(Broken)


def test_a_declared_password_stays_out_of_every_rendering() -> None:
    """§27.5 does not stop applying because the secret came from a decorator."""
    manifest = collect_manifest(Documents, ReadDocument, Editor, Staff, Alice)
    assert "correct-horse-battery" not in repr(manifest)
    assert "correct-horse-battery" not in str(manifest)
    password = manifest.users[0].initial_password
    assert password is not None
    assert password.get_secret_value() == "correct-horse-battery"
