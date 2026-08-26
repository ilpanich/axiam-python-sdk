"""The declarative forms of a manifest — CONTRACT.md §27.7.

§27.7 asks each SDK for the declarative form its users would expect. In Python
that is two things, and this module has both:

- :func:`define_manifest`, which builds the manifest as a value and **validates
  at the point of declaration** rather than at ``plan`` time;
- class decorators, for codebases that already declare their domain that way.

Both lower to the same :class:`~axiam_sdk.management.manifest.ManagementManifest`
and go through the same ``plan``/``apply``. A declarative form that talked to the
network itself would be a second implementation of §27.6, and the two would
disagree.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from typing import Protocol, TypeVar

from axiam_sdk.management.manifest._plan import validate
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
    "Decorator",
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

C = TypeVar("C", bound=type)


class Decorator(Protocol):
    """A class decorator that records one manifest declaration and returns the class.

    Spelled as a callback protocol rather than ``Callable[[type], type]`` so the
    decorated class keeps its own type: ``@axiam_user(...)`` applied to ``Alice``
    still gives back ``Alice``, not a bare ``type``.
    """

    def __call__(self, cls: C) -> C:
        """Record the declaration on ``cls`` and return it unchanged."""
        ...


_BUCKET = "__axiam_manifest__"
"""Attribute the decorators record into, read out of ``cls.__dict__`` only.

Reading it off ``cls.__dict__`` rather than with ``getattr`` is what stops a
subclass inheriting its parent's declarations and silently contributing them a
second time.
"""


@dataclass
class _Bucket:
    """What one decorated class has declared so far."""

    resource: ResourceSpec | None = None
    """The resource this class declares, if any."""

    scopes: list[ScopeSpec] = field(default_factory=list)
    """Scopes declared on this class, to live under its resource."""

    permissions: list[PermissionSpec] = field(default_factory=list)
    """Permissions declared on this class."""

    role: RoleSpec | None = None
    """The role this class declares, if any."""

    grants: list[GrantSpec] = field(default_factory=list)
    """Grants declared on this class, to attach to its role."""

    group: GroupSpec | None = None
    """The group this class declares, if any."""

    user: UserSpec | None = None
    """The user this class declares, if any."""


def _bucket(cls: type) -> _Bucket:
    """This class's own bucket, created on first use and never inherited."""
    if _BUCKET not in cls.__dict__:
        setattr(cls, _BUCKET, _Bucket())
    bucket = cls.__dict__[_BUCKET]
    assert isinstance(bucket, _Bucket)
    return bucket


def _require_class(cls: object, decorator: str) -> type:
    """Refuse a decorator applied to anything but a class.

    Raises:
        TypeError: when ``cls`` is not a class.
    """
    if not isinstance(cls, type):
        raise TypeError(f"@{decorator} applies to classes only, not to {type(cls).__name__}")
    return cls


def define_manifest(
    *,
    resources: Sequence[ResourceSpec] = (),
    permissions: Sequence[PermissionSpec] = (),
    roles: Sequence[RoleSpec] = (),
    groups: Sequence[GroupSpec] = (),
    users: Sequence[UserSpec] = (),
) -> ManagementManifest:
    """Declare a manifest and check it immediately.

    The eager validation is the part that earns its keep: a dangling key, a
    duplicate, or a cycle in the resource parents fails where the manifest is
    *written* rather than on the first ``plan`` against a live tenant — which,
    for a manifest that lives in a config module, is usually at import time.

    ::

        tenant_shape = define_manifest(
            resources=[
                ResourceSpec(
                    key="docs", name="documents", resource_type="collection",
                    scopes=(ScopeSpec(key="draft", name="draft", description="Unpublished"),),
                )
            ],
            permissions=[PermissionSpec(key="read", action="document:read", description="Read")],
            roles=[
                RoleSpec(
                    key="editor", name="Editor", description="Edits",
                    grants=(GrantSpec(permission="read", scopes=("draft",)),),
                )
            ],
        )

    Raises:
        NetworkError: if the manifest cannot be reconciled — a dangling
            cross-reference key, a duplicate key, or a cycle in the resource
            parents.
    """
    manifest = ManagementManifest(
        resources=tuple(resources),
        permissions=tuple(permissions),
        roles=tuple(roles),
        groups=tuple(groups),
        users=tuple(users),
    )
    validate(manifest)
    return manifest


def axiam_resource(spec: ResourceSpec) -> Decorator:
    """Declare a resource on this class.

    Stack :func:`axiam_scope` on the same class to declare scopes beneath it;
    decorator order does not matter, because each one only records into the
    class's bucket and :func:`collect_manifest` does the assembling.

    ::

        @axiam_resource(ResourceSpec(key="docs", name="documents", resource_type="collection"))
        @axiam_scope(ScopeSpec(key="draft", name="draft", description="Unpublished"))
        class Documents:
            pass
    """

    def apply(cls: C) -> C:
        """Record ``spec`` as this class's resource."""
        _bucket(_require_class(cls, "axiam_resource")).resource = spec
        return cls

    return apply


def axiam_scope(spec: ScopeSpec) -> Decorator:
    """Declare a scope, beneath whichever resource the same class declares."""

    def apply(cls: C) -> C:
        """Record ``spec`` among this class's scopes."""
        _bucket(_require_class(cls, "axiam_scope")).scopes.append(spec)
        return cls

    return apply


def axiam_permission(spec: PermissionSpec) -> Decorator:
    """Declare a permission."""

    def apply(cls: C) -> C:
        """Record ``spec`` among this class's permissions."""
        _bucket(_require_class(cls, "axiam_permission")).permissions.append(spec)
        return cls

    return apply


def axiam_role(spec: RoleSpec) -> Decorator:
    """Declare a role on this class.

    Stack :func:`axiam_grant` on the same class to grant permissions to it.
    """

    def apply(cls: C) -> C:
        """Record ``spec`` as this class's role."""
        _bucket(_require_class(cls, "axiam_role")).role = spec
        return cls

    return apply


def axiam_grant(spec: GrantSpec) -> Decorator:
    """Grant a permission to whichever role the same class declares."""

    def apply(cls: C) -> C:
        """Record ``spec`` among this class's grants."""
        _bucket(_require_class(cls, "axiam_grant")).grants.append(spec)
        return cls

    return apply


def axiam_group(spec: GroupSpec) -> Decorator:
    """Declare a group."""

    def apply(cls: C) -> C:
        """Record ``spec`` as this class's group."""
        _bucket(_require_class(cls, "axiam_group")).group = spec
        return cls

    return apply


def axiam_user(spec: UserSpec) -> Decorator:
    """Declare a user."""

    def apply(cls: C) -> C:
        """Record ``spec`` as this class's user."""
        _bucket(_require_class(cls, "axiam_user")).user = spec
        return cls

    return apply


def collect_manifest(*classes: type) -> ManagementManifest:
    """Assemble a manifest from decorated classes.

    Validated on the way out, exactly as :func:`define_manifest` is — a scope
    decorated onto a class that declares no resource, or a grant on a class that
    declares no role, is a mistake worth hearing about at assembly rather than on
    the first ``plan``.

    ::

        shape = collect_manifest(Documents, ReadDocument, Editor, Staff, Alice)
        client.manifest.apply(shape)

    Raises:
        TypeError: if a decorator has nothing to attach to, or a class carries no
            manifest decorator at all.
        NetworkError: if the assembled manifest cannot be reconciled.
    """
    resources: list[ResourceSpec] = []
    permissions: list[PermissionSpec] = []
    roles: list[RoleSpec] = []
    groups: list[GroupSpec] = []
    users: list[UserSpec] = []

    for cls in classes:
        bucket = cls.__dict__.get(_BUCKET)
        if not isinstance(bucket, _Bucket):
            raise TypeError(
                f"{cls.__name__} carries no AXIAM manifest decorator; it declares nothing "
                f"to collect"
            )
        if bucket.scopes and bucket.resource is None:
            raise TypeError(
                f"{cls.__name__} declares scopes with @axiam_scope but no resource with "
                f"@axiam_resource; a scope has nowhere to live without one"
            )
        if bucket.grants and bucket.role is None:
            raise TypeError(
                f"{cls.__name__} declares grants with @axiam_grant but no role with "
                f"@axiam_role; a grant has nothing to attach to without one"
            )
        if bucket.resource is not None:
            resources.append(
                replace(
                    bucket.resource,
                    scopes=(*bucket.resource.scopes, *bucket.scopes),
                )
            )
        permissions.extend(bucket.permissions)
        if bucket.role is not None:
            roles.append(replace(bucket.role, grants=(*bucket.role.grants, *bucket.grants)))
        if bucket.group is not None:
            groups.append(bucket.group)
        if bucket.user is not None:
            users.append(bucket.user)

    return define_manifest(
        resources=resources,
        permissions=permissions,
        roles=roles,
        groups=groups,
        users=users,
    )
