"""The desired shape of a tenant — CONTRACT.md §27.6.

A manifest is a **value**. It is built before the things in it exist, so it
cannot name them by UUID; every spec carries a manifest-local ``key`` that other
specs refer to, and ``plan`` resolves those keys against the tenant's current
state.

Nothing here touches the network and nothing here needs a client — which is what
makes a manifest something you can load from configuration, commit to a
repository, and diff.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import SecretStr

__all__ = [
    "GrantSpec",
    "GroupSpec",
    "ManagementManifest",
    "PermissionSpec",
    "ResourceSpec",
    "RoleBinding",
    "RoleSpec",
    "ScopedRoleBinding",
    "ScopeSpec",
    "ServiceAccountSpec",
    "UserSpec",
]


@dataclass(frozen=True)
class ScopeSpec:
    """A scope, always beneath the resource that declares it."""

    key: str
    """Manifest-local identifier, referred to by a role's grants."""

    name: str
    """The scope's name — its natural key within its resource."""

    description: str
    """Human-readable description. The server requires one."""


@dataclass(frozen=True)
class ResourceSpec:
    """A resource in the hierarchy, and the scopes beneath it."""

    key: str
    """Manifest-local identifier, referred to by ``parent`` and by grants."""

    name: str
    """The resource's name — its natural key within the tenant."""

    resource_type: str
    """The server's ``resource_type`` discriminator."""

    parent: str | None = None
    """The ``key`` of this resource's parent, if it has one."""

    scopes: tuple[ScopeSpec, ...] = ()
    """Scopes declared under this resource."""

    metadata: dict[str, Any] | None = None
    """Arbitrary key-value metadata (CONTRACT §27.6.1 addition 1, contract
    1.51).

    Sent on ``Create``, and on ``Update`` when stated and it differs from
    the server's value. Drift is **JSON equality of the whole object**,
    never a key-by-key merge — a stated ``{}`` matches what the server
    stores for a resource created with none, and an unstated ``metadata``
    (``None`` here) is silent about it, exactly like any other field
    (§27.6 rule 3). A merge would make ``apply`` unable to remove a key,
    which rule 6's idempotence test would then never catch.
    """


@dataclass(frozen=True)
class PermissionSpec:
    """A permission — an action, tenant-wide."""

    key: str
    """Manifest-local identifier, referred to by a role's grants."""

    action: str
    """The action — the permission's natural key within the tenant."""

    description: str
    """Human-readable description. The server requires one."""


@dataclass(frozen=True)
class GrantSpec:
    """One permission granted to a role, optionally narrowed to scopes."""

    permission: str
    """The ``key`` of the :class:`PermissionSpec` being granted."""

    effect: str | None = None
    """Allow or deny. ``None`` lets the server default, which is allow.

    A ``deny`` grant overrides **every** allow, at any depth of the resource
    hierarchy and at equal specificity — AXIAM's RBAC engine is deny-override,
    not most-specific-wins.
    """

    scopes: tuple[str, ...] = ()
    """The ``key``s of scopes this grant is narrowed to. Empty means the whole resource."""


@dataclass(frozen=True)
class ScopedRoleBinding:
    """A role bound at a specific resource, optionally non-inheriting
    (CONTRACT §27.6.1 addition 2 / S-10, contract 1.51).

    The object shape of a :data:`RoleBinding` — the other shape is a bare
    role key, meaning "no resource, and so no inheritance question", exactly
    as every SDK bound a role before this addition existed.
    """

    role: str
    """The ``key`` of the :class:`RoleSpec` being bound."""

    resource: str
    """The ``key`` of the :class:`ResourceSpec` this binding is scoped to."""

    inherit: bool = True
    """Whether the assignment also reaches the descendants of ``resource``
    (``True``, the default) or applies at that resource only (``False``).

    Reaches the wire only as ``False``: an inheritable binding's request
    body stays byte-for-byte what it was before this field existed (§27.6.1
    addition 2, "An SDK MUST NOT send `inherit: true` explicitly").
    """


RoleBinding = str | ScopedRoleBinding
"""One entry of a :class:`GroupSpec`, :class:`UserSpec` or
:class:`ServiceAccountSpec`'s ``roles``: either a bare role **key** (a
``str`` — no resource, so no inheritance question) or a
:class:`ScopedRoleBinding` (an object naming a resource and, optionally,
``inherit: false``). CONTRACT §27.6.1 addition 2, contract 1.51.
"""


@dataclass(frozen=True)
class RoleSpec:
    """A role and the permissions granted to it."""

    key: str
    """Manifest-local identifier, referred to by users and groups."""

    name: str
    """The role's name — its natural key within the tenant."""

    description: str
    """Human-readable description. The server requires one."""

    is_global: bool = False
    """Whether the role applies tenant-wide rather than to a resource subtree."""

    grants: tuple[GrantSpec, ...] = ()
    """Permissions this role grants."""


@dataclass(frozen=True)
class GroupSpec:
    """A group and the roles its members inherit."""

    key: str
    """Manifest-local identifier, referred to by users."""

    name: str
    """The group's name — its natural key within the tenant."""

    description: str
    """Human-readable description. The server requires one."""

    roles: tuple[RoleBinding, ...] = ()
    """Roles assigned to this group — each either a bare role key or a
    :class:`ScopedRoleBinding` (CONTRACT §27.6.1 addition 2, contract 1.51)."""


@dataclass(frozen=True)
class UserSpec:
    """A user, their roles and their group memberships."""

    key: str
    """Manifest-local identifier."""

    username: str
    """The username — the user's natural key within the tenant."""

    email: str
    """The user's email address."""

    initial_password: SecretStr | None = None
    """The password to set **if this user has to be created**.

    Never used for a user that already exists: a manifest is a description of
    shape, and silently resetting a live account's password because a config
    file mentions one is not a shape change. ``plan`` fails before any request
    when a user must be created and this is absent, rather than discovering it
    halfway through an apply (§27.6 rule 1).
    """

    roles: tuple[RoleBinding, ...] = ()
    """Roles assigned directly to this user — each either a bare role key or
    a :class:`ScopedRoleBinding` (CONTRACT §27.6.1 addition 2, contract 1.51)."""

    groups: tuple[str, ...] = ()
    """The ``key``s of groups this user belongs to."""


@dataclass(frozen=True)
class ServiceAccountSpec:
    """A service account and the roles bound to it (CONTRACT §27.6.1
    addition 3, contract 1.51).

    **The natural key is** :attr:`name`, **and the server does not enforce
    it** — a service account's only unique index is its ``client_id``, so a
    tenant can hold two accounts sharing a name. ``plan`` fails, before
    ``apply`` writes anything, when more than one existing account matches a
    stated name (§27.6.1 addition 3): picking one would reconcile an
    arbitrary account.
    """

    key: str
    """Manifest-local identifier, referred to by nothing else in this
    manifest — a service account cannot itself hold another service
    account's role in 1.51."""

    name: str
    """The service account's name — its natural key, unenforced (see
    above)."""

    description: str | None = None
    """The only field reconciled by ``Update`` (sparse, §27.4 rule 5).
    ``status`` is not a manifest field in 1.51."""

    roles: tuple[RoleBinding, ...] = ()
    """Roles bound to this service account — each either a bare role key or
    a :class:`ScopedRoleBinding`, through
    ``roles.assign_to_service_account``. Group membership of a service
    account is not a manifest field in 1.51."""


@dataclass(frozen=True)
class ManagementManifest:
    """The shape a tenant should have.

    Deliberately covers only the namespaces that describe a tenant's *shape*.
    Certificates, CA certificates, PGP keys and SCIM tokens are absent on purpose
    (§27.6): they mint one-time secrets, and a declarative layer that "ensures a
    certificate exists" either re-mints one on every run or silently accepts
    drift. Both are worse than an imperative call made once, on purpose, whose
    result the caller stores. ``service_accounts`` is the one exception that
    mints a one-time secret and is still covered — §27.5 rule 5 says why:
    a service account's identity is stable apart from its secret, so the
    secret is minted once, at ``Create``, exactly like an imperative call.
    ``webhooks`` stays unspecified in 1.51; this SDK does not implement it.
    """

    resources: tuple[ResourceSpec, ...] = field(default_factory=tuple)
    """Resources, in any order — ``plan`` sorts them so a parent precedes its children."""

    permissions: tuple[PermissionSpec, ...] = field(default_factory=tuple)
    """Permissions. What binds one to a resource is the scope list on a role's grant."""

    roles: tuple[RoleSpec, ...] = field(default_factory=tuple)
    """Roles and the permissions granted to them."""

    groups: tuple[GroupSpec, ...] = field(default_factory=tuple)
    """Groups and the roles their members inherit."""

    users: tuple[UserSpec, ...] = field(default_factory=tuple)
    """Users, their role assignments and their group memberships."""

    service_accounts: tuple[ServiceAccountSpec, ...] = field(default_factory=tuple)
    """Service accounts and their role bindings (CONTRACT §27.6.1 addition 3,
    contract 1.51)."""
