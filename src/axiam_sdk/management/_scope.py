"""Where ``{org_id}`` and ``{tenant_id}`` come from — CONTRACT.md §27.4 rule 3.

Thirty-one of the 147 routes carry one or both, and in almost every call they are
the client's own. Making the caller restate them every time is ceremony that
gets wrapped in a helper anyway; making them impossible to override is worse,
because a platform-admin token legitimately administers a tenant other than the
one its client was built with. So they default from the client, and every
handle that needs one exposes an override.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from axiam_sdk._errors import NetworkError

# Reused rather than redefined: this SDK already carries one UUID pattern for
# §12.3 rule 4's identical "a slug cannot be substituted" refusal, and a fourth
# copy of the same regex is a fourth place for them to drift.
from axiam_sdk._oidc import _UUID_RE

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk._client import _AxiamClientBase

__all__ = ["NamespaceScope"]


@dataclass(frozen=True)
class NamespaceScope:
    """Per-handle overrides for the two implicit path parameters.

    Named ``NamespaceScope`` rather than ``Scope`` because the server's schema
    set already has a ``Scope`` — the sub-resource kind §27.1's ``scopes``
    namespace administers — and two exported types of that name is one too many.
    """

    org_id: str | None = None
    """Override for ``{org_id}``. ``None`` means "the client's"."""

    tenant_id: str | None = None
    """Override for ``{tenant_id}``. ``None`` means "the client's"."""

    def with_org(self, org_id: str) -> NamespaceScope:
        """A copy of this scope addressing ``org_id`` instead."""
        return replace(self, org_id=org_id)

    def with_tenant(self, tenant_id: str) -> NamespaceScope:
        """A copy of this scope addressing ``tenant_id`` instead."""
        return replace(self, tenant_id=tenant_id)


def resolve_org(client: _AxiamClientBase, scope: NamespaceScope, operation: str) -> str:
    """Resolve ``{org_id}``: the handle's override, else the client's.

    A client built with ``org_slug`` and no ``org_id`` fails **here**, with no
    wire call. §27.4 rule 3 forbids resolving the slug behind the caller's back:
    a silent extra round-trip on an admin path is what §12.1 rule 2 refuses for
    ``/oauth2/*``, and for the same reason — the caller cannot see it, cannot
    cache it, and pays for it on every call.

    Raises:
        NetworkError: client-side, with no wire call, when no organization UUID
            is available.
    """
    if scope.org_id is not None:
        return require_uuid(scope.org_id, "org_id", operation)
    configured = client.resolved_org_id()
    if configured:
        return require_uuid(configured, "org_id", operation)
    slug = client._org_slug
    if slug:
        raise NetworkError(
            f"{operation}: this route needs an organization UUID, but the client was built "
            f"with org_slug {slug!r}. Rebuild it with org_id, log in so the token's org_id "
            f"claim resolves one, or name one on the handle with .in_org(...)."
        )
    raise NetworkError(
        f"{operation}: this route needs an organization UUID and the client has none. Build "
        f"the client with org_id, log in so the token's org_id claim resolves one, or name "
        f"one on the handle with .in_org(...)."
    )


def resolve_tenant(client: _AxiamClientBase, scope: NamespaceScope, operation: str) -> str:
    """Resolve ``{tenant_id}`` where it names the *context*, not the object.

    Namespaces where ``{tenant_id}`` names the thing being acted on —
    ``tenants``, and the signing CAs under ``ca_certificates`` — take it as an
    ordinary argument instead and never reach this.

    This SDK's client is built with a tenant **slug** (§5 requires one and there
    is no ``tenant_id`` constructor argument), so the UUID normally arrives with
    the access token's ``tenant_id`` claim. Before a login there is none, and
    that is a client-side failure rather than a request that would 404.

    Raises:
        NetworkError: client-side, with no wire call, when no tenant UUID is
            available.
    """
    if scope.tenant_id is not None:
        return require_uuid(scope.tenant_id, "tenant_id", operation)
    configured = client._resolved_tenant_id
    if configured:
        return require_uuid(configured, "tenant_id", operation)
    raise NetworkError(
        f"{operation}: this route needs a tenant UUID, but the client was built with "
        f"tenant_slug {client._session.tenant_slug!r} and none has been resolved yet. Call "
        f"login() first so the access token's tenant_id claim resolves one, or name one on "
        f"the handle with .for_tenant(...)."
    )


def require_uuid(value: str, parameter: str, operation: str) -> str:
    """Refuse a path identifier that is not a UUID, before any wire call.

    §27.9 requires this: every ``{..._id}`` on this surface is a UUID, so a slug
    or a name reaching one produces a 404 that reads as "no such object" when
    the real fault is the argument. Catching it here costs a regex and turns a
    misleading server answer into an accurate local one.

    Raises:
        NetworkError: client-side, with no wire call, when ``value`` is not a
            UUID.
    """
    if not _UUID_RE.match(value):
        raise NetworkError(
            f"{operation}: {parameter} must be a UUID, got {value!r}; a slug or name cannot "
            f"be substituted on a management route."
        )
    return value
