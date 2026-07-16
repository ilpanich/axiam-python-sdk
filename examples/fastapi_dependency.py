"""fastapi_dependency.py demonstrates guarding a FastAPI route with
axiam_sdk.fastapi.require_authenticated_user(...) (CONTRACT.md §10, D-09,
SC#4), and layering the declarative authorization helpers
require_access(...)/require_role(...) (CONTRACT.md §11) on top of it.

require_authenticated_user(verifier, configured_tenant) verifies the inbound
session LOCALLY via a JWKS-backed verifier (no per-request AXIAM-server
round-trip on a cache hit), enforces the configured-tenant claim, and injects
the authenticated identity (AxiamUser) into the route via Depends(...) — or
raises HTTPException(401) automatically before the route handler ever runs.

require_access(verifier, configured_tenant, client, action, ...) composes
with that same authentication pipeline, then calls the async
AsyncAxiamClient's check_access(...) — with subject_id set to the
*authenticated caller's* user_id, never this client's own (typically
service-account) identity — for a resource resolved from the request (here,
the doc_id path parameter). Denied -> 403; an unresolvable resource id ->
400; a transport failure while calling the authz endpoint -> 503 (fail
closed, CONTRACT.md §11.2.5).

require_role(verifier, configured_tenant, *roles) is a local, no-round-trip
check against the already-verified identity's roles — cheaper but coarser
than require_access, and NOT a substitute for it (§11.2.9).

This example is illustrative/importable — it does not require a live AXIAM
server to byte-compile or to construct the FastAPI app object (SC#4).
Serving real traffic requires the configured AXIAM_BASE_URL to be a
reachable AXIAM server (for the verifier's JWKS fetch and the authz check
client).

Run: uvicorn examples.fastapi_dependency:app --reload
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI

from axiam_sdk import AsyncAxiamClient
from axiam_sdk.fastapi import (
    AxiamUser,
    JwksVerifier,
    require_access,
    require_authenticated_user,
    require_role,
)


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")

# JwksVerifier is the same local-verification primitive the Django
# middleware example uses, bound to {base_url}/oauth2/jwks (§10, D-16).
verifier = JwksVerifier(base_url)

# The declarative require_access(...) helper takes an AsyncAxiamClient
# (async-native, matching FastAPI's own async handlers) used solely to
# issue the authz check — not the session that authenticated the caller.
authz_client = AsyncAxiamClient(base_url=base_url, tenant_slug=tenant_slug)

app = FastAPI()

# require_authenticated_user(...) is a dependency FACTORY — the verifier and
# configured tenant must be configured per-app, mirroring the Go
# middleware's Middleware(verifier, configuredTenant, opts...) pattern.
authenticated_user = require_authenticated_user(verifier, tenant_slug)


@app.get("/protected")
async def protected(user: AxiamUser = Depends(authenticated_user)) -> dict[str, object]:  # noqa: B008
    """A route guarded by the FastAPI dependency — reaching this handler
    means the caller's token was verified locally and matched the
    configured tenant (T-19-19 cross-tenant replay defense)."""
    return {
        "message": f"Hello, user {user.user_id} (tenant {user.tenant_id})",
        "roles": user.roles,
    }


# require_access(...) resolves the resource id from the {doc_id} path
# parameter (resource_param) — see CONTRACT.md §11.2.3 for the full
# resource_id/resource_param/resolver precedence.
require_doc_read = require_access(
    verifier, tenant_slug, authz_client, "documents:read", resource_param="doc_id"
)


@app.get("/docs/{doc_id}")
async def get_doc(
    doc_id: str,
    user: AxiamUser = Depends(require_doc_read),  # noqa: B008
) -> dict[str, object]:
    """A route guarded by require_access — reaching this handler means the
    caller is authenticated AND authorized (`documents:read`, checked with
    subject_id=user.user_id) for the given doc_id (CONTRACT.md §11)."""
    return {"message": f"user {user.user_id} may read document {doc_id}"}


# require_role(...) is a local, no-round-trip check against the verified
# identity's roles — no AsyncAxiamClient needed.
require_admin_role = require_role(verifier, tenant_slug, "admin")


@app.delete("/admin/cache")
async def reset_cache(user: AxiamUser = Depends(require_admin_role)) -> dict[str, object]:  # noqa: B008
    """A route guarded by require_role — reaching this handler means the
    caller's verified token carries the "admin" role. Coarser than
    require_access: it never calls the AXIAM server (CONTRACT.md §11.2.9)."""
    return {"message": f"cache reset by {user.user_id}"}
