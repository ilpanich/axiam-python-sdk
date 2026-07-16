"""django_middleware.py demonstrates registering
axiam_sdk.django.middleware.AxiamAuthMiddleware in a Django settings/urls
snippet and reading request.axiam_user in a view (CONTRACT.md §10, D-10,
SC#4), and layering the declarative authorization view decorators
require_access(...)/require_role(...) (CONTRACT.md §11,
axiam_sdk.django.decorators) on top of it.

AxiamAuthMiddleware verifies the inbound session LOCALLY via a JWKS-backed
verifier (settings.AXIAM_JWKS_BASE_URL), enforces the configured-tenant
claim (settings.AXIAM_TENANT_SLUG), and attaches request.axiam_user on
success — or returns a standardized 401 JSON response before the view ever
runs. It declares sync_capable/async_capable so it works under WSGI
(primary target) or ASGI without Django forcing an unnecessary sync<->async
adaptation shim.

require_access(client, action, resource_param=..., scope=...) reads
request.axiam_user (never re-verifying the token itself) and calls the sync
AxiamClient's check_access(...) with subject_id set to the *authenticated
request's* user_id, never this client's own (typically service-account)
identity, for a resource resolved from the view's keyword arguments. Denied
-> 403; an unresolvable resource id -> 400; a transport failure while
calling the authz endpoint -> 503 (fail closed, CONTRACT.md §11.2.5); a
missing request.axiam_user (middleware not installed) -> 401.

require_role(*roles) is a local, no-round-trip check against the already-
verified identity's roles — cheaper but coarser than require_access, and
NOT a substitute for it (§11.2.9).

This example is illustrative/importable — it does not require a live AXIAM
server to byte-compile or import (SC#4). Serving real traffic requires the
configured AXIAM_JWKS_BASE_URL to be a reachable AXIAM server (for the
middleware's JWKS fetch and the authz check client).

This file is a runnable settings+urls+view snippet, not a full Django
project — wire it into a real project's settings.py/urls.py, or run it
standalone via `python examples/django_middleware.py` (uses
django.conf.settings.configure(...) so no manage.py/project scaffold is
required for illustration).
"""

from __future__ import annotations

import os

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.urls import path

from axiam_sdk import AxiamClient
from axiam_sdk.django.decorators import require_access, require_role


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="example-only-not-for-production",  # noqa: S105
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
        MIDDLEWARE=[
            # Register AxiamAuthMiddleware to guard every request behind it
            # (D-10). It attaches request.axiam_user on success.
            "axiam_sdk.django.middleware.AxiamAuthMiddleware",
        ],
        # Settings AxiamAuthMiddleware reads at construction time (§10):
        AXIAM_JWKS_BASE_URL=getenv("AXIAM_BASE_URL", "https://localhost:8443"),
        AXIAM_TENANT_SLUG=getenv("AXIAM_TENANT_SLUG", "acme"),
    )


def protected_view(request: HttpRequest) -> JsonResponse:
    """A view guarded by AxiamAuthMiddleware — reaching this handler means
    the caller's token was verified locally and matched the configured
    tenant (T-19-19 cross-tenant replay defense)."""
    user = request.axiam_user  # type: ignore[attr-defined]
    return JsonResponse(
        {
            "message": f"Hello, user {user.user_id} (tenant {user.tenant_id})",
            "roles": user.roles,
        }
    )


# The declarative require_access(...) decorator takes a sync AxiamClient
# (matching Django's synchronous view/middleware convention) used solely to
# issue the authz check — not the session that authenticated the caller.
authz_client = AxiamClient(
    base_url=getenv("AXIAM_BASE_URL", "https://localhost:8443"),
    tenant_slug=getenv("AXIAM_TENANT_SLUG", "acme"),
)


@require_access(authz_client, "documents:read", resource_param="doc_id")
def get_document(request: HttpRequest, doc_id: str) -> JsonResponse:
    """A view guarded by require_access — reaching this handler means the
    caller is authenticated AND authorized (`documents:read`, checked with
    subject_id=request.axiam_user.user_id) for the given doc_id
    (CONTRACT.md §11)."""
    user = request.axiam_user  # type: ignore[attr-defined]
    return JsonResponse({"message": f"user {user.user_id} may read document {doc_id}"})


@require_role("admin")
def reset_cache_view(request: HttpRequest) -> JsonResponse:
    """A view guarded by require_role — reaching this handler means the
    caller's verified identity carries the "admin" role. Coarser than
    require_access: it never calls the AXIAM server (CONTRACT.md
    §11.2.9)."""
    user = request.axiam_user  # type: ignore[attr-defined]
    return JsonResponse({"message": f"cache reset by {user.user_id}"})


urlpatterns = [
    path("protected", protected_view),
    path("docs/<uuid:doc_id>", get_document),
    path("admin/cache", reset_cache_view),
]


if __name__ == "__main__":
    import django
    from django.core.management import execute_from_command_line

    django.setup()
    execute_from_command_line(["manage.py", "runserver"])
