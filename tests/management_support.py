"""Shared scaffolding for the CONTRACT §27 management tests.

The generated conformance suite (``test_management_surface_generated.py``) and
the hand-written semantics suites in ``tests/management/`` both build a client
the same way: a real ``login()`` against a mocked endpoint, so the org and tenant
UUIDs the management routes interpolate come from the access token's claims
exactly as they would in production, rather than being poked into private
attributes by the test.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import httpx
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient

BASE_URL = "https://management.test"
"""The origin every management test mounts routes against."""

ORG_ID = "22222222-2222-4222-8222-222222222222"
"""The organization UUID the test client's access token carries."""

TENANT_ID = "33333333-3333-4333-8333-333333333333"
"""The tenant UUID the test client's access token carries."""

EXAMPLE_ID = "11111111-1111-4111-8111-111111111111"
"""The identifier the generated cases pass for every ``{..._id}`` path parameter."""

TENANT_SLUG = "acme"
"""The slug the client is built with, and sends as ``X-Tenant-ID`` (§5 rule 2)."""

_REGISTRY = json.loads(
    (Path(__file__).resolve().parent.parent / "management-registry.json").read_text()
)


def expected_surface() -> list[str]:
    """Every ``namespace.operation`` the registry declares, sorted.

    Read from the registry rather than restated here, so a registry that grows an
    operation fails the generated suite until the surface is regenerated.
    """
    return sorted(
        f"{namespace}.{operation}"
        for namespace, nsdef in _REGISTRY["namespaces"].items()
        for operation in nsdef["operations"]
    )


def access_token(*, org_id: str = ORG_ID, tenant_id: str = TENANT_ID) -> str:
    """A structurally-valid unsigned JWT carrying the claims the client reads.

    Signature verification is not this layer's job (``_jwks.py`` owns it); what
    matters here is that ``org_id`` and ``tenant_id`` reach the client through
    the same unverified-claims decode a real login uses.
    """
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    claims = {
        "sub": "user-1",
        "tenant_id": tenant_id,
        "org_id": org_id,
        "jti": "session-uuid-1",
        "exp": 9999999999,
    }
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.fake-signature"


def mount_login(router: respx.MockRouter, **claims: str) -> None:
    """Mock ``POST /api/v1/auth/login`` so a client can reach an authenticated state."""
    router.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[
                ("Set-Cookie", f"axiam_access={access_token(**claims)}; Path=/; HttpOnly"),
            ],
        )
    )


def mount_json(
    router: respx.MockRouter, method: str, path: str, status: int, body: Any
) -> respx.Route:
    """Mount one management route, answering ``body`` at ``status``.

    The route is matched on method **and** exact path, so an operation that sends
    its request somewhere other than the registry's path fails here rather than
    falling through to another mock.
    """
    return router.request(method, f"{BASE_URL}{path}").mock(
        return_value=httpx.Response(status) if body is None else httpx.Response(status, json=body)
    )


@contextmanager
def with_client(**claims: str) -> Iterator[tuple[respx.MockRouter, AxiamClient]]:
    """A logged-in sync client and the router its requests are matched against."""
    with respx.mock(assert_all_called=False) as router:
        mount_login(router, **claims)
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        client.login("admin@example.test", "password123")
        try:
            yield router, client
        finally:
            client.close()


@asynccontextmanager
async def with_async_client(
    **claims: str,
) -> AsyncIterator[tuple[respx.MockRouter, AsyncAxiamClient]]:
    """A logged-in async client and the router its requests are matched against."""
    with respx.mock(assert_all_called=False) as router:
        mount_login(router, **claims)
        client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        await client.login("admin@example.test", "password123")
        try:
            yield router, client
        finally:
            await client.aclose()


@contextmanager
def anonymous_client() -> Iterator[tuple[respx.MockRouter, AxiamClient]]:
    """A client that has never logged in, for the §27.4 rule 1 refusals."""
    with respx.mock(assert_all_called=False) as router:
        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        try:
            yield router, client
        finally:
            client.close()
