"""Regression tests for the Django declarative authorization view decorators
``require_auth``/``require_access``/``require_role`` (CONTRACT.md §11,
``axiam_sdk.django.decorators``).

These decorators read ``request.axiam_user`` — set by
:class:`~axiam_sdk.django.middleware.AxiamAuthMiddleware` — and never
perform their own token extraction/verification, so tests build the request
directly (via ``request.axiam_user = ...``) rather than re-deriving identity
from a real token, mirroring ``test_django_middleware.py``'s separation of
concerns. The authorization check itself (``require_access``) is exercised
against a real :class:`~axiam_sdk.AxiamClient` with its
``/api/v1/authz/check`` endpoint mocked via ``respx`` (no live AXIAM
server).

Verifies the full CONTRACT.md §11 matrix:
  - allow -> 200; deny (``allowed: false``) -> 403 ``authorization_denied``;
  - a 403 from the server itself (``AuthzError``) -> 403
    ``authorization_denied``;
  - ``request.axiam_user`` absent (middleware not installed / request never
    authenticated) -> 401 ``authentication_failed`` with an installation
    hint, no authz call is ever made;
  - a missing/unparseable resource id -> 400 ``invalid_request``, no authz
    call is ever made;
  - a transport failure calling the authz endpoint (server 500) -> 503
    ``authz_unavailable``, fail closed;
  - ``subject_id`` on the wire is the authenticated user's ``user_id``;
  - ``scope`` passthrough;
  - no raw token value ever appears in any response body;
  - both sync and async views are supported;
  - ``require_role`` is a local check (no authz-endpoint call at all).
"""

from __future__ import annotations

import json
from typing import Any

import django
import httpx
import pytest
import respx
from asgiref.sync import iscoroutinefunction
from django.conf import settings as django_settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory

if not django_settings.configured:
    # Same settings ``test_django_middleware.py`` configures with — Django
    # settings are configured exactly once per process, so whichever test
    # module's import runs first must supply everything every other module
    # needs (AXIAM_JWKS_BASE_URL/AXIAM_TENANT_SLUG for AxiamAuthMiddleware's
    # own construction in that sibling module).
    django_settings.configure(
        DEBUG=True,
        USE_TZ=True,
        AXIAM_JWKS_BASE_URL="https://axiam.example.test",
        AXIAM_TENANT_SLUG="acme",
    )
    django.setup()

from axiam_sdk import AxiamClient  # noqa: E402
from axiam_sdk.django.decorators import require_access, require_auth, require_role  # noqa: E402
from axiam_sdk.django.middleware import AxiamUser  # noqa: E402

BASE_URL = "https://axiam.example.test"
RESOURCE_ID = "11111111-1111-1111-1111-111111111111"


def _authenticated_request(
    factory: RequestFactory,
    path: str = "/",
    *,
    user_id: str = "user-1",
    roles: list[str] | None = None,
) -> HttpRequest:
    request = factory.get(path)
    request.axiam_user = AxiamUser(user_id=user_id, tenant_id="acme", roles=roles or [])  # type: ignore[attr-defined]
    return request


def _unauthenticated_request(factory: RequestFactory, path: str = "/") -> HttpRequest:
    return factory.get(path)


def _sync_view(request: HttpRequest, **kwargs: Any) -> HttpResponse:
    return JsonResponse({"user_id": request.axiam_user.user_id, **kwargs})  # type: ignore[attr-defined]


async def _async_view(request: HttpRequest, **kwargs: Any) -> HttpResponse:
    return JsonResponse({"user_id": request.axiam_user.user_id, **kwargs})  # type: ignore[attr-defined]


# ---------------------------------------------------------------------
# require_auth
# ---------------------------------------------------------------------


def test_require_auth_passes_with_axiam_user_sync() -> None:
    view = require_auth(_sync_view)
    request = _authenticated_request(RequestFactory())

    response = view(request)

    assert response.status_code == 200
    assert json.loads(response.content)["user_id"] == "user-1"


def test_require_auth_401_without_axiam_user_sync() -> None:
    view = require_auth(_sync_view)
    request = _unauthenticated_request(RequestFactory())

    response = view(request)

    assert response.status_code == 401
    body = json.loads(response.content)
    assert body["error"] == "authentication_failed"
    assert "AxiamAuthMiddleware" in body["message"]


@pytest.mark.asyncio
async def test_require_auth_passes_with_axiam_user_async() -> None:
    view = require_auth(_async_view)
    assert iscoroutinefunction(view)
    request = _authenticated_request(RequestFactory())

    response = await view(request)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_require_auth_401_without_axiam_user_async() -> None:
    view = require_auth(_async_view)
    request = _unauthenticated_request(RequestFactory())

    response = await view(request)

    assert response.status_code == 401


# ---------------------------------------------------------------------
# require_access
# ---------------------------------------------------------------------


def test_require_access_allowed_yields_200(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_sync_view)
    request = _authenticated_request(RequestFactory())

    response = view(request, pk=RESOURCE_ID)

    assert response.status_code == 200
    client.close()


def test_require_access_subject_id_and_action_on_wire(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_sync_view)
    request = _authenticated_request(RequestFactory(), user_id="requesting-user-42")

    view(request, pk=RESOURCE_ID)

    sent = json.loads(route.calls.last.request.content)
    assert sent["subject_id"] == "requesting-user-42"
    assert sent["action"] == "documents:read"
    assert sent["resource_id"] == RESOURCE_ID
    assert "scope" not in sent
    client.close()


def test_require_access_scope_passthrough(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk", scope="field:email")(
        _sync_view
    )
    request = _authenticated_request(RequestFactory())

    view(request, pk=RESOURCE_ID)

    sent = json.loads(route.calls.last.request.content)
    assert sent["scope"] == "field:email"
    client.close()


def test_require_access_denied_yields_403(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": False, "reason": "no permission"})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_sync_view)
    request = _authenticated_request(RequestFactory())

    response = view(request, pk=RESOURCE_ID)

    assert response.status_code == 403
    assert json.loads(response.content)["error"] == "authorization_denied"
    client.close()


def test_require_access_server_403_yields_403(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_sync_view)
    request = _authenticated_request(RequestFactory())

    response = view(request, pk=RESOURCE_ID)

    assert response.status_code == 403
    assert json.loads(response.content)["error"] == "authorization_denied"
    client.close()


def test_require_access_unauthenticated_yields_401_no_authz_call(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_sync_view)
    request = _unauthenticated_request(RequestFactory())

    response = view(request, pk=RESOURCE_ID)

    assert response.status_code == 401
    assert not route.called
    client.close()


def test_require_access_bad_uuid_yields_400_no_authz_call(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_sync_view)
    request = _authenticated_request(RequestFactory())

    response = view(request, pk="not-a-uuid")

    assert response.status_code == 400
    assert json.loads(response.content)["error"] == "invalid_request"
    assert not route.called
    client.close()


def test_require_access_missing_resource_param_yields_400(respx_mock: respx.MockRouter) -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="doc_id")(_sync_view)
    request = _authenticated_request(RequestFactory())

    response = view(request)

    assert response.status_code == 400
    assert json.loads(response.content)["error"] == "invalid_request"
    client.close()


def test_require_access_network_failure_fails_closed_503(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(500, json={"error": "boom"})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_sync_view)
    request = _authenticated_request(RequestFactory())

    response = view(request, pk=RESOURCE_ID)

    assert response.status_code == 503
    assert json.loads(response.content)["error"] == "authz_unavailable"
    client.close()


def test_require_access_default_resource_param_is_pk(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read")(_sync_view)
    request = _authenticated_request(RequestFactory())

    response = view(request, pk=RESOURCE_ID)

    assert response.status_code == 200
    sent = json.loads(route.calls.last.request.content)
    assert sent["resource_id"] == RESOURCE_ID
    client.close()


@pytest.mark.asyncio
async def test_require_access_async_view_allowed(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_async_view)
    assert iscoroutinefunction(view)
    request = _authenticated_request(RequestFactory())

    response = await view(request, pk=RESOURCE_ID)

    assert response.status_code == 200
    client.close()


@pytest.mark.asyncio
async def test_require_access_async_view_denied(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": False, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_async_view)
    request = _authenticated_request(RequestFactory())

    response = await view(request, pk=RESOURCE_ID)

    assert response.status_code == 403
    client.close()


def test_require_access_no_token_value_in_response(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": False, "reason": None})
    )
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    view = require_access(client, "documents:read", resource_param="pk")(_sync_view)
    request = _authenticated_request(RequestFactory())
    request.META["HTTP_AUTHORIZATION"] = "Bearer super-secret-token-value"

    response = view(request, pk=RESOURCE_ID)

    assert b"super-secret-token-value" not in response.content
    client.close()


# ---------------------------------------------------------------------
# require_role
# ---------------------------------------------------------------------


def test_require_role_allows_matching_role() -> None:
    view = require_role("admin", "auditor")(_sync_view)
    request = _authenticated_request(RequestFactory(), roles=["auditor"])

    response = view(request)

    assert response.status_code == 200


def test_require_role_denies_missing_role() -> None:
    view = require_role("admin")(_sync_view)
    request = _authenticated_request(RequestFactory(), roles=["reader"])

    response = view(request)

    assert response.status_code == 403
    assert json.loads(response.content)["error"] == "authorization_denied"


def test_require_role_unauthenticated_yields_401() -> None:
    view = require_role("admin")(_sync_view)
    request = _unauthenticated_request(RequestFactory())

    response = view(request)

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_require_role_async_view() -> None:
    view = require_role("admin")(_async_view)
    assert iscoroutinefunction(view)
    request = _authenticated_request(RequestFactory(), roles=["admin"])

    response = await view(request)

    assert response.status_code == 200
