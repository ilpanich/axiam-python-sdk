"""The ``scim_targets`` management namespace — CONTRACT §31.8's six required tests.

The credential is generated at run time; failure messages print offsets and
fixed text only.
"""

from __future__ import annotations

import json
import secrets
import uuid
from typing import Any

import httpx
import pydantic
import pytest
from pydantic import SecretStr

from axiam_sdk import AuthError, NetworkError
from axiam_sdk.management import (
    ConflictError,
    NotFoundError,
    PageRequest,
    ValidationError,
    models,
    scim_target_input,
)
from tests.management_support import BASE_URL, TENANT_ID, mount_json, with_client

TARGETS = "/api/v1/scim-targets"


def credential() -> str:
    """A credential made at run time."""
    return f"scim-{secrets.token_urlsafe(24)}"


def assert_no_fragment(haystack: str, secret: str) -> None:
    """No 8-character substring of ``secret`` in ``haystack`` (offset-only failure)."""
    for i in range(len(secret) - 7):
        if secret[i : i + 8] in haystack:
            pytest.fail(f"an 8-character fragment of the secret (offset {i}) was rendered")


def target_body(**extra: Any) -> dict[str, Any]:
    """A server ``ScimTargetResponse`` body."""
    body: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "tenant_id": TENANT_ID,
        "name": "Downstream",
        "base_url": "https://idp.example/scim/v2",
        "enabled": True,
        "auth": {"type": "bearer"},
        "scope": {"type": "all_users"},
        "push_groups": False,
        "user_name_from": "username",
        "deprovision": "deactivate",
        "created_at": "2026-10-05T00:00:00Z",
        "updated_at": "2026-10-05T00:00:00Z",
        "state": {
            "last_success_at": None,
            "last_failure_at": None,
            "last_failure_reason": None,
            "consecutive_failures": 0,
            "dead_lettered_total": 0,
            "last_reconciled_at": None,
        },
    }
    body.update(extra)
    return body


def target_input(secret: str | None = None) -> models.ScimTargetInput:
    """A ``ScimTargetInput`` with the four required members (and a credential)."""
    body = models.ScimTargetInput(
        auth=models.ScimTargetAuthBearer(type="bearer"),
        base_url="https://idp.example/scim/v2",
        name="Downstream",
        scope=models.ScimTargetScopeAllUsers(type="all_users"),
    )
    if secret is not None:
        body.credential = SecretStr(secret)
    return body


def sent(route: Any, index: int = 0) -> Any:
    """The JSON body of the ``index``-th request a route saw."""
    return json.loads(route.calls[index].request.content)


# ── 1. Redaction ─────────────────────────────────────────────────────────────


def test_the_credential_is_on_the_wire_and_in_no_rendering() -> None:
    """The input and an error raised by ``create`` hold no fragment of it."""
    c = credential()
    body = target_input(c)
    for rendering in (repr(body), str(body), body.model_dump_json()):
        assert_no_fragment(rendering, c)
    with with_client() as (router, client):
        route = mount_json(
            router,
            "POST",
            TARGETS,
            400,
            {"error": "validation_error", "message": "base_url: not https"},
        )
        with pytest.raises(ValidationError) as excinfo:
            client.scim_targets.create(body)
        assert_no_fragment(f"{excinfo.value} {excinfo.value!r}", c)
        if sent(route)["credential"] != c:
            pytest.fail("the credential was not on the wire")


# ── 2. No credential on the response ─────────────────────────────────────────


def test_a_credential_in_a_response_is_dropped() -> None:
    """Neither the response nor an unknown ``auth`` arm keeps it."""
    leaked = credential()
    target_id = str(uuid.uuid4())
    with with_client() as (router, client):
        mount_json(
            router,
            "GET",
            f"{TARGETS}/{target_id}",
            200,
            target_body(credential=leaked, auth={"type": "mtls", "credential": leaked}),
        )
        target = client.scim_targets.get(target_id)
    for rendering in (repr(target), str(target)):
        assert_no_fragment(rendering, leaked)
    assert "credential" not in models.ScimTargetResponse.model_fields
    assert not hasattr(target, "credential")
    assert isinstance(target.auth, models.ScimTargetAuthUnknown)
    assert "credential" not in (target.auth.model_extra or {})
    with pytest.raises(pydantic.ValidationError):
        models.ScimTargetAuthUnknown.model_validate("not an object")


# ── 3. Replacement and the omitted credential ────────────────────────────────


def test_update_without_a_credential_sends_no_key_and_the_variants_keep_their_shape() -> None:
    """No ``credential`` key when absent; the four arms serialize exactly."""
    with pytest.raises(pydantic.ValidationError):
        models.ScimTargetInput(name="x", base_url="https://x")  # type: ignore[call-arg]
    c = credential()
    target_id = str(uuid.uuid4())
    with with_client() as (router, client):
        route = mount_json(router, "PUT", f"{TARGETS}/{target_id}", 200, target_body())
        client.scim_targets.update(target_id, target_input())
        client.scim_targets.update(target_id, target_input(c))
        assert "credential" not in sent(route, 0)
        if sent(route, 1)["credential"] != c:
            pytest.fail("the credential was not on the wire")

    shapes = [
        (models.ScimTargetAuthBearer(type="bearer"), {"type": "bearer"}),
        (
            models.ScimTargetAuthOauth2ClientCredentials(
                type="oauth2_client_credentials",
                client_id="axiam",
                scope="scim",
                token_url="https://idp.example/token",
            ),
            {
                "type": "oauth2_client_credentials",
                "client_id": "axiam",
                "scope": "scim",
                "token_url": "https://idp.example/token",
            },
        ),
        (models.ScimTargetScopeAllUsers(type="all_users"), {"type": "all_users"}),
        (
            models.ScimTargetScopeGroups(type="groups", group_ids=[str(uuid.UUID(int=0))]),
            {"type": "groups", "group_ids": [str(uuid.UUID(int=0))]},
        ),
    ]
    for model, wire in shapes:
        assert model.to_wire() == wire


# ── 4. Open decoding and pagination ──────────────────────────────────────────


def test_unknown_values_decode_and_the_pager_carries_search() -> None:
    """Unknown ``auth.type``, enums and failure reason; ``state: null``."""
    odd = target_body(
        auth={"type": "mtls", "certificate_id": str(uuid.uuid4())},
        deprovision="archive",
        user_name_from="employee_number",
        state=None,
    )
    failing = target_body(
        state={
            "last_success_at": None,
            "last_failure_at": "2026-10-05T01:00:00Z",
            "last_failure_reason": "a reason this SDK has never seen",
            "consecutive_failures": 3,
            "dead_lettered_total": 1,
            "last_reconciled_at": None,
        }
    )

    def page(request: httpx.Request) -> httpx.Response:
        """``odd``, then ``failing``, then nothing."""
        offset = int(request.url.params.get("offset", "0"))
        items = {0: [odd], 1: [failing]}.get(offset, [])
        return httpx.Response(200, json={"items": items, "total": 2, "offset": offset, "limit": 1})

    with with_client() as (router, client):
        listing = router.get(f"{BASE_URL}{TARGETS}").mock(side_effect=page)
        first = client.scim_targets.list(PageRequest(limit=1, search="downstream"))
        assert first.total == 2
        item = first.items[0]
        assert isinstance(item.auth, models.ScimTargetAuthUnknown)
        assert item.auth.type == "mtls"
        assert item.deprovision == "archive"
        assert item.user_name_from == "employee_number"
        assert item.state is None
        everything = client.scim_targets.list_all(PageRequest(limit=1, search="downstream"))
        assert everything[1].state is not None
        assert everything[1].state.last_failure_reason == "a reason this SDK has never seen"
        for call in listing.calls:
            assert call.request.url.params.get("search") == "downstream"

        # An unknown arm or enum value decodes, converts, and is never sent.
        put = mount_json(router, "PUT", f"{TARGETS}/{item.id}", 200, target_body())
        with pytest.raises(ValidationError):
            client.scim_targets.update(item.id, scim_target_input(item))
        assert put.call_count == 0


# ── 5. No retry ──────────────────────────────────────────────────────────────


def test_no_write_is_retried_on_503() -> None:
    """``create``, ``update``, ``delete``, ``reconcile``: one request each."""
    target_id = str(uuid.uuid4())
    with with_client() as (router, client):
        assert client._retry_enabled
        routes = [
            mount_json(router, "POST", TARGETS, 503, None),
            mount_json(router, "PUT", f"{TARGETS}/{target_id}", 503, None),
            mount_json(router, "DELETE", f"{TARGETS}/{target_id}", 503, None),
            mount_json(router, "POST", f"{TARGETS}/{target_id}/reconcile", 503, None),
        ]
        t = client.scim_targets
        for call in (
            lambda: t.create(target_input(credential())),
            lambda: t.update(target_id, target_input()),
            lambda: t.delete(target_id),
            lambda: t.reconcile(target_id),
        ):
            with pytest.raises(NetworkError):
                call()
        assert [r.call_count for r in routes] == [1, 1, 1, 1]


# ── 6. Errors and reconcile ──────────────────────────────────────────────────


def test_statuses_map_and_reconcile_is_a_bodyless_202() -> None:
    """400/409/404/401, and ``reconcile`` sends no body and decodes the 202."""
    target_id = str(uuid.uuid4())
    other = str(uuid.uuid4())
    with with_client() as (router, client):
        mount_json(
            router,
            "POST",
            TARGETS,
            400,
            {"error": "validation_error", "message": "credential: required on create"},
        )
        mount_json(
            router,
            "PUT",
            f"{TARGETS}/{target_id}",
            409,
            {"error": "conflict", "message": "the SCIM target changed since it was read"},
        )
        mount_json(
            router,
            "POST",
            f"{TARGETS}/{other}/reconcile",
            409,
            {"error": "conflict", "message": "a run holds the claim"},
        )
        mount_json(
            router, "GET", f"{TARGETS}/{target_id}", 404, {"error": "not_found", "message": "no"}
        )
        mount_json(
            router,
            "DELETE",
            f"{TARGETS}/{target_id}",
            401,
            {"error": "unauthorized", "message": "human only"},
        )
        mount_json(router, "POST", "/api/v1/auth/refresh", 401, {"error": "unauthorized"})
        reconcile = mount_json(
            router,
            "POST",
            f"{TARGETS}/{target_id}/reconcile",
            202,
            {"target_id": target_id, "status": "started"},
        )
        t = client.scim_targets
        with pytest.raises(ValidationError) as invalid:
            t.create(target_input())
        assert "credential" in invalid.value.message
        with pytest.raises(ConflictError):
            t.update(target_id, target_input())
        with pytest.raises(ConflictError):
            t.reconcile(other)
        with pytest.raises(NotFoundError):
            t.get(target_id)
        with pytest.raises(AuthError):
            t.delete(target_id)

        accepted = t.reconcile(target_id)
        assert accepted.target_id == target_id
        assert accepted.status == "started"
        assert reconcile.calls[0].request.content == b"", "reconcile sends no body"


def test_a_read_converts_into_the_replacement_body_without_a_credential() -> None:
    """Every member carried over; the credential absent."""
    target = models.ScimTargetResponse.model_validate(target_body())
    body = scim_target_input(target)
    assert body.credential is None and not body.has_member("credential")
    assert body.base_url == target.base_url
    wire = body.to_wire()
    assert "credential" not in wire
    assert wire["auth"] == {"type": "bearer"}
    assert wire["scope"] == {"type": "all_users"}
