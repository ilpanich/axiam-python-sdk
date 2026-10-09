"""The ``directory`` management namespace — CONTRACT §30.8's six required tests.

The bind secret is generated at run time: a literal would be a credential in
the repository and would let a redaction test pass by coincidence. Failure
messages print offsets and fixed text only, never a secret or a rendering.
"""

from __future__ import annotations

import inspect
import json
import secrets
import uuid
from typing import Any

import pydantic
import pytest
from pydantic import SecretStr

from axiam_sdk import NetworkError
from axiam_sdk.management import (
    ConflictError,
    NotFoundError,
    ValidationError,
    models,
    set_directory_config,
)
from tests.management_support import TENANT_ID, mount_json, with_async_client, with_client

DIRECTORY = f"/api/v1/tenants/{TENANT_ID}/directory"


def bind_secret() -> str:
    """A bind secret made at run time."""
    return f"bind-{secrets.token_urlsafe(24)}"


def assert_no_fragment(haystack: str, secret: str) -> None:
    """No 8-character substring of ``secret`` in ``haystack`` (offset-only failure)."""
    for i in range(len(secret) - 7):
        if secret[i : i + 8] in haystack:
            pytest.fail(f"an 8-character fragment of the secret (offset {i}) was rendered")


def config_body(**extra: Any) -> dict[str, Any]:
    """A server ``DirectoryConfig`` body."""
    body: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "tenant_id": TENANT_ID,
        "enabled": True,
        "kind": "active_directory",
        "url": "ldaps://dc.corp.example",
        "start_tls": False,
        "bind_dn": "cn=svc,dc=corp",
        "base_dn": "dc=corp",
        "user_filter": "(sAMAccountName={username})",
        "user_attribute_map": {
            "username": "sAMAccountName",
            "email": "mail",
            "display_name": "displayName",
            "external_id": "objectGUID",
        },
        "group_base_dn": None,
        "group_filter": None,
        "group_member_attribute": "member",
        "group_nesting_depth": 5,
        "group_mappings": [],
        "sync_interval_secs": 3600,
        "jit_provisioning": False,
        "trust_anchors_pem": [],
        "created_at": "2026-10-04T00:00:00Z",
        "updated_at": "2026-10-04T00:00:00Z",
    }
    body.update(extra)
    return body


def set_body(secret: str | None = None) -> models.SetDirectoryConfig:
    """A ``SetDirectoryConfig`` with only the seven required members (and a secret)."""
    body = models.SetDirectoryConfig(
        base_dn="dc=corp",
        bind_dn="cn=svc,dc=corp",
        enabled=True,
        kind="active_directory",
        start_tls=False,
        url="ldaps://dc.corp.example",
        user_filter="(sAMAccountName={username})",
    )
    if secret is not None:
        body.bind_secret = SecretStr(secret)
    return body


def sent(route: Any, index: int = 0) -> Any:
    """The JSON body of the ``index``-th request a route saw."""
    return json.loads(route.calls[index].request.content)


# ── 1. Redaction ─────────────────────────────────────────────────────────────


def test_the_bind_secret_reaches_the_wire_and_no_rendering() -> None:
    """Both request types, and an error raised by ``set``, hold no fragment."""
    s = bind_secret()
    put = set_body(s)
    patch = models.UpdateDirectoryConfig(bind_secret=SecretStr(s))
    for rendering in (
        repr(put),
        str(put),
        put.model_dump_json(),
        repr(patch),
        str(patch),
        patch.model_dump_json(),
    ):
        assert_no_fragment(rendering, s)

    with with_client() as (router, client):
        route = mount_json(
            router,
            "PUT",
            DIRECTORY,
            400,
            {"error": "validation_error", "message": "url: plaintext LDAP is refused"},
        )
        with pytest.raises(ValidationError) as excinfo:
            client.directory.set(put)
        assert_no_fragment(f"{excinfo.value} {excinfo.value!r}", s)
        if sent(route)["bind_secret"] != s:
            pytest.fail("the bind secret was not on the wire")


# ── 2. No secret on the response ─────────────────────────────────────────────


def test_a_bind_secret_in_a_response_is_dropped() -> None:
    """The type declares no such member, so the decoder has nowhere to keep it."""
    leaked = bind_secret()
    with with_client() as (router, client):
        mount_json(router, "GET", DIRECTORY, 200, config_body(bind_secret=leaked))
        config = client.directory.get()
    for rendering in (repr(config), str(config), config.model_dump_json()):
        assert_no_fragment(rendering, leaked)
    assert "bind_secret" not in models.DirectoryConfig.model_fields
    assert not hasattr(config, "bind_secret")
    assert config.url == "ldaps://dc.corp.example"


# ── 3. Sparse update ─────────────────────────────────────────────────────────


def test_update_sends_exactly_the_members_it_was_given() -> None:
    """``{"enabled": false}``, two keys with the secret, and an explicit null."""
    s = bind_secret()
    with with_client() as (router, client):
        route = mount_json(router, "PATCH", DIRECTORY, 200, config_body())
        client.directory.update(models.UpdateDirectoryConfig(enabled=False))
        client.directory.update(
            models.UpdateDirectoryConfig(url="ldaps://dc2.corp.example", bind_secret=SecretStr(s))
        )
        client.directory.update(models.UpdateDirectoryConfig(group_filter=None))
        assert sent(route, 0) == {"enabled": False}
        second = sent(route, 1)
        assert sorted(second) == ["bind_secret", "url"]
        if second["bind_secret"] != s:
            pytest.fail("the bind secret was not on the wire")
        assert sent(route, 2) == {"group_filter": None}


def test_explicit_null_is_documented_and_readable_on_the_four_fields() -> None:
    """The name-listed fields say so; ``has_member`` tells null from absent."""
    for model in (models.UpdateDirectoryConfig, models.SamlIdpInfo):
        assert inspect.getsource(model).count("**``null`` is not absent**") == 2
    patch = models.UpdateDirectoryConfig(group_filter=None)
    assert patch.has_member("group_filter") and not patch.has_member("group_base_dn")
    assert patch.to_wire() == {"group_filter": None}


# ── 4. Replacement ───────────────────────────────────────────────────────────


def test_set_needs_its_seven_members_sends_them_and_decodes_201_and_200() -> None:
    """Pydantic refuses a half-built replacement; 201 and 200 both decode."""
    with pytest.raises(pydantic.ValidationError):
        models.SetDirectoryConfig(  # type: ignore[call-arg]
            base_dn="dc=corp", bind_dn="cn=svc", enabled=True, kind="open_ldap"
        )
    for status in (201, 200):
        with with_client() as (router, client):
            route = mount_json(router, "PUT", DIRECTORY, status, config_body())
            config = client.directory.set(set_body())
            assert config.enabled
            body = sent(route)
            for required in (
                "enabled",
                "kind",
                "url",
                "start_tls",
                "bind_dn",
                "base_dn",
                "user_filter",
            ):
                assert required in body, required
            assert "bind_secret" not in body, "absent keeps the stored secret"


# ── 5. No retry ──────────────────────────────────────────────────────────────


def test_no_write_is_retried_on_503() -> None:
    """``set``, ``update``, ``delete``, ``link_account``: one request each."""
    with with_client() as (router, client):
        assert client._retry_enabled
        routes = [
            mount_json(router, "PUT", DIRECTORY, 503, None),
            mount_json(router, "PATCH", DIRECTORY, 503, None),
            mount_json(router, "DELETE", DIRECTORY, 503, None),
            mount_json(router, "POST", f"{DIRECTORY}/links", 503, None),
        ]
        d = client.directory
        calls = [
            lambda: d.set(set_body(bind_secret())),
            lambda: d.update(models.UpdateDirectoryConfig()),
            d.delete,
            lambda: d.link_account(models.LinkDirectoryAccount(user_id=str(uuid.uuid4()))),
        ]
        for call in calls:
            with pytest.raises(NetworkError):
                call()
        assert [r.call_count for r in routes] == [1, 1, 1, 1]


# ── 6. Errors and link_account ───────────────────────────────────────────────


def test_errors_map_per_section_2_and_link_account_sends_only_the_user_id() -> None:
    """400/409/404, and the exact ``link_account`` body and result."""
    user = str(uuid.uuid4())
    with with_client() as (router, client):
        mount_json(
            router,
            "PUT",
            DIRECTORY,
            400,
            {
                "error": "validation_error",
                "message": "url: changing the connection requires entering the bind secret again",
            },
        )
        mount_json(router, "PATCH", DIRECTORY, 409, {"error": "conflict", "message": "opaque"})
        mount_json(router, "GET", DIRECTORY, 404, {"error": "not_found", "message": "none"})
        link = mount_json(
            router,
            "POST",
            f"{DIRECTORY}/links",
            200,
            {
                "user_id": user,
                "directory_external_id": "3f2a-objectguid",
                "webauthn_credentials_deleted": 2,
                "certificates_revoked": 1,
                "was_already_linked": False,
            },
        )
        with pytest.raises(ValidationError) as invalid:
            client.directory.set(set_body())
        assert "bind secret again" in invalid.value.message
        with pytest.raises(ConflictError):
            client.directory.update(models.UpdateDirectoryConfig(enabled=True))
        with pytest.raises(NotFoundError):
            client.directory.get()

        result = client.directory.link_account(models.LinkDirectoryAccount(user_id=user))
        assert sent(link) == {"user_id": user}
        assert result.user_id == user
        assert result.directory_external_id == "3f2a-objectguid"
        assert result.webauthn_credentials_deleted == 2
        assert result.certificates_revoked == 1
        assert result.was_already_linked is False


# ── Beyond the six ───────────────────────────────────────────────────────────


def test_sync_status_decodes_an_unknown_result_and_the_first_run_nulls() -> None:
    """``last_result`` is an open enum; the instants are null before a run."""
    with with_client() as (router, client):
        mount_json(
            router,
            "GET",
            f"{DIRECTORY}/sync-status",
            200,
            {
                "last_result": "something_new",
                "last_attempt_at": None,
                "last_full_run_at": None,
                "full_required": True,
                "has_watermark": False,
            },
        )
        status = client.directory.get_sync_status()
    assert status.last_result == "something_new"
    assert status.full_required and not status.has_watermark


def test_an_unknown_kind_decodes_but_is_never_sent() -> None:
    """§30.2's open enum: read it, but refuse to write it back, with no request."""
    with with_client() as (router, client):
        mount_json(router, "GET", DIRECTORY, 200, config_body(kind="freeipa"))
        put = mount_json(router, "PUT", DIRECTORY, 200, config_body())
        config = client.directory.get()
        assert config.kind == "freeipa"
        with pytest.raises(ValidationError) as excinfo:
            client.directory.set(set_directory_config(config))
        assert excinfo.value.fields[0].field == "kind"
        assert put.call_count == 0


def test_a_read_converts_into_the_replacement_body_without_a_secret() -> None:
    """The read-modify-write form: every member over, the secret absent."""
    config = models.DirectoryConfig.model_validate(config_body())
    body = set_directory_config(config)
    assert body.bind_secret is None and not body.has_member("bind_secret")
    assert body.url == config.url
    assert body.group_nesting_depth == 5
    assert body.sync_interval_secs == 3600
    assert "bind_secret" not in body.to_wire()


@pytest.mark.asyncio
async def test_the_async_handle_sends_the_same_sparse_body() -> None:
    """The async surface shares the call builder, and so the body."""
    async with with_async_client() as (router, client):
        route = mount_json(router, "PATCH", DIRECTORY, 200, config_body())
        await client.directory.update(models.UpdateDirectoryConfig(group_base_dn=None))
        assert sent(route) == {"group_base_dn": None}


# ── §34.2 P12.3: a write-only secret is present or absent, never null ───────


def test_an_assigned_none_secret_is_omitted_never_sent_as_null() -> None:
    """``bind_secret=None`` on either request type is "keep", not a third state:
    the member is absent from the wire, while a nullable non-secret member set
    to ``None`` still goes as ``null`` (§30.2, §34.2 P12.3)."""
    with with_client() as (router, client):
        put = mount_json(router, "PUT", DIRECTORY, 200, config_body())
        patch = mount_json(router, "PATCH", DIRECTORY, 200, config_body())
        body = set_body()
        body.bind_secret = None
        client.directory.set(body)
        client.directory.update(models.UpdateDirectoryConfig(bind_secret=None, group_filter=None))
        assert "bind_secret" not in sent(put), "null is not a third state"
        assert sent(patch) == {"group_filter": None}
