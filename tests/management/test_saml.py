"""The ``saml`` management namespace — CONTRACT §29.8's eight required tests.

Failure messages print fixed text only, never a value under test.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pydantic
import pytest

from axiam_sdk import NetworkError
from axiam_sdk.management import (
    ConflictError,
    NotFoundError,
    PageRequest,
    ValidationError,
    models,
    saml_service_provider_input,
)
from tests.management_support import (
    BASE_URL,
    TENANT_ID,
    mount_json,
    with_async_client,
    with_client,
)

SAML = f"/api/v1/tenants/{TENANT_ID}/saml"


def sp_body(**extra: Any) -> dict[str, Any]:
    """A server ``SamlServiceProvider`` body."""
    body: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "tenant_id": TENANT_ID,
        "enabled": True,
        "display_name": "Payroll",
        "entity_id": "https://payroll.example/sp",
        "acs_urls": [
            {
                "url": "https://payroll.example/acs",
                "binding": "http_post",
                "index": 0,
                "is_default": True,
            }
        ],
        "slo_url": None,
        "slo_binding": None,
        "name_id_format": "persistent",
        "sign_responses": True,
        "encrypt_assertions": False,
        "sp_signing_cert_pem": None,
        "sp_encryption_cert_pem": None,
        "want_authn_requests_signed": False,
        "allow_idp_initiated": False,
        "attribute_mappings": [],
        "allowed_groups": [],
        "created_at": "2026-10-04T00:00:00Z",
        "updated_at": "2026-10-04T00:00:00Z",
    }
    body.update(extra)
    return body


def credential_body(status: str, **extra: Any) -> dict[str, Any]:
    """A server ``SamlIdpCredential`` body."""
    body: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "tenant_id": TENANT_ID,
        "issuer_ca_id": str(uuid.uuid4()),
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "serial": "0a1b",
        "fingerprint": "ab" * 32,
        "not_before": "2026-10-04T00:00:00Z",
        "not_after": "2027-10-04T00:00:00Z",
        "status": status,
        "created_at": "2026-10-04T00:00:00Z",
        "retired_at": None,
    }
    body.update(extra)
    return body


def sp_input() -> models.SamlServiceProviderInput:
    """A minimal ``SamlServiceProviderInput``: the three required members."""
    return models.SamlServiceProviderInput(
        acs_urls=[
            models.AcsEndpoint(
                binding="http_post", index=0, is_default=True, url="https://payroll.example/acs"
            )
        ],
        display_name="Payroll",
        entity_id="https://payroll.example/sp",
    )


def sent(route: Any, index: int = 0) -> Any:
    """The JSON body of the ``index``-th request a route saw."""
    return json.loads(route.calls[index].request.content)


# ── 1. Replacement ───────────────────────────────────────────────────────────


def test_update_service_provider_puts_the_whole_registration() -> None:
    """Read-modify-write sends every member; the input needs its three."""
    with pytest.raises(pydantic.ValidationError):
        models.SamlServiceProviderInput(display_name="x", entity_id="y")  # type: ignore[call-arg]
    sp_id = str(uuid.uuid4())
    with with_client() as (router, client):
        route = mount_json(router, "PUT", f"{SAML}/service-providers/{sp_id}", 200, sp_body())
        current = models.SamlServiceProvider.model_validate(sp_body())
        body = saml_service_provider_input(current)
        body.display_name = "Payroll (EU)"
        sp = client.saml.update_service_provider(sp_id, body)
        assert isinstance(sp, models.SamlServiceProvider)
        assert sp.entity_id == "https://payroll.example/sp"
        wire = sent(route)
        assert route.calls[0].request.method == "PUT"
        for member in models.SamlServiceProviderInput.model_fields:
            assert member in wire, member
        assert wire["display_name"] == "Payroll (EU)"


# ── 2. No signing switch, open decoding ──────────────────────────────────────


def test_sign_assertions_does_not_exist_and_unknown_values_decode() -> None:
    """Decode the unknowns; re-encode sends no ``sign_assertions`` and no extra."""
    assert "sign_assertions" not in models.SamlServiceProvider.model_fields
    assert "sign_assertions" not in models.SamlServiceProviderInput.model_fields
    sp_id = str(uuid.uuid4())
    body = sp_body(sign_assertions=False, some_future_member=1)
    body["acs_urls"][0]["binding"] = "http_artifact"
    with with_client() as (router, client):
        mount_json(router, "GET", f"{SAML}/service-providers/{sp_id}", 200, body)
        put = mount_json(router, "PUT", f"{SAML}/service-providers/{sp_id}", 200, sp_body())
        sp = client.saml.get_service_provider(sp_id)
        assert sp.acs_urls[0].binding == "http_artifact"
        replacement = saml_service_provider_input(sp)
        with pytest.raises(ValidationError):
            client.saml.update_service_provider(sp_id, replacement)
        assert put.call_count == 0, "an unknown value is never sent"
        replacement.acs_urls[0].binding = "http_post"
        client.saml.update_service_provider(sp_id, replacement)
        wire = sent(put)
        assert "sign_assertions" not in wire
        assert "some_future_member" not in wire


# ── 3. Draft round trip ──────────────────────────────────────────────────────


def test_parse_sp_metadata_sends_exactly_one_member_and_the_draft_creates() -> None:
    """Exactly one member, both-or-neither refused locally, the draft accepted."""
    draft = {
        "service_provider": {
            "display_name": "Imported",
            "entity_id": "https://imported.example/sp",
            "acs_urls": [
                {
                    "url": "https://imported.example/acs",
                    "binding": "http_post",
                    "index": 1,
                    "is_default": False,
                }
            ],
            "want_authn_requests_signed": True,
            "sp_signing_cert_pem": (
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            ),
        },
        "signing_certificate_fingerprint": "cd" * 32,
        "encryption_certificate_fingerprint": None,
        "warnings": ["the metadata's signature was not evaluated"],
    }
    with with_client() as (router, client):
        parsed = mount_json(router, "POST", f"{SAML}/parse-sp-metadata", 200, draft)
        created = mount_json(router, "POST", f"{SAML}/service-providers", 201, sp_body())
        from_url = client.saml.parse_sp_metadata(
            models.ParseSamlSpMetadata.from_url("https://imported.example/metadata")
        )
        client.saml.parse_sp_metadata(models.ParseSamlSpMetadata.from_xml("<EntityDescriptor/>"))
        for both_or_neither in (
            models.ParseSamlSpMetadata(metadata_url="https://a", metadata_xml="<x/>"),
            models.ParseSamlSpMetadata(),
        ):
            with pytest.raises(ValidationError):
                client.saml.parse_sp_metadata(both_or_neither)
        assert parsed.call_count == 2, "the refused calls sent nothing"
        assert sent(parsed, 0) == {"metadata_url": "https://imported.example/metadata"}
        assert sent(parsed, 1) == {"metadata_xml": "<EntityDescriptor/>"}

        assert from_url.warnings == ["the metadata's signature was not evaluated"]
        client.saml.create_service_provider(from_url.service_provider)
        assert sent(created) == draft["service_provider"]


# ── 4. Credentials carry no key ──────────────────────────────────────────────


def test_a_credential_has_no_key_member_and_promotion_may_retire_nothing() -> None:
    """A leaked ``private_key_pem`` is dropped; ``retired: null`` decodes."""
    leaked = f"-----BEGIN PRIVATE KEY-----{uuid.uuid4().hex}"
    cred_id = str(uuid.uuid4())
    with with_client() as (router, client):
        mount_json(
            router,
            "POST",
            f"{SAML}/idp-credentials/{cred_id}/retire",
            200,
            credential_body("retired", private_key_pem=leaked),
        )
        mount_json(
            router,
            "POST",
            f"{SAML}/idp-credentials/{cred_id}/promote",
            200,
            {"active": credential_body("active"), "retired": None},
        )
        credential = client.saml.retire_idp_credential(cred_id)
        for rendering in (repr(credential), str(credential), credential.model_dump_json()):
            if leaked in rendering or "private_key_pem" in rendering:
                pytest.fail("a credential rendering carried key material")
        assert "private_key_pem" not in models.SamlIdpCredential.model_fields
        assert not hasattr(credential, "private_key_pem")
        promotion = client.saml.promote_idp_credential(cred_id)
        assert promotion.retired is None
        assert promotion.active.status == "active"


# ── 5. Pagination ────────────────────────────────────────────────────────────


def test_service_providers_page_with_search_and_credentials_are_a_plain_list() -> None:
    """``Page`` with ``total``; ``search`` on every request; a plain list."""
    with with_client() as (router, client):

        def page(request: httpx.Request) -> httpx.Response:
            """Two one-item pages, then an empty one."""
            offset = int(request.url.params.get("offset", "0"))
            items = [sp_body()] if offset < 2 else []
            return httpx.Response(
                200, json={"items": items, "total": 2, "offset": offset, "limit": 1}
            )

        listing = router.get(f"{BASE_URL}{SAML}/service-providers").mock(side_effect=page)
        mount_json(
            router,
            "GET",
            f"{SAML}/idp-credentials",
            200,
            [credential_body("next"), credential_body("active")],
        )
        first = client.saml.list_service_providers(PageRequest(limit=1, search="payroll"))
        assert first.total == 2
        everything = client.saml.list_service_providers_all(PageRequest(limit=1, search="payroll"))
        assert len(everything) == 2
        assert listing.call_count >= 3
        for call in listing.calls:
            assert call.request.url.params.get("search") == "payroll"
        credentials = client.saml.list_idp_credentials()
        assert isinstance(credentials, list) and len(credentials) == 2
        assert all(isinstance(c, models.SamlIdpCredential) for c in credentials)


# ── 6. No retry ──────────────────────────────────────────────────────────────


def test_none_of_the_seven_writes_is_retried_on_503() -> None:
    """A retry-enabled client: exactly one request each, ``NetworkError``."""
    item = str(uuid.uuid4())
    with with_client() as (router, client):
        assert client._retry_enabled
        routes = [
            mount_json(router, "POST", f"{SAML}/service-providers", 503, None),
            mount_json(router, "PUT", f"{SAML}/service-providers/{item}", 503, None),
            mount_json(router, "DELETE", f"{SAML}/service-providers/{item}", 503, None),
            mount_json(router, "POST", f"{SAML}/parse-sp-metadata", 503, None),
            mount_json(router, "POST", f"{SAML}/idp-credentials", 503, None),
            mount_json(router, "POST", f"{SAML}/idp-credentials/{item}/promote", 503, None),
            mount_json(router, "POST", f"{SAML}/idp-credentials/{item}/retire", 503, None),
        ]
        s = client.saml
        calls = [
            lambda: s.create_service_provider(sp_input()),
            lambda: s.update_service_provider(item, sp_input()),
            lambda: s.delete_service_provider(item),
            lambda: s.parse_sp_metadata(models.ParseSamlSpMetadata.from_url("https://m")),
            lambda: s.issue_idp_credential(
                models.IssueSamlIdpCredential(issuer_ca_id=str(uuid.uuid4()), slot="next")
            ),
            lambda: s.promote_idp_credential(item),
            lambda: s.retire_idp_credential(item),
        ]
        for call in calls:
            with pytest.raises(NetworkError):
                call()
        assert [r.call_count for r in routes] == [1] * 7


# ── 7. Errors ────────────────────────────────────────────────────────────────


def test_statuses_map_per_section_2() -> None:
    """409 on create and promote, 400 with its message, 404, and 503."""
    item = str(uuid.uuid4())
    with with_client() as (router, client):
        mount_json(
            router,
            "POST",
            f"{SAML}/service-providers",
            409,
            {"error": "conflict", "message": "entity_id"},
        )
        mount_json(
            router,
            "PUT",
            f"{SAML}/service-providers/{item}",
            400,
            {
                "error": "validation_error",
                "message": "entity_id is immutable: register a new service provider",
            },
        )
        mount_json(
            router,
            "GET",
            f"{SAML}/service-providers/{item}",
            404,
            {"error": "not_found", "message": "no"},
        )
        mount_json(
            router,
            "POST",
            f"{SAML}/idp-credentials/{item}/promote",
            409,
            {"error": "conflict", "message": "not next"},
        )
        mount_json(
            router,
            "POST",
            f"{SAML}/parse-sp-metadata",
            503,
            {"error": "service_unavailable", "message": "saml"},
        )
        s = client.saml
        with pytest.raises(ConflictError):
            s.create_service_provider(sp_input())
        with pytest.raises(ValidationError) as invalid:
            s.update_service_provider(item, sp_input())
        assert "immutable" in invalid.value.message
        with pytest.raises(NotFoundError):
            s.get_service_provider(item)
        with pytest.raises(ConflictError):
            s.promote_idp_credential(item)
        with pytest.raises(NetworkError) as unavailable:
            s.parse_sp_metadata(models.ParseSamlSpMetadata.from_url("https://m"))
        assert not isinstance(unavailable.value, ValidationError)


# ── 8. Readiness is read, not cached ─────────────────────────────────────────


def test_get_idp_is_never_cached_and_keeps_null_apart_from_absent() -> None:
    """Two calls, two requests; the configured tenant in the path; null kept."""
    active = str(uuid.uuid4())
    body = {
        "tenant_id": TENANT_ID,
        "saml_available": True,
        "saml_idp_enabled": False,
        "metadata_served": True,
        "entity_id": "https://iam.example/saml/v2/t",
        "metadata_url": "https://iam.example/saml/v2/t/metadata",
        "sso_url": "https://iam.example/saml/v2/t/sso",
        "slo_url": "https://iam.example/saml/v2/t/slo",
        "active_credential_id": active,
        "next_credential_id": None,
    }
    with with_client() as (router, client):
        route = mount_json(router, "GET", f"{SAML}/idp", 200, body)
        info = client.saml.get_idp()
        client.saml.get_idp()
        assert route.call_count == 2, "two calls, two requests"
        assert route.calls[0].request.url.path == f"{SAML}/idp"
    assert info.active_credential_id == active
    assert info.next_credential_id is None and info.has_member("next_credential_id")
    assert info.saml_available and info.metadata_served and not info.saml_idp_enabled

    without = models.SamlIdpInfo.model_validate(
        {k: v for k, v in body.items() if k not in ("active_credential_id", "next_credential_id")}
    )
    assert without.next_credential_id is None
    assert not without.has_member("next_credential_id"), "absent stays absent"
    assert not without.has_member("active_credential_id")


@pytest.mark.asyncio
async def test_the_async_handle_refuses_both_or_neither_too() -> None:
    """The precheck lives in the shared call builder."""
    async with with_async_client() as (router, client):
        parsed = mount_json(router, "POST", f"{SAML}/parse-sp-metadata", 200, {})
        with pytest.raises(ValidationError):
            await client.saml.parse_sp_metadata(models.ParseSamlSpMetadata())
        assert parsed.call_count == 0
