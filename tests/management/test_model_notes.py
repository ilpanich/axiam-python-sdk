"""CONTRACT §27.15 (contract 1.60): ``window_minutes`` on the notification
rules, and the ``federation`` configuration's ``allow_sha1_signatures``,
``idp_metadata_signing_cert_pem`` and ``update_config`` null rule (notes 1, 6,
7 and 8)."""

from __future__ import annotations

import base64
import inspect
import json
import secrets
from typing import Any

import pytest
from pydantic import SecretStr

from axiam_sdk.management import models
from tests.management_support import EXAMPLE_ID, mount_json, with_client

RULES = "/api/v1/notification-rules"
CONFIGS = "/api/v1/federation-configs"

#: The ten nullable members of ``UpdateFederationConfigRequest`` that an
#: explicit ``null`` clears (§27.15 note 8).
CLEARABLE = (
    "metadata_url",
    "idp_signing_cert_pem",
    "idp_metadata_signing_cert_pem",
    "provider_slug",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "apple_team_id",
    "apple_key_id",
    "button_icon",
)


def sent(route: Any, index: int = 0) -> Any:
    """The JSON body of the ``index``-th request a route saw."""
    return json.loads(route.calls[index].request.content)


def rule_body(**extra: Any) -> dict[str, Any]:
    """A server ``NotificationRuleResponse`` body."""
    body: dict[str, Any] = {
        "id": EXAMPLE_ID,
        "tenant_id": EXAMPLE_ID,
        "name": "Lockouts",
        "description": "",
        "enabled": True,
        "events": ["login_failure"],
        "recipient_emails": ["ops@example.test"],
        "created_at": "2026-10-05T00:00:00Z",
        "updated_at": "2026-10-05T00:00:00Z",
        "window_minutes": 15,
    }
    body.update(extra)
    return body


def config_body(**extra: Any) -> dict[str, Any]:
    """A server ``FederationConfigResponse`` body, from a 1.0.0 server unless
    ``extra`` removes members."""
    body: dict[str, Any] = {
        "id": EXAMPLE_ID,
        "tenant_id": EXAMPLE_ID,
        "provider": "corp-idp",
        "provider_kind": "saml",
        "protocol": "Saml",
        "client_id": "axiam",
        "enabled": True,
        "allow_sha1_signatures": False,
        "allow_tenant_inheritance": False,
        "allowed_algorithms": [],
        "allowed_issuer_tenants": [],
        "attribute_map": None,
        "effective_scopes": [],
        "has_bundled_mark": False,
        "mints_client_secret": False,
        "pkce_required": False,
        "scopes": [],
        "token_exchange": {
            "accepted_audiences": [],
            "enabled": False,
            "max_token_age_secs": 300,
            "scope_map": {},
            "subject_mapping": "email",
        },
        "created_at": "2026-10-05T00:00:00Z",
        "updated_at": "2026-10-05T00:00:00Z",
    }
    body.update(extra)
    return body


def create_fields() -> dict[str, Any]:
    """The required members of ``CreateFederationConfigRequest``, the client
    secret made at run time."""
    return {
        "provider": "corp-idp",
        "protocol": "Saml",
        "client_id": "axiam",
        "client_secret": SecretStr(secrets.token_urlsafe(24)),
    }


def pem() -> str:
    """A PEM-shaped certificate made at run time (the SDK never parses it)."""
    der = base64.b64encode(secrets.token_bytes(48)).decode()
    return f"-----BEGIN CERTIFICATE-----\n{der}\n-----END CERTIFICATE-----\n"


# ── note 1: window_minutes ───────────────────────────────────────────────────


def test_window_minutes_is_passed_through_never_clamped() -> None:
    """§27.15 note 1's required test: ``create`` with ``window_minutes`` sends it
    as given, ``create`` without it sends no such key, and a response carrying it
    decodes it. Out-of-range values go through unclamped -- the server's ``400``
    is the answer, not a silently different request -- and ``update`` is sparse."""
    with with_client() as (router, client):
        post = mount_json(router, "POST", RULES, 201, rule_body(window_minutes=60))
        put = mount_json(router, "PUT", f"{RULES}/{EXAMPLE_ID}", 200, rule_body())
        create = {
            "name": "Lockouts",
            "description": "",
            "events": ["login_failure"],
            "recipient_emails": ["ops@example.test"],
        }

        created = client.notification_rules.create(
            models.CreateNotificationRuleRequest(**create, window_minutes=60)
        )
        assert created.window_minutes == 60
        client.notification_rules.create(models.CreateNotificationRuleRequest(**create))
        for value in (0, 1441, -5):
            client.notification_rules.create(
                models.CreateNotificationRuleRequest(**create, window_minutes=value)
            )
        assert sent(post, 0)["window_minutes"] == 60
        assert "window_minutes" not in sent(post, 1)
        assert [sent(post, i)["window_minutes"] for i in (2, 3, 4)] == [0, 1441, -5]

        client.notification_rules.update(
            EXAMPLE_ID, models.UpdateNotificationRuleRequest(window_minutes=1441)
        )
        client.notification_rules.update(
            EXAMPLE_ID, models.UpdateNotificationRuleRequest(enabled=False)
        )
        assert sent(put, 0) == {"window_minutes": 1441}
        assert sent(put, 1) == {"enabled": False}


# ── note 6: allow_sha1_signatures ────────────────────────────────────────────


def test_allow_sha1_signatures_is_sent_only_when_set_and_absent_decodes_false() -> None:
    """§27.15 note 6: optional on create and update and sent only when the caller
    sets it; a response from a server before 1.0.0, which lacks it, decodes as
    ``False``."""
    older = config_body()
    del older["allow_sha1_signatures"]
    assert models.FederationConfigResponse.model_validate(older).allow_sha1_signatures is False
    decoded = models.FederationConfigResponse.model_validate(
        config_body(allow_sha1_signatures=True)
    )
    assert decoded.allow_sha1_signatures is True

    with with_client() as (router, client):
        post = mount_json(router, "POST", CONFIGS, 201, config_body())
        put = mount_json(router, "PUT", f"{CONFIGS}/{EXAMPLE_ID}", 200, older)
        create = create_fields()
        client.federation.create_config(models.CreateFederationConfigRequest(**create))
        client.federation.create_config(
            models.CreateFederationConfigRequest(**create, allow_sha1_signatures=True)
        )
        assert "allow_sha1_signatures" not in sent(post, 0)
        assert sent(post, 1)["allow_sha1_signatures"] is True

        updated = client.federation.update_config(
            EXAMPLE_ID, models.UpdateFederationConfigRequest(allow_sha1_signatures=False)
        )
        assert sent(put, 0) == {"allow_sha1_signatures": False}
        assert updated.allow_sha1_signatures is False


# ── note 7: idp_metadata_signing_cert_pem ────────────────────────────────────


def test_idp_metadata_signing_cert_pem_is_optional_nullable_and_sent_only_when_set() -> None:
    """§27.15 note 7: optional and nullable on the three models; sent only when the
    caller sets it; a response's ``null`` and its absence both decode."""
    cert = pem()
    with_cert = models.FederationConfigResponse.model_validate(
        config_body(idp_metadata_signing_cert_pem=cert)
    )
    assert with_cert.idp_metadata_signing_cert_pem == cert
    unset = models.FederationConfigResponse.model_validate(
        config_body(idp_metadata_signing_cert_pem=None)
    )
    assert unset.idp_metadata_signing_cert_pem is None
    assert unset.has_member("idp_metadata_signing_cert_pem")
    absent = models.FederationConfigResponse.model_validate(config_body())
    assert absent.idp_metadata_signing_cert_pem is None
    assert not absent.has_member("idp_metadata_signing_cert_pem")

    with with_client() as (router, client):
        post = mount_json(router, "POST", CONFIGS, 201, config_body())
        create = create_fields()
        client.federation.create_config(models.CreateFederationConfigRequest(**create))
        client.federation.create_config(
            models.CreateFederationConfigRequest(**create, idp_metadata_signing_cert_pem=cert)
        )
        assert "idp_metadata_signing_cert_pem" not in sent(post, 0)
        assert sent(post, 1)["idp_metadata_signing_cert_pem"] == cert


# ── note 8: an explicit null clears, an omitted member is left ──────────────


def test_federation_update_null_clears_and_unset_is_absent() -> None:
    """§27.15 note 8 with §27.4 rule 5's exact-key-set test: ``update_config``
    with only ``enabled = false`` sends exactly ``{"enabled":false}``; with
    ``idp_metadata_signing_cert_pem`` explicitly ``None`` it sends exactly
    ``{"idp_metadata_signing_cert_pem":null}``; with a certificate, exactly that
    key. Each of the ten nullable members, set to ``None`` alone, is sent as
    exactly that one ``null`` key."""
    cert = pem()
    with with_client() as (router, client):
        put = mount_json(router, "PUT", f"{CONFIGS}/{EXAMPLE_ID}", 200, config_body())
        update = client.federation.update_config
        update(EXAMPLE_ID, models.UpdateFederationConfigRequest(enabled=False))
        update(EXAMPLE_ID, models.UpdateFederationConfigRequest(idp_metadata_signing_cert_pem=None))
        update(EXAMPLE_ID, models.UpdateFederationConfigRequest(idp_metadata_signing_cert_pem=cert))
        assert put.calls[0].request.content == b'{"enabled":false}'
        assert put.calls[1].request.content == b'{"idp_metadata_signing_cert_pem":null}'
        assert sent(put, 2) == {"idp_metadata_signing_cert_pem": cert}

        for i, member in enumerate(CLEARABLE, start=3):
            body = models.UpdateFederationConfigRequest(**{member: None})
            assert body.has_member(member)
            update(EXAMPLE_ID, body)
            assert sent(put, i) == {member: None}, member

    # Unset and set-to-None are distinct states on every one of the ten.
    blank = models.UpdateFederationConfigRequest()
    assert not any(blank.has_member(member) for member in CLEARABLE)
    assert blank.to_wire() == {}


@pytest.mark.parametrize("member", CLEARABLE)
def test_each_clearable_member_documents_null_clears(member: str) -> None:
    """The ten members say, on the field, that ``None`` sends ``null``."""
    doc = models.UpdateFederationConfigRequest.__doc__ or ""
    source = inspect.getsource(models.UpdateFederationConfigRequest)
    assert "null`` is not absent" in source.split(f"    {member}:", 1)[1].split('"""', 2)[1]
    assert "sparse" in doc


def test_the_null_rule_is_documented_at_the_call_site() -> None:
    """``update_config`` on both handles repeats note 8."""
    from axiam_sdk.management.ops import federation

    for handle in (federation.FederationApi, federation.AsyncFederationApi):
        doc = " ".join((inspect.getdoc(handle.update_config) or "").split())
        assert "explicit ``None`` clears" in doc
        assert "§27.15 note 8" in doc
