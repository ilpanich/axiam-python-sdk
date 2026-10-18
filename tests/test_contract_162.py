"""Contract 1.62 (the 1.1.0 release): the two request-member rules of §27.11 rule 5.

* **(f) An assigned ``None`` is "none".** ``user_id`` on ``certificates.generate`` and
  ``certificates.sign_csr``, and ``expected_updated_at`` on ``ssf.update_stream`` and
  ``scim_targets.update``: the key is left out of the body, and ``null`` is never sent.
* **(i) The request ``user_id`` is an untyped string**, so that a value that is not a UUID
  reaches the server and its ``400`` is the caller's to see; the response member stays a
  plain optional string too (this SDK types no UUID).

Both already held at contract 1.61 in this SDK; these tests are the 1.62 form of the
assertion, so a later change to the models cannot lose them.
"""

from __future__ import annotations

import json
import typing
import uuid

import pytest

from axiam_sdk import AsyncAxiamClient
from axiam_sdk.management import ValidationError, models
from tests.management_support import (
    EXAMPLE_ID,
    mount_json,
    with_async_client,
    with_client,
)
from tests.test_contract_161 import _certificate


def test_the_request_user_id_is_a_plain_optional_string_not_a_uuid() -> None:
    """(i): the annotation is ``str | None`` on both requests and on the response."""
    for model in (
        models.CreateCertificateRequest,
        models.SignCertificateCsrRequest,
        models.Certificate,
    ):
        annotation = model.model_fields["user_id"].annotation
        assert annotation == (str | None), model
        assert uuid.UUID not in typing.get_args(annotation), model


@pytest.mark.parametrize("malformed", ["not-a-uuid", "", " 123 ", "{3f2a}", "ÄÖÜ"])
def test_a_malformed_user_id_reaches_the_server_and_its_400_is_surfaced(malformed: str) -> None:
    """(i): no client-side judgement of the value; the server's ``400`` is raised."""
    with with_client() as (router, client):
        generate = mount_json(
            router,
            "POST",
            "/api/v1/certificates",
            400,
            {"error": "validation_error", "message": "user_id is not a UUID"},
        )
        sign = mount_json(
            router,
            "POST",
            "/api/v1/certificates/sign-csr",
            400,
            {"error": "validation_error", "message": "user_id is not a UUID"},
        )
        with pytest.raises(ValidationError) as raised:
            client.certificates.generate(
                models.CreateCertificateRequest(
                    cert_type="User",
                    issuer_ca_id=EXAMPLE_ID,
                    key_algorithm="Ed25519",
                    subject="ada",
                    user_id=malformed,
                    validity_days=90,
                )
            )
        assert "user_id is not a UUID" in str(raised.value)
        with pytest.raises(ValidationError):
            client.certificates.sign_csr(
                models.SignCertificateCsrRequest(
                    cert_type="User",
                    csr_pem="csr",
                    issuer_ca_id=EXAMPLE_ID,
                    subject="ada",
                    user_id=malformed,
                    validity_days=90,
                )
            )
        assert json.loads(generate.calls[0].request.content)["user_id"] == malformed
        assert json.loads(sign.calls[0].request.content)["user_id"] == malformed


def test_an_assigned_none_is_none_on_every_member_the_rule_names() -> None:
    """(f): ``user_id`` x2 and ``expected_updated_at`` x2, set to ``None`` after
    construction as well as by the constructor, never reach the wire as ``null``."""
    generate = models.CreateCertificateRequest(
        cert_type="User",
        issuer_ca_id=EXAMPLE_ID,
        key_algorithm="Ed25519",
        subject="ada",
        validity_days=90,
    )
    generate.user_id = None
    sign = models.SignCertificateCsrRequest(
        cert_type="User",
        csr_pem="csr",
        issuer_ca_id=EXAMPLE_ID,
        subject="ada",
        validity_days=90,
        user_id=None,
    )
    stream = models.SsfStreamInput(
        audience="https://rp.example",
        delivery_method="push",
        events_allowed=["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
        receiver_client_id="rp-1",
    )
    stream.expected_updated_at = None
    target = models.ScimTargetInput.model_construct(
        _fields_set={"expected_updated_at"}, expected_updated_at=None
    )
    for body in (generate, sign, stream, target):
        wire = body.to_wire()
        assert "user_id" not in wire and "expected_updated_at" not in wire, wire
        assert None not in wire.values(), wire


@pytest.mark.asyncio
async def test_the_async_client_drops_the_assigned_none_too() -> None:
    """(f), async twin: one request, no ``user_id`` key."""
    async with with_async_client() as (router, client):
        assert isinstance(client, AsyncAxiamClient)
        route = mount_json(
            router, "POST", "/api/v1/certificates", 201, _certificate(private_key_pem="k")
        )
        body = models.CreateCertificateRequest(
            cert_type="User",
            issuer_ca_id=EXAMPLE_ID,
            key_algorithm="Ed25519",
            subject="ada",
            user_id=None,
            validity_days=90,
        )
        await client.certificates.generate(body)
        assert "user_id" not in json.loads(route.calls[0].request.content)
