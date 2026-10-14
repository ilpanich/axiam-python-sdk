"""Contract 1.61 -- the rows §34.5 assigns every SDK that ships ``certificates``:
§27.11 rule 5, ``Certificate.user_id`` and the optional request member on
``certificates.generate`` and ``certificates.sign_csr`` (the one required test).

``SsfStreamInput.expected_updated_at`` and the three meanings of
``events_requested`` are §32.8 test 1's and live in ``tests/management/test_ssf.py``.
``CibaPendingList`` is a console surface no operation returns (§33.3 rule 16);
this SDK models neither it nor ``CibaApprovalPage``.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from axiam_sdk.management import models
from tests.management_support import (
    EXAMPLE_ID,
    TENANT_ID,
    mount_json,
    with_async_client,
    with_client,
)


def _certificate(**extra: Any) -> dict[str, Any]:
    """A ``Certificate`` wire fixture of a ``User`` certificate."""
    body: dict[str, Any] = {
        "cert_type": "User",
        "created_at": "2026-10-13T00:00:00Z",
        "fingerprint": "ab:cd",
        "id": str(uuid.uuid4()),
        "issuer_ca_id": EXAMPLE_ID,
        "key_algorithm": "Ed25519",
        "metadata": {},
        "not_after": "2027-10-13T00:00:00Z",
        "not_before": "2026-10-13T00:00:00Z",
        "public_cert_pem": "pem",
        "status": "Active",
        "subject": "ada",
        "tenant_id": TENANT_ID,
    }
    body.update(extra)
    return body


def _generate(user_id: str | None = None) -> models.CreateCertificateRequest:
    return models.CreateCertificateRequest(
        cert_type="User",
        issuer_ca_id=EXAMPLE_ID,
        key_algorithm="Ed25519",
        subject="ada",
        user_id=user_id,
        validity_days=90,
    )


def _sign(user_id: str | None = None) -> models.SignCertificateCsrRequest:
    return models.SignCertificateCsrRequest(
        cert_type="User",
        csr_pem="csr",
        issuer_ca_id=EXAMPLE_ID,
        subject="ada",
        user_id=user_id,
        validity_days=90,
    )


def test_generate_and_sign_csr_send_user_id_as_given_and_omit_the_key_when_unset() -> None:
    """Required test, first half (§27.11 rule 5)."""
    account = str(uuid.uuid4())
    with with_client() as (router, client):
        generate = mount_json(
            router, "POST", "/api/v1/certificates", 201, _certificate(private_key_pem="k")
        )
        sign = mount_json(router, "POST", "/api/v1/certificates/sign-csr", 201, _certificate())

        client.certificates.generate(_generate(account))
        client.certificates.generate(_generate())
        client.certificates.sign_csr(_sign(account))
        client.certificates.sign_csr(_sign())

        for route in (generate, sign):
            named = json.loads(route.calls[0].request.content)
            unset = json.loads(route.calls[1].request.content)
            assert named["user_id"] == account
            assert "user_id" not in unset, f"unset is absent, never null: {unset}"
            assert b"user_id" not in route.calls[1].request.content


def test_a_certificate_decodes_a_uuid_a_null_and_an_absent_user_id() -> None:
    """Required test, second half: a UUID, ``null`` and a missing member each
    decode; the last two name no account, and nothing is synthesised."""
    account = str(uuid.uuid4())
    named = models.Certificate.model_validate(_certificate(user_id=account))
    assert named.user_id == account
    assert models.Certificate.model_validate(_certificate(user_id=None)).user_id is None
    assert models.Certificate.model_validate(_certificate()).user_id is None
    # A metadata.user_id is free-form metadata; it does not become the field.
    from_metadata = models.Certificate.model_validate(_certificate(metadata={"user_id": account}))
    assert from_metadata.user_id is None


def test_user_id_reaches_a_generated_certificate_and_a_get_with_no_second_request() -> None:
    """``generate`` answers a ``GeneratedCertificate`` and ``get`` a
    ``Certificate``; the member reaches both and costs no further request."""
    account = str(uuid.uuid4())
    cert_id = str(uuid.uuid4())
    with with_client() as (router, client):
        post = mount_json(
            router,
            "POST",
            "/api/v1/certificates",
            201,
            _certificate(private_key_pem="k", user_id=account),
        )
        get = mount_json(
            router, "GET", f"/api/v1/certificates/{cert_id}", 200, _certificate(user_id=account)
        )
        generated = client.certificates.generate(_generate(account))
        assert generated.user_id == account
        assert client.certificates.get(cert_id).user_id == account
        assert (post.call_count, get.call_count) == (1, 1)


async def test_the_async_client_carries_user_id_too() -> None:
    """The async twin sends and decodes the member the same way."""
    account = str(uuid.uuid4())
    async with with_async_client() as (router, client):
        route = mount_json(
            router, "POST", "/api/v1/certificates/sign-csr", 201, _certificate(user_id=account)
        )
        signed = await client.certificates.sign_csr(_sign(account))
        assert signed.user_id == account
        assert json.loads(route.calls[0].request.content)["user_id"] == account
