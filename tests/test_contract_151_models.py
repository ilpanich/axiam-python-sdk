"""CONTRACT.md §27.13 (contract 1.51) — the model changes of the dogfooding
remediation, as a decoder and an encoder see them.

The regenerated types pick up every new field for free. What they do not pick
up by themselves is the behaviour §27.13 asks for at the edges: a ``cert_type``
this SDK does not know must not fail ``certificates.list``, a
``subject_alt_names`` entry must reach the wire in the shape the server
parses, and an ``inherit`` a server does not send must read as ``True``.

Re-vendoring contract 1.51 exposed two generator defects (``tools/gen_management.py``
in the Rust reference, ``scripts/gen_management.py`` here), fixed in the
generator rather than worked around at a call site:

* ``SubjectAltName`` is an externally tagged ``oneOf`` -- ``{"dns": ...}`` or
  ``{"ip": ...}`` -- which the generator recognised as neither an
  internally-tagged union nor a plain object, and emitted as an empty class
  that serializes as ``{}``. The server refuses ``{}``.
* ``inherit`` is required on the three role-side assignment listings, but a
  server older than contract 1.51 omits it. A bare, non-defaulted
  ``bool`` field would fail the *whole* listing against such a server --
  which is also the manifest's planning read.
"""

from __future__ import annotations

import json
import uuid

from axiam_sdk.management import models
from tests.management_support import (
    EXAMPLE_ID,
    TENANT_ID,
    mount_json,
    with_async_client,
    with_client,
)


def _certificate(cert_type: str, **extra: object) -> dict[str, object]:
    """A ``Certificate`` wire fixture of the given ``cert_type``."""
    body: dict[str, object] = {
        "cert_type": cert_type,
        "created_at": "2026-09-24T00:00:00Z",
        "fingerprint": "ab",
        "id": str(uuid.uuid4()),
        "issuer_ca_id": EXAMPLE_ID,
        "key_algorithm": "Ed25519",
        "metadata": {},
        "not_after": "2027-09-24T00:00:00Z",
        "not_before": "2026-09-24T00:00:00Z",
        "public_cert_pem": "pem",
        "status": "Active",
        "subject": "device-001",
        "tenant_id": TENANT_ID,
    }
    body.update(extra)
    return body


# ---------------------------------------------------------------------------
# S-7 rule 2 -- `CertificateType` decodes openly
# ---------------------------------------------------------------------------


def test_certificates_list_survives_a_type_this_sdk_does_not_know() -> None:
    """One certificate of a type this SDK has never heard of must not take
    the whole page down with it (§27.13 S-7 rule 2)."""
    with with_client() as (router, client):
        mount_json(
            router,
            "GET",
            "/api/v1/certificates",
            200,
            {
                "items": [
                    _certificate("Device"),
                    _certificate("Server"),
                    _certificate("Gateway"),
                ],
                "total": 3,
                "offset": 0,
                "limit": 50,
            },
        )

        page = client.certificates.list()
        types = [c.cert_type for c in page.items]
        assert types == ["Device", "Server", "Gateway"], (
            "the unknown value is kept verbatim, not collapsed or rejected"
        )


def test_an_unknown_certificate_type_round_trips_verbatim() -> None:
    """The raw string survives a read-modify-write: decoding and re-encoding a
    record must not rewrite a field this SDK did not understand."""
    decoded = models.Certificate.model_validate(_certificate("Gateway"))
    assert decoded.cert_type == "Gateway"
    assert decoded.model_dump(by_alias=True)["cert_type"] == "Gateway"

    # The I4 twin: the known values are the ones the server spells.
    for value in ("User", "Service", "Device", "Server"):
        known = models.Certificate.model_validate(_certificate(value))
        assert known.cert_type == value


# ---------------------------------------------------------------------------
# S-7 rule 1 -- `subject_alt_names`
# ---------------------------------------------------------------------------


def test_a_server_certificate_sends_its_names_externally_tagged() -> None:
    """``SubjectAltName`` is externally tagged: ``{"dns": ...}`` or
    ``{"ip": ...}``.

    The generator used to emit this ``oneOf`` as a class with no fields,
    which serializes as ``{}`` and is refused by the server. This pins the
    shape on the wire through a real ``generate()`` call, not only through
    ``model_dump``, so the request path cannot re-shape it either.
    """
    with with_client() as (router, client):
        route = mount_json(
            router,
            "POST",
            "/api/v1/certificates",
            201,
            _certificate("Server", private_key_pem="k"),
        )

        client.certificates.generate(
            models.CreateCertificateRequest(
                cert_type="Server",
                issuer_ca_id=EXAMPLE_ID,
                key_algorithm="Ed25519",
                subject="api.lakeside.internal",
                subject_alt_names=[
                    models.SubjectAltNameDns(dns="api.lakeside.internal"),
                    models.SubjectAltNameIp(ip="10.0.0.5"),
                ],
                validity_days=90,
            )
        )

        body = json.loads(route.calls.last.request.content)
        assert body["subject_alt_names"] == [
            {"dns": "api.lakeside.internal"},
            {"ip": "10.0.0.5"},
        ]


def test_a_leaf_request_without_names_omits_the_key() -> None:
    """The I4 twin: a request with no names sends **no** ``subject_alt_names``
    key -- not ``null``, not ``[]`` (§27.13 S-7 rule 1: "SHOULD omit the
    key") -- on both leaf paths, so a pre-1.51 body is byte-for-byte what it
    was."""
    generate = models.CreateCertificateRequest(
        cert_type="Device",
        issuer_ca_id=EXAMPLE_ID,
        key_algorithm="Ed25519",
        subject="device-001",
        validity_days=90,
    ).to_wire()
    sign = models.SignCertificateCsrRequest(
        cert_type="Device",
        csr_pem="csr",
        issuer_ca_id=EXAMPLE_ID,
        validity_days=90,
    ).to_wire()
    for label, body in (("generate", generate), ("sign_csr", sign)):
        assert "subject_alt_names" not in body, f"{label}: {body}"


def test_a_subject_alt_name_decodes_from_the_documented_shape() -> None:
    """A name decodes back from the shape the server documents."""
    adapter_input = [{"dns": "a.example"}, {"ip": "fd00::1"}]
    names = [
        models.SubjectAltNameDns.model_validate(n)
        if "dns" in n
        else models.SubjectAltNameIp.model_validate(n)
        for n in adapter_input
    ]
    assert names[0].dns == "a.example"
    assert names[1].ip == "fd00::1"


# ---------------------------------------------------------------------------
# S-10 -- `inherit`
# ---------------------------------------------------------------------------


def test_an_assign_request_carries_inherit_only_when_stated() -> None:
    """Rule 1: the key is sent only when it is ``False``. Leaving it unset --
    the default -- keeps an inheritable assignment's body byte-for-byte a
    pre-1.51 body."""
    omitted = models.AssignRoleToUserRequest(user_id=EXAMPLE_ID, resource_id=EXAMPLE_ID).to_wire()
    assert set(omitted) == {"resource_id", "user_id"}, "no inherit key when it is not stated"

    stopped = models.AssignRoleToUserRequest(
        user_id=EXAMPLE_ID, resource_id=EXAMPLE_ID, inherit=False
    ).to_wire()
    assert stopped["inherit"] is False


def test_a_role_side_listing_reads_an_absent_inherit_as_true() -> None:
    """Rule 3, role side. The field is required there, but a server older
    than contract 1.51 does not send it -- and failing the listing over it
    would take the manifest's planning read down with it. Absent reads as
    ``True``; a stated ``False`` is kept."""

    def user(extra: dict[str, object] | None = None) -> dict[str, object]:
        row: dict[str, object] = {
            "user": {
                "created_at": "2026-09-24T00:00:00Z",
                "email": "a@example.com",
                "email_verified": True,
                "failed_login_attempts": 0,
                "id": str(uuid.uuid4()),
                "is_locked": False,
                "metadata": {},
                "mfa_enabled": False,
                "status": "Active",
                "tenant_id": TENANT_ID,
                "updated_at": "2026-09-24T00:00:00Z",
                "username": "a",
            }
        }
        if extra:
            row.update(extra)
        return row

    with with_client() as (router, client):
        mount_json(
            router,
            "GET",
            f"/api/v1/roles/{EXAMPLE_ID}/users",
            200,
            [user(), user({"inherit": False})],
        )

        rows = client.roles.list_users(EXAMPLE_ID)
        assert rows[0].inherit is True, "absent must read as true, never false"
        assert rows[1].inherit is False, "a stated false is kept"


def test_a_subject_side_assignment_reads_absent_as_inheriting() -> None:
    """Rule 3, subject side: ``RoleAssignment.inherit`` is optional, and
    ``RoleAssignment.inherits`` is the one place the default is decided."""

    def role(extra: dict[str, object] | None = None) -> dict[str, object]:
        row: dict[str, object] = {
            "role": {
                "created_at": "2026-09-24T00:00:00Z",
                "description": "d",
                "id": str(uuid.uuid4()),
                "is_global": False,
                "name": "r",
                "tenant_id": TENANT_ID,
                "updated_at": "2026-09-24T00:00:00Z",
            }
        }
        if extra:
            row.update(extra)
        return row

    with with_client() as (router, client):
        mount_json(
            router,
            "GET",
            f"/api/v1/users/{EXAMPLE_ID}/roles",
            200,
            [role(), role({"inherit": True}), role({"inherit": False})],
        )

        rows = client.users.list_roles(EXAMPLE_ID)
        assert rows[0].inherit is None, "the wire value is not invented"
        assert [r.inherits for r in rows] == [True, True, False]


async def test_a_role_side_listing_reads_an_absent_inherit_as_true_async() -> None:
    """The async twin of the role-side absent-``inherit`` test."""

    def user(extra: dict[str, object] | None = None) -> dict[str, object]:
        row: dict[str, object] = {
            "user": {
                "created_at": "2026-09-24T00:00:00Z",
                "email": "a@example.com",
                "email_verified": True,
                "failed_login_attempts": 0,
                "id": str(uuid.uuid4()),
                "is_locked": False,
                "metadata": {},
                "mfa_enabled": False,
                "status": "Active",
                "tenant_id": TENANT_ID,
                "updated_at": "2026-09-24T00:00:00Z",
                "username": "a",
            }
        }
        if extra:
            row.update(extra)
        return row

    async with with_async_client() as (router, client):
        mount_json(
            router,
            "GET",
            f"/api/v1/roles/{EXAMPLE_ID}/users",
            200,
            [user(), user({"inherit": False})],
        )

        rows = await client.roles.list_users(EXAMPLE_ID)
        assert rows[0].inherit is True
        assert rows[1].inherit is False
