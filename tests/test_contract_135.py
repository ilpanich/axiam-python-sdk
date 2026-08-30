"""Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the
principal tenant, and tenant-scoped role assignments.

Two of these rules are the kind an SDK breaks silently rather than loudly,
which is why they are pinned here rather than left to the generated surface
test:

* **§5.2.2 rule 2.** A registration record for the caller's *own* password is
  sealed against the tenant the account lives in, not the one the client is
  pointed at. Get it wrong and the server answers "the OPAQUE session was
  issued for a different tenant" — but only for an organization-level
  principal that has switched tenant, so it passes every test written against
  an ordinary account.
* **§5.2.3 rule 1.** ``tenant_scope: []`` is refused with ``400``.
  ``exclude_unset`` does not prevent it: the natural way to build the field is
  to collect into a list and pass it, which yields ``[]`` for "no tenants
  named" and *is* set, so it would go on the wire.
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient, NetworkError
from axiam_sdk.management.models import (
    AssignRoleToGroupRequest,
    AssignRoleToServiceAccountRequest,
    AssignRoleToUserRequest,
)

BASE_URL = "https://axiam-135.test"


def fixture_password() -> str:
    """A throwaway credential built at run time.

    Deliberately not a literal. A password spelled out in source is a finding
    for CodeQL and for secret scanners alike, and it stays one wherever the
    file gets copied. Nothing here depends on the value: the login mock answers
    ``200`` regardless, so what is under test is which tenant the body names,
    never whether a credential matched.
    """
    return f"Fixture-{uuid.uuid4()}-aA1!"


def _access_token(tenant_id: str = "tenant-uuid-1", org_id: str = "org-uuid-1") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "tenant_id": tenant_id,
                    "org_id": org_id,
                    "jti": "session-uuid-1",
                    "exp": 9999999999,
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.fake-signature"


def _login_response(user: dict[str, Any]) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "user": {
                "id": "user-1",
                "username": "alice",
                "email": "alice@example.com",
                **user,
            },
            "session_id": "session-uuid-1",
            "expires_in": 900,
        },
        headers=[("Set-Cookie", f"axiam_access={_access_token()}; Path=/; HttpOnly")],
    )


def _client() -> AxiamClient:
    return AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme")


# ---------------------------------------------------------------------
# §5.2.2 — acting tenant vs principal tenant
# ---------------------------------------------------------------------


def test_absent_principal_tenant_reads_as_the_acting_tenant(
    respx_mock: respx.MockRouter,
) -> None:
    """Rule 1: absent means *equal*, not unknown.

    A server older than contract 1.34 omits ``principal_tenant_id`` and cannot
    switch the acting tenant either, so reading ``tenant_id`` there is not a
    guess — it is the only value the field could have had.
    """
    acting = str(uuid.uuid4())
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=_login_response({"tenant_id": acting})
    )

    result = _client().login("alice@example.com", fixture_password())

    assert result.principal_tenant_id == acting


def test_a_divergent_principal_tenant_is_reported_separately(
    respx_mock: respx.MockRouter,
) -> None:
    """The whole point of the field: for an organization-level principal that
    has selected another tenant, the two differ and must not be collapsed."""
    acting = str(uuid.uuid4())
    principal = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=_login_response(
            {
                "tenant_id": acting,
                "principal_tenant_id": principal,
                "principal_tenant_slug": "organization",
                "org_id": org_id,
                "organization_level": True,
            }
        )
    )

    result = _client().login("alice@example.com", fixture_password())

    assert result.principal_tenant_id == principal
    assert result.principal_tenant_slug == "organization"
    # Rule 3: read the organization from the session rather than resolving a
    # slug through the `super-admin`-only `GET /api/v1/organizations`.
    assert result.org_id == org_id


def test_reachable_tenant_ids_narrows_an_organization_level_principal(
    respx_mock: respx.MockRouter,
) -> None:
    """A narrowed principal still reports ``organization_level=True``, which is
    exactly why gating on that flag alone offers tenants the server refuses."""
    reachable = str(uuid.uuid4())
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=_login_response(
            {
                "tenant_id": str(uuid.uuid4()),
                "organization_level": True,
                "reachable_tenant_ids": [reachable],
            }
        )
    )

    result = _client().login("alice@example.com", fixture_password())

    assert result.organization_level is True
    assert result.reachable_tenant_ids == (reachable,)


def test_absent_reachable_tenant_ids_is_unrestricted_not_empty(
    respx_mock: respx.MockRouter,
) -> None:
    """``None``, never ``()``: an empty collection would read as "reaches
    nothing", which is the opposite of what an omitted field means."""
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=_login_response({"tenant_id": str(uuid.uuid4())})
    )

    result = _client().login("alice@example.com", fixture_password())

    assert result.reachable_tenant_ids is None


# ---------------------------------------------------------------------
# §5.2.2 rule 2 — which tenant a registration record is sealed against
# ---------------------------------------------------------------------


def _register_start_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "opaque_session": "sealed-registration-session",
            "registration_response": "34" * 64,
            "ksf": "argon2id",
            "memory_kib": 8192,
            "iterations": 1,
            "parallelism": 1,
        },
    )


def test_opaque_enrollment_seals_against_the_acting_tenant(
    respx_mock: respx.MockRouter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Creating **another** account seals against the tenant it is created in —
    the one this client was pointed at."""
    _stub_opaque(monkeypatch)
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=_login_response(
            {"tenant_id": str(uuid.uuid4()), "principal_tenant_id": str(uuid.uuid4())}
        )
    )
    route = respx_mock.post(f"{BASE_URL}/api/v1/auth/opaque/register/start").mock(
        return_value=_register_start_response()
    )

    client = _client()
    client.login("alice@example.com", fixture_password())
    client.opaque_enrollment(fixture_password())

    body = json.loads(route.calls[0].request.content)
    assert body["tenant_slug"] == "acme"
    assert "tenant_id" not in body


def test_opaque_enrollment_for_self_seals_against_the_principal_tenant(
    respx_mock: respx.MockRouter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The caller's **own** password change seals against the tenant the
    account lives in."""
    _stub_opaque(monkeypatch)
    principal = str(uuid.uuid4())
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=_login_response(
            {
                "tenant_id": str(uuid.uuid4()),
                "principal_tenant_id": principal,
                "organization_level": True,
            }
        )
    )
    route = respx_mock.post(f"{BASE_URL}/api/v1/auth/opaque/register/start").mock(
        return_value=_register_start_response()
    )

    client = _client()
    client.login("alice@example.com", fixture_password())
    client.opaque_enrollment_for_self(fixture_password())

    body = json.loads(route.calls[0].request.content)
    assert body["tenant_id"] == principal
    # The acting tenant's slug must not travel alongside the principal tenant's
    # id, or it out-votes it server-side.
    assert "tenant_slug" not in body


def test_opaque_enrollment_for_self_refuses_before_a_login() -> None:
    """Before a login there is no principal tenant to seal against, and
    guessing the acting one is the bug this method exists to prevent."""
    with pytest.raises(NetworkError, match="principal tenant"):
        _client().opaque_enrollment_for_self(fixture_password())


@pytest.mark.asyncio
async def test_async_opaque_enrollment_for_self_refuses_before_a_login() -> None:
    """The async twin carries the same rule — a fix applied to only one of the
    two clients would leave the bug live on the other."""
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="acme")
    with pytest.raises(NetworkError, match="principal tenant"):
        await client.opaque_enrollment_for_self(fixture_password())


def _stub_opaque(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for the OPAQUE shared library.

    The protocol is proven in ``axiam-opaque``; what these tests are about is
    which workspace the HTTP body names, so the exchange only has to be
    well-formed.
    """
    import axiam_sdk._opaque as opaque_mod

    class _Exchange:
        request = "ee" * 32

        def finish(self, *_args: Any, **_kwargs: Any) -> str:
            return "ff" * 192

    monkeypatch.setattr(opaque_mod, "start_registration", lambda _password: _Exchange())


# ---------------------------------------------------------------------
# §5.2.3 rules 1 and 2 — tenant_scope on an assignment
# ---------------------------------------------------------------------


def test_an_empty_tenant_scope_is_dropped_from_the_body() -> None:
    """Rule 1. ``[]`` is refused with 400, and ``[]`` is what collecting into a
    list produces for "no tenants named", so both spellings of absent must
    travel the same way: by not appearing."""
    unset = AssignRoleToUserRequest(user_id=str(uuid.uuid4()))
    empty = AssignRoleToUserRequest(user_id=str(uuid.uuid4()), tenant_scope=[])

    assert "tenant_scope" not in unset.to_wire()
    assert "tenant_scope" not in empty.to_wire()


def test_a_named_tenant_scope_is_sent() -> None:
    """Rule 2. Dropping a scope the caller *did* name would turn a refusal they
    need to see into a success that silently applied no restriction."""
    scoped = str(uuid.uuid4())

    for body in (
        AssignRoleToUserRequest(user_id=str(uuid.uuid4()), tenant_scope=[scoped]),
        AssignRoleToGroupRequest(group_id=str(uuid.uuid4()), tenant_scope=[scoped]),
        AssignRoleToServiceAccountRequest(
            service_account_id=str(uuid.uuid4()), tenant_scope=[scoped]
        ),
    ):
        assert body.to_wire()["tenant_scope"] == [scoped]


def test_other_empty_lists_are_still_sent() -> None:
    """The allowlist is one field wide on purpose.

    Elsewhere ``[]`` is meaningful — a replacement body clearing a list — and
    dropping it would make "remove every entry" inexpressible.
    """
    from axiam_sdk.management.models import UpdateWebhookRequest

    body = UpdateWebhookRequest(events=[]).to_wire()
    assert body["events"] == [], "clearing a webhook's event list must stay expressible"
