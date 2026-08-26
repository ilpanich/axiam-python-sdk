"""CONTRACT §27.4, §27.5 and §27.2 semantics — the §27.9 required tests.

Every assertion here exists because the thing it checks is easy to get wrong and
silent when wrong. Where §27.9 says to assert on the request *path* rather than
on the arguments, these do.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from pydantic import SecretStr

from axiam_sdk import AuthError, AuthzError, NetworkError
from axiam_sdk.management import (
    ConflictError,
    NotFoundError,
    PageRequest,
    ValidationError,
    models,
)
from tests.management_support import (
    BASE_URL,
    EXAMPLE_ID,
    ORG_ID,
    TENANT_ID,
    TENANT_SLUG,
    anonymous_client,
    mount_json,
    with_client,
)

# ---------------------------------------------------------------------------
# §27.4 rule 1 — the authentication precondition
# ---------------------------------------------------------------------------


def test_no_session_makes_no_wire_call() -> None:
    """A management call without a session fails locally, with zero requests."""
    with anonymous_client() as (router, client):
        route = mount_json(router, "GET", "/api/v1/users", 200, {"items": [], "total": 0})
        with pytest.raises(AuthError, match="no active session"):
            client.users.list()
        assert route.call_count == 0


# ---------------------------------------------------------------------------
# §27.4 rule 3 — implicit path context
# ---------------------------------------------------------------------------


def test_org_and_tenant_come_from_the_client_and_land_in_the_path() -> None:
    """The client's org and tenant UUIDs are interpolated, not passed in."""
    with with_client() as (router, client):
        org_route = mount_json(
            router,
            "GET",
            f"/api/v1/organizations/{ORG_ID}",
            200,
            _org(ORG_ID, "Acme", "acme"),
        )
        tenant_route = mount_json(router, "GET", f"/api/v1/tenants/{TENANT_ID}/settings", 200, {})

        client.organizations.get()
        client.settings.get_tenant_override()

        assert org_route.call_count == 1
        assert tenant_route.call_count == 1
        assert org_route.calls[0].request.url.path == f"/api/v1/organizations/{ORG_ID}"
        assert tenant_route.calls[0].request.url.path == f"/api/v1/tenants/{TENANT_ID}/settings"


def test_an_explicit_override_changes_the_path() -> None:
    """``in_org`` / ``for_tenant`` reach another org or tenant (§27.4 rule 3)."""
    other_org = "44444444-4444-4444-8444-444444444444"
    other_tenant = "55555555-5555-4555-8555-555555555555"
    with with_client() as (router, client):
        org_route = mount_json(
            router,
            "GET",
            f"/api/v1/organizations/{other_org}",
            200,
            _org(other_org, "Other", "other"),
        )
        tenant_route = mount_json(
            router, "GET", f"/api/v1/tenants/{other_tenant}/settings", 200, {}
        )

        client.organizations.in_org(other_org).get()
        client.settings.for_tenant(other_tenant).get_tenant_override()

        assert org_route.calls[0].request.url.path == f"/api/v1/organizations/{other_org}"
        assert tenant_route.calls[0].request.url.path == f"/api/v1/tenants/{other_tenant}/settings"


def test_the_override_does_not_mutate_the_original_handle() -> None:
    """A scoped handle is a new handle; the one it came from is unchanged."""
    other_org = "44444444-4444-4444-8444-444444444444"
    with with_client() as (router, client):
        base = client.organizations
        scoped = base.in_org(other_org)
        assert scoped is not base

        route = mount_json(
            router,
            "GET",
            f"/api/v1/organizations/{ORG_ID}",
            200,
            _org(ORG_ID, "Acme", "acme"),
        )
        base.get()
        assert route.call_count == 1


def test_a_slug_only_client_refuses_a_tenant_route_without_calling() -> None:
    """No tenant UUID resolved yet means a local failure, not a 404."""
    with anonymous_client() as (router, client):
        route = mount_json(router, "GET", f"/api/v1/tenants/{TENANT_ID}/settings", 200, {})
        with pytest.raises(NetworkError, match="needs a tenant UUID"):
            client.settings.get_tenant_override()
        assert route.call_count == 0


def test_a_client_with_no_org_names_the_missing_configuration() -> None:
    """The org failure says what to do about it, and issues no request."""
    with anonymous_client() as (router, client):
        route = mount_json(router, "GET", f"/api/v1/organizations/{ORG_ID}", 200, {})
        with pytest.raises(NetworkError, match="organization UUID"):
            client.organizations.get()
        assert route.call_count == 0


def test_a_non_uuid_identifier_fails_client_side_with_zero_wire_calls() -> None:
    """§27.9: a slug where a UUID belongs is caught here, not by a misleading 404."""
    with with_client() as (router, client):
        route = mount_json(router, "GET", "/api/v1/users/not-a-uuid", 200, {})
        with pytest.raises(NetworkError, match="must be a UUID"):
            client.users.get("not-a-uuid")
        assert route.call_count == 0


def test_tenant_header_is_still_present_on_management_requests() -> None:
    """§5 rule 2 does not lapse on this surface."""
    with with_client() as (router, client):
        route = mount_json(
            router, "GET", "/api/v1/users", 200, {"items": [], "total": 0, "offset": 0, "limit": 50}
        )
        client.users.list()
        assert route.calls[0].request.headers["X-Tenant-ID"] == TENANT_SLUG


# ---------------------------------------------------------------------------
# §27.4 rule 4 — pagination
# ---------------------------------------------------------------------------


def _org(org_id: str, name: str, slug: str) -> dict[str, object]:
    """A minimal organization response body."""
    return {
        "id": org_id,
        "name": name,
        "slug": slug,
        "metadata": {},
        "created_at": "2026-08-26T00:00:00Z",
        "updated_at": "2026-08-26T00:00:00Z",
    }


def _user(index: int) -> dict[str, object]:
    """A minimal user response body, distinguishable by index."""
    return {
        "id": f"{index:08d}-1111-4111-8111-111111111111",
        "username": f"user{index}",
        "email": f"user{index}@example.test",
        "email_verified": True,
        "failed_login_attempts": 0,
        "is_locked": False,
        "metadata": {},
        "mfa_enabled": False,
        "status": "Active",
        "tenant_id": TENANT_ID,
        "created_at": "2026-08-26T00:00:00Z",
        "updated_at": "2026-08-26T00:00:00Z",
    }


def test_total_is_the_whole_set_not_the_page() -> None:
    """A ``Page`` reporting ``total == len(items)`` would pass a single-page fixture."""
    with with_client() as (router, client):
        mount_json(
            router,
            "GET",
            "/api/v1/users",
            200,
            {"items": [_user(1), _user(2)], "total": 57, "offset": 0, "limit": 2},
        )
        page = client.users.list(PageRequest(limit=2))
        assert len(page.items) == 2
        assert page.total == 57
        assert page.has_more() is True


def test_list_all_walks_every_page_with_the_expected_offsets() -> None:
    """The auto-paging form issues exactly the requests the set needs."""
    seen: list[str | None] = []

    def responder(request: httpx.Request) -> httpx.Response:
        """Answer three pages of two from a set of five."""
        offset = int(request.url.params.get("offset", "0"))
        seen.append(request.url.params.get("offset"))
        items = [_user(i) for i in range(offset, min(offset + 2, 5))]
        return httpx.Response(200, json={"items": items, "total": 5, "offset": offset, "limit": 2})

    with with_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/users").mock(side_effect=responder)
        everyone = client.users.list_all(PageRequest(limit=2))

        assert [u.username for u in everyone] == [f"user{i}" for i in range(5)]
        assert seen == ["0", "2", "4"]


def test_list_all_stops_on_an_empty_page_even_when_total_insists() -> None:
    """A misreporting server costs one wasted request, not an unbounded loop."""
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        """First page has one item; the second is empty but ``total`` says 99."""
        calls["n"] += 1
        items = [_user(1)] if calls["n"] == 1 else []
        offset = int(request.url.params.get("offset", "0"))
        return httpx.Response(200, json={"items": items, "total": 99, "offset": offset, "limit": 1})

    with with_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/users").mock(side_effect=responder)
        everyone = client.users.list_all(PageRequest(limit=1))
        assert len(everyone) == 1
        assert calls["n"] == 2


def test_a_bare_array_operation_is_not_a_page() -> None:
    """§27.4 rule 4: ``scopes.list`` answers with an array and is modelled as one."""
    with with_client() as (router, client):
        mount_json(
            router,
            "GET",
            f"/api/v1/resources/{EXAMPLE_ID}/scopes",
            200,
            [
                {
                    "id": EXAMPLE_ID,
                    "name": "draft",
                    "description": "Unpublished",
                    "resource_id": EXAMPLE_ID,
                    "tenant_id": TENANT_ID,
                    "created_at": "2026-08-26T00:00:00Z",
                    "updated_at": "2026-08-26T00:00:00Z",
                }
            ],
        )
        scopes = client.scopes.list(EXAMPLE_ID)
        assert isinstance(scopes, list)
        assert not hasattr(scopes, "total")
        assert not hasattr(client.scopes, "list_all")


# ---------------------------------------------------------------------------
# §27.4 rule 5 — update shapes
# ---------------------------------------------------------------------------


def test_a_sparse_update_sends_exactly_the_one_key_it_was_given() -> None:
    """Asserting the field is present would pass with every other field as null."""
    with with_client() as (router, client):
        route = mount_json(router, "PUT", f"/api/v1/users/{EXAMPLE_ID}", 200, _user(1))
        client.users.update(EXAMPLE_ID, models.UpdateUserRequest(email="new@example.test"))

        body = json.loads(route.calls[0].request.content)
        assert set(body) == {"email"}


def test_a_sparse_update_can_still_send_an_explicit_null() -> None:
    """Leaving a field out and setting it to ``None`` are different statements."""
    with with_client() as (router, client):
        route = mount_json(router, "PUT", f"/api/v1/users/{EXAMPLE_ID}", 200, _user(1))
        client.users.update(EXAMPLE_ID, models.UpdateUserRequest(username=None))

        body = json.loads(route.calls[0].request.content)
        assert body == {"username": None}


def test_a_replacement_body_will_not_construct_with_a_field_omitted() -> None:
    """§27.4 rule 5: a ``PUT`` that replaces refuses a half-filled body."""
    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError):
        models.SetMtlsTrustAnchor()  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# §27.4 rule 7 — error mapping
# ---------------------------------------------------------------------------


def test_404_maps_to_not_found_which_is_still_an_authz_error() -> None:
    """A caller catching AuthzError before §27 keeps working."""
    with with_client() as (router, client):
        mount_json(router, "GET", f"/api/v1/users/{EXAMPLE_ID}", 404, {"message": "gone"})
        with pytest.raises(NotFoundError) as caught:
            client.users.get(EXAMPLE_ID)
        assert isinstance(caught.value, AuthzError)
        assert caught.value.operation == "users.get"


def test_409_maps_to_conflict_and_issues_the_write_exactly_once() -> None:
    """A 409 is the server telling the truth; retrying produces the same answer."""
    with with_client() as (router, client):
        route = mount_json(
            router, "POST", "/api/v1/roles", 409, {"message": "role name already taken"}
        )
        with pytest.raises(ConflictError, match="already taken"):
            client.roles.create(
                models.CreateRoleRequest(name="Editor", description="Edits", is_global=False)
            )
        assert route.call_count == 1


def test_400_maps_to_validation_error_with_field_detail() -> None:
    """A user's invalid input must be distinguishable from a broken socket."""
    with with_client() as (router, client):
        mount_json(
            router,
            "POST",
            "/api/v1/users",
            400,
            {"message": "invalid", "errors": [{"field": "email", "message": "not an email"}]},
        )
        with pytest.raises(ValidationError) as caught:
            client.users.create(
                models.CreateUserRequest(
                    username="bob", email="nope", password=SecretStr("hunter2hunter2")
                )
            )
        assert isinstance(caught.value, NetworkError)
        assert caught.value.status == 400
        assert [(f.field, f.message) for f in caught.value.fields] == [("email", "not an email")]


def test_422_maps_to_validation_error_too() -> None:
    """§27.4 rule 7 names 400 and 422 together."""
    with with_client() as (router, client):
        mount_json(
            router,
            "POST",
            "/api/v1/users",
            422,
            {"errors": {"username": "already taken"}},
        )
        with pytest.raises(ValidationError) as caught:
            client.users.create(
                models.CreateUserRequest(
                    username="bob", email="b@example.test", password=SecretStr("hunter2hunter2")
                )
            )
        assert caught.value.status == 422
        assert [(f.field, f.message) for f in caught.value.fields] == [
            ("username", "already taken")
        ]


def test_an_ordinary_403_stays_a_plain_authz_error() -> None:
    """§27 classifies three statuses and widens the taxonomy no further."""
    with with_client() as (router, client):
        mount_json(router, "GET", f"/api/v1/users/{EXAMPLE_ID}", 403, {"message": "nope"})
        with pytest.raises(AuthzError) as caught:
            client.users.get(EXAMPLE_ID)
        assert not isinstance(caught.value, NotFoundError)
        assert not isinstance(caught.value, ConflictError)


def test_a_repeated_delete_is_not_swallowed_into_success() -> None:
    """A second delete 404s, and that is reported rather than absorbed."""
    with with_client() as (router, client):
        mount_json(router, "DELETE", f"/api/v1/users/{EXAMPLE_ID}", 404, {"message": "gone"})
        with pytest.raises(NotFoundError):
            client.users.delete(EXAMPLE_ID)


# ---------------------------------------------------------------------------
# §27.4 rule 8 — retry
# ---------------------------------------------------------------------------


def test_a_write_is_issued_exactly_once_on_a_503() -> None:
    """Even a write that looks idempotent is never replayed."""
    with with_client() as (router, client):
        route = mount_json(router, "POST", "/api/v1/roles", 503, {"message": "unavailable"})
        with pytest.raises(NetworkError):
            client.roles.create(
                models.CreateRoleRequest(name="Editor", description="Edits", is_global=False)
            )
        assert route.call_count == 1


def test_a_read_is_retried_under_the_shared_policy() -> None:
    """§16.2's runner owns the backoff; §27 only decides what is eligible."""
    calls = {"n": 0}

    def responder(request: httpx.Request) -> httpx.Response:
        """Fail once with a 503, then succeed."""
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, json={"message": "unavailable"})
        return httpx.Response(200, json={"items": [], "total": 0, "offset": 0, "limit": 50})

    with with_client() as (router, client):
        router.get(f"{BASE_URL}/api/v1/users").mock(side_effect=responder)
        page = client.users.list()
        assert page.total == 0
        assert calls["n"] == 2


# ---------------------------------------------------------------------------
# §27.5 — secrets
# ---------------------------------------------------------------------------


def test_a_returned_one_time_secret_is_redacted_from_every_rendering() -> None:
    """§27.5: the value is reachable only through an explicit unwrap."""
    with with_client() as (router, client):
        mount_json(
            router,
            "POST",
            "/api/v1/scim-tokens",
            201,
            {
                "id": EXAMPLE_ID,
                "name": "provisioning",
                "created_by": EXAMPLE_ID,
                "created_at": "2026-08-26T00:00:00Z",
                "expires_at": "2026-09-26T00:00:00Z",
                "status": "active",
                "tenant_id": TENANT_ID,
                "user_id": EXAMPLE_ID,
                "provisioning_token": "scim_live_supersecret",
            },
        )
        created = client.scim_tokens.create(
            models.CreateScimTokenRequest(name="provisioning", user_id=EXAMPLE_ID)
        )

        assert "scim_live_supersecret" not in repr(created)
        assert "scim_live_supersecret" not in str(created)
        assert "scim_live_supersecret" not in created.model_dump_json()
        assert created.provisioning_token.get_secret_value() == "scim_live_supersecret"


def test_a_supplied_password_is_redacted_but_still_sent() -> None:
    """Wrapping a secret must not stop it reaching the server."""
    with with_client() as (router, client):
        route = mount_json(router, "POST", "/api/v1/users", 201, _user(1))
        body = models.CreateUserRequest(
            username="bob", email="bob@example.test", password=SecretStr("hunter2hunter2")
        )

        assert "hunter2hunter2" not in repr(body)
        assert "hunter2hunter2" not in body.model_dump_json()

        client.users.create(body)
        sent = json.loads(route.calls[0].request.content)
        assert sent["password"] == "hunter2hunter2"


# ---------------------------------------------------------------------------
# §27.2 — handle rules
# ---------------------------------------------------------------------------


def test_acquiring_a_handle_performs_no_io() -> None:
    """§27.2 rule 1: a handle holds the client and does nothing else."""
    with respx.mock(assert_all_called=False) as router:
        catch_all = router.route().mock(return_value=httpx.Response(200, json={}))
        from axiam_sdk import AxiamClient

        client = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
        for name in ("users", "roles", "groups", "certificates", "platform"):
            getattr(client, name)
        client.management.users  # noqa: B018 — the access is the thing under test
        assert catch_all.call_count == 0
        client.close()


def test_the_same_namespaces_are_reachable_through_management() -> None:
    """``client.users`` and ``client.management.users`` are the same handle type."""
    with with_client() as (_router, client):
        assert type(client.users) is type(client.management.users)
        assert type(client.manifest) is type(client.management.manifest)


def test_a_closed_client_rejects_every_operation() -> None:
    """§18.1 rule 4: use-after-close is an error, never a silent reconnect."""
    with with_client() as (router, client):
        mount_json(router, "GET", "/api/v1/users", 200, {"items": [], "total": 0})
        client.close()
        with pytest.raises(NetworkError, match="client is closed"):
            client.users.list()
