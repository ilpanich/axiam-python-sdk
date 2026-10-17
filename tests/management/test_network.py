"""The ``network`` management namespace -- CONTRACT §36.8's five tests (contract 1.62).

Against a mocked HTTP server, for the twelve operations of §36.1. The decision
route (``POST /api/v1/network/decide``) is not SDK work (§27.0, §36.9, §36.11):
test 1 asserts that no method reaches it.
"""

from __future__ import annotations

import inspect
import json
import uuid
from typing import Any

import httpx
import pydantic
import pytest

from axiam_sdk import AuthError, AuthzError, NetworkError
from axiam_sdk.management import (
    ConflictError,
    NotFoundError,
    PageRequest,
    ValidationError,
    models,
)
from tests.management_support import (
    EXAMPLE_ID,
    TENANT_ID,
    anonymous_client,
    mount_json,
    with_async_client,
    with_client,
)

SEGMENTS = "/api/v1/network/segments"
PROFILES = "/api/v1/network/profiles"
POLICY = "/api/v1/network/policy"
SEGMENT_ID = str(uuid.uuid4())
ADMIN = str(uuid.uuid4())


def segment_body(**extra: Any) -> dict[str, Any]:
    """A server ``NetworkSegmentResponse`` body."""
    body: dict[str, Any] = {
        "id": SEGMENT_ID,
        "tenant_id": TENANT_ID,
        "path": "/network/zones/default/staff",
        "name": "staff",
        "site_key": "default",
        "kind": "access",
        "vlan_id": 20,
        "filter_ids": ["staff-in"],
        "rank": 1,
        "enabled": True,
        "version": 3,
        "created_by": ADMIN,
        "updated_by": ADMIN,
        "created_at": "2026-10-16T00:00:00Z",
        "updated_at": "2026-10-16T00:00:00Z",
    }
    body.update(extra)
    return body


def profile_body(**extra: Any) -> dict[str, Any]:
    """A server ``NetworkReplyProfile`` body (the effective profile)."""
    body: dict[str, Any] = {
        "segment_id": SEGMENT_ID,
        "tenant_id": TENANT_ID,
        "dictionary": "axiam-radius-reply/1",
        "session_timeout_secs": 3600,
        "session_timeout_clamped": False,
        "termination_action": "radius_request",
        "idle_timeout_secs": None,
        "filter_id": None,
        "service_type": None,
        "version": 5,
        "created_by": ADMIN,
        "updated_by": ADMIN,
        "created_at": "2026-10-16T00:00:00Z",
        "updated_at": "2026-10-16T00:00:00Z",
    }
    body.update(extra)
    return body


def policy_body(**extra: Any) -> dict[str, Any]:
    """A server ``NetworkPolicyResponse`` body."""
    body: dict[str, Any] = {
        "tenant_id": TENANT_ID,
        "session_timeout_max_secs": 3600,
        "version": 0,
    }
    body.update(extra)
    return body


def sent(route: Any, index: int = 0) -> Any:
    """The JSON body of the ``index``-th request a route saw."""
    return json.loads(route.calls[index].request.content)


def create_segment_request(**extra: Any) -> models.CreateNetworkSegmentRequest:
    """A ``CreateNetworkSegmentRequest`` with the required members."""
    return models.CreateNetworkSegmentRequest(
        kind="access", name="staff", site_key="default", vlan_id=20, **extra
    )


def replace_segment_request(**extra: Any) -> models.ReplaceNetworkSegmentRequest:
    """A ``ReplaceNetworkSegmentRequest`` with the required members."""
    return models.ReplaceNetworkSegmentRequest(
        enabled=True, filter_ids=["staff-in"], version=3, vlan_id=20, **extra
    )


# ── 1. The surface ───────────────────────────────────────────────────────────

OPERATIONS = {
    "list_segments": ("GET", SEGMENTS),
    "create_segment": ("POST", SEGMENTS),
    "get_segment": ("GET", f"{SEGMENTS}/{{id}}"),
    "replace_segment": ("PUT", f"{SEGMENTS}/{{id}}"),
    "delete_segment": ("DELETE", f"{SEGMENTS}/{{id}}"),
    "list_profiles": ("GET", PROFILES),
    "create_profile": ("POST", PROFILES),
    "get_profile": ("GET", f"{PROFILES}/{{id}}"),
    "replace_profile": ("PUT", f"{PROFILES}/{{id}}"),
    "delete_profile": ("DELETE", f"{PROFILES}/{{id}}"),
    "get_policy": ("GET", POLICY),
    "replace_policy": ("PUT", POLICY),
}


def test_the_twelve_operations_exist_and_the_decision_route_is_not_reachable() -> None:
    """Twelve methods with the §36.1 verbs and paths; none for ``/network/decide``."""
    with with_client() as (router, client):
        methods = {
            name
            for name, member in inspect.getmembers(client.network, inspect.ismethod)
            if not name.startswith("_") and not name.endswith("_all")
        }
        assert methods == set(OPERATIONS), methods ^ set(OPERATIONS)
        assert "decide" not in " ".join(methods)

        mount_json(
            router, "GET", SEGMENTS, 200, {"items": [], "total": 0, "offset": 0, "limit": 50}
        )
        mount_json(router, "POST", SEGMENTS, 201, segment_body())
        mount_json(router, "GET", f"{SEGMENTS}/{SEGMENT_ID}", 200, segment_body())
        mount_json(router, "PUT", f"{SEGMENTS}/{SEGMENT_ID}", 200, segment_body())
        mount_json(router, "DELETE", f"{SEGMENTS}/{SEGMENT_ID}", 204, None)
        mount_json(
            router, "GET", PROFILES, 200, {"items": [], "total": 0, "offset": 0, "limit": 50}
        )
        mount_json(router, "POST", PROFILES, 201, profile_body())
        mount_json(router, "GET", f"{PROFILES}/{SEGMENT_ID}", 200, profile_body())
        mount_json(router, "PUT", f"{PROFILES}/{SEGMENT_ID}", 200, profile_body())
        mount_json(router, "DELETE", f"{PROFILES}/{SEGMENT_ID}", 204, None)
        mount_json(router, "GET", POLICY, 200, policy_body())
        mount_json(router, "PUT", POLICY, 200, policy_body(version=1))

        profile_input = models.NetworkReplyProfileInput(session_timeout_secs=3600)
        client.network.list_segments()
        client.network.create_segment(create_segment_request(rank=1))
        client.network.get_segment(SEGMENT_ID)
        client.network.replace_segment(SEGMENT_ID, replace_segment_request(rank=1))
        client.network.delete_segment(SEGMENT_ID, 3)
        client.network.list_profiles()
        client.network.create_profile(
            models.CreateNetworkReplyProfileRequest(
                profile=profile_input, segment_id=SEGMENT_ID, segment_version=3
            )
        )
        client.network.get_profile(SEGMENT_ID)
        client.network.replace_profile(
            SEGMENT_ID,
            models.ReplaceNetworkReplyProfileRequest(
                profile=profile_input, segment_version=3, version=5
            ),
        )
        client.network.delete_profile(SEGMENT_ID, 5)
        client.network.get_policy()
        client.network.replace_policy(
            models.ReplaceNetworkPolicyRequest(session_timeout_max_secs=3600, version=0)
        )

        seen = [(c.request.method, c.request.url.path) for c in router.calls[1:]]
        assert seen == [
            (method, path.replace("{id}", SEGMENT_ID)) for method, path in OPERATIONS.values()
        ]
        assert not any(path.endswith("/network/decide") for _, path in seen)


@pytest.mark.asyncio
async def test_the_async_handle_has_the_same_twelve() -> None:
    """The async twin carries the same operations, as coroutines."""
    async with with_async_client() as (router, client):
        names = {
            name
            for name, member in inspect.getmembers(client.network, inspect.ismethod)
            if not name.startswith("_") and not name.endswith("_all")
        }
        assert names == set(OPERATIONS)
        mount_json(router, "GET", POLICY, 200, policy_body())
        policy = await client.network.get_policy()
        assert policy.session_timeout_max_secs == 3600 and policy.version == 0


def test_a_handle_performs_no_io_and_an_anonymous_client_makes_no_call() -> None:
    """§27.2 rule 1 / §27.4 rule 1 hold for the new namespace."""
    with anonymous_client() as (router, client):
        handle = client.network
        assert handle is not None and router.calls.call_count == 0
        with pytest.raises(AuthError):
            handle.get_policy()
        assert router.calls.call_count == 0


def test_a_non_uuid_identifier_fails_client_side() -> None:
    """§27.4 rule 3: a malformed id makes zero wire calls."""
    with with_client() as (router, client):
        before = router.calls.call_count
        with pytest.raises(NetworkError):
            client.network.get_segment("not-a-uuid")
        with pytest.raises(NetworkError):
            client.network.delete_profile("not-a-uuid", 1)
        assert router.calls.call_count == before


# ── 2. Versions ──────────────────────────────────────────────────────────────


def test_every_write_sends_the_version_it_was_given_exactly() -> None:
    """``version`` in the body or on the query, ``segment_version`` on a profile write."""
    with with_client() as (router, client):
        replace_seg = mount_json(router, "PUT", f"{SEGMENTS}/{SEGMENT_ID}", 200, segment_body())
        delete_seg = mount_json(router, "DELETE", f"{SEGMENTS}/{SEGMENT_ID}", 204, None)
        create_prof = mount_json(router, "POST", PROFILES, 201, profile_body())
        replace_prof = mount_json(router, "PUT", f"{PROFILES}/{SEGMENT_ID}", 200, profile_body())
        delete_prof = mount_json(router, "DELETE", f"{PROFILES}/{SEGMENT_ID}", 204, None)
        replace_pol = mount_json(router, "PUT", POLICY, 200, policy_body(version=8))

        client.network.replace_segment(SEGMENT_ID, replace_segment_request(rank=1))
        assert sent(replace_seg)["version"] == 3

        client.network.delete_segment(SEGMENT_ID, 41)
        assert delete_seg.calls[0].request.url.params["version"] == "41"

        client.network.delete_profile(SEGMENT_ID, 0)
        assert delete_prof.calls[0].request.url.params["version"] == "0"

        profile = models.NetworkReplyProfileInput(session_timeout_secs=900)
        client.network.create_profile(
            models.CreateNetworkReplyProfileRequest(
                profile=profile, segment_id=SEGMENT_ID, segment_version=17
            )
        )
        assert sent(create_prof)["segment_version"] == 17

        client.network.replace_profile(
            SEGMENT_ID,
            models.ReplaceNetworkReplyProfileRequest(
                profile=profile, segment_version=17, version=9
            ),
        )
        assert (sent(replace_prof)["version"], sent(replace_prof)["segment_version"]) == (9, 17)

        client.network.replace_policy(
            models.ReplaceNetworkPolicyRequest(session_timeout_max_secs=600, version=0)
        )
        assert sent(replace_pol) == {"session_timeout_max_secs": 600, "version": 0}


def test_a_delete_cannot_be_called_without_a_version() -> None:
    """``?version=`` is a required argument, not an optional one."""
    with with_client() as (router, client):
        route = mount_json(router, "DELETE", f"{SEGMENTS}/{SEGMENT_ID}", 204, None)
        with pytest.raises(TypeError):
            client.network.delete_segment(SEGMENT_ID)  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            client.network.delete_profile(SEGMENT_ID)  # type: ignore[call-arg]
        assert route.call_count == 0


WRITES: list[tuple[str, str, str]] = [
    ("PUT", f"{SEGMENTS}/{SEGMENT_ID}", "replace_segment"),
    ("DELETE", f"{SEGMENTS}/{SEGMENT_ID}", "delete_segment"),
    ("POST", PROFILES, "create_profile"),
    ("PUT", f"{PROFILES}/{SEGMENT_ID}", "replace_profile"),
    ("DELETE", f"{PROFILES}/{SEGMENT_ID}", "delete_profile"),
    ("PUT", POLICY, "replace_policy"),
    ("POST", SEGMENTS, "create_segment"),
]


def call_write(client: Any, name: str) -> Any:
    """Call one of the seven writes with valid arguments."""
    profile = models.NetworkReplyProfileInput(session_timeout_secs=900)
    if name == "replace_segment":
        return client.network.replace_segment(SEGMENT_ID, replace_segment_request(rank=1))
    if name == "delete_segment":
        return client.network.delete_segment(SEGMENT_ID, 3)
    if name == "create_profile":
        return client.network.create_profile(
            models.CreateNetworkReplyProfileRequest(
                profile=profile, segment_id=SEGMENT_ID, segment_version=3
            )
        )
    if name == "replace_profile":
        return client.network.replace_profile(
            SEGMENT_ID,
            models.ReplaceNetworkReplyProfileRequest(profile=profile, segment_version=3, version=5),
        )
    if name == "delete_profile":
        return client.network.delete_profile(SEGMENT_ID, 5)
    if name == "replace_policy":
        return client.network.replace_policy(
            models.ReplaceNetworkPolicyRequest(session_timeout_max_secs=600, version=0)
        )
    return client.network.create_segment(create_segment_request(rank=1))


@pytest.mark.parametrize(("method", "path", "name"), WRITES)
def test_a_409_is_a_conflict_after_one_request_and_exposes_its_reason_code(
    method: str, path: str, name: str
) -> None:
    """Each write: ``409`` -> ``ConflictError``, exactly one request, ``reason_code`` kept."""
    with with_client() as (router, client):
        route = mount_json(
            router,
            method,
            path,
            409,
            {"error": "conflict", "message": "the row changed", "reason_code": "stale_version"},
        )
        with pytest.raises(ConflictError) as raised:
            call_write(client, name)
        assert route.call_count == 1, "§27.4 rule 8: a 409 is never retried"
        assert raised.value.reason_code == "stale_version"
        assert isinstance(raised.value, AuthzError)


def test_an_already_exists_409_exposes_duplicate_vlan() -> None:
    """``error: already_exists`` + ``reason_code: duplicate_vlan`` is a ``ConflictError`` too."""
    with with_client() as (router, client):
        route = mount_json(
            router,
            "POST",
            SEGMENTS,
            409,
            {"error": "already_exists", "message": "vlan taken", "reason_code": "duplicate_vlan"},
        )
        with pytest.raises(ConflictError) as raised:
            client.network.create_segment(create_segment_request(rank=1))
        assert route.call_count == 1
        assert raised.value.reason_code == "duplicate_vlan"


def test_an_unknown_reason_code_is_surfaced_verbatim_and_an_absent_one_is_none() -> None:
    """The vocabulary is open (§27.13); a server before 1.62 sends none."""
    with with_client() as (router, client):
        mount_json(
            router,
            "PUT",
            POLICY,
            409,
            {"error": "conflict", "message": "m", "reason_code": "a_code_from_the_future"},
        )
        with pytest.raises(ConflictError) as raised:
            call_write(client, "replace_policy")
        assert raised.value.reason_code == "a_code_from_the_future"
    with with_client() as (router, client):
        mount_json(router, "PUT", POLICY, 409, {"error": "conflict", "message": "m"})
        with pytest.raises(ConflictError) as raised:
            call_write(client, "replace_policy")
        assert raised.value.reason_code is None


# ── 3. Closed bodies ─────────────────────────────────────────────────────────


def test_serialized_requests_carry_exactly_the_members_set() -> None:
    """An unset ``rank``, ``idle_timeout_secs``, ``filter_id`` or ``service_type`` is absent."""
    assert set(create_segment_request().to_wire()) == {"kind", "name", "site_key", "vlan_id"}
    assert set(create_segment_request(rank=2, filter_ids=["a"], enabled=False).to_wire()) == {
        "kind",
        "name",
        "site_key",
        "vlan_id",
        "rank",
        "filter_ids",
        "enabled",
    }
    assert set(replace_segment_request().to_wire()) == {
        "enabled",
        "filter_ids",
        "version",
        "vlan_id",
    }
    assert replace_segment_request().to_wire().get("kind") is None
    profile = models.NetworkReplyProfileInput(session_timeout_secs=900)
    assert profile.to_wire() == {"session_timeout_secs": 900}
    assert "vlan_id" not in models.NetworkReplyProfileInput.model_fields
    create_profile = models.CreateNetworkReplyProfileRequest(
        profile=profile, segment_id=SEGMENT_ID, segment_version=3
    )
    assert create_profile.to_wire() == {
        "profile": {"session_timeout_secs": 900},
        "segment_id": SEGMENT_ID,
        "segment_version": 3,
    }
    assert models.ReplaceNetworkPolicyRequest(
        session_timeout_max_secs=300, version=0
    ).to_wire() == {"session_timeout_max_secs": 300, "version": 0}


def test_the_replace_types_cannot_be_built_without_their_required_members() -> None:
    """Required members are required; a replacement does not preserve what it omits."""
    with pytest.raises(pydantic.ValidationError):
        models.ReplaceNetworkSegmentRequest(enabled=True, filter_ids=[], vlan_id=1)  # type: ignore[call-arg]
    with pytest.raises(pydantic.ValidationError):
        models.ReplaceNetworkReplyProfileRequest(  # type: ignore[call-arg]
            profile=models.NetworkReplyProfileInput(session_timeout_secs=900), version=1
        )
    with pytest.raises(pydantic.ValidationError):
        models.ReplaceNetworkPolicyRequest(version=0)  # type: ignore[call-arg]
    with pytest.raises(pydantic.ValidationError):
        models.NetworkReplyProfileInput()  # type: ignore[call-arg]


def test_an_unknown_enum_value_is_never_sent() -> None:
    """§36.2: an open enumeration decodes but is not re-sent (`to_wire` refuses)."""
    segment = models.NetworkSegmentResponse.model_validate(segment_body(kind="a_future_kind"))
    assert segment.kind == "a_future_kind"
    with pytest.raises(ValidationError):
        models.CreateNetworkSegmentRequest(
            kind="a_future_kind", name="n", site_key="s", vlan_id=1
        ).to_wire()
    with pytest.raises(ValidationError):
        models.NetworkReplyProfileInput(
            session_timeout_secs=900, service_type="administrative_user"
        ).to_wire()


# ── 4. Open decoding and pagination ──────────────────────────────────────────


def test_unknown_enum_values_decode() -> None:
    """Unknown ``kind``, ``termination_action`` and ``service_type`` decode, and so does a clamp."""
    segment = models.NetworkSegmentResponse.model_validate(segment_body(kind="mesh"))
    assert segment.kind == "mesh"
    profile = models.NetworkReplyProfile.model_validate(
        profile_body(
            termination_action="a_future_action",
            service_type="a_future_service",
            session_timeout_clamped=True,
            session_timeout_secs=300,
        )
    )
    assert profile.termination_action == "a_future_action"
    assert profile.service_type == "a_future_service"
    assert profile.session_timeout_clamped is True and profile.session_timeout_secs == 300


def test_both_lists_return_a_page_with_total_and_the_pager_carries_search_and_site() -> None:
    """``Page.total`` is the server's; the walk puts ``search`` (and ``site``) on every request."""
    with with_client() as (router, client):
        first = {"items": [segment_body()], "total": 2, "offset": 0, "limit": 1}
        second = {"items": [segment_body(name="guest")], "total": 2, "offset": 1, "limit": 1}
        route = router.get(f"https://management.test{SEGMENTS}")
        route.side_effect = [
            httpx.Response(200, json=first),
            httpx.Response(200, json=second),
            httpx.Response(200, json={**second, "items": [], "offset": 2}),
        ]
        page = client.network.list_segments("default", PageRequest(limit=1, search="st"))
        assert page.total == 2 and len(page.items) == 1
        assert isinstance(page.items[0], models.NetworkSegmentResponse)
        route.side_effect = [
            httpx.Response(200, json=first),
            httpx.Response(200, json=second),
            httpx.Response(200, json={**second, "items": [], "offset": 2}),
        ]
        everything = client.network.list_segments_all(
            "default", PageRequest(limit=1, search="st", offset=0)
        )
        assert len(everything) == 2
        for call in route.calls:
            assert call.request.url.params["search"] == "st"
            assert call.request.url.params["site"] == "default"

    with with_client() as (router, client):
        route = mount_json(
            router,
            "GET",
            PROFILES,
            200,
            {"items": [profile_body()], "total": 7, "offset": 0, "limit": 1},
        )
        page = client.network.list_profiles(PageRequest(limit=1, search="staff-in"))
        assert page.total == 7 and len(page.items) == 1
        assert route.calls[0].request.url.params["search"] == "staff-in"
        assert "site" not in route.calls[0].request.url.params


def test_a_list_without_a_term_or_site_sends_neither_key() -> None:
    """Absent means absent (§27.9), not an empty string."""
    with with_client() as (router, client):
        route = mount_json(
            router, "GET", SEGMENTS, 200, {"items": [], "total": 0, "offset": 0, "limit": 50}
        )
        client.network.list_segments(page=PageRequest(search="  "))
        keys = set(route.calls[0].request.url.params)
        assert "search" not in keys and "site" not in keys


# ── 5. Errors ────────────────────────────────────────────────────────────────


def test_a_403_is_authz_error_exposing_the_action_and_the_node() -> None:
    """``action`` and ``resource_id`` come from the body, never from the message."""
    with with_client() as (router, client):
        mount_json(
            router,
            "POST",
            PROFILES,
            403,
            {
                "error": "authorization_denied",
                "message": "denied",
                "action": "network:grant",
                "resource_id": EXAMPLE_ID,
            },
        )
        with pytest.raises(AuthzError) as raised:
            call_write(client, "create_profile")
        assert not isinstance(raised.value, (NotFoundError, ConflictError))
        assert raised.value.action == "network:grant"
        assert raised.value.resource_id == EXAMPLE_ID


def test_400_404_and_401_map_to_the_taxonomy() -> None:
    """``400`` -> ValidationError with the message, ``404`` -> NotFound, ``401`` -> Auth."""
    with with_client() as (router, client):
        mount_json(
            router, "POST", SEGMENTS, 400, {"error": "validation_error", "message": "vlan range"}
        )
        with pytest.raises(ValidationError) as bad:
            client.network.create_segment(create_segment_request(rank=1))
        assert "vlan range" in str(bad.value)
        mount_json(router, "GET", f"{PROFILES}/{SEGMENT_ID}", 404, {"error": "not_found"})
        with pytest.raises(NotFoundError):
            client.network.get_profile(SEGMENT_ID)
    with with_client() as (router, client):
        mount_json(router, "GET", POLICY, 401, {"error": "unauthorized"})
        mount_json(router, "POST", "/api/v1/auth/refresh", 401, {"error": "unauthorized"})
        with pytest.raises(AuthError):
            client.network.get_policy()


@pytest.mark.parametrize(("method", "path", "name"), WRITES)
@pytest.mark.parametrize("status", [429, 503])
def test_429_and_503_on_each_write_are_network_errors_after_one_request(
    method: str, path: str, name: str, status: int
) -> None:
    """The seven writes are never retried (§36.7)."""
    with with_client() as (router, client):
        route = mount_json(router, method, path, status, {"error": "unavailable"})
        with pytest.raises(NetworkError):
            call_write(client, name)
        assert route.call_count == 1
