"""The ``network`` namespace in a manifest -- CONTRACT §27.6.2 and §27.9 "Manifest, ``network``"
(contract 1.62; §34.6 items n, u, v, w).

A small stateful fake of the server's network routes stands behind a mocked transport, so
that ``apply`` then ``plan`` is a real round trip: it holds segments, profiles and the cap,
bumps versions, refuses a stale one with ``409`` and a ``reason_code``, clamps a profile on
read, and refuses a value above the cap with ``403`` -- the behaviours the manifest has to
get right against.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from axiam_sdk import NetworkError
from axiam_sdk.management import ValidationError
from axiam_sdk.management.manifest import (
    UNSET,
    ManagementManifest,
    NetworkPolicySpec,
    NetworkProfileSpec,
    NetworkSegmentSpec,
    NetworkSpec,
    RoleSpec,
    define_manifest,
)
from tests.management_support import BASE_URL, TENANT_ID, with_async_client, with_client

ADMIN = str(uuid.uuid4())
STAMP = "2026-10-16T00:00:00Z"
NETWORK = "/api/v1/network"


class FakeNetwork:
    """The server's network routes, enough of them: state, versions and refusals."""

    def __init__(self, *, cap: int = 3600, cap_version: int = 0) -> None:
        """An empty tenant with the default cap (version 0 until written)."""
        self.cap = cap
        self.cap_version = cap_version
        self.segments: dict[str, dict[str, Any]] = {}
        self.profiles: dict[str, dict[str, Any]] = {}
        self.stored_timeout: dict[str, int] = {}
        self.requests: list[tuple[str, str, Any]] = []
        self._segment_start = 4  # a version that is not 1, so a stale reuse shows

    # -- state seeding ------------------------------------------------------------------

    def add_segment(self, **fields: Any) -> dict[str, Any]:
        """Seed a segment as the server would hold it."""
        sid = str(uuid.uuid4())
        kind = fields.get("kind", "access")
        segment = {
            "id": sid,
            "tenant_id": TENANT_ID,
            "path": f"/network/{'zones' if kind == 'access' else 'quarantine'}/default/x",
            "name": "staff",
            "site_key": "default",
            "kind": kind,
            "vlan_id": 20,
            "filter_ids": ["staff-in"],
            "rank": 1 if kind == "access" else None,
            "enabled": True,
            "version": 2,
            "created_by": ADMIN,
            "updated_by": ADMIN,
            "created_at": STAMP,
            "updated_at": STAMP,
        }
        segment.update(fields)
        self.segments[sid] = segment
        return segment

    def add_profile(self, segment: dict[str, Any], **fields: Any) -> dict[str, Any]:
        """Seed the segment's profile (the *stored* values; reads clamp)."""
        profile = {
            "segment_id": segment["id"],
            "tenant_id": TENANT_ID,
            "dictionary": "axiam-radius-reply/1",
            "session_timeout_secs": 3600,
            "termination_action": "radius_request",
            "idle_timeout_secs": None,
            "filter_id": None,
            "service_type": None,
            "version": 6,
            "created_by": ADMIN,
            "updated_by": ADMIN,
            "created_at": STAMP,
            "updated_at": STAMP,
        }
        profile.update(fields)
        self.profiles[segment["id"]] = profile
        return profile

    # -- the wire -------------------------------------------------------------------------

    def mount(self, router: respx.MockRouter) -> None:
        """Route every network call to this fake."""
        router.route(path__regex=rf"^{NETWORK}/.*").mock(side_effect=self.handle)

    def writes(self) -> list[tuple[str, str]]:
        """``(method, path)`` of every non-GET request seen, in order."""
        return [(m, p) for m, p, _ in self.requests if m != "GET"]

    def handle(self, request: httpx.Request) -> httpx.Response:
        """Dispatch one request."""
        path = request.url.path
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, path, body))
        try:
            if path == f"{NETWORK}/policy":
                return self._policy(request, body)
            if path == f"{NETWORK}/segments":
                return self._segments(request, body)
            if path == f"{NETWORK}/profiles":
                return self._profiles(request, body)
            match = re.fullmatch(rf"{NETWORK}/(segments|profiles)/([0-9a-f-]{{36}})", path)
            if match:
                if match.group(1) == "segments":
                    return self._segment(request, match.group(2), body)
                return self._profile(request, match.group(2), body)
        except _Refusal as refusal:
            return refusal.response
        return httpx.Response(404, json={"error": "not_found"})

    def _page(self, request: httpx.Request, rows: list[dict[str, Any]]) -> httpx.Response:
        offset = int(request.url.params.get("offset", 0))
        limit = int(request.url.params.get("limit", 50))
        return httpx.Response(
            200,
            json={
                "items": rows[offset : offset + limit],
                "total": len(rows),
                "offset": offset,
                "limit": limit,
            },
        )

    def effective(self, profile: dict[str, Any]) -> dict[str, Any]:
        """A profile as a read returns it: clamped to the cap, with the flag."""
        out = dict(profile)
        clamped = profile["session_timeout_secs"] > self.cap
        out["session_timeout_secs"] = min(profile["session_timeout_secs"], self.cap)
        out["session_timeout_clamped"] = clamped
        return out

    def _policy(self, request: httpx.Request, body: Any) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=self._policy_body())
        if body["version"] != self.cap_version:
            return _conflict("conflict", "stale_version")
        self.cap = body["session_timeout_max_secs"]
        self.cap_version += 1
        return httpx.Response(200, json=self._policy_body())

    def _policy_body(self) -> dict[str, Any]:
        return {
            "tenant_id": TENANT_ID,
            "session_timeout_max_secs": self.cap,
            "version": self.cap_version,
        }

    def _segments(self, request: httpx.Request, body: Any) -> httpx.Response:
        if request.method == "GET":
            return self._page(request, list(self.segments.values()))
        for other in self.segments.values():
            if other["site_key"] == body["site_key"]:
                if other["name"] == body["name"]:
                    return _conflict("already_exists", "duplicate_name")
                if other["vlan_id"] == body["vlan_id"]:
                    return _conflict("already_exists", "duplicate_vlan")
        segment = self.add_segment(
            kind=body["kind"],
            name=body["name"],
            site_key=body["site_key"],
            vlan_id=body["vlan_id"],
            filter_ids=body.get("filter_ids", []),
            rank=body.get("rank"),
            enabled=body.get("enabled", True),
            version=self._segment_start,
        )
        return httpx.Response(201, json=segment)

    def _segment(self, request: httpx.Request, sid: str, body: Any) -> httpx.Response:
        segment = self.segments.get(sid)
        if segment is None:
            return httpx.Response(404, json={"error": "not_found"})
        if request.method == "GET":
            return httpx.Response(200, json=segment)
        if request.method == "DELETE":
            del self.segments[sid]
            self.profiles.pop(sid, None)
            return httpx.Response(204)
        if body["version"] != segment["version"]:
            return _conflict("conflict", "stale_version")
        profile = self.profiles.get(sid)
        if profile and profile["filter_id"] and profile["filter_id"] not in body["filter_ids"]:
            return _conflict("conflict", "strands_profile")
        segment.update(
            vlan_id=body["vlan_id"],
            filter_ids=body["filter_ids"],
            enabled=body["enabled"],
            rank=body.get("rank"),
            version=segment["version"] + 1,
        )
        return httpx.Response(200, json=segment)

    def _profiles(self, request: httpx.Request, body: Any) -> httpx.Response:
        if request.method == "GET":
            return self._page(request, [self.effective(p) for p in self.profiles.values()])
        sid = body["segment_id"]
        segment = self.segments.get(sid)
        if segment is None:
            return httpx.Response(404, json={"error": "not_found"})
        if body["segment_version"] != segment["version"]:
            return _conflict("conflict", "stale_version")
        if sid in self.profiles:
            return _conflict("already_exists", "profile_exists")
        self._check_cap(body["profile"])
        profile = self.add_profile(segment, version=1)
        profile.update(_profile_members(body["profile"]))
        return httpx.Response(201, json=self.effective(profile))

    def _profile(self, request: httpx.Request, sid: str, body: Any) -> httpx.Response:
        profile = self.profiles.get(sid)
        if profile is None:
            return httpx.Response(404, json={"error": "not_found"})
        if request.method == "GET":
            return httpx.Response(200, json=self.effective(profile))
        if request.method == "DELETE":
            del self.profiles[sid]
            return httpx.Response(204)
        segment = self.segments[sid]
        if body["version"] != profile["version"] or body["segment_version"] != segment["version"]:
            return _conflict("conflict", "stale_version")
        self._check_cap(body["profile"])
        profile.update(
            {"idle_timeout_secs": None, "filter_id": None, "service_type": None}
        )  # a replacement: what is omitted is not preserved
        profile.update(_profile_members(body["profile"]))
        profile["version"] += 1
        return httpx.Response(200, json=self.effective(profile))

    def _check_cap(self, profile: dict[str, Any]) -> None:
        if profile["session_timeout_secs"] > self.cap:
            raise _Refusal(
                httpx.Response(
                    403,
                    json={
                        "error": "authorization_denied",
                        "message": (
                            f"session_timeout_secs is above the tenant's cap of {self.cap}"
                        ),
                    },
                )
            )


class _Refusal(Exception):
    """A refusal the fake raises out of a handler."""

    def __init__(self, response: httpx.Response) -> None:
        """Carry the response to return."""
        super().__init__("refusal")
        self.response = response


def _conflict(error: str, reason_code: str) -> httpx.Response:
    return httpx.Response(
        409, json={"error": error, "message": "a conflict", "reason_code": reason_code}
    )


def _profile_members(profile: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in profile.items() if k != "dictionary"}
    out.setdefault("termination_action", "radius_request")
    return out


def segment_spec(**kw: Any) -> NetworkSegmentSpec:
    """The ``staff`` access segment of the tests."""
    args: dict[str, Any] = {
        "key": "staff",
        "site": "default",
        "kind": "access",
        "name": "staff",
        "vlan_id": 20,
    }
    args.update(kw)
    return NetworkSegmentSpec(**args)


def manifest(
    *,
    policy: int | None = None,
    segments: tuple[NetworkSegmentSpec, ...] = (),
    profiles: tuple[NetworkProfileSpec, ...] = (),
) -> ManagementManifest:
    """A manifest with only a ``network`` section."""
    return ManagementManifest(
        network=NetworkSpec(
            policy=NetworkPolicySpec(policy) if policy is not None else None,
            segments=segments,
            profiles=profiles,
        )
    )


def full_manifest() -> ManagementManifest:
    """A policy, a segment and its profile."""
    return manifest(
        policy=3600,
        segments=(segment_spec(rank=1, filter_ids=("staff-in", "staff-out")),),
        profiles=(
            NetworkProfileSpec(segment="staff", session_timeout_secs=1800, filter_id="staff-in"),
        ),
    )


# ── plan ─────────────────────────────────────────────────────────────────────


def test_plan_issues_gets_only_and_reads_policy_segments_and_profiles() -> None:
    """§27.9: ``get_policy``, ``list_segments``, ``list_profiles`` -- and no other method."""
    fake = FakeNetwork()
    with with_client() as (router, client):
        fake.mount(router)
        before = router.calls.call_count
        plan = client.manifest.plan(full_manifest())
        methods = {c.request.method for c in router.calls[before:]}
        paths = [c.request.url.path for c in router.calls[before:]]
    assert methods == {"GET"}
    assert paths == [f"{NETWORK}/policy", f"{NETWORK}/segments", f"{NETWORK}/profiles"]
    assert [a.change for a in plan.actions] == ["no-change", "create", "create"]
    assert [a.target for a in plan.actions] == [
        "network-policy",
        "network-segment",
        "network-profile",
    ]
    assert fake.writes() == []


def test_a_manifest_without_a_network_section_reads_nothing_about_the_network() -> None:
    """Appended last, so a manifest without the section plans exactly as before 1.62."""
    fake = FakeNetwork()
    with with_client() as (router, client):
        fake.mount(router)
        # An empty tenant: nothing exists, so only the role listing is asked.
        router.get(f"{BASE_URL}/api/v1/roles").mock(
            return_value=httpx.Response(
                200, json={"items": [], "total": 0, "offset": 0, "limit": 200}
            )
        )
        for path in ("resources", "permissions", "groups", "users", "service-accounts"):
            router.get(f"{BASE_URL}/api/v1/{path}").mock(
                return_value=httpx.Response(
                    200, json={"items": [], "total": 0, "offset": 0, "limit": 200}
                )
            )
        client.manifest.plan(ManagementManifest(roles=(RoleSpec("r", "R", "d"),)))
    assert fake.requests == []


def test_each_part_is_read_only_when_the_manifest_states_it() -> None:
    """No policy stated: no ``get_policy``. No profiles stated: no ``list_profiles``."""
    fake = FakeNetwork()
    with with_client() as (router, client):
        fake.mount(router)
        client.manifest.plan(manifest(segments=(segment_spec(rank=1),)))
    assert [p for _, p, _ in fake.requests] == [f"{NETWORK}/segments"]


def test_the_policy_is_never_created_and_an_unchanged_cap_is_no_change() -> None:
    """A singleton that always exists: ``NoChange`` or ``Update``, never ``Create``."""
    fake = FakeNetwork(cap=3600, cap_version=0)
    with with_client() as (router, client):
        fake.mount(router)
        same = client.manifest.plan(manifest(policy=3600))
        other = client.manifest.plan(manifest(policy=900))
    assert [a.change for a in same.actions] == ["no-change"]
    assert [a.change for a in other.actions] == ["update"]


# ── apply: create, then update ───────────────────────────────────────────────


def test_on_an_empty_tenant_apply_creates_the_segment_then_the_profile_and_converges() -> None:
    """The profile carries the new segment's id and the ``version`` of the create response."""
    fake = FakeNetwork()
    with with_client() as (router, client):
        fake.mount(router)
        report = client.manifest.apply(full_manifest())
        assert report.is_complete(), report.failure()
        again = client.manifest.plan(full_manifest())
    assert fake.writes() == [("POST", f"{NETWORK}/segments"), ("POST", f"{NETWORK}/profiles")]
    segment = next(iter(fake.segments.values()))
    created = [b for m, p, b in fake.requests if m == "POST" and p.endswith("/profiles")][0]
    assert created["segment_id"] == segment["id"]
    assert created["segment_version"] == 4, "the create response's version, not a guess"
    assert created["profile"] == {"session_timeout_secs": 1800, "filter_id": "staff-in"}
    assert [a.change for a in again.actions] == ["no-change"] * 3
    assert report.changed_count() == 2


def test_the_create_body_states_the_wire_kind_and_filter_ids_in_the_stated_order() -> None:
    """``"kind": "access"`` verbatim; the array in the manifest's order; no ``zones`` anywhere."""
    fake = FakeNetwork()
    spec = segment_spec(rank=1, filter_ids=("zeta", "alpha", "mid"), enabled=False)
    with with_client() as (router, client):
        fake.mount(router)
        client.manifest.apply(manifest(segments=(spec,)))
    body = next(b for m, p, b in fake.requests if m == "POST")
    assert body == {
        "kind": "access",
        "site_key": "default",
        "name": "staff",
        "vlan_id": 20,
        "rank": 1,
        "filter_ids": ["zeta", "alpha", "mid"],
        "enabled": False,
    }
    sources = Path(__file__).resolve().parents[2] / "src/axiam_sdk/management/manifest"
    for path in sources.glob("*.py"):
        assert not re.search(r"""["']zones["']""", path.read_text()), (
            f"{path.name}: no SDK maps to or from `zones` (§27.6.2 item 1)"
        )


def test_a_segment_kind_matches_the_wire_spelling_only() -> None:
    """``access`` against a read of ``"access"`` is ``NoChange``; any other spelling is a
    different segment (and is sent as given for the server to judge)."""
    fake = FakeNetwork()
    fake.add_segment()
    with with_client() as (router, client):
        fake.mount(router)
        same = client.manifest.plan(manifest(segments=(segment_spec(rank=1),)))
        other = client.manifest.plan(manifest(segments=(segment_spec(kind="zones", rank=1),)))
    assert [a.change for a in same.actions] == ["no-change"]
    assert [a.change for a in other.actions] == ["create"]


def test_a_segment_update_sends_the_full_replacement_built_from_the_read() -> None:
    """``version`` as read, the stated member, every unstated one carried -- and no
    ``kind``, ``site_key`` or ``name``."""
    fake = FakeNetwork()
    segment = fake.add_segment(filter_ids=["a", "b"], rank=3, enabled=False, version=9)
    with with_client() as (router, client):
        fake.mount(router)
        spec = segment_spec(vlan_id=30)  # rank, filter_ids, enabled unstated
        report = client.manifest.apply(manifest(segments=(spec,)))
    assert report.is_complete(), report.failure()
    body = next(b for m, p, b in fake.requests if m == "PUT")
    assert body == {
        "version": 9,
        "vlan_id": 30,
        "filter_ids": ["a", "b"],
        "enabled": False,
        "rank": 3,
    }
    assert segment["vlan_id"] == 30 and segment["version"] == 10


def test_a_stated_null_leaves_the_key_out_and_clears_the_member() -> None:
    """On a segment (``rank``) and on a profile (``idle_timeout_secs``, ``filter_id``)."""
    fake = FakeNetwork()
    segment = fake.add_segment(kind="quarantine", rank=None, vlan_id=99, name="quar")
    segment["rank"] = 5  # a stale rank the manifest clears
    fake.add_profile(segment, session_timeout_secs=600, idle_timeout_secs=120, filter_id="staff-in")
    spec = segment_spec(kind="quarantine", name="quar", vlan_id=99, rank=None)
    profile = NetworkProfileSpec(
        segment="staff", session_timeout_secs=600, idle_timeout_secs=None, filter_id=None
    )
    with with_client() as (router, client):
        fake.mount(router)
        plan = client.manifest.plan(manifest(segments=(spec,), profiles=(profile,)))
        assert [a.change for a in plan.actions] == ["update", "update"]
        report = client.manifest.apply(manifest(segments=(spec,), profiles=(profile,)))
    assert report.is_complete(), report.failure()
    puts = [b for m, p, b in fake.requests if m == "PUT"]
    assert "rank" not in puts[0]
    assert set(puts[1]["profile"]) == {"session_timeout_secs", "dictionary", "termination_action"}


def test_a_segment_and_its_profile_in_one_apply_use_the_segment_writes_own_version() -> None:
    """``replace_segment`` then ``replace_profile``; the profile's ``segment_version`` is the
    replace response's, not the one ``plan`` read."""
    fake = FakeNetwork()
    segment = fake.add_segment(version=9)
    fake.add_profile(segment, session_timeout_secs=600, version=6)
    spec = segment_spec(vlan_id=30)
    profile = NetworkProfileSpec(segment="staff", session_timeout_secs=900)
    with with_client() as (router, client):
        fake.mount(router)
        report = client.manifest.apply(manifest(segments=(spec,), profiles=(profile,)))
    assert report.is_complete(), report.failure()
    assert fake.writes() == [
        ("PUT", f"{NETWORK}/segments/{segment['id']}"),
        ("PUT", f"{NETWORK}/profiles/{segment['id']}"),
    ]
    sent = [b for m, p, b in fake.requests if m == "PUT"]
    assert sent[0]["version"] == 9
    assert sent[1]["segment_version"] == 10, "the replace response's version, not the read's 9"
    assert sent[1]["version"] == 6
    assert sent[1]["profile"]["dictionary"] == "axiam-radius-reply/1"


def test_a_profile_for_an_unchanged_segment_carries_the_read_segment_version() -> None:
    """No segment write: the version ``plan`` read is the one that is sent."""
    fake = FakeNetwork()
    segment = fake.add_segment(version=9)
    with with_client() as (router, client):
        fake.mount(router)
        report = client.manifest.apply(
            manifest(
                segments=(segment_spec(rank=1),),
                profiles=(NetworkProfileSpec(segment="staff", session_timeout_secs=900),),
            )
        )
    assert report.is_complete(), report.failure()
    created = next(b for m, p, b in fake.requests if m == "POST")
    assert created["segment_id"] == segment["id"] and created["segment_version"] == 9


def test_the_policy_is_written_first_so_a_profile_above_the_old_cap_can_follow() -> None:
    """§27.6.2 item 2: policy, then segments, then profiles."""
    fake = FakeNetwork(cap=3600, cap_version=0)
    spec = manifest(
        policy=7200,
        segments=(segment_spec(rank=1),),
        profiles=(NetworkProfileSpec(segment="staff", session_timeout_secs=7000),),
    )
    with with_client() as (router, client):
        fake.mount(router)
        plan = client.manifest.plan(spec)
        assert [a.target for a in plan.actions] == [
            "network-policy",
            "network-segment",
            "network-profile",
        ]
        report = client.manifest.apply(spec)
    assert report.is_complete(), report.failure()
    assert [(m, p.rsplit("/", 1)[-1]) for m, p in fake.writes()] == [
        ("PUT", "policy"),
        ("POST", "segments"),
        ("POST", "profiles"),
    ]
    assert fake.cap == 7200 and fake.cap_version == 1


def test_profiles_follow_the_order_of_their_segments() -> None:
    """Stable (rule 8): profiles are ordered by their segments, in whatever order listed."""
    fake = FakeNetwork()
    a = segment_spec(key="a", name="a", vlan_id=10, rank=1)
    b = segment_spec(key="b", name="b", vlan_id=11, rank=2)
    spec = manifest(
        segments=(a, b),
        profiles=(
            NetworkProfileSpec(segment="b", session_timeout_secs=900),
            NetworkProfileSpec(segment="a", session_timeout_secs=900),
        ),
    )
    with with_client() as (router, client):
        fake.mount(router)
        first = client.manifest.plan(spec)
        second = client.manifest.plan(spec)
    assert [(x.target, x.key) for x in first.actions] == [
        ("network-segment", "a"),
        ("network-segment", "b"),
        ("network-profile", "a"),
        ("network-profile", "b"),
    ]
    assert first == second


# ── 409, 403 and no retry ────────────────────────────────────────────────────


def _stale_cases() -> list[tuple[str, FakeNetwork, ManagementManifest, str, str]]:
    """``(name, server, manifest, failing path suffix, expected reason_code)``."""
    cases = []
    # segment create -> duplicate_vlan (already_exists)
    fake = FakeNetwork()
    fake.add_segment(name="other", vlan_id=20)
    cases.append(
        (
            "create_segment",
            fake,
            manifest(segments=(segment_spec(rank=1),)),
            "segments",
            "duplicate_vlan",
        )
    )
    # segment replace -> stale_version
    fake = FakeNetwork()
    seg = fake.add_segment()
    cases.append(
        (
            "replace_segment",
            fake,
            manifest(segments=(segment_spec(vlan_id=30),)),
            f"segments/{seg['id']}",
            "stale_version",
        )
    )
    # profile create -> stale_version
    fake = FakeNetwork()
    fake.add_segment()
    cases.append(
        (
            "create_profile",
            fake,
            manifest(
                segments=(segment_spec(rank=1),),
                profiles=(NetworkProfileSpec(segment="staff", session_timeout_secs=900),),
            ),
            "profiles",
            "stale_version",
        )
    )
    # profile replace -> stale_version
    fake = FakeNetwork()
    seg = fake.add_segment()
    fake.add_profile(seg, session_timeout_secs=600)
    cases.append(
        (
            "replace_profile",
            fake,
            manifest(
                segments=(segment_spec(rank=1),),
                profiles=(NetworkProfileSpec(segment="staff", session_timeout_secs=900),),
            ),
            f"profiles/{seg['id']}",
            "stale_version",
        )
    )
    # policy replace -> stale_version
    fake = FakeNetwork()
    cases.append(("replace_policy", fake, manifest(policy=900), "policy", "stale_version"))
    return cases


@pytest.mark.parametrize("index", range(5))
def test_a_409_makes_one_request_stops_the_apply_and_exposes_its_reason_code(index: int) -> None:
    """Each network write: exactly one request, later actions not attempted, ``reason_code``
    on the outcome and on the failure."""
    name, fake, spec, suffix, expected = _stale_cases()[index]
    # Make the write stale in the one place that needs it, after `plan` has read.
    original = fake.handle
    state = {"armed": False}

    def handle(request: httpx.Request) -> httpx.Response:
        if state["armed"] and request.method != "GET" and request.url.path.endswith(suffix):
            fake.requests.append((request.method, request.url.path, None))
            error = "already_exists" if expected.startswith("duplicate") else "conflict"
            return _conflict(error, expected)
        return original(request)

    fake.handle = handle  # type: ignore[method-assign]
    with with_client() as (router, client):
        fake.mount(router)
        plan = client.manifest.plan(spec)
        state["armed"] = True
        before = len(fake.requests)
        report = client.manifest.apply(spec)
    attempted = [r for r in fake.requests[before:] if r[0] != "GET"]
    assert len([r for r in attempted if r[1].endswith(suffix)]) == 1, name
    failure = report.failure()
    assert failure is not None and failure.reason_code == expected, name
    failed = [s for s in report.steps if s.outcome.status == "failed"]
    assert len(failed) == 1 and failed[0].outcome.reason_code == expected
    index_failed = report.steps.index(failed[0])
    assert all(s.outcome.status == "not-attempted" for s in report.steps[index_failed + 1 :])
    assert any(a.change != "no-change" for a in plan.actions)
    assert not report.is_complete()


def test_a_clamped_profile_is_judged_on_the_read() -> None:
    """Stored 7200, cap 3600, read 3600 + ``session_timeout_clamped``: stating the cap is
    ``NoChange`` and ``apply`` writes nothing; stating a value above the cap is an ``Update``
    whose ``apply`` sends one ``replace_profile``, meets ``403``, stops without retry, never
    attempts the later action, and the outcome carries the server's message."""
    fake = FakeNetwork(cap=3600)
    seg_a = fake.add_segment(name="a", vlan_id=10, rank=1)
    seg_b = fake.add_segment(name="b", vlan_id=11, rank=2)
    fake.add_profile(seg_a, session_timeout_secs=7200)  # stored above the (lowered) cap
    fake.add_profile(seg_b, session_timeout_secs=900)
    a = segment_spec(key="a", name="a", vlan_id=10, rank=1)
    b = segment_spec(key="b", name="b", vlan_id=11, rank=2)

    at_cap = manifest(
        segments=(a, b),
        profiles=(
            NetworkProfileSpec(segment="a", session_timeout_secs=3600),
            NetworkProfileSpec(segment="b", session_timeout_secs=900),
        ),
    )
    above = manifest(
        segments=(a, b),
        profiles=(
            NetworkProfileSpec(segment="a", session_timeout_secs=5000),
            NetworkProfileSpec(segment="b", session_timeout_secs=1200),
        ),
    )
    with with_client() as (router, client):
        fake.mount(router)
        assert client.manifest.plan(at_cap).is_converged()
        assert client.manifest.apply(at_cap).changed_count() == 0
        assert fake.writes() == []
        assert fake.profiles[seg_a["id"]]["session_timeout_secs"] == 7200, "stored value kept"

        plan = client.manifest.plan(above)
        assert [a.change for a in plan.actions if a.target == "network-profile"] == [
            "update",
            "update",
        ]
        report = client.manifest.apply(above)
    assert fake.writes() == [("PUT", f"{NETWORK}/profiles/{seg_a['id']}")], "one write, no retry"
    failure = report.failure()
    assert failure is not None and failure.action.target == "network-profile"
    assert "session_timeout_secs is above the tenant's cap of 3600" in failure.message
    assert failure.reason_code is None
    statuses = [s.outcome.status for s in report.steps]
    assert statuses[-2:] == ["failed", "not-attempted"], statuses
    assert fake.profiles[seg_b["id"]]["session_timeout_secs"] == 900, "later action not attempted"


def test_an_update_of_an_unstated_timeout_cannot_exist_but_a_carried_member_is_the_reads() -> None:
    """The timeout is always stated; the members left unstated ride across from the read."""
    fake = FakeNetwork()
    seg = fake.add_segment()
    fake.add_profile(
        seg,
        session_timeout_secs=600,
        idle_timeout_secs=120,
        filter_id="staff-in",
        service_type="framed_user",
        termination_action="default",
    )
    spec = manifest(
        segments=(segment_spec(rank=1),),
        profiles=(NetworkProfileSpec(segment="staff", session_timeout_secs=900),),
    )
    with with_client() as (router, client):
        fake.mount(router)
        client.manifest.apply(spec)
    sent = next(b for m, p, b in fake.requests if m == "PUT")
    assert sent["profile"] == {
        "session_timeout_secs": 900,
        "dictionary": "axiam-radius-reply/1",
        "termination_action": "default",
        "idle_timeout_secs": 120,
        "filter_id": "staff-in",
        "service_type": "framed_user",
    }


# ── filter_ids is a set ──────────────────────────────────────────────────────


def test_filter_ids_in_another_order_is_no_change_and_no_write() -> None:
    """A reorder alone is never an ``Update``."""
    fake = FakeNetwork()
    fake.add_segment(filter_ids=["a", "b", "c"])
    spec = manifest(segments=(segment_spec(rank=1, filter_ids=("c", "a", "b")),))
    with with_client() as (router, client):
        fake.mount(router)
        assert client.manifest.plan(spec).is_converged()
        assert client.manifest.apply(spec).changed_count() == 0
    assert fake.writes() == []


def test_an_update_for_another_member_sends_filter_ids_in_the_stated_order() -> None:
    """Names compare as exact strings; when the SDK writes, it sends the stated order."""
    fake = FakeNetwork()
    fake.add_segment(filter_ids=["a", "b", "c"])
    spec = manifest(segments=(segment_spec(rank=1, vlan_id=30, filter_ids=("c", "a", "b")),))
    with with_client() as (router, client):
        fake.mount(router)
        client.manifest.apply(spec)
    body = next(b for m, p, b in fake.requests if m == "PUT")
    assert body["filter_ids"] == ["c", "a", "b"]


def test_a_changed_name_in_filter_ids_is_an_update() -> None:
    """Exact strings: a different case is a different name."""
    fake = FakeNetwork()
    fake.add_segment(filter_ids=["a"])
    spec = manifest(segments=(segment_spec(rank=1, filter_ids=("A",)),))
    with with_client() as (router, client):
        fake.mount(router)
        assert [a.change for a in client.manifest.plan(spec).actions] == ["update"]


# ── refusals before any request ──────────────────────────────────────────────


def test_a_repeated_filter_id_is_refused_at_plan_and_at_apply_with_zero_wire_calls() -> None:
    """The comparison is of sets, and a set has no repeated member."""
    spec = manifest(segments=(segment_spec(rank=1, filter_ids=("a", "b", "a")),))
    with with_client() as (router, client):
        before = router.calls.call_count
        with pytest.raises(NetworkError, match="filter_id 'a' more than once"):
            client.manifest.plan(spec)
        with pytest.raises(NetworkError, match="more than once"):
            client.manifest.apply(spec)
        assert router.calls.call_count == before
    with pytest.raises(NetworkError):
        define_manifest(network=spec.network)


def test_a_repeated_natural_key_and_a_dangling_profile_are_refused_with_zero_wire_calls() -> None:
    """Two segments with one site, kind and name; a profile naming no segment of the manifest;
    two profiles for one segment; a repeated segment key."""
    twice = manifest(
        segments=(segment_spec(key="one", vlan_id=10), segment_spec(key="two", vlan_id=11))
    )
    dangling = manifest(
        segments=(segment_spec(),),
        profiles=(NetworkProfileSpec(segment="ghost", session_timeout_secs=900),),
    )
    two_profiles = manifest(
        segments=(segment_spec(),),
        profiles=(
            NetworkProfileSpec(segment="staff", session_timeout_secs=900),
            NetworkProfileSpec(segment="staff", session_timeout_secs=901),
        ),
    )
    same_key = manifest(segments=(segment_spec(), segment_spec(name="other", vlan_id=11)))
    with with_client() as (router, client):
        before = router.calls.call_count
        for bad, text in (
            (twice, "natural key"),
            (dangling, "no network segment of this manifest declares"),
            (two_profiles, "more than one profile"),
            (same_key, "declared more than once"),
        ):
            with pytest.raises(NetworkError, match=text):
                client.manifest.plan(bad)
            with pytest.raises(NetworkError, match=text):
                client.manifest.apply(bad)
        assert router.calls.call_count == before


@pytest.mark.parametrize("member", ["termination_action", "service_type"])
def test_an_unknown_open_enum_on_an_unstated_member_is_refused_at_plan_with_no_write(
    member: str,
) -> None:
    """C162-07 (§27.6.2 item 4): an ``Update`` would re-send what the SDK cannot name."""
    fake = FakeNetwork()
    seg = fake.add_segment()
    fake.add_profile(seg, session_timeout_secs=600, **{member: "future"})
    other = {"filter_id": "staff-in"} if member == "termination_action" else {}
    if member == "termination_action":
        seg["filter_ids"] = ["staff-in"]
    spec = manifest(
        segments=(segment_spec(rank=1, filter_ids=("staff-in",)),),
        profiles=(
            NetworkProfileSpec(
                segment="staff",
                session_timeout_secs=900,
                **({"service_type": "framed_user"} if member == "termination_action" else {}),
                **({"termination_action": "default"} if member == "service_type" else {}),
                **other,
            ),
        ),
    )
    with with_client() as (router, client):
        fake.mount(router)
        for call in (client.manifest.plan, client.manifest.apply):
            with pytest.raises(ValidationError, match=rf"{member}.*'future'"):
                call(spec)
    assert fake.writes() == []


@pytest.mark.parametrize(
    ("member", "stated_value"),
    [("termination_action", "default"), ("service_type", "framed_user")],
)
def test_a_stated_member_resolves_an_unknown_one_and_nothing_to_change_is_no_change(
    member: str, stated_value: str
) -> None:
    """The stated value replaces the unknown one; a ``NoChange`` is never refused for it.

    C163-09 (§27.9): both members, the body never carries the unknown ``"future"``, and
    ``apply`` of an unchanged manifest writes nothing (as ``plan`` reports it converged).
    """
    fake = FakeNetwork()
    seg = fake.add_segment()
    fake.add_profile(seg, session_timeout_secs=600, **{member: "future"})
    stated = manifest(
        segments=(segment_spec(rank=1),),
        profiles=(
            NetworkProfileSpec(segment="staff", session_timeout_secs=900, **{member: stated_value}),
        ),
    )
    unchanged = manifest(
        segments=(segment_spec(rank=1),),
        profiles=(NetworkProfileSpec(segment="staff", session_timeout_secs=600),),
    )
    with with_client() as (router, client):
        fake.mount(router)
        assert client.manifest.plan(unchanged).is_converged()
        client.manifest.apply(unchanged)
        assert fake.writes() == [], "NoChange at apply writes nothing"
        client.manifest.apply(stated)
    body = next(b for m, p, b in fake.requests if m == "PUT")
    assert body["profile"][member] == stated_value
    assert "future" not in json.dumps(body), "the unknown value is never re-sent"


def test_a_stated_none_termination_action_is_refused_with_zero_wire_calls() -> None:
    """C162-08: the member has a server default, so a manifest cannot say none."""
    spec = manifest(
        segments=(segment_spec(),),
        profiles=(
            NetworkProfileSpec(segment="staff", session_timeout_secs=900, termination_action=None),
        ),
    )
    with with_client() as (router, client):
        before = router.calls.call_count
        for call in (client.manifest.plan, client.manifest.apply):
            with pytest.raises(NetworkError, match="termination_action as None"):
                call(spec)
        assert router.calls.call_count == before


def test_the_same_name_on_another_site_or_kind_is_a_different_segment() -> None:
    """The key is site + kind + name, all three."""
    spec = manifest(
        segments=(
            segment_spec(key="a", site="hq", vlan_id=10, rank=1),
            segment_spec(key="b", site="branch", vlan_id=10, rank=1),
            segment_spec(key="c", kind="quarantine", vlan_id=11),
        )
    )
    define_manifest(network=spec.network)


# ── pruning ──────────────────────────────────────────────────────────────────


def test_a_segment_the_manifest_does_not_state_is_left_alone_and_nothing_is_deleted() -> None:
    """This SDK has no pruning for any namespace (§27.6 rule 4): no ``DELETE``, ever."""
    fake = FakeNetwork()
    fake.add_segment(name="kept", vlan_id=40, rank=9)
    stale = fake.add_segment(name="unlisted", vlan_id=41, rank=10)
    fake.add_profile(stale)
    spec = manifest(segments=(segment_spec(rank=1),))
    with with_client() as (router, client):
        fake.mount(router)
        client.manifest.apply(spec)
    assert not [r for r in fake.requests if r[0] == "DELETE"]
    assert stale["id"] in fake.segments and stale["id"] in fake.profiles


# ── the async twin ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_async_manifest_applies_and_converges_too() -> None:
    """The same section on ``AsyncAxiamClient``: ordered writes, then an all-``NoChange`` plan."""
    fake = FakeNetwork()
    async with with_async_client() as (router, client):
        fake.mount(router)
        report = await client.manifest.apply(full_manifest())
        assert report.is_complete(), report.failure()
        again = await client.manifest.plan(full_manifest())
    assert [(m, p.rsplit("/", 1)[-1]) for m, p in fake.writes()] == [
        ("POST", "segments"),
        ("POST", "profiles"),
    ]
    assert [a.change for a in again.actions] == ["no-change"] * 3


@pytest.mark.asyncio
async def test_the_async_manifest_stops_on_a_conflict_and_exposes_its_reason_code() -> None:
    """A ``409`` fails that action, exposes the sub-code, and later actions are not attempted."""
    fake = FakeNetwork()
    fake.add_segment(name="other", vlan_id=20)
    async with with_async_client() as (router, client):
        fake.mount(router)
        report = await client.manifest.apply(
            manifest(
                segments=(segment_spec(rank=1),),
                profiles=(NetworkProfileSpec(segment="staff", session_timeout_secs=900),),
            )
        )
    failure = report.failure()
    assert failure is not None and failure.reason_code == "duplicate_vlan"
    assert [s.outcome.status for s in report.steps] == ["failed", "not-attempted"]


def test_a_403_on_a_network_write_is_an_authorization_failure_reported_as_given() -> None:
    """The write gate's refusal is the action's failure; nothing is adjusted or retried."""

    def answer(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"items": [], "total": 0, "offset": 0, "limit": 200})
        return httpx.Response(
            403,
            json={
                "error": "authorization_denied",
                "message": "denied by the write gate",
                "action": "network:segments_write",
                "resource_id": "/network/zones/default",
            },
        )

    with with_client() as (router, client):
        router.route(path__regex=rf"^{NETWORK}/.*").mock(side_effect=answer)
        report = client.manifest.apply(
            manifest(
                segments=(segment_spec(rank=1),),
                profiles=(NetworkProfileSpec(segment="staff", session_timeout_secs=900),),
            )
        )
        posts = [
            c for c in router.calls if c.request.method == "POST" and NETWORK in str(c.request.url)
        ]
    assert len(posts) == 1, "one write, never retried, and the profile is not attempted"
    failure = report.failure()
    assert failure is not None and "denied by the write gate" in failure.message
    assert [s.outcome.status for s in report.steps] == ["failed", "not-attempted"]


def test_unstated_members_are_the_unset_sentinel_and_it_prints_as_written() -> None:
    """``UNSET`` is a statement of silence, distinct from ``None``."""
    spec = segment_spec()
    assert spec.rank is UNSET and spec.filter_ids is UNSET and spec.enabled is UNSET
    assert repr(UNSET) == "UNSET"
    assert segment_spec(rank=None).rank is None
