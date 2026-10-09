"""The ``ssf`` management namespace — CONTRACT §32.8's six management tests.

The push header is generated at run time; failure messages print offsets and
fixed text only.
"""

from __future__ import annotations

import json
import secrets
import uuid
from typing import Any

import httpx
import pydantic
import pytest
from pydantic import SecretStr

from axiam_sdk import AuthError, NetworkError
from axiam_sdk.management import (
    ConflictError,
    NotFoundError,
    PageRequest,
    ValidationError,
    models,
    ssf_stream_input,
)
from axiam_sdk.ssf import SESSION_REVOKED
from tests.management_support import BASE_URL, TENANT_ID, mount_json, with_client

STREAMS = f"/api/v1/tenants/{TENANT_ID}/ssf/streams"


def header() -> str:
    """A push ``Authorization`` header value made at run time."""
    return f"Bearer {secrets.token_urlsafe(24)}"


def assert_no_fragment(haystack: str, secret: str) -> None:
    """No 8-character substring of ``secret`` in ``haystack`` (offset-only failure)."""
    for i in range(len(secret) - 7):
        if secret[i : i + 8] in haystack:
            pytest.fail(f"an 8-character fragment of the secret (offset {i}) was rendered")


def stream_body(**extra: Any) -> dict[str, Any]:
    """A server ``SsfStream`` body."""
    body: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "tenant_id": TENANT_ID,
        "receiver_client_id": "rp-1",
        "audience": "https://rp.example",
        "description": None,
        "delivery_method": "push",
        "endpoint_url": "https://rp.example/ssf",
        "authorization_header_set": True,
        "events_allowed": [SESSION_REVOKED],
        "events_requested": [SESSION_REVOKED],
        "events_delivered": [SESSION_REVOKED],
        "subject_format": "iss_sub",
        "status": "enabled",
        "status_reason": None,
        "status_actor": "admin",
        "last_verification_at": None,
        "created_at": "2026-10-04T00:00:00Z",
        "updated_at": "2026-10-04T00:00:00Z",
        "transmitter_active": True,
    }
    body.update(extra)
    return body


def stream_input(push_header: str | None = None) -> models.SsfStreamInput:
    """An ``SsfStreamInput`` with the four required members, a description and
    an endpoint (and a header)."""
    body = models.SsfStreamInput(
        audience="https://rp.example",
        delivery_method="push",
        description="the RP",
        endpoint_url="https://rp.example/ssf",
        events_allowed=[SESSION_REVOKED],
        receiver_client_id="rp-1",
    )
    if push_header is not None:
        body.authorization_header = SecretStr(push_header)
    return body


def sent(route: Any, index: int = 0) -> Any:
    """The JSON body of the ``index``-th request a route saw."""
    return json.loads(route.calls[index].request.content)


# ── 1. Replacement ───────────────────────────────────────────────────────────


def test_update_stream_puts_every_member_it_models() -> None:
    """``PUT`` with every modelled member; the four required ones enforced."""
    with pytest.raises(pydantic.ValidationError):
        models.SsfStreamInput(audience="a", delivery_method="push")  # type: ignore[call-arg]
    stream_id = str(uuid.uuid4())
    with with_client() as (router, client):
        route = mount_json(router, "PUT", f"{STREAMS}/{stream_id}", 200, stream_body())
        body = stream_input()
        body.events_requested = [SESSION_REVOKED]
        body.subject_format = "iss_sub"
        body.status = "enabled"
        body.status_reason = "ok"
        body.clear_authorization_header = False
        stream = client.ssf.update_stream(stream_id, body)
        assert isinstance(stream, models.SsfStream) and stream.transmitter_active
        assert route.calls[0].request.method == "PUT"
        wire = sent(route)
        for member in (
            "receiver_client_id",
            "audience",
            "delivery_method",
            "events_allowed",
            "description",
            "endpoint_url",
            "events_requested",
            "subject_format",
            "status",
            "status_reason",
            "clear_authorization_header",
        ):
            assert member in wire, member
        assert wire["events_allowed"] == [SESSION_REVOKED]
        assert "authorization_header" not in wire, "absent keeps the stored header"


# ── 2. The header is Sensitive ───────────────────────────────────────────────


def test_the_push_header_is_sent_and_never_rendered() -> None:
    """On the wire, in no rendering; a response carrying one drops it."""
    h = header()
    body = stream_input(h)
    for rendering in (repr(body), str(body), body.model_dump_json()):
        assert_no_fragment(rendering, h)
    stream_id = str(uuid.uuid4())
    with with_client() as (router, client):
        create = mount_json(router, "POST", STREAMS, 201, stream_body())
        mount_json(
            router,
            "GET",
            f"{STREAMS}/{stream_id}",
            200,
            stream_body(authorization_header=h),
        )
        client.ssf.create_stream(body)
        if sent(create)["authorization_header"] != h:
            pytest.fail("the push header was not on the wire")
        stream = client.ssf.get_stream(stream_id)
    for rendering in (repr(stream), str(stream), stream.model_dump_json()):
        assert_no_fragment(rendering, h)
    assert "authorization_header" not in models.SsfStream.model_fields
    assert not hasattr(stream, "authorization_header")


# ── 3. Open decoding ─────────────────────────────────────────────────────────


def test_unknown_values_and_an_inactive_transmitter_decode() -> None:
    """Unknown status, method, format, actor and event type; the reason optional."""
    odd = stream_body(
        status="archived",
        delivery_method="websocket",
        subject_format="opaque",
        status_actor="system",
        events_allowed=["https://example.test/secevent/new-event"],
        transmitter_active=False,
        transmitter_inactive_reason="per-tenant issuers are off",
    )
    stream = models.SsfStream.model_validate(odd)
    assert stream.status == "archived"
    assert stream.delivery_method == "websocket"
    assert stream.subject_format == "opaque"
    assert stream.status_actor == "system"
    assert stream.events_allowed == ["https://example.test/secevent/new-event"]
    assert stream.transmitter_active is False
    assert stream.transmitter_inactive_reason == "per-tenant issuers are off"
    without = models.SsfStream.model_validate(stream_body(transmitter_active=False))
    assert without.transmitter_inactive_reason is None
    # Decoded, but never sent back.
    with pytest.raises(ValidationError):
        ssf_stream_input(stream).to_wire()


# ── 4. Pagination ────────────────────────────────────────────────────────────


def test_list_streams_pages_with_search_on_every_request() -> None:
    """``Page`` with ``total``; the walk carries ``search``."""

    def page(request: httpx.Request) -> httpx.Response:
        """Two one-item pages, then an empty one."""
        offset = int(request.url.params.get("offset", "0"))
        items = [stream_body()] if offset < 2 else []
        return httpx.Response(200, json={"items": items, "total": 2, "offset": offset, "limit": 1})

    with with_client() as (router, client):
        listing = router.get(f"{BASE_URL}{STREAMS}").mock(side_effect=page)
        first = client.ssf.list_streams(PageRequest(limit=1, search="rp.example"))
        assert first.total == 2
        assert len(client.ssf.list_streams_all(PageRequest(limit=1, search="rp.example"))) == 2
        for call in listing.calls:
            assert call.request.url.params.get("search") == "rp.example"


# ── 5. No retry ──────────────────────────────────────────────────────────────


def test_no_write_is_retried_on_503() -> None:
    """The three writes: exactly one request each, ``NetworkError``."""
    stream_id = str(uuid.uuid4())
    with with_client() as (router, client):
        assert client._retry_enabled
        routes = [
            mount_json(router, "POST", STREAMS, 503, None),
            mount_json(router, "PUT", f"{STREAMS}/{stream_id}", 503, None),
            mount_json(router, "DELETE", f"{STREAMS}/{stream_id}", 503, None),
        ]
        for call in (
            lambda: client.ssf.create_stream(stream_input(header())),
            lambda: client.ssf.update_stream(stream_id, stream_input()),
            lambda: client.ssf.delete_stream(stream_id),
        ):
            with pytest.raises(NetworkError):
                call()
        assert [r.call_count for r in routes] == [1, 1, 1]


# ── 6. Errors ────────────────────────────────────────────────────────────────


def test_statuses_map_per_section_2() -> None:
    """400 with the message, 409 on create, 404 on get, 401 (refresh failing)."""
    stream_id = str(uuid.uuid4())
    with with_client() as (router, client):
        mount_json(
            router,
            "PUT",
            f"{STREAMS}/{stream_id}",
            400,
            {"error": "validation_error", "message": "endpoint_url: must be https"},
        )
        mount_json(router, "POST", STREAMS, 409, {"error": "conflict", "message": "audience"})
        mount_json(
            router, "GET", f"{STREAMS}/{stream_id}", 404, {"error": "not_found", "message": "no"}
        )
        mount_json(
            router,
            "DELETE",
            f"{STREAMS}/{stream_id}",
            401,
            {"error": "unauthorized", "message": "human only"},
        )
        mount_json(router, "POST", "/api/v1/auth/refresh", 401, {"error": "unauthorized"})
        with pytest.raises(ValidationError) as invalid:
            client.ssf.update_stream(stream_id, stream_input())
        assert "must be https" in invalid.value.message
        with pytest.raises(ConflictError):
            client.ssf.create_stream(stream_input())
        with pytest.raises(NotFoundError):
            client.ssf.get_stream(stream_id)
        with pytest.raises(AuthError):
            client.ssf.delete_stream(stream_id)


def test_a_read_converts_into_the_replacement_body_without_the_header() -> None:
    """Every input member carried over; the header and its clear flag absent."""
    stream = models.SsfStream.model_validate(stream_body(description="the RP"))
    body = ssf_stream_input(stream)
    wire = body.to_wire()
    assert "authorization_header" not in wire
    assert "clear_authorization_header" not in wire
    assert wire["events_requested"] == [SESSION_REVOKED]
    assert wire["description"] == "the RP"
    assert wire["status"] == "enabled"


# ── §34.2 P12.3: a write-only secret is present or absent, never null ───────


def test_an_assigned_none_push_header_is_omitted_never_sent_as_null() -> None:
    """``authorization_header=None`` keeps the stored header: no key on the
    wire, on ``create_stream`` or ``update_stream`` (§32.2, §34.2 P12.3)."""
    stream_id = str(uuid.uuid4())
    with with_client() as (router, client):
        post = mount_json(router, "POST", STREAMS, 201, stream_body())
        put = mount_json(router, "PUT", f"{STREAMS}/{stream_id}", 200, stream_body())
        body = stream_input()
        body.authorization_header = None
        client.ssf.create_stream(body)
        client.ssf.update_stream(stream_id, body)
        for route in (post, put):
            assert "authorization_header" not in json.loads(route.calls[0].request.content)
