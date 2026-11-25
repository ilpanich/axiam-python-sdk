"""CONTRACT.md §8 "Signed authorization responses" (contract 1.68; N2, D-9): the AMQP authz
requester.

Broker-free: a fake :class:`AuthzTransport` stands in for the broker, and the contract's four
test vectors are verified byte for byte. The fixture's server-signed ``AuthzRequest`` vector pins
the request side the same way.
"""

# ruff: noqa: E501 -- the contract's wire vectors are single-line byte strings.

from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_mod
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from axiam_sdk.amqp import (
    AUTHZ_REQUEST_QUEUE,
    AioPikaAuthzTransport,
    AuthzRequester,
    AuthzRequesterClosedError,
    build_authz_request,
)
from axiam_sdk.amqp._authz_requester import _Pending

VEC_MASTER_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
VEC_SUBKEY = bytes.fromhex("919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89")
VEC_TENANT = "11111111-1111-1111-1111-111111111111"
VEC_OTHER_TENANT = "99999999-9999-9999-9999-999999999999"
VEC_CORRELATION = "22222222-2222-2222-2222-222222222222"
VEC_NONCE = "55555555-5555-5555-5555-555555555555"
SUBJECT = "33333333-3333-3333-3333-333333333333"
RESOURCE = "44444444-4444-4444-4444-444444444444"

# (name, canonical bytes, signature, allowed, reason, reason_code) -- CONTRACT §8 vectors 1-4.
VECTORS = [
    (
        "1 allow",
        '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
        "8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a",
        True,
        "",
        "allowed",
    ),
    (
        "2 deny no_grant",
        '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action \'documents:read\'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
        "f3105ee678acd79da6ffd28c02b86311e16bb8d8dfd3fd0addbacdf73bd5a400",
        False,
        "no permission grants action 'documents:read'",
        "no_grant",
    ),
    (
        "3 deny denied_by_rule",
        '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"an explicit deny rule refuses action \'documents:read\'","reason_code":"denied_by_rule","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
        "4bfc2ce9a035bd4a028ee2a5cb75a08832915c60cd2b176c8d4bf28910a61adc",
        False,
        "an explicit deny rule refuses action 'documents:read'",
        "denied_by_rule",
    ),
    (
        "4 escapes encoders disagree on",
        '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action \'docs:a&b</\\"c\\">/é€\'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
        "5194142df4bf66b07e9e8d516caf6be099af025219ab12deb26fea39e93490ff",
        False,
        "no permission grants action 'docs:a&b</\"c\">/é€'",
        "no_grant",
    ),
]


def wire(canonical: str, signature: str) -> bytes:
    return (canonical[:-1] + ',"hmac_signature":"' + signature + '"}').encode("utf-8")


def vector_wire(index: int) -> bytes:
    _name, canonical, signature, *_rest = VECTORS[index]
    return wire(canonical, signature)


def subkey_for(tenant: str, key_version: int) -> bytes:
    """HKDF-SHA256(salt, ikm=master, info="axiam-amqp-v1" || key_version || tenant raw 16)."""
    info = b"axiam-amqp-v1" + bytes([key_version]) + uuid.UUID(tenant).bytes
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"axiam-amqp-hkdf-salt-v1", info=info
    ).derive(VEC_MASTER_KEY)


def sign_with(key: bytes, canonical: str) -> bytes:
    mac = hmac_mod.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return wire(canonical, mac)


class RecordingDelivery:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.acked = 0
        self.nacked = 0

    async def ack(self) -> None:
        self.acked += 1

    async def nack(self) -> None:
        self.nacked += 1


class FakeTransport:
    """A broker-free AuthzTransport."""

    def __init__(self, queue: str = "amq.gen-Xk3p") -> None:
        self.queue = queue
        self.deliveries: asyncio.Queue[RecordingDelivery | None] = asyncio.Queue()
        self.published: list[dict[str, Any]] = []
        self.closed = 0

    async def declare_reply_queue(self):
        async def stream():
            while True:
                item = await self.deliveries.get()
                if item is None:
                    return
                yield item

        return self.queue, stream()

    async def publish_request(self, queue: str, reply_to: str, correlation_id: str, body: bytes):
        self.published.append(
            {"queue": queue, "reply_to": reply_to, "correlation_id": correlation_id, "body": body}
        )

    async def close(self) -> None:
        self.closed += 1


class ListLogger(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def make_logger() -> tuple[logging.Logger, ListLogger]:
    logger = logging.getLogger(f"test.authz.{uuid.uuid4()}")
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    handler = ListLogger()
    logger.addHandler(handler)
    return logger, handler


async def vector_requester(**kwargs: Any) -> tuple[AuthzRequester, asyncio.Future[Any]]:
    """A requester for the vectors' tenant with one outstanding request (the vectors'
    correlation_id and nonce)."""
    requester = await AuthzRequester.open(
        FakeTransport(), tenant_id=VEC_TENANT, signing_key=VEC_SUBKEY, **kwargs
    )
    future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    requester._pending[VEC_CORRELATION] = _Pending(VEC_NONCE, future)
    return requester, future


async def offer(
    requester: AuthzRequester, future: asyncio.Future[Any], body: bytes
) -> tuple[Any, RecordingDelivery]:
    """Feed ``body`` to the requester; return the decision it completed the request with (or
    ``None``) and the delivery."""
    delivery = RecordingDelivery(body)
    await requester._handle(delivery)
    return (future.result() if future.done() else None), delivery


# --- the contract's vectors -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_subkey_derivation_matches_the_contract() -> None:
    assert subkey_for(VEC_TENANT, 2) == VEC_SUBKEY


@pytest.mark.parametrize("index", range(4), ids=[v[0] for v in VECTORS])
@pytest.mark.asyncio
async def test_contract_vectors_verify(index: int) -> None:
    _name, _canonical, _sig, allowed, reason, code = VECTORS[index]
    requester, future = await vector_requester()
    try:
        decision, delivery = await offer(requester, future, vector_wire(index))
        assert decision is not None, "the contract vector must verify and complete the request"
        assert (decision.allowed, decision.reason, decision.reason_code) == (allowed, reason, code)
        assert decision.unsigned is False
        assert delivery.acked == 1

        # Retired on acceptance: the same response again is dropped.
        again = asyncio.get_running_loop().create_future()
        duplicate = RecordingDelivery(vector_wire(index))
        await requester._handle(duplicate)
        assert not again.done()
        assert duplicate.nacked == 1 and duplicate.acked == 0
    finally:
        await requester.close()


@pytest.mark.asyncio
async def test_vector_4_decision_comes_from_the_received_bytes_not_a_reserialization() -> None:
    """C2: ``json.dumps`` with its default ``ensure_ascii`` would write ``\\u00e9`` for ``é`` and
    compute a different MAC. The requester verifies the received bytes."""
    canonical = VECTORS[3][1]
    reserialized = json.dumps(json.loads(canonical), separators=(",", ":"))
    assert reserialized != canonical, "the vector must be one a re-serialization breaks"
    requester, future = await vector_requester()
    try:
        decision, _d = await offer(requester, future, vector_wire(3))
        assert decision is not None
        assert decision.reason == "no permission grants action 'docs:a&b</\"c\">/é€'"
    finally:
        await requester.close()


# --- discarded, never an allow, never a completed request ----------------------------------


def _replace(body: bytes, old: str, new: str) -> bytes:
    text = body.decode("utf-8")
    assert old in text, old
    return text.replace(old, new, 1).encode("utf-8")


def _discard_cases() -> list[tuple[str, bytes]]:
    v1, v2 = VECTORS[0][1], VECTORS[1][1]
    good = VEC_SUBKEY
    return [
        ("vector 1 under another tenant's subkey", sign_with(subkey_for(VEC_OTHER_TENANT, 2), v1)),
        ("vector 1 under key_version 3", sign_with(subkey_for(VEC_TENANT, 3), v1)),
        (
            "tampered: allowed flipped to false, signature kept",
            _replace(vector_wire(0), '"allowed":true', '"allowed":false'),
        ),
        (
            "tampered: vector 2 flipped to true, signature kept",
            _replace(vector_wire(1), '"allowed":false', '"allowed":true'),
        ),
        ("tampered reason_code", _replace(vector_wire(1), "no_grant", "allowed")),
        (
            "response for another nonce",
            sign_with(good, v1.replace(VEC_NONCE, "66666666-6666-6666-6666-666666666666")),
        ),
        (
            "response for another correlation_id",
            sign_with(good, v1.replace(VEC_CORRELATION, "77777777-7777-7777-7777-777777777777")),
        ),
        (
            "response for another tenant (validly signed with our key)",
            sign_with(good, v1.replace(VEC_TENANT, VEC_OTHER_TENANT)),
        ),
        (
            "no allowed: a signed AuthzRequest on the response queue",
            sign_with(
                good,
                f'{{"correlation_id":"{VEC_CORRELATION}","tenant_id":"{VEC_TENANT}",'
                f'"subject_id":"{SUBJECT}","action":"documents:read","resource_id":"{RESOURCE}",'
                f'"key_version":2,"nonce":"{VEC_NONCE}","issued_at":"2026-07-10T12:00:00Z"}}',
            ),
        ),
        (
            "allowed not a boolean",
            sign_with(good, v1.replace('"allowed":true', '"allowed":"true"')),
        ),
        (
            "no tenant_id",
            sign_with(good, v1.replace(f'"tenant_id":"{VEC_TENANT}",', "")),
        ),
        ("no nonce", sign_with(good, v1.replace(f',"nonce":"{VEC_NONCE}"', ""))),
        (
            "signature not the trailing member",
            _replace(vector_wire(0), '"allowed":true', '"allowed":true,"x":1'),
        ),
        (
            "duplicate allowed keys, validly signed",
            sign_with(good, v1.replace('"allowed":true', '"allowed":false,"allowed":true')),
        ),
        (
            "case-variant allowed key, validly signed",
            sign_with(good, v1.replace('"reason_code"', '"ALLOWED":false,"reason_code"')),
        ),
        ("trailing whitespace after the closing brace", vector_wire(0) + b"\n"),
        (
            "non-hex signature",
            _replace(vector_wire(0), VECTORS[0][2], "z" * 64),
        ),
        ("short signature", _replace(vector_wire(0), VECTORS[0][2], VECTORS[0][2][:62])),
        ("not JSON", b"not json"),
        ("not an object", b"[1,2]"),
        ("invalid UTF-8", b"\xff\xfe"),
        (
            "reason is not a string, validly signed",
            sign_with(
                good,
                v2.replace(
                    '"reason":"no permission grants action \'documents:read\'"', '"reason":7'
                ),
            ),
        ),
    ]


@pytest.mark.parametrize(("name", "body"), _discard_cases(), ids=[c[0] for c in _discard_cases()])
@pytest.mark.asyncio
async def test_a_response_that_fails_verification_is_discarded_and_never_allows(
    name: str, body: bytes
) -> None:
    logger, log = make_logger()
    requester, future = await vector_requester(logger=logger)
    try:
        decision, delivery = await offer(requester, future, body)
        assert decision is None and not future.done(), "never completes the request, never an allow"
        assert delivery.nacked == 1 and delivery.acked == 0, "nacked without requeue"
        assert any("discarded" in line for line in log.records), "logged as a security event"
        assert all("hmac" not in line.lower() or "hmac_signature" in line for line in log.records)
        for _n, _c, signature, *_r in VECTORS:
            assert all(signature not in line for line in log.records)

        # The request is still outstanding: the genuine answer completes it.
        decision, _ = await offer(requester, future, vector_wire(0))
        assert decision is not None and decision.allowed is True
    finally:
        await requester.close()


# --- unsigned responses ----------------------------------------------------------------------

UNSIGNED = (
    f'{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"reason_code":"allowed"}}'
).encode()


@pytest.mark.asyncio
async def test_unsigned_is_refused_by_default() -> None:
    requester, future = await vector_requester()
    try:
        decision, delivery = await offer(requester, future, UNSIGNED)
        assert decision is None and delivery.nacked == 1
    finally:
        await requester.close()


@pytest.mark.asyncio
async def test_unsigned_is_accepted_with_the_opt_out_flagged_and_logged() -> None:
    logger, log = make_logger()
    requester, future = await vector_requester(allow_unsigned_responses=True, logger=logger)
    try:
        decision, _d = await offer(requester, future, UNSIGNED)
        assert decision is not None
        assert (decision.allowed, decision.unsigned, decision.reason_code) == (
            True,
            True,
            "allowed",
        )
        assert any("UNSIGNED" in line for line in log.records)
    finally:
        await requester.close()


@pytest.mark.parametrize(
    "body",
    [
        '{"correlation_id":"77777777-7777-7777-7777-777777777777","allowed":true}',
        f'{{"correlation_id":"{VEC_CORRELATION}"}}',
        f'{{"correlation_id":"{VEC_CORRELATION}","allowed":"yes"}}',
    ],
)
@pytest.mark.asyncio
async def test_opt_out_needs_an_outstanding_correlation_id_and_a_boolean_allowed(body: str) -> None:
    requester, future = await vector_requester(allow_unsigned_responses=True)
    try:
        decision, _d = await offer(requester, future, body.encode())
        assert decision is None
    finally:
        await requester.close()


@pytest.mark.asyncio
async def test_opt_out_never_admits_a_signed_response_that_fails() -> None:
    requester, future = await vector_requester(allow_unsigned_responses=True)
    try:
        tampered = _replace(vector_wire(1), '"allowed":false', '"allowed":true')
        decision, _d = await offer(requester, future, tampered)
        assert decision is None
        null_sig = (
            f'{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"hmac_signature":null}}'
        ).encode()
        decision, _d = await offer(requester, future, null_sig)
        assert decision is None, "a null hmac_signature is a signature member, not an absent one"
    finally:
        await requester.close()


# --- the request ----------------------------------------------------------------------------


def test_request_reproduces_the_server_signed_vector() -> None:
    fixture = json.loads(
        (Path(__file__).parent.parent / "testdata" / "v2_reference_vectors.json").read_text()
    )
    reference = fixture["authz_request"]
    body = build_authz_request(
        VEC_SUBKEY,
        correlation_id=VEC_CORRELATION,
        tenant_id=VEC_TENANT,
        subject_id=SUBJECT,
        action="documents:read",
        resource_id=RESOURCE,
        scope="confidential",
        nonce=VEC_NONCE,
        issued_at=datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC),
    )
    expected = (
        reference["canonical_signed_json"][:-1]
        + ',"hmac_signature":"'
        + reference["hmac_signature_hex"]
        + '"}'
    )
    assert body.decode("utf-8") == expected


def test_request_writes_non_ascii_and_html_characters_raw_like_serde_json() -> None:
    body = build_authz_request(
        VEC_SUBKEY,
        correlation_id=VEC_CORRELATION,
        tenant_id=VEC_TENANT,
        subject_id=SUBJECT,
        action='docs:a&b</"c">/é€ ',
        resource_id=RESOURCE,
        scope=None,
        nonce=VEC_NONCE,
        issued_at=datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC),
    )
    text = body.decode("utf-8")
    assert '"action":"docs:a&b</\\"c\\">/é€ "' in text
    assert '"scope"' not in text
    canonical, _, tail = text.rpartition(',"hmac_signature":"')
    signature = tail[:-2]
    assert (
        hmac_mod.new(VEC_SUBKEY, (canonical + "}").encode(), hashlib.sha256).hexdigest()
        == signature
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"subject_id": "x"},
        {"resource_id": "x"},
        {"action": "a\ud800b"},
    ],
)
def test_request_refuses_unsignable_input(kwargs: dict[str, str]) -> None:
    args: dict[str, Any] = {
        "correlation_id": "c",
        "tenant_id": VEC_TENANT,
        "subject_id": SUBJECT,
        "action": "a",
        "resource_id": RESOURCE,
        "scope": None,
        "nonce": "n",
        "issued_at": datetime.now(UTC),
    }
    args.update(kwargs)
    with pytest.raises(ValueError):
        build_authz_request(b"k", **args)


# --- opening, end to end, timeout, close ------------------------------------------------------


@pytest.mark.parametrize("queue", ["", "axiam.authz.response", "axiam.mail.outbound"])
@pytest.mark.asyncio
async def test_open_refuses_a_non_private_reply_queue(queue: str) -> None:
    transport = FakeTransport(queue)
    with pytest.raises(ValueError, match="private queue"):
        await AuthzRequester.open(transport, tenant_id=VEC_TENANT, signing_key=VEC_SUBKEY)
    assert transport.closed == 1


@pytest.mark.asyncio
async def test_open_refuses_a_bad_tenant_or_a_missing_key() -> None:
    with pytest.raises(ValueError):
        await AuthzRequester.open(FakeTransport(), tenant_id="not-a-uuid", signing_key=b"k")
    with pytest.raises(ValueError):
        await AuthzRequester.open(FakeTransport(), tenant_id=VEC_TENANT, signing_key=b"")


async def _next_published(transport: FakeTransport, count: int) -> dict[str, Any]:
    for _ in range(200):
        if len(transport.published) >= count:
            return transport.published[count - 1]
        await asyncio.sleep(0.005)
    raise AssertionError("no request was published")


@pytest.mark.asyncio
async def test_check_end_to_end_with_a_fake_channel() -> None:
    transport = FakeTransport()
    logger, log = make_logger()
    requester = await AuthzRequester.open(
        transport, tenant_id=VEC_TENANT, signing_key=VEC_SUBKEY, timeout=3, logger=logger
    )
    assert requester.reply_to == "amq.gen-Xk3p"

    task = asyncio.create_task(requester.check(SUBJECT, 'docs:a&b</"c">', RESOURCE, "confidential"))
    published = await _next_published(transport, 1)

    # Default-exchange routing to the request queue, a private reply_to, and a correlation_id
    # property equal to the body's.
    assert published["queue"] == AUTHZ_REQUEST_QUEUE
    assert published["reply_to"] == transport.queue
    request = json.loads(published["body"])
    assert request["correlation_id"] == published["correlation_id"]
    assert request["tenant_id"] == VEC_TENANT and request["key_version"] == 2
    text = published["body"].decode("utf-8")
    assert '"action":"docs:a&b</\\"c\\">"' in text, "serde_json writes < > & raw"

    # The request verifies under the subkey over its canonical bytes (received bytes, trailing
    # signature cut out), as the server would.
    canonical, _, tail = text.rpartition(',"hmac_signature":"')
    assert (
        hmac_mod.new(VEC_SUBKEY, (canonical + "}").encode(), hashlib.sha256).hexdigest()
        == tail[:-2]
    )

    # A forgery with the right ids and the wrong key is discarded; the Check keeps waiting.
    canonical_response = (
        f'{{"correlation_id":"{published["correlation_id"]}","allowed":true,'
        f'"reason_code":"allowed","tenant_id":"{VEC_TENANT}","nonce":"{request["nonce"]}"}}'
    )
    forged = RecordingDelivery(sign_with(subkey_for(VEC_OTHER_TENANT, 2), canonical_response))
    await transport.deliveries.put(forged)
    await asyncio.sleep(0.05)
    assert not task.done(), "a forged response completed the check"
    assert forged.nacked == 1
    assert any("discarded" in line for line in log.records)

    genuine = RecordingDelivery(sign_with(VEC_SUBKEY, canonical_response))
    await transport.deliveries.put(genuine)
    decision = await asyncio.wait_for(task, 2)
    assert decision.allowed is True and decision.reason_code == "allowed"
    assert genuine.acked == 1

    # Fresh, distinct, unpredictable ids per request.
    task2 = asyncio.create_task(requester.check(SUBJECT, "documents:read", RESOURCE))
    published2 = await _next_published(transport, 2)
    request2 = json.loads(published2["body"])
    assert published2["correlation_id"] != published["correlation_id"]
    assert request2["nonce"] != request["nonce"]
    assert request2["nonce"] != published2["correlation_id"]
    assert "scope" not in request2

    await requester.close()
    with pytest.raises(AuthzRequesterClosedError):
        await task2
    with pytest.raises(AuthzRequesterClosedError):
        await requester.check(SUBJECT, "a", RESOURCE)


@pytest.mark.asyncio
async def test_check_times_out_without_an_answer_and_leaves_nothing_outstanding() -> None:
    requester = await AuthzRequester.open(
        FakeTransport(), tenant_id=VEC_TENANT, signing_key=VEC_SUBKEY, timeout=0.03
    )
    try:
        with pytest.raises(TimeoutError):
            await requester.check(SUBJECT, "a", RESOURCE)
        assert requester._pending == {}
    finally:
        await requester.close()


@pytest.mark.asyncio
async def test_the_requester_closes_when_the_reply_queue_goes_away() -> None:
    transport = FakeTransport()
    requester = await AuthzRequester.open(
        transport, tenant_id=VEC_TENANT, signing_key=VEC_SUBKEY, timeout=3
    )
    task = asyncio.create_task(requester.check(SUBJECT, "a", RESOURCE))
    await _next_published(transport, 1)
    await transport.deliveries.put(None)  # the broker closed the queue
    with pytest.raises(AuthzRequesterClosedError):
        await asyncio.wait_for(task, 2)
    await requester.close()


# --- the aio-pika transport -------------------------------------------------------------------


class FakeQueue:
    name = "amq.gen-abc"

    def __init__(self, calls: dict[str, Any]) -> None:
        self._calls = calls

    def iterator(self, **kwargs: Any) -> Any:
        self._calls["iterator_kwargs"] = kwargs
        calls = self._calls

        class It:
            async def __aenter__(self) -> It:
                return self

            async def __aexit__(self, *exc: object) -> None:
                calls["iterator_closed"] = True

            def __aiter__(self) -> It:
                return self

            async def __anext__(self) -> Any:
                raise StopAsyncIteration

        return It()


class FakeExchange:
    def __init__(self, calls: dict[str, Any]) -> None:
        self._calls = calls

    async def publish(self, message: Any, routing_key: str) -> None:
        self._calls["published"] = (message, routing_key)


class FakeChannel:
    def __init__(self) -> None:
        self.calls: dict[str, Any] = {}
        self.default_exchange = FakeExchange(self.calls)

    async def declare_queue(self, name: str = "", **kwargs: Any) -> FakeQueue:
        self.calls["declare"] = (name, kwargs)
        return FakeQueue(self.calls)


@pytest.mark.asyncio
async def test_aio_pika_transport_declares_a_private_exclusive_reply_queue() -> None:
    channel = FakeChannel()
    transport = AioPikaAuthzTransport(channel)

    queue, deliveries = await transport.declare_reply_queue()

    assert queue == "amq.gen-abc"
    name, kwargs = channel.calls["declare"]
    # Broker-named (empty), not durable, auto-delete, EXCLUSIVE; consumed exclusively with manual
    # acknowledgement.
    assert name == ""
    assert kwargs == {"durable": False, "exclusive": True, "auto_delete": True}
    assert channel.calls["iterator_kwargs"] == {"no_ack": False, "exclusive": True}

    await transport.publish_request(AUTHZ_REQUEST_QUEUE, queue, "cid", b"{}")
    message, routing_key = channel.calls["published"]
    assert routing_key == AUTHZ_REQUEST_QUEUE
    assert message.reply_to == queue and message.correlation_id == "cid" and message.body == b"{}"

    assert [d async for d in deliveries] == [], "the iterator ends with the broker's"
    await transport.close()
    assert channel.calls["iterator_closed"] is True
    await transport.close()  # idempotent
