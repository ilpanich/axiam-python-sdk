"""CONTRACT.md 1.69 §8 (D-8, D-9, D-10): the event consumer is typed, logs one fixed discard
event per refusal in the normative reason order, and no body (a byte-order mark included) escapes
the delivery loop."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from axiam_sdk.amqp._consumer import _on_message, consume
from axiam_sdk.amqp._replay import NonceStore

REFERENCE: dict[str, Any] = json.loads(
    (Path(__file__).parent.parent / "testdata" / "v2_reference_vectors.json").read_text("utf-8")
)
SUBKEY = bytes.fromhex(REFERENCE["hkdf"]["derived_subkey_hex"])
ISSUED = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
CONFIGURED_TENANT = "0c0ffee0-0000-4000-8000-0000000000aa"
OTHER = {"authz_request": "audit_event", "audit_event": "authz_request"}
KINDS = ["authz_request", "audit_event"]
BOM = b"\xef\xbb\xbf"


class _Ctx:
    async def __aenter__(self) -> _Ctx:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class _Message:
    def __init__(
        self, body: bytes, exchange: str = "axiam.ex", routing_key: str = "rk.test"
    ) -> None:
        self.body = body
        self.exchange = exchange
        self.routing_key = routing_key
        self.acked = False
        self.nacked: bool | None = None

    def process(self, ignore_processed: bool = False) -> _Ctx:
        return _Ctx()

    async def ack(self, multiple: bool = False) -> None:
        self.acked = True

    async def nack(self, multiple: bool = False, requeue: bool = True) -> None:
        self.nacked = requeue


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.raw: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.raw.append(record)


def _logger() -> tuple[logging.Logger, _ListHandler]:
    logger = logging.getLogger(f"test.typed.{uuid.uuid4()}")
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    handler = _ListHandler()
    logger.addHandler(handler)
    return logger, handler


def _wire(kind: str) -> bytes:
    return REFERENCE[kind]["wire_json"].encode("utf-8")


def _sign(canonical: str) -> bytes:
    mac = hmac.new(SUBKEY, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return (canonical[:-1] + ',"hmac_signature":"' + mac + '"}').encode("utf-8")


async def _deliver(
    body: bytes, kind: str, store: NonceStore | None = None
) -> tuple[_Message, list[dict[str, Any]], _ListHandler]:
    handled: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any]) -> None:
        handled.append(event)

    logger, log = _logger()
    message = _Message(body)
    await _on_message(
        message,
        SUBKEY,
        handler,
        logger,
        tenant_id=CONFIGURED_TENANT,
        message_type=kind,  # type: ignore[arg-type]
        nonce_store=store if store is not None else NonceStore(ttl_seconds=600),
        now=ISSUED,
    )
    return message, handled, log


def _events(log: _ListHandler) -> list[logging.LogRecord]:
    return [r for r in log.raw if r.levelno == logging.WARNING]


def _flat(record: logging.LogRecord) -> str:
    reserved = set(logging.LogRecord("n", 0, "p", 0, "m", (), None).__dict__) | {"message"}
    members = {k: v for k, v in record.__dict__.items() if k not in reserved}
    return record.getMessage() + " " + json.dumps(members, default=str, sort_keys=True)


def _flip_signature_digit(wire: bytes) -> bytes:
    marker = b'"hmac_signature":"'
    at = wire.rindex(marker) + len(marker)
    flipped = b"0" if wire[at : at + 1] != b"0" else b"1"
    return wire[:at] + flipped + wire[at + 1 :]


# --- D-9: typed consume ------------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.asyncio
async def test_the_configured_type_is_accepted(kind: str) -> None:
    message, handled, log = await _deliver(_wire(kind), kind)
    assert message.acked is True and len(handled) == 1 and _events(log) == []


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.asyncio
async def test_the_other_types_vector_is_malformed_and_never_dispatched(kind: str) -> None:
    message, handled, log = await _deliver(_wire(OTHER[kind]), kind)
    assert handled == [] and message.nacked is False
    events = _events(log)
    assert len(events) == 1 and events[0].reason == "malformed"  # type: ignore[attr-defined]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.asyncio
async def test_the_other_type_is_still_malformed_not_signature_with_a_digit_changed(
    kind: str,
) -> None:
    message, handled, log = await _deliver(_flip_signature_digit(_wire(OTHER[kind])), kind)
    assert handled == [] and message.nacked is False
    assert [e.reason for e in _events(log)] == ["malformed"]  # type: ignore[attr-defined]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.asyncio
async def test_same_type_with_a_digit_changed_is_signature(kind: str) -> None:
    _message, handled, log = await _deliver(_flip_signature_digit(_wire(kind)), kind)
    assert handled == []
    assert [e.reason for e in _events(log)] == ["signature"]  # type: ignore[attr-defined]


def test_consume_requires_a_type_and_a_tenant() -> None:
    import asyncio

    async def handler(event: dict[str, Any]) -> None:
        return None

    with pytest.raises(ValueError):
        asyncio.run(
            consume(None, "q", SUBKEY, handler, tenant_id="t", message_type="bogus")  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        asyncio.run(
            consume(None, "q", SUBKEY, handler, tenant_id="", message_type="audit_event")  # type: ignore[arg-type]
        )


# --- D-8: the event ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "reason"),
    [("malformed", "malformed"), ("unsigned", "unsigned"), ("signature", "signature")],
)
@pytest.mark.asyncio
async def test_the_event_carries_exchange_routing_key_and_the_configured_tenant(
    name: str, reason: str
) -> None:
    wire = _wire("audit_event")
    body = {
        "malformed": _wire("authz_request"),
        "unsigned": REFERENCE["audit_event"]["canonical_signed_json"].encode(),
        "signature": _flip_signature_digit(wire),
    }[name]
    message, handled, log = await _deliver(body, "audit_event")
    assert handled == [] and message.nacked is False
    (event,) = _events(log)
    assert event.reason == reason  # type: ignore[attr-defined]
    assert event.exchange == "axiam.ex"  # type: ignore[attr-defined]
    assert event.routing_key == "rk.test"  # type: ignore[attr-defined]
    assert event.tenant_id == CONFIGURED_TENANT  # type: ignore[attr-defined]
    assert event.timestamp.endswith("Z")  # type: ignore[attr-defined]
    flat = _flat(event)
    nonce = REFERENCE["audit_event"]["message"]["nonce"]
    signatures = [REFERENCE[k]["hmac_signature_hex"] for k in KINDS]
    assert nonce not in flat and not any(s in flat for s in signatures)
    assert REFERENCE["audit_event"]["message"]["tenant_id"] not in flat, "the body's tenant"


def _canonical_audit() -> str:
    return REFERENCE["audit_event"]["canonical_signed_json"]


def _reason_cases() -> list[tuple[str, bytes, str]]:
    canonical = _canonical_audit()
    wire = _wire("audit_event")
    nonce = REFERENCE["audit_event"]["message"]["nonce"]
    return [
        ("not an object", b"[1]", "malformed"),
        ("trailing newline", wire + b"\n", "malformed"),
        ("no signature, wrong layout", b'{"correlation_id":"c"}', "unsigned"),
        (
            "another type without a signature",
            REFERENCE["authz_request"]["canonical_signed_json"].encode(),
            "unsigned",
        ),
        (
            "signature not trailing",
            ('{"hmac_signature":"' + "0" * 64 + '",' + canonical[1:]).encode(),
            "malformed",
        ),
        ("bad signature", _flip_signature_digit(wire), "signature"),
        (
            "verified but ill-typed member",
            _sign(canonical.replace('"action":"user.login"', '"action":5')),
            "malformed",
        ),
        (
            "verified but nonce not a uuid",
            _sign(canonical.replace(nonce, "not-a-uuid")),
            "malformed",
        ),
        (
            "verified but issued_at not rfc3339",
            _sign(canonical.replace("2026-07-10T12:00:00Z", "yesterday")),
            "malformed",
        ),
        (
            "key_version 1",
            _sign(canonical.replace('"key_version":2', '"key_version":1')),
            "key_version",
        ),
        (
            "stale",
            _sign(canonical.replace("2026-07-10T12:00:00Z", "2026-07-10T11:00:00Z")),
            "stale",
        ),
    ]


@pytest.mark.parametrize(
    ("name", "body", "reason"), _reason_cases(), ids=[c[0] for c in _reason_cases()]
)
@pytest.mark.asyncio
async def test_the_first_applicable_reason_is_reported(name: str, body: bytes, reason: str) -> None:
    message, handled, log = await _deliver(body, "audit_event")
    assert handled == [] and message.nacked is False
    assert [e.reason for e in _events(log)] == [reason]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_a_replayed_nonce_is_replay_and_a_refused_message_leaves_no_nonce() -> None:
    store = NonceStore(ttl_seconds=600)
    wire = _wire("audit_event")
    _m, handled, log = await _deliver(wire, "audit_event", store)
    assert len(handled) == 1 and _events(log) == []
    _m, handled, log = await _deliver(wire, "audit_event", store)
    assert handled == [] and [e.reason for e in _events(log)] == ["replay"]  # type: ignore[attr-defined]

    fresh = NonceStore(ttl_seconds=600)
    stale = _sign(_canonical_audit().replace("2026-07-10T12:00:00Z", "2026-07-10T11:00:00Z"))
    await _deliver(stale, "audit_event", fresh)
    assert len(fresh) == 0, "a message refused at (7) leaves no nonce behind"


# --- D-10: BOM and robustness ------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.asyncio
async def test_a_bom_prefixed_vector_is_malformed_and_the_next_delivery_is_served(
    kind: str,
) -> None:
    handled: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any]) -> None:
        handled.append(event)

    logger, log = _logger()
    store = NonceStore(ttl_seconds=600)
    common: dict[str, Any] = {
        "tenant_id": CONFIGURED_TENANT,
        "message_type": kind,
        "nonce_store": store,
        "now": ISSUED,
    }
    bad = _Message(BOM + _wire(kind))
    await _on_message(bad, SUBKEY, handler, logger, **common)
    assert bad.nacked is False and handled == []
    assert [e.reason for e in _events(log)] == ["malformed"]  # type: ignore[attr-defined]
    good = _Message(_wire(kind))
    await _on_message(good, SUBKEY, handler, logger, **common)
    assert good.acked is True and len(handled) == 1, "the BOM copy did not burn the nonce"


@pytest.mark.parametrize(
    "body",
    [b"", b" " + b"{}", b"\xff\xfe", b"[" * 100_000, b"{" * 100_000, b"\x00", b"null", b'{"a":'],
)
@pytest.mark.asyncio
async def test_no_body_raises_out_of_the_consumer(body: bytes) -> None:
    message, handled, log = await _deliver(body, "authz_request")
    assert handled == [] and message.nacked is False
    assert len(_events(log)) == 1


@pytest.mark.asyncio
async def test_the_registered_callback_never_lets_an_exception_escape() -> None:
    class _Queue:
        callback: Any = None

        async def consume(self, callback: Any, no_ack: bool = True, consumer_tag: str = "") -> None:
            self.callback = callback

    class _Channel:
        def __init__(self) -> None:
            self.queue = _Queue()

        async def set_qos(self, prefetch_count: int) -> None:
            return None

        async def declare_queue(self, name: str, **kwargs: Any) -> _Queue:
            return self.queue

    class _Exploding(_Message):
        def process(self, ignore_processed: bool = False) -> _Ctx:
            raise RuntimeError("boom")

    async def handler(event: dict[str, Any]) -> None:
        return None

    channel = _Channel()
    logger, log = _logger()
    await consume(
        channel,  # type: ignore[arg-type]
        "q",
        SUBKEY,
        handler,
        tenant_id=CONFIGURED_TENANT,
        message_type="audit_event",
        logger=logger,
    )
    await channel.queue.callback(_Exploding(b"{}"))  # must not raise
    assert any("RuntimeError" in r.getMessage() for r in log.raw)


@pytest.mark.asyncio
async def test_an_empty_routing_key_and_exchange_are_reported_as_the_broker_gave_them() -> None:
    async def handler(event: dict[str, Any]) -> None:
        return None

    logger, log = _logger()
    message = _Message(_wire("authz_request"), exchange="", routing_key="")
    await _on_message(
        message,
        SUBKEY,
        handler,
        logger,
        tenant_id=CONFIGURED_TENANT,
        message_type="audit_event",
        queue_name="the-queue",
    )
    (event,) = _events(log)
    assert event.exchange == "" and event.routing_key == ""  # type: ignore[attr-defined]


def _with_member(canonical: str, old: str, new: str) -> bytes:
    assert old in canonical
    return _sign(canonical.replace(old, new))


@pytest.mark.parametrize(
    ("name", "old", "new"),
    [
        ("required string null", '"action":"user.login"', '"action":null'),
        (
            "required uuid not a uuid",
            '"actor_id":"66666666-6666-6666-6666-666666666666"',
            '"actor_id":"x"',
        ),
        (
            "tenant not a uuid",
            '"tenant_id":"11111111-1111-1111-1111-111111111111"',
            '"tenant_id":"t"',
        ),
        ("issued_at without offset", "2026-07-10T12:00:00Z", "2026-07-10T12:00:00"),
        ("issued_at date only", "2026-07-10T12:00:00Z", "2026-07-10"),
        ("issued_at space separator", "2026-07-10T12:00:00Z", "2026-07-10 12:00:00Z"),
        ("key_version above u8", '"key_version":2', '"key_version":300'),
        (
            "optional ip_address wrong type",
            '"ip_address":"203.0.113.7"',
            '"ip_address":5',
        ),
    ],
)
@pytest.mark.asyncio
async def test_decode_refuses_each_case_as_malformed(name: str, old: str, new: str) -> None:
    canonical = _canonical_audit()
    message, handled, log = await _deliver(_with_member(canonical, old, new), "audit_event")
    assert handled == [] and message.nacked is False, name
    assert [e.reason for e in _events(log)] == ["malformed"], name  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_a_routing_key_with_a_newline_cannot_forge_a_log_line() -> None:
    async def handler(event: dict[str, Any]) -> None:
        return None

    logger, log = _logger()
    message = _Message(b"[]", routing_key="a\nFORGED reason=ok")
    await _on_message(
        message,
        SUBKEY,
        handler,
        logger,
        tenant_id="t\nx",
        message_type="audit_event",
    )
    (event,) = _events(log)
    assert "\n" not in event.getMessage()


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
@pytest.mark.asyncio
async def test_non_finite_json_constants_are_malformed(constant: str) -> None:
    canonical = _canonical_audit().replace('"method":"password"', '"method":' + constant)
    message, handled, log = await _deliver(_sign(canonical), "audit_event")
    assert handled == [] and message.nacked is False
    assert [e.reason for e in _events(log)] == ["malformed"]  # type: ignore[attr-defined]
