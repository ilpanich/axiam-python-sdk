"""Coverage for the ``consume()`` entrypoint wiring and the post-verify
non-object-body branch of ``_on_message`` (CONTRACT.md §8).

``test_amqp_consumer.py`` drives the ack/nack matrix on ``_on_message``
directly; this file covers ``consume()``'s QoS/passive-declare/register
setup against fake aio-pika doubles (no live broker) and proves the
registered per-delivery callback forwards to ``_on_message``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from axiam_sdk.amqp._consumer import CONSUMER_TAG, DEFAULT_PREFETCH, _on_message, consume

VALID_SIGNING_KEY = b"axiam-sdk-test-signing-key"


def _v2_fields() -> dict[str, Any]:
    return {
        "key_version": 2,
        "nonce": str(uuid.uuid4()),
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _authz(action: str, resource_id: str) -> dict[str, Any]:
    """A genuine ``AuthzRequest`` layout (CONTRACT §8 v2): the consumer refuses other shapes."""
    return {
        "correlation_id": "11111111-1111-1111-1111-111111111111",
        "tenant_id": "22222222-2222-2222-2222-222222222222",
        "subject_id": "33333333-3333-3333-3333-333333333333",
        "action": action,
        "resource_id": resource_id,
        **_v2_fields(),
    }


def _sign(signing_key: bytes, message: dict[str, Any]) -> bytes:
    canonical = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
    signed = dict(message)
    signed["hmac_signature"] = sig
    return json.dumps(signed, separators=(",", ":")).encode("utf-8")


class _RecordingProcessContext:
    async def __aenter__(self) -> _RecordingProcessContext:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class RecordingMessage:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.acked = False
        self.nacked: bool | None = None

    def process(self, ignore_processed: bool = False) -> _RecordingProcessContext:
        return _RecordingProcessContext()

    async def ack(self, multiple: bool = False) -> None:
        self.acked = True

    async def nack(self, multiple: bool = False, requeue: bool = True) -> None:
        self.nacked = requeue


class _FakeQueue:
    def __init__(self) -> None:
        self.consume_args: dict[str, Any] = {}
        self.callback: Any = None

    async def consume(self, callback: Any, no_ack: bool = True, consumer_tag: str = "") -> None:
        self.callback = callback
        self.consume_args = {"no_ack": no_ack, "consumer_tag": consumer_tag}


class _FakeChannel:
    def __init__(self) -> None:
        self.qos: dict[str, Any] = {}
        self.declare_args: dict[str, Any] = {}
        self.queue = _FakeQueue()

    async def set_qos(self, prefetch_count: int = 0) -> None:
        self.qos = {"prefetch_count": prefetch_count}

    async def declare_queue(
        self, name: str, durable: bool = False, passive: bool = False
    ) -> _FakeQueue:
        self.declare_args = {"name": name, "durable": durable, "passive": passive}
        return self.queue


async def test_consume_sets_qos_declares_passive_and_registers_callback() -> None:
    channel = _FakeChannel()
    handled: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any]) -> None:
        handled.append(event)

    await consume(channel, "tenant-queue", VALID_SIGNING_KEY, handler)

    assert channel.qos == {"prefetch_count": DEFAULT_PREFETCH}
    assert channel.declare_args == {"name": "tenant-queue", "durable": True, "passive": True}
    assert channel.queue.consume_args == {"no_ack": False, "consumer_tag": CONSUMER_TAG}
    assert callable(channel.queue.callback)


async def test_consume_callback_dispatches_to_on_message() -> None:
    channel = _FakeChannel()
    handled: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any]) -> None:
        handled.append(event)

    await consume(channel, "q", VALID_SIGNING_KEY, handler, prefetch=3)
    assert channel.qos == {"prefetch_count": 3}

    body = _sign(VALID_SIGNING_KEY, _authz("read", "r"))
    message = RecordingMessage(body)

    # Invoke the registered per-delivery callback -> _on_message -> handler.
    await channel.queue.callback(message)

    assert message.acked is True
    assert len(handled) == 1


async def test_consume_uses_default_logger_when_none() -> None:
    channel = _FakeChannel()

    async def handler(event: dict[str, Any]) -> None:
        return None

    # logger omitted -> the module NullHandler logger is used; must not raise.
    await consume(channel, "q", VALID_SIGNING_KEY, handler)
    assert channel.queue.callback is not None


async def test_on_message_validly_signed_non_object_body_nacks_without_requeue() -> None:
    """A body whose signature verifies over the received bytes but which is not one JSON object
    (here: valid HMAC over ``{not json}``) is nacked without requeue and never dispatched. The
    SDK parses the verified bytes exactly once (server #882), so there is no separate
    "re-parse" step left to fail: the refusal is part of verification."""
    canonical = '{"action":"read","resource_id":["r",}'
    mac = hmac.new(VALID_SIGNING_KEY, canonical.encode(), hashlib.sha256).hexdigest()
    message = RecordingMessage((canonical[:-1] + ',"hmac_signature":"' + mac + '"}').encode())

    handler_calls = 0

    async def handler(event: dict[str, Any]) -> None:
        nonlocal handler_calls
        handler_calls += 1

    logger = logging.getLogger("test.axiam_sdk.amqp.consume")
    await _on_message(message, VALID_SIGNING_KEY, handler, logger)

    assert message.acked is False
    assert message.nacked is False
    assert handler_calls == 0
