"""CONTRACT.md §8 / server #882 (D-5): the event consumer verifies the HMAC over the bytes it
received and hands the handler a value parsed from those same bytes.

A re-serialization (the old ``json.dumps(msg, separators=...)``) fails a genuine message whenever
the SDK encoder and ``serde_json`` disagree -- ``json.dumps`` escapes every non-ASCII character
by default -- and it lets a handler see a different parse than the one verified (C2): a duplicate
key collapses to its last value in ``json.loads`` and vanishes in the re-serialization.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from axiam_sdk.amqp._consumer import _on_message
from axiam_sdk.amqp._hmac import verify_hmac

KEY = b"axiam-sdk-received-bytes-test-key"

#: Characters a re-serializing encoder and serde_json disagree on, plus a control character
#: written as a ``\u`` escape exactly as serde_json writes it.
HOSTILE_ACTION = 'docs:a&b</"c">/é€ \\ \u0001  '


def _v2() -> str:
    return (
        f'"key_version":2,"nonce":"{uuid.uuid4()}",'
        f'"issued_at":"{datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}"'
    )


def _serde_style(members: dict[str, Any]) -> str:
    """The bytes serde_json writes: compact, everything but the controls, ``"`` and ``\\`` raw."""
    return json.dumps(members, separators=(",", ":"), ensure_ascii=False)


def _signed(canonical: str, key: bytes = KEY) -> bytes:
    mac = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return (canonical[:-1] + ',"hmac_signature":"' + mac + '"}').encode("utf-8")


class _Ctx:
    async def __aenter__(self) -> _Ctx:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class _Message:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.acked = False
        self.nacked: bool | None = None

    def process(self, ignore_processed: bool = False) -> _Ctx:
        return _Ctx()

    async def ack(self, multiple: bool = False) -> None:
        self.acked = True

    async def nack(self, multiple: bool = False, requeue: bool = True) -> None:
        self.nacked = requeue


def _canonical_with(action: str) -> str:
    body = _serde_style({"tenant_id": "t-1", "action": action})
    return body[:-1] + "," + _v2() + "}"


def test_genuine_message_with_html_non_ascii_and_u_escapes_verifies() -> None:
    body = _signed(_canonical_with(HOSTILE_ACTION))
    assert "\\u0001" in body.decode("utf-8"), "the control character travels as a \\u escape"
    assert verify_hmac(KEY, body) is True


@pytest.mark.asyncio
async def test_handler_receives_the_value_parsed_from_the_verified_bytes() -> None:
    body = _signed(_canonical_with(HOSTILE_ACTION))
    handled: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any]) -> None:
        handled.append(event)

    message = _Message(body)
    await _on_message(message, KEY, handler, logging.getLogger("test.received"))

    assert message.acked is True and message.nacked is None
    assert len(handled) == 1
    assert handled[0]["action"] == HOSTILE_ACTION
    assert "hmac_signature" not in handled[0]


def _duplicate_key_attack() -> bytes:
    """Signed over the re-serialization (``"action":"read"``, the last duplicate wins) but sent
    with a first, different value: the old verifier re-serialized, so it accepted this, and the
    handler saw ``read`` while a decoder keeping the first duplicate would read ``admin``."""
    fields = _v2()
    reserialized = '{"tenant_id":"t-1","action":"read",' + fields + "}"
    mac = hmac.new(KEY, reserialized.encode(), hashlib.sha256).hexdigest()
    sent = (
        '{"tenant_id":"t-1","action":"admin","action":"read",'
        + fields
        + ',"hmac_signature":"'
        + mac
        + '"}'
    )
    return sent.encode("utf-8")


def _signed_duplicate_key() -> bytes:
    """A duplicate key, validly signed over the received bytes."""
    return _signed('{"tenant_id":"t-1","action":"a","action":"b",' + _v2() + "}")


def _signed_with_trailing_content() -> bytes:
    return _signed(_canonical_with("read")) + b'{"x":1}'


def _signed_with_trailing_whitespace() -> bytes:
    return _signed(_canonical_with("read")) + b"\n"


def _signature_not_last() -> bytes:
    canonical = _canonical_with("read")
    mac = hmac.new(KEY, canonical.encode(), hashlib.sha256).hexdigest()
    return ('{"hmac_signature":"' + mac + '",' + canonical[1:]).encode("utf-8")


REFUSED = {
    "duplicate key, signed over the re-serialization": _duplicate_key_attack,
    "duplicate key, signed over the received bytes": _signed_duplicate_key,
    "trailing content": _signed_with_trailing_content,
    "trailing whitespace": _signed_with_trailing_whitespace,
    "signature not the trailing member": _signature_not_last,
}


@pytest.mark.parametrize("name", REFUSED)
def test_verify_hmac_refuses_what_is_not_the_signed_bytes(name: str) -> None:
    assert verify_hmac(KEY, REFUSED[name]()) is False


@pytest.mark.parametrize("name", REFUSED)
@pytest.mark.asyncio
async def test_a_body_with_a_duplicate_key_or_trailing_content_is_nacked_and_never_dispatched(
    name: str,
) -> None:
    handled: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any]) -> None:
        handled.append(event)

    message = _Message(REFUSED[name]())
    await _on_message(message, KEY, handler, logging.getLogger("test.received"))

    assert handled == [], "the handler must never run"
    assert message.nacked is False, "nacked without requeue"
    assert message.acked is False
