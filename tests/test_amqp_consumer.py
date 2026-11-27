"""Async AMQP consumer ack/nack decision matrix tests (CONTRACT.md §8, NEW-4).

Drives all paths of ``axiam_sdk.amqp._consumer._on_message`` against a
recording fake ``AbstractIncomingMessage`` double (no live broker) —
mirroring Go's ``AckableDelivery``/``recordingDelivery`` seam
(``the Go SDK's amqp/consumer_test.go``).

Every message body used here is v2-shaped (``key_version=2`` + ``nonce`` +
``issued_at``, per NEW-4 / ``testdata/v2_reference_vectors.json``'s field
order) and self-signed with a fixed
test key via ``_sign()`` below — this file's job is exercising the ack/nack
DECISION MATRIX itself, not proving cross-language HMAC byte-parity (that
proof against the real server-signed v2 reference vectors, plus the NEW-4
replay-protection reject paths, lives in ``test_amqp_v2_replay.py``).
``issued_at`` defaults to the real wall clock at test-construction time so
these tests satisfy NEW-4's freshness/nonce checks without injecting a
fixed ``now``.
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

from axiam_sdk.amqp._consumer import ErrDrop, _on_message

#: Fixed HMAC signing key for this file's self-signed v2 test vectors
#: (mirrors ``tests/conftest.py``'s ``signing_key`` fixture value).
VALID_SIGNING_KEY = b"axiam-sdk-test-signing-key"


def _v2_fields(now: datetime | None = None) -> dict[str, Any]:
    """Build the three NEW-4 signed-body fields with fresh defaults:
    ``key_version=2``, a random ``nonce``, and ``issued_at`` = now — so a
    message built from these fields naturally satisfies the freshness and
    replay checks against the real wall clock unless a test overrides
    ``now``."""
    if now is None:
        now = datetime.now(UTC)
    return {
        "key_version": 2,
        "nonce": str(uuid.uuid4()),
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
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
    """Build a wire body with a real HMAC-SHA256 signature for arbitrary
    message content, reusing the exact canonicalization axiam_sdk.amqp._hmac
    expects (insertion order, no sort_keys)."""
    canonical = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
    signed = dict(message)
    signed["hmac_signature"] = sig
    return json.dumps(signed, separators=(",", ":")).encode("utf-8")


VALID_MESSAGE: dict[str, Any] = _authz("read", "44444444-4444-4444-4444-444444444444")
VALID_BODY = _sign(VALID_SIGNING_KEY, VALID_MESSAGE)
VALID_SIGNATURE_HEX = json.loads(VALID_BODY)["hmac_signature"]


class _RecordingProcessContext:
    """Async context manager double for ``message.process(...)``.

    Mirrors aio-pika's real ``ignore_processed=True`` behavior: entering is
    a no-op, and exiting never auto-acks/nacks (the SDK is fully
    responsible for calling ``message.ack()``/``message.nack()`` itself).
    """

    async def __aenter__(self) -> _RecordingProcessContext:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class RecordingMessage:
    """Recording fake ``AbstractIncomingMessage`` double.

    Exposes ``.body``, an async ``.process()`` context manager, and
    recording ``.ack()``/``.nack(requeue=...)`` calls — no live broker
    required. Mirrors Go's ``recordingDelivery`` test fake.
    """

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.acked = False
        self.nacked: bool | None = None  # None = not nacked; else requeue value

    def process(self, ignore_processed: bool = False) -> _RecordingProcessContext:
        return _RecordingProcessContext()

    async def ack(self, multiple: bool = False) -> None:
        self.acked = True

    async def nack(self, multiple: bool = False, requeue: bool = True) -> None:
        self.nacked = requeue


class _RecordingLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


@pytest.fixture
def recording_logger() -> tuple[logging.Logger, _RecordingLogHandler]:
    logger = logging.getLogger("test.axiam_sdk.amqp")
    logger.setLevel(logging.DEBUG)
    handler = _RecordingLogHandler()
    logger.addHandler(handler)
    yield logger, handler
    logger.removeHandler(handler)


async def test_valid_hmac_and_none_handler_acks(
    recording_logger: tuple[logging.Logger, _RecordingLogHandler],
) -> None:
    """Path 1: valid HMAC + handler returns None -> ack(); handler IS invoked."""
    logger, _handler = recording_logger
    message = RecordingMessage(VALID_BODY)
    handler_called_with: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any]) -> None:
        handler_called_with.append(event)

    await _on_message(
        message, VALID_SIGNING_KEY, handler, logger, tenant_id="t-1", message_type="authz_request"
    )

    assert message.acked is True
    assert message.nacked is None
    assert len(handler_called_with) == 1
    assert "hmac_signature" not in handler_called_with[0]


async def test_invalid_hmac_nacks_without_requeue_and_handler_never_called(
    recording_logger: tuple[logging.Logger, _RecordingLogHandler],
) -> None:
    """Path 2: invalid HMAC -> nack(requeue=False); handler NOT called;
    security log emitted without the signature value (verify-before-handler,
    T-19-16/T-19-17)."""
    logger, handler_records = recording_logger
    tampered = json.loads(VALID_BODY)
    tampered["hmac_signature"] = "0" * len(VALID_SIGNATURE_HEX)  # wrong signature
    body = json.dumps(tampered, separators=(",", ":")).encode("utf-8")
    message = RecordingMessage(body)

    handler_calls = 0

    async def handler(event: dict[str, Any]) -> None:
        nonlocal handler_calls
        handler_calls += 1

    await _on_message(
        message, VALID_SIGNING_KEY, handler, logger, tenant_id="t-1", message_type="authz_request"
    )

    assert message.acked is False
    assert message.nacked is False  # requeue=False
    assert handler_calls == 0  # handler never invoked

    log_text = " ".join(handler_records.records)
    assert VALID_SIGNATURE_HEX not in log_text
    assert "0" * len(VALID_SIGNATURE_HEX) not in log_text
    assert "hmac" in log_text.lower() or "security" in log_text.lower()


async def test_handler_raises_errdrop_nacks_without_requeue(
    recording_logger: tuple[logging.Logger, _RecordingLogHandler],
) -> None:
    """Path 3: valid HMAC + handler raises ErrDrop -> nack(requeue=False)."""
    logger, _handler = recording_logger
    body = _sign(VALID_SIGNING_KEY, _authz("delete", "x"))
    message = RecordingMessage(body)

    async def handler(event: dict[str, Any]) -> None:
        raise ErrDrop("poison message")

    await _on_message(
        message, VALID_SIGNING_KEY, handler, logger, tenant_id="t-1", message_type="authz_request"
    )

    assert message.acked is False
    assert message.nacked is False  # requeue=False


async def test_handler_raises_other_exception_nacks_with_requeue(
    recording_logger: tuple[logging.Logger, _RecordingLogHandler],
) -> None:
    """Path 4: valid HMAC + handler raises a plain exception -> nack(requeue=True)."""
    logger, _handler = recording_logger
    body = _sign(VALID_SIGNING_KEY, _authz("update", "y"))
    message = RecordingMessage(body)

    async def handler(event: dict[str, Any]) -> None:
        raise RuntimeError("transient downstream failure")

    await _on_message(
        message, VALID_SIGNING_KEY, handler, logger, tenant_id="t-1", message_type="authz_request"
    )

    assert message.acked is False
    assert message.nacked is True  # requeue=True


async def test_validly_signed_unparseable_body_nacks_without_requeue(
    recording_logger: tuple[logging.Logger, _RecordingLogHandler],
) -> None:
    """Path 5: the HMAC verifies over the received bytes, but those bytes are not a usable JSON
    object -> nack(requeue=False); handler NOT invoked.

    The SDK parses the verified bytes once (server #882: verify the received bytes, dispatch
    what was parsed from them), so this refusal is part of verification and needs no separate
    "post-verify parse" branch. The body here is correctly signed over ``{not json}``: the
    scenario an attacker holding the signing key could still produce."""
    logger, handler_records = recording_logger
    canonical = '{"action":"update","resource_id":[}'
    mac = hmac.new(VALID_SIGNING_KEY, canonical.encode(), hashlib.sha256).hexdigest()
    message = RecordingMessage((canonical[:-1] + ',"hmac_signature":"' + mac + '"}').encode())

    handler_calls = 0

    async def handler(event: dict[str, Any]) -> None:
        nonlocal handler_calls
        handler_calls += 1

    await _on_message(
        message, VALID_SIGNING_KEY, handler, logger, tenant_id="t-1", message_type="authz_request"
    )

    assert message.acked is False
    assert message.nacked is False  # requeue=False
    assert handler_calls == 0  # handler never invoked

    log_text = " ".join(handler_records.records)
    assert VALID_SIGNATURE_HEX not in log_text
