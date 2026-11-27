"""Async AMQP event consumer with HMAC verify-before-handler (CONTRACT.md §8).

Closure-handler consumer built on ``aio-pika`` (D-02, async-only). Ports
``the Go SDK's amqp/consumer.go``'s ``verifyAndDispatch`` ack/nack decision matrix
and ``the Go SDK's amqp/errdrop.go``'s exported ``ErrDrop`` sentinel.

Security invariant (T-19-16/T-19-17/T-19-18): every delivery's HMAC-SHA256
signature is verified via :func:`axiam_sdk.amqp._hmac.verify_and_decode` — over the
received bytes, byte-for-byte compatible with the Rust server — BEFORE the
caller-supplied handler is ever invoked, and the handler is given the value
parsed from those verified bytes (server #882). An unverified message never
reaches the handler. The SDK owns the ack/nack loop (``message.process(
ignore_processed=True)``); ``aio-pika``'s automatic context-manager
auto-acking is never used.

Ack/nack decision matrix (§8):

- any discard (steps 2a-2c, HMAC, decode, v2 gates) -> nack(requeue=False) + one security event
- handler(event) returns ``None``         -> ack()
- handler(event) raises :class:`ErrDrop`  -> nack(requeue=False)
- handler(event) raises any other error   -> nack(requeue=True)

Typed consume (contract 1.69, D-9): the consumer is configured with the ONE signed type it
consumes (``message_type``) and its own ``tenant_id``. A body with another signed type's layout
is refused as ``malformed`` before the HMAC is computed and before anything is decoded.

Security event (§8 rule 4, D-8): every discard logs exactly one warning carrying ``timestamp``,
``exchange``, ``routing_key``, ``tenant_id`` (the consumer's own, never read from the body) and
``reason`` (``malformed``, ``unsigned``, ``signature``, ``key_version``, ``stale``, ``replay``,
the first applicable in the normative order). It NEVER includes a signature, nonce, key or any
part of the body (§8.4).

NEW-4 (AMQP replay protection, v2 wire protocol): once the HMAC verifies,
the parsed body is additionally checked by
:func:`axiam_sdk.amqp._replay.validate_freshness` — ``key_version`` must be
>= 2, ``issued_at`` must be within a configurable clock-skew window (default
5 minutes) of now, and ``nonce`` must not have been seen before within the
freshness window (2x skew). A single :class:`axiam_sdk.amqp._replay.NonceStore`
is created once per :func:`consume` call and threaded through every delivery
so nonce dedup actually persists across the consumer's lifetime.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal

from aio_pika.abc import AbstractChannel, AbstractIncomingMessage

from axiam_sdk.amqp._hmac import cut_trailing_signature, strict_json_object, verify_and_decode
from axiam_sdk.amqp._replay import (
    DEFAULT_SKEW_SECONDS,
    MIN_KEY_VERSION,
    NonceStore,
    _parse_rfc3339,
)

#: Default AMQP QoS prefetch count applied unless the caller overrides it
#: via ``consume(..., prefetch=...)`` (CF-06; mirrors Go's ``defaultPrefetch
#: = 10``).
DEFAULT_PREFETCH = 10

#: Consumer tag identifying this SDK's consumer to the broker (mirrors Go's
#: ``consumerTag``).
CONSUMER_TAG = "axiam-sdk-consumer"

Handler = Callable[[dict[str, Any]], Awaitable[None]]


class ErrDrop(Exception):
    """Sentinel a handler raises to signal "poison message" (D-02, §8).

    Raising ``ErrDrop`` from a ``consume()`` handler causes the delivery to
    be nacked WITHOUT requeue, exactly like an HMAC or parse failure — the
    message is dropped rather than looping the queue. Any OTHER exception
    raised by the handler is treated as transient and nacks WITH requeue.
    Mirrors Go's exported ``var ErrDrop = errors.New(...)`` sentinel
    (``the Go SDK's amqp/errdrop.go``).
    """


#: The one signed type an event consumer is configured with (contract 1.69, §8 step 2c).
EventType = Literal["authz_request", "audit_event"]

#: The top-level members of each signed layout (CONTRACT §8 v2), in wire order, with whether each
#: is required. A consumer checks ONLY its configured type's layout: any other shape signed with
#: the tenant subkey (the other event type, an ``AuthzResponse``, a cache invalidation) is refused.
_LAYOUTS: dict[str, tuple[tuple[str, bool], ...]] = {
    "authz_request": (
        ("correlation_id", True),
        ("tenant_id", True),
        ("subject_id", True),
        ("action", True),
        ("resource_id", True),
        ("scope", False),
        ("key_version", True),
        ("nonce", True),
        ("issued_at", True),
    ),
    "audit_event": (
        ("tenant_id", True),
        ("actor_id", True),
        ("actor_type", True),
        ("action", True),
        ("resource_id", False),
        ("outcome", True),
        ("ip_address", False),
        ("metadata", False),
        ("key_version", True),
        ("nonce", True),
        ("issued_at", True),
    ),
}
#: Step 2f's decode, per type: the members that must be present and strings, those that may be
#: absent but are strings when present, and those of them that are UUIDs (the server's ``Uuid``
#: fields; ``crates/axiam-amqp/src/messages.rs``).
_REQUIRED_STRINGS: dict[str, tuple[str, ...]] = {
    "authz_request": ("correlation_id", "tenant_id", "subject_id", "action", "resource_id"),
    "audit_event": ("tenant_id", "actor_id", "actor_type", "action", "outcome"),
}
_OPTIONAL_STRINGS: dict[str, tuple[str, ...]] = {
    "authz_request": ("scope",),
    "audit_event": ("resource_id", "ip_address"),
}
_UUID_MEMBERS: dict[str, tuple[str, ...]] = {
    "authz_request": ("correlation_id", "tenant_id", "subject_id", "resource_id"),
    "audit_event": ("tenant_id", "actor_id", "resource_id"),
}
_MAX_KEY_VERSION = 255  # the server's ``u8``
#: RFC 3339 ``date-time``: ``T`` separator, a seconds field and an explicit offset.
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})")


def _refuse_constant(name: str) -> Any:
    """``json.loads`` ``parse_constant`` hook: ``NaN`` and ``Infinity`` are not JSON."""
    raise ValueError("a non-finite JSON constant")


def _has_layout(names: list[str], layout: tuple[tuple[str, bool], ...]) -> bool:
    """Whether ``names`` are, in order, exactly ``layout``'s members (an optional one present in
    its place or absent) and nothing else."""
    position = 0
    for name, required in layout:
        if position < len(names) and names[position] == name:
            position += 1
        elif required:
            return False
    return position == len(names)


def _shape_reason(body: bytes) -> str | None:
    """Reasons (1) and (2) of §8 rule 4: ``malformed`` when ``body`` is not one JSON object (its
    first byte is not ``{`` -- a byte-order mark included, never stripped -- it is not JSON, or
    anything follows the closing brace), ``unsigned`` when it has no top-level ``hmac_signature``
    member, else ``None``. Duplicate members are not judged here (that is reason 3)."""
    if body[:1] != b"{":
        return "malformed"
    try:
        text = body.decode("utf-8")
        if text[-1:] in (" ", "\t", "\n", "\r"):
            return "malformed"
        parsed = json.loads(text, parse_constant=_refuse_constant)
    except (ValueError, RecursionError):
        return "malformed"
    if not isinstance(parsed, dict):
        return "malformed"
    if "hmac_signature" not in parsed:
        return "unsigned"
    return None


def _decodes(event: dict[str, Any], message_type: str) -> bool:
    """Step 2f's decode of the verified bytes into the configured type: required members present
    and of the JSON type the struct gives them, optional ones absent or of that type, the server's
    ``Uuid`` members UUIDs, ``key_version`` an integer in ``u8`` range, ``issued_at`` an RFC 3339
    ``date-time`` with an offset and ``nonce`` a UUID. Reads only; never returns a value."""
    for name in _REQUIRED_STRINGS[message_type]:
        if not isinstance(event.get(name), str):
            return False
    for name in _OPTIONAL_STRINGS[message_type]:
        if name in event and not isinstance(event[name], str):
            return False
    if message_type == "audit_event" and "metadata" in event:
        if not isinstance(event["metadata"], dict):
            return False
    key_version = event.get("key_version")
    if (
        not isinstance(key_version, int)
        or isinstance(key_version, bool)
        or not 0 <= key_version <= _MAX_KEY_VERSION
    ):
        return False
    nonce = event.get("nonce")
    issued_at = event.get("issued_at")
    if not isinstance(nonce, str) or not isinstance(issued_at, str):
        return False
    if _RFC3339.fullmatch(issued_at) is None:
        return False
    try:
        uuid.UUID(nonce)
        for name in _UUID_MEMBERS[message_type]:
            if name in event:
                uuid.UUID(event[name])
        _parse_rfc3339(issued_at)
    except (ValueError, OverflowError):
        return False
    return True


def _verify(
    body: bytes,
    signing_key: bytes,
    message_type: str,
    nonce_store: NonceStore,
    skew_seconds: float,
    now: datetime | None,
) -> tuple[dict[str, Any] | None, str]:
    """Apply §8 steps 2a-2f and the v2 gates in the normative order of rule 4 (positions (1) to
    (8)); return ``(event, "")`` for an accepted message or ``(None, reason)`` for the first
    reason that applies. The nonce is recorded last, after the decode and every gate passed."""
    reason = _shape_reason(body)  # (1) and (2)
    if reason is not None:
        return None, reason
    cut = cut_trailing_signature(body)  # (3): everything steps 2a-2c refuse
    if cut is None:
        return None, "malformed"
    canonical, _signature = cut
    try:
        strict_json_object(body)  # a duplicate or case-folded member name
        names = list(strict_json_object(canonical))
    except ValueError:
        return None, "malformed"
    if not _has_layout(names, _LAYOUTS[message_type]):  # the typed check, before the HMAC
        return None, "malformed"
    event = verify_and_decode(signing_key, body)  # (4)
    if event is None:
        return None, "signature"
    if not _decodes(event, message_type):  # (5)
        return None, "malformed"
    if event["key_version"] < MIN_KEY_VERSION:  # (6)
        return None, "key_version"
    reference = now if now is not None else datetime.now(UTC)
    if abs((reference - _parse_rfc3339(event["issued_at"])).total_seconds()) > skew_seconds:  # (7)
        return None, "stale"
    if not nonce_store.check_and_record(event["nonce"]):  # (8), recorded only now
        return None, "replay"
    return event, ""


def _log_discard(
    logger: logging.Logger, message: Any, queue_name: str, tenant_id: str, reason: str
) -> None:
    """The one security event of a discard (contract 1.69, §8 rule 4): ``timestamp``,
    ``exchange``, ``routing_key``, ``tenant_id`` (the consumer's own) and ``reason``, as both
    ``extra`` members and message text. Never a signature, nonce, key or any part of the body."""
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    reported_exchange = getattr(message, "exchange", None)
    exchange = reported_exchange if isinstance(reported_exchange, str) else ""
    reported_key = getattr(message, "routing_key", None)
    routing_key = reported_key if isinstance(reported_key, str) else queue_name
    logger.warning(
        "axiam_sdk_security: AMQP event discarded: timestamp=%s exchange=%r routing_key=%r "
        "tenant_id=%r reason=%s",
        timestamp,
        exchange,
        routing_key,
        tenant_id,
        reason,
        extra={
            "timestamp": timestamp,
            "exchange": exchange,
            "routing_key": routing_key,
            "tenant_id": tenant_id,
            "reason": reason,
        },
    )


async def _on_message(
    message: AbstractIncomingMessage,
    signing_key: bytes,
    handler: Handler,
    logger: logging.Logger,
    *,
    tenant_id: str,
    message_type: EventType,
    queue_name: str = "",
    nonce_store: NonceStore | None = None,
    skew_seconds: float = DEFAULT_SKEW_SECONDS,
    now: datetime | None = None,
) -> None:
    """Verify, parse, and dispatch a single delivery per the §8 matrix.

    The SDK drives ack/nack itself via ``message.process(
    ignore_processed=True)`` — this disables aio-pika's automatic
    ack-on-success-else-requeue context-manager behavior so every outcome
    below is an explicit, deliberate decision.

    ``message_type`` is the one signed type this consumer consumes and ``tenant_id`` the tenant
    whose subkey ``signing_key`` is; both are the consumer's configuration, never read from a
    body. ``queue_name`` stands in for the routing key where the transport reports none.

    ``nonce_store`` SHOULD be a single instance shared across every
    delivery on the consumer loop (:func:`consume` does this for you); if
    omitted, a throwaway single-use store is created for this call only,
    which makes replay detection meaningless beyond duplicate nonces
    within this one call — acceptable for standalone/test invocations of
    this private helper, never for production use via :func:`consume`.

    ``now`` overrides the wall-clock reference used for the ``issued_at``
    freshness check (default ``None`` uses real UTC now). It exists purely so tests can exercise
    the freshness check deterministically against a fixed reference vector's ``issued_at``;
    :func:`consume` never passes it.

    No body can make the verification raise: whatever the bytes, a delivery ends in an ack, or a
    nack and one security event, and the caller goes on to the next delivery.
    """
    if nonce_store is None:
        nonce_store = NonceStore(ttl_seconds=2 * skew_seconds)

    async with message.process(ignore_processed=True):
        # Verification MUST happen before anything else touches the body — the handler must
        # never see an unverified message (T-19-16). The event handed on is parsed from the
        # verified canonical bytes; the body is never re-serialized (server #882, D-5).
        try:
            event, reason = _verify(
                message.body, signing_key, message_type, nonce_store, skew_seconds, now
            )
        except Exception:  # noqa: BLE001 -- no body may end the delivery loop (D-10)
            event, reason = None, "malformed"
        if event is None:
            # Security event (§8.4): the fact and its reason only, never a value of the body.
            _log_discard(logger, message, queue_name, tenant_id, reason or "malformed")
            await message.nack(requeue=False)
            return

        try:
            await handler(event)
        except ErrDrop:
            # Poison message (§8, T-19-18): drop without requeue rather
            # than looping the queue.
            await message.nack(requeue=False)
            return
        except Exception:
            # Transient/retryable handler error: requeue.
            await message.nack(requeue=True)
            return

        await message.ack()


async def consume(
    channel: AbstractChannel,
    queue_name: str,
    signing_key: bytes,
    handler: Handler,
    *,
    tenant_id: str,
    message_type: EventType,
    prefetch: int = DEFAULT_PREFETCH,
    skew_seconds: float = DEFAULT_SKEW_SECONDS,
    nonce_store: NonceStore | None = None,
    logger: logging.Logger | None = None,
) -> None:
    """Consume ``queue_name`` on ``channel``, verifying HMAC before dispatch.

    Sets QoS prefetch (default :data:`DEFAULT_PREFETCH`), passively declares
    ``queue_name`` (the queue MUST already exist server-side — the SDK does
    not create infrastructure), and registers an async per-message callback
    with ``no_ack=False`` so the SDK — not aio-pika — owns every ack/nack
    decision (§8).

    ``signing_key`` MUST be obtained from the AXIAM management API for the
    tenant whose queue is being consumed (§8.1); hardcoding a signing key is
    prohibited. ``tenant_id`` is that tenant: it is what every discard event reports (never a
    value read from a body). ``message_type`` (``"authz_request"`` or ``"audit_event"``) is the
    ONE signed type this consumer accepts (contract 1.69, D-9); an application consuming both
    types runs two consumers.

    NEW-4 (AMQP replay protection): ``skew_seconds`` bounds how far
    ``issued_at`` may drift from wall-clock now (default 300s / 5 minutes)
    before a message is rejected as stale. ``nonce_store`` is an optional
    injectable :class:`axiam_sdk.amqp._replay.NonceStore`; if omitted, a
    single store with TTL ``2 * skew_seconds`` is created here — once, for
    the lifetime of this ``consume()`` call — and threaded through every
    delivery's ``_on_message`` invocation so nonce replay detection
    persists across the whole consumer loop rather than resetting per
    message.

    ``logger`` is an injectable ``logging.Logger`` (D-15: observability
    off-by-default). If omitted, a module-level logger with a
    :class:`logging.NullHandler` is used so the consumer is silent unless
    the caller configures logging.
    """
    if message_type not in _LAYOUTS:
        raise ValueError("message_type must be 'authz_request' or 'audit_event'")
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if logger is None:
        logger = _DEFAULT_LOGGER
    if nonce_store is None:
        nonce_store = NonceStore(ttl_seconds=2 * skew_seconds)

    await channel.set_qos(prefetch_count=prefetch)
    queue = await channel.declare_queue(queue_name, durable=True, passive=True)

    async def _callback(message: AbstractIncomingMessage) -> None:
        """Per-delivery callback registered with ``queue.consume`` — binds
        the fixed ``signing_key``/``handler``/``logger``/``nonce_store``/
        ``skew_seconds`` for this ``consume()`` call and forwards each
        incoming message to :func:`_on_message` for the actual verify/
        parse/dispatch decision."""
        try:
            await _on_message(
                message,
                signing_key,
                handler,
                logger,
                tenant_id=tenant_id,
                message_type=message_type,
                queue_name=queue_name,
                nonce_store=nonce_store,
                skew_seconds=skew_seconds,
            )
        except Exception as exc:  # noqa: BLE001 -- nothing may escape the delivery loop (D-10)
            logger.warning(
                "axiam_sdk_security: AMQP event handling failed unexpectedly (%s); "
                "the consumer keeps serving",
                type(exc).__qualname__,
            )

    await queue.consume(_callback, no_ack=False, consumer_tag=CONSUMER_TAG)


_DEFAULT_LOGGER = logging.getLogger("axiam_sdk.amqp")
_DEFAULT_LOGGER.addHandler(logging.NullHandler())
