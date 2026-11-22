"""The AMQP authorization requester (CONTRACT.md §8, "Signed authorization responses",
contract 1.68; N2, D-9).

:class:`AuthzRequester` publishes a signed ``AuthzRequest`` on ``axiam.authz.request`` through
the default exchange with a **private** ``reply_to`` queue, and accepts an answer only when it
verifies as the server's signed response to *that* request. It is the first requester in this
SDK: until contract 1.68 the SDK only consumed AMQP messages, and the server answered every
tenant, unsigned, on the one shared ``axiam.authz.response`` queue (N2).

The rule that decides the design is **verify the received bytes and deliver the same bytes**
(C2). The signature is checked over the delivery body with its trailing ``hmac_signature``
member cut out of the closing brace -- never over a re-serialization, which fails whenever
``reason`` carries a character encoders disagree on -- and the decision handed to the caller is
decoded from those very canonical bytes.

What a delivery must satisfy to complete a request (rules 1-4 of §8):

1. *strict parse* -- a JSON object with no duplicate or case-variant key, ``allowed`` a JSON
   boolean, ``tenant_id``, ``nonce`` and ``hmac_signature`` present, the signature the trailing
   member;
2. *signature* -- HMAC-SHA256 under the subkey of the requester's **own** tenant and the
   ``key_version`` it sent, constant-time;
3. *binding* -- ``tenant_id`` is the requester's, and ``correlation_id`` **and** ``nonce`` match
   one request still outstanding, which is then retired;
4. anything else is nacked without requeue, logged as a security event (never a signature
   value), never an allow, and the caller keeps waiting for the genuine answer.

A response with no ``hmac_signature`` member at all (a server older than 1.68) is refused unless
the integrator passes ``allow_unsigned_responses=True``; that opt-out never admits a response
that *carries* a signature and fails it.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import re
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

__all__ = [
    "AUTHZ_KEY_VERSION",
    "AUTHZ_REQUEST_QUEUE",
    "AioPikaAuthzTransport",
    "AuthzDecision",
    "AuthzDelivery",
    "AuthzRequester",
    "AuthzRequesterClosedError",
    "AuthzTransport",
    "build_authz_request",
]

#: The queue the server consumes ``AuthzRequest`` from (default exchange, routing key).
AUTHZ_REQUEST_QUEUE = "axiam.authz.request"

#: The signing-key version this requester sends and derives nothing from: the caller supplies
#: the tenant subkey for it (§8.1), and the response carries no ``key_version`` -- the requester
#: uses the one it sent.
AUTHZ_KEY_VERSION = 2

#: Bounds one :meth:`AuthzRequester.check` unless the caller passes a timeout.
DEFAULT_AUTHZ_TIMEOUT_SECONDS = 10.0

#: The prefix of the server's own queues; it does not honour a ``reply_to`` that starts with it
#: (§8 rule 5), which would put this requester back on the shared queue the contract forbids.
_SERVER_QUEUE_PREFIX = "axiam."

_SIG_MEMBER = b',"hmac_signature":"'
_SIG_HEX_LENGTH = 64
_SIG_TAIL = b'"}'
_HEX64 = re.compile(rb"[0-9a-fA-F]{64}")

_LOGGER = logging.getLogger("axiam_sdk.amqp")


class AuthzRequesterClosedError(Exception):
    """Raised by :meth:`AuthzRequester.check` once the requester's reply queue has gone away or
    :meth:`AuthzRequester.close` was called."""


@dataclass(frozen=True)
class AuthzDecision:
    """A verified answer to one ``AuthzRequest``."""

    #: The decision. ``True`` only for a response that verified under the tenant subkey (or, with
    #: ``allow_unsigned_responses``, one that carried no signature at all -- see ``unsigned``).
    allowed: bool
    #: The server's human-readable reason; ``""`` when absent.
    reason: str = ""
    #: The machine-readable code (``allowed``, ``no_grant``, ``denied_by_rule``,
    #: ``tenant_suspended``, ...); ``""`` when absent. A code this SDK does not know is surfaced
    #: verbatim (§11.2 rule 9).
    reason_code: str = ""
    #: ``True`` when the response carried no ``hmac_signature`` and was accepted only because
    #: ``allow_unsigned_responses`` is set.
    unsigned: bool = False


class AuthzDelivery(Protocol):
    """One message off the private reply queue."""

    @property
    def body(self) -> bytes:
        """The raw message bytes, exactly as received."""

    async def ack(self) -> None:
        """Acknowledge the delivery."""

    async def nack(self) -> None:
        """Negatively acknowledge WITHOUT requeue: a redelivered response is no more genuine."""


class AuthzTransport(Protocol):
    """The seam between the requester and a broker: it declares the private reply queue and
    publishes requests. :class:`AioPikaAuthzTransport` is the ``aio-pika`` implementation; tests
    supply a fake."""

    async def declare_reply_queue(self) -> tuple[str, AsyncIterator[AuthzDelivery]]:
        """Declare an EXCLUSIVE, auto-delete, broker-named queue only this requester consumes (an
        ``amq.gen-...`` queue) and start consuming it with manual acknowledgement. Returns its
        name and its deliveries; the iterator ends when the queue or connection goes away."""

    async def publish_request(
        self, queue: str, reply_to: str, correlation_id: str, body: bytes
    ) -> None:
        """Publish ``body`` on the default exchange with routing key ``queue``, AMQP
        ``reply_to`` = ``reply_to`` and ``correlation_id`` = ``correlation_id``."""

    async def close(self) -> None:
        """Release the consumer. Idempotent. The queue is exclusive and auto-delete, so the
        broker removes it with it."""


# ---------------------------------------------------------------------------
# Building a request
# ---------------------------------------------------------------------------


def _hmac_hex(key: bytes, data: bytes) -> str:
    """Hex HMAC-SHA256 of ``data`` under ``key``."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _rfc3339_seconds(moment: datetime) -> str:
    """UTC, whole seconds, ``Z``-suffixed -- the form the server writes for ``issued_at``."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_authz_request(
    signing_key: bytes,
    *,
    correlation_id: str,
    tenant_id: str,
    subject_id: str,
    action: str,
    resource_id: str,
    scope: str | None,
    nonce: str,
    issued_at: datetime,
    key_version: int = AUTHZ_KEY_VERSION,
) -> bytes:
    """Serialize and sign an ``AuthzRequest`` in the server's field order, compact, with the
    signature appended as the trailing member.

    The members are written the way the server's ``serde_json`` writes them: ``"`` and ``\\``
    escaped, ``\\b \\f \\n \\r \\t`` and the other control characters below U+0020 escaped
    (``\\u00XX``, lower-case hex), and everything else -- ``/``, ``<``, ``>``, ``&`` and all
    non-ASCII, U+2028 and U+2029 included -- raw UTF-8. ``json.dumps(..., ensure_ascii=False)``
    does exactly that, and the default ``ensure_ascii=True`` would not: it would sign different
    bytes from the ones the server verifies for any non-ASCII ``action``.

    Raises:
        ValueError: ``subject_id`` or ``resource_id`` is not a UUID, or a string is not valid
            Unicode (a lone surrogate), which UTF-8 cannot carry.
    """
    members: dict[str, Any] = {
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "subject_id": str(uuid.UUID(subject_id)),
        "action": action,
        "resource_id": str(uuid.UUID(resource_id)),
    }
    if scope is not None:
        members["scope"] = scope
    members["key_version"] = key_version
    members["nonce"] = nonce
    members["issued_at"] = _rfc3339_seconds(issued_at)
    try:
        canonical = json.dumps(members, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("action and scope must be valid Unicode") from exc
    signature = _hmac_hex(signing_key, canonical).encode("ascii")
    return canonical[:-1] + _SIG_MEMBER + signature + _SIG_TAIL


# ---------------------------------------------------------------------------
# Verifying a response
# ---------------------------------------------------------------------------


class _Discard(Exception):  # noqa: N818 -- a control-flow signal, not an error type
    """A delivery that fails §8 rule 1, 2 or 3. ``str(exc)`` names the fact, never a value."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that refuses an object with a repeated key."""
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _Discard("a duplicate key")
        seen[key] = value
    return seen


def _strict_object(raw: bytes) -> dict[str, Any]:
    """Parse ``raw`` as one JSON object with unambiguous keys: no duplicate key at any depth and
    no two top-level keys equal under case folding (a decoder that matches keys case-insensitively
    would otherwise read a different decision from the same bytes)."""
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except _Discard:
        raise
    except (ValueError, RecursionError) as exc:
        raise _Discard("the body is not a JSON object") from exc
    if not isinstance(parsed, dict):
        raise _Discard("the body is not a JSON object")
    folded = {key.casefold() for key in parsed}
    if len(folded) != len(parsed):
        raise _Discard("keys that differ only by case")
    return parsed


def _cut_trailing_signature(body: bytes) -> tuple[bytes, bytes] | None:
    """Remove the final ``,"hmac_signature":"<64 hex>"`` member from ``body``.

    Returns ``(canonical, signature_hex)`` -- ``canonical`` being the rest closed with ``}`` --
    or ``None`` when ``body`` does not end in exactly that member. Never repaired by
    re-serializing.
    """
    suffix_length = len(_SIG_MEMBER) + _SIG_HEX_LENGTH + len(_SIG_TAIL)
    if len(body) <= suffix_length or not body.endswith(_SIG_TAIL):
        return None
    start = len(body) - suffix_length
    if body[start : start + len(_SIG_MEMBER)] != _SIG_MEMBER:
        return None
    signature = body[start + len(_SIG_MEMBER) : len(body) - len(_SIG_TAIL)]
    if _HEX64.fullmatch(signature) is None:
        return None
    return body[:start] + b"}", signature


def _is_json_string(value: object) -> bool:
    """Whether ``value`` is a non-empty JSON string."""
    return isinstance(value, str) and value != ""


def _optional_text(members: dict[str, Any], name: str) -> str:
    """An optional string member: ``""`` when absent or ``null``; anything but a string is a
    discard."""
    value = members.get(name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise _Discard(f"{name} is not a string")
    return value


@dataclass
class _Pending:
    """One outstanding request."""

    nonce: str
    future: asyncio.Future[AuthzDecision]


class AuthzRequester:
    """Publishes ``AuthzRequest`` messages and verifies their answers.

    Safe for many concurrent :meth:`check` calls on one event loop. Build one with
    :meth:`open`; close it with :meth:`close` (or ``async with``).

    ``tenant_id`` is the requester's **own** tenant and the only tenant a response is accepted
    for. ``signing_key`` is that tenant's AMQP subkey for key version 2, obtained from the AXIAM
    management API (§8.1) -- never hardcoded, and never the master key.
    """

    def __init__(
        self,
        transport: AuthzTransport,
        *,
        tenant_id: str,
        signing_key: bytes,
        reply_to: str,
        allow_unsigned_responses: bool,
        timeout: float,
        logger: logging.Logger,
        clock: Callable[[], datetime],
    ) -> None:
        """Internal: use :meth:`open`, which declares the private reply queue first."""
        self._transport = transport
        self._tenant_id = tenant_id
        self._signing_key = bytes(signing_key)
        self._reply_to = reply_to
        self._allow_unsigned = allow_unsigned_responses
        self._timeout = timeout
        self._logger = logger
        self._clock = clock
        self._pending: dict[str, _Pending] = {}
        self._closed = False
        self._consumer: asyncio.Task[None] | None = None

    @classmethod
    async def open(
        cls,
        transport: AuthzTransport,
        *,
        tenant_id: str,
        signing_key: bytes,
        allow_unsigned_responses: bool = False,
        timeout: float = DEFAULT_AUTHZ_TIMEOUT_SECONDS,
        logger: logging.Logger | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> AuthzRequester:
        """Open a private reply queue on ``transport`` and return a requester for ``tenant_id``.

        Args:
            transport: Usually ``AioPikaAuthzTransport(channel)``.
            tenant_id: The requester's own tenant UUID.
            signing_key: The tenant's AMQP subkey for key version 2 (§8.1).
            allow_unsigned_responses: The explicit, integrator-set opt-out for ONE rolling
                upgrade against a server older than contract 1.68, whose responses are unsigned.
                Off by default. With it set, a response that carries **no** ``hmac_signature``
                member at all is accepted on its ``correlation_id`` alone (and logged as a
                security warning); a response that carries a signature is verified in full
                whatever this says, and the opt-out never admits one that fails. Remove it once
                the server is upgraded.
            timeout: Bounds each :meth:`check`, in seconds (default 10).
            logger: Receives the security events (a discarded response, an unsigned one
                admitted). Messages never contain a signature value. Silent by default.
            clock: Returns the current time; tests only.

        Raises:
            ValueError: ``tenant_id`` is not a UUID, ``signing_key`` is empty, or the transport's
                reply queue name is empty or starts with ``axiam.`` (not a private queue).
        """
        try:
            tenant = str(uuid.UUID(tenant_id))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("authz requester tenant_id is not a UUID") from exc
        if not signing_key:
            raise ValueError("authz requester needs the tenant signing key")

        queue, deliveries = await transport.declare_reply_queue()
        if not queue or queue.startswith(_SERVER_QUEUE_PREFIX):
            # The server answers a reply_to naming one of its own queues on the shared
            # axiam.authz.response instead (§8 rule 5).
            await transport.close()
            raise ValueError(f"authz reply queue {queue!r} is not a private queue")

        requester = cls(
            transport,
            tenant_id=tenant,
            signing_key=signing_key,
            reply_to=queue,
            allow_unsigned_responses=allow_unsigned_responses,
            timeout=timeout,
            logger=logger if logger is not None else _LOGGER,
            clock=clock if clock is not None else lambda: datetime.now(UTC),
        )
        requester._consumer = asyncio.create_task(requester._consume(deliveries))
        return requester

    @property
    def reply_to(self) -> str:
        """The private reply queue requests name in their ``reply_to``."""
        return self._reply_to

    async def __aenter__(self) -> AuthzRequester:
        """Enter the ``async with`` form."""
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """Close on leaving the ``async with`` block."""
        await self.close()

    async def close(self) -> None:
        """Stop accepting answers; outstanding and later :meth:`check` calls raise
        :class:`AuthzRequesterClosedError`. Idempotent."""
        self._shutdown()
        consumer = self._consumer
        if consumer is not None and consumer is not asyncio.current_task():
            consumer.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await consumer
        await self._transport.close()

    def _shutdown(self) -> None:
        """Refuse new checks and fail every outstanding one."""
        self._closed = True
        for pending in self._pending.values():
            if not pending.future.done():
                pending.future.set_exception(AuthzRequesterClosedError("authz requester is closed"))

    async def check(
        self,
        subject_id: str,
        action: str,
        resource_id: str,
        scope: str | None = None,
        *,
        timeout: float | None = None,
    ) -> AuthzDecision:
        """Ask the server whether ``subject_id`` may perform ``action`` on ``resource_id``
        (optionally narrowed by one ``scope``) and wait for the verified answer.

        A response that fails verification or binding is discarded and this keeps waiting for
        the genuine one until the timeout ends: a failed verification is never an allow and
        never completes the request.

        Raises:
            ValueError: ``subject_id`` / ``resource_id`` is not a UUID, or a string is not valid
                Unicode.
            TimeoutError: no verified answer arrived in time.
            AuthzRequesterClosedError: the requester is closed.
        """
        if self._closed:
            raise AuthzRequesterClosedError("authz requester is closed")
        correlation_id = str(uuid.uuid4())  # os.urandom: unpredictable
        nonce = str(uuid.uuid4())  # independent of the correlation_id
        body = build_authz_request(
            self._signing_key,
            correlation_id=correlation_id,
            tenant_id=self._tenant_id,
            subject_id=subject_id,
            action=action,
            resource_id=resource_id,
            scope=scope,
            nonce=nonce,
            issued_at=self._clock(),
        )
        pending = _Pending(nonce, asyncio.get_running_loop().create_future())
        self._pending[correlation_id] = pending
        try:
            async with asyncio.timeout(timeout if timeout is not None else self._timeout):
                await self._transport.publish_request(
                    AUTHZ_REQUEST_QUEUE, self._reply_to, correlation_id, body
                )
                return await pending.future
        finally:
            self._pending.pop(correlation_id, None)

    async def _consume(self, deliveries: AsyncIterator[AuthzDelivery]) -> None:
        """Read the private reply queue until it ends."""
        try:
            async for delivery in deliveries:
                await self._handle(delivery)
        finally:
            # The queue or connection went away: nothing further can be answered.
            self._shutdown()

    async def _handle(self, delivery: AuthzDelivery) -> None:
        """Verify one delivery and complete the matching request, or discard it (nack without
        requeue plus a security event)."""
        body = delivery.body
        try:
            decision, correlation_id = self._verify_response(body)
        except _Discard as exc:
            # The fact of failure only -- never a signature value (§8 protocol rule 4).
            self._logger.warning("axiam_sdk_security: AMQP authz response discarded: %s", exc)
            await delivery.nack()
            return

        pending = self._pending.get(correlation_id)
        if pending is None or pending.future.done():
            self._logger.warning(
                "axiam_sdk_security: AMQP authz response discarded: no outstanding request"
            )
            await delivery.nack()
            return
        # Retire on acceptance: a second response for it is dropped.
        del self._pending[correlation_id]
        pending.future.set_result(decision)
        await delivery.ack()

    def _verify_response(self, body: bytes) -> tuple[AuthzDecision, str]:
        """Apply §8's consumer obligations 1-3 to ``body``; return the decision and the
        ``correlation_id`` it answers.

        Never re-serializes: the signature is checked over ``body`` minus its trailing signature
        member, and the decision is decoded from those same bytes (C2).
        """
        members = _strict_object(body)

        # Rule 1 (strict parse) for the member every response carries.
        if type(members.get("allowed")) is not bool:
            raise _Discard("allowed is missing or not a boolean")

        if "hmac_signature" not in members:
            return self._accept_unsigned(members)

        cut = _cut_trailing_signature(body)
        if cut is None:
            raise _Discard("the body does not end in the hmac_signature member")
        canonical, signature = cut
        if members["hmac_signature"] != signature.decode("ascii"):
            raise _Discard("hmac_signature is not the trailing member")

        # Rule 2: HMAC-SHA256 under the requester's own tenant subkey, constant time.
        expected = hmac.new(self._signing_key, canonical, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, bytes.fromhex(signature.decode("ascii"))):
            raise _Discard("the signature does not verify")

        # Everything below reads the verified canonical bytes, not `body` (C2).
        verified = _strict_object(canonical)
        correlation_id = verified.get("correlation_id")
        tenant_id = verified.get("tenant_id")
        nonce = verified.get("nonce")
        if not (
            _is_json_string(tenant_id)
            and _is_json_string(nonce)
            and _is_json_string(correlation_id)
        ):
            raise _Discard("tenant_id, nonce or correlation_id is missing")
        if type(verified.get("allowed")) is not bool:
            raise _Discard("allowed is missing or not a boolean")

        # Rule 3: the requester's own tenant, and one outstanding request.
        if tenant_id != self._tenant_id:
            raise _Discard("tenant_id is not the requester's")
        pending = self._pending.get(str(correlation_id))
        if pending is None or not hmac.compare_digest(pending.nonce.encode(), str(nonce).encode()):
            raise _Discard("correlation_id and nonce match no outstanding request")

        decision = AuthzDecision(
            allowed=verified["allowed"],
            reason=_optional_text(verified, "reason"),
            reason_code=_optional_text(verified, "reason_code"),
        )
        return decision, str(correlation_id)

    def _accept_unsigned(self, members: dict[str, Any]) -> tuple[AuthzDecision, str]:
        """A response with no ``hmac_signature`` member: refused unless the opt-out is set, in
        which case it is accepted on its ``correlation_id`` alone (a pre-1.68 server answers with
        no ``tenant_id`` or ``nonce``)."""
        if not self._allow_unsigned:
            raise _Discard("the response is unsigned")
        correlation_id = members.get("correlation_id")
        if not _is_json_string(correlation_id):
            raise _Discard("the unsigned response has no correlation_id")
        if str(correlation_id) not in self._pending:
            raise _Discard("correlation_id matches no outstanding request")
        decision = AuthzDecision(
            allowed=members["allowed"],
            reason=_optional_text(members, "reason"),
            reason_code=_optional_text(members, "reason_code"),
            unsigned=True,
        )
        self._logger.warning(
            "axiam_sdk_security: AMQP authz response accepted UNSIGNED because "
            "allow_unsigned_responses is set"
        )
        return decision, str(correlation_id)


# ---------------------------------------------------------------------------
# aio-pika transport
# ---------------------------------------------------------------------------


class _AioPikaAuthzDelivery:
    """Adapts an ``aio_pika`` incoming message to :class:`AuthzDelivery`."""

    def __init__(self, message: Any) -> None:
        """Wrap one incoming aio-pika message."""
        self._message = message

    @property
    def body(self) -> bytes:
        """The raw message bytes."""
        raw: bytes = self._message.body
        return raw

    async def ack(self) -> None:
        """Acknowledge the delivery."""
        await self._message.ack()

    async def nack(self) -> None:
        """Negatively acknowledge WITHOUT requeue."""
        await self._message.nack(requeue=False)


class AioPikaAuthzTransport:
    """``aio-pika`` implementation of :class:`AuthzTransport` over a channel the caller opened
    (over ``amqps://``, §8b -- this class dials nothing).

    The reply queue is declared with an empty name, so the broker names it (``amq.gen-...``),
    **exclusive** (only this connection may consume it), auto-delete and not durable, and is
    consumed exclusively with manual acknowledgement. Requests go through the default exchange.
    """

    def __init__(self, channel: Any) -> None:
        """Wrap an open aio-pika channel."""
        self._channel = channel
        self._iterator: Any = None

    async def declare_reply_queue(self) -> tuple[str, AsyncIterator[AuthzDelivery]]:
        """Declare the private reply queue and start consuming it."""
        queue = await self._channel.declare_queue(
            "", durable=False, exclusive=True, auto_delete=True
        )
        self._iterator = queue.iterator(no_ack=False, exclusive=True)
        await self._iterator.__aenter__()
        return str(queue.name), self._deliveries(self._iterator)

    @staticmethod
    async def _deliveries(iterator: Any) -> AsyncIterator[AuthzDelivery]:
        """Wrap each aio-pika message as an :class:`AuthzDelivery`."""
        async for message in iterator:
            yield _AioPikaAuthzDelivery(message)

    async def publish_request(
        self, queue: str, reply_to: str, correlation_id: str, body: bytes
    ) -> None:
        """Publish ``body`` on the default exchange with routing key ``queue``."""
        import aio_pika

        await self._channel.default_exchange.publish(
            aio_pika.Message(
                body=body,
                content_type="application/json",
                correlation_id=correlation_id,
                reply_to=reply_to,
            ),
            routing_key=queue,
        )

    async def close(self) -> None:
        """Cancel the consumer. Idempotent."""
        iterator, self._iterator = self._iterator, None
        if iterator is not None:
            with contextlib.suppress(Exception):
                await iterator.__aexit__(None, None, None)
