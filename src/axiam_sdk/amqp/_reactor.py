"""``reactor_serve`` — the SDK reactor runtime (CONTRACT.md §22.10).

A **Reactor** is an external process that subscribes to named hook events on the
AMQP bus and answers back — allow, deny, or a field-allow-listed mutation —
inside a timeout the server declared. It is AXIAM's answer to Zitadel Actions
and Keycloak SPIs, and the difference is the whole design: those load
third-party code INTO the authorization server, and this keeps it outside,
reachable only through a signed reply schema the server validates before it
believes a word of it.

One helper. It connects (TLS per §8b and §6), consumes the SERVER-DECLARED
queue, and for each delivery verifies §8 v2 (``key_version``, MAC, freshness,
nonce), decodes the event, dispatches to a user-supplied handler, then signs and
publishes the reply. It reconnects with §16-shaped jittered backoff and drains
in-flight events on shutdown per §18.

The four rules §22.10 puts on this helper, and where each one lives
==================================================================

1. **It MUST NOT declare topology** (§22.1) — enforced by the shape of
   :class:`ReactorTransport`, which has no declare or bind method at all. There
   is nowhere in this module for an exchange, queue or binding declaration to
   live, so the rule cannot be violated by a later edit that forgets it. This is
   not tidiness: a reactor that can bind is a reactor that can bind itself to
   ``*.token.pre_issue`` and read another tenant's issuance events.
2. **It MUST fail closed on its own errors.** A handler that raises, an answer
   this SDK refuses to send, a body that will not decode, a window that has
   already closed — every one of them results in NO REPLY, letting the
   operator's ``failure_policy`` decide. An SDK that answered ``allow`` on
   behalf of a handler that crashed would have overridden a ``fail_closed``
   setting from inside the library.
3. **It MUST NOT filter a patch** to the allowed subset (§22.4 rule 1) — see
   :func:`axiam_sdk.amqp.mutate`.
4. **It SHOULD honour ``timeout_ms``** by abandoning work whose window has
   closed rather than replying late (§22.3).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from axiam_sdk._telemetry import (
    RequestEnd,
    RequestStart,
    TelemetryDispatcher,
    TelemetryHook,
)
from axiam_sdk.amqp._reactor_protocol import (
    REACTOR_FRESHNESS_SKEW_SECONDS,
    EventRejection,
    ReactorDecision,
    ReactorEvent,
    _require_mfa_allowed,
    build_reactor_reply,
    reactor_reply_bytes,
    sign_reactor_reply,
    verify_event,
)
from axiam_sdk.amqp._reactor_registry import (
    REACTOR_CHAIN_CEILING_MS,
    ReactorMode,
    event_spec,
    reactor_queue_name,
)
from axiam_sdk.amqp._replay import NonceStore

__all__ = [
    "ReactorDelivery",
    "ReactorTransport",
    "ReactorDialer",
    "ReactorConfig",
    "ReactorHandler",
    "InsecureReactorUrlError",
    "aio_pika_dialer",
    "dispatch_reactor_delivery",
    "reactor_serve",
]

#: Telemetry operation name for one reactor dispatch (§19.1).
_TELEMETRY_OPERATION = "reactor_dispatch"

#: Reconnect backoff. The shape is §16.1's — 200 ms base, doubling, capped at
#: 5 s, FULL jitter over ``[0, backoff]`` — because an outage that drops every
#: reactor at once is exactly the herd §16's jitter exists to break up.
#:
#: What is deliberately NOT borrowed is §16.1's three-attempt cap: that bounds
#: one caller's wait for one request, and a long-lived daemon that stopped
#: reconnecting after three tries would go quietly deaf for the rest of the
#: process's life. The loop instead runs until the caller cancels it.
_RECONNECT_BASE_DELAY_SECONDS = 0.2
_RECONNECT_MAX_DELAY_SECONDS = 5.0

#: How long shutdown waits for in-flight handlers once the runtime is cancelled
#: (§18.1 rule 3 — background work joined, not abandoned). The default is
#: §22.8's chain wall-clock ceiling: past that, no in-flight dispatch can still
#: have a server waiting on it.
_DEFAULT_DRAIN_GRACE_SECONDS = REACTOR_CHAIN_CEILING_MS / 1000.0

_DEFAULT_LOGGER = logging.getLogger("axiam_sdk.amqp.reactor")
_DEFAULT_LOGGER.addHandler(logging.NullHandler())


class InsecureReactorUrlError(ValueError):
    """Raised for an AMQP URL that is not ``amqps://`` (CONTRACT.md §8b).

    Reactors connect across a trust boundary, so the transport is TLS, with a
    supplied CA bundle, no verification-skip switch and no plaintext fallback. A
    plaintext URL is refused at dial time rather than downgraded, because a
    fallback that works is a fallback that gets used.

    HMAC does not substitute for TLS and TLS does not substitute for HMAC: the
    signed reply proves who wrote it, and only TLS keeps the payload off the
    wire in the clear.
    """


class ReactorDelivery(Protocol):
    """One message off the reactor's queue."""

    @property
    def body(self) -> bytes:
        """The raw message bytes, exactly as received."""

    @property
    def reply_to(self) -> str | None:
        """The reply queue named in the delivery's AMQP ``reply_to`` property.

        Standard AMQP RPC. What the SERVER authenticates is not this property
        but the ``correlation_id`` INSIDE the signed reply body (§22.1); this
        only says where to put it.
        """

    @property
    def correlation_id(self) -> str | None:
        """The delivery's AMQP ``correlation_id`` property, echoed onto the reply.

        Not the authenticated binding either — the one in the signed body is.
        """

    async def ack(self) -> None:
        """Acknowledge the delivery."""

    async def nack(self) -> None:
        """Negatively acknowledge the delivery WITHOUT requeue.

        There is no requeue parameter on purpose. A reactor's dispatch window is
        at most five seconds, so a redelivered event can only ever produce a
        reply the server has already stopped reading — requeuing spends the
        broker's effort to guarantee a late answer.
        """


class ReactorTransport(Protocol):
    """One live session against the broker.

    A consumer on the reactor's own queue, and a way to publish a reply back to
    the queue the delivery named.

    **Note the absence of any declare or bind method** (§22.1). The server
    declares the exchange, the per-reactor queue and the bindings from the
    registration's ``events``; actors consume. That rule is enforced here by the
    shape of the protocol rather than by a review comment, because there is
    nowhere for a declaration to live.
    """

    def consume(self, queue: str) -> AsyncIterator[ReactorDelivery]:
        """Start consuming ``queue`` and yield deliveries until the session ends.

        The iterator finishing is what tells :func:`reactor_serve` to reconnect.
        """

    async def publish_reply(
        self, reply_queue: str, correlation_id: str | None, body: bytes
    ) -> None:
        """Publish ``body`` to ``reply_queue`` via the default exchange."""

    async def close(self) -> None:
        """Release the session. Idempotent (§18.1 rule 2)."""


#: Opens one transport session. :func:`reactor_serve` calls it again after a
#: session ends, which is how reconnect works: the dialer, not the runtime, owns
#: how a connection is made.
ReactorDialer = Callable[[], Awaitable[ReactorTransport]]

#: A reactor handler: one coroutine from a verified event to one of three
#: answers (§22.10).
#:
#: Return :func:`axiam_sdk.amqp.allow`, :func:`axiam_sdk.amqp.require_step_up`,
#: :func:`axiam_sdk.amqp.deny`, :func:`axiam_sdk.amqp.mutate` or
#: :func:`axiam_sdk.amqp.abstain`. Raising means "I could not decide": NO REPLY
#: is published and the registration's ``failure_policy`` applies — which is the
#: honest outcome, and the one an operator configured.
#:
#: In ``listen`` mode the return value is IGNORED and no reply is ever published
#: (§22.5): a listener cannot affect any outcome. Write a listener handler
#: IDEMPOTENTLY — a redelivery after a broker hiccup is normal, and a listener
#: that double-counts is one that assumed an exactly-once delivery it was never
#: promised.
ReactorHandler = Callable[[ReactorEvent], Awaitable[ReactorDecision]]


@dataclass
class ReactorConfig:
    """Which reactor this process is, and how it verifies and signs (§22.1, §22.9)."""

    #: The tenant whose events this reactor serves. An event naming any other
    #: tenant is refused before the handler sees it.
    tenant_id: str
    #: This reactor's registration id, from ``POST /api/v1/reactors`` (§22.9).
    #: It names the ONE queue this process may consume. Passing another
    #: reactor's id is not a supported way to share a runtime: §22.1 forbids
    #: deriving a queue name for a reactor other than the one you are.
    reactor_id: str
    #: The tenant's HKDF-derived AMQP subkey (§8.1, §22.2) — **not** the master
    #: key. Fetch it from the AXIAM management API; hardcoding one is
    #: prohibited. It is a credential (§22.12): this runtime never logs it at
    #: any level, it never appears in a reconnect diagnostic, and no telemetry
    #: event has a field it could be put in. Pass ``SecretBytes.get_secret_value()``
    #: if you hold it in this SDK's ``Sensitive`` equivalent.
    signing_key: bytes
    #: ``intercept`` (the default) or ``listen``.
    mode: ReactorMode = "intercept"
    #: Overrides the derived queue name. It is only ever the queue the SERVER
    #: declared for THIS reactor (§22.1).
    queue: str | None = None
    #: Override the ±300 s ``issued_at`` acceptance window. The same window,
    #: doubled, bounds how long a ``nonce`` is remembered for replay detection.
    skew_seconds: float = REACTOR_FRESHNESS_SKEW_SECONDS
    #: Nonce dedup store. One is created and shared across the consumer by
    #: default — a fresh store per delivery would defeat replay dedup entirely.
    nonce_store: NonceStore | None = None
    #: Injectable logger (D-15: observability off by default). Refusals are
    #: logged as a category, never with the received or expected MAC.
    logger: logging.Logger | None = None
    #: A §19 telemetry hook. One ``RequestStart``/``RequestEnd`` pair is emitted
    #: per dispatch, labelled with the registry event name — a bounded label
    #: set, never a correlation id.
    telemetry_hook: TelemetryHook | None = None
    #: How long shutdown waits for in-flight dispatches (§18.1 rule 3).
    drain_grace_seconds: float = _DEFAULT_DRAIN_GRACE_SECONDS

    def resolved_queue(self) -> str:
        """The queue this reactor consumes: :attr:`queue`, or the derived name."""
        return self.queue if self.queue else reactor_queue_name(self.tenant_id, self.reactor_id)

    def __post_init__(self) -> None:
        """Reject a configuration that cannot produce a verifiable reactor."""
        if not self.tenant_id:
            raise ValueError("ReactorConfig.tenant_id is required")
        if not self.reactor_id and not self.queue:
            raise ValueError(
                "ReactorConfig needs either reactor_id (to derive the server-declared "
                "queue) or an explicit queue"
            )
        if not self.signing_key:
            raise ValueError(
                "ReactorConfig.signing_key is required — fetch the tenant AMQP subkey "
                "from the management API (CONTRACT.md §8.1)"
            )
        if self.mode not in ("intercept", "listen"):
            raise ValueError('ReactorConfig.mode must be "intercept" or "listen"')


@dataclass
class _DispatchContext:
    """Everything one dispatch needs that does not come from the delivery."""

    signing_key: bytes
    tenant_id: str
    mode: ReactorMode
    skew_seconds: float
    nonce_store: NonceStore
    logger: logging.Logger
    telemetry: TelemetryDispatcher | None = None


def _registry_label(name: str) -> str:
    """Map a wire event name onto the registry's own string.

    A telemetry label can never be an attacker-chosen string or a cardinality
    bomb: an event outside the registry is reported as ``unknown_event``.
    """
    spec = event_spec(name)
    return spec.name if spec is not None else "unknown_event"


def _emit(dispatcher: TelemetryDispatcher | None, event: RequestStart | RequestEnd) -> None:
    """Deliver a telemetry event if a hook is installed.

    :class:`TelemetryDispatcher` already swallows anything a sink raises (§19.2
    rule 2) — telemetry is not permitted to fail an authorization decision.
    """
    if dispatcher is not None:
        dispatcher.emit(event)


async def _reject(
    delivery: ReactorDelivery,
    ctx: _DispatchContext,
    rejection: EventRejection,
) -> None:
    """Nack without requeue and log the category.

    The log line names the failure category only — never the received or
    expected MAC, and never the signing key (§8.4, §22.12).
    """
    ctx.logger.warning(
        "axiam_sdk_security: reactor event refused (%s); nacking without requeue",
        rejection,
    )
    await delivery.nack()


async def dispatch_reactor_delivery(
    delivery: ReactorDelivery,
    transport: ReactorTransport,
    ctx: _DispatchContext,
    handler: ReactorHandler,
) -> None:
    """Verify one delivery, dispatch it to ``handler``, and publish the answer.

    The order is §22.3's and is not negotiable: ``key_version``, MAC, freshness,
    nonce, THEN decode and dispatch. Every path that cannot produce a USABLE
    reply publishes nothing at all, which is what hands the decision to the
    registration's ``failure_policy`` (§22.8) rather than to this library.

    Separately testable because it is the load-bearing unit backing
    :func:`reactor_serve`'s per-message loop, mirroring the §8 consumer's
    ``_on_message``.
    """
    try:
        body = json.loads(delivery.body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        await _reject(delivery, ctx, "malformed")
        return
    if not isinstance(body, dict):
        await _reject(delivery, ctx, "malformed")
        return

    started = asyncio.get_running_loop().time()
    event, rejection = verify_event(
        body,
        ctx.signing_key,
        datetime.now(timezone.utc),
        ctx.skew_seconds,
    )
    if event is None:
        # The two return shapes are exclusive, so `rejection` is always set
        # here; the fallback keeps the type honest without an assert.
        await _reject(delivery, ctx, rejection or "malformed")
        return

    # The fourth §22.3 check: the nonce seen-set. It is state rather than a
    # property of the message, which is why it lives here and not in
    # verify_event.
    if not ctx.nonce_store.check_and_record(event.nonce):
        await _reject(delivery, ctx, "replayed_nonce")
        return

    # A queue is per-tenant and the subkey is per-tenant, so this can only fire
    # on a misconfiguration — but a reactor answering for a tenant it was not
    # configured as is exactly the confusion §22.1 refuses to allow.
    if event.tenant_id != ctx.tenant_id:
        await _reject(delivery, ctx, "tenant_mismatch")
        return

    deadline = started + event.timeout_seconds
    label = _registry_label(event.event)
    _emit(
        ctx.telemetry,
        RequestStart(
            operation=_TELEMETRY_OPERATION,
            method="AMQP",
            path_template=label,
            attempt=1,
        ),
    )

    # §22.10 rules 2 and 4 together: the handler runs inside the window the
    # server declared, and an exception is caught rather than propagated — both
    # resolve to *no reply*, never to a synthesized `allow`.
    decision: ReactorDecision | None = None
    try:
        decision = await asyncio.wait_for(handler(event), timeout=event.timeout_seconds)
    except asyncio.CancelledError:
        # Shutdown, not a handler failure. Publishing nothing is still the right
        # answer, and the cancellation must keep propagating (§18).
        raise
    except asyncio.TimeoutError:
        ctx.logger.warning(
            "axiam_sdk.reactor: handler outran timeout_ms for %s; publishing no reply "
            "so the registration's failure_policy decides",
            label,
        )
    except Exception as exc:  # noqa: BLE001 - any handler failure is "no reply".
        ctx.logger.warning(
            "axiam_sdk.reactor: handler raised %s for %s; publishing no reply so the "
            "registration's failure_policy decides",
            type(exc).__name__,
            label,
        )

    _emit(
        ctx.telemetry,
        RequestEnd(
            operation=_TELEMETRY_OPERATION,
            method="AMQP",
            path_template=label,
            attempt=1,
            status=None,
            duration_ms=(asyncio.get_running_loop().time() - started) * 1000.0,
            outcome="failure" if decision is None else "success",
        ),
    )

    # A listener never publishes (§22.5): the server does not wait for it and
    # does not read a reply, so anything it sent would be noise on a queue
    # nobody is draining.
    if ctx.mode == "listen":
        await delivery.ack()
        return

    if decision is not None:
        await _publish_answer(delivery, transport, ctx, event, decision, deadline, label)

    # The event verified and was consumed. Acking is what keeps `last_seen_at`
    # moving — a heartbeat derived from real work (§22.9) — and requeueing an
    # event whose correlation is already spent would only re-run a handler
    # against a window that has closed.
    await delivery.ack()


async def _publish_answer(
    delivery: ReactorDelivery,
    transport: ReactorTransport,
    ctx: _DispatchContext,
    event: ReactorEvent,
    decision: ReactorDecision,
    deadline: float,
    label: str,
) -> None:
    """Build, sign and publish the reply for ``decision`` — or publish nothing.

    Three local refusals produce no reply rather than a body the server would
    reject anyway. None of them is *filtering*: no field is dropped from a patch
    the handler asked for.
    """
    if decision.kind == "abstain":
        return

    patch: dict[str, str] | None = None
    if decision.kind == "mutate":
        patch = decision.patch or {}
        if not patch:
            # `mutate` with an empty patch is `malformed_mutation` server-side
            # (§22.4 row 10). Refusing it here drops no field — the reply has no
            # content to carry.
            ctx.logger.warning(
                "axiam_sdk.reactor: handler returned a mutation with an empty patch "
                "(malformed_mutation) for %s; publishing no reply",
                label,
            )
            return

    # §22.4 row 7 / rule 3: `require_mfa` rides on `allow`, on `login.post_auth`,
    # and nowhere else. §22.13 allows an SDK to refuse this client-side; doing so
    # puts the mistake in the reactor author's log instead of only in the
    # server's audit trail.
    if decision.require_mfa and not _require_mfa_allowed(event.event):
        ctx.logger.warning(
            "axiam_sdk.reactor: require_mfa is only valid on login.post_auth "
            "(require_mfa_not_supported) for %s; publishing no reply",
            label,
        )
        return

    reply = sign_reactor_reply(
        build_reactor_reply(
            event.correlation_id,
            event.tenant_id,
            event.event,
            "allow" if decision.kind == "allow" else decision.kind,
            reason=decision.reason if decision.kind == "deny" else None,
            patch=patch,
            require_mfa=decision.require_mfa,
        ),
        ctx.signing_key,
    )

    # §22.3 / §22.10 rule 4: a late reply is discarded, and the CPU spent
    # producing it was spent for nothing. Do not spend the network on it too.
    if asyncio.get_running_loop().time() >= deadline:
        ctx.logger.warning(
            "axiam_sdk.reactor: the window for %s closed before the reply was ready; "
            "not publishing",
            label,
        )
        return

    reply_to = delivery.reply_to
    if not reply_to:
        ctx.logger.warning(
            "axiam_sdk.reactor: delivery for %s carried no reply_to property; nowhere "
            "to publish the reply",
            label,
        )
        return

    # The AMQP property is the RPC convention; what the server AUTHENTICATES is
    # the correlation_id inside the signed body, which build_reactor_reply
    # copied from the event.
    property_correlation = delivery.correlation_id or event.correlation_id
    body = reactor_reply_bytes(reply)
    try:
        await transport.publish_reply(reply_to, property_correlation, body)
    except Exception as exc:  # noqa: BLE001 - a publish failure is "no reply".
        ctx.logger.warning(
            "axiam_sdk.reactor: publishing the reply for %s failed (%s); the "
            "registration's failure_policy decides",
            label,
            type(exc).__name__,
        )


def _reconnect_delay(attempt: int, fraction: float) -> float:
    """``min(5s, 200ms * 2**(attempt-1))`` with full jitter over ``[0, that]``.

    §16.1's shape, unbounded in attempts — see the module constants for why the
    three-attempt cap is deliberately not borrowed.
    """
    attempt = max(attempt, 1)
    backoff = _RECONNECT_MAX_DELAY_SECONDS
    if attempt < 32:
        backoff = min(_RECONNECT_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), backoff)
    return backoff * min(max(fraction, 0.0), 1.0)


def aio_pika_dialer(
    url: str,
    *,
    ca_bundle: str | None = None,
    prefetch: int = 10,
    heartbeat: int = 10,
) -> ReactorDialer:
    """Build a :data:`ReactorDialer` that connects to ``url`` over TLS (§8b).

    ``url`` MUST be ``amqps://``. A plaintext ``amqp://`` URL raises
    :class:`InsecureReactorUrlError` at dial time rather than being downgraded,
    because a fallback that works is a fallback that gets used. ``ca_bundle`` —
    a bundle path, or inline PEM text — is the only TLS-related knob (§8b
    rule 2): there is no option anywhere in this SDK that weakens or disables
    verification, which is §8b rule 4.

    The returned transport declares nothing. It attaches to the queue the server
    already declared (``get_queue(..., ensure=False)`` sends no ``Queue.Declare``
    frame, not even a passive one) and publishes to the default exchange, which
    exists on every broker and needs no declaration (§22.1).
    """
    if not url.lower().startswith("amqps://"):
        raise InsecureReactorUrlError(
            "reactor AMQP URL must use amqps:// (CONTRACT.md §8b) — HMAC does not "
            "substitute for TLS"
        )

    async def dial() -> ReactorTransport:
        """Open one aio-pika session against the configured broker."""
        import aio_pika

        # `create_default_context` is verification-on: `check_hostname` set and
        # `verify_mode=CERT_REQUIRED`. Nothing below relaxes either — §8b rule 4
        # forbids a verification-skip switch under any name, and rule 2's custom
        # CA bundle is what removes any legitimate reason to want one.
        context = ssl.create_default_context()
        if ca_bundle is not None:
            if "-----BEGIN" in ca_bundle:
                context.load_verify_locations(cadata=ca_bundle)
            else:
                context.load_verify_locations(cafile=ca_bundle)
        connection = await aio_pika.connect_robust(url, ssl_context=context, heartbeat=heartbeat)
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=prefetch)
        return _AioPikaTransport(connection, channel)

    return dial


class _AioPikaTransport:
    """``aio-pika`` implementation of :class:`ReactorTransport`.

    It declares nothing: ``consume`` attaches to a queue the server already
    declared and ``publish_reply`` uses the default exchange (§22.1). There is
    no ``declare_queue``, ``declare_exchange`` or ``bind`` call in this class,
    and the protocol it satisfies offers nowhere to add one.
    """

    def __init__(self, connection: Any, channel: Any) -> None:
        """Wrap an already-open aio-pika connection and channel."""
        self._connection = connection
        self._channel = channel

    def consume(self, queue: str) -> AsyncIterator[ReactorDelivery]:
        """Iterate deliveries from the server-declared ``queue``."""
        return self._iterate(queue)

    async def _iterate(self, queue: str) -> AsyncIterator[ReactorDelivery]:
        """Attach to ``queue`` without declaring it and yield each delivery.

        ``ensure=False`` is what keeps this a pure attach: with ``ensure=True``
        aio-pika would send a passive ``Queue.Declare``, and §22.1 says actors
        never declare — not even to check.
        """
        target = await self._channel.get_queue(queue, ensure=False)
        async with target.iterator(no_ack=False) as deliveries:
            async for message in deliveries:
                yield _AioPikaDelivery(message)

    async def publish_reply(
        self, reply_queue: str, correlation_id: str | None, body: bytes
    ) -> None:
        """Publish ``body`` to ``reply_queue`` through the default exchange."""
        import aio_pika

        exchange = await self._channel.get_exchange("", ensure=False)
        await exchange.publish(
            aio_pika.Message(
                body=body,
                content_type="application/json",
                correlation_id=correlation_id,
            ),
            routing_key=reply_queue,
        )

    async def close(self) -> None:
        """Close the channel and connection, tolerating an already-closed one."""
        with contextlib.suppress(Exception):
            await self._channel.close()
        with contextlib.suppress(Exception):
            await self._connection.close()


class _AioPikaDelivery:
    """Adapts an ``aio_pika`` incoming message to :class:`ReactorDelivery`."""

    def __init__(self, message: Any) -> None:
        """Wrap one incoming aio-pika message."""
        self._message = message

    @property
    def body(self) -> bytes:
        """The raw message bytes."""
        raw: bytes = self._message.body
        return raw

    @property
    def reply_to(self) -> str | None:
        """The delivery's AMQP ``reply_to`` property."""
        value: str | None = self._message.reply_to
        return value

    @property
    def correlation_id(self) -> str | None:
        """The delivery's AMQP ``correlation_id`` property."""
        value: str | None = self._message.correlation_id
        return value

    async def ack(self) -> None:
        """Acknowledge the delivery."""
        await self._message.ack()

    async def nack(self) -> None:
        """Negatively acknowledge WITHOUT requeue."""
        await self._message.nack(requeue=False)


async def reactor_serve(
    dial: ReactorDialer,
    config: ReactorConfig,
    handler: ReactorHandler,
) -> None:
    """Run a reactor until the calling task is cancelled (§22.10's ``reactor_serve``).

    It dials, consumes the server-declared queue, and for each delivery checks
    ``key_version``, verifies the MAC, checks freshness, checks the nonce,
    decodes the event, dispatches to ``handler``, then signs and publishes the
    reply. It reconnects with jittered backoff when a session drops, and on
    cancellation it stops taking deliveries and drains the in-flight ones before
    returning (§18).

    **It never declares an exchange, a queue or a binding** (§22.1).

    ``handler`` is called ONLY with an event whose ``key_version``, MAC,
    freshness and nonce have all passed. A transport failure is never fatal — it
    is a reconnect.

    Security (§22.12): the ``payload``, ``patch``, ``reason`` and ``decision``
    are tenant business data — readable by design, since a handler that cannot
    inspect the event cannot decide anything, but this runtime never logs them
    at info level and yours should not either. The signing key is never logged
    at any level and never appears in an error payload.

    Example::

        await reactor_serve(
            aio_pika_dialer("amqps://broker.example.com:5671"),
            ReactorConfig(tenant_id=tenant, reactor_id=reactor, signing_key=subkey),
            decide,
        )
    """
    logger = config.logger if config.logger is not None else _DEFAULT_LOGGER
    ctx = _DispatchContext(
        signing_key=config.signing_key,
        tenant_id=config.tenant_id,
        mode=config.mode,
        skew_seconds=config.skew_seconds,
        # One store shared across every delivery on this consumer — a fresh
        # store per message would defeat replay dedup entirely.
        nonce_store=(
            config.nonce_store
            if config.nonce_store is not None
            else NonceStore(ttl_seconds=2 * config.skew_seconds)
        ),
        logger=logger,
        telemetry=(
            TelemetryDispatcher(config.telemetry_hook)
            if config.telemetry_hook is not None
            else None
        ),
    )
    queue = config.resolved_queue()

    attempt = 0
    while True:
        try:
            await _run_session(dial, queue, ctx, handler, config.drain_grace_seconds)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - every transport failure is a reconnect.
            # The reason is a CATEGORY, not the error text: an AMQP dial error
            # embeds the URL, and an AMQP URL carries credentials.
            logger.warning(
                "axiam_sdk.reactor: session ended (%s); reconnecting", type(exc).__name__
            )
        attempt += 1
        await asyncio.sleep(_reconnect_delay(attempt, random.random()))  # noqa: S311


async def _run_session(
    dial: ReactorDialer,
    queue: str,
    ctx: _DispatchContext,
    handler: ReactorHandler,
    drain_grace_seconds: float,
) -> None:
    """Serve one connection, returning when it ends.

    In-flight dispatches are drained before it returns, on every path — a lost
    session and a cancelled task alike (§18.1 rule 3: background work joined,
    not abandoned).
    """
    transport = await dial()
    in_flight: set[asyncio.Task[None]] = set()
    try:
        async for delivery in transport.consume(queue):
            # Each dispatch runs on its own task so one slow handler cannot
            # spend another event's 500 ms budget.
            task = asyncio.create_task(dispatch_reactor_delivery(delivery, transport, ctx, handler))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)
    finally:
        if in_flight:
            with contextlib.suppress(asyncio.TimeoutError, TimeoutError):
                await asyncio.wait_for(
                    asyncio.gather(*in_flight, return_exceptions=True),
                    timeout=drain_grace_seconds,
                )
        await transport.close()
