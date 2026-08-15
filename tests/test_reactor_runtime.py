"""CONTRACT.md §22.13 "Runtime" — the behavioural half of the required tests.

A handler that raises produces NO REPLY (zero published messages, not an
``allow``); the runtime declares no exchange, queue or binding; shutdown drains
in-flight events per §18; and the signing key never appears in any log line or
error payload.

Nothing here touches a broker: the runtime is written against a transport seam
that offers exactly the two operations §22.1 permits, and the fake below offers
three MORE than that — ``declare_queue``, ``declare_exchange`` and ``bind`` are
present precisely so the tests can prove the runtime never reaches for them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from axiam_sdk._telemetry import TelemetryEvent
from axiam_sdk.amqp import (
    GRANT_PRE_ASSIGN,
    LOGIN_POST_AUTH,
    TOKEN_PRE_ISSUE,
    USER_PRE_CREATE,
    InsecureReactorUrlError,
    NonceStore,
    ReactorConfig,
    ReactorDecision,
    ReactorEvent,
    abstain,
    aio_pika_dialer,
    allow,
    deny,
    dispatch_reactor_delivery,
    mutate,
    reactor_queue_name,
    reactor_reply_signature_valid,
    reactor_serve,
    require_step_up,
    signing_key_fingerprint,
    to_chrono_rfc3339,
)
from axiam_sdk.amqp._reactor import _DispatchContext, _reconnect_delay
from axiam_sdk.amqp._reactor_protocol import REACTOR_FRESHNESS_SKEW_SECONDS, _canonical_json

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parent.parent / "testdata" / "reactor_v2_reference_vectors.json"
    ).read_text(encoding="utf-8")
)
SUBKEY = bytes.fromhex(_FIXTURE["hkdf"]["derived_subkey_hex"])
TENANT = _FIXTURE["tenant_id"]
REACTOR_ID = _FIXTURE["reactor_id"]


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeDelivery:
    """One recorded delivery, with the ack/nack calls it received."""

    def __init__(
        self,
        body: bytes,
        reply_to: str | None = "amq.reply-to.abc",
        correlation_id: str | None = "prop-cid",
    ) -> None:
        """Build a delivery carrying ``body`` and the two RPC properties."""
        self._body = body
        self._reply_to = reply_to
        self._correlation_id = correlation_id
        self.acked = 0
        self.nacked = 0

    @property
    def body(self) -> bytes:
        """The raw message bytes."""
        return self._body

    @property
    def reply_to(self) -> str | None:
        """The AMQP ``reply_to`` property."""
        return self._reply_to

    @property
    def correlation_id(self) -> str | None:
        """The AMQP ``correlation_id`` property."""
        return self._correlation_id

    async def ack(self) -> None:
        """Record an ack."""
        self.acked += 1

    async def nack(self) -> None:
        """Record a nack (there is no requeue parameter, by design)."""
        self.nacked += 1


class FakeTransport:
    """A transport that offers MORE than the runtime is allowed to use.

    ``declare_queue``, ``declare_exchange`` and ``bind`` exist here so a test
    can prove the runtime never reaches for them — an assertion against the AMQP
    client's declare calls, not against a comment. If a future edit adds a
    declare, the assertion fails.
    """

    def __init__(self, deliveries: list[FakeDelivery] | None = None) -> None:
        """Build a transport that will hand out ``deliveries`` once."""
        self.deliveries = deliveries or []
        self.published: list[tuple[str, str | None, bytes]] = []
        self.declare_calls: list[str] = []
        self.consumed_queue: str | None = None
        self.closed = 0
        self.publish_error: Exception | None = None
        self.hold: asyncio.Event | None = None

    async def declare_queue(self, *args: Any, **kwargs: Any) -> None:
        """Never called by a conformant runtime (§22.1)."""
        self.declare_calls.append("declare_queue")

    async def declare_exchange(self, *args: Any, **kwargs: Any) -> None:
        """Never called by a conformant runtime (§22.1)."""
        self.declare_calls.append("declare_exchange")

    async def bind(self, *args: Any, **kwargs: Any) -> None:
        """Never called by a conformant runtime (§22.1)."""
        self.declare_calls.append("bind")

    async def _iterate(self, queue: str) -> AsyncIterator[FakeDelivery]:
        """Yield the queued deliveries, then optionally park forever."""
        self.consumed_queue = queue
        for delivery in self.deliveries:
            yield delivery
        if self.hold is not None:
            await self.hold.wait()

    def consume(self, queue: str) -> AsyncIterator[FakeDelivery]:
        """Start consuming ``queue``."""
        return self._iterate(queue)

    async def publish_reply(
        self, reply_queue: str, correlation_id: str | None, body: bytes
    ) -> None:
        """Record a published reply, or fail if the test asked for a failure."""
        if self.publish_error is not None:
            raise self.publish_error
        self.published.append((reply_queue, correlation_id, body))

    async def close(self) -> None:
        """Record the teardown."""
        self.closed += 1

    def only_reply(self) -> dict[str, Any]:
        """The single published reply, parsed. Fails if there is not exactly one."""
        assert len(self.published) == 1, self.published
        parsed: dict[str, Any] = json.loads(self.published[0][2])
        return parsed


def signed_event(
    *,
    event: str = LOGIN_POST_AUTH,
    tenant_id: str = TENANT,
    timeout_ms: int = 5_000,
    key_version: int = 2,
    issued_at: datetime | None = None,
    nonce: str | None = None,
    payload: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> bytes:
    """Build and sign an event exactly as the server would, in wire field order."""
    body: dict[str, Any] = {
        "tenant_id": tenant_id,
        "event": event,
        "correlation_id": correlation_id or str(uuid.uuid4()),
        "payload": payload if payload is not None else {"sub": "alice"},
        "timeout_ms": timeout_ms,
        "key_version": key_version,
        "nonce": nonce or str(uuid.uuid4()),
        "issued_at": to_chrono_rfc3339(issued_at or datetime.now(timezone.utc)),
        "hmac_signature": None,
    }
    import hashlib
    import hmac as hmac_mod

    signature = hmac_mod.new(SUBKEY, _canonical_json(body), hashlib.sha256).hexdigest()
    return _canonical_json({**body, "hmac_signature": signature})


def context(**overrides: Any) -> _DispatchContext:
    """A dispatch context with a fresh nonce store and a silent logger."""
    base: dict[str, Any] = {
        "signing_key": SUBKEY,
        "tenant_id": TENANT,
        "mode": "intercept",
        "skew_seconds": REACTOR_FRESHNESS_SKEW_SECONDS,
        "nonce_store": NonceStore(ttl_seconds=2 * REACTOR_FRESHNESS_SKEW_SECONDS),
        "logger": logging.getLogger("test.reactor.silent"),
    }
    base.update(overrides)
    return _DispatchContext(**base)


async def dispatch(
    delivery: FakeDelivery,
    handler: Any,
    transport: FakeTransport | None = None,
    ctx: _DispatchContext | None = None,
) -> FakeTransport:
    """Run one dispatch and return the transport it published through."""
    transport = transport if transport is not None else FakeTransport()
    await dispatch_reactor_delivery(delivery, transport, ctx or context(), handler)
    return transport


# ---------------------------------------------------------------------------


class TestHappyPath:
    """One delivery, verified, dispatched, signed and published."""

    async def test_verifies_dispatches_signs_and_publishes(self) -> None:
        """The correlation in the SIGNED BODY is what the server authenticates."""
        body = json.loads(signed_event())
        delivery = FakeDelivery(signed_event(correlation_id=body["correlation_id"]))
        seen: list[ReactorEvent] = []

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Record the event and allow."""
            seen.append(event)
            return allow()

        transport = await dispatch(delivery, handler)

        assert len(seen) == 1
        assert delivery.acked == 1
        assert delivery.nacked == 0

        reply = transport.only_reply()
        assert reply["decision"] == "allow"
        assert reply["key_version"] == 2
        assert "require_mfa" not in reply
        assert reactor_reply_signature_valid(reply, SUBKEY)
        assert reply["correlation_id"] == seen[0].correlation_id
        assert reply["tenant_id"] == TENANT
        assert reply["event"] == LOGIN_POST_AUTH
        # The AMQP property is only the RPC convention.
        assert transport.published[0][0] == "amq.reply-to.abc"
        assert transport.published[0][1] == "prop-cid"

    async def test_surfaces_timeout_ms_and_the_chained_patch_to_the_handler(self) -> None:
        """§22.3: the handler is told the window, and what the chain already did."""
        captured: list[ReactorEvent] = []

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Record and abstain."""
            captured.append(event)
            return abstain()

        await dispatch(
            FakeDelivery(
                signed_event(
                    event=TOKEN_PRE_ISSUE,
                    timeout_ms=750,
                    payload={"sub": "alice", "_reactor_patch": {"ext.department": "eng"}},
                )
            ),
            handler,
        )

        event = captured[0]
        assert event.timeout_ms == 750
        assert event.timeout_seconds == 0.75
        assert event.chain_patch == {"ext.department": "eng"}
        assert event.spec is not None and event.spec.name == TOKEN_PRE_ISSUE

    async def test_reports_no_chained_patch_on_a_first_in_chain_dispatch(self) -> None:
        """``chain_patch`` is ``None`` when the payload carries none, or a non-dict."""
        captured: list[ReactorEvent] = []

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Record and abstain."""
            captured.append(event)
            return abstain()

        await dispatch(FakeDelivery(signed_event()), handler)
        assert captured[0].chain_patch is None

        await dispatch(FakeDelivery(signed_event(payload={"_reactor_patch": "not a map"})), handler)
        assert captured[1].chain_patch is None

    async def test_an_unknown_event_still_reaches_the_handler_with_a_bounded_label(self) -> None:
        """An event outside the registry has no spec, and no attacker-chosen label."""
        events: list[TelemetryEvent] = []
        captured: list[ReactorEvent] = []

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Record and abstain."""
            captured.append(event)
            return abstain()

        await dispatch(
            FakeDelivery(signed_event(event="../../../etc/passwd")),
            handler,
            ctx=context(telemetry=_dispatcher(events)),
        )
        assert captured[0].spec is None
        assert events[0].path_template == "unknown_event"  # type: ignore[union-attr]


class TestFailClosedOnOwnErrors:
    """§22.10 rule 2 — every one of our own failures publishes NOTHING."""

    async def test_publishes_nothing_when_the_handler_raises(self) -> None:
        """Zero published messages, asserted — not an ``allow``."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Fail."""
            raise RuntimeError("handler blew up")

        delivery = FakeDelivery(signed_event())
        transport = await dispatch(delivery, handler)
        assert transport.published == []
        assert delivery.acked == 1

    async def test_publishes_nothing_when_the_handler_outruns_timeout_ms(self) -> None:
        """The server declared a 5 ms window; the handler takes far longer."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Sleep past the window."""
            await asyncio.sleep(0.2)
            return allow()

        transport = await dispatch(FakeDelivery(signed_event(timeout_ms=5)), handler)
        assert transport.published == []

    async def test_publishes_nothing_when_the_handler_abstains(self) -> None:
        """``abstain`` is the explicit form of "let the failure policy decide"."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Abstain."""
            return abstain()

        delivery = FakeDelivery(signed_event(event=GRANT_PRE_ASSIGN))
        transport = await dispatch(delivery, handler)
        assert transport.published == []
        assert delivery.acked == 1

    @pytest.mark.parametrize("patch", [{}, None])
    async def test_publishes_nothing_for_a_mutation_with_no_patch(
        self, patch: dict[str, str] | None
    ) -> None:
        """``malformed_mutation`` server-side; refusing it here drops no field."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Return an empty mutation."""
            return ReactorDecision(kind="mutate", patch=patch)

        transport = await dispatch(FakeDelivery(signed_event(event=TOKEN_PRE_ISSUE)), handler)
        assert transport.published == []

    async def test_publishes_nothing_when_the_delivery_carries_no_reply_to(self) -> None:
        """Nowhere to put the reply is still "no reply", never a guess."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Allow."""
            return allow()

        transport = await dispatch(FakeDelivery(signed_event(), reply_to=None), handler)
        assert transport.published == []

    async def test_publishes_nothing_when_the_broker_rejects_the_publication(self) -> None:
        """A publish failure hands the outcome to the failure policy too."""
        transport = FakeTransport()
        transport.publish_error = ConnectionResetError("broker went away")

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Allow."""
            return allow()

        delivery = FakeDelivery(signed_event())
        await dispatch(delivery, handler, transport=transport)
        assert transport.published == []
        assert delivery.acked == 1

    async def test_publishes_nothing_when_the_window_closed_before_the_reply(self) -> None:
        """§22.3: a late reply is discarded; do not spend the network on it."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Return in time, but only just — the deadline passes en route."""
            await asyncio.sleep(0.06)
            return allow()

        # 50 ms window, a 60 ms handler: asyncio.wait_for's own timeout and the
        # deadline check race, and both outcomes are "no reply", which is the
        # property under test.
        transport = await dispatch(FakeDelivery(signed_event(timeout_ms=50)), handler)
        assert transport.published == []

    async def test_a_cancelled_dispatch_propagates_rather_than_answering(self) -> None:
        """Shutdown is not a handler failure, and it must keep propagating (§18)."""
        started = asyncio.Event()

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Park until cancelled."""
            started.set()
            await asyncio.sleep(10)
            return allow()

        transport = FakeTransport()
        task = asyncio.create_task(
            dispatch_reactor_delivery(FakeDelivery(signed_event()), transport, context(), handler)
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert transport.published == []


class TestNoFiltering:
    """§22.10 rule 3 / §22.4 rule 1 — a patch goes out exactly as returned."""

    async def test_publishes_a_forbidden_patch_key_unfiltered(self) -> None:
        """The SDK must NOT silently drop ``sub`` from a token.pre_issue patch."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Return a patch containing a key the server will refuse."""
            return mutate({"ext.department": "eng", "sub": "root"})

        transport = await dispatch(FakeDelivery(signed_event(event=TOKEN_PRE_ISSUE)), handler)
        reply = transport.only_reply()
        assert reply["decision"] == "mutate"
        assert reply["patch"] == {"ext.department": "eng", "sub": "root"}
        assert reactor_reply_signature_valid(reply, SUBKEY)
        assert b'"sub":"root"' in transport.published[0][2]

    async def test_snapshots_the_callers_mapping(self) -> None:
        """Mutating the handler's dict afterwards cannot change what was signed."""
        original = {"ext.a": "1"}
        decision = mutate(original)
        original["ext.b"] = "2"
        assert decision.patch == {"ext.a": "1"}


class TestRequireMfa:
    """§22.4 rule 3 — ``require_mfa`` rides on ``allow``, on one event only."""

    async def test_rides_on_allow_for_login_post_auth(self) -> None:
        """The only event where step-up is meaningful."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Demand step-up."""
            return require_step_up()

        transport = await dispatch(FakeDelivery(signed_event(event=LOGIN_POST_AUTH)), handler)
        reply = transport.only_reply()
        assert reply["decision"] == "allow"
        assert reply["require_mfa"] is True
        assert reactor_reply_signature_valid(reply, SUBKEY)

    @pytest.mark.parametrize("event", [TOKEN_PRE_ISSUE, USER_PRE_CREATE, GRANT_PRE_ASSIGN])
    async def test_is_refused_client_side_on_every_other_event(self, event: str) -> None:
        """§22.13 permits refusing locally; doing so names the author's mistake."""

        async def handler(ev: ReactorEvent) -> ReactorDecision:
            """Demand step-up on an event that has no step-up notion."""
            return require_step_up()

        transport = await dispatch(FakeDelivery(signed_event(event=event)), handler)
        assert transport.published == []


class TestDenyOnTheWire:
    """§22.4 — the deny answer, with and without a reason."""

    async def test_publishes_decision_deny_with_the_reason(self) -> None:
        """The reason is audited; the decision stands without one."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Refuse."""
            return deny("embargoed region")

        transport = await dispatch(FakeDelivery(signed_event()), handler)
        reply = transport.only_reply()
        assert reply["decision"] == "deny"
        assert reply["reason"] == "embargoed region"
        assert reactor_reply_signature_valid(reply, SUBKEY)

    async def test_omits_reason_entirely_when_the_handler_gives_none(self) -> None:
        """The omission is inside the signed bytes, so it is not cosmetic."""

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Refuse without explaining."""
            return deny()

        transport = await dispatch(FakeDelivery(signed_event()), handler)
        raw = transport.published[0][2]
        assert b'"decision":"deny"' in raw
        assert b"reason" not in raw
        assert reactor_reply_signature_valid(transport.only_reply(), SUBKEY)


class TestListenMode:
    """§22.5 — a listener cannot affect any outcome, so it publishes nothing."""

    @pytest.mark.parametrize("answer", ["deny", "mutate", "allow"])
    async def test_never_publishes_but_still_observes_and_acks(self, answer: str) -> None:
        """Even an answer that would have vetoed is dropped on the floor."""
        calls = 0

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Return whichever answer the parametrization asked for."""
            nonlocal calls
            calls += 1
            if answer == "deny":
                return deny("nope")
            if answer == "mutate":
                return mutate({"ext.department": "eng"})
            return allow()

        delivery = FakeDelivery(signed_event(event=TOKEN_PRE_ISSUE))
        transport = await dispatch(delivery, handler, ctx=context(mode="listen"))
        assert calls == 1
        assert transport.published == []
        assert delivery.acked == 1


class TestVerificationBeforeTheHandler:
    """§22.3 — nothing unverified ever reaches user code."""

    async def _never_called(self, event: ReactorEvent) -> ReactorDecision:
        """A handler that fails the test if it is ever invoked."""
        raise AssertionError("an unverified event reached the handler")

    async def test_nacks_a_bad_signature_without_requeue(self) -> None:
        """The nack has no requeue parameter to get wrong."""
        body = json.loads(signed_event())
        body["hmac_signature"] = "00" * 32
        delivery = FakeDelivery(_canonical_json(body))
        transport = await dispatch(delivery, self._never_called)
        assert delivery.nacked == 1
        assert delivery.acked == 0
        assert transport.published == []

    async def test_nacks_a_v1_event(self) -> None:
        """``key_version < 2`` carries no replay protection at all."""
        delivery = FakeDelivery(signed_event(key_version=1))
        await dispatch(delivery, self._never_called)
        assert delivery.nacked == 1

    @pytest.mark.parametrize("direction", [1, -1])
    async def test_nacks_a_stale_event_in_either_direction(self, direction: int) -> None:
        """A future timestamp is the shape of a captured message held for later."""
        drift = timedelta(seconds=REACTOR_FRESHNESS_SKEW_SECONDS + 30) * direction
        delivery = FakeDelivery(signed_event(issued_at=datetime.now(timezone.utc) - drift))
        await dispatch(delivery, self._never_called)
        assert delivery.nacked == 1

    async def test_nacks_a_replayed_nonce_the_second_time(self) -> None:
        """One store shared across the consumer, or dedup does nothing."""
        ctx = context()
        raw = signed_event()
        calls = 0

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Count and allow."""
            nonlocal calls
            calls += 1
            return allow()

        first = FakeDelivery(raw)
        await dispatch(first, handler, ctx=ctx)
        second = FakeDelivery(raw)
        transport = await dispatch(second, handler, ctx=ctx)

        assert calls == 1
        assert second.nacked == 1
        assert transport.published == []

    async def test_nacks_an_event_naming_another_tenant(self) -> None:
        """A reactor answering for a tenant it was not configured as is the
        confusion §22.1 refuses to allow."""
        # Signed correctly, but for a different tenant — the queue and the
        # subkey are both per-tenant, so this can only be a misconfiguration.
        delivery = FakeDelivery(signed_event(tenant_id="33333333-3333-3333-3333-333333333333"))
        await dispatch(delivery, self._never_called)
        assert delivery.nacked == 1

    @pytest.mark.parametrize("raw", [b"{not json", b"[1,2,3]", b'"a string"', b"42", b"null"])
    async def test_nacks_a_body_that_is_not_a_reactor_event_object(self, raw: bytes) -> None:
        """Undecodable, or decodable but not an object: both are malformed."""
        delivery = FakeDelivery(raw)
        transport = await dispatch(delivery, self._never_called)
        assert delivery.nacked == 1
        assert transport.published == []

    async def test_nacks_a_signed_body_whose_fields_are_the_wrong_shape(self) -> None:
        """A signature attests to who wrote the bytes, not to what they mean.

        These bodies really were signed with the tenant subkey, and the runtime
        still refuses them — the one class of rejection a valid MAC cannot
        rescue.
        """
        import hashlib
        import hmac as hmac_mod

        for override in (
            {"timeout_ms": "500"},
            {"payload": [1, 2, 3]},
            {"payload": None},
            {"tenant_id": 7},
            {"nonce": 7},
            {"issued_at": 7},
            {"correlation_id": 7},
            {"event": 7},
            {"key_version": "2"},
            {"key_version": True},
            {"issued_at": "not a timestamp"},
        ):
            body: dict[str, Any] = {
                "tenant_id": TENANT,
                "event": LOGIN_POST_AUTH,
                "correlation_id": str(uuid.uuid4()),
                "payload": {"sub": "alice"},
                "timeout_ms": 5_000,
                "key_version": 2,
                "nonce": str(uuid.uuid4()),
                "issued_at": to_chrono_rfc3339(datetime.now(timezone.utc)),
                "hmac_signature": None,
                **override,
            }
            signature = hmac_mod.new(SUBKEY, _canonical_json(body), hashlib.sha256).hexdigest()
            delivery = FakeDelivery(_canonical_json({**body, "hmac_signature": signature}))
            await dispatch(delivery, self._never_called)
            assert delivery.nacked == 1, override


class TestSigningKeyNeverLogged:
    """§22.12 — the key is a credential and appears in no log line."""

    async def test_survives_every_logging_path_this_runtime_has(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Drive every refusal, then scan the serialized output for the key."""
        logger = logging.getLogger("test.reactor.leak")
        ctx = context(logger=logger)

        async def boom(event: ReactorEvent) -> ReactorDecision:
            """Fail."""
            raise RuntimeError("boom")

        async def step_up(event: ReactorEvent) -> ReactorDecision:
            """Demand step-up where it is not supported."""
            return require_step_up()

        async def ok(event: ReactorEvent) -> ReactorDecision:
            """Allow."""
            return allow()

        with caplog.at_level(logging.DEBUG, logger="test.reactor.leak"):
            bad = json.loads(signed_event())
            bad["hmac_signature"] = "11" * 32
            await dispatch(FakeDelivery(_canonical_json(bad)), ok, ctx=ctx)

            replayed = signed_event()
            await dispatch(FakeDelivery(replayed), ok, ctx=ctx)
            await dispatch(FakeDelivery(replayed), ok, ctx=ctx)

            await dispatch(FakeDelivery(signed_event()), boom, ctx=ctx)
            await dispatch(FakeDelivery(signed_event(event=TOKEN_PRE_ISSUE)), step_up, ctx=ctx)
            await dispatch(FakeDelivery(signed_event(), reply_to=None), ok, ctx=ctx)
            await dispatch(FakeDelivery(signed_event(timeout_ms=5)), _slow, ctx=ctx)

        assert caplog.records, "these paths must log something"
        rendered = "\n".join(record.getMessage() for record in caplog.records)
        assert SUBKEY.hex() not in rendered
        assert repr(SUBKEY) not in rendered
        assert str(list(SUBKEY)) not in rendered

    def test_fingerprints_the_key_without_printing_it(self) -> None:
        """Eight hex characters: enough to tell two keys apart, far too little
        to attack."""
        print_ = signing_key_fingerprint(SUBKEY)
        assert len(print_) == 8
        assert print_ == signing_key_fingerprint(SUBKEY)
        assert print_ not in SUBKEY.hex()
        assert signing_key_fingerprint(b"another key") != print_


async def _slow(event: ReactorEvent) -> ReactorDecision:
    """A handler that always outruns a short window."""
    await asyncio.sleep(0.2)
    return allow()


def _dispatcher(sink: list[TelemetryEvent]) -> Any:
    """Build a §19 dispatcher appending every event to ``sink``."""
    from axiam_sdk._telemetry import TelemetryDispatcher

    return TelemetryDispatcher(sink.append)


class TestTelemetry:
    """§19 — one pair per dispatch, with a label from the registry."""

    async def test_emits_request_start_and_end_with_a_bounded_label(self) -> None:
        """The path template is the registry event name, never a correlation id."""
        events: list[TelemetryEvent] = []

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Allow."""
            return allow()

        await dispatch(
            FakeDelivery(signed_event(event=TOKEN_PRE_ISSUE)),
            handler,
            ctx=context(telemetry=_dispatcher(events)),
        )

        assert [type(event).__name__ for event in events] == ["RequestStart", "RequestEnd"]
        assert events[0].path_template == "token.pre_issue"  # type: ignore[union-attr]
        assert events[0].method == "AMQP"  # type: ignore[union-attr]
        assert events[1].outcome == "success"  # type: ignore[union-attr]
        assert events[1].status is None  # type: ignore[union-attr]

    async def test_reports_failure_when_no_reply_was_produced(self) -> None:
        """A fail_open timeout produces ``allow`` AND an audit record; health
        MUST NOT be inferred from the outcome alone (§22.8)."""
        events: list[TelemetryEvent] = []

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Fail."""
            raise ValueError("nope")

        await dispatch(
            FakeDelivery(signed_event(event=USER_PRE_CREATE)),
            handler,
            ctx=context(telemetry=_dispatcher(events)),
        )
        assert events[1].outcome == "failure"  # type: ignore[union-attr]
        assert events[1].path_template == "user.pre_create"  # type: ignore[union-attr]


class TestReactorConfig:
    """Configuration that cannot produce a verifiable reactor is refused."""

    def test_derives_the_server_declared_queue_from_the_reactor_id(self) -> None:
        """The one queue this process may consume (§22.1)."""
        config = ReactorConfig(tenant_id=TENANT, reactor_id=REACTOR_ID, signing_key=SUBKEY)
        assert config.resolved_queue() == reactor_queue_name(TENANT, REACTOR_ID)

    def test_honours_an_explicit_queue_override(self) -> None:
        """Still only ever the queue the server declared for THIS reactor."""
        config = ReactorConfig(
            tenant_id=TENANT, reactor_id="", signing_key=SUBKEY, queue="axiam.reactor.q.x.y"
        )
        assert config.resolved_queue() == "axiam.reactor.q.x.y"

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"tenant_id": ""}, "tenant_id"),
            ({"reactor_id": ""}, "reactor_id"),
            ({"signing_key": b""}, "signing_key"),
            ({"mode": "observe"}, "mode"),
        ],
    )
    def test_refuses_an_unusable_configuration(self, kwargs: dict[str, Any], message: str) -> None:
        """Each of the four ways to be unconfigurable raises at construction."""
        base: dict[str, Any] = {
            "tenant_id": TENANT,
            "reactor_id": REACTOR_ID,
            "signing_key": SUBKEY,
        }
        base.update(kwargs)
        with pytest.raises(ValueError, match=message):
            ReactorConfig(**base)


class TestReactorServe:
    """§22.1 and §18 — the two claims that need the whole runtime."""

    async def test_consumes_the_server_declared_queue_and_declares_nothing(self) -> None:
        """Asserted against the AMQP client's declare calls, as §22.13 words it."""
        transport = FakeTransport([FakeDelivery(signed_event())])

        async def dial() -> FakeTransport:
            """Hand out the one prepared session."""
            return transport

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Allow."""
            return allow()

        task = asyncio.create_task(
            reactor_serve(
                dial,  # type: ignore[arg-type]
                ReactorConfig(tenant_id=TENANT, reactor_id=REACTOR_ID, signing_key=SUBKEY),
                handler,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert transport.consumed_queue == reactor_queue_name(TENANT, REACTOR_ID)
        assert transport.declare_calls == []
        assert len(transport.published) == 1
        assert transport.closed >= 1

    async def test_drains_the_in_flight_event_on_shutdown(self) -> None:
        """§18: shutdown drains rather than truncates."""
        started = asyncio.Event()
        transport = FakeTransport([FakeDelivery(signed_event())])
        transport.hold = asyncio.Event()

        async def dial() -> FakeTransport:
            """Hand out the one prepared session."""
            return transport

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Still working when the shutdown arrives."""
            started.set()
            await asyncio.sleep(0.05)
            return allow()

        task = asyncio.create_task(
            reactor_serve(
                dial,  # type: ignore[arg-type]
                ReactorConfig(tenant_id=TENANT, reactor_id=REACTOR_ID, signing_key=SUBKEY),
                handler,
            )
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert len(transport.published) == 1, "the in-flight event must be answered"
        assert transport.closed >= 1

    async def test_reconnects_after_a_session_ends_or_fails(self) -> None:
        """A transport failure is never fatal — it is a reconnect (§16-shaped)."""
        attempts = 0

        async def dial() -> FakeTransport:
            """Fail once, then hand out a session that ends immediately."""
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ConnectionRefusedError("broker down")
            return FakeTransport()

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Allow."""
            return allow()

        task = asyncio.create_task(
            reactor_serve(
                dial,  # type: ignore[arg-type]
                ReactorConfig(
                    tenant_id=TENANT,
                    reactor_id=REACTOR_ID,
                    signing_key=SUBKEY,
                    logger=logging.getLogger("test.reactor.reconnect"),
                ),
                handler,
            )
        )
        # The first reconnect waits up to 200 ms of full jitter, so poll rather
        # than guess a sleep long enough to have covered it.
        for _ in range(200):
            if attempts >= 2:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert attempts >= 2

    async def test_does_not_log_the_broker_url_when_a_session_drops(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An AMQP dial error embeds the URL, and an AMQP URL carries credentials."""

        async def dial() -> FakeTransport:
            """Fail with an error whose text carries a password."""
            raise ConnectionRefusedError("amqps://reactor:hunter2@broker.example:5671 refused")

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Allow."""
            return allow()

        logger = logging.getLogger("test.reactor.redaction")
        with caplog.at_level(logging.DEBUG, logger="test.reactor.redaction"):
            task = asyncio.create_task(
                reactor_serve(
                    dial,  # type: ignore[arg-type]
                    ReactorConfig(
                        tenant_id=TENANT,
                        reactor_id=REACTOR_ID,
                        signing_key=SUBKEY,
                        logger=logger,
                    ),
                    handler,
                )
            )
            await asyncio.sleep(0.02)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        rendered = "\n".join(record.getMessage() for record in caplog.records)
        assert rendered, "a dropped session must be reported"
        assert "hunter2" not in rendered
        assert "ConnectionRefusedError" in rendered

    async def test_shares_one_nonce_store_across_the_whole_consumer(self) -> None:
        """A fresh store per delivery would defeat replay dedup entirely."""
        raw = signed_event()
        transport = FakeTransport([FakeDelivery(raw), FakeDelivery(raw)])
        calls = 0

        async def dial() -> FakeTransport:
            """Hand out the one prepared session."""
            return transport

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Count and allow."""
            nonlocal calls
            calls += 1
            return allow()

        task = asyncio.create_task(
            reactor_serve(
                dial,  # type: ignore[arg-type]
                ReactorConfig(tenant_id=TENANT, reactor_id=REACTOR_ID, signing_key=SUBKEY),
                handler,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert calls == 1, "the second delivery is a replay"
        assert len(transport.published) == 1

    async def test_accepts_an_injected_nonce_store_and_telemetry_hook(self) -> None:
        """Both are injectable so an operator can share or observe them."""
        events: list[TelemetryEvent] = []
        store = NonceStore(ttl_seconds=600)
        transport = FakeTransport([FakeDelivery(signed_event())])

        async def dial() -> FakeTransport:
            """Hand out the one prepared session."""
            return transport

        async def handler(event: ReactorEvent) -> ReactorDecision:
            """Allow."""
            return allow()

        task = asyncio.create_task(
            reactor_serve(
                dial,  # type: ignore[arg-type]
                ReactorConfig(
                    tenant_id=TENANT,
                    reactor_id=REACTOR_ID,
                    signing_key=SUBKEY,
                    nonce_store=store,
                    telemetry_hook=events.append,
                ),
                handler,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert len(store) == 1
        assert [type(event).__name__ for event in events] == ["RequestStart", "RequestEnd"]


class TestReconnectBackoff:
    """§16.1's shape, unbounded in attempts."""

    @pytest.mark.parametrize(
        ("attempt", "expected_ceiling"),
        [(0, 0.2), (1, 0.2), (2, 0.4), (3, 0.8), (10, 5.0), (99, 5.0)],
    )
    def test_doubles_and_clamps_at_five_seconds(
        self, attempt: int, expected_ceiling: float
    ) -> None:
        """Full jitter over ``[0, backoff]``: the fraction picks the point."""
        assert _reconnect_delay(attempt, 1.0) == pytest.approx(expected_ceiling)
        assert _reconnect_delay(attempt, 0.0) == 0.0

    @pytest.mark.parametrize("fraction", [-1.0, 2.0])
    def test_clamps_a_jitter_fraction_outside_the_unit_interval(self, fraction: float) -> None:
        """A caller-supplied fraction cannot widen the ceiling or go negative."""
        delay = _reconnect_delay(3, fraction)
        assert 0.0 <= delay <= 0.8


class TestTransportSecurity:
    """§8b — TLS, a CA bundle, and no plaintext fallback."""

    @pytest.mark.parametrize(
        "url",
        [
            "amqp://broker.example.com:5672",
            "AMQP://broker.example.com:5672",
            "http://broker.example.com",
            "",
        ],
    )
    def test_refuses_a_url_that_is_not_amqps(self, url: str) -> None:
        """A failed TLS connection is an error to surface, not one to work
        around — so a plaintext URL is refused at build time, not downgraded."""
        with pytest.raises(InsecureReactorUrlError):
            aio_pika_dialer(url)

    @pytest.mark.parametrize("url", ["amqps://broker.example.com:5671", "AMQPS://b:5671"])
    def test_accepts_an_amqps_url_case_insensitively(self, url: str) -> None:
        """The scheme comparison is on the lowercased URL."""
        assert callable(aio_pika_dialer(url))

    def test_exposes_no_verification_skip_option(self) -> None:
        """§8b rule 4: not under any name, in this SDK's own source tree."""
        import inspect

        from axiam_sdk.amqp import _reactor

        signature = inspect.signature(aio_pika_dialer)
        assert set(signature.parameters) == {"url", "ca_bundle", "prefetch", "heartbeat"}
        source = inspect.getsource(_reactor)
        for banned in ("check_hostname = False", "CERT_NONE", "_create_unverified_context"):
            assert banned not in source
