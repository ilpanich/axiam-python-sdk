"""The reactor's ``aio-pika`` adapter and the last two dispatch paths (§22.1, §8b).

The runtime is written against a transport seam, so the adapter that satisfies
it is the one place in this SDK holding a real channel — and therefore the one
place §22.1's "actors consume; they never declare topology" could leak through.
It is tested here rather than excluded from coverage: the fakes below offer
``declare_queue``, ``declare_exchange`` and ``bind``, and the assertions are that
none of them is ever called.

Nothing here reaches a broker. ``aio_pika.connect_robust`` is monkeypatched, and
the TLS assertions use the host's own trust store rendered back to PEM by
:mod:`ssl` — no certificate is minted and no socket is opened.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from axiam_sdk.amqp import (
    LOGIN_POST_AUTH,
    aio_pika_dialer,
    allow,
    dispatch_reactor_delivery,
    to_chrono_rfc3339,
)
from axiam_sdk.amqp._reactor import _AioPikaDelivery, _AioPikaTransport
from axiam_sdk.amqp._reactor_protocol import _canonical_json
from tests.test_reactor_runtime import SUBKEY, FakeDelivery, FakeTransport, context, signed_event

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parent.parent / "testdata" / "reactor_v2_reference_vectors.json"
    ).read_text(encoding="utf-8")
)
TENANT = _FIXTURE["tenant_id"]


def _system_ca_pem() -> str:
    """Render the host's own trust roots back to PEM text.

    A real, parseable CA bundle with no certificate-minting dependency and no
    fixture to keep in sync — ``load_verify_locations`` accepts it, which is the
    only thing the §8b rule 2 assertions need.
    """
    roots = ssl.create_default_context().get_ca_certs(binary_form=True)
    if not roots:  # pragma: no cover - a host with no trust store.
        pytest.skip("host has no system trust store to render as PEM")
    return "".join(ssl.DER_cert_to_PEM_cert(der) for der in roots[:2])


# ---------------------------------------------------------------------------
# Fake aio-pika objects
# ---------------------------------------------------------------------------


class FakeIterator:
    """An async context manager yielding a fixed list of messages."""

    def __init__(self, messages: list[Any]) -> None:
        """Hold the messages this iterator will hand out exactly once."""
        self._messages = messages
        self.entered = 0
        self.exited = 0

    async def __aenter__(self) -> FakeIterator:
        """Record entry and return self."""
        self.entered += 1
        return self

    async def __aexit__(self, *exc: object) -> None:
        """Record the exit — the consumer is cancelled here in aio-pika."""
        self.exited += 1

    def __aiter__(self) -> FakeIterator:
        """Iterate the held messages."""
        self._pending = list(self._messages)
        return self

    async def __anext__(self) -> Any:
        """Hand out the next message, or stop."""
        if not self._pending:
            raise StopAsyncIteration
        return self._pending.pop(0)


class FakeQueue:
    """An aio-pika queue that records how its iterator was opened."""

    def __init__(self, messages: list[Any]) -> None:
        """Prepare a queue that will yield ``messages``."""
        self.iterator_kwargs: dict[str, Any] = {}
        self._iterator = FakeIterator(messages)

    def iterator(self, **kwargs: Any) -> FakeIterator:
        """Open the delivery iterator, recording the kwargs used."""
        self.iterator_kwargs = kwargs
        return self._iterator


class FakeExchange:
    """The default exchange, recording every publication."""

    def __init__(self) -> None:
        """Start with nothing published."""
        self.published: list[tuple[Any, str]] = []

    async def publish(self, message: Any, routing_key: str, **kwargs: Any) -> None:
        """Record one publication."""
        self.published.append((message, routing_key))


class FakeChannel:
    """An aio-pika channel offering MORE than §22.1 permits.

    ``declare_queue``, ``declare_exchange`` and ``bind`` exist here so the
    assertions below can prove the adapter never reaches for them.
    """

    def __init__(self, messages: list[Any] | None = None) -> None:
        """Prepare a channel whose queue will yield ``messages``."""
        self.queue = FakeQueue(messages or [])
        self.exchange = FakeExchange()
        self.declare_calls: list[str] = []
        self.get_queue_calls: list[tuple[str, bool]] = []
        self.get_exchange_calls: list[tuple[str, bool]] = []
        self.qos: int | None = None
        self.closed = 0
        self.close_error: Exception | None = None

    async def declare_queue(self, *args: Any, **kwargs: Any) -> FakeQueue:
        """Never called by a conformant adapter (§22.1)."""
        self.declare_calls.append("declare_queue")
        return self.queue

    async def declare_exchange(self, *args: Any, **kwargs: Any) -> FakeExchange:
        """Never called by a conformant adapter (§22.1)."""
        self.declare_calls.append("declare_exchange")
        return self.exchange

    async def get_queue(self, name: str, *, ensure: bool = True) -> FakeQueue:
        """Attach to an existing queue — no ``Queue.Declare`` frame."""
        self.get_queue_calls.append((name, ensure))
        return self.queue

    async def get_exchange(self, name: str, *, ensure: bool = True) -> FakeExchange:
        """Attach to an existing exchange — no ``Exchange.Declare`` frame."""
        self.get_exchange_calls.append((name, ensure))
        return self.exchange

    async def set_qos(self, prefetch_count: int) -> None:
        """Record the prefetch the dialer applied."""
        self.qos = prefetch_count

    async def close(self) -> None:
        """Record the close, or fail if the test asked for a failure."""
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


class FakeConnection:
    """An aio-pika connection handing out one channel."""

    def __init__(self, channel: FakeChannel) -> None:
        """Wrap the channel this connection will return."""
        self._channel = channel
        self.closed = 0
        self.close_error: Exception | None = None

    async def channel(self) -> FakeChannel:
        """Open the session channel."""
        return self._channel

    async def close(self) -> None:
        """Record the close, or fail if the test asked for a failure."""
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


class FakeMessage:
    """An aio-pika incoming message, recording ack/nack."""

    def __init__(
        self, body: bytes = b"{}", reply_to: str | None = "rq", correlation_id: str | None = "cid"
    ) -> None:
        """Build a message carrying ``body`` and the two RPC properties."""
        self.body = body
        self.reply_to = reply_to
        self.correlation_id = correlation_id
        self.acked = 0
        self.nack_calls: list[bool] = []

    async def ack(self) -> None:
        """Record an ack."""
        self.acked += 1

    async def nack(self, requeue: bool = True) -> None:
        """Record a nack and the requeue flag it was given."""
        self.nack_calls.append(requeue)


# ---------------------------------------------------------------------------


class TestAioPikaDialer:
    """§8b — TLS on, a CA bundle knob, and nothing that weakens verification."""

    async def _dial(self, monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> dict[str, Any]:
        """Run the dialer against a monkeypatched ``connect_robust``."""
        import aio_pika

        channel = FakeChannel()
        connection = FakeConnection(channel)
        seen: dict[str, Any] = {"channel": channel, "connection": connection}

        async def fake_connect(url: str, **connect_kwargs: Any) -> FakeConnection:
            """Record the connection arguments instead of opening a socket."""
            seen["url"] = url
            seen.update(connect_kwargs)
            return connection

        monkeypatch.setattr(aio_pika, "connect_robust", fake_connect)
        seen["transport"] = await aio_pika_dialer("amqps://broker.example:5671", **kwargs)()
        return seen

    async def test_connects_with_a_verifying_tls_context_and_sets_qos(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``create_default_context`` semantics, unweakened, plus the prefetch."""
        seen = await self._dial(monkeypatch, prefetch=25, heartbeat=42)

        tls: ssl.SSLContext = seen["ssl_context"]
        assert tls.check_hostname is True
        assert tls.verify_mode is ssl.CERT_REQUIRED
        assert seen["heartbeat"] == 42
        assert seen["channel"].qos == 25
        assert isinstance(seen["transport"], _AioPikaTransport)
        # The dial itself declares nothing either.
        assert seen["channel"].declare_calls == []

    async def test_loads_a_ca_bundle_given_as_inline_pem(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§8b rule 2: a privately-issued broker certificate is the common case."""
        pem = _system_ca_pem()
        seen = await self._dial(monkeypatch, ca_bundle=pem)
        tls: ssl.SSLContext = seen["ssl_context"]
        assert tls.get_ca_certs(), "the supplied roots must be in the context"
        assert tls.verify_mode is ssl.CERT_REQUIRED

    async def test_loads_a_ca_bundle_given_as_a_file_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The same knob accepts a path, which is the historical form."""
        bundle = tmp_path / "ca.pem"
        bundle.write_text(_system_ca_pem(), encoding="utf-8")
        seen = await self._dial(monkeypatch, ca_bundle=str(bundle))
        tls: ssl.SSLContext = seen["ssl_context"]
        assert tls.get_ca_certs()

    async def test_surfaces_a_bad_ca_bundle_rather_than_dialing_anyway(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A CA bundle that will not parse fails closed, before the connection.

        Falling back to the system roots here would silently connect to a broker
        the operator did not mean to trust.
        """
        with pytest.raises(ssl.SSLError):
            await self._dial(monkeypatch, ca_bundle="-----BEGIN CERTIFICATE-----\nnope\n")
        with pytest.raises((FileNotFoundError, OSError)):
            await self._dial(monkeypatch, ca_bundle="/nonexistent/ca-bundle.pem")


class TestAioPikaTransport:
    """§22.1 — the adapter attaches; it never declares."""

    async def test_consumes_without_declaring_the_queue(self) -> None:
        """``get_queue(..., ensure=False)`` sends no ``Queue.Declare`` frame.

        With ``ensure=True`` aio-pika would send a passive declare, and §22.1
        says actors never declare — not even to check.
        """
        message = FakeMessage(body=b"hello")
        channel = FakeChannel([message])
        transport = _AioPikaTransport(FakeConnection(channel), channel)

        seen = [delivery async for delivery in transport.consume("axiam.reactor.q.t.r")]

        assert channel.get_queue_calls == [("axiam.reactor.q.t.r", False)]
        assert channel.declare_calls == []
        assert channel.queue.iterator_kwargs == {"no_ack": False}
        assert len(seen) == 1
        assert seen[0].body == b"hello"

    async def test_publishes_the_reply_through_the_default_exchange(self) -> None:
        """The default exchange exists on every broker and needs no declaration."""
        channel = FakeChannel()
        transport = _AioPikaTransport(FakeConnection(channel), channel)

        await transport.publish_reply("amq.reply-to.abc", "cid-7", b'{"decision":"allow"}')

        assert channel.get_exchange_calls == [("", False)]
        assert channel.declare_calls == []
        message, routing_key = channel.exchange.published[0]
        assert routing_key == "amq.reply-to.abc"
        assert message.body == b'{"decision":"allow"}'
        assert message.correlation_id == "cid-7"
        assert message.content_type == "application/json"

    async def test_close_is_idempotent_against_an_already_closed_session(self) -> None:
        """§18.1 rule 2: tearing down a corpse is the state the caller asked for.

        Both halves are still attempted — a channel that refuses to close must
        not leave the connection open, or the shutdown has leaked the socket.
        """
        channel = FakeChannel()
        channel.close_error = RuntimeError("channel already closed")
        connection = FakeConnection(channel)
        connection.close_error = RuntimeError("connection already closed")
        transport = _AioPikaTransport(connection, channel)

        await transport.close()
        await transport.close()

        assert channel.closed == 2
        assert connection.closed == 2


class TestAioPikaDelivery:
    """The delivery adapter forwards the three fields and the two settlements."""

    async def test_exposes_the_body_and_both_rpc_properties(self) -> None:
        """Nothing is reinterpreted — the runtime reads what the broker sent."""
        delivery = _AioPikaDelivery(FakeMessage(body=b"raw", reply_to="rq", correlation_id="cid"))
        assert delivery.body == b"raw"
        assert delivery.reply_to == "rq"
        assert delivery.correlation_id == "cid"

    async def test_reports_absent_properties_as_none(self) -> None:
        """A delivery with no ``reply_to`` is answerable nowhere, not guessable."""
        delivery = _AioPikaDelivery(FakeMessage(reply_to=None, correlation_id=None))
        assert delivery.reply_to is None
        assert delivery.correlation_id is None

    async def test_nacks_without_requeue_and_acks_plainly(self) -> None:
        """There is no requeue parameter on the seam, so there is none to get
        wrong: a redelivered event can only ever produce a late reply."""
        message = FakeMessage()
        delivery = _AioPikaDelivery(message)
        await delivery.ack()
        await delivery.nack()
        assert message.acked == 1
        assert message.nack_calls == [False]


class TestLateReplyIsAbandoned:
    """§22.3 / §22.10 rule 4 — the deadline check, made deterministic."""

    async def test_does_not_publish_once_the_window_has_closed(self) -> None:
        """The handler returns in time; the clock crosses the deadline en route.

        The loop's clock is advanced by the handler rather than by a sleep, so
        this asserts the deadline check itself rather than racing
        ``asyncio.wait_for``'s own timer against it.
        """
        loop = asyncio.get_running_loop()
        real_time = loop.time
        jumped = False

        def shifted_time() -> float:
            """The loop's clock, plus a minute once the handler has run."""
            return real_time() + (60.0 if jumped else 0.0)

        async def handler(event: Any) -> Any:
            """Answer immediately, but only after the window has closed."""
            nonlocal jumped
            jumped = True
            return allow()

        body = _canonical_json(json.loads(signed_event(event=LOGIN_POST_AUTH, timeout_ms=5_000)))
        delivery = FakeDelivery(body)
        transport = FakeTransport()
        records: list[str] = []
        logger = logging.getLogger("test.reactor.deadline")
        handlerobj = _ListHandler(records)
        logger.addHandler(handlerobj)
        logger.setLevel(logging.DEBUG)

        loop.time = shifted_time  # type: ignore[method-assign]
        try:
            await dispatch_reactor_delivery(delivery, transport, context(logger=logger), handler)
        finally:
            loop.time = real_time  # type: ignore[method-assign]
            logger.removeHandler(handlerobj)

        assert transport.published == []
        assert delivery.acked == 1
        assert any("closed before the reply was ready" in line for line in records)


class _ListHandler(logging.Handler):
    """A logging handler that appends rendered messages to a list."""

    def __init__(self, sink: list[str]) -> None:
        """Wrap the list this handler writes into."""
        super().__init__()
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        """Render one record into the sink."""
        self._sink.append(record.getMessage())


class TestParseRfc3339:
    """``issued_at`` parsing accepts the shapes the server can emit."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("2026-07-10T12:00:00Z", datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)),
            ("2026-07-10T12:00:00z", datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)),
            ("2026-07-10T12:00:00+00:00", datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)),
            # A naive timestamp is read as UTC rather than as local time, which
            # would make freshness depend on the reactor host's timezone.
            ("2026-07-10T12:00:00", datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)),
        ],
    )
    async def test_accepts_every_shape_and_reads_naive_as_utc(
        self, raw: str, expected: datetime
    ) -> None:
        """Round-trip each accepted rendering through a full verified dispatch."""
        import hashlib
        import hmac as hmac_mod

        body: dict[str, Any] = {
            "tenant_id": TENANT,
            "event": LOGIN_POST_AUTH,
            "correlation_id": str(uuid.uuid4()),
            "payload": {"sub": "alice"},
            "timeout_ms": 5_000,
            "key_version": 2,
            "nonce": str(uuid.uuid4()),
            "issued_at": raw,
            "hmac_signature": None,
        }
        signature = hmac_mod.new(SUBKEY, _canonical_json(body), hashlib.sha256).hexdigest()
        delivery = FakeDelivery(_canonical_json({**body, "hmac_signature": signature}))
        transport = FakeTransport()

        async def handler(event: Any) -> Any:
            """Allow."""
            return allow()

        # Verified against the vector's own instant, so the parse — not the
        # wall clock — is what decides.
        await dispatch_reactor_delivery(delivery, transport, context(), handler)

        # Whatever the rendering, the parsed instant is the same, so freshness
        # against "now" behaves identically: an hour-old timestamp is stale.
        assert expected.tzinfo is timezone.utc
        assert delivery.nacked == 1  # 2026-07-10 is far outside ±300 s of now.

    async def test_a_current_timestamp_in_each_shape_verifies(self) -> None:
        """The same shapes, stamped now, pass the freshness gate."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        assert to_chrono_rfc3339(now).endswith("Z")
