"""CONTRACT.md 1.69 §8, as corrected: the vectors' ``wire_json``, the consumer's refusals, the
producer's wire form and the requester's normative discard-reason order."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from axiam_sdk.amqp import AuthzRequester, build_authz_request
from axiam_sdk.amqp._consumer import _on_message
from axiam_sdk.amqp._hmac import cut_trailing_signature, verify_and_decode
from axiam_sdk.amqp._replay import NonceStore

from .test_amqp_authz_requester import (
    VEC_CORRELATION,
    VEC_NONCE,
    VEC_SUBKEY,
    VEC_TENANT,
    VECTORS,
    FakeTransport,
    RecordingDelivery,
    discard_events,
    make_logger,
    offer,
    sign_with,
    vector_requester,
    vector_wire,
)

REFERENCE: dict[str, Any] = json.loads(
    (Path(__file__).parent.parent / "testdata" / "v2_reference_vectors.json").read_text("utf-8")
)
SUBKEY = bytes.fromhex(REFERENCE["hkdf"]["derived_subkey_hex"])
ISSUED = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
KINDS = ["authz_request", "audit_event"]


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


async def _consume(body: bytes, key: bytes = SUBKEY) -> tuple[_Message, list[dict[str, Any]]]:
    handled: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any]) -> None:
        handled.append(event)

    message = _Message(body)
    await _on_message(
        message,
        key,
        handler,
        logging.getLogger("test.contract169"),
        nonce_store=NonceStore(ttl_seconds=600),
        now=ISSUED,
    )
    return message, handled


def _sign(canonical: str) -> bytes:
    mac = hmac.new(SUBKEY, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return (canonical[:-1] + ',"hmac_signature":"' + mac + '"}').encode("utf-8")


def _sign_bytes(canonical: bytes, key: bytes = SUBKEY) -> bytes:
    mac = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return canonical[:-1] + b',"hmac_signature":"' + mac.encode() + b'"}'


# --- 3: the vectors' wire_json -----------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_wire_json_cuts_to_exactly_canonical_signed_json_and_verifies(kind: str) -> None:
    vector = REFERENCE[kind]
    wire = vector["wire_json"].encode("utf-8")
    cut = cut_trailing_signature(wire)
    assert cut is not None
    canonical, signature = cut
    assert canonical == vector["canonical_signed_json"].encode("utf-8")
    assert signature.decode() == vector["hmac_signature_hex"]
    assert verify_and_decode(SUBKEY, wire) == json.loads(canonical)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.asyncio
async def test_wire_json_passes_the_layout_check_and_is_dispatched(kind: str) -> None:
    wire = REFERENCE[kind]["wire_json"].encode("utf-8")
    message, handled = await _consume(wire)
    assert message.acked is True and message.nacked is None
    assert len(handled) == 1 and "hmac_signature" not in handled[0]
    assert handled[0] == json.loads(REFERENCE[kind]["canonical_signed_json"])


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.asyncio
async def test_the_vectors_message_member_is_not_wire_bytes_and_is_refused(kind: str) -> None:
    sorted_object = json.dumps(REFERENCE[kind]["message"], separators=(",", ":")).encode()
    message, handled = await _consume(sorted_object)
    assert handled == [] and message.nacked is False


def _audit_wire() -> str:
    return REFERENCE["audit_event"]["wire_json"]


def _audit_canonical() -> str:
    return REFERENCE["audit_event"]["canonical_signed_json"]


def _negatives() -> dict[str, bytes]:
    canonical = _audit_canonical()
    wire = _audit_wire().encode()
    nested = canonical.replace('"method":"password"', '"method":"a","method":"password"')
    moved = canonical.replace('"nonce":"88888888-8888-8888-8888-888888888888",', "").replace(
        '"key_version":2,', '"nonce":"88888888-8888-8888-8888-888888888888","key_version":2,'
    )
    sig = REFERENCE["audit_event"]["hmac_signature_hex"]
    return {
        "duplicate top-level member, validly signed": _sign(
            canonical.replace('"action":"user.login"', '"action":"x","action":"user.login"')
        ),
        "duplicate nested member, validly signed": _sign(nested),
        "trailing newline after the brace": wire + b"\n",
        "trailing space after the brace": wire + b" ",
        "trailing second object": wire + b"{}",
        "hmac_signature null": canonical[:-1].encode() + b',"hmac_signature":null}',
        "hmac_signature number": canonical[:-1].encode() + b',"hmac_signature":7}',
        "hmac_signature first": ('{"hmac_signature":"' + sig + '",' + canonical[1:]).encode(),
        "no hmac_signature": canonical.encode(),
        "reordered members, signed over the reordering": _sign(moved),
        "case-variant top-level name, validly signed": _sign(
            canonical.replace('"outcome":"Success"', '"Outcome":"x","outcome":"Success"')
        ),
        # U+212A KELVIN SIGN and "k" fold together; so do "ss" and U+00DF.
        "unicode-folded top-level names, validly signed": _sign(
            canonical.replace('"outcome":"Success"', '"outcome":"Success","K":1,"k":2')
        ),
        "validly signed, prefixed with a UTF-8 byte order mark": _sign_bytes(
            b"\xef\xbb\xbf" + canonical.encode()
        ),
        "validly signed, a string value holding the raw bytes of a surrogate": _sign_bytes(
            canonical.encode().replace(b"user.login", b"user.\xed\xa0\x80")
        ),
        "validly signed AuthzResponse": sign_with(SUBKEY, VECTORS[0][1]),
        "validly signed cache invalidation shape": _sign(
            '{"origin_id":"o","tenant_id":"t","key_version":2,"nonce":"n",'
            '"issued_at":"2026-07-10T12:00:00Z"}'
        ),
    }


@pytest.mark.parametrize("name", list(_negatives()))
@pytest.mark.asyncio
async def test_the_event_consumer_nacks_and_never_dispatches(name: str) -> None:
    message, handled = await _consume(_negatives()[name])
    assert handled == [], "the handler must never run"
    assert message.nacked is False and message.acked is False


@pytest.mark.parametrize("name", list(_negatives()))
def test_verify_and_decode_refuses_it(name: str) -> None:
    body = _negatives()[name]
    decoded = verify_and_decode(SUBKEY, body)
    # Byte-valid signed objects: the layout check, not the verifier, refuses them.
    if name in {
        "validly signed AuthzResponse",
        "validly signed cache invalidation shape",
        "reordered members, signed over the reordering",
    }:
        assert decoded is not None
    else:
        assert decoded is None


@pytest.mark.asyncio
async def test_a_genuine_message_with_html_non_ascii_and_u_escapes_verifies_and_is_dispatched() -> (
    None
):
    canonical = (
        _audit_canonical()
        .replace(
            '"action":"user.login"',
            '"action":"a<b>&c é€ \\u0041 \\u0001"',
        )
        .replace('"method":"password"', '"method":"<x>&é \\u0041"')
    )
    message, handled = await _consume(_sign(canonical))
    assert message.acked is True
    assert handled[0]["action"] == "a<b>&c é€ A \x01"
    assert handled[0]["metadata"] == {"method": "<x>&é A"}


# --- 4: the producer's wire form ---------------------------------------------------------------


def test_the_producer_emits_exactly_wire_json_for_the_vector_inputs() -> None:
    reference = REFERENCE["authz_request"]
    message = reference["message"]
    body = build_authz_request(
        SUBKEY,
        correlation_id=message["correlation_id"],
        tenant_id=message["tenant_id"],
        subject_id=message["subject_id"],
        action=message["action"],
        resource_id=message["resource_id"],
        scope=message["scope"],
        nonce=message["nonce"],
        issued_at=ISSUED,
    )
    assert body == reference["wire_json"].encode("utf-8")


# --- 5: the requester's reason order -----------------------------------------------------------


def _bad_signature(wire: bytes) -> bytes:
    return wire.replace(VECTORS[0][2].encode(), b"0" * 64)


def _reason_order_cases() -> list[tuple[str, bytes, str]]:
    v1 = VECTORS[0][1]
    wire1 = vector_wire(0)
    no_nonce = v1.replace(f',"nonce":"{VEC_NONCE}"', "")
    no_tenant = v1.replace(f'"tenant_id":"{VEC_TENANT}",', "")
    no_corr = v1.replace(f'"correlation_id":"{VEC_CORRELATION}",', "")
    return [
        ("not an object beats everything", b"[1]", "malformed"),
        ("trailing newline, no signature at all", v1.encode() + b"\n", "malformed"),
        ("neither signature nor allowed", b'{"correlation_id":"c"}', "unsigned"),
        (
            "unsigned though tenant_id missing",
            no_tenant.replace(',"nonce"', ',"n"').encode(),
            "unsigned",
        ),
        (
            "bad signature and nonce missing is malformed, not signature",
            (no_nonce[:-1] + ',"hmac_signature":"' + "0" * 64 + '"}').encode(),
            "malformed",
        ),
        (
            "bad signature and tenant_id missing is malformed",
            (no_tenant[:-1] + ',"hmac_signature":"' + "0" * 64 + '"}').encode(),
            "malformed",
        ),
        (
            "bad signature and correlation_id missing is malformed",
            (no_corr[:-1] + ',"hmac_signature":"' + "0" * 64 + '"}').encode(),
            "malformed",
        ),
        (
            "bad signature and nonce ill-typed is malformed",
            _bad_signature(wire1).replace(f'"nonce":"{VEC_NONCE}"'.encode(), b'"nonce":5'),
            "malformed",
        ),
        ("well-typed, HMAC fails", _bad_signature(wire1), "signature"),
        (
            "wrong tenant, HMAC valid",
            sign_with(VEC_SUBKEY, v1.replace(VEC_TENANT, "99999999-9999-9999-9999-999999999999")),
            "tenant",
        ),
        (
            "unknown request, HMAC valid",
            sign_with(VEC_SUBKEY, v1.replace(VEC_NONCE, "66666666-6666-6666-6666-666666666666")),
            "unknown_request",
        ),
    ]


@pytest.mark.parametrize(
    ("name", "body", "reason"),
    _reason_order_cases(),
    ids=[c[0] for c in _reason_order_cases()],
)
@pytest.mark.asyncio
async def test_the_requester_reports_the_first_reason_that_applies(
    name: str, body: bytes, reason: str
) -> None:
    logger, log = make_logger()
    requester, future = await vector_requester(logger=logger)
    try:
        decision, delivery = await offer(requester, future, body)
        assert decision is None and delivery.nacked == 1
        events = discard_events(log)
        assert len(events) == 1
        assert events[0].reason == reason  # type: ignore[attr-defined]
    finally:
        await requester.close()


@pytest.mark.asyncio
async def test_after_close_an_answer_is_neither_decoded_nor_dispatched_nor_logged() -> None:
    logger, log = make_logger()
    requester, future = await vector_requester(logger=logger)
    await requester.close()
    delivery = RecordingDelivery(vector_wire(0))
    await requester._handle(delivery)
    assert delivery.nacked == 1 and delivery.acked == 0, "nacked without requeue"
    assert discard_events(log) == [], "no discard event after Close"


@pytest.mark.asyncio
async def test_after_close_the_body_is_not_even_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    requester = await AuthzRequester.open(
        FakeTransport(), tenant_id=VEC_TENANT, signing_key=VEC_SUBKEY
    )
    await requester.close()

    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("decoded after close")

    monkeypatch.setattr("axiam_sdk.amqp._authz_requester.strict_json_object", boom)
    delivery = RecordingDelivery(vector_wire(0))
    await requester._handle(delivery)
    assert delivery.nacked == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: b"\xef\xbb\xbf" + c,
        lambda c: c.replace(b"allowed", b"allow\xed\xa0\x80ed", 1).replace(
            b'"allow\xed\xa0\x80ed":true', b'"allowed":true,"x":"\xed\xa0\x80"'
        ),
    ],
    ids=["byte order mark", "raw surrogate bytes"],
)
@pytest.mark.asyncio
async def test_the_requester_discards_a_validly_signed_body_that_is_not_strict_utf8(
    mutate: Any,
) -> None:
    logger, log = make_logger()
    requester, future = await vector_requester(logger=logger)
    try:
        body = _sign_bytes(mutate(VECTORS[0][1].encode()), VEC_SUBKEY)
        decision, delivery = await offer(requester, future, body)
        assert decision is None and delivery.nacked == 1
        events = discard_events(log)
        assert len(events) == 1 and events[0].reason == "malformed"  # type: ignore[attr-defined]
    finally:
        await requester.close()
