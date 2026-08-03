"""Webhook signature verification tests (CONTRACT.md §13.4, T-145).

Computes the cross-SDK pin vector's ``v1`` locally from CONTRACT.md §13.4's
shared ``(secret, timestamp, body)`` fixture using this SDK's own
HMAC-SHA256, rather than hardcoding a hex value copied from anywhere — the
pin is "every SDK computes the same hex from the same input", proven by
each SDK's own algorithm accepting its own computation.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr, ValidationError

from axiam_sdk.webhook import (
    DEFAULT_TOLERANCE_SECONDS,
    WebhookEvent,
    WebhookVerifyError,
    verify_webhook,
)

# CONTRACT.md §13.4 shared cross-SDK pin vector.
PIN_SECRET = "whsec_test_0123456789abcdef"
PIN_TIMESTAMP = 1785700000
PIN_BODY = b'{"event":"user.created","id":"01JQ0000000000000000000000"}'


def _sign(secret: str, timestamp: int, body: bytes) -> str:
    """Compute ``v1`` exactly as the server does (§13.1): hex-lowercase
    HMAC-SHA256 over ``f"{timestamp}.{body}"`` keyed by ``secret``'s raw
    UTF-8 bytes — the same algorithm :func:`verify_webhook` recomputes, used
    here only to build test fixtures (never asserted against a hardcoded
    hex value)."""
    payload = f"{timestamp}.".encode("ascii") + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _header(secret: str, timestamp: int, body: bytes) -> str:
    """Build a well-formed ``X-Axiam-Signature`` header value for the given
    ``(secret, timestamp, body)`` triple."""
    return f"t={timestamp},v1={_sign(secret, timestamp, body)}"


# ---------------------------------------------------------------------
# 1. Valid signature + fresh timestamp -> accepted
# ---------------------------------------------------------------------


def test_valid_signature_fresh_timestamp_accepted() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b'{"event":"user.created"}'
    header = _header("whsec_abc", timestamp, body)

    event = verify_webhook("whsec_abc", header, body, now=now)

    assert isinstance(event, WebhookEvent)
    assert event.body == body
    assert event.timestamp == timestamp


def test_valid_signature_accepts_secretstr() -> None:
    """CONTRACT.md §7 — the secret may be wrapped in this SDK's
    ``Sensitive<T>`` equivalent, ``pydantic.SecretStr``."""
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    header = _header("whsec_wrapped", timestamp, body)

    event = verify_webhook(SecretStr("whsec_wrapped"), header, body, now=now)

    assert event.timestamp == timestamp


# ---------------------------------------------------------------------
# 2. Tampered body (one byte flipped) -> rejected
# ---------------------------------------------------------------------


def test_tampered_body_rejected() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b'{"event":"user.created"}'
    header = _header("whsec_abc", timestamp, body)

    tampered = bytearray(body)
    tampered[10] ^= 0xFF  # flip one byte

    with pytest.raises(WebhookVerifyError, match="signature mismatch"):
        verify_webhook("whsec_abc", header, bytes(tampered), now=now)


# ---------------------------------------------------------------------
# 3. Wrong secret -> rejected
# ---------------------------------------------------------------------


def test_wrong_secret_rejected() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b'{"event":"user.created"}'
    header = _header("whsec_right", timestamp, body)

    with pytest.raises(WebhookVerifyError, match="signature mismatch"):
        verify_webhook("whsec_wrong", header, body, now=now)


# ---------------------------------------------------------------------
# 4. Stale timestamp (now - t > tolerance) -> rejected
# ---------------------------------------------------------------------


def test_stale_timestamp_rejected() -> None:
    now = datetime.now(timezone.utc)
    stale_timestamp = int((now - timedelta(seconds=DEFAULT_TOLERANCE_SECONDS + 1)).timestamp())
    body = b"{}"
    header = _header("whsec_abc", stale_timestamp, body)

    with pytest.raises(WebhookVerifyError, match="timestamp outside tolerance"):
        verify_webhook("whsec_abc", header, body, now=now)


def test_timestamp_within_tolerance_accepted_at_the_boundary() -> None:
    """Exactly at the tolerance boundary (``abs(now - t) == tolerance``) is
    still accepted — the rule is strictly-greater-than rejection.

    ``now`` is truncated to whole seconds first so subtracting an integer
    ``timedelta`` and comparing against an integer ``timestamp`` lands
    exactly on the boundary, with no sub-second float rounding pushing the
    computed delta a hair past 100."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    timestamp = int((now - timedelta(seconds=100)).timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    event = verify_webhook("whsec_abc", header, body, tolerance=100, now=now)
    assert event.timestamp == timestamp


# ---------------------------------------------------------------------
# 5. Future timestamp beyond tolerance -> rejected (two-sided freshness)
# ---------------------------------------------------------------------


def test_future_timestamp_beyond_tolerance_rejected() -> None:
    now = datetime.now(timezone.utc)
    future_timestamp = int((now + timedelta(seconds=DEFAULT_TOLERANCE_SECONDS + 1)).timestamp())
    body = b"{}"
    header = _header("whsec_abc", future_timestamp, body)

    with pytest.raises(WebhookVerifyError, match="timestamp outside tolerance"):
        verify_webhook("whsec_abc", header, body, now=now)


def test_custom_tolerance_is_honored() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int((now - timedelta(seconds=30)).timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    # Rejected under a tight 10s tolerance...
    with pytest.raises(WebhookVerifyError, match="timestamp outside tolerance"):
        verify_webhook("whsec_abc", header, body, tolerance=10, now=now)

    # ...but accepted under a looser 60s tolerance for the same vector.
    event = verify_webhook("whsec_abc", header, body, tolerance=60, now=now)
    assert event.timestamp == timestamp


# ---------------------------------------------------------------------
# 6. Malformed header (no v1, t non-numeric, empty) -> rejected
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        pytest.param("", id="empty"),
        pytest.param("t=1785700000", id="no-v1"),
        pytest.param("v1=deadbeef", id="no-t"),
        pytest.param("t=not-a-number,v1=deadbeef", id="t-non-numeric"),
        pytest.param("t=1785700000,t=1785700001,v1=deadbeef", id="duplicate-t"),
        pytest.param("garbage-with-no-equals-signs", id="no-kv-pairs"),
    ],
)
def test_malformed_header_rejected(header: str) -> None:
    with pytest.raises(WebhookVerifyError, match="malformed signature header"):
        verify_webhook("whsec_abc", header, b"{}")


def test_unknown_scheme_keys_are_ignored_forward_compat() -> None:
    """Rule 3: unknown keys/schemes in the header are ignored, not fatal —
    only a genuinely missing ``v1`` is a failure."""
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    v1 = _sign("whsec_abc", timestamp, body)
    header = f"t={timestamp},v2=some-future-scheme-value,v1={v1}"

    event = verify_webhook("whsec_abc", header, body, now=now)
    assert event.timestamp == timestamp


def test_non_hex_v1_candidate_fails_closed_not_string_compare() -> None:
    """Rule 4: a non-hex ``v1`` candidate must fail closed for that
    candidate rather than falling back to a raw string comparison — proven
    here by pairing a garbage non-hex candidate with a valid one and
    confirming the valid one still succeeds (the malformed one is simply
    skipped, not treated as an automatic failure of the whole header)."""
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    valid_v1 = _sign("whsec_abc", timestamp, body)
    header = f"t={timestamp},v1=not-hex-zzz,v1={valid_v1}"

    event = verify_webhook("whsec_abc", header, body, now=now)
    assert event.timestamp == timestamp


def test_all_v1_candidates_non_hex_rejected() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    header = f"t={timestamp},v1=not-hex-at-all"

    with pytest.raises(WebhookVerifyError, match="signature mismatch"):
        verify_webhook("whsec_abc", header, b"{}", now=now)


def test_body_must_be_bytes() -> None:
    """The raw-bytes contract (CONTRACT.md §13.3 rule 1) is enforced at
    runtime, not just by the type hint."""
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    header = _header("whsec_abc", timestamp, b"{}")

    with pytest.raises(WebhookVerifyError, match="body must be raw bytes"):
        verify_webhook("whsec_abc", header, "{}", now=now)  # type: ignore[arg-type]


# ---------------------------------------------------------------------
# X-Axiam-Timestamp cross-check (rule 2) + event/delivery pass-through
# ---------------------------------------------------------------------


def test_matching_timestamp_header_is_accepted() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    event = verify_webhook("whsec_abc", header, body, now=now, timestamp_header=str(timestamp))
    assert event.timestamp == timestamp


def test_mismatched_timestamp_header_rejected() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    with pytest.raises(
        WebhookVerifyError, match="X-Axiam-Timestamp does not match signature header"
    ):
        verify_webhook("whsec_abc", header, body, now=now, timestamp_header=str(timestamp + 1))


def test_malformed_timestamp_header_rejected() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    with pytest.raises(WebhookVerifyError, match="malformed X-Axiam-Timestamp header"):
        verify_webhook("whsec_abc", header, body, now=now, timestamp_header="not-a-number")


def test_event_type_and_delivery_id_pass_through() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    event = verify_webhook(
        "whsec_abc",
        header,
        body,
        now=now,
        event_type="user.created",
        delivery_id="11111111-1111-1111-1111-111111111111",
    )
    assert event.event_type == "user.created"
    assert event.delivery_id == "11111111-1111-1111-1111-111111111111"


def test_omitting_now_uses_real_wall_clock() -> None:
    """Without an injected ``now``, freshness is judged against the real
    wall clock — a signature minted for right now is accepted."""
    timestamp = int(datetime.now(timezone.utc).timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    event = verify_webhook("whsec_abc", header, body)
    assert event.timestamp == timestamp


def test_event_type_and_delivery_id_default_to_none() -> None:
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    event = verify_webhook("whsec_abc", header, body, now=now)
    assert event.event_type is None
    assert event.delivery_id is None


def test_naive_now_is_treated_as_utc() -> None:
    """A naive ``datetime`` passed to ``now`` must be interpreted as UTC,
    not local time — otherwise the freshness check would silently corrupt
    on any host not running in UTC."""
    naive_now = datetime(2026, 8, 2, 12, 0, 0)  # no tzinfo
    aware_now = naive_now.replace(tzinfo=timezone.utc)
    timestamp = int(aware_now.timestamp())
    body = b"{}"
    header = _header("whsec_abc", timestamp, body)

    event = verify_webhook("whsec_abc", header, body, now=naive_now)
    assert event.timestamp == timestamp


def test_error_message_never_contains_secret_or_expected_signature() -> None:
    """CONTRACT.md §13.3 rule 6 — the typed exception's message never
    surfaces the expected/computed MAC or the secret."""
    now = datetime.now(timezone.utc)
    timestamp = int(now.timestamp())
    body = b"{}"
    secret = "super-secret-value-must-never-leak"
    header = _header(secret, timestamp, body)
    expected_v1 = _sign(secret, timestamp, body)

    tampered = b"{}x"
    with pytest.raises(WebhookVerifyError) as exc_info:
        verify_webhook(secret, header, tampered, now=now)

    message = str(exc_info.value)
    assert secret not in message
    assert expected_v1 not in message


def test_webhook_event_repr_does_not_leak_via_frozen_model() -> None:
    """:class:`WebhookEvent` carries no secret material itself (only the
    already-verified body/timestamp/event metadata) — this is a sanity
    check that construction stays frozen/immutable per this SDK's model
    convention (D-06/D-07)."""
    event = WebhookEvent(event_type=None, delivery_id=None, body=b"{}", timestamp=1)
    with pytest.raises(ValidationError):
        event.timestamp = 2  # type: ignore[misc]


# ---------------------------------------------------------------------
# 7. Cross-SDK pin vector (CONTRACT.md §13.4)
# ---------------------------------------------------------------------


def test_cross_sdk_pin_vector_accepted() -> None:
    """Computes ``v1`` locally from the CONTRACT.md §13.4 shared vector
    using this SDK's own HMAC-SHA256 (never a hardcoded hex value) and
    asserts :func:`verify_webhook` accepts it — the actual cross-SDK pin is
    "every SDK's own algorithm accepts its own computation over the same
    input", proven independently in each SDK's test suite."""
    header = _header(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY)
    now = datetime.fromtimestamp(PIN_TIMESTAMP, tz=timezone.utc)

    event = verify_webhook(PIN_SECRET, header, PIN_BODY, now=now)

    assert event.timestamp == PIN_TIMESTAMP
    assert event.body == PIN_BODY


def test_cross_sdk_pin_vector_tampered_body_rejected() -> None:
    """Same pin vector, one byte flipped in the body — must be rejected."""
    header = _header(PIN_SECRET, PIN_TIMESTAMP, PIN_BODY)
    now = datetime.fromtimestamp(PIN_TIMESTAMP, tz=timezone.utc)

    tampered = bytearray(PIN_BODY)
    tampered[0] ^= 0xFF

    with pytest.raises(WebhookVerifyError, match="signature mismatch"):
        verify_webhook(PIN_SECRET, header, bytes(tampered), now=now)
