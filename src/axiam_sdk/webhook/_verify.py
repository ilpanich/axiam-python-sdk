"""Webhook signature verification implementation (CONTRACT.md §13, T-145).

Byte-for-byte port of the server's signed-timestamp scheme
(``crates/axiam-api-rest/src/webhook.rs::compute_signature_v2``): the server
signs ``HMAC-SHA256(secret_utf8_bytes, "<timestamp>.<raw_body>")`` and sends
it as ``X-Axiam-Signature: t=<unix_seconds>,v1=<hex_lowercase>``. This module
cannot import the server crate (the SDK MUST NOT depend on server crates), so
the algorithm is reimplemented here and pinned against a self-computed
cross-SDK vector in ``tests/test_webhook_verify.py`` (CONTRACT.md §13.4).

**Raw body only.** ``body`` MUST be the exact, untouched bytes received off
the wire — never a re-serialized/re-encoded copy of a parsed JSON payload,
since key order and whitespace changes break the MAC. In Flask, pass
``request.get_data()`` (NOT ``request.get_json()`` re-dumped); in FastAPI,
pass ``await request.body()`` (NOT a re-serialized Pydantic model). See the
README for a full receiver example.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from pydantic import BaseModel, SecretStr

#: Default freshness window, in seconds, enforced by :func:`verify_webhook`
#: (CONTRACT.md §13.2). Two-sided: a timestamp more than this many seconds
#: in the past OR the future is rejected.
DEFAULT_TOLERANCE_SECONDS: float = 300.0


class WebhookVerifyError(Exception):
    """Raised by :func:`verify_webhook` on any verification failure
    (CONTRACT.md §13.3 rule 6 — fail closed and quiet).

    ``str(exc)`` is a short, non-sensitive, stable reason string. It
    NEVER contains the expected/computed signature, the secret, or any
    other value that could help an attacker forge a valid header — only a
    fixed, greppable category of what went wrong (e.g. ``"signature
    mismatch"``, ``"malformed signature header"``, ``"timestamp outside
    tolerance"``). Callers MUST NOT be tempted to log ``str(exc)`` believing
    it is safe to skip further redaction of anything ELSE they attach to the
    same log line (the secret and computed MAC must never be logged by
    caller code either, per CONTRACT.md §13.3 rule 6).
    """

    def __init__(self, reason: str) -> None:
        """Build the exception from a short, non-sensitive ``reason``
        (see the class docstring); ``str(self)`` is exactly
        ``"webhook signature verification failed: <reason>"``."""
        super().__init__(f"webhook signature verification failed: {reason}")
        self.reason = reason


class WebhookEvent(BaseModel):
    """A webhook delivery whose signature has already been verified by
    :func:`verify_webhook` (CONTRACT.md §13.2 rule 6).

    ``event_type``/``delivery_id`` are the caller-supplied ``X-Axiam-Event``/
    ``X-Axiam-Delivery`` header values, passed through unverified (neither
    header is covered by the HMAC — only ``t`` and ``body`` are) — they are
    ``None`` unless the caller passed them into :func:`verify_webhook`.
    ``X-Axiam-Delivery`` is the at-least-once dedup key (CONTRACT.md §13.3
    rule 7): retries replay a validly-signed delivery within the freshness
    window, so a receiver that must not double-process an event should keep
    a short-lived seen-set of ``delivery_id`` values.
    """

    event_type: str | None
    delivery_id: str | None
    body: bytes
    timestamp: int

    model_config = {"frozen": True}


def _secret_bytes(secret: SecretStr | str) -> bytes:
    """Extract the raw UTF-8 HMAC key bytes from ``secret`` (CONTRACT.md §7
    — accepted either as this SDK's ``Sensitive<T>`` equivalent,
    ``pydantic.SecretStr``, or a plain ``str`` for callers that have not
    wrapped it). Never logged; the returned bytes live only as long as this
    call's HMAC computation."""
    if isinstance(secret, SecretStr):
        return secret.get_secret_value().encode("utf-8")
    return secret.encode("utf-8")


def _parse_signature_header(header: str) -> tuple[int, list[str]]:
    """Parse ``X-Axiam-Signature: t=<unix_seconds>,v1=<hex>[,v1=<hex>...]``
    (CONTRACT.md §13.3 rule 3) into ``(timestamp, [v1_hex, ...])``.

    Splits on commas into ``key=value`` pairs. Exactly one ``t`` is
    required; unknown keys are ignored for forward compatibility. At least
    one ``v1`` is required — a header with no ``v1`` at all is a failure,
    never treated as "nothing to check" (rule 3). ``t`` must parse as a
    base-10 integer.

    Raises:
        WebhookVerifyError: if the header is empty, has no ``t``, has a
            duplicate ``t``, has a non-numeric ``t``, or has no ``v1``.
    """
    timestamp_raw: str | None = None
    v1_values: list[str] = []
    for part in header.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "t":
            if timestamp_raw is not None:
                raise WebhookVerifyError("malformed signature header (duplicate t)")
            timestamp_raw = value
        elif key == "v1":
            v1_values.append(value)
        # Unknown keys/schemes are ignored (forward compat, rule 3).

    if timestamp_raw is None:
        raise WebhookVerifyError("malformed signature header (missing t)")
    if not v1_values:
        raise WebhookVerifyError("malformed signature header (missing v1)")
    try:
        timestamp = int(timestamp_raw)
    except ValueError:
        raise WebhookVerifyError("malformed signature header (non-numeric t)") from None
    return timestamp, v1_values


def _reference_epoch(now: datetime | None) -> float:
    """Resolve the freshness reference time to a Unix-epoch float.

    Uses ``now`` (the test-injection seam, CONTRACT.md §13.2) when given —
    a naive ``datetime`` is treated as UTC rather than local time, since a
    silent local-time interpretation would corrupt the freshness check on
    any host not running in UTC. Defaults to the real wall-clock time in UTC
    when ``now`` is ``None``.
    """
    if now is None:
        return datetime.now(timezone.utc).timestamp()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.timestamp()


def verify_webhook(
    secret: SecretStr | str,
    signature_header: str,
    body: bytes,
    *,
    tolerance: float = DEFAULT_TOLERANCE_SECONDS,
    now: datetime | None = None,
    timestamp_header: str | None = None,
    event_type: str | None = None,
    delivery_id: str | None = None,
) -> WebhookEvent:
    """Verify an AXIAM webhook delivery's ``X-Axiam-Signature`` header
    (CONTRACT.md §13).

    Runs the §13.3 algorithm in order: (1) parse ``signature_header`` into
    its ``t``/``v1`` components — a header with no ``v1`` is a failure, not
    "nothing to verify"; (2) recompute ``HMAC-SHA256(secret,
    f"{t}.{body}")``; (3) compare it against every supplied ``v1`` in
    constant time (:func:`hmac.compare_digest`, on DECODED bytes — a
    non-hex ``v1`` fails closed for that candidate rather than falling back
    to a string compare); (4) enforce the two-sided freshness window
    ``abs(now - t) <= tolerance``.

    Args:
        secret: The webhook's plaintext secret, as this SDK's §7
            ``Sensitive<T>`` equivalent (``pydantic.SecretStr``) or a plain
            ``str``. Its raw UTF-8 bytes are the HMAC key.
        signature_header: The raw ``X-Axiam-Signature`` header value, e.g.
            ``"t=1785700000,v1=<hex>"``.
        body: The **exact raw bytes** received off the wire — never a
            re-serialized copy of parsed JSON (see the module docstring).
        tolerance: The freshness window in seconds, applied both to the
            past and the future. Defaults to :data:`DEFAULT_TOLERANCE_SECONDS`
            (300s).
        now: Test-injection seam for the freshness reference time. Defaults
            to the real wall-clock time (UTC) when omitted. A naive
            ``datetime`` is treated as UTC.
        timestamp_header: The raw ``X-Axiam-Timestamp`` header value, if the
            caller also wants it checked. ``X-Axiam-Timestamp`` is redundant
            with (and NOT covered by the MAC the way) the signature header's
            ``t=`` field is — when supplied, it MUST equal the parsed ``t``
            or verification fails (CONTRACT.md §13.3 rule 2).
        event_type: The raw ``X-Axiam-Event`` header value, if the caller
            wants it carried on the returned :class:`WebhookEvent`. Passed
            through unverified — it is not covered by the MAC.
        delivery_id: The raw ``X-Axiam-Delivery`` header value (the
            at-least-once dedup key, §13.3 rule 7), if the caller wants it
            carried on the returned :class:`WebhookEvent`. Passed through
            unverified — it is not covered by the MAC.

    Returns:
        The verified :class:`WebhookEvent`.

    Raises:
        WebhookVerifyError: on any parse failure, signature mismatch, or
            staleness — the message never includes the expected/computed
            signature or the secret (§13.3 rule 6).
    """
    if not isinstance(body, bytes):
        raise WebhookVerifyError("body must be raw bytes")

    timestamp, candidates = _parse_signature_header(signature_header)

    if timestamp_header is not None:
        try:
            separate_timestamp = int(timestamp_header.strip())
        except ValueError:
            raise WebhookVerifyError("malformed X-Axiam-Timestamp header") from None
        if separate_timestamp != timestamp:
            raise WebhookVerifyError("X-Axiam-Timestamp does not match signature header's t=")

    signed_payload = f"{timestamp}.".encode("ascii") + body
    expected_mac = hmac.new(_secret_bytes(secret), signed_payload, hashlib.sha256).digest()

    matched = False
    for candidate_hex in candidates:
        try:
            candidate_mac = bytes.fromhex(candidate_hex)
        except ValueError:
            # Fail closed for this candidate (§13.3 rule 4) — never fall
            # back to comparing raw hex strings.
            continue
        if hmac.compare_digest(expected_mac, candidate_mac):
            matched = True
    if not matched:
        raise WebhookVerifyError("signature mismatch")

    if abs(_reference_epoch(now) - timestamp) > tolerance:
        raise WebhookVerifyError("timestamp outside tolerance")

    return WebhookEvent(
        event_type=event_type,
        delivery_id=delivery_id,
        body=body,
        timestamp=timestamp,
    )
