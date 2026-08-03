"""AXIAM SDK webhook signature verification (CONTRACT.md §13, T-145).

Verifies the Stripe-style signed-timestamp scheme the AXIAM server uses for
every webhook delivery (``crates/axiam-api-rest/src/webhook.rs``,
``compute_signature_v2``): ``v1 = HMAC-SHA256(secret, "<timestamp>.<raw_body>")``,
carried in the ``X-Axiam-Signature: t=<unix_seconds>,v1=<hex>`` header.

Public surface:

- :func:`verify_webhook` — parse the signature header, recompute the MAC
  over the caller-supplied raw body, compare it in constant time, and
  enforce a two-sided freshness window. Returns a typed :class:`WebhookEvent`
  on success; raises :class:`WebhookVerifyError` on any failure.
- :class:`WebhookEvent` — the parsed, verified delivery.
- :class:`WebhookVerifyError` — the typed failure raised by
  :func:`verify_webhook`; its message never includes the expected/computed
  signature.
- :data:`DEFAULT_TOLERANCE_SECONDS` — the default freshness window (300s).
"""

from axiam_sdk.webhook._verify import (
    DEFAULT_TOLERANCE_SECONDS,
    WebhookEvent,
    WebhookVerifyError,
    verify_webhook,
)

__all__ = [
    "verify_webhook",
    "WebhookEvent",
    "WebhookVerifyError",
    "DEFAULT_TOLERANCE_SECONDS",
]
