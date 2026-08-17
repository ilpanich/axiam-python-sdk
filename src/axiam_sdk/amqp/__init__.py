"""AXIAM SDK AMQP transport (CONTRACT.md §8, §22, D-02).

Async-only (``aio-pika``) with mandatory HMAC-SHA256 verify-before-handler and
v2 replay protection (NEW-4). Two surfaces share those primitives:

**§8 — the event consumer.**

- :func:`consume` — closure-handler consumer; the SDK owns the ack/nack
  loop, verifies every delivery's HMAC signature before the caller's
  handler is ever invoked, and rejects stale/replayed/pre-v2 messages.
- :class:`ErrDrop` — sentinel a handler raises to signal "poison message,
  nack WITHOUT requeue" (mirrors Go's exported ``ErrDrop``).
- :func:`verify_hmac` — the underlying HMAC-SHA256 verifier (19-01),
  re-exported for callers that need to verify a message body directly.
- :class:`NonceStore` / :func:`validate_freshness` / :data:`DEFAULT_SKEW_SECONDS`
  — the NEW-4 replay-protection primitives ``consume()`` uses internally,
  re-exported for callers that need to verify freshness directly or inject
  a shared store across multiple consumers.

**§22 — the reactor runtime.** A reactor is an external process that subscribes
to named hook events on the AMQP bus and answers back — allow, deny, or a
field-allow-listed mutation — inside a timeout the server declared.

- :func:`reactor_serve` — the runtime §22.10's per-language table names for
  Python. It consumes the SERVER-DECLARED queue, verifies §8 v2 in full before
  user code sees an event, dispatches to a handler, then signs and publishes the
  reply. It declares no topology and fails closed on its own errors.
- :func:`allow` / :func:`require_step_up` / :func:`deny` / :func:`mutate` /
  :func:`abstain` — the answers a handler returns.
- :data:`EVENT_REGISTRY`, :func:`event_spec`, :func:`patch_field_allowed`,
  :func:`default_failure_policy_for` — the §22.5 registry, its mutable-field
  allow-lists and §22.8's strictest-wins failure-policy composition.
- :func:`aio_pika_dialer` — an ``amqps://``-only dialer (§8b).
- :class:`ReactorRouter` / :func:`on_reactor_event` / :func:`reactor_handlers` —
  §22.14's declarative binding: one handler per event instead of an ``if`` chain
  whose final ``return allow()`` answers for code that never ran.

§8's HMAC runs in BOTH directions on the reactor exchange: the server signs the
event, the reactor signs the reply with the same tenant subkey, and an unsigned
or stale reply is discarded as though the reactor had never answered. One
canonicalization difference separates the two chapters and produces a MAC that
never verifies with no other symptom — a reactor body serializes
``hmac_signature`` as ``null`` rather than omitting it. See
:mod:`axiam_sdk.amqp._reactor_protocol` for that and the two other traps.
"""

from axiam_sdk.amqp._consumer import ErrDrop, consume
from axiam_sdk.amqp._hmac import verify_hmac
from axiam_sdk.amqp._reactor import (
    InsecureReactorUrlError,
    ReactorConfig,
    ReactorDelivery,
    ReactorDialer,
    ReactorHandler,
    ReactorTransport,
    aio_pika_dialer,
    dispatch_reactor_delivery,
    reactor_serve,
)
from axiam_sdk.amqp._reactor_protocol import (
    REACTOR_CHAIN_PATCH_KEY,
    REACTOR_DEFAULT_DENY_REASON,
    REACTOR_FRESHNESS_SKEW_SECONDS,
    REACTOR_KEY_VERSION,
    EventRejection,
    ReactorDecision,
    ReactorEvent,
    ReplyDecision,
    ReplyRejection,
    abstain,
    allow,
    build_reactor_reply,
    canonical_event_bytes,
    canonical_reply_bytes,
    deny,
    is_fresh,
    mutate,
    reactor_reply_bytes,
    reactor_reply_signature_valid,
    require_step_up,
    sign_reactor_reply,
    signing_key_fingerprint,
    to_chrono_rfc3339,
    verify_event,
)
from axiam_sdk.amqp._reactor_registry import (
    DEFAULT_REACTOR_MAX_IN_FLIGHT,
    DEFAULT_REACTOR_TIMEOUT_MS,
    EVENT_REGISTRY,
    GRANT_PRE_ASSIGN,
    LOGIN_POST_AUTH,
    MAX_REACTOR_TIMEOUT_MS,
    MIN_REACTOR_TIMEOUT_MS,
    REACTOR_CHAIN_CEILING_MS,
    REACTOR_EVENT_NAMES,
    REACTOR_EXCHANGE,
    TOKEN_PRE_ISSUE,
    USER_PRE_CREATE,
    USER_PRE_UPDATE,
    FailurePolicy,
    ReactorEventSpec,
    ReactorMode,
    default_failure_policy_for,
    event_spec,
    patch_field_allowed,
    reactor_queue_name,
    reactor_routing_key,
)
from axiam_sdk.amqp._reactor_router import (
    ReactorRouter,
    on_reactor_event,
    reactor_handlers,
)
from axiam_sdk.amqp._replay import DEFAULT_SKEW_SECONDS, NonceStore, validate_freshness

__all__ = [
    # §8 — the event consumer.
    "consume",
    "ErrDrop",
    "verify_hmac",
    "NonceStore",
    "validate_freshness",
    "DEFAULT_SKEW_SECONDS",
    # §22 — the reactor runtime.
    "reactor_serve",
    "dispatch_reactor_delivery",
    "aio_pika_dialer",
    "ReactorConfig",
    "ReactorHandler",
    "ReactorDelivery",
    "ReactorTransport",
    "ReactorDialer",
    "InsecureReactorUrlError",
    # §22.4 — the answers a handler returns.
    "ReactorDecision",
    "allow",
    "require_step_up",
    "deny",
    "mutate",
    "abstain",
    # §22.2/§22.3/§22.4 — the wire protocol.
    "ReactorEvent",
    "ReplyDecision",
    "EventRejection",
    "ReplyRejection",
    "REACTOR_KEY_VERSION",
    "REACTOR_FRESHNESS_SKEW_SECONDS",
    "REACTOR_CHAIN_PATCH_KEY",
    "REACTOR_DEFAULT_DENY_REASON",
    "to_chrono_rfc3339",
    "is_fresh",
    "canonical_event_bytes",
    "verify_event",
    "build_reactor_reply",
    "canonical_reply_bytes",
    "reactor_reply_bytes",
    "sign_reactor_reply",
    "reactor_reply_signature_valid",
    "signing_key_fingerprint",
    # §22.5/§22.7/§22.8 — the registry.
    "EVENT_REGISTRY",
    "REACTOR_EVENT_NAMES",
    "ReactorEventSpec",
    "FailurePolicy",
    "ReactorMode",
    "TOKEN_PRE_ISSUE",
    "LOGIN_POST_AUTH",
    "USER_PRE_CREATE",
    "USER_PRE_UPDATE",
    "GRANT_PRE_ASSIGN",
    "event_spec",
    "patch_field_allowed",
    "default_failure_policy_for",
    "reactor_routing_key",
    "reactor_queue_name",
    "REACTOR_EXCHANGE",
    "DEFAULT_REACTOR_TIMEOUT_MS",
    "MIN_REACTOR_TIMEOUT_MS",
    "MAX_REACTOR_TIMEOUT_MS",
    "REACTOR_CHAIN_CEILING_MS",
    "DEFAULT_REACTOR_MAX_IN_FLIGHT",
    # §22.14 — declarative handler binding.
    "ReactorRouter",
    "on_reactor_event",
    "reactor_handlers",
]
