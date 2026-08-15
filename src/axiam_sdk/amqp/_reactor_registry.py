"""Reactor event registry and mutable-field allow-lists (CONTRACT.md §22.5, §22.7, §22.8).

Mirror, never import. This is the same data as the server's ``EVENT_REGISTRY``
in ``crates/axiam-core/src/models/reactor.rs``, restated here because a reactor
runtime validates an incoming event name and a handler's patch keys on the
delivery path, where a network call is not available. The live copy is served at
``GET /api/v1/reactors/events`` and is what an admin UI SHOULD read; this table
is the offline equivalent.

What is deliberately ABSENT is load-bearing. The three hot-path decision
operations — the single authorization check, the batch check and token
introspection — are not hookable (§22.7, a normative MUST NOT), so they appear
in no constant, no tuple and no example anywhere in this package. Their names
are not written here either, so the conformance test can enforce the rule with a
plain scan of the source rather than a judgement call about which mentions are
innocent.

The reason is arithmetic, not policy: a reactor round-trip is milliseconds and
the check path's budget is microseconds. An application that needs external
input on an authorization decision writes a **deny grant**, which the engine
evaluates in the hot path at hot-path cost.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

__all__ = [
    "REACTOR_EXCHANGE",
    "TOKEN_PRE_ISSUE",
    "LOGIN_POST_AUTH",
    "USER_PRE_CREATE",
    "USER_PRE_UPDATE",
    "GRANT_PRE_ASSIGN",
    "REACTOR_EVENT_NAMES",
    "EVENT_REGISTRY",
    "ReactorEventSpec",
    "FailurePolicy",
    "ReactorMode",
    "event_spec",
    "patch_field_allowed",
    "default_failure_policy_for",
    "reactor_routing_key",
    "reactor_queue_name",
    "DEFAULT_REACTOR_TIMEOUT_MS",
    "MIN_REACTOR_TIMEOUT_MS",
    "MAX_REACTOR_TIMEOUT_MS",
    "REACTOR_CHAIN_CEILING_MS",
    "DEFAULT_REACTOR_MAX_IN_FLIGHT",
]

#: Topic exchange every reactor event is published to (§22.1). The **server**
#: declares it; a reactor runtime never does.
REACTOR_EXCHANGE = "axiam.reactor.events"

#: Before an access token is minted. Mutable: the ``ext.`` claim namespace only.
TOKEN_PRE_ISSUE = "token.pre_issue"

#: After credentials verify and before any session or token is issued — on
#: password authentication, on SAML ACS and on the OIDC callback alike (§22.5,
#: SEC-095). MFA completion and the WebAuthn ``authenticate/finish`` ceremony
#: are NOT separate firings: both continue a login already gated at its first
#: step. Veto-only, and the only event on which ``require_mfa`` is meaningful.
#:
#: The federated paths have no step-up branch, so a ``require_mfa`` answer there
#: is refused (the sign-in fails) rather than silently dropped — a reactor that
#: needs step-up on a federated login answers ``deny`` and drives enrolment out
#: of band.
LOGIN_POST_AUTH = "login.post_auth"

#: Before a user row is written. Mutable: ``username``, ``email``, ``metadata.``.
USER_PRE_CREATE = "user.pre_create"

#: Before a user profile is updated. Mutable: ``username``, ``email``,
#: ``metadata.``.
USER_PRE_UPDATE = "user.pre_update"

#: Before a role or permission assignment. Veto-only — four-eyes workflows live
#: here.
GRANT_PRE_ASSIGN = "grant.pre_assign"

#: What the server does when an interceptor produces no usable reply (§22.8).
#: "No usable reply" is one closed set and every member takes the same path:
#: timeout, transport failure, a budget exhausted before this reactor was
#: reached, the in-flight cap, and every §22.4 rejection — including a valid
#: signature carrying a forbidden patch field.
FailurePolicy = Literal["fail_open", "fail_closed"]

#: How a reactor participates in an event (§22.5, §22.9). ``listen`` is
#: fire-and-forget observation: the server never waits and never reads a reply,
#: so a listener cannot affect any outcome.
ReactorMode = Literal["intercept", "listen"]

#: Per-dispatch timeout a registration gets when it names none (§22.8).
DEFAULT_REACTOR_TIMEOUT_MS = 500

#: Lowest ``timeout_ms`` accepted at registration (§22.8). ``0`` is refused.
MIN_REACTOR_TIMEOUT_MS = 1

#: Highest ``timeout_ms`` accepted at registration, and the wall-clock ceiling
#: on a whole dispatch chain (§22.8). A reactor that needs longer than five
#: seconds to answer is not an interceptor, it is an outage.
MAX_REACTOR_TIMEOUT_MS = 5_000

#: Wall-clock ceiling on one dispatch chain (§22.8). Reactors not reached inside
#: it are not contacted at all, and each of their own failure policies is
#: applied anyway — so an unreached ``fail_closed`` veto still denies.
REACTOR_CHAIN_CEILING_MS = 5_000

#: Per-tenant in-flight interception cap, enforced server-side with a
#: non-blocking acquire (§22.8). Stated here so a reactor author sizing a worker
#: pool knows the ceiling they are working under.
DEFAULT_REACTOR_MAX_IN_FLIGHT = 64


@dataclass(frozen=True)
class ReactorEventSpec:
    """One hookable event: its name, what a reply may change, and what happens
    when the reactor does not answer (CONTRACT.md §22.5)."""

    #: Wire name, and the second half of the routing key ``<tenant_id>.<event>``.
    name: str
    #: Whether an interceptor may register for this event at all. ``False``
    #: means listen-only.
    interceptable: bool
    #: Whether an interceptor's reply may carry a ``patch``.
    mutable: bool
    #: The COMPLETE allow-list: exact field names, or a namespace prefix ending
    #: in ``.`` — see :func:`patch_field_allowed`.
    mutable_fields: tuple[str, ...] = field(default=())
    #: The ``failure_policy`` a registration gets for this event when it names
    #: none, before §22.8's strictest-wins composition.
    default_failure_policy: FailurePolicy = "fail_closed"
    #: The one-liner the admin surface shows.
    description: str = ""


#: Every hookable event in contract v1 — five of them (§22.5).
#:
#: The order matches the server's ``EVENT_REGISTRY``. It is a tuple of frozen
#: dataclasses so a caller cannot edit the SDK's copy of the allow-lists in
#: place. Nothing on the authorization hot path appears here, and nothing may be
#: added locally: an event outside the registry dispatches to nothing and
#: resolves to ``allow`` server-side, which is what makes §22.7's exclusion
#: structural rather than advisory.
EVENT_REGISTRY: tuple[ReactorEventSpec, ...] = (
    ReactorEventSpec(
        name=TOKEN_PRE_ISSUE,
        interceptable=True,
        mutable=True,
        # Custom claims only. `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`,
        # `scope`, `scp`, `azp`, `act` and `client_id` are all unreachable
        # because none of them begins with `ext.` — a hook that can rewrite
        # `sub` is a hook that can mint a token for anyone, and a CORRECTLY
        # SIGNED reply setting it is refused exactly as a forged one is.
        mutable_fields=("ext.",),
        default_failure_policy="fail_open",
        description="Enrich or veto token issuance. May add claims under `ext.` only.",
    ),
    ReactorEventSpec(
        name=LOGIN_POST_AUTH,
        interceptable=True,
        mutable=False,
        mutable_fields=(),
        default_failure_policy="fail_closed",
        description=(
            "After credentials verify, before session issuance: veto or require step-up MFA."
        ),
    ),
    ReactorEventSpec(
        name=USER_PRE_CREATE,
        interceptable=True,
        mutable=True,
        mutable_fields=("username", "email", "metadata."),
        default_failure_policy="fail_closed",
        description="Validate or normalize a new user's profile fields.",
    ),
    ReactorEventSpec(
        name=USER_PRE_UPDATE,
        interceptable=True,
        mutable=True,
        mutable_fields=("username", "email", "metadata."),
        default_failure_policy="fail_closed",
        description="Validate or normalize a profile update.",
    ),
    ReactorEventSpec(
        name=GRANT_PRE_ASSIGN,
        interceptable=True,
        mutable=False,
        mutable_fields=(),
        default_failure_policy="fail_closed",
        description="Veto a role or permission assignment (four-eyes workflows). Veto-only.",
    ),
)

#: The five v1 registry event names, in registry order. Handlers compare against
#: the named constants rather than string literals so a typo is a lookup miss at
#: import time rather than an event that silently never fires.
REACTOR_EVENT_NAMES: tuple[str, ...] = tuple(spec.name for spec in EVENT_REGISTRY)


def event_spec(name: str) -> ReactorEventSpec | None:
    """Look an event up by wire name.

    ``None`` for any name outside the registry — including the three hot-path
    operations §22.7 excludes, which are absent by construction rather than by a
    filter that could be forgotten.
    """
    for spec in EVENT_REGISTRY:
        if spec.name == name:
            return spec
    return None


def patch_field_allowed(spec: ReactorEventSpec, field_name: str) -> bool:
    """Report whether ``field_name`` may appear in a patch for ``spec`` (§22.5).

    An allow-list entry ending in ``.`` is a NAMESPACE PREFIX: it matches a field
    that starts with the entry and has at least one character after the dot. So
    ``ext.`` admits ``ext.department`` and ``ext.a.b.c``, and refuses ``ext.``
    itself (it names the namespace, not a claim), ``ext`` (not in the
    namespace), ``extra`` / ``external_id`` (a prefix match on the *string* is
    not a match on the namespace) and ``evil.ext.department`` (not a suffix
    match either).

    This is a LOOKUP, not a filter. It exists so a handler can check its own
    patch before returning it. The runtime does NOT call it to prune a patch:
    §22.4 rule 1 and §22.10 rule 3 forbid filtering a handler's patch down to
    the allowed subset, because one forbidden key rejects the *whole* patch
    server-side and dropping it silently would leave the author believing a
    field was set when it was not.

    Mirrors ``ReactorEventSpec::patch_field_allowed`` in
    ``crates/axiam-core/src/models/reactor.rs``.
    """
    if not spec.mutable:
        return False
    for allowed in spec.mutable_fields:
        if allowed.endswith("."):
            if len(field_name) > len(allowed) and field_name.startswith(allowed):
                return True
            continue
        if field_name == allowed:
            return True
    return False


def default_failure_policy_for(event_names: object) -> FailurePolicy:
    """Compose the ``failure_policy`` a registration naming none inherits (§22.8).

    The STRICTEST default among its events wins, **in either array order**. A
    reactor registered for both ``token.pre_issue`` (open) and
    ``login.post_auth`` (closed) can veto a login, so it inherits
    ``fail_closed``. Reimplementing this as "take the first event's default"
    would let the order of a JSON array decide whether an unreachable fraud
    check passes, which is why §22.8 states it as a MUST NOT reimplement rather
    than a note.

    An unknown event name contributes ``fail_closed``: the server will refuse
    the registration outright, and guessing open on a name this SDK does not
    recognise is the one guess that could weaken a decision. An empty list is
    ``fail_closed`` for the same reason — a registration with no events is
    invalid, not permissive.

    ``event_names`` is typed as ``object`` and iterated defensively because this
    is the one registry helper an admin UI is likely to call with whatever came
    back off a wire.
    """
    if not isinstance(event_names, (list, tuple, set, frozenset)):
        return "fail_closed"
    names = list(event_names)
    if not names:
        return "fail_closed"
    for name in names:
        if not isinstance(name, str):
            return "fail_closed"
        spec = event_spec(name)
        if spec is None or spec.default_failure_policy == "fail_closed":
            return "fail_closed"
    return "fail_open"


def reactor_routing_key(tenant_id: str, event: str) -> str:
    """Render the topic routing key for one event: ``<tenant_id>.<event>`` (§22.1).

    Mirrors ``routing_key()`` in ``crates/axiam-amqp/src/reactor/protocol.rs``.
    Exported for logging, assertions and admin tooling; a reactor runtime never
    binds it, because bindings are the server's, derived from the registration's
    ``events``.
    """
    return f"{tenant_id}.{event}"


def reactor_queue_name(tenant_id: str, reactor_id: str) -> str:
    """Render the durable per-reactor queue the SERVER declares (§22.1).

    ``axiam.reactor.q.<tenant_id>.<reactor_id>``; mirrors ``queue_name()`` in
    ``crates/axiam-amqp/src/reactor/protocol.rs``.

    Deriving the name is not the same as declaring it. A reactor consumes this
    queue and nothing else; it never declares, redeclares or binds it, and never
    derives a name for a reactor other than the one it is configured as. A
    reactor that can bind is a reactor that can bind itself to
    ``*.token.pre_issue`` and read another tenant's issuance events.
    """
    return f"axiam.reactor.q.{tenant_id}.{reactor_id}"
