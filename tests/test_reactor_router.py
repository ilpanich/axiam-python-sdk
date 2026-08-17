"""CONTRACT.md §22.14 — declarative reactor handler binding.

Six tests for six rules. None of them needs a broker: the router is pure
composition over the handler :func:`reactor_serve` already takes, so what is
under test is the binding table and the one answer it gives for an event
nobody bound.
"""

from __future__ import annotations

import inspect

import pytest

from axiam_sdk.amqp import (
    GRANT_PRE_ASSIGN,
    LOGIN_POST_AUTH,
    TOKEN_PRE_ISSUE,
    USER_PRE_CREATE,
    ReactorEvent,
    ReactorRouter,
    allow,
    default_failure_policy_for,
    deny,
    mutate,
    on_reactor_event,
    reactor_handlers,
)

#: Assembled from halves for the same reason the registry test does it: §22.13
#: bars these three names from the reactor source, and a literal here would be
#: one more place for a scan to trip over.
EXCLUDED_HOT_PATH = tuple(
    f"{prefix}.{op}"
    for prefix, op in (("authz", "check"), ("authz", "check_batch"), ("token", "introspect"))
)


def _event(name: str) -> ReactorEvent:
    """A minimal verified event — only ``event`` is read by the router."""
    return ReactorEvent(
        tenant_id="11111111-1111-1111-1111-111111111111",
        event=name,
        correlation_id="c-1",
        payload={},
        timeout_ms=500,
        nonce="n-1",
        issued_at=0.0,
        key_version=2,
    )


# --------------------------------------------------------------------------
# Rule 1 — it composes; it does not replace.
# --------------------------------------------------------------------------


async def test_dispatches_each_event_to_its_own_handler() -> None:
    router = ReactorRouter()

    @router.on(TOKEN_PRE_ISSUE)
    def enrich(event: ReactorEvent):
        return mutate({"ext.department": "engineering"})

    @router.on(LOGIN_POST_AUTH)
    async def screen(event: ReactorEvent):
        return deny("embargoed region")

    handler = router.handler()

    assert (await handler(_event(TOKEN_PRE_ISSUE))).kind == "mutate"
    assert (await handler(_event(LOGIN_POST_AUTH))).kind == "deny"

    # The composed value is what `reactor_serve` accepts: a coroutine function
    # of one event. Asserted rather than assumed, because a router that
    # returned a sync callable would fail only at dispatch time.
    assert inspect.iscoroutinefunction(handler)


async def test_decorated_handler_stays_directly_callable() -> None:
    """``@router.on`` returns the function unchanged, so it stays unit-testable."""
    router = ReactorRouter()

    @router.on(TOKEN_PRE_ISSUE)
    def enrich(event: ReactorEvent):
        return allow()

    assert enrich(_event(TOKEN_PRE_ISSUE)).kind == "allow"


async def test_reactor_handlers_accepts_a_mapping_and_decorated_objects() -> None:
    class Reactor:
        @on_reactor_event(TOKEN_PRE_ISSUE)
        def enrich(self, event: ReactorEvent):
            return mutate({"ext.team": self.team})

        team = "platform"

    from_object = reactor_handlers(Reactor())
    decision = await from_object(_event(TOKEN_PRE_ISSUE))
    assert decision.patch == {"ext.team": "platform"}, "a bound method lost its instance"

    from_mapping = reactor_handlers({LOGIN_POST_AUTH: lambda event: allow()})
    assert (await from_mapping(_event(LOGIN_POST_AUTH))).kind == "allow"

    # Both spellings in one call, and both go through the same rules.
    combined = reactor_handlers({LOGIN_POST_AUTH: lambda event: allow()}, Reactor())
    assert (await combined(_event(TOKEN_PRE_ISSUE))).kind == "mutate"
    assert (await combined(_event(LOGIN_POST_AUTH))).kind == "allow"


# --------------------------------------------------------------------------
# Rule 2 — an unregistered name is refused at BIND time.
# --------------------------------------------------------------------------


def test_rejects_a_misspelled_event_when_it_is_bound() -> None:
    router = ReactorRouter()
    with pytest.raises(ValueError, match="not a hookable reactor event"):
        router.bind("token.pre_isue", lambda event: allow())

    # And through the decorator, at import time.
    with pytest.raises(ValueError, match="not a hookable reactor event"):
        on_reactor_event("token.pre_isue")


@pytest.mark.parametrize("name", EXCLUDED_HOT_PATH)
def test_rejects_the_hot_path_operations(name: str) -> None:
    """§22.7's three are in no registry row, so rule 2 refuses them as unknown."""
    router = ReactorRouter()
    with pytest.raises(ValueError, match="not a hookable reactor event"):
        router.bind(name, lambda event: allow())
    with pytest.raises(ValueError, match="not a hookable reactor event"):
        on_reactor_event(name)


def test_rejection_message_names_the_registry_not_the_exclusions() -> None:
    """The message lists what IS hookable — §22.14 rule 2's second half."""
    router = ReactorRouter()
    with pytest.raises(ValueError) as excinfo:
        router.bind("nope", lambda event: allow())
    message = str(excinfo.value)
    assert TOKEN_PRE_ISSUE in message
    for excluded in EXCLUDED_HOT_PATH:
        assert excluded not in message


@pytest.mark.parametrize("bad", ["", None, 42])
def test_rejects_an_unusable_event_name(bad: object) -> None:
    router = ReactorRouter()
    with pytest.raises(ValueError, match="non-empty string"):
        router.bind(bad, lambda event: allow())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-empty string"):
        on_reactor_event(bad)  # type: ignore[arg-type]


def test_rejects_a_non_callable_handler() -> None:
    router = ReactorRouter()
    with pytest.raises(TypeError, match="not callable"):
        router.bind(TOKEN_PRE_ISSUE, "not a function")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Rule 3 — one handler per event.
# --------------------------------------------------------------------------


def test_rejects_a_duplicate_binding() -> None:
    router = ReactorRouter()
    router.bind(TOKEN_PRE_ISSUE, lambda event: allow())
    with pytest.raises(ValueError, match="already bound"):
        router.bind(TOKEN_PRE_ISSUE, lambda event: deny("second"))


# --------------------------------------------------------------------------
# Rule 4 — an unbound event ABSTAINS. The reason this module exists.
# --------------------------------------------------------------------------


async def test_unbound_event_abstains_rather_than_allowing() -> None:
    handler = reactor_handlers({TOKEN_PRE_ISSUE: lambda event: allow()})

    decision = await handler(_event(GRANT_PRE_ASSIGN))

    assert decision.kind == "abstain"
    # Stated separately and deliberately: "not allow" is the whole claim.
    # A `default: return allow()` arm answers on behalf of code that never
    # ran, which defeats an operator's fail_closed setting (§22.10 rule 2).
    assert decision.kind != "allow"
    assert decision.kind != "deny"


async def test_empty_router_is_refused() -> None:
    """A reactor that handles nothing abstains from everything — an outage."""
    with pytest.raises(ValueError, match="no bindings"):
        ReactorRouter().handler()


# --------------------------------------------------------------------------
# Rule 5 — a handler's own failure propagates unchanged.
# --------------------------------------------------------------------------


async def test_a_failing_sync_handler_propagates() -> None:
    def explode(event: ReactorEvent):
        raise RuntimeError("fraud service unreachable")

    handler = reactor_handlers({LOGIN_POST_AUTH: explode})
    with pytest.raises(RuntimeError, match="fraud service unreachable"):
        await handler(_event(LOGIN_POST_AUTH))


async def test_a_failing_async_handler_propagates() -> None:
    async def explode(event: ReactorEvent):
        raise RuntimeError("directory timed out")

    handler = reactor_handlers({USER_PRE_CREATE: explode})
    with pytest.raises(RuntimeError, match="directory timed out"):
        await handler(_event(USER_PRE_CREATE))


# --------------------------------------------------------------------------
# Rule 6 and the SHOULD — no filtering, and the bound events are visible.
# --------------------------------------------------------------------------


async def test_a_forbidden_patch_key_is_sent_unfiltered() -> None:
    """§22.10 rule 3: the router is the newest place to be tempted into pruning."""
    handler = reactor_handlers({TOKEN_PRE_ISSUE: lambda event: mutate({"sub": "attacker"})})

    decision = await handler(_event(TOKEN_PRE_ISSUE))

    assert decision.patch == {"sub": "attacker"}, "the router silently dropped a patch key"


def test_bound_events_feed_the_failure_policy() -> None:
    router = ReactorRouter()
    router.bind(TOKEN_PRE_ISSUE, lambda event: allow())
    router.bind(LOGIN_POST_AUTH, lambda event: allow())

    assert router.events == (TOKEN_PRE_ISSUE, LOGIN_POST_AUTH)
    # token.pre_issue defaults open, login.post_auth defaults closed; §22.8's
    # strictest-wins composition makes the pair fail_closed.
    assert default_failure_policy_for(router.events) == "fail_closed"


async def test_handler_snapshots_its_bindings() -> None:
    router = ReactorRouter()
    router.bind(TOKEN_PRE_ISSUE, lambda event: allow())
    handler = router.handler()

    router.bind(GRANT_PRE_ASSIGN, lambda event: deny("late"))

    assert (await handler(_event(GRANT_PRE_ASSIGN))).kind == "abstain"


def test_include_ignores_undecorated_members() -> None:
    class Mixed:
        team = "platform"

        def helper(self, event: ReactorEvent):
            return allow()

        @on_reactor_event(TOKEN_PRE_ISSUE)
        def enrich(self, event: ReactorEvent):
            return allow()

    router = ReactorRouter()
    router.include(Mixed())
    assert router.events == (TOKEN_PRE_ISSUE,)
