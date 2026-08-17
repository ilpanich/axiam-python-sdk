"""Declarative reactor handler binding — CONTRACT.md §22.14.

:func:`~axiam_sdk.amqp.reactor_serve` takes **one** function from an event to
one answer, which is the right shape for the wire and the wrong shape for the
code. A reactor registered for three events opens with a chain of ``if
event.event == ...``, and that chain is where two defects live.

The first is cheap: a misspelled event name is valid Python, matches nothing,
and is discovered as an event that never fires. The second is not. It is the
final ``return allow()`` — the arm that answers on behalf of code that never
ran. That is the defect §22.10 rule 2 forbids the *runtime* from committing,
relocated into user code where the rule does not reach it: an operator who set
``fail_closed`` on a registration has it defeated by a fallback in a file they
never read.

This module is the declarative form. Bind one handler per event and let the
router compose them::

    from axiam_sdk.amqp import (
        LOGIN_POST_AUTH, TOKEN_PRE_ISSUE, ReactorRouter, reactor_serve,
    )

    router = ReactorRouter()

    @router.on(TOKEN_PRE_ISSUE)
    def enrich_token(event):
        return mutate({"ext.department": "engineering"})

    @router.on(LOGIN_POST_AUTH)
    async def screen_login(event):
        return deny("embargoed region") if await embargoed(event) else allow()

    await reactor_serve(dialer, config, router.handler())

or, for a class-based reactor, mark the methods and collect them::

    class Reactor:
        @on_reactor_event(TOKEN_PRE_ISSUE)
        def enrich(self, event): ...

    handler = reactor_handlers(Reactor())

It is **pure sugar** (§22.14 rule 1): the value it produces is exactly the
:data:`~axiam_sdk.amqp.ReactorHandler` ``reactor_serve`` already accepts. It
opens nothing, verifies nothing and signs nothing, and it does not filter a
patch (§22.10 rule 3). What it adds is the two answers the ``if`` chain got
wrong — a name outside the §22.5 registry is refused when you **bind** it, and
an event with no handler **abstains** rather than being allowed.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any, TypeVar

from axiam_sdk.amqp._reactor import ReactorHandler
from axiam_sdk.amqp._reactor_protocol import ReactorDecision, ReactorEvent, abstain
from axiam_sdk.amqp._reactor_registry import REACTOR_EVENT_NAMES, event_spec

__all__ = [
    "ReactorRouter",
    "on_reactor_event",
    "reactor_handlers",
]

#: What a bound handler may be: sync or async, one event in, one answer out.
#: Both are supported because the decision itself is frequently pure — the
#: ``ext.`` claims to add are computed from the payload — and forcing ``async
#: def`` on a function that never awaits buys nothing.
BoundHandler = Callable[[ReactorEvent], ReactorDecision | Awaitable[ReactorDecision]]

_F = TypeVar("_F", bound=Callable[..., Any])

#: Attribute :func:`on_reactor_event` stamps on a function, read back by
#: :meth:`ReactorRouter.include`.
_EVENT_ATTR = "__axiam_reactor_event__"


def _registry_hint() -> str:
    """The hookable event names, for a rejection message.

    Deliberately built from the registry rather than from a list of what is
    *excluded*: §22.13 requires the three hot-path operations to be absent from
    every event constant this SDK exposes, so naming them here — even only to
    say they are refused — is the thing that would break it (§22.14 rule 2).
    """
    return ", ".join(sorted(REACTOR_EVENT_NAMES))


def _check_bindable(event: str, handler: BoundHandler, bound: Mapping[str, BoundHandler]) -> None:
    """Raise :class:`ValueError`/:class:`TypeError` for a binding §22.14 refuses."""
    if not isinstance(event, str) or not event:
        raise ValueError("a reactor event name must be a non-empty string")
    if not callable(handler):
        raise TypeError(f"the handler bound to {event!r} is not callable")
    if event_spec(event) is None:
        raise ValueError(
            f"{event!r} is not a hookable reactor event; the registry is [{_registry_hint()}]"
        )
    if event in bound:
        raise ValueError(f"reactor event {event!r} is already bound")


def on_reactor_event(event: str) -> Callable[[_F], _F]:
    """Mark a function or method as the handler for one hook event (§22.14).

    The name is validated **here**, when the decorator runs at import time, so
    a typo fails the process rather than becoming an event that never fires.
    Collect the decorated callables with :func:`reactor_handlers` or
    :meth:`ReactorRouter.include`.

    ::

        class Reactor:
            @on_reactor_event(TOKEN_PRE_ISSUE)
            def enrich(self, event: ReactorEvent) -> ReactorDecision:
                return mutate({"ext.department": "engineering"})

    :param event: a §22.5 registry event name.
    :raises ValueError: if ``event`` is not in the registry. §22.7's hot-path
        operations are in no registry row, so binding one fails here.
    """
    if not isinstance(event, str) or not event:
        raise ValueError("a reactor event name must be a non-empty string")
    if event_spec(event) is None:
        raise ValueError(
            f"{event!r} is not a hookable reactor event; the registry is [{_registry_hint()}]"
        )

    def decorator(func: _F) -> _F:
        """Stamp ``func`` with its event and return it unchanged."""
        setattr(func, _EVENT_ATTR, event)
        return func

    return decorator


class ReactorRouter:
    """One handler per hook event, composed into the single §22.10 handler.

    A router is built once at startup and read only afterwards. Binding after
    :meth:`handler` has been called does not disturb the handler already
    returned — it snapshots its table — but it is not a supported way to
    reconfigure a running reactor.
    """

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        """Start with an empty binding table."""
        self._handlers: dict[str, BoundHandler] = {}

    def bind(self, event: str, handler: BoundHandler) -> None:
        """Bind ``handler`` to ``event``.

        :raises ValueError: if ``event`` is outside the §22.5 registry (which
            is how §22.7's hot-path operations are refused) or is already
            bound — a second binding is a mistake, never a silent overwrite,
            because which of the two runs is not visible from either one.
        :raises TypeError: if ``handler`` is not callable.
        """
        _check_bindable(event, handler, self._handlers)
        self._handlers[event] = handler

    def on(self, event: str) -> Callable[[_F], _F]:
        """Decorator form of :meth:`bind`.

        ::

            @router.on(TOKEN_PRE_ISSUE)
            def enrich_token(event: ReactorEvent) -> ReactorDecision: ...

        Returns the function unchanged, so it stays directly callable and
        directly testable.
        """

        def decorator(func: _F) -> _F:
            """Bind ``func`` to the captured event and return it unchanged."""
            self.bind(event, func)
            return func

        return decorator

    def include(self, *sources: object) -> None:
        """Bind every :func:`on_reactor_event`-marked callable found on ``sources``.

        A source is any object — an instance, a class or a module. Bound
        methods are collected with their instance already attached, so a
        class-based reactor keeps its state.
        """
        for source in sources:
            for name in dir(source):
                if name.startswith("__"):
                    continue
                try:
                    member = getattr(source, name)
                except AttributeError:  # pragma: no cover - defensive
                    continue
                event = getattr(member, _EVENT_ATTR, None)
                if isinstance(event, str):
                    self.bind(event, member)

    @property
    def events(self) -> tuple[str, ...]:
        """The bound event names, in binding order.

        Pass them to :func:`~axiam_sdk.amqp.default_failure_policy_for` to see
        what an unreachable reactor costs — the strictest default among them
        (§22.8) — computed from the code that handles the events rather than
        from a restatement of the registration.
        """
        return tuple(self._handlers)

    def handler(self) -> ReactorHandler:
        """Compose the bindings into the handler ``reactor_serve`` accepts.

        :raises ValueError: if nothing is bound. A reactor that handles nothing
            would consume its queue and abstain from every event, which looks
            exactly like an outage.
        """
        if not self._handlers:
            raise ValueError("ReactorRouter has no bindings; bind at least one event")

        bound = dict(self._handlers)

        async def dispatch(event: ReactorEvent) -> ReactorDecision:
            """Route one verified event to its handler, or abstain (§22.14 rule 4)."""
            handler = bound.get(event.event)
            if handler is None:
                # §22.14 rule 4. NOT allow(): publishing nothing lets the
                # registration's failure_policy resolve this exactly as it
                # resolves a timeout (§22.8), and the router does not know
                # what the registration was for. The operator's policy does.
                return abstain()
            # Called without a try/except on purpose (§22.14 rule 5): a
            # handler's own exception must reach the runtime unchanged so it
            # publishes nothing. Catching it here would satisfy the letter of
            # §22.10 rule 2 while defeating it.
            result = handler(event)
            if inspect.isawaitable(result):
                return await result
            return result

        return dispatch


def reactor_handlers(
    source: Mapping[str, BoundHandler] | object,
    *more: object,
) -> ReactorHandler:
    """Build a §22.10 handler from a mapping, or from decorated objects.

    Two spellings of the same thing::

        handler = reactor_handlers({TOKEN_PRE_ISSUE: enrich, LOGIN_POST_AUTH: screen})
        handler = reactor_handlers(MyReactor())   # @on_reactor_event methods

    Both go through :class:`ReactorRouter`, so every §22.14 rule applies
    identically: unregistered names and duplicates are refused here, an unbound
    event abstains, and a handler's own exception propagates.
    """
    router = ReactorRouter()
    sources: Iterable[object] = (source, *more)
    for item in sources:
        if isinstance(item, Mapping):
            for event, handler in item.items():
                router.bind(event, handler)
        else:
            router.include(item)
    return router.handler()
