"""Turning a §27 request model into the body that goes on the socket.

Two §27 rules meet in this module.

**§27.4 rule 5 — sparse updates.** A body carrying one field must change one
field, which means an unset field is *absent from the wire body* rather than
sent as ``null``. Pydantic's ``exclude_unset`` is exactly that distinction, and
using it is why these models are pydantic models rather than dataclasses: a
dataclass cannot tell "not mentioned" from "explicitly None".

**§27.5 / §7 rule 4 — secrets.** Secret fields are :class:`~pydantic.SecretStr`,
so they are redacted from every ``repr``, log line and default JSON rendering —
and therefore cannot be serialized directly, since what would go on the wire is
``"**********"``. :func:`to_wire` is the single place that unwraps them, so
"put a secret on the socket" stays one greppable call rather than fourteen.
"""

from __future__ import annotations

import datetime as _datetime
from collections.abc import Callable, Iterable
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, SecretStr, model_serializer

__all__ = ["UNKNOWN_ARM", "ManagementModel", "OpenUnionUnknown", "open_discriminator"]

#: Fields the server refuses when present-but-empty, so :meth:`to_wire` drops
#: them in that case as well as when they are unset.
#:
#: CONTRACT.md §5.2.3 rule 1: ``tenant_scope: []`` is refused with ``400``. An
#: assignment that reaches no tenant contributes nothing anywhere, so it is a
#: grant that does not exist rather than a restriction, and the server declines
#: to guess which was meant. ``exclude_unset`` alone does not cover it: the
#: natural way to build the field is to collect into a list and pass it, which
#: yields ``[]`` for "no tenants named" and *is* set, so it would go on the
#: wire.
#:
#: Deliberately a name list rather than a rule over every empty list: for the
#: others ``[]`` is meaningful (a replacement body clearing a list), and
#: dropping it would make "remove every entry" inexpressible.
_OMIT_WHEN_EMPTY = frozenset({"tenant_scope"})


class ManagementModel(BaseModel):
    """Base of every generated §27 request and response model."""

    model_config = ConfigDict(populate_by_name=True)

    def to_wire(self) -> dict[str, Any]:
        """This model as its JSON-ready wire body.

        Unset fields are omitted entirely (§27.4 rule 5) and secrets are
        unwrapped (§27.5). A field explicitly set to ``None`` *is* sent as
        ``null`` — that is the caller saying so, which is a different statement
        from leaving it out.

        The one exception is ``tenant_scope`` — see :data:`_OMIT_WHEN_EMPTY`.
        """
        exposed = _expose(self.model_dump(exclude_unset=True, by_alias=True))
        assert isinstance(exposed, dict)
        for field in _OMIT_WHEN_EMPTY:
            if field in exposed and exposed[field] == []:
                del exposed[field]
        return exposed


#: The pydantic ``Tag`` of every open union's catch-all arm. A discriminator value
#: the server sends that this SDK's copy of the spec does not list is routed here
#: by :func:`open_discriminator`; the string itself never reaches the wire.
UNKNOWN_ARM = "__axiam_unknown_arm__"


def open_discriminator(tag: str, known: Iterable[str]) -> Callable[[Any], str]:
    """A pydantic ``Discriminator`` callable for an **open** tagged union.

    A closed ``Field(discriminator=...)`` union fails validation on a tag value
    it does not list, which would fail the *whole* response the value arrived
    in. Some unions are open by contract -- CONTRACT §31.2 requires
    ``ScimTargetAuth`` and ``ScimTargetScope`` to decode an unknown ``type``
    without failing -- so their tag is picked here: a listed value selects its
    arm, anything else selects the :data:`UNKNOWN_ARM` catch-all.
    """
    listed = frozenset(known)

    def pick(value: Any) -> str:
        """The arm ``Tag`` for ``value`` (a raw mapping or a built model)."""
        raw = value.get(tag) if isinstance(value, dict) else getattr(value, tag, None)
        return raw if isinstance(raw, str) and raw in listed else UNKNOWN_ARM

    return pick


class OpenUnionUnknown(ManagementModel):
    """Base of the catch-all arm of an open tagged union.

    It decodes any object whose tag this SDK does not recognise, keeping every
    member the server sent (``extra="allow"``), so an arm added server-side does
    not fail the read it appears in. It **refuses to serialize**: a value this
    SDK cannot describe must not be sent back (CONTRACT §31.2), so
    :meth:`ManagementModel.to_wire` -- and ``model_dump`` -- raise rather than
    echo it into a request body.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    @model_serializer(mode="plain")
    def _refuse(self) -> dict[str, Any]:
        """Refuse to serialize an arm this SDK does not recognise.

        Raises:
            ValueError: always (pydantic surfaces it as a
                ``PydanticSerializationError``, itself a ``ValueError``).
        """
        raise ValueError(
            f"{type(self).__name__}: refusing to serialize a union arm this SDK does "
            f"not recognise; an unknown variant decodes but is never sent (CONTRACT §31.2)"
        )


def _expose(value: Any) -> Any:
    """Recursively render ``value`` JSON-ready, unwrapping every secret.

    ``model_dump`` in python mode leaves ``SecretStr``, ``UUID``, ``datetime``
    and ``Enum`` as objects; json mode would render the secrets as
    ``"**********"``. So the dump stays in python mode and this walk does the
    conversion, which keeps the unwrap in one auditable place.
    """
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    if isinstance(value, dict):
        return {k: _expose(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expose(v) for v in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, _datetime.datetime | _datetime.date):
        return value.isoformat()
    return value
