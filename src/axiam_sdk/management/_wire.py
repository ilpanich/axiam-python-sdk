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
from typing import Any, ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, SecretStr

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

#: The write-only secrets of §30 – §32 (``SetDirectoryConfig`` /
#: ``UpdateDirectoryConfig.bind_secret``, ``ScimTargetInput.credential``,
#: ``SsfStreamInput.authorization_header``). Each is **present or absent, never
#: ``null``** (CONTRACT §34.2 P12.3): sent to replace the stored value, omitted
#: to keep it. An explicitly assigned ``None`` therefore means "keep" and is
#: dropped by :meth:`ManagementModel.to_wire` rather than sent as a third state.
_NEVER_NULL_SECRETS = frozenset({"bind_secret", "credential", "authorization_header"})


class ManagementModel(BaseModel):
    """Base of every generated §27 request and response model."""

    model_config = ConfigDict(populate_by_name=True)

    _OPEN_ENUM_FIELDS: ClassVar[dict[str, frozenset[str]]] = {}
    """The open-enum fields of this model and the values this SDK knows,
    filled in by the generator per class. Empty on the base."""

    def has_member(self, name: str) -> bool:
        """Whether ``name`` was set: present on the wire for a decoded model,
        or assigned by the caller for one being built.

        This is how ``null`` is told from absence (§27.4 rule 5): a member the
        server sent as ``null`` and one it did not send both read as ``None``,
        and only the first is a member. ``name`` may be the wire name or the
        attribute name.
        """
        fields = type(self).model_fields
        attribute = next((key for key, info in fields.items() if name in (key, info.alias)), name)
        return attribute in self.model_fields_set

    def to_wire(self) -> dict[str, Any]:
        """This model as its JSON-ready wire body.

        Unset fields are omitted entirely (§27.4 rule 5) and secrets are
        unwrapped (§27.5). A field explicitly set to ``None`` *is* sent as
        ``null`` — that is the caller saying so, which is a different statement
        from leaving it out — except a write-only secret, which is present or
        absent and never ``null``: ``None`` there is omitted, and keeps the
        stored value (see :data:`_NEVER_NULL_SECRETS`).

        The other exception is ``tenant_scope`` — see :data:`_OMIT_WHEN_EMPTY`.

        Raises:
            ValidationError: locally, before anything is sent, when an open-enum
                field anywhere in the body holds a value this SDK does not know
                (CONTRACT §29.2, §32.2: such a value decodes, and is never sent).
        """
        _refuse_unknown_enums(self)
        exposed = _expose(self.model_dump(exclude_unset=True, by_alias=True))
        assert isinstance(exposed, dict)
        for field in _OMIT_WHEN_EMPTY:
            if field in exposed and exposed[field] == []:
                del exposed[field]
        for field in _NEVER_NULL_SECRETS:
            if field in exposed and exposed[field] is None:
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


def _refuse_unknown_enums(value: Any) -> None:
    """Walk a request body and refuse any open-enum value -- or open-union arm --
    this SDK does not know.

    Raises:
        ValidationError: naming the model and the field, never the value.
    """
    if isinstance(value, OpenUnionUnknown):
        from axiam_sdk.management._errors import local_refusal

        raise local_refusal(
            type(value).__name__,
            "type",
            "a union arm this SDK does not know decodes, but is never sent (CONTRACT.md §31.2)",
        )
    if isinstance(value, ManagementModel):
        for field, known in type(value)._OPEN_ENUM_FIELDS.items():
            held = getattr(value, field, None)
            items = held if isinstance(held, list) else [held]
            if any(isinstance(item, str) and item not in known for item in items):
                from axiam_sdk.management._errors import local_refusal

                raise local_refusal(
                    type(value).__name__,
                    field,
                    "a value this SDK does not know decodes, but is never sent "
                    "(CONTRACT.md §29.2, §32.2)",
                )
        for name in type(value).model_fields:
            _refuse_unknown_enums(getattr(value, name, None))
    elif isinstance(value, list | tuple):
        for item in value:
            _refuse_unknown_enums(item)
    elif isinstance(value, dict):
        for item in value.values():
            _refuse_unknown_enums(item)


class OpenUnionUnknown(ManagementModel):
    """Base of the catch-all arm of an open tagged union.

    It decodes any object whose tag this SDK does not recognise, so an arm added
    server-side does not fail the read it appears in. It keeps the discriminator
    and **nothing else**: only declared members are kept from a response, in a
    known arm and in an unknown one (CONTRACT §34.2 P12.1, §29.5), so a member the
    server sent beyond the tag -- a secret it should not have, say -- never
    survives to be logged. It is **never sent**: a value this SDK cannot
    describe must not be sent back (CONTRACT §31.2), so
    :meth:`ManagementModel.to_wire` refuses it locally, with a
    ``ValidationError``, before anything goes on the wire. Rendering it for a
    log line never fails: ``repr``, ``model_dump`` and ``model_dump_json``
    render it like any other model (CONTRACT §34.2 P12.2).
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


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
