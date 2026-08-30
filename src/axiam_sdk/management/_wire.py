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
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, SecretStr

__all__ = ["ManagementModel"]

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
