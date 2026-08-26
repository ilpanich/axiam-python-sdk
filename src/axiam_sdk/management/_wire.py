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


class ManagementModel(BaseModel):
    """Base of every generated §27 request and response model."""

    model_config = ConfigDict(populate_by_name=True)

    def to_wire(self) -> dict[str, Any]:
        """This model as its JSON-ready wire body.

        Unset fields are omitted entirely (§27.4 rule 5) and secrets are
        unwrapped (§27.5). A field explicitly set to ``None`` *is* sent as
        ``null`` — that is the caller saying so, which is a different statement
        from leaving it out.
        """
        exposed = _expose(self.model_dump(exclude_unset=True, by_alias=True))
        assert isinstance(exposed, dict)
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
