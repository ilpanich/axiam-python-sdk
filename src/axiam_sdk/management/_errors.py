"""The §27.4 rule 7 error sub-types.

CONTRACT.md §2 fixes the taxonomy at three error types and §27 does not widen
it. What it adds is a *classification* inside two of them, because a management
surface produces refusals §2 never had to describe — §2 has no 404 row at all,
since nothing before §27 could return one.

Python has real subclassing, so these are subclasses: every
``except AuthzError:`` written before §27 keeps working, and a caller who needs
the distinction catches the narrower type first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from axiam_sdk._errors import AuthzError, NetworkError

__all__ = [
    "ConflictError",
    "FieldError",
    "NotFoundError",
    "ValidationError",
]


@dataclass(frozen=True)
class FieldError:
    """One field-level complaint inside a :class:`ValidationError`."""

    field: str
    """The offending field's name, as the server names it."""

    message: str
    """What is wrong with it."""


class NotFoundError(AuthzError):
    """HTTP 404 — the resource does not exist, **or** belongs to another tenant.

    The server answers identically in both cases on purpose: a distinguishable
    "exists but not yours" lets a caller enumerate another tenant's ids. That is
    why this is an :class:`~axiam_sdk.AuthzError` rather than a category of its
    own — in a multi-tenant IAM the two really are one outcome.
    """

    def __init__(self, operation: str, message: str) -> None:
        """Build the error for ``operation`` (e.g. ``"users.get"``)."""
        super().__init__(message)
        self.operation = operation


class ConflictError(AuthzError):
    """HTTP 409 — a uniqueness or state conflict, such as a role name taken.

    Never retried (§27.4 rule 8): a 409 is the server telling the truth, not a
    transient fault, and a retry produces the identical answer one round-trip
    later.
    """

    def __init__(self, operation: str, message: str) -> None:
        """Build the error for ``operation`` (e.g. ``"roles.create"``)."""
        super().__init__(message)
        self.operation = operation


class ValidationError(NetworkError):
    """HTTP 400/422 — the request was rejected.

    §2 maps 400 to :class:`~axiam_sdk.NetworkError`, described as an "SDK
    programming error". That description was written when nothing but the SDK
    itself could produce a 400. On this surface a 400 is usually a *user's*
    invalid input — an email that is not an email, a slug already taken — and an
    application needs to tell that from a broken socket without matching on
    message text. The parent type is inherited from §2 rather than chosen here.
    """

    def __init__(
        self,
        operation: str,
        status: int,
        message: str,
        fields: list[FieldError],
        cause: BaseException | None = None,
    ) -> None:
        """Build the error, carrying the status and any per-field detail."""
        super().__init__(message, cause=cause)
        self.operation = operation
        self.status = status
        self.fields = fields


def parse_field_errors(body: Any) -> list[FieldError]:
    """Pull field-level detail out of an error body, on a best-effort basis.

    Two shapes are recognised — a list of ``{"field": ..., "message": ...}`` and
    an object keyed by field name. A body in neither shape yields no fields
    rather than an error: failing to parse an error body would replace a useful
    message with a useless one.
    """
    if not isinstance(body, dict):
        return []
    errors = body.get("errors")
    if isinstance(errors, list):
        return [
            FieldError(field=str(e["field"]), message=str(e.get("message", "")))
            for e in errors
            if isinstance(e, dict) and isinstance(e.get("field"), str)
        ]
    if isinstance(errors, dict):
        return [
            FieldError(field=str(k), message=v) for k, v in errors.items() if isinstance(v, str)
        ]
    return []
