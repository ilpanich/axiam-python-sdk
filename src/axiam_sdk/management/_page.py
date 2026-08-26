"""Pagination for the §27 management surface.

Twenty of the 146 operations take ``offset``/``limit`` and answer with the
envelope ``{items, total, offset, limit}``. The other thirteen collection reads
answer with a bare array and are **not** paginated — §27.4 rule 4 forbids
modelling those as a page, because a ``Page`` reporting ``total == len(items)``
is indistinguishable from a real one right up to the moment a caller relies on
``total``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")
M = TypeVar("M", bound=BaseModel)

__all__ = ["Page", "PageRequest"]


@dataclass(frozen=True)
class PageRequest:
    """Where a paginated read starts, and how much of it to take.

    ``limit`` is deliberately optional with no SDK-side default: §27.4 rule 4
    forbids silently truncating, and a client-side default does exactly that
    while leaving the caller no way to tell a short page from a complete one.
    """

    offset: int = 0
    """How many items to skip."""

    limit: int | None = None
    """How many items to take. ``None`` lets the server decide."""


@dataclass(frozen=True)
class Page(Generic[T]):
    """One page of a paginated management read."""

    items: list[T]
    """The items on this page."""

    total: int
    """How many items exist in the whole set, across every page."""

    offset: int
    """The offset this page starts at."""

    limit: int
    """The page size the server applied."""

    def has_more(self) -> bool:
        """Whether another page follows this one."""
        return bool(self.items) and self.offset + len(self.items) < self.total


def page_query(page: PageRequest | None) -> dict[str, str | None]:
    """The query parameters a :class:`PageRequest` contributes.

    ``limit`` is omitted entirely when unset rather than sent as ``0`` — the
    server reads ``limit=0`` as "none", which would return an empty page.
    """
    request = page or PageRequest()
    return {
        "offset": str(request.offset),
        "limit": None if request.limit is None else str(request.limit),
    }


def page_of(raw: Any, model: type[M]) -> Page[M]:
    """Parse a ``{items, total, offset, limit}`` envelope into a :class:`Page`.

    ``total`` is read from the envelope and never inferred from ``len(items)``:
    the whole point of the type is that the two differ.
    """
    envelope = raw if isinstance(raw, dict) else {}
    items = envelope.get("items") or []
    return Page(
        items=[model.model_validate(item) for item in items],
        total=int(envelope.get("total", 0)),
        offset=int(envelope.get("offset", 0)),
        limit=int(envelope.get("limit", 0)),
    )


def collect_pages(
    start: PageRequest | None,
    fetch: Callable[[PageRequest], Page[T]],
) -> list[T]:
    """Walk a paginated read to exhaustion, concatenating every page.

    The ``list_all`` shape §27.4 rule 4 requires. The walk stops on an empty
    page even when ``total`` disagrees, so a misreporting server costs one
    wasted request rather than an unbounded loop.
    """
    request = start or PageRequest()
    out: list[T] = []
    while True:
        page = fetch(request)
        out.extend(page.items)
        nxt = page.offset + len(page.items)
        if not page.items or nxt >= page.total:
            return out
        request = PageRequest(offset=nxt, limit=request.limit)


async def collect_pages_async(
    start: PageRequest | None,
    fetch: Callable[[PageRequest], Awaitable[Page[T]]],
) -> list[T]:
    """Async twin of :func:`collect_pages`, with identical stopping rules."""
    request = start or PageRequest()
    out: list[T] = []
    while True:
        page = await fetch(request)
        out.extend(page.items)
        nxt = page.offset + len(page.items)
        if not page.items or nxt >= page.total:
            return out
        request = PageRequest(offset=nxt, limit=request.limit)
