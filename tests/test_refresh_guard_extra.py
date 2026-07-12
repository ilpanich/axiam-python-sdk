"""Extra coverage for ``RefreshGuard._store_refreshed`` accepting an
attribute-style (non-mapping) ``do_refresh`` result, complementing the
dict-result path already exercised through the REST client tests.
"""

from __future__ import annotations

from dataclasses import dataclass

from axiam_sdk.token.refresh_guard import RefreshGuard


@dataclass
class _TokenTriple:
    access: str
    refresh: str | None
    exp: int | None


def test_store_refreshed_reads_object_attributes() -> None:
    guard = RefreshGuard()
    result = _TokenTriple(access="new-access", refresh="new-refresh", exp=4242)

    returned = guard.refresh_if_needed_sync(None, lambda: result)

    assert returned == "new-access"
    assert guard.cached_access_token() == "new-access"
    assert guard.cached_refresh_token() == "new-refresh"
    assert guard.cached_exp() == 4242


def test_store_refreshed_object_without_refresh_keeps_prior() -> None:
    guard = RefreshGuard()
    guard.seed("seed-access", "seed-refresh", exp=1)

    # An object whose refresh is falsy must NOT clobber the seeded refresh.
    result = _TokenTriple(access="rotated-access", refresh=None, exp=2)
    guard.refresh_if_needed_sync("seed-access", lambda: result)

    assert guard.cached_access_token() == "rotated-access"
    assert guard.cached_refresh_token() == "seed-refresh"


async def test_async_store_refreshed_reads_object_attributes() -> None:
    guard = RefreshGuard()
    result = _TokenTriple(access="a2", refresh="r2", exp=7)

    async def _do() -> _TokenTriple:
        return result

    returned = await guard.refresh_if_needed_async(None, _do)
    assert returned == "a2"
    assert guard.cached_exp() == 7
