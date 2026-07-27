"""``MemoryOidcStateStore`` tests (CONTRACT.md §12.3 rule 1): single-use
consume + 10-minute TTL, clamped for configured shorter TTLs in tests."""

from __future__ import annotations

import time

from pydantic import SecretStr

from axiam_sdk import MemoryOidcStateStore, OidcStateEntry


def _entry(state: str = "state-1") -> OidcStateEntry:
    return OidcStateEntry(
        state=state,
        nonce="nonce-1",
        code_verifier=SecretStr("verifier-1"),
        redirect_uri="https://app.test/callback",
    )


def test_save_then_consume_returns_the_entry() -> None:
    store = MemoryOidcStateStore()
    store.save(_entry())

    entry = store.consume("state-1")

    assert entry is not None
    assert entry.state == "state-1"
    assert entry.nonce == "nonce-1"
    assert entry.code_verifier.get_secret_value() == "verifier-1"
    assert entry.redirect_uri == "https://app.test/callback"


def test_consume_is_single_use() -> None:
    store = MemoryOidcStateStore()
    store.save(_entry())

    first = store.consume("state-1")
    second = store.consume("state-1")

    assert first is not None
    assert second is None


def test_consume_unknown_state_returns_none() -> None:
    store = MemoryOidcStateStore()
    assert store.consume("never-saved") is None


def test_ttl_expiry() -> None:
    store = MemoryOidcStateStore(ttl_seconds=0.05)
    store.save(_entry())

    time.sleep(0.1)

    assert store.consume("state-1") is None


def test_ttl_is_clamped_to_ten_minutes() -> None:
    from axiam_sdk._oidc_state import OIDC_STATE_TTL_SECONDS

    store = MemoryOidcStateStore(ttl_seconds=OIDC_STATE_TTL_SECONDS * 10)
    assert store._ttl_seconds == OIDC_STATE_TTL_SECONDS


def test_return_to_is_optional() -> None:
    store = MemoryOidcStateStore()
    store.save(_entry())
    entry = store.consume("state-1")
    assert entry is not None
    assert entry.return_to is None


def test_return_to_round_trips() -> None:
    store = MemoryOidcStateStore()
    entry_in = OidcStateEntry(
        state="state-2",
        nonce="nonce-2",
        code_verifier=SecretStr("verifier-2"),
        redirect_uri="https://app.test/callback",
        return_to="/dashboard",
    )
    store.save(entry_in)
    entry_out = store.consume("state-2")
    assert entry_out is not None
    assert entry_out.return_to == "/dashboard"


def test_size_reflects_unexpired_entries() -> None:
    store = MemoryOidcStateStore()
    assert store.size == 0
    store.save(_entry("a"))
    store.save(_entry("b"))
    assert store.size == 2
    store.consume("a")
    assert store.size == 1


def test_save_sweeps_expired_entries() -> None:
    """The sweep-on-save path (not just the expiry check inside
    ``consume``) actually deletes stale entries from the backing dict."""
    store = MemoryOidcStateStore(ttl_seconds=0.05)
    store.save(_entry("expires-soon"))
    time.sleep(0.1)

    store.save(_entry("triggers-sweep"))

    assert "expires-soon" not in store._entries
    assert store.size == 1


def test_repr_does_not_leak_code_verifier() -> None:
    entry = _entry()
    assert "verifier-1" not in repr(entry)
    assert "verifier-1" not in str(entry)
