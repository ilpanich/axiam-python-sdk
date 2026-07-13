"""Unit coverage for the NEW-4 replay primitives (``NonceStore`` and
``validate_freshness``) driving each individual rejection-reason branch and
the store's pruning/len bookkeeping, complementing the end-to-end
reference-vector paths in ``test_amqp_v2_replay.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from axiam_sdk.amqp._replay import NonceStore, validate_freshness


def _fresh_event(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "key_version": 2,
        "nonce": "nonce-abc",
        "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    event.update(overrides)
    return event


# ---------------------------------------------------------------------
# NonceStore: prune + len bookkeeping
# ---------------------------------------------------------------------


def test_nonce_store_records_and_detects_replay() -> None:
    store = NonceStore(ttl_seconds=100)
    assert store.check_and_record("n1", now=0.0) is True
    assert len(store) == 1
    # Same nonce within TTL -> replay.
    assert store.check_and_record("n1", now=10.0) is False
    assert len(store) == 1


def test_nonce_store_prunes_expired_entries() -> None:
    store = NonceStore(ttl_seconds=100)
    assert store.check_and_record("n1", now=0.0) is True
    # Well past expiry (0 + 100): the pruning pass drops n1, so the same
    # nonce is considered fresh again and len reflects only live entries.
    assert store.check_and_record("n2", now=250.0) is True
    assert len(store) == 1  # n1 was pruned before n2 was recorded


def test_nonce_store_uses_monotonic_when_now_omitted() -> None:
    store = NonceStore(ttl_seconds=100)
    assert store.check_and_record("n1") is True
    assert store.check_and_record("n1") is False


# ---------------------------------------------------------------------
# validate_freshness: each rejection reason branch
# ---------------------------------------------------------------------


def test_valid_event_passes() -> None:
    store = NonceStore(ttl_seconds=600)
    assert validate_freshness(_fresh_event(), store) is None


def test_missing_key_version() -> None:
    store = NonceStore(ttl_seconds=600)
    event = _fresh_event()
    del event["key_version"]
    assert validate_freshness(event, store) == "missing or invalid key_version"


def test_bool_key_version_is_rejected() -> None:
    store = NonceStore(ttl_seconds=600)
    # bool is a subclass of int but must be rejected as invalid.
    assert validate_freshness(_fresh_event(key_version=True), store) == (
        "missing or invalid key_version"
    )


def test_key_version_below_minimum() -> None:
    store = NonceStore(ttl_seconds=600)
    assert validate_freshness(_fresh_event(key_version=1), store) == (
        "unsupported key_version (replay protection unavailable)"
    )


def test_missing_issued_at() -> None:
    store = NonceStore(ttl_seconds=600)
    assert validate_freshness(_fresh_event(issued_at=12345), store) == (
        "missing or invalid issued_at"
    )


def test_unparseable_issued_at() -> None:
    store = NonceStore(ttl_seconds=600)
    assert validate_freshness(_fresh_event(issued_at="not-a-timestamp"), store) == (
        "unparseable issued_at"
    )


def test_stale_issued_at() -> None:
    store = NonceStore(ttl_seconds=600)
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert validate_freshness(_fresh_event(issued_at=old), store, skew_seconds=300) == (
        "stale issued_at outside allowed clock-skew window"
    )


def test_missing_nonce() -> None:
    store = NonceStore(ttl_seconds=600)
    assert validate_freshness(_fresh_event(nonce=""), store) == "missing or invalid nonce"
    assert validate_freshness(_fresh_event(nonce=123), store) == "missing or invalid nonce"


def test_replayed_nonce() -> None:
    store = NonceStore(ttl_seconds=600)
    now = datetime.now(timezone.utc)
    event = _fresh_event(nonce="dup", issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert validate_freshness(event, store, now=now) is None
    # A distinct event object with the same nonce, same store -> replay.
    event2 = _fresh_event(nonce="dup", issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert validate_freshness(event2, store, now=now) == "replayed nonce"


def test_naive_issued_at_treated_as_utc() -> None:
    store = NonceStore(ttl_seconds=600)
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    # No 'Z' / offset suffix -> parsed as naive then coerced to UTC.
    event = _fresh_event(issued_at="2026-01-01T12:00:00")
    assert validate_freshness(event, store, now=now) is None
