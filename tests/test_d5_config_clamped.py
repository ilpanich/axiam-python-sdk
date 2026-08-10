"""§19.2 rule 6 — a clamped setting is reported, not swallowed (contract 1.9).

Clamping is right: rejecting would break a caller whose configuration was
merely optimistic, and honoring would let one client become the herd §16 exists
to prevent. Doing it *silently* is the part that is wrong — an operator who set
a 60-second memo TTL believes they have one, and their staleness reasoning is
off by a factor of twelve with nothing to say so.
"""

from __future__ import annotations

from axiam_sdk import AxiamClient
from axiam_sdk._decision_memo import MAX_TTL_MS
from axiam_sdk._telemetry import ConfigClamped, TelemetryEvent

BASE_URL = "https://axiam-d5.test"


def _clamps(**kwargs: object) -> list[ConfigClamped]:
    """Build a client and return only its ConfigClamped events.

    Construction alone is the subject: the event fires at build time, before any
    request, because that is the only moment an operator can act on it.
    """
    events: list[TelemetryEvent] = []
    AxiamClient(
        base_url=BASE_URL,
        tenant_slug="acme",
        org_slug="acme",
        telemetry_hook=events.append,
        **kwargs,  # type: ignore[arg-type]
    )
    return [e for e in events if isinstance(e, ConfigClamped)]


def test_a_clamped_memo_ttl_is_reported() -> None:
    clamps = _clamps(decision_memo_ttl_ms=60_000.0)

    assert len(clamps) == 1
    assert clamps[0].setting == "decision_memo_ttl_ms"
    assert clamps[0].requested == "60000.0"
    assert clamps[0].effective == str(MAX_TTL_MS)
    assert clamps[0].contract_reference == "§17.1 rule 2"


def test_a_value_already_within_its_limit_reports_nothing() -> None:
    # An event that fires when nothing happened trains its reader to ignore it.
    assert _clamps(decision_memo_ttl_ms=2_000.0) == []


def test_the_disabled_default_reports_nothing() -> None:
    # Matters more than it looks: the memo is off by default, so without this
    # guard every client ever built would fire a zero-to-zero "clamp".
    assert _clamps() == []
    assert _clamps(decision_memo_ttl_ms=0.0) == []
