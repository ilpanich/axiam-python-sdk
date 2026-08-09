"""Telemetry hooks — CONTRACT.md §19.

Wiring metrics to an AXIAM client **without this package depending on any
metrics library**. The sink below aggregates in-process so the example runs with
no extra dependencies; the block at the bottom shows the exact mapping onto
OpenTelemetry, which is a drop-in replacement for the body.

Run::

    python examples/telemetry_hook.py
"""

from __future__ import annotations

from collections import defaultdict

from axiam_sdk import AxiamClient, RequestEnd, Retry, TelemetryEvent

#: (operation, outcome) -> [count, total_ms]
_requests: dict[tuple[str, str], list[float]] = defaultdict(lambda: [0.0, 0.0])
#: operation -> retry count
_retries: dict[str, int] = defaultdict(int)


def record(event: TelemetryEvent) -> None:
    """A §19 sink. Aggregates in memory; see the OTel mapping below."""
    if isinstance(event, RequestEnd):
        # One pair per ATTEMPT, not per logical call (§19.2 rule 5), so counting
        # these gives the real number of wire calls — including the ones a retry
        # made on your behalf.
        stat = _requests[(event.operation, event.outcome)]
        stat[0] += 1
        stat[1] += event.duration_ms
    elif isinstance(event, Retry):
        # §16.5 — the reason this event exists. A retried-then-succeeded
        # operation is otherwise invisible: the caller sees a slow success and
        # no signal that the server is failing. Alert on this rate, not on the
        # error rate, or a degrading server looks healthy right up until the
        # retries stop being enough.
        _retries[event.operation] += 1


def report() -> None:
    print("--- requests (per attempt) ---")
    for (operation, outcome), (count, total_ms) in _requests.items():
        print(f"  {operation:<20} {outcome:<8} count={int(count)} mean={total_ms / count:.0f}ms")
    print("--- retries ---")
    if not _retries:
        print("  (none)")
    for operation, count in _retries.items():
        print(f"  {operation:<20} {count}")


def main() -> None:
    client = AxiamClient(
        base_url="https://axiam.example.com",
        tenant_slug="acme",
        org_slug="acme",
        telemetry_hook=record,
    )

    # This will fail — the host does not resolve — which is the point: a failing
    # call still emits a RequestEnd carrying the failure, and the §16 retries
    # are visible as Retry events. Against a real server the same sink reports
    # the success path.
    try:
        decision = client.check_access("read", "00000000-0000-0000-0000-000000000000")
        print(f"allowed={decision.allowed} ({decision.reason_code or 'no reason code'})")
    except Exception as err:  # noqa: BLE001 — the example is about the telemetry.
        print(f"check failed as expected in this example: {type(err).__name__}")

    report()

    # §18: release the client's local resources. Does not log out.
    client.close()


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# The same sink, against OpenTelemetry
# ---------------------------------------------------------------------------
#
# This package deliberately ships no ``opentelemetry-*`` dependency — §19's
# whole point is that you choose your metrics stack. With the OTel API in YOUR
# requirements, ``record`` becomes::
#
#     from opentelemetry import metrics
#
#     meter = metrics.get_meter("axiam-sdk")
#     duration = meter.create_histogram("axiam.client.request.duration")
#     retry_counter = meter.create_counter("axiam.client.retries")
#
#     def record(event: TelemetryEvent) -> None:
#         if isinstance(event, RequestEnd):
#             duration.record(
#                 event.duration_ms / 1000.0,
#                 {
#                     "axiam.operation": event.operation,
#                     # The path TEMPLATE, never a substituted URL: a metric
#                     # label carrying a UUID is a cardinality bomb.
#                     "http.route": event.path_template,
#                     "http.response.status_code": event.status or 0,
#                     "axiam.outcome": event.outcome,
#                 },
#             )
#         elif isinstance(event, Retry):
#             retry_counter.add(
#                 1,
#                 {"axiam.operation": event.operation, "axiam.attempt": event.attempt},
#             )
#
# Two rules to keep in mind when writing any adapter:
#
#   * **Do not block.** Hooks run on the calling path (§19.2 rule 4). Every
#     mature metrics library already buffers; if yours does not, buffer on your
#     side rather than doing I/O here.
#   * **Do not enrich events from elsewhere.** The event dataclasses are frozen
#     with a fixed field set precisely so this surface cannot leak a token into
#     a metrics backend (§19.2 rule 3). Adding, say, the current
#     ``Authorization`` header would defeat that on your side of the boundary.
#
# A hook that raises is caught and swallowed by the SDK (§19.2 rule 2) — an
# authorization check is never failed by telemetry — but that is a backstop,
# not a licence to let a sink raise.
