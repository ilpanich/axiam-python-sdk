# Performance — where the time actually goes

> Written to close D1/J5 of
> [`improvement-after-run5-benchmark.md`](https://github.com/ilpanich/axiam/blob/main/claude_dev/improvement-after-run5-benchmark.md).
> Every number below is measured, not estimated, and the method is in
> [Reproducing](#reproducing) so you can disagree with it on evidence.

## The finding

Benchmark run 5 recorded this SDK's `check_access` at **p50 40.2 ms / p95
116.8 ms / 311 rps** against AXIAM, while the Go, Java and Rust SDKs sat at
~10 ms / ~60 ms / 835–869 rps at the same 16-way concurrency. The obvious
reading — "the async rewrite did not work, something in `axiam_sdk` is slow" —
is wrong, and the measurement that settles it is simple: **run the same client
against a server that does no work at all.**

Against a stub HTTP server in a separate process, answering a fixed JSON body
with zero computation, at the same 16 in-flight calls:

| client | p50 | p95 | throughput | client CPU |
|---|---|---|---|---|
| raw `httpx.AsyncClient`, no cookie jar | 44.0 ms | 51.5 ms | 347 rps | 1 589 µs/call |
| raw `httpx.AsyncClient` + cookie jar | 47.2 ms | 58.4 ms | 324 rps | 2 121 µs/call |
| `AsyncAxiamClient.check_access` | 47.3 ms | 57.9 ms | 324 rps | 2 172 µs/call |

Three things follow.

**1. The SDK is not the residual.** It costs ~50 µs per call more than raw
`httpx` with the same cookie jar — around 2% of the client's CPU per request.
A `cProfile` of the hot path puts every top cost centre in `httpcore` and
`anyio`: `connection_pool._assign_requests_to_connections` alone calls
`connection.is_idle` **611 times per request**, and six module-import lookups
happen per call inside `anyio`/`httpcore` themselves. No `axiam_sdk` frame
appears in the top 28.

**2. ~310 rps per process is the CPython ceiling, not an AXIAM number.** The
stub server is not the bottleneck: three client processes driving it
concurrently reached 320 + 308 + 301 = **929 rps aggregate**, each capped at
the same ~310. Run 5's 311 rps against the real AXIAM server is that same
ceiling — the server was contributing nothing measurable to it.

**3. The p50 target in the plan is arithmetically unreachable in one
process.** At 16 in-flight calls, on a single-threaded event loop, with ~2 ms
of CPU per request, latency cannot go below `16 × 2 ms ≈ 32 ms` no matter how
fast the server answers — the calls queue behind each other on the loop
thread. That is what the 44–47 ms p50 above is: almost entirely client-side
queueing against a server with zero latency.

## What to do about it

### Use uvloop (`pip install axiam-sdk[speed]`)

Measured on the same harness:

| loop | p50 | p95 | throughput | client CPU |
|---|---|---|---|---|
| stdlib `asyncio` | 47.4 ms | 68.2 ms | 314 rps | 2 182 µs/call |
| `uvloop` | 45.0 ms | 54.7 ms | 337 rps | 1 735 µs/call |

−20% client CPU and a materially tighter tail, for one line in your
application's startup. The SDK does **not** install a loop policy for you —
choosing the event loop belongs to the application, not to a library it
happens to import:

```python
import uvloop
from axiam_sdk import AsyncAxiamClient


async def main() -> None:
    async with AsyncAxiamClient(base_url=..., tenant_slug=..., org_slug=...) as client:
        ...


uvloop.run(main())  # Python 3.11+
```

### Scale with processes, not with in-flight calls

Because the ceiling is CPU on one event-loop thread, raising
`max_connections` or the number of concurrent `await`s past ~16 buys latency,
not throughput. The thing that does scale is processes:

```
1 process  × 16 in-flight  ≈  310 rps
3 processes × 16 in-flight ≈  929 rps      (measured)
```

Under `gunicorn`/`uvicorn`, that is `--workers N`. This is the ordinary
CPython answer and not specific to this SDK; it is written down here because
the benchmark table invites the opposite conclusion.

### Keep one client

`AsyncAxiamClient` builds its `httpx.AsyncClient` lazily and holds it for the
client's lifetime, so connections are pooled and reused across calls. Building
a client per request throws that away and adds a TCP (and, under TLS, a
handshake) round trip to every call. Use `async with` — or one module-level
client and an explicit `await client.aclose()` at shutdown.

## What was ruled out

The plan listed four suspects. Measured, in order:

1. **Per-request session/connector churn** — not present. One
   `httpx.AsyncClient` is built lazily and reused; `_session.py` holds it for
   the client's lifetime.
2. **Sync-in-async on the hot path** — the CSRF token read/write takes a
   `threading.Lock`, and JSON parsing plus `pydantic` model construction run
   inline. None of them reach the profile's top 28; together they are inside
   the ~50 µs the SDK adds over raw `httpx`. Moving them to an executor would
   cost more in hand-offs than it saves, and a fast path that skipped
   `AccessResult` construction would trade the typed contract for well under
   1% of the request.
3. **uvloop absent** — real, measured above, now shipped as `[speed]`.
4. **Per-call object churn / pydantic on `check()`** — see (2). Not indicted.

The cookie jar is the one non-trivial SDK-adjacent cost: `http.cookiejar` is
pure Python, and httpx re-runs its policy and domain matching on every request
and response, which the table above prices at ~530 µs/call (25% of client
CPU). It is not removable — the AXIAM session *is* cookies (`axiam_access`,
`axiam_refresh`, `axiam_csrf`, CONTRACT.md §3), and reimplementing cookie
policy to save CPU is not a trade worth making in an auth client.

## Reproducing

The measurements above come from a stub server in a separate process (a
threaded stub in the client's own process competes for the GIL and is
indistinguishable from client cost), 200 warm-up calls, 1 200–1 500 timed
calls, latency measured *after* acquiring the concurrency semaphore so
queueing outside the in-flight window is excluded. The AXIAM benchmark
harness' Python bench (`benchmarks/sdk/python/bench.py` in the server repo)
uses the same shape against a real server.

If you reproduce a materially different result — particularly one where
`axiam_sdk` frames appear high in a `cProfile` of `check_access` — that is a
bug worth filing, and this document is the baseline to file it against.
