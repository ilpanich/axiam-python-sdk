# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#50)

## [1.0.0-alpha27] - 2026-08-17

### Added

- §22.14 declarative reactor handler binding — ReactorRouter

### Changed

- Re-vendor CONTRACT.md 1.23, and fix a plaintext example default
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo

### Fixed

- Reformat the §22.14 README snippets for `ruff format`

## [1.0.0-alpha25] - 2026-08-16

### Added

- Ship the CONTRACT.md §22 reactor runtime (R2.5) (#46)
- Extend §10.1 rule 9 for DPoP and implement §21.7.2 (#43)
- Subject_token_type is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- Wire §20.3 challenge emission into the §11 guards, plus the example pair (#37)
- §20 — UMA 2.0 Protection API and ticket grant
- Report clamped settings via §19 ConfigClamped (contract 1.9)
- §16 retry, §17 memo, §18 close(), §19 telemetry (D5) (#34)
- Device grant, token exchange, logout helpers; re-vendor (D6)

### Changed

- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#45)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#42)
- Add the §20.7 required timeout assertion
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Format PERFORMANCE.md's example to ruff's blank-line rules
- Close the async residual — it is CPython, not the SDK (D1/J5)

### Fixed

- Close the coverage fail_under rounding loophole (precision=2)
- R5.7 — F-11/F-14 conformance follow-ups (F-08 already fixed) (#44)
- Export the token-type constants from axiam_sdk

## [Unreleased]

### Added

- **CONTRACT.md §22 — Reactors (AMQP extension actors).** New `axiam_sdk.amqp`
  reactor surface and `reactor_serve(dial, config, handler)`, the name §22.10's
  per-language table gives this runtime in Python: it consumes the
  server-declared per-reactor queue, verifies every event (§8 v2 —
  `key_version`, MAC, ±300 s freshness, nonce seen-set) *before* user code sees
  it, dispatches to a handler returning `allow()` / `deny()` / `mutate()` /
  `require_step_up()` / `abstain()`, then signs and publishes the reply. Also
  ships the event registry with its mutable-field allow-lists, the
  strictest-wins `failure_policy` composition (§22.8), an `amqps://`-only
  dialer (§8b), a §18 drain on cancellation, and `examples/reactor.py`.

  **§8's HMAC now runs in both directions**, and Python has *three* ways to
  produce a MAC that never verifies with no other symptom. The first is shared
  with every SDK: a reactor body signs `hmac_signature` as **`null`**, where
  `AuthzRequest` and `AuditEventMessage` omit it. The second and third are
  ours: `json.dumps` escapes every non-ASCII character into a `\uXXXX`
  sequence unless `ensure_ascii=False`, while `serde_json` escapes none of
  them; and `datetime.isoformat()` renders UTC as `+00:00` with six fractional
  digits, while the server's `chrono` emits `…T12:00:00Z` with no fraction at
  all on a whole second. `to_chrono_rfc3339()` is the fix for the third and the
  runtime always uses it. All three are pinned by the server-generated vectors
  in `testdata/reactor_v2_reference_vectors.json` — same master key, tenant and
  derived subkey as the §8 fixture, so one loader serves both.

  Three behaviours are structural rather than documented. The runtime **declares
  no topology**: the `ReactorTransport` protocol has no declare or bind method
  at all, the aio-pika adapter attaches with `get_queue(..., ensure=False)` so
  not even a passive declare goes on the wire, and tests drive both against
  fakes that *do* offer `declare_queue`/`declare_exchange`/`bind`, asserting
  none is ever called (§22.1). It **fails closed on its own errors**: a raising
  handler, a handler that outruns `timeout_ms`, an unparseable body, a closed
  window or a failed publication each publish *nothing*, so the operator's
  `failure_policy` decides rather than a synthesized `allow` from inside the
  library (§22.10 rule 2). And it **does not filter a patch** — one forbidden
  key rejects the whole patch server-side, and pruning it would leave the
  author believing a field was set (§22.4 rule 1).

  §22.7's hot-path exclusion is honoured by absence: the single check, the batch
  check and token introspection appear in no constant, no registry row and no
  example, and a test scans the reactor source for their names rather than
  trusting a comment.

  Not shipped, deliberately: a typed client for the §22.9 admin CRUD endpoints.
  That subsection is informative, and §22.9 specifically warns against
  re-deriving `PUT` merge semantics or the `failure_policy` re-derivation
  client-side — so the right surface is the server's. Reactor HKDF derivation
  also stays out, exactly as §8 already has it: §8.1 hands this SDK the
  pre-derived tenant subkey and it never sees the master key.

- **CONTRACT.md §21.7.2 DPoP proof verification (RFC 9449).** New `axiam_sdk._dpop`
  implements all ten checks and returns the proof key's RFC 7638 thumbprint, so a
  value passed on to rule 9 can only have come from a proof that verified.
  `InMemoryJtiStore` covers check 8 for a single process; the `JtiStore` protocol
  is a required argument, not an optional one, because there is no safe default
  that skips replay tracking.

  Two design points worth knowing: the algorithm is derived from the embedded
  `jwk` and the header's `alg` is **never read** (the test runs the real
  public-key-as-HMAC-secret forgery), and the `jti` is claimed **last**, after
  every other check passes, so a stream of invalid proofs cannot burn `jti`
  values out of the store and deny service to valid ones.

- **CONTRACT.md §10.1 rule 9 extended for DPoP (contract 1.16/1.17).**
  `CnfClaim` gains `jkt` (RFC 9449 §6.1), and a new `verify_token_binding(claims, *, certificate_thumbprint=..., dpop_thumbprint=...)` (keyword-only, because two same-typed optional thumbprints are exactly the pair a positional call transposes silently) applies the full
  ten-row rule against a certificate thumbprint, a verified DPoP key
  thumbprint, or **both**. A `cnf` naming both methods is a **conjunction** —
  satisfying only the more convenient one is not compliance — and a `cnf`
  naming nothing this SDK can check (including an *empty* one) is refused
  rather than read as unbound.

  `verify_certificate_binding` remains as the narrower entry point for transports that can only
  produce a certificate, and now **refuses** a DPoP-bound or both-bound token
  rather than ignoring the half it cannot check.

  New example: `examples/sender_constrained_guard.py`.

  Not a breaking change: an unbound token is still accepted with no certificate
  and no proof, asserted directly by the first test in the new group.

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `JwksVerifier.verify_sender_constrained(token, expected_tenant_id=..., presented_thumbprint=...)`
    — the guard entry point for a resource server that accepts bound tokens.
  - `verify_certificate_binding(claims, presented_thumbprint)` — the rule, standalone.
  - `certificate_thumbprint_s256(der)` — RFC 8705 §3.1 `x5t#S256`: base64url,
    **unpadded**, SHA-256 over the DER certificate. Under the stdlib `ssl` module, feed
    it `sock.getpeercert(binary_form=True)`.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate — asserted directly, because the
  likeliest wrong implementation of this rule is one that starts demanding certificates
  from every caller.

  `verify_access_token` deliberately does **not** apply rule 9: it has no transport to ask
  for a peer certificate, and folding the thumbprint in would make every existing caller
  pass `None` — which reads as "no certificate" and rejects every bound token.

  The thumbprint must come from the transport, never from a caller-settable header. A
  `cnf` naming an unimplemented method is **rejected**, never read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.

### Changed

- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **Re-sync vendored `CONTRACT.md`, `openapi.json` and `proto/` to contract 1.19**
  (upstream **R5.8**). The vendored copies had been pinned at the 1.15-era artifacts and
  drifted three contract revisions behind `ilpanich/axiam@main`. All five files are now
  byte-identical to upstream, and `proto/axiam/v1/reactor.proto` (contract 1.18 §22, the
  AMQP reactor protocol) is vendored here for the first time.

- **Regenerated the committed gRPC stubs** (`src/axiam_sdk/grpc/gen`) from the new protos
  with the pinned `grpcio-tools==1.78.*`, per D-04. The diff is exactly the SDK-Q10 field
  additions — no toolchain-version churn — and `bash scripts/gen_grpc.sh` is reproducible
  against it, so CI's drift gate stays clean.

- **CONTRACT.md §11.2 rule 9 — the gRPC decision reads `reason`, not `deny_reason`**
  (**SDK-Q10**, contract 1.19). `CheckAccessResponse` gains `reason` (proto field 4,
  explicit presence) carrying the same string the REST decision body has always called
  `reason`; `deny_reason` (field 2) is now `[deprecated = true]` and is removed at AXIAM
  2.0. The four duplicated decision-mapping sites (sync/async × single/batch) collapse
  into one `_to_decision` helper that reads `reason`, falling back to `deny_reason` only
  when `HasField("reason")` is false — that absence is precisely a pre-SDK-Q10 server, and
  is why the guard is presence rather than truthiness. `AccessResult` still exposes one
  `reason`, so this is not a breaking change for callers and nothing changes on the wire
  today.

  **Known residual, deliberately not taken here:** contract 1.19 also relaxes gRPC
  `subject_id` to optional (an *empty* value meaning "the subject in the verified token").
  `check_access`/`batch_check` still take `subject_id` as a required argument — relaxing it
  is a signature change and belongs in its own change, not in an artifact re-sync.


### Changed

- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `token_exchange`'s `subject_token_type` is now required.** It
  shipped optional, defaulting to `…:access_token` when `None` — which satisfied §15.7's "never
  inspect the subject token" while leaving the rule it serves unenforced: an optional argument
  with a default *is* a default the SDK applies whenever the caller says nothing. §15.1 now
  makes it required, on both `AxiamClient` and `AsyncAxiamClient`.

  Python refuses the call before any SDK code runs — a `TypeError`, with no wire call. A test
  asserts that, including zero requests.

  **`ACCESS_TOKEN_TYPE` and `JWT_TOKEN_TYPE` are now exported from `axiam_sdk`**, not just from
  the private `axiam_sdk._oidc`. They were reachable only through a private module — survivable
  while the type was optional and defaulted, and not once naming it is mandatory: every caller
  would have had to import a private module (or retype the URN) to make a call that now requires
  one.

  **Migration** — one line, naming what you were previously getting by silence:

  ```python
  exchanged = client.token_exchange(
      subject_token=user_token,
      subject_token_type=ACCESS_TOKEN_TYPE,  # <- add this
      scopes=["orders:read"],
  )
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only
  legal value when X4 landed. For a caller who actually held a refresh token, the old default
  traded the `invalid_request` that names the type for a generic `invalid_grant`.

### Added

- **§15.7 external-IdP subject tokens (X4).** `token_exchange` (and its async twin) can now
  exchange a token minted by a trusted external IdP — a partner's Entra, Okta or Keycloak — for
  an AXIAM token scoped to what the resolved AXIAM user may actually do. No new operation: the
  same method, plus a `subject_token_type` keyword and the new `JWT_TOKEN_TYPE` constant
  alongside the existing `ACCESS_TOKEN_TYPE`.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and
  a wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted
  by a test. (This shipped with an `…:access_token` default; contract 1.13 removed it — see
  *Changed* above.)

  Also asserted: an `actor_token` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as
  a different type; the one normative description — `the subject token's issuer is not
  configured for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your
  token* — reaches the caller intact; and nothing re-exchanges an exchanged token, which both
  server paths refuse because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.10 → 1.12
  plus §15.7), which also brings contract 1.11's lifted §12.6 deferral, contract 1.12's
  `/oauth2/*` error rows dispatching on the `error` field at any status, and the
  `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§20.3 challenge emission wired into the §11 guards.** A new `UmaChallenger` (realm,
  `as_uri`, PAT, client) passed as `uma_challenge=` to FastAPI's `require_access` or Django's
  `@require_access`: on denial the guard mints a permission ticket for the action just
  refused and sets `WWW-Authenticate: UMA` alongside the 403.

  **Opt-in by construction.** Emitting a challenge means minting a credential, so a guard
  that did it by default would turn every unauthorized request into a Protection API call.
  And **failure is not escalation**: if minting fails the denial still surfaces as a plain
  403, because a caller who was going to be refused is refused either way and an outage must
  not turn a deny into a 500 — still less into an allow.

  The challenger carries the *client* rather than a bound method, so the async guard takes
  the async client and the sync Django guard the sync one — neither has to bridge event loops
  to mint a ticket.

- **A runnable UMA example pair**: `examples/uma_resource_server.py` mints a PAT, registers a
  resource and guards a route with the challenger; `examples/uma_client.py` catches the
  refusal, parses the challenge, **makes the trust decision about `as_uri` explicitly**,
  exchanges the ticket and retries with the RPT. The client half exists partly to show what
  §20.3 is protecting: the `as_uri` is chosen by the server you just failed against, and the
  example refuses to redeem against a host that is not the issuer it already trusts.

- **§20 UMA 2.0 — Protection API and ticket grant (contract 1.10).** New methods on both
  `AxiamClient` and `AsyncAxiamClient`: `uma_register_resource` / `uma_read_resource` /
  `uma_update_resource` / `uma_delete_resource` / `uma_list_resources`, `uma_request_ticket`,
  `uma_exchange_ticket`, plus the module-level `WWW-Authenticate: UMA` helpers
  `uma_parse_challenge` and `uma_challenge_header`, and the `ResourceSet` /
  `RequestedPermission` / `RptPermission` / `RequestingPartyToken` / `UmaChallenge` models.

  Two behaviours are load-bearing rather than incidental, and both are asserted by counting
  requests. **`uma_exchange_ticket` never retries** — the one documented exception to the §16
  retry policy, because a ticket is consumed before the request is evaluated, so a retry
  cannot succeed and under concurrency is exactly the second redemption that
  ilpanich/axiam#302's measured residual describes. And **`uma_parse_challenge` does not
  exchange the ticket it parsed**: the `as_uri` names an authorization server the caller has
  not chosen to trust.

  The PAT is an explicit first argument on every Protection API call rather than being taken
  from the client's session, because that session is usually a *user* session and a ticket
  binds to a `client_id`.

- **§19 `ConfigClamped` event (contract 1.9).** A clamped setting is now reported at
  construction rather than applied silently — currently the §17.1 rule 2 memo TTL. Clamping
  is right; clamping *silently* is not: an operator who set a 60-second TTL believes their
  staleness bound is 60 seconds, and it is five. Nothing is emitted for a value already
  within its limit, or for the disabled default.

### Changed

- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` with the UMA paths.

## [Unreleased]

### Added

- **§16 bounded read-only retry policy** (`_retry.py`), wired into `check_access`/`can`/
  `batch_check` on **both** the sync and async clients: 3 attempts, 200 ms base, 5 s cap,
  **full jitter** over `[0, backoff]`, `Retry-After` honored as a floor. This SDK had no §16
  policy before — only §9.3's refresh-then-retry-once, which is a different mechanism — so
  §11.2 rule 5's requirement had gone unmet since it was written. Sync and async share the
  backoff arithmetic so the two cannot drift.
- **§18 shutdown semantics** on `close()`/`aclose()`: idempotent, memo cleared, and
  use-after-close raises `NetworkError` rather than silently reconnecting. Neither logs out
  nor reaches the network — the server-side session outlives the client object, and a
  `close()` that logged out would end every user's session on each deploy.
- **§19 telemetry hooks** (`_telemetry.py`) — `telemetry_hook=`, plus the frozen
  `RequestStart`/`RequestEnd`/`Retry`/`Refresh` events and `examples/telemetry_hook.py` with
  the OpenTelemetry mapping. A hook that raises cannot fail the operation that fired it, and
  no event payload can carry a token. One request pair per *attempt*, not per logical call,
  so callers can count real wire calls.
- **§17 decision memo — opt-in, off by default** (`_decision_memo.py`):
  `decision_memo_ttl_ms=`, clamped to 5000 ms, thread-safe. Allows and denies memoized
  identically, failures never memoized, cleared on any credential change.
  **Reads-your-own-writes is not guaranteed.**
- `retry_enabled=` (§16.6), default on. No knob for the attempt cap, base or delay cap:
  §16.1 forbids raising them.
- Public exports: `DecisionMemo`, `TelemetryEvent`, `TelemetryHook`, `RequestStart`,
  `RequestEnd`, `Retry`, `Refresh`.

### Changed

- Re-vendored `CONTRACT.md` at **1.8.1**. `openapi.json` unchanged — docs-only contract revs.
- `login`, `verify_mfa`, `refresh` and `logout` now clear the decision memo (§17.1 rule 9)
  and reject after close (§18.1 rule 4), on both clients.

- **`[speed]` extra (uvloop) and `PERFORMANCE.md` (D1/J5).** Benchmark run 5
  put this SDK's `check_access` at p50 40.2 ms / 311 rps against Go, Java and
  Rust's ~10 ms / ~850 rps, and the open question was what in `axiam_sdk` was
  slow. Measured against an out-of-process stub server doing no work at all,
  the answer is: nothing. `AsyncAxiamClient.check_access` costs ~50 µs/call
  more than raw `httpx` with the same cookie jar (~2% of client CPU), and every
  top cost centre in a `cProfile` of the hot path lives in `httpcore`/`anyio`.
  The ~310 rps is a per-process CPython ceiling — three client processes
  against the same zero-work stub reached 929 rps aggregate, each capped at
  ~310. `pip install "axiam-sdk[speed]"` installs uvloop, measured at −20%
  client CPU and p95 68 → 55 ms; the SDK still never installs a loop policy
  itself. `PERFORMANCE.md` carries the numbers, the method, and the guidance
  (scale with processes, not with in-flight calls per process).

## [1.0.0-alpha24] - 2026-08-04

### Added

- Apply the full CONTRACT §10.1 local-verification set
- Add verify_webhook signature verification helper (CONTRACT.md §13, T-145)

### Changed

- Device (mTLS) tokens now carry aud=axiam:m2m (#31)
- Service accounts can use login_client_credentials (#30)
- Pin CONTRACT §10.1 rule 8 against regression (§15.3.1) (#29)
- Bump pypa/gh-action-pypi-publish from 1.14.1 to 1.14.2

### Fixed

- Tighten the skew ceiling and diagnose the slug/UUID comparand (#27)

## [Unreleased]

### Added

- **CONTRACT §10.1 rule-8 regression tests (§15.3.1).** Rule 8 — "the decision is
  about the caller's credential and no other" — was enforced only by inspection
  here. SEC-085 satisfied rules 1–7 and was still an authentication bypass, so
  the absence of a guardrail is the condition that let it survive three reviews.

  This SDK is structurally safe from that shape: `_authenticate` is handed a
  verifier and a configured tenant, **never a logged-in client session**, so
  there is no second credential in scope to substitute. The new tests pin that
  property rather than assume it — one asserts a failed verification is not
  followed by one against another token, the other asserts the guard's signature
  is exactly `(request, verifier, configured_tenant)` and would fail the moment a
  client or session parameter were threaded in, which is how the PHP bug became
  reachable.

### Changed — BREAKING (configuration)

- **`MAX_CLOCK_SKEW_SECONDS` lowered 300 → 60 (§13.4 observation 5).** The old
  ceiling satisfied CONTRACT.md §10.1 rule 7 — it was named and bounded — but it
  was 5× the RECOMMENDED leeway and 5× what every sibling SDK fixes its value
  at, so an operator could widen the acceptance window on an expired token to
  five minutes and still be "conformant". The ceiling now equals the
  recommendation, matching the C++ SDK.

  `JwksVerifier(..., clock_skew_seconds=...)` above 60 now raises `ValueError`
  at construction instead of being accepted. The default (60) is unchanged, so
  this affects only deployments that explicitly widened the leeway.

### Fixed

- **Slug-vs-UUID tenant comparand now diagnoses itself (§13.4 observation 6).**
  AXIAM access tokens carry the tenant **UUID** in `tenant_id`, but this SDK's
  client is commonly configured with a tenant **slug**. A guard handed that slug
  rejects 100% of traffic — fail-closed and safe, but it presents as "every token
  is invalid" with nothing pointing at the cause. `JwksVerifier` now logs a
  single `WARNING` naming the real problem. It fires **once per verifier**, only
  when the configured value is not UUID-shaped while the claim is, and strictly
  *after* the rejection is decided — so it cannot be used as a log-flood lever
  and does not alter the verification outcome. A genuine cross-tenant rejection
  (UUID vs UUID) stays silent.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Implement OIDC/SSO relying-party helpers (CONTRACT.md §12)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Update grpcio requirement from <1.83,>=1.78 to >=1.78,<1.84
- Update grpcio-tools requirement
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Re-sync vendored CONTRACT.md to contract 1.5

### Fixed

- Enforce §9 rule 6 invariants in the oidc_refresh coalescer
- Accept any 2xx as success in revoke()

## [Unreleased]

### Changed — BREAKING

- **Local token verification now applies the complete CONTRACT.md §10.1
  minimum local-verification set.** Both §10 guards — the FastAPI
  `Depends(require_authenticated_user)` dependency (and the §11
  `require_access`/`require_role` helpers that compose with it) and the Django
  `AxiamAuthMiddleware` — route through a single new entry point,
  `JwksVerifier.verify_access_token(token, expected_tenant_id=...)`. This
  **tightens acceptance**; tokens the AXIAM server mints are unaffected (they
  always carry `exp` and never a future `nbf`), but a guard fed tokens from
  another signer sharing the organization-wide JWKS may start rejecting what
  it previously accepted. That is the intent.

  What changed in behaviour:

  - **`exp` is now REQUIRED (§10.1 rule 2).** Previously the guards checked
    `exp` only *if present*, so a signature-valid token carrying **no** `exp`
    — a permanent credential — was accepted. This is the `SEC-080` defect and
    it was not closed by the JWT library: PyJWT's `verify_exp` default only
    fires when the claim is present (its own `Options` docstring says so), so
    `jwt.decode` accepts a no-`exp` token. `exp` is now in an explicit
    `require` list. An `exp` of the wrong JSON type is also rejected,
    including a numeric *string* such as `"9999999999"`, which PyJWT silently
    coerces with `int()`.
  - **`nbf` is now honoured explicitly (§10.1 rule 3).** PyJWT enforced this
    by default already, but implicitly and untested; it is now pinned by
    tests and covered by the documented clock skew.
  - **Absent `tenant_id`, or no configured tenant, now fails closed
    (§10.1 rule 4)**, and a non-string `tenant_id` is rejected rather than
    compared.
  - **`iss` and `aud` are checked when configured (§10.1 rules 5-6).** Both
    are new, **optional, and unset by default** — no issuer or audience is
    ever assumed or hardcoded, so an existing deployment that configures
    neither sees no change from these two rules. Configure them via the new
    `JwksVerifier(expected_issuer=..., expected_audience=...)` keyword
    arguments, or, for Django, the new `AXIAM_EXPECTED_ISSUER` /
    `AXIAM_EXPECTED_AUDIENCE` settings. `RECOMMENDED_RESOURCE_SERVER_AUDIENCE`
    (`"axiam:user"`) is exported for guards fronting a user-facing resource
    server.
  - **Clock skew is now a named, bounded constant (§10.1 rule 7).** Rules 2
    and 3 allow `DEFAULT_CLOCK_SKEW_SECONDS` (60 s, the RECOMMENDED value)
    of leeway, overridable via `clock_skew_seconds` / Django's
    `AXIAM_CLOCK_SKEW_SECONDS` but hard-bounded by `MAX_CLOCK_SKEW_SECONDS`
    (300 s) — a value outside that range raises `ValueError` at construction
    rather than silently widening acceptance. Previously there was no leeway
    at all, so a token within 60 s of expiry that used to be rejected on a
    skewed clock is now accepted.

- **`JwksVerifier.verify()` has been renamed to
  `JwksVerifier.verify_signature_only_unchecked()`** (source-breaking for
  anyone who called it directly). The method is unchanged: it verifies the
  EdDSA signature and *nothing else*. §10.1 permits such a raw primitive but
  requires that its name make the omission obvious at the call site and that
  it not be the documented guard entry point — `verify_access_token` is now
  that entry point. Callers doing their own policy should switch to the new
  name; callers who expected `verify()` to be a guard were relying on a
  behaviour it never had and should switch to `verify_access_token`.

### Added

- Webhook signature verification (CONTRACT.md §13, T-145, contract 1.7):
  `axiam_sdk.webhook.verify_webhook(secret, signature_header, body, ...)`
  verifies the `X-Axiam-Signature: t=<unix_seconds>,v1=<hex>` header AXIAM
  sends on every webhook delivery — HMAC-SHA256 over
  `"<timestamp>.<raw_body>"`, keyed by the webhook secret's raw UTF-8 bytes.
  `body` MUST be the exact raw bytes off the wire (re-serializing parsed
  JSON breaks the MAC — documented in the README with a Flask/FastAPI
  example). Verification is constant-time (`hmac.compare_digest` over the
  *decoded* MAC bytes, never a hex-string `==`) with a two-sided freshness
  window (`abs(now - t) > tolerance` rejects both stale AND future-dated
  timestamps, default 300s) and a `now` injection seam for tests. `secret`
  accepts this SDK's §7 `Sensitive<T>` equivalent (`pydantic.SecretStr`) or
  a plain `str`. A signature header with no `v1` field is always a
  failure — never treated as "nothing to verify". On success returns a
  frozen `WebhookEvent` (`event_type`/`delivery_id` passed through from the
  caller-supplied `X-Axiam-Event`/`X-Axiam-Delivery` headers, since neither
  is covered by the MAC); on any failure raises the typed
  `WebhookVerifyError`, whose message never includes the expected/computed
  signature or the secret. New public module `axiam_sdk.webhook`
  (`verify_webhook`, `WebhookEvent`, `WebhookVerifyError`,
  `DEFAULT_TOLERANCE_SECONDS`); no new runtime dependency. Vendored
  CONTRACT.md re-synced to contract 1.7 (§13 added).

### Fixed

- `oidc_refresh` single-flight coalescer (CONTRACT.md §9 rule 6, contract
  1.6): the async coalescer vacated its in-flight slot **before** publishing
  the outcome (rule 6a, the same shape as the Go SDK bug) and its joiners
  awaited the shared `asyncio.Future` directly, so a single cancelled joiner
  — an `asyncio.wait_for` timeout, a cancelled request task — cancelled that
  *shared* future: the leader's own publication then raised
  `InvalidStateError` after a **successful** wire call (losing the rotated
  token set), and every other participant got a spurious `CancelledError`
  instead of the outcome. Cancelling the caller that *started* the burst
  likewise tore the shared wire call down under all the joiners. The slot now
  holds one `asyncio.Task` that every participant joins via
  `asyncio.shield`, so per-caller cancellation only cancels that caller; the
  slot is cleared by an identity-checked done callback on that same task, so
  publication provably precedes vacating (6a), a settled-but-uncleared slot
  is joined rather than re-dialled (6b), a lagging attempt cannot clear a
  newer attempt's entry (6c), and a caller arriving after full settlement
  performs its own fresh refresh (6d). The sync coalescer's waiters re-tested
  *slot occupancy* to decide whether their own refresh was still in flight
  (rule 6b), so a waiter that had not yet been rescheduled when a newly
  arrived caller legitimately started the next refresh was handed **that**
  refresh's outcome — typically the `invalid_grant` of replaying the token
  the waiter's own (successful) refresh had just consumed. Waiters now hold
  and block on the publication of the attempt they joined. Unchanged:
  exactly one wire call per burst with the outcome shared (§9 rules 1–2), no
  retry on refresh failure (§9.3 — the same exception object reaches every
  caller), and no lock held across the network call.

- `revoke()` (sync and async): a `2xx` other than the literal `200` — e.g. a
  `204 No Content` — is now treated as success, matching CONTRACT.md §12.1
  note 5 as corrected in contract 1.5 ("any 2xx MAY be treated as success,
  RECOMMENDED") and every other SDK's behavior. Previously only `200` was
  accepted and a legal `204` revocation response would incorrectly raise
  (cross-SDK conformance review F-08). A `5xx` still raises `NetworkError`
  and a `401` carrying an `OAuth2ErrorResponse` body still raises
  `OAuthProtocolError` without entering the §9 refresh guard, both unchanged.

### Added

- OIDC / SSO relying-party helpers (CONTRACT.md §12, contract 1.4): the nine
  canonical operations — `oidc_discover`, `oidc_begin`, `oidc_exchange`,
  `oidc_refresh`, `login_client_credentials`, `introspect`, `revoke`,
  `sso_start`, `sso_complete` — added directly to both `AxiamClient` (sync)
  and `AsyncAxiamClient` (`async def` twins under the same names, SDK-Q08).
  Shared pure logic (PKCE via `secrets`/`hashlib`/`base64`, ID-token
  validation, discovery cache, tenant/client-credential resolution) lives in
  new `_oidc.py`/`_oidc_pkce.py`/`_oidc_idtoken.py`/`_oidc_state.py` modules;
  no new runtime dependency was added. New public types: `OidcConfiguration`,
  `IdTokenClaims`, `AuthorizationRequest`, `OidcTokenSet`,
  `IntrospectionResult`, `SsoStartResult`, `SsoCompleteResult`,
  `OidcStateStore`/`OidcStateEntry`/`MemoryOidcStateStore`, and
  `OAuthProtocolError` — a language-idiomatic sub-type of the existing
  `AuthError`, so existing `except AuthError:` code keeps matching it
  unchanged. `access_token`/`refresh_token`/`id_token`/`client_secret`/
  `code_verifier` are `pydantic.SecretStr`; `state`/`nonce` remain plain
  strings (not secrets, per §12.3 rule 2). ID-token validation (§12.4)
  reuses the existing `JwksVerifier` (extended, not forked) and raises
  `AuthError` with a stable `reason` — `invalid_alg`, `unknown_kid`,
  `invalid_signature`, `invalid_issuer`, `invalid_audience`,
  `token_expired`, or `nonce_mismatch`. `oidc_refresh` runs under the
  existing §9 single-flight refresh guard (extended with
  `run_exclusive_sync`/`run_exclusive_async`), so it can never interleave
  with a concurrent cookie-session `refresh()`, and de-duplicates its own
  concurrent callers. New framework glue: `axiam_sdk.fastapi.oidc_login_router`
  (a two-route `APIRouter`) and `axiam_sdk.django.oidc.oidc_login_views` (a
  `(login_view, callback_view)` pair). Conformance statement updated to
  "§1–§12 (including §6.1 mTLS)".

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Bump actions/setup-python from 6.3.0 to 7.0.0 (#13)
- Bump pypa/gh-action-pypi-publish from 1.14.0 to 1.14.1 (#14)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#15)
- Ratchet coverage floor 96%->97% (#17)

### Fixed

- Format README code blocks for ruff 0.16 and pin ruff (#18)

## [1.0.0-alpha16] - 2026-07-22

### Added

- Implement get_user_info (CONTRACT.md §1.1)

### Changed

- Vendor userinfo.proto + CONTRACT 1.3 (§1.1 gRPC userinfo)

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Supply organization context for login/refresh (CONTRACT §5.1) (#12)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

## [Unreleased]

### Added

- gRPC-only `get_user_info` operation (CONTRACT.md §1.1, contract 1.3): the
  low-latency counterpart of the server's REST `GET /oauth2/userinfo`
  endpoint, invoking `axiam.v1.UserInfoService/GetUserInfo` (new vendored
  `proto/axiam/v1/userinfo.proto`) over the SDK's existing gRPC channel,
  reusing the same `authorization`/`x-tenant-id` metadata as `check_access`.
  Exposed as `get_user_info()` on both `AuthzGrpcClient` (sync) and
  `AsyncAuthzGrpcClient` (async); the request is empty (identity from the
  bearer token) and it returns a typed `UserInfo(sub, tenant_id, org_id,
  email, preferred_username)` where `email`/`preferred_username` are `None`
  unless the token carries the `email`/`profile` scope respectively. A
  no-token call raises `AuthError` client-side without a wire call, and a gRPC
  `UNAUTHENTICATED` drives the same single-flight refresh-and-retry-once path
  as `check_access` (§9). `UserInfo` is re-exported from the package root.
  Conformance statement unchanged (§1–§11; the new operation lives in §1).
- Client-certificate / mutual-TLS (mTLS) support (CONTRACT.md §6.1):
  `AxiamClient` and `AsyncAxiamClient` gained additive `client_cert=` /
  `client_key=` parameters (PEM certificate chain + PEM private key, each
  `str` or `bytes`), applied to both the REST (httpx `SSLContext`) and gRPC
  (`grpc.ssl_channel_credentials`) transports. The gRPC authorization clients
  and `build_channel_credentials` accept the same parameters. The two must be
  supplied together (otherwise a construction-time `ValueError`), a non-PEM
  value is rejected, and presenting a client certificate never relaxes strict
  server verification (§6). The private key is secret material — never logged,
  exposed via a getter, or shown in `repr` (§6.1 rule 3 / §7). Conformance
  statement updated to "§1–§11 (including §6.1 mTLS)".

## [1.0.0-alpha2] - 2026-07-16

### Added

- Declarative authorization helpers (CONTRACT.md §11): `require_access` /
  `require_role` for FastAPI (`axiam_sdk.fastapi`, async, takes
  `AsyncAxiamClient`) and Django (`axiam_sdk.django.decorators`, new module,
  sync `AxiamClient` with async-view support). Both compose strictly on top
  of the existing §10 authentication guards, check the authenticated
  request's caller (`subject_id`) rather than the SDK client's own identity,
  and fail closed (503) on a transport failure while calling the authz
  endpoint. `AxiamClient.check_access`/`AsyncAxiamClient.check_access` gained
  an additive `subject_id` keyword argument (CONTRACT.md §11.2) alongside
  their unchanged existing signatures.
- Conformance statement updated to CONTRACT.md §1–§11.

## [1.0.0-alpha] - 2026-07-15

First alpha release of the official Python client SDK for AXIAM. This is an
early, pre-production preview published to PyPI for evaluation and feedback —
the public API may still change before the beta and stable releases.

> Distributed on PyPI as `1.0.0a1` (the PEP 440 spelling of `1.0.0-alpha`).

### Added

- REST client covering the AXIAM API surface (authentication, authorization
  checks, tenant/user/role/resource management).
- gRPC client for low-latency authorization checks (generated stubs shipped in
  the package; no `protoc` needed by consumers).
- FastAPI and Django integration helpers for guarding application routes.
- Strict TLS by default with no certificate-verification bypass surface.
- Fully type-annotated (`mypy --strict`) with a 100%-documented public API.
- Runnable examples for the common authentication and authorization flows.

[1.0.0-alpha]: https://github.com/ilpanich/axiam-python-sdk/releases/tag/v1.0.0-alpha
