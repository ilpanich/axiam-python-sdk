# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
