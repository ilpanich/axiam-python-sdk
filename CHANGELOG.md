# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Contract **1.51**, the dogfooding remediation
([`claude_dev/dogfooding-findings-fix-plan.md`](https://github.com/ilpanich/axiam/blob/main/claude_dev/dogfooding-findings-fix-plan.md)'s
C-3 task; CONTRACT.md §1.1.1, §5.2 rule 1, §6.1 rules 6-10, §10.1 rule 9,
§27.6.1, §27.13). `CONTRACT.md`, `openapi.json` and `management-registry.json`
are re-vendored byte-for-byte from `ilpanich/axiam@56fbe44`; `proto/` was
already identical. The §27 surface (162 operations, up from 160) and the
gRPC stubs (`token.proto` added to `scripts/gen_grpc.sh`) are regenerated
from them.

### Added

- **Acting tenant** (§5.2 rule 1). `AxiamClient(acting_tenant=...)` /
  `AsyncAxiamClient(acting_tenant=...)` at construction, and
  `client.acting_tenant(tenant_id)` / `client.clear_acting_tenant()` on an
  existing client — Python's own handle idiom rather than the reference's
  builder method, since a Python client is already a plain value that can be
  shallow-copied. `acting_tenant(...)` returns a *new* handle sharing the
  session (cookie jar, refresh guard, decision memo) with the client it was
  called on; the original is unchanged, so two handles can act on two
  tenants at once over one session. `X-Axiam-Tenant` is sent on `/api/v1`
  REST requests of such a handle **only when set** — a client that never
  asks for it sends exactly what it sent before. Once a login result has
  reported the principal's reach, the on-client form refuses client-side
  (`AuthError`, no wire call) unless the principal is `organization_level`,
  and refuses a tenant outside `reachable_tenant_ids`; a client holding no
  login result (a service account, an injected token, OPAQUE/SSO/WebAuthn)
  sends the header regardless and lets the server's `403` answer. The §17
  decision-memo key includes the acting tenant. REST-only: the gRPC
  interceptor reads no acting-tenant metadata.
- **`authenticate_device()`** on both clients, the mTLS device login (§6.1
  rules 6-10): `POST /api/v1/auth/device`, no body, returns
  `DeviceToken(access_token: SecretStr, token_type, expires_in)`. Reachable
  only on a client built with `client_cert=`/`client_key=` — otherwise
  `AuthError` before any wire call. The token is adopted as the client's
  credential (`Authorization: Bearer`, cookie jar cleared and an explicit
  empty `Cookie` header sent) rather than living beside the jar, because the
  server reads the `axiam_access` cookie before `Authorization` and a
  leftover session cookie would otherwise win. No refresh token exists by
  design (D-6): a `401` on this credential, at login or later, is
  `AuthError` with no refresh attempt; a `429` is `NetworkError`, not an
  authentication failure, and is not retried. New example:
  [`examples/device_mtls_provisioning.py`](examples/device_mtls_provisioning.py).
- **gRPC `validate_token()` / `introspect_token()`** (§1.1.1, §10.3) on
  `AuthzGrpcClient` and `AsyncAuthzGrpcClient`, on the same channel and
  interceptor `check_access`/`get_user_info` already use. Every response
  field is modelled, including `cnf` as `TokenCnf | None` — absent and empty
  stay distinct. `TokenValidation.verify_possession(...)` /
  `TokenIntrospection.verify_possession(...)` apply CONTRACT.md §10.1 rule 9
  against caller-supplied evidence, delegating to the same
  `axiam_sdk._jwks.verify_token_binding` the local `JwksVerifier` uses — a
  gRPC-validating guard and a JWKS-verifying one never disagree about
  whether a token is a bearer token. A no-token call raises `AuthError`
  client-side, exactly like `get_user_info`.
- **`JwksVerifier.verify_with_proofs(token, *, expected_tenant_id,
  certificate_thumbprint=, dpop_thumbprint=)`**, the full §10.1 set
  including rule-9 evidence in one call, replacing the
  `verify_access_token()` + separate `verify_token_binding()` pairing the
  now-fixed default entry point made unsafe (see Breaking).
- **Manifest additions** (§27.6.1, §27.5 rule 5):
  - `ResourceSpec.metadata: dict[str, Any] | None`, sent on Create; on
    Update only when stated and it differs from the server's value as a
    whole-object JSON comparison, never a key-by-key merge — unstated is
    silent, matching every other field.
  - `RoleBinding = str | ScopedRoleBinding` on `GroupSpec.roles`,
    `UserSpec.roles` and the new `ServiceAccountSpec.roles`.
    `ScopedRoleBinding(role=, resource=, inherit=True)` is the object shape;
    a bare role key is unchanged and still compiles every existing
    manifest. One role bound twice to one subject — plain and scoped
    included — is rejected by `plan()`/`apply()` before any request, and so
    is a global role bound with `inherit=False`. A changed binding is
    unassign-then-assign (the server has no update endpoint for it),
    carries the server's `tenant_scope` across unchanged, and re-assigns
    the previous binding when the new assign fails — the step's outcome
    names whether the restore itself also succeeded. `inherit` reaches the
    wire only as `False`, so an inheritable binding's request body stays
    byte-for-byte what it was before contract 1.51.
  - `ServiceAccountSpec(key, name, description=None, roles=())`. Reconciled
    by `name`, which the server does not enforce uniqueness on: `plan()`
    fails, before any write, when a stated name matches more than one
    existing account. A `Create` outcome carries the one-time
    `client_secret` (`ApplyReport.client_secret(manifest_key)`) — set even
    when a *later* step of the same `apply` fails, because each step's
    outcome is recorded as it completes. `apply()` never calls
    `rotate_secret` to reconcile; a second `apply` against an unchanged
    tenant is `NoChange`.
  - `axiam_service_account` decorator, wired into `define_manifest` and
    `collect_manifest`.
  - `webhooks` stays unspecified in contract 1.51 and is **declined** — see
    Declined below.
- **Contract 1.51 model changes** (§27.13), from the regenerated surface:
  `SubjectAltNameDns` / `SubjectAltNameIp` (`SubjectAltName` is their
  union); `inherit` on `RoleGroupAssignment`, `RoleUserAssignment` and
  `RoleServiceAccountAssignment`, defaulting to `True` when absent from the
  wire (a server older than 1.51 omits it, and an inheritable assignment is
  what every assignment meant before the field existed); `RoleAssignment`
  gained an `.inherits` property reading the same way.

### Fixed

- **`scripts/gen_management.py` generated `SubjectAltName` — an externally
  tagged `oneOf` (`{"dns": ...}` vs `{"ip": ...}`, no shared discriminator
  field) — as an empty class with no fields**, because the generator's
  `discriminated()` detector only recognised internally-tagged unions (a
  shared enum-valued tag). It emitted `{}` on the wire, which the server
  refuses. A new `externally_tagged()` detector fixes the generation; the
  regenerated `SubjectAltNameDns | SubjectAltNameIp` union is the "Added"
  entry above.
- **The same generator would have produced a required `inherit` field**,
  which fails to decode a role-side assignment listing from a server older
  than contract 1.51 (which omits it). `DEFAULT_TRUE_FIELDS` makes the
  generator emit `= True` for it instead, matching §27.13's S-10 rule 3.

### Breaking

- **`JwksVerifier.verify_access_token` — and so every guard built on it
  (`AxiamUser`, the §11 dependency/middleware, and the §28 MCP guard) —
  accepted a sender-constrained token as an ordinary bearer token, against
  CONTRACT.md §10.1 rule 9.** This is the SDK's documented default
  verification entry point, and it had no transport evidence to check a
  `cnf` claim against, so it should have refused any token carrying one; it
  admitted them instead. Checked specifically because C-3 named this as the
  first thing to verify, before any new feature: every `authenticate_device()`
  token now carries `cnf.x5t#S256` (mTLS device certificates are new in this
  same release), so the gap was no longer theoretical — a device token would
  have passed the default guard with no proof of possession. `verify_access_token`
  now refuses any token carrying `cnf` (`AuthError`); `verify_with_proofs`
  (Added, above) and `verify_sender_constrained` (unchanged, and itself
  fixed in the same commit — it called the now-refusing
  `verify_access_token` internally and would otherwise have rejected every
  bound token, including a correctly-proven one) are the accept-with-evidence
  paths. An unbound token is unaffected either way.
  `tests/test_local_verification_set.py`'s
  `test_verify_access_token_does_not_apply_rule_9` — which pinned the
  defect — is inverted to
  `test_verify_access_token_applies_rule_9_with_no_evidence`, asserting the
  refusal.
- `GroupSpec.roles`, `UserSpec.roles` and `ServiceAccountSpec.roles` are
  `tuple[RoleBinding, ...]`, not `tuple[str, ...]`. A bare role key still
  compiles and compares equal to a plain binding; code that iterates the
  tuple assuming every element is a `str` has to change.
- `ManagementManifest` gains `service_accounts`, and `ResourceSpec` gains
  `metadata`. Both are dataclasses with defaults, so positional
  construction is unaffected; a caller that lists every field by keyword
  against `__dataclass_fields__` would see the new ones.

### Declined

- **§27.6 `webhooks` is not a manifest resource in this release.** The
  contract names it under §27.6 alongside the other management namespaces
  but leaves its shape unspecified for the manifest surface in 1.51 (no
  natural key, no drift semantics defined) — the same reading the Rust
  reference SDK gave it. Adding a `WebhookSpec` ahead of the contract would
  mean guessing at semantics no other SDK agrees on. Revisit when the
  contract defines it.

pytest tests: 1653 passed on `origin/main` before this work began; 1736
passed at the end (0 failed). Coverage (`pytest --cov=axiam_sdk
--cov-report=lcov`, the same invocation `.github/workflows/coverage.yml`
runs): 98.57% on `origin/main`, 98.56% on this branch — both clear the
`fail_under = 98` floor in `pyproject.toml`.

## [1.0.0-beta16] - 2026-09-19

### Added

- MCP resource-server helpers (CONTRACT.md §28, contract 1.48)

- **MCP resource-server helpers** (CONTRACT.md §28, RFC 9728 + RFC 6750,
  contract 1.48) — the resource-server half of the Model Context Protocol
  authorization handshake, on both the FastAPI dependency and the Django
  middleware/decorators. AXIAM is the authorization server and implements
  none of §28; this section is for a service — typically an MCP server —
  fronted by this SDK's own guard.

  Three operations, all pure local computation (no network I/O, so §16's
  retry policy and §9's single-flight refresh do not apply): top-level
  `protected_resource_metadata(...)` and `bearer_challenge(...)` build the
  RFC 9728 document and the RFC 6750 `WWW-Authenticate` value respectively;
  `serve_protected_resource_metadata(...)` registers the unauthenticated
  route that serves the document and is framework-specific —
  `axiam_sdk.fastapi.serve_protected_resource_metadata(app, metadata,
  verifier=None)` and `axiam_sdk.django.mcp.serve_protected_resource_metadata
  (urlpatterns, metadata, expected_audience=None, resource_metadata_url=None)`.

  **Opt-in and additive.** A new `resource_metadata_url` option — on
  `JwksVerifier` for FastAPI, `settings.AXIAM_RESOURCE_METADATA_URL` for
  Django — is what turns §28 on. Left unset, every guard in this SDK is
  byte-for-byte what it was before §28 existed: no `WWW-Authenticate` header
  on any response, no status changed, no body changed. Setting it *requires*
  `expected_audience` (`JwksVerifier`'s existing §10.1 row 6 option /
  `settings.AXIAM_EXPECTED_AUDIENCE`) to also be set — the SDK refuses the
  configuration at construction, naming both options, rather than publishing
  a resource identifier it does not check `aud` against.

  Every 401 a §28-configured guard emits carries the challenge: no `error`
  parameter when the request carried no credential at all, `error=
  "invalid_token"` when one was presented and rejected — expired, wrong
  tenant, wrong audience, bad signature, an unsatisfiable `cnf`, a revoked
  `sid` are all `invalid_token`, indistinguishably, and the guard never adds
  an `error_description` to that automatic challenge. Exactly one class of
  403 gains a header: a `require_access`/`@require_access` call that named a
  `scope=` argument whose decision came back `reason_code="no_grant"`; every
  other 403 (`denied_by_rule`, an absent/unrecognised `reason_code`, a
  scope-less denial, a `require_role` failure, a CSRF refusal) carries none.
  The JSON body never changes — `insufficient_scope` appears only in the
  header, the body stays the unchanged §11 `authorization_denied` shape.
  Where a route also carries a §20.3 `uma_challenge`, the UMA challenge wins
  and exactly one `WWW-Authenticate` value is ever emitted.

  `protected_resource_metadata`/`bearer_challenge` validate and refuse
  (`ValidationError`, CONTRACT.md §2's existing taxonomy — §28 adds no new
  error type); neither ever normalises, trims or escapes a bad value to make
  it pass.

  **Divergences from the TypeScript reference (T9b), both structural rather
  than behavioural, and both documented in code:** FastAPI is a
  dependency-only integration with no ASGI-middleware variant, so
  `serve_protected_resource_metadata` registers a route carrying no
  `Depends(...)` at all rather than exempting one path from a global guard
  that does not exist on this surface. Django has no central
  application/router object the way Express, Fastify and FastAPI do — URL
  routing is a plain `urlpatterns` list — so that list stands in for `app`,
  and because `urls.py` and `settings.py` are separate modules,
  `serve_protected_resource_metadata`'s §28.5 rule 3 cross-check takes the
  two raw setting values rather than a shared verifier/session object.

  This SDK ships no resource-server-side gRPC or AMQP guard — `axiam_sdk.grpc`
  and `axiam_sdk.amqp` are this SDK acting as AXIAM's *client* over those
  transports, not a guard protecting an integrator's own service — so §28.5
  rule 8's optional gRPC `www-authenticate` metadata form and its AMQP
  prohibition both find no guard to attach to or forbid anything on; neither
  is wired up.

  Tests: the five §28.9 required tests, on §28.9's own fixture — the two
  framework-independent ones (document shape + validation negatives,
  challenge quoting + refusals) in `tests/test_mcp.py`; the three that need a
  live guard (401 with the challenge, 403 `insufficient_scope`, a wrong-`aud`
  token refused) duplicated against both frameworks in
  `tests/test_fastapi_mcp.py` and `tests/test_django_mcp.py`, alongside each
  surface's own off-by-default regression asserting the header's absence
  rather than merely the status.

  `CONTRACT.md`/`openapi.json` re-synced to contract 1.48 from
  `ilpanich/axiam`'s `claude_dev/mcp-authorization-server-plan.md` branch
  (`claude/t21-2a-public-clients`), ahead of that repository's `main` until
  Phase 21 lands. The §27 management surface (`src/axiam_sdk/management/`,
  `tests/test_management_surface_generated.py`) is regenerated from the
  newer `openapi.json` in the same change — `scripts/gen_management.py
  --check` fails otherwise — picking up, additively, T21.2's public-client
  `token_endpoint_auth_method: none` (and the now-optional
  `OAuth2ClientCreatedResponse.client_secret`), T21.3's `allowed_resources`
  RFC 8707 audience allow-list, and T21.4's `ManagedBy` client-provenance
  discriminator; no existing management operation, request or response
  shape changes. **Superseded in part by F-28-01 below**: re-syncing from a
  phase branch is what contract 1.49 now forbids, and both artefacts are
  re-synced once, from `main`, after Phase 21 lands.

### Changed

- Re-sync CONTRACT.md 1.50 and management-registry.json from axiam main @ da94e1d04

- F-28-01 — re-sync CONTRACT.md 1.49, openapi.json and management-registry.json from axiam main @ e4c62180e

- Conformance statement at contract 1.48; record F-28-01 (T21.9 T9d)

- **Breaking — `CreateRegistrationTokenResponse.initial_access_token` is now a
  `SecretStr` (contract 1.50, CONTRACT.md §27.5).** The field was a plain `str`;
  it is the one-time RFC 7591 §1.2 initial access token, so it belonged in the
  §27.5 sensitive table from the day `oauth2_clients.create_registration_token`
  shipped and was omitted. As a plain `str` it appeared in every `repr()`, log
  line and `model_dump_json()` of the response — the leak §7 rule 1 and §27.5
  exist to prevent. The §27.5 table now lists **fifteen** operations, not
  fourteen.

  **Migration.** Reading the token now takes the explicit reveal, as it already
  does for the other fourteen fields:

  ```diff
  - token = created.initial_access_token
  + token = created.initial_access_token.get_secret_value()
  ```

  No plain-`str` accessor is kept alongside it: the plain accessor is precisely
  the leak. The wire shape is unchanged — `openapi.json` and `proto/` do not
  move, only this SDK's type does.

  The vendored artefacts are re-synced from **`ilpanich/axiam` `main` @
  `da94e1d04`**:

  | Artefact | Blob |
  |---|---|
  | `CONTRACT.md` (1.50) | `28c163e32d25` |
  | `openapi.json` | `b75e30eaa359` (unchanged) |
  | `management-registry.json` | `aab87fd79910` |

  `proto/` already matched and is unchanged; the gRPC stubs regenerate
  byte-identically. The §27 surface is regenerated in the same commit
  (`python scripts/gen_management.py`); the operation count stays at **162**
  across 24 namespaces and the only generated movement is this one field's
  type, on both the sync and async handles. The README's conformance statement
  now names contract 1.50. Upstream: ilpanich/axiam#480.

- **Contract conformance statement corrected** (CONTRACT.md Closing Notes,
  §28.11 row R-3, T21.9 T9d). The README named §28 but still claimed
  *contract 1.38*, while the vendored `CONTRACT.md` was already at 1.48. The
  contract's own rule is that the statement follows the code; it now reads
  *contract 1.48*.

- **F-28-01 — the vendored contract artefacts are re-synced from a merged
  `main` (contract 1.49).** This repository's copies had been re-synced above
  from a **phase branch**, which kept moving afterwards (CONTRACT.md §28.11 row
  R-1). They are now re-synced once, from **`ilpanich/axiam` `main` @
  `e4c62180e`**, as contract 1.49 requires:

  | Artefact | Blob |
  |---|---|
  | `CONTRACT.md` (1.49) | `2493348c3285` |
  | `openapi.json` | `b75e30eaa359` |
  | `management-registry.json` | `4619f441aac0` |

  `proto/` already matched and is unchanged; the gRPC stubs regenerate
  byte-identically. The §27 management surface is regenerated in the same
  commit (`python scripts/gen_management.py`), moving from **160 to 162
  operations** across the same 24 namespaces:

  - `client.oauth2_clients.create_registration_token(body)` and
    `client.oauth2_clients.list_registration_tokens()`, sync and async —
    `POST` / `GET /api/v1/oauth2-clients/registration-tokens`, the RFC 7591
    initial access tokens (T21.4). The create is not retried (§27.4 rule 8),
    like every write here. New models `CreateRegistrationTokenRequest`,
    `CreateRegistrationTokenResponse` and `RegistrationTokenResponse`.
  - New model `CimdPolicy` (T21.5 client ID metadata documents), carried as an
    optional `cimd` field on `OidcPolicy`, `SetOrgSettings` and
    `TenantSettingsOverride`.

  T21.2–T21.4's `none` auth method, optional `client_secret`,
  `allowed_resources` and `ManagedBy` were already picked up by the
  phase-branch regeneration above and do not move.
  `tests/test_management_surface_generated.py` is regenerated with it. No
  hand-written operation changes signature or behaviour. The README's
  conformance statement now names contract 1.49.

## [1.0.0-beta15] - 2026-09-15

### Added

- Sign-csr certificates, passkey-first-factor setup (contract 1.45) (#81)

- **`certificates.sign_csr` — an end-entity certificate from a caller-supplied
  CSR** (CONTRACT.md §27, contract 1.45). `client.certificates.sign_csr(models.SignCertificateCsrRequest(...))`
  on both clients, `POST /api/v1/certificates/sign-csr`, generated straight
  from the re-vendored registry — the operation count moves **159 → 160**
  across the same 24 namespaces.

  The response is the existing `Certificate`, **not** `GeneratedCertificate`:
  there is no key to return, the caller supplied the CSR and kept its own
  private half, and AXIAM never sees it. `SignCertificateCsrRequest` carries
  no `subject`/`key_algorithm` either — both are read out of the CSR
  server-side, the only place they can be stated without the row and the
  certificate disagreeing. A model round-trip test in
  `tests/management/test_semantics.py` pins that `Certificate` has no
  `private_key_pem` field at all, so §27.5's sensitive-fields table staying
  silent about this operation is a property of the type, not an oversight.

- **`webauthn_setup_register_start` / `webauthn_setup_register_finish` — a
  passkey or security key as the first factor at forced MFA enrolment**
  (CONTRACT.md §24.1, §25.2 rule 2, contract 1.45). The WebAuthn twin of
  `mfa_setup_enroll` / `mfa_setup_confirm`, on both clients:
  `POST /api/v1/auth/webauthn/setup/register/start` and `.../finish`, taking
  the `setup_token` a `login()` `mfa_setup_required` outcome carries. A
  tenant that enforces MFA no longer means every newly-created user has to
  own a TOTP app to get past their first sign-in.

  Both calls take **no session** — the setup token is the only credential and
  it travels in the body — and neither attaches this client's own session
  credential, even when one is already configured: they go through a new
  credential-free request path (`_Session._credential_free_request` /
  `_send_sync_credential_free` / `_send_async_credential_free`) that never
  touches `Client.build_request()`'s cookie-jar merge, rather than the shared
  `_send_sync`/`_send_async` choke point every other call uses.
  `webauthn_setup_register_finish` adopts credentials **exactly** as
  `mfa_setup_confirm` does on a `200` — the same success path, so cookies are
  absorbed, the §17 decision memo is cleared, and the org/tenant claims are
  cached identically — and, on a `403`, surfaces the tenant's
  attestation-policy message verbatim instead of a fixed string (§24.4 rule
  1), because it is the only way the person holding the key learns that a
  different one would work. A `503` from `start` is not retried, the same
  posture `webauthn_register_start` already has.

  Tests in `tests/test_webauthn.py` (sync and async) cover the happy path,
  the `401`/`400`/`403`/`503` statuses, that neither call requires or sends a
  session credential — asserted on the transport, with a fully-configured
  session seeded first, so the assertion is meaningful rather than
  vacuously true — and that `setup_register_finish`'s adoption is
  indistinguishable from `mfa_setup_confirm`'s: the memo is cleared, the
  access cookie is present, and the CSRF token this response set is captured
  and echoed on the very next state-changing request.

### Changed

- Re-vendor CONTRACT.md at 1.46

- Re-vendored `CONTRACT.md` (1.44 → 1.45), `openapi.json` and
  `management-registry.json` from `ilpanich/axiam@3d5b279`. `proto/axiam/v1/`
  did not change upstream and was re-verified as already identical rather
  than re-copied. The README's §27 operation count moves to **160** in both
  places it is stated.

## [1.0.0-beta14] - 2026-09-13

### Added

- §10.4 revocation feed, §21.3.1 alias refusal, §16 T-262 tests

- **CONTRACT.md §10.4 — an optional session-revocation feed poller (contract
  1.44).** `RevocationFeed`, handed to a verifier as
  `JwksVerifier(..., revocation_feed=...)`.

  Local verification proves a token was issued and has not expired, never that
  the session behind it still exists — so a logout or a role removal does not
  reach a token already in a caller's hands until it expires, up to fifteen
  minutes. A deployment that publishes `GET /oauth2/revocations` lets a guard
  close that to **one poll interval**, for one cacheable fetch per interval
  rather than the round trip per request gRPC introspection costs.

  Nothing changes unless you pass one. It never fetches on the request path
  after the first call — `verify_access_token` reads a cached set. And it never
  fails closed: an unreachable feed, a non-`200`, an unparseable body or an
  unknown `alg` all behave exactly as no feed at all, and specifically not as
  an empty list, which would assert that nothing has been revoked. A token with
  no `sid` is never matched against it, and there is no fallback to `jti`.
  `RevocationFeed` is thread-safe, so one instance can serve several guards.

- Two tests pinning CONTRACT.md §16 against the server's new answer for a
  contended write — `503` with `Retry-After: 1` (AXIAM T-262). No behaviour
  changed: §16.3 already retried `5xx` on an eligible operation and §16.1
  already honoured `Retry-After` as a floor. Both halves are asserted through
  the public surface with a wire count, because a retry policy nobody
  exercises that way is the failure §16.7 exists for.

### Changed

- Re-vendor the final CONTRACT.md (1.44) from the axiam branch

- **A malformed `mtls_endpoint_aliases` entry now raises instead of falling
  back to the top-level endpoint** (CONTRACT.md §21.3.1 vector C, contract
  1.43).

  Falling back looks like the safe answer and is the dangerous one: the caller
  asked to authenticate with a certificate, the operator published something
  unusable, and sending the certificate to the front-channel host authenticates
  nothing while appearing to work.

  "Malformed" means not an absolute URL, or a scheme weaker than the top-level
  endpoint the alias replaces — comparing like with like, so an `http` alias
  for an `http` endpoint (a development deployment) is still accepted.

  The refusal is an `AuthError`, not a `NetworkError`: nothing failed in
  transport, and §16.3 retries `NetworkError` and only `NetworkError`, so the
  other choice would have retried a permanent misconfiguration three times and
  reported it as a transient one.

  A client built without `client_cert=` never reads the member at all, so a
  deployment whose aliases are malformed cannot break the clients that never
  use them.

- Re-vendored `CONTRACT.md` (1.44), `openapi.json` and
  `management-registry.json` from `axiam`, and regenerated the §27 management
  surface. The surface gains `SessionResponse`, whose T-254 replay fields were
  published server-side at 1.0.0-beta13.

## [1.0.0-beta13] - 2026-09-12

### Added

- Accept an optional dpop_jkt on oidc_par (RFC 9449 §10.1)

- Model the two RFC 8414 §2 discovery members added in 1.42

- Prefer RFC 8705 §5 mtls_endpoint_aliases on mTLS calls

- **RFC 8414 §2 discovery metadata (SDK contract 1.42, CONTRACT.md §21.5).**
  `OidcConfiguration` gains `code_challenge_methods_supported` and
  `token_endpoint_auth_signing_alg_values_supported`. AXIAM publishes `["S256"]`
  and `["PS256", "ES256", "EdDSA"]`; both members were absent until the first
  OpenID Foundation conformance run reported them NOT FOUND.

  Both are modelled **optional** even though `openapi.json` marks them
  required, which §21.5 is explicit about: RFC 8414 defines no default for
  either, so absence does not mean "S256" — it means a conforming client cannot
  establish that PKCE is available at all. A required field here would reject
  both a pre-1.42 AXIAM document and every non-AXIAM OP that omits it, which is
  why every neighbouring member of this model is optional too. The SDK does not
  consult either member: §12 always sends `code_challenge_method=S256` and has
  no `plain` fallback to negotiate away.

- **`dpop_jkt` on `oidc_par` (RFC 9449 §10.1, CONTRACT.md §26.1).** Both
  `AxiamClient.oidc_par` and `AsyncAxiamClient.oidc_par` take an optional
  `dpop_jkt`, sent in the `POST /oauth2/par` form **only when supplied** —
  absent and empty are different requests, and an empty thumbprint would bind
  the authorization code to a key nobody holds. Pass the RFC 7638 SHA-256
  thumbprint of the key the token request will prove possession of;
  `axiam_sdk._dpop.jwk_thumbprint_s256` computes one from a JWK. Caller-supplied
  rather than derived: this SDK verifies DPoP proofs, it does not mint them.

  `request_uri`, which `PushedAuthorizationRequest` also gained server-side in
  1.42, is deliberately **not** exposed. RFC 9126 §2.1 makes it the one
  authorization parameter a client MUST NOT push; the server models it so it can
  refuse it, and a client able to send one is a client able to chain one pushed
  request into another.

- **RFC 8705 §5 `mtls_endpoint_aliases` (SDK contract 1.40, CONTRACT.md §21.3
  rule 2).** `OidcConfiguration` gains an optional `mtls_endpoint_aliases`
  field (the new `MtlsEndpointAliases` model, exported from `axiam_sdk`), and
  the §12 helpers now prefer an alias over the top-level entry of the same name
  on any call made over mutual TLS — that is, from a client constructed with
  `client_cert=`/`client_key=`. Affected: `oidc_exchange`, `oidc_refresh`,
  `login_client_credentials`, `device_poll` and `token_exchange` (all
  `token_endpoint`), plus `introspect`, `revoke`, `device_authorize` and
  `oidc_par`. Sync and async clients alike.

  Absence of the field means "this deployment terminates mutual TLS on the
  issuer's own host", never "mTLS is unsupported": a client without it keeps
  using the conventional endpoints instead of failing. Every field of
  `MtlsEndpointAliases` is itself optional, so an endpoint a partial object
  does not name falls back rather than failing the whole document. No alias is
  synthesised for `authorization_endpoint`, `end_session_endpoint` or
  `jwks_uri`, which are front-channel or public. `issuer` does not move, and
  §12.4 rule 3 still compares a token's `iss` against it by exact string —
  including for a token minted at an alias endpoint.

### Changed

- Record the 1.40 -> 1.42 re-sync in CHANGELOG and README

- Pin that a tenant-scoped discovery endpoint is not doubled

- Re-vendor CONTRACT/openapi/registry at 1.42 and regenerate §27

- Re-vendored `CONTRACT.md`, `openapi.json` and `management-registry.json` from
  `ilpanich/axiam` at SDK contract **1.42**, spanning two revisions (the
  previous vendor was 1.40). The registry grows from 155 to **158 operations
  across 24 namespaces**: `privacy.list_consents`,
  `privacy.grant_scope_consent` and `privacy.withdraw_scope_consent`
  (`GET/POST/DELETE /api/v1/account/consents[/oidc-scopes[/{client_id}]]`).
  The §27 surface is regenerated, not hand-edited.

  Also regenerated into the §27 models: `ClientAuthMethod` gains
  `client_secret_basic`; `CreateOAuth2ClientRequest`,
  `UpdateOAuth2ClientRequest` and `OAuth2ClientResponse` gain
  `authn_request_params` and `browser_sso`; `SecuritySettings` gains `oidc`;
  `SetOrgSettings` and `TenantSettingsOverride` gain `default_locale` and
  `sensitive_scopes_enabled`; `User` and `UpdateUser` gain `address`,
  `phone_number` and `phone_number_verified_at`; and the `Address`,
  `AuthnRequestParamsMode`, `ConsentView`, `GrantScopeConsent`, `OidcPolicy`
  and `UserInfoPostForm` schemas are new.

  `proto/` is byte-identical upstream, so the gRPC stubs are untouched.

- The earlier 1.40 re-vendor entry below is unchanged and still accurate for
  that revision; this one supersedes its version and operation count.

  Additive and server-side: no deployment publishes `mtls_endpoint_aliases`
  until an operator sets `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL`, so every existing
  consumer keeps working unchanged against every existing deployment. No public
  API was removed or renamed.

### Unchanged (reviewed against the 1.42 server behaviour)

Recorded because "we looked and nothing was needed" is the answer, and a later
reader should not have to re-derive it.

- **ID tokens no longer carry `tenant_id`, `org_id` or `email`** (OIDC Core
  §5.4). `IdTokenClaims` types none of the three and keeps unrecognised claims
  via `extra = "allow"` (§12.1), so nothing in this SDK reads them off an ID
  token and nothing silently empties. The identifiers still arrive in the
  access-token claims and from gRPC `GetUserInfo`.

- **Refresh-token rotation now supersedes rather than revokes, with a 60 s
  grace.** §9 rule 6 single-flight exists to stop the SDK making a *second*
  wire call with an already-rotated token; a server-side tolerance does not
  make replaying one correct, and no test here asserts the server's rejection.

- **`/oauth2/authorize` is content-negotiated on `Accept`.** This SDK never
  calls that endpoint server-side — it builds the URL and hands it to a browser
  — so there is no request to add a header to and no error body to parse.

- **`error_description` is now rendered as RFC 6749 §5.2 NQSCHAR.** Every
  error-mapping assertion here runs against this repo's own mocks, and
  dispatch is on the `error` field, never on the prose (§12.3 rule 3).

- **DPoP `htu` canonicalisation.** `canonical_htu` is untouched: §21.7.2 check 6
  is unchanged in 1.42 and requires `htu` to be compared with query and
  fragment removed and *no further normalisation* — a normalising comparison is
  where two unequal URIs become equal. The server's own comparison rule is not
  this verifier's.

- **DPoP single-use proofs at resource endpoints.** §21.7.2 check 8 already
  required an SDK-side `jti` single-use check within the freshness window, and
  `InMemoryJtiStore` already implements it.

- **`client_secret_basic` is now advertised.** §5 rule 3 still forbids sending
  an `Authorization: Basic` header to `/oauth2/*`; the enum member is a
  registration value a management caller may set, not a change to this client's
  own `client_secret_post` default.

- **The `claims` request parameter is now honoured.** No SDK surface sends one,
  and it is deliberately not added to `oidc_par`.

- **Discovery now publishes `?tenant_id=` inside the advertised endpoint URLs.**
  This SDK replaces rather than appends (`httpx.URL.copy_merge_params`, whose
  `QueryParams.merge` overwrites the key), so it never doubled the parameter.
  Two regression tests now pin that, including one that a tenant-scoped
  `token_endpoint` keeps its unrelated query parameters (RFC 6749 §3.1/§3.2).

## [1.0.0-beta12] - 2026-09-06

### Changed

- Maintenance release — no notable changes since v1.0.0-beta11.

## [1.0.0-beta11] - 2026-09-04

### Fixed

- Regenerate the §27 surface for the WebAuthn policy fields

- Regenerated the §27 management surface from the vendored
  `management-registry.json` / `openapi.json`. The v1.0.0-beta09 re-vendor
  carried the WebAuthn user-verification policy — `SecuritySettings.webauthn`,
  and `webauthn_user_verification` on the organization and tenant settings
  requests — without regenerating the code emitted from it. This SDK's
  drift-check runs on pull requests only, so beta09 and beta10 both published a
  surface in which the new policy could be neither read nor set.
  `python3 scripts/gen_management.py --check` is green again.

## [1.0.0-beta10] - 2026-09-03

### Changed

- Maintenance release — no notable changes since v1.0.0-beta09.

## [1.0.0-beta09] - 2026-09-02

### Changed

- Maintenance release — no notable changes since v1.0.0-beta08.

## [1.0.0-beta08] - 2026-09-02

### Added

- The four public "Sign in with X" operations (CONTRACT §12.1, 1.38)

- **Contract 1.38: the four public "Sign in with X" operations.** `sso_providers`,
  `sso_start_oauth2`, `sso_complete_oauth2` and `sso_complete_handoff`, under the
  exact CONTRACT.md §12.2 Python names, on **both** `AxiamClient` and
  `AsyncAxiamClient` — the same snake_case names on each, as `async def` twins on
  the async client (SDK-Q08 still prohibits `async_*` prefixes). New public models
  `FederationProvider` and `FederationProviderList`, named by the §12.1 SDK-type
  table. Upstream: ilpanich/axiam#398.

  Four rules an implementation can satisfy by accident and break by accident, so
  each is stated in the code and carries a test:

  - **An empty provider list is a success** (§12.1 note 9). An unknown
    organization, a known one with nothing configured, and a request naming no
    workspace at all all answer `200 []`. `sso_providers` returns each as an
    ordinary result and raises nothing: the endpoint is shaped so it cannot
    enumerate organization or tenant slugs, and distinguishing the three
    client-side would rebuild that oracle. It is therefore also the one
    federation operation whose body builder raises **no** `AuthError` when no
    workspace resolves — a client-side refusal would be that same two-valued
    answer by another route.
  - **`protocol` selects the start operation** (§12.1 note 10), never
    `provider_kind`: `OidcConnect` → `sso_start`, `OAuth2` → `sso_start_oauth2`,
    `Saml` → the SAML login endpoint, which is not a §12 vocabulary operation.
    `FederationProvider.protocol` is the wire string, with `PROTOCOL_OIDC_CONNECT`
    / `PROTOCOL_OAUTH2` / `PROTOCOL_SAML` exported to compare against; an enum the
    SDK enforced would turn a value added server-side into a validation failure
    for the whole list.
  - **PKCE on the OAuth2 variant is server-side** (§12.1 note 11). Nothing here
    computes a verifier or sends a challenge, and a test asserts the absence
    rather than leaving it to be noticed.
  - **A `400` from a start call is a configuration refusal** (§12.1 rule 12a,
    new at 1.38): the deployment rejecting a `redirect_uri` whose origin is
    neither its own issuer nor listed in `AXIAM__AUTH__SSO_SPA_ORIGINS`. It
    surfaces as `NetworkError` — §2's `400` row, the taxonomy's
    configuration/programming-error member, distinct from the `AuthError` a `401`
    gets — and is not retried.

  `HANDOFF_QUERY_PARAM` (`axiam_handoff`) and `HANDOFF_CODE_TTL_SECONDS` (60) are
  exported for callers driving the browser hop. A handoff `401` is terminal:
  `sso_complete_handoff` makes exactly one wire call, so it cannot become a retry
  by accident.

- `tests/test_oidc_login_providers.py` — 27 tests. The wire-shape half reads the
  vendored `openapi.json` and asserts method, path, media type, the success schema
  names, that the `sso_providers` identifiers are declared `in: query`, and that
  neither OAuth2 start schema carries PKCE material; the SDK half asserts what
  actually reaches the wire matches. The rule half covers note 9 (all three
  empty-list cases, plus that a workspace-less request is still *sent*), note 10
  (all three dispatch branches, with a `Saml` fixture whose `provider_kind` is
  `google` so a kind-based dispatch fails), note 12 (terminal `401`, exactly one
  request) and rule 12a (a `400` from either start operation is `NetworkError` and
  unretried; a `401` from the same endpoint stays `AuthError`). Every operation is
  exercised on both clients.

### Changed

- State contract 1.38 conformance and document the thirteen §12 operations

- Regenerate the §27 surface from the re-vendored artifacts

- Wire shape and the four load-bearing rules for the 1.38 operations

- Re-vendor CONTRACT.md 1.38, openapi.json and management-registry.json

- Re-vendored `CONTRACT.md` (1.29 → 1.38), `openapi.json` and
  `management-registry.json` byte-for-byte from `ilpanich/axiam@1c457f6`.
  `proto/axiam/v1/` and `opaque-test-vectors.json` did not change upstream and
  were re-verified as already identical rather than re-copied.
  `management-registry.json` moves only its `spec_digest`: `operation_count`
  stays at 155, so no §27 operation was added or removed.

- Regenerated the §27 management surface (`python scripts/gen_management.py`), as
  §27.8 requires whenever the vendored artifacts move. `openapi.json` gains ten
  fields on the federation-config schemas (`allow_tenant_inheritance`,
  `allowed_issuer_tenants`, the two Apple identifiers, the OAuth2 endpoint trio,
  `provider_kind`/`provider_slug`, `button_icon`, `scopes`/`effective_scopes`,
  `has_bundled_mark`, `mints_client_secret`, `pkce_required`), so
  `src/axiam_sdk/management/models.py` and the generated surface test move with
  it. The operation surface itself is unchanged.

- The README's contract-conformance statement names **contract 1.38** and §12's
  thirteen operations, and its §12 section documents the four new ones, the
  protocol-dispatch table, the faithful `FederationProvider` shape, and the
  rule-12a taxonomy mapping.

## [1.0.0-beta07] - 2026-08-30

### Changed

- Re-vendor AXIAM contract 1.36

- **Documented contract 1.36, which this SDK already vendors.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` were re-vendored from the
  `sdks/` sources in [`ilpanich/axiam`](https://github.com/ilpanich/axiam)
  (ilpanich/axiam#396) as part of the 1.0.0-beta06 release, whose note recorded
  only "no notable changes". That understated it — the contract moved in that
  release — and v1.0.0-beta06 is tagged, so the correction is recorded here
  rather than by editing a released section. No SDK code changed with the
  artifacts; the three entries below are why not.

- **§5.2.2 rule 4 is new, and is an errata rather than a wire change.** The
  server now scopes every *self-service* endpoint to `principal_tenant_id`
  rather than to the acting tenant — `GET`/`PUT /users/{own id}`, that user's
  `mfa-methods`, `POST /users/{own id}/reset-mfa`, `POST /auth/mfa/enroll` and
  `/confirm`, `POST /auth/webauthn/register/start` and `/finish`, `POST
  /users/me/resend-verification`, the §25 account export and erasure for the
  caller's own id, and `GET /oauth2/userinfo`. Each of those answered `404` for
  an organization-level caller that had switched to another tenant and now
  succeeds. No request or response field is added, so nothing here is a wire
  change.

  The rule also forbids the obvious workaround: an SDK MUST NOT clear or rewrite
  the acting-tenant header for those calls, because that header is what makes
  the **administrative** form of the same endpoints reach the tenant the caller
  asked for — stripping it would break reading another tenant's user in order to
  fix reading your own. This SDK was audited for such a workaround and has none:
  `X-Tenant-ID` is set in one place, `_session.py`'s request decorator,
  unconditionally for every same-origin request; no endpoint is special-cased.

- **Issue #395 is settled: the acting-tenant header is `X-Axiam-Tenant`**, and
  §5.2, §5.2.2 and §5.2.3 now name it. The note under 1.0.0-beta05 below
  recorded the contract and the server disagreeing on it; they no longer do, and
  the name this SDK documents was already the server's. §5 rule 2's
  *unconditional* `X-Tenant-ID` is deliberately **not** renamed, and the
  contract now carries a note saying why it must not be: it names the client's
  *constructor* tenant, so folding it into `X-Axiam-Tenant` would override the
  acting tenant on every request an organization-level principal made after a
  switch. Every existing §5 rule 2 send is left exactly as it was.

- **`openapi.json` gained `/api/v1/auth/me`, `/api/v1/auth/password/change` and
  `/api/v1/admin/bootstrap`.** All three were always served and always normative
  in `CONTRACT.md`; they were missing from the generated document only because
  their handlers were never listed in its `paths(…)`. `management-registry.json`
  keeps `operation_count` at **155** — bootstrap is excluded on the §27.0
  boundary — so §27 code generation is unaffected and the generated surface is
  unchanged.

## [1.0.0-beta06] - 2026-08-30

### Changed

- Maintenance release — no notable changes since v1.0.0-beta05.

## [1.0.0-beta05] - 2026-08-30

### Added

- Contract 1.35, carrying 1.34 — service-account RBAC, principal tenant, tenant scope

- **Contract 1.35, which carries contract 1.34 with it.** Nothing had been
  fanned out since 1.33, so this re-vendors `CONTRACT.md`, `openapi.json` and
  `management-registry.json` across both revisions. The registry still holds
  155 operations across 24 namespaces — 1.35 changed only its `spec_digest` —
  so the eight §27 operations below arrived with 1.34 and are new here
  regardless.

- **§27: service accounts as RBAC principals** (contract 1.34) — eight
  generated operations across `roles`, `groups` and `service_accounts`.
  `unassign_from_service_account` takes the same optional `resource_id` query
  parameter as the user and group unassign calls: omitting it removes the
  *global* grant specifically, not every grant of that role.

- **§5.2.2: the acting tenant and the principal tenant are different things**
  (contract 1.34). `LoginResult` gains `principal_tenant_id`,
  `principal_tenant_slug`, `org_id` and (from §5.2.3) `reachable_tenant_ids`.
  Absent means equal — a server older than 1.34 omits them and cannot switch
  the acting tenant either, so `principal_tenant_id` falls back to the acting
  tenant the server reported. Read `org_id` from the session instead of
  resolving a slug through `GET /api/v1/organizations`, which is
  `super-admin`-only.

- **§5.2.3: tenant-scoped role assignments** (contract 1.35). `tenant_scope`
  appears on the three assignment request bodies and on the assignment objects
  the read paths return. Omitted means unrestricted, which is what every
  assignment written before the field existed already meant.

### Fixed

- **A registration record for your own password was sealed against the wrong
  tenant.** CONTRACT.md §5.2.2 rule 2: the caller's credentials live in the
  tenant the *account* lives in, not whichever tenant the client is currently
  pointed at, and a record sealed against the acting tenant is refused with
  "the OPAQUE session was issued for a different tenant".

  `opaque_enrollment` had one behaviour for a method documented for three
  callers — user creation, change-password and reset completion — and only the
  first of those wants the acting tenant. It keeps that behaviour, which is
  correct for creating *another* account; the new
  `opaque_enrollment_for_self` seals against `principal_tenant_id` and is what
  a self-service password change must call. Both `AxiamClient` and
  `AsyncAxiamClient` carry it — fixing only one would have left the bug live
  on the other.

  The two collapse to the same request for every ordinary principal, so this
  only bit an organization-level account that had switched tenant — which is
  why it survived every test written against an ordinary one.

- **An empty `tenant_scope` is no longer put on the wire.** The server refuses
  `[]` with `400`: an assignment reaching no tenant is a grant that does not
  exist rather than a restriction. `exclude_unset` did not cover it, because
  the natural way to build the field is to collect into a list and pass it,
  which yields `[]` and *is* set. `ManagementModel.to_wire` now drops it, via a
  one-field allowlist — elsewhere `[]` means "clear this list", and dropping it
  there would make "remove every entry" inexpressible.

### Note on `X-Tenant-ID` vs `X-Axiam-Tenant`

CONTRACT.md §5.2.2 and §5.2.3 name the acting-tenant header `X-Tenant-ID`, but
the AXIAM server reads **`X-Axiam-Tenant`** (`ACTIVE_TENANT_HEADER` in
`crates/axiam-api-rest/src/extractors/auth.rs`), as do its own tests, the admin
UI, and the `openapi.json` vendored alongside that contract. The server never
reads `X-Tenant-ID` at all.

Documentation updated here names `X-Axiam-Tenant`, because a tenant switch sent
under the other name is not refused — it is ignored, and the request quietly
acts on the principal's own tenant instead. The discrepancy has been reported
upstream; this SDK's existing `X-Tenant-ID` sends are left as they are, being
out of scope for a contract re-vendor.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Re-vendor contract 1.33, attest published dists, pin actions by digest

- **CONTRACT 1.32 — signing in an organization-level principal (§5.2.1).**
  `CONTRACT.md`, `openapi.json` and `management-registry.json` re-vendored from
  the AXIAM server, where the same bug class had made an organization-level
  administrator unable to sign in at all (ilpanich/axiam#388).

  Naming no tenant now resolves the organization's own reserved scope on
  `/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start` and
  `/auth/webauthn/authenticate/discoverable/start`. That reserved tenant's slug
  is `organization`, so this SDK reaches it through the ordinary constructor:

  ```python
  AxiamClient(base_url=..., tenant_slug="organization", org_slug="globex")
  ```

  Prefer that over omitting the tenant: §5 rule 2 still requires one on the
  `X-Tenant-ID` header of every request after the login.

### Fixed

- Refuse a whitespace-only tenant_slug, not just an empty one

- **A whitespace-only `tenant_slug` is now refused at construction** (CONTRACT.md
  §5, §5.2.1 rule 2). `not tenant_slug` caught `""` but not `"   "`, which is
  exactly as much of a tenant and reaches the wire the same way.

  It matters because nothing can carry a blank slug: the server resolves
  nothing, and on `/auth/opaque/login/start` it fails on the workspace *before*
  the tenant's OPAQUE mode is read — so the `404` of §23.4 rule 10 never
  arrives, this SDK has no fallback to take, and sign-in fails even against a
  tenant with OPAQUE **disabled**, answered as "invalid credentials".

## [1.0.0-beta02] - 2026-08-28

### Added

- Contract 1.31 — list search, the truthful resend, organization scope

- Implement CONTRACT §27 — the management API

- **CONTRACT 1.31 — the AXIAM server PR #383 surface.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` re-vendored, and the six things
  they describe implemented.

  - **`search` on all twenty paginated management operations** (§27.4 rule 4).
    A third field on `PageRequest`, not a third argument on twenty generated
    `list` methods:

    ```python
    client.users.list(PageRequest(limit=50, search="ada"))
    client.users.list_all(PageRequest(limit=200, search="ada"))
    ```

    Putting it on the page request is what makes `list_all` carry the term
    across the whole walk. A walk that filtered its first request and not the
    rest returns the matches followed by the unfiltered tail, which from the
    caller's side looks like a server bug.

    The server applies it **before** `offset`/`limit`, so `Page.total` counts
    matches rather than rows. A blank or whitespace-only term is treated as
    unset and sends no `search` parameter, so a box that fires on every
    keystroke does not ask a different question once it is cleared. The server's
    length cap is deliberately **not** copied here: a client-side truncation the
    server would not have made is a silently different query.

  - **`resend_own_verification()`** on both clients (§25.1, §25.7) —
    `POST /api/v1/users/me/resend-verification`, for a caller signed in to the
    account it is asking about. It takes no address, and reports what happened:
    returns for enqueued, `ConflictError` for already-verified-or-ineligible,
    `NetworkError` for the daily limit.

    `resend_verification` still exists and still returns normally whatever
    happens, because it takes an address from an anonymous caller and a truthful
    answer there is an enumeration oracle. Use the new one whenever there is a
    session — a profile page wired to the old one reports success while doing
    nothing, which is the defect the pair exists to separate. This SDK does not
    fall back from one to the other in either direction (§25.7 rule 2).

  - **`LoginResult.organization_level`** (§5.2) — whether the account holds
    grants that apply in every tenant of its organization. Check it before
    offering a tenant switch: an ordinary tenant principal changing
    `X-Tenant-ID` gets a `403`. `False` against a server older than contract
    1.31, which is the safe reading of absent.

  - **`Tenant.kind` and `TenantKind`** (§27.11) — ordinary tenant or the
    organization's own scope. `None` on a row written before that scope existed.
    Read-only: it is not on `CreateTenantRequest` or `UpdateTenantRequest`.

  - **`MtlsTrustAnchorResponse.trusted_anchors`** (§27.11) — how many CAs the
    live listener now trusts, when it was reloaded. `None` is **not** zero: it
    means there was no listener to ask, which is the case
    `restart_required=True` already reports.

  - **`Certificate.bound_service_account_id`** (§27.11) — the service account a
    certificate authenticates, resolved for a whole page in one query by
    `certificates.list()` and `None` on `certificates.get()`. The SDK does not
    issue a second request to fill it in there.

- **CONTRACT.md §27 — the management API.** 146 administrative operations
  across 24 namespaces, on both `AxiamClient` and `AsyncAxiamClient`, reached as
  `client.<namespace>.<operation>` (and equivalently through
  `client.management`). The namespace handles and their models are generated
  from the vendored `management-registry.json` and `openapi.json` by
  `scripts/gen_management.py`; a new CI job runs that generator with `--check`,
  so a registry that moves without a regeneration fails the build rather than
  shipping a client that disagrees with the contract.

  The semantics the section fixes are implemented rather than approximated:
  acquiring a handle performs no I/O; `{org_id}`/`{tenant_id}` default from the
  client and are overridable per handle with `.in_org(...)` / `.for_tenant(...)`;
  `Page.total` is the whole set and `list_all()` walks it; a sparse update body
  sends only the fields that were set; 404/409/400/422 map to `NotFoundError`,
  `ConflictError` and `ValidationError` (subclasses of the §2 types, so existing
  `except` clauses keep working); only `GET` is retried; and one-time secrets
  come back as `SecretStr`.

- **Declarative management (§27.6/§27.7).** `client.manifest.plan(...)` reports
  what reconciling a `ManagementManifest` would do without writing anything, and
  `.apply(...)` runs it, stopping at the first failure and reporting every step
  including the ones it did not attempt. Two declarative spellings, both
  validated where the manifest is written: `define_manifest(...)` and the
  `@axiam_resource` / `@axiam_role` / `@axiam_grant` / … class decorators
  assembled by `collect_manifest(...)`.

- **`AxiamClient.resolved_tenant_id()`** — the public twin of the existing
  `resolved_org_id()`. §27 routes where `{tenant_id}` names the object rather
  than the context (the signing CAs under `ca_certificates`, and the `tenants`
  namespace) take that UUID as an ordinary argument, so callers need to read the
  one the session already decoded instead of re-deriving it.

- **Examples**: `management_basics.py`, `management_manifest.py`, and
  `device_mtls_provisioning.py` — an end-to-end IoT flow that mints a device
  certificate from the tenant's signing CA, binds it to a service account, and
  then authenticates as that device over §6.1 mutual TLS.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#70)

- Re-vendor the contract artifacts: spec digest + §27.10 posture (#68)

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated management enums are open.** Each is now `Literal[...] | str`, so
  a value this SDK's copy of the spec does not list validates instead of raising
  (§27.11 rule 1). A bare `Literal` is checked strictly by pydantic, which would
  turn the next `kind` or `status` the server adds into a validation error on
  the *whole* response — taking down every record on the page over one field of
  one of them, including the records the caller was after. The listed members
  stay in the annotation because they are what a reader needs; what the widening
  removes is the claim that nothing else can occur.

- Coverage floor raised from 97% to 98% (measured 98.59%).

### Fixed

- Use datetime.timezone.utc, not the 3.11-only datetime.UTC alias

- **`scripts/gen_management.py` no longer drops a projected list element.** The
  server answers `GET /api/v1/certificates` with `Certificate` plus one resolved
  graph edge, expressed as an `allOf` of the `$ref` and an anonymous object.
  Read as a whole, that composition has no name, so the registry carried a page
  with no element type and the added field reached no model. The generator now
  takes the base name through the `allOf` and folds the projection's added
  fields onto the base model as optional. (The registry-side half of this is
  AXIAM PR #386.)

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- Update furo requirement from ~=2024.8 to ~=2025.12

- Update protobuf requirement from <7,>=6.31.1 to >=6.31.1,<8

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

## [1.0.0-alpha43] - 2026-08-24

### Added

- Support Python 3.14 and pin the floor+newest version policy (#62)

- **Python 3.14 is now a supported and CI-built interpreter.** The trove
  classifiers gain `Programming Language :: Python :: 3.14`, so PyPI and the
  README badge both report it, and the gating CI matrix now runs the full test
  suite on it.

- **`tests/test_language_version_policy.py`** — a conformance test for the
  support policy itself. `requires-python`, the trove classifiers and the CI
  `python-version` matrix are three independent declarations of the same fact
  and nothing previously compared them, so they could drift in either
  direction: a classifier claiming an interpreter nothing built on, or a green
  CI leg for a version `pip` would refuse to install on. The test fails the
  build when they disagree.

- **`examples/version_compatibility.py`** — a runnable preflight that reports
  the running interpreter against the SDK's declared range, read out of
  installed package metadata rather than hardcoded. Intended as a
  container-image or startup check.

- **A "Supported Python versions" section in the README**, stating the two
  distinct claims explicitly: the SDK is *built* against its floor and *runs
  on* everything through the newest release, with a CI leg proving each.

### Changed

- **The gating CI matrix is now floor + newest (3.10, 3.14) rather than every
  release in between (3.10, 3.11, 3.12, 3.13)** — D-18. Those two legs are the
  ones that catch breakage: the floor rejects syntax and stdlib APIs the
  declared minimum does not have, and the newest catches removals and
  deprecations that have become errors. A version sitting between two green
  legs is interpolation. 3.11-3.13 remain supported and classified; 3.12
  additionally runs the whole suite under the Coverage and docs workflows.

  `requires-python` is unchanged at `>=3.10`, so no consumer loses an install
  they had before.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Honour `mode` after a failed exchange (§23.4 rule 7)

- **`login/start` now carries `mode`, and it decides what follows a failed
  exchange — CONTRACT.md §23.4 rule 7.** The response to
  `POST /api/v1/auth/opaque/login/start` gains an optional `mode` field holding
  the tenant's `opaque_mode` (`optional` or `required`; never `disabled`, which
  still answers `404`). Read into the new `OpaqueLoginStart` response type,
  which tolerates its absence.

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)

- Re-vendor CONTRACT.md 1.29 and openapi.json 1.0.0-alpha40

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- **`login_opaque` falls back to `login()` under `opaque_mode: optional`**
  (§23.4 rule 7), on both `AxiamClient` and `AsyncAxiamClient`. When the
  envelope does not open — a wrong password, an unknown identity, an account
  with no registration record, or a hostile endpoint, indistinguishable by
  design — `KE3` is still never sent, and what happens next now depends only on
  `mode`:

  - `optional` — the same credentials are retried over `POST /auth/login`
    before anything is reported, and that call's outcome is the caller's:
    its success on success, its error on failure. Every account has no
    registration record the moment an operator enables OPAQUE and acquires one
    only when its password is next set, so treating the failed exchange as
    final locked out every user of a tenant mid-migration — the state
    `optional` exists to serve.
  - `required`, an unrecognised value, or **no `mode` at all** (a server older
    than contract 1.29) — `AuthError`, and nothing is retried. Under `required`
    the retry would be refused anyway (`403 opaque_required`, for every
    principal, before any credential is examined), so trying would put a
    plaintext password on the wire for nothing.

  **Not a behaviour change under `required`**, which is what this SDK did for
  every mode until now, and no new error type: an OPAQUE credential failure is
  still `AuthError`. `mode` is **not** downgrade protection and the SDK does not
  document it as one — a hostile server that wanted the plaintext could answer
  `404` and get the fallback whatever it puts in the field.

- **README: the OPAQUE section no longer says "do not retry over `login()`"**
  unconditionally, which contract 1.29 makes wrong for `optional`. It now
  tabulates the three `mode` cases and says the SDK handles the retry itself.

- Re-vendor `CONTRACT.md` at **1.29** and `openapi.json` at
  **1.0.0-alpha40**, byte-identical to the server repository's `sdks/`. §23.4
  rule 7 is the only normative change; `OpaqueLoginStartResponse` gains the
  matching optional `mode` property.

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Format the §20 samples as ruff formats them
- Document the §20 surface this SDK has shipped since alpha25
- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Claim §20, which this SDK has shipped since alpha25
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Added

- Add WebAuthn (§24), account lifecycle (§25) and PAR (§26)

- **WebAuthn and passkeys — CONTRACT.md §24.** Six relying-party operations on
  both `AxiamClient` and `AsyncAxiamClient`: `webauthn_register_start`/`_finish`,
  `webauthn_authenticate_start`/`_finish`,
  `webauthn_discoverable_start`/`_finish`. Python has no authenticator, so
  §24.6b's linked-API helper is deliberately absent — §24.6b rule 2 forbids
  emulating one in software.

- **The §24.6a JSON bridge.** `webauthn_request_json()` produces the exact
  string a platform authenticator API takes, and every `*_finish` accepts the
  platform's response JSON string directly — so a service driving an Android or
  iOS client passes both directions through untouched. Plus
  `classify_webauthn_error()` / `webauthn_error_message()`, which give a
  server-side caller the same five outcomes a browser sees.

- **Account lifecycle and MFA enrolment — CONTRACT.md §25.** Nine operations:
  `mfa_enroll`/`mfa_confirm`, `mfa_setup_enroll`/`mfa_setup_confirm`,
  `verify_email`, `resend_verification`, `request_password_reset`,
  `confirm_password_reset`, `password_reset_context`.

- **Pushed authorization requests — CONTRACT.md §26 (RFC 9126).** `oidc_par` on
  both clients, plus `pushed_authorization_request_endpoint` on
  `OidcConfiguration`.

- Examples: `webauthn_relying_party.py`, `account_lifecycle.py`, `par_login.py`.

### Changed

- Cover the async §24/§25 twins and reformat the README

- Re-vendor CONTRACT.md at 1.28

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- **Document §20 in the README body.** The statement claimed UMA 2.0 from the
  previous release, and the README still described none of it — all seven
  §20.1 operations, the §20.3 challenger and two runnable examples shipped
  with no prose pointing at them. Adds the Protection API, the ticket dance,
  and the three behaviours that cost the most to discover the hard way: the
  ticket exchange never retries (a ticket is spent before the request is
  evaluated), an undeclared scope is a `400` rather than a denial, and a
  partial grant is refused whole with no auto-narrowing.

- **Conformance statement now names §20.** The UMA 2.0 Protection API and ticket
  grant landed at 1.0.0-alpha25 — all seven §20.1 canonical operations on both
  `AxiamClient` and `AsyncAxiamClient`, plus the §20.3 `UmaChallenger`, covered by
  `tests/test_uma.py` and `tests/test_uma_challenge_guard.py` — but the statement
  was never widened to say so. The README body still documents no §20 surface;
  that gap is separate and is not closed here.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- **`LoginResult` gains `mfa_setup_required` and `setup_token`** (§25.2 rule 1).
  A tenant that requires MFA answers `403 mfa_setup_required` with a setup token
  for an account that has none; that used to arrive as an `AuthzError`, telling
  the caller they lacked permission to log in when what the server said was
  recoverable and came with the means to recover.

  **Not breaking in Python.** This model has always been one type with flags
  rather than a discriminated union, so nothing that reads `mfa_required` has to
  change — unlike the SDKs whose login result is a union, where the same
  contract rule adds a variant. A genuine authorization refusal still raises
  `AuthzError`: the branch is matched on the body's discriminant, not the status.

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Apply ruff format to docs/conf.py
- Create .readthedocs.yaml

### Fixed

- Add the Sphinx build Read the Docs expects, and the missing protobuf dep

## [1.0.0-alpha34] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha33.

## [1.0.0-alpha33] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807), CONTRACT §23
- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `login_opaque` and
  `opaque_enrollment` on both `AxiamClient` and `AsyncAxiamClient`, plus
  `opaque_available()` for choosing the password path up front.
- `examples/opaque_login.py`.

### Changed

- CHANGELOG.md multiple "unreleased entries"
- Link to the AXIAM platform documentation site
- Re-vendor openapi.json at alpha32, and collapse a duplicated changelog heading (#54)
- **BREAKING** — the OPAQUE protocol is NOT implemented in this SDK. CONTRACT
  §23.1 forbids it, so the client half is a `ctypes` binding to
  `libaxiam_opaque_ffi` — the same implementation the AXIAM server links,
  published as a per-platform asset on the axiam release page. There is
  deliberately no `[opaque]` extra: the artifact is not a PyPI distribution,
  and a name that installed nothing would read as though it installed the
  thing. Put the library on the loader path or point `AXIAM_OPAQUE_LIBRARY` at
  it.
- Failure taxonomy for the OPAQUE path: a tenant with OPAQUE disabled, an
  absent library, and a key-stretching function this build cannot perform are
  all `NetworkError` (a caller can fall back, or an operator can act);
  everything else is `AuthError` and must NOT be retried over `login()`
  (§23.4 rule 7).
- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.

### Removed

- **BREAKING** — SRP-6a. `login_srp`, `srp_enrollment`, the `axiam_sdk._srp`
  module, `srp-test-vectors.json` and the `[srp]` extra (`argon2-cffi`) are all
  gone. AXIAM's server-side SRP endpoints are removed in the same release, so
  keeping the client would leave a method that only ever returns 404.

### Fixed

- Build the KSF before spending the exchange's state handle
- OPAQUE: a refused key-stretching function no longer strands the exchange's
  native state handle. `finish()` spent the handle before building the KSF, so
  an unrecognised function or an out-of-range cost left it out of its one-shot
  slot and unreachable by `__del__` — a leaked Rust allocation once per login
  attempt against a misconfigured tenant. The KSF is now built first, so a
  refusal leaves the exchange intact: it is released normally, and a caller who
  fixes the parameters can retry.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client (CONTRACT §23) (#51)

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

- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#45)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#42)
- Add the §20.7 required timeout assertion
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Format PERFORMANCE.md's example to ruff's blank-line rules
- Close the async residual — it is CPython, not the SDK (D1/J5)
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
- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` with the UMA paths.

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

### Fixed

- Close the coverage fail_under rounding loophole (precision=2)
- R5.7 — F-11/F-14 conformance follow-ups (F-08 already fixed) (#44)
- Export the token-type constants from axiam_sdk

## [1.0.0-alpha24] - 2026-08-04

### Added

- Apply the full CONTRACT §10.1 local-verification set
- Add verify_webhook signature verification helper (CONTRACT.md §13, T-145)
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

### Changed

- Device (mTLS) tokens now carry aud=axiam:m2m (#31)
- Service accounts can use login_client_credentials (#30)
- Pin CONTRACT §10.1 rule 8 against regression (§15.3.1) (#29)
- Bump pypa/gh-action-pypi-publish from 1.14.1 to 1.14.2

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

- Tighten the skew ceiling and diagnose the slug/UUID comparand (#27)
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

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Update grpcio requirement from <1.83,>=1.78 to >=1.78,<1.84
- Update grpcio-tools requirement
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Re-sync vendored CONTRACT.md to contract 1.5

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

### Fixed

- Enforce §9 rule 6 invariants in the oidc_refresh coalescer
- Accept any 2xx as success in revoke()
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
