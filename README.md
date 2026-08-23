# axiam-sdk (Python)

[![CI](https://github.com/ilpanich/axiam-python-sdk/actions/workflows/sdk-ci-python.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-python-sdk/actions/workflows/sdk-ci-python.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-python-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-python-sdk?branch=main)
[![PyPI](https://img.shields.io/pypi/v/axiam-sdk.svg)](https://pypi.org/project/axiam-sdk/)
[![Python versions](https://img.shields.io/pypi/pyversions/axiam-sdk.svg)](https://pypi.org/project/axiam-sdk/)
[![Docs](https://img.shields.io/badge/docs-pdoc-blue.svg)](https://ilpanich.github.io/axiam-python-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Python client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

## Package identity

- **Repository:** [github.com/ilpanich/axiam-python-sdk](https://github.com/ilpanich/axiam-python-sdk)
- **PyPI package:** `axiam-sdk`
- **Registry:** [pypi.org/project/axiam-sdk](https://pypi.org/project/axiam-sdk/) _(reserved, not yet published)_
- **Version tags:** `vX.Y.Z`
- **API docs:** [ilpanich.github.io/axiam-python-sdk](https://ilpanich.github.io/axiam-python-sdk/)
- **License:** Apache-2.0
- **Python:** `>=3.10` (D-11)

## Contract conformance

This SDK conforms to CONTRACT.md §1–§13 and §12.7, §14, §15, §17, §19, §20, §21, §22,
§23, §24, §25, §26 (including §6.1 mTLS and the §10.1 minimum local-verification set).

§12.7, §14, §15, §20, §22, §24, §25 and §26 are named rather than folded into the
range because they landed after this SDK already claimed §1–§13: widening the
range silently would turn a statement that was true when written into a
different claim without anyone editing it.

See [`CONTRACT.md`](./CONTRACT.md) for the full cross-language behavioral contract.

## Status

Implemented (Phase 19). `AxiamClient` (sync) and the dedicated
`AsyncAxiamClient` (async, SDK-Q08) each expose the same canonical operation
names — `login`, `verify_mfa`, `refresh`, `logout`, `check_access`, `can`,
`batch_check`, and the nine §12 OIDC/SSO relying-party operations (see below)
— as sync or `async def` methods respectively (never an `async_*`-prefixed
twin on the sync class). Each client owns its own session, cookie jar, and
single-flight refresh guard. gRPC (sync `grpcio` + async `grpc.aio`), AMQP
(async-only `aio-pika`), a FastAPI dependency plus an `oidc_login_router`,
and a Django middleware plus `oidc_login_views`, are all available. Seven
runnable examples live under [`examples/`](./examples).

## Installation

```bash
pip install axiam-sdk
```

The FastAPI dependency and Django middleware are optional extras — install
only what you need, since a pure REST/gRPC/AMQP consumer should not be
forced to pull in FastAPI or Django:

```bash
pip install "axiam-sdk[fastapi]"
pip install "axiam-sdk[django]"
```

`[speed]` adds `uvloop` for async workloads — measured at −20% client CPU and
a materially tighter p95 on the `check_access` path. The SDK never installs a
loop policy for you; see [PERFORMANCE.md](PERFORMANCE.md), which also explains
why a single CPython process tops out around 310 checks/s and what to do about
it:

```bash
pip install "axiam-sdk[speed]"
```

```python
from axiam_sdk import AxiamClient
```

## Quickstart

### Login + MFA (§1, §5) — sync `AxiamClient` or async `AsyncAxiamClient`

`AxiamClient` (sync) and `AsyncAxiamClient` (async, SDK-Q08) are separate
classes, each with their own session — pick the one that matches your call
site's paradigm.

```python
from axiam_sdk import AxiamClient

# tenant_slug is required — AXIAM is multi-tenant and there is no default
# tenant (§5). login/refresh also require organization context (§5.1) — a
# tenant slug is only unique within an org — so pass org_slug too. TLS is
# always verify=True (§6); the only escape hatch is an explicit custom_ca
# parameter, never a boolean bypass.
with AxiamClient(base_url="https://localhost:8443", tenant_slug="acme", org_slug="acme") as client:
    result = client.login(email, password)
    if result.mfa_required:
        result = client.verify_mfa(result.mfa_token, totp_code)
    print(result.session_id, result.expires_in)
```

```python
import asyncio
from axiam_sdk import AsyncAxiamClient


async def main() -> None:
    async with AsyncAxiamClient(
        base_url="https://localhost:8443", tenant_slug="acme", org_slug="acme"
    ) as client:
        result = await client.login(email, password)
        if result.mfa_required:
            result = await client.verify_mfa(result.mfa_token, totp_code)
        print(result.session_id, result.expires_in)


asyncio.run(main())
```

See [`examples/login_mfa.py`](./examples/login_mfa.py).

### REST authorization checks — check_access / can / batch_check (§1)

```python
result = client.check_access("resource:read", resource_id)
can_write = client.can("resource:write", resource_id)

from axiam_sdk import AccessCheck

results = client.batch_check(
    [
        AccessCheck(action="resource:read", resource_id=resource_id),
        AccessCheck(action="resource:delete", resource_id=resource_id, scope="admin"),
    ]
)
```

`AsyncAxiamClient` exposes the same `check_access`/`can`/`batch_check` names
as `async def` methods, each backed by that client's own session and
single-flight refresh guard (§9). See
[`examples/rest_authz.py`](./examples/rest_authz.py).

### gRPC authorization checks (§1, §5, §9, §6)

`AuthzGrpcClient` (sync, `grpcio`) and `AsyncAuthzGrpcClient` (async,
`grpc.aio`) are both first-class transports — the async client is not a
thread-pool bridge over the sync one.

```python
from axiam_sdk.grpc import AuthzGrpcClient

client = AuthzGrpcClient(
    "localhost:9443",
    token_fn=lambda: current_access_token,  # non-blocking cache read
    tenant_id=tenant_id,
    refresh_fn=refresh_fn,  # invoked exactly once on UNAUTHENTICATED, then one retry (§9.3)
)
decision = client.check_access(subject_id, "resource:read", resource_id)
```

See [`examples/grpc_checkaccess.py`](./examples/grpc_checkaccess.py).

#### gRPC-only userinfo — `get_user_info` (§1.1)

`get_user_info` is the low-latency gRPC counterpart of the server's REST
`GET /oauth2/userinfo` endpoint (CONTRACT.md §1.1, contract 1.3). It has no
REST form in the SDK vocabulary. The request is empty — identity is derived
entirely server-side from the bearer token — and it returns a typed
`UserInfo(sub, tenant_id, org_id, email, preferred_username)`. `email` is
populated only when the access token carries the `email` scope and
`preferred_username` only with the `profile` scope (both `None` otherwise);
`sub`/`tenant_id`/`org_id` are always present. Calling it with no token raises
`AuthError` client-side without a wire call, and a gRPC `UNAUTHENTICATED`
drives the same single-flight refresh-and-retry-once path as `check_access`
(§9). It is exposed as `get_user_info()` on both `AuthzGrpcClient` (sync) and
`AsyncAuthzGrpcClient` (async).

```python
info = client.get_user_info()
print(info.sub, info.tenant_id, info.org_id, info.email, info.preferred_username)
```

### AMQP event consumer (§8)

```python
from axiam_sdk.amqp import ErrDrop, consume


async def handler(event: dict) -> None:
    if "action" not in event:
        raise ErrDrop("poison message")  # nack without requeue
    ...  # None return -> ack; any other exception -> nack with requeue


await consume(channel, "axiam.authz.request", signing_key, handler, prefetch=10)
```

Every delivery's HMAC-SHA256 signature is verified BEFORE the handler is
ever invoked — an unverified message never reaches your code. See
[`examples/amqp_consumer.py`](./examples/amqp_consumer.py).

### Reactors — AMQP extension actors (§22)

A **reactor** is an external process that subscribes to named hook events on the AMQP bus and
answers back — allow, deny, or a field-allow-listed mutation — inside a timeout the server
declared. It is AXIAM's answer to Zitadel Actions and Keycloak SPIs, and the difference is the
whole design: those load third-party code *into* the authorization server, and this keeps it
outside, reachable only through a signed reply schema the server validates before it believes
a word of it.

```python
from axiam_sdk.amqp import (
    LOGIN_POST_AUTH,
    TOKEN_PRE_ISSUE,
    ReactorConfig,
    ReactorDecision,
    ReactorEvent,
    aio_pika_dialer,
    allow,
    deny,
    mutate,
    reactor_serve,
)


async def decide(event: ReactorEvent) -> ReactorDecision:
    # token.pre_issue is mutable — the `ext.` namespace, and nothing else.
    if event.event == TOKEN_PRE_ISSUE:
        return mutate({"ext.cost_center": "42"})
    # login.post_auth is veto-only, plus step-up.
    if event.event == LOGIN_POST_AUTH and event.payload.get("ip", "").startswith("198.51.100."):
        return deny("embargoed region")
    return allow()


await reactor_serve(
    aio_pika_dialer("amqps://reactor:secret@broker.example.com:5671"),
    ReactorConfig(
        tenant_id="11111111-1111-1111-1111-111111111111",
        reactor_id="99999999-9999-9999-9999-999999999999",
        signing_key=subkey,  # the tenant's HKDF-derived AMQP subkey, never the master key
    ),
    decide,
)
```

#### Binding handlers per event (§22.14)

The `if` chain above is the shape every multi-event reactor grows, and its last line —
`return allow()` — answers on behalf of code that never ran. That is the defect §22.10
rule 2 forbids the *runtime* from committing, relocated into your file where the rule does
not reach it: an operator who set `fail_closed` on the registration has it defeated there.

`ReactorRouter` is §22.14's declarative form, in the spirit of the §11 declarative
authorization helpers:

```python
from axiam_sdk.amqp import LOGIN_POST_AUTH, TOKEN_PRE_ISSUE, ReactorRouter, reactor_serve

router = ReactorRouter()


@router.on(TOKEN_PRE_ISSUE)
def enrich_token(event: ReactorEvent) -> ReactorDecision:  # sync or async, both work
    return mutate({"ext.cost_center": "42"})


@router.on(LOGIN_POST_AUTH)
async def screen_login(event: ReactorEvent) -> ReactorDecision:
    return deny("embargoed region") if await embargoed(event) else allow()


await reactor_serve(dialer, config, router.handler())
```

- **A misspelled event is refused when you bind it** — `ReactorRouter` accepts only §22.5
  registry names, which is also how it refuses the three hot-path operations §22.7
  excludes: they are in no registry row.
- **An unbound event abstains** — no reply, and the registration's `failure_policy` decides
  (§22.8), exactly as it decides a timeout. Never a synthesized `allow`.
- A duplicate binding raises rather than silently overwriting, and `router.events` feeds
  `default_failure_policy_for` so you can see what an unreachable reactor costs before you
  go live.

For a class-based reactor, mark the methods and collect them — bound methods keep their
instance:

```python
from axiam_sdk.amqp import on_reactor_event, reactor_handlers


class Reactor:
    @on_reactor_event(TOKEN_PRE_ISSUE)
    def enrich(self, event: ReactorEvent) -> ReactorDecision: ...


handler = reactor_handlers(Reactor())  # or reactor_handlers({TOKEN_PRE_ISSUE: fn})
```

It is pure sugar: the value it produces is exactly the handler `reactor_serve` already
takes. It opens nothing, verifies nothing, signs nothing, does not filter a patch, and a
handler's own exception reaches the runtime unchanged so nothing is published.

See [`examples/reactor.py`](./examples/reactor.py) for a complete three-hook reactor with
graceful shutdown and a telemetry hook.

#### The five hookable events, and their allow-lists

| Event | Mutable | Complete allow-list | Default failure policy |
|---|---|---|---|
| `token.pre_issue` | yes | the **`ext.`** namespace only | `fail_open` |
| `login.post_auth` | no | — (veto, or `require_mfa`) | `fail_closed` |
| `user.pre_create` | yes | `username`, `email`, `metadata.` | `fail_closed` |
| `user.pre_update` | yes | `username`, `email`, `metadata.` | `fail_closed` |
| `grant.pre_assign` | no | — (veto only) | `fail_closed` |

An entry ending in `.` is a **namespace prefix** and needs at least one character after the
dot: `ext.` admits `ext.department` and `ext.a.b.c`, and refuses `ext.` itself, `ext`, `extra`,
`external_id` and `evil.ext.department`. So a reactor can never reach `sub`, `aud`, `exp`,
`scope` or any other standard claim — a **correctly signed** reply setting `sub` is refused
exactly as a forged one is.

Registrations that name no `failure_policy` get **the strictest default among their events**,
in either array order — `default_failure_policy_for([...])` computes it, and "take the first
event's default" is specifically what §22.8 forbids, because it lets the order of a JSON array
decide whether an unreachable fraud check passes.

#### The authorization hot path is not hookable, and this SDK does not pretend otherwise

The single check, the batch check and token introspection are absent from `EVENT_REGISTRY`,
from `REACTOR_EVENT_NAMES` and from every example here (§22.7, a normative MUST NOT). A
reactor round-trip is milliseconds; the check path's budget is microseconds. An application
that needs external input on an authorization decision writes a **deny grant**, which the
engine evaluates in the hot path at hot-path cost — and there is deliberately no client-side
interceptor in this SDK offering itself as the reactor equivalent.

#### What the runtime guarantees

- **Both directions are signed.** The server signs the event with the tenant's HKDF-derived
  AMQP subkey; the reactor signs its reply with the same key. An unsigned or stale reply is
  not a weak reply — the server discards it as though the reactor had never answered. Every
  event is verified (`key_version >= 2`, MAC, ±300 s freshness in both directions, nonce
  seen-set) *before* your handler is called.
- **Three canonicalization traps, all of them silent failures if missed.** A reactor body
  signs `hmac_signature` as **`null`**, where §8's own two message types omit it;
  `json.dumps` must run with `ensure_ascii=False`, because `serde_json` escapes no non-ASCII
  and Python escapes all of it by default; and `issued_at` is `chrono`'s RFC 3339
  (`…T12:00:00Z`, no fraction on a whole second), not `datetime.isoformat()`'s `+00:00` with
  six digits. All three are pinned by server-generated vectors rather than by memory — see
  [`testdata/reactor_v2_reference_vectors.json`](./testdata/reactor_v2_reference_vectors.json)
  and [`tests/test_reactor_vectors.py`](./tests/test_reactor_vectors.py).
- **It declares no topology.** No queue declare, no exchange declare, no bind — the server
  owns all three, and the transport protocol this runtime is written against does not even
  offer them. A reactor that can bind is a reactor that can bind itself to
  `*.token.pre_issue` and read another tenant's issuance events.
- **It fails closed on its own errors.** A handler that raises, a body that will not parse, a
  window that has already closed: each publishes **nothing**, so the registration's
  `failure_policy` decides. Synthesizing an `allow` would override the operator's
  `fail_closed` setting from inside the library. `abstain()` is the explicit form of the same
  thing.
- **It does not filter your patch.** One forbidden key rejects the whole patch server-side;
  pruning it here would leave you believing a field was set when it was dropped. Check
  yourself with `patch_field_allowed(spec, field)` if you want to know before you send.
- **It honours `timeout_ms`.** The handler runs inside the window the server declared, and a
  reply whose window has closed is abandoned rather than published late.
- **Shutdown drains (§18).** Cancel the `reactor_serve` task; it stops taking deliveries, lets
  every dispatch already running finish — handler, signature, publish — and only then closes
  the channel and connection.
- **TLS is not optional (§8b).** `aio_pika_dialer` accepts `amqps://` only and refuses a
  plaintext URL rather than downgrading. `ca_bundle=` takes a path or inline PEM for a
  privately-issued broker certificate; there is no verification-skip switch under any name.

#### Registering a reactor (§22.9)

Registration is a REST admin call, not part of this runtime:

```bash
curl -X POST https://axiam.example.com/api/v1/reactors \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"fraud-check","events":["login.post_auth"],"mode":"intercept","timeout_ms":500}'
```

The response's `id` is what `reactor_id` takes, and the server declares the queue.
`timeout_ms` defaults to **500** and is refused outside `1…5000`; the chain's wall-clock
ceiling is **5000 ms** and the per-tenant in-flight cap is **64**. This SDK exposes those as
constants (`DEFAULT_REACTOR_TIMEOUT_MS`, `MAX_REACTOR_TIMEOUT_MS`,
`DEFAULT_REACTOR_MAX_IN_FLIGHT`) but ships **no typed client for the CRUD endpoints** — call
them through the REST client and let the server validate; §22.9 explicitly warns against
re-deriving `PUT` merge semantics or the `failure_policy` re-derivation client-side.

#### Logging

The `payload`, `patch`, `reason` and `decision` are tenant business data — readable by design,
since a handler that cannot inspect the event cannot decide anything, but this runtime never
logs them at info level and yours should not either (§22.12). The signing key is never logged
at any level and never appears in an error payload; `signing_key_fingerprint()` gives eight
hex characters for an operational log instead. `nonce`, `correlation_id` and `hmac_signature`
are not secrets and may be logged for correlation.

### Local token verification (§10.1)

Both framework guards below verify the access token **locally** and therefore
apply the complete CONTRACT.md §10.1 minimum local-verification set, through
the single entry point `JwksVerifier.verify_access_token(...)`:

| # | Claim | What this SDK does |
|---|-------|--------------------|
| 1 | signature | `alg` pinned to `EdDSA` and checked **before** any JWKS lookup, so `alg: none` and HS-family confusion are rejected without ever consulting a key |
| 2 | `exp` | **Required** and must be a JSON number — a token with no `exp` is a permanent credential and is rejected, and a numeric *string* `exp` (which PyJWT would coerce) is rejected too |
| 3 | `nbf` | Honoured when present; absent is valid |
| 4 | `tenant_id` | **Required** and asserted against the configured tenant; no configured tenant fails closed |
| 5 | `iss` | Checked **only** when `expected_issuer` is configured (optional, unset by default — no issuer is ever assumed) |
| 6 | `aud` | Checked **only** when `expected_audience` is configured; a user-facing resource server should pass `RECOMMENDED_RESOURCE_SERVER_AUDIENCE` (`"axiam:user"`) |
| 7 | clock skew | `DEFAULT_CLOCK_SKEW_SECONDS` (60 s), bounded by `MAX_CLOCK_SKEW_SECONDS` — never settable to an unbounded value |

```python
from axiam_sdk._jwks import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    RECOMMENDED_RESOURCE_SERVER_AUDIENCE,
    JwksVerifier,
)

verifier = JwksVerifier(
    base_url,
    expected_issuer="https://axiam.example.com",  # optional
    expected_audience=RECOMMENDED_RESOURCE_SERVER_AUDIENCE,  # optional
    clock_skew_seconds=DEFAULT_CLOCK_SKEW_SECONDS,  # bounded
)
```

`JwksVerifier.verify_signature_only_unchecked(...)` is the raw signature-only
primitive §10.1 permits for integrators implementing their own policy. Its
name states the omission: it checks **no** claims at all, and the SDK's own
guards never call it.

### FastAPI dependency (§10) — `axiam-sdk[fastapi]`

```python
from fastapi import Depends, FastAPI
from axiam_sdk.fastapi import AxiamUser, JwksVerifier, require_authenticated_user

verifier = JwksVerifier(base_url)
authenticated_user = require_authenticated_user(verifier, "acme")

app = FastAPI()


@app.get("/protected")
async def protected(user: AxiamUser = Depends(authenticated_user)):
    return {"user_id": user.user_id, "tenant_id": user.tenant_id, "roles": user.roles}
```

See [`examples/fastapi_dependency.py`](./examples/fastapi_dependency.py).

### Django middleware (§10) — `axiam-sdk[django]`

```python
# settings.py
MIDDLEWARE = [..., "axiam_sdk.django.middleware.AxiamAuthMiddleware"]
AXIAM_JWKS_BASE_URL = "https://localhost:8443"
AXIAM_TENANT_SLUG = "acme"

# Optional §10.1 rule 5-7 settings; all default to unset / the recommended value.
AXIAM_EXPECTED_ISSUER = "https://localhost:8443"  # unset -> iss not checked
AXIAM_EXPECTED_AUDIENCE = "axiam:user"  # unset -> aud not checked
AXIAM_CLOCK_SKEW_SECONDS = 60  # bounded by MAX_CLOCK_SKEW_SECONDS
```

```python
# views.py
def protected_view(request):
    user = request.axiam_user
    return JsonResponse({"user_id": user.user_id, "roles": user.roles})
```

See [`examples/django_middleware.py`](./examples/django_middleware.py).

### Declarative authorization helpers (§11)

Layered on top of the §10 authentication guards above, `require_access` /
`require_role` add a per-endpoint AXIAM authorization check without hand-
writing `check_access(...)` calls in every handler. They run strictly
*after* authentication (never a separate/duplicated token-verification
path) and check the *request's authenticated caller* (`subject_id`), never
the SDK client's own — typically service-account — identity. Error
mapping: unauthenticated -> 401; denied -> 403; an
unresolvable resource id -> 400; a transport failure while calling the
authz endpoint -> 503 (fail closed — never allow on a transport error). No
decision caching: every request is a fresh `check_access` round-trip.
`require_role` is a local, no-round-trip check against the verified
identity's roles — cheaper but coarser, and NOT a substitute for
`require_access`'s authoritative, resource-level check.

**FastAPI** (`axiam-sdk[fastapi]`) — `require_access` takes the async
`AsyncAxiamClient`:

```python
from fastapi import Depends, FastAPI
from axiam_sdk import AsyncAxiamClient
from axiam_sdk.fastapi import AxiamUser, JwksVerifier, require_access, require_role

verifier = JwksVerifier(base_url)
authz_client = AsyncAxiamClient(base_url=base_url, tenant_slug="acme")

app = FastAPI()

require_doc_read = require_access(
    verifier, "acme", authz_client, "documents:read", resource_param="doc_id"
)


@app.get("/docs/{doc_id}")
async def get_doc(doc_id: str, user: AxiamUser = Depends(require_doc_read)):
    return {"message": f"user {user.user_id} may read document {doc_id}"}


require_admin_role = require_role(verifier, "acme", "admin")


@app.delete("/admin/cache")
async def reset_cache(user: AxiamUser = Depends(require_admin_role)):
    return {"message": f"cache reset by {user.user_id}"}
```

The resource id is resolved, in precedence order, from a literal
`resource_id=` (singleton resources), a `resource_param=` path parameter
name, or a `resolver=lambda request: ...` callback (body fields, headers,
composite lookups) — exactly one must be supplied.

**Django** (`axiam-sdk[django]`) — `require_access`/`require_role` are view
decorators reading `request.axiam_user` (set by `AxiamAuthMiddleware`) and
take the sync `AxiamClient`:

```python
from axiam_sdk import AxiamClient
from axiam_sdk.django.decorators import require_access, require_role

authz_client = AxiamClient(base_url="https://localhost:8443", tenant_slug="acme")


@require_access(authz_client, "documents:read", resource_param="doc_id")
def get_document(request, doc_id):
    user = request.axiam_user
    return JsonResponse({"message": f"user {user.user_id} may read document {doc_id}"})


@require_role("admin")
def reset_cache_view(request):
    return JsonResponse({"message": f"cache reset by {request.axiam_user.user_id}"})
```

Both async and sync Django views are supported (`require_access`/
`require_role` detect the wrapped view's dispatch mode automatically).
`resource_param` defaults to `"pk"`, matching the view kwarg Django's own
URL path converters typically bind a captured resource identifier to.

See [`examples/fastapi_dependency.py`](./examples/fastapi_dependency.py) and
[`examples/django_middleware.py`](./examples/django_middleware.py).

## OIDC / SSO relying-party helpers (§12)

`AxiamClient`/`AsyncAxiamClient` expose the nine canonical §12 operations
directly (this SDK has no browser-bundle constraint, so — unlike the
TypeScript SDK's dedicated `OidcClient` — the methods live on the same
client used for everything else). They let a backend application offer
"Login with AXIAM" (authorization-code + PKCE against AXIAM's own OIDC
provider), authenticate itself as a service account (`client_credentials`),
introspect/revoke tokens, and drive the server's upstream-IdP federation
endpoints:

| Operation | Purpose |
|-----------|---------|
| `oidc_discover()` | `GET /.well-known/openid-configuration` — cached per origin, ≥5-minute TTL, single-flight |
| `oidc_begin(...)` | Build the authorization URL + PKCE verifier/state/nonce — **pure local computation, no network I/O** |
| `oidc_exchange(...)` | `POST /oauth2/token` (`authorization_code`) — validates the returned ID token in full (§12.4) before returning |
| `oidc_refresh(...)` | `POST /oauth2/token` (`refresh_token`) — a **distinct** operation from `refresh()`, under the same §9 single-flight guard |
| `login_client_credentials(...)` | `POST /oauth2/token` (`client_credentials`) — service-account M2M login, no `id_token` |
| `introspect(...)` | `POST /oauth2/introspect` (RFC 7662) — requires confidential-client credentials |
| `revoke(...)` | `POST /oauth2/revoke` (RFC 7009) — idempotent; any `200` (including for an unknown token) is success |
| `sso_start(...)` | `POST /api/v1/auth/federation/oidc/start` — step 1 of upstream-IdP SSO |
| `sso_complete(...)` | `POST /api/v1/auth/federation/oidc/callback` — step 2; the session arrives via `Set-Cookie`, no token in the body |

Both `AxiamClient` (sync) and `AsyncAxiamClient` (async, `async def` twins
under the *same* names, SDK-Q08) expose all nine — including `oidc_begin`,
which performs no I/O but is still `async def` on the async client, per
CONTRACT.md §12.2's Python naming table.

**The caller owns the login state (§12.3 rule 1).** `oidc_begin` returns
`state`, `nonce`, and `code_verifier` and stores none of them anywhere — no
process-global cache, no implicit session. Persist all three yourself
(typically in your own HTTP session) between the login redirect and the
callback, and pass `nonce`/`code_verifier` back into `oidc_exchange`
explicitly. `MemoryOidcStateStore` (single-use `consume`, 10-minute TTL) is
available for framework integrations that need somewhere to park that
triple across the two HTTP requests of a redirect flow — it is optional and
per-instance, never process-global.

```python
from axiam_sdk import AxiamClient, OAuthProtocolError, AuthError

client = AxiamClient(
    base_url="https://localhost:8443",
    tenant_slug="acme",
    client_id="my-backend-app",
    client_secret="changeme",  # omit for a public client
)

configuration = client.oidc_discover()
request = client.oidc_begin(
    configuration=configuration,
    redirect_uri="https://app.example.com/oidc/callback",
    scope="openid profile email",
)
# ... persist request.state / request.nonce / request.code_verifier,
# redirect the browser to request.url, and receive the callback ...

try:
    tokens = client.oidc_exchange(
        code=callback_code,
        code_verifier=request.code_verifier,
        redirect_uri="https://app.example.com/oidc/callback",
        nonce=request.nonce,
        tenant_id="00000000-0000-0000-0000-000000000000",
    )
except OAuthProtocolError as exc:
    print(f"{exc.error}: {exc.error_description}")
except AuthError as exc:
    print(f"login failed ({exc.reason}): {exc}")
else:
    print(tokens.id_claims.sub if tokens.id_claims else "no id_token")
```

`OAuthProtocolError` is a language-idiomatic **sub-type of `AuthError`**
(CONTRACT.md §2/§12.3 rule 3) — existing `except AuthError:` code keeps
matching it unchanged. It carries `error`/`error_description` and
`str(exc) == "<error>: <error_description>"`. Every §12.4 ID-token
validation failure raises the plain `AuthError` with a stable
`reason` — one of `invalid_alg`, `unknown_kid`, `invalid_signature`,
`invalid_issuer`, `invalid_audience`, `token_expired`, `nonce_mismatch`.

`access_token`, `refresh_token`, `id_token`, `client_secret`, and
`code_verifier` are all `pydantic.SecretStr` (§7/§12.5) — never printed or
serialized in the clear; read the raw value via `.get_secret_value()`.
`state`/`nonce` are plain strings (§12.3 rule 2 — not secrets).

**Framework glue.** `axiam_sdk.fastapi.oidc_login_router(client, redirect_uri=...)`
builds a two-route `APIRouter` (login redirect + callback); `axiam_sdk.django.oidc.oidc_login_views(client, redirect_uri=...)`
builds a `(login_view, callback_view)` pair sharing one state store. Both
delegate entirely to the operations above and to the existing session/cookie
machinery — see [`examples/oidc_login.py`](./examples/oidc_login.py).

## OPAQUE (§23)

`login_opaque` authenticates the password without sending it. What crosses the
wire is a blinded group element and a MAC, neither useful without the account's
registration record **and** the tenant's OPRF seed.

```python
# Same LoginResult as login(), including the mfa_required case.
result = client.login_opaque("alice", "correct horse battery staple")
```

Unlike the SRP-6a this replaces, it returns without verifying a server proof
separately, and nothing is missing: RFC 9807's AKE authenticates the server
during the handshake, so opening `KE2` **is** the proof that it holds the
record. The old contract had to mandate an `M2` check in capitals because
skipping it kept only half the protocol; there is now nothing to skip.

Fall back to `login()` when the tenant does not offer OPAQUE. That case is a
`NetworkError`, deliberately **not** an `AuthError`, so it cannot be mistaken
for a bad password:

```python
try:
    result = client.login_opaque(user, password)
except NetworkError as exc:
    if "opaque_mode is disabled" not in str(exc):
        raise  # a KSF this build cannot perform — not a fallback case
    result = client.login(user, password)
```

`AuthError` from `login_opaque` is the whole of the authentication check, and
covers both halves of the mutual authentication: a wrong password, an account
that does not exist, and a server that does not hold the record are
indistinguishable by design. **Do not retry over `login()`** — that hands the
plaintext to an endpoint that just failed to prove it holds the record (§23.4
rule 7).

### Enrolment

The server cannot build a registration record — it never sees the plaintext —
so one has to be sent with any request that sets a password:

```python
enrollment = client.opaque_enrollment("new password")
# send enrollment["registration_record"] and enrollment["opaque_session"]
# as the request's `opaque` object
```

It is `async`/one round trip because OPAQUE's envelope is sealed under the
server's oblivious PRF: there is no offline computation that produces a valid
record. Note the absence of an `identity` argument. The SRP version required
the account's canonical username, and passing an email produced a verifier no
login could ever satisfy; a record binds to a credential identifier the server
chooses, so there is nothing here to get wrong — and a later rename cannot
invalidate a credential.

There is also no `group` or `kdf` argument. The key-stretching function comes
from the `*/start` response, every time: a credential enrolled under one cost
keeps working after a tenant raises its policy, so a client that used local
defaults would derive a different randomized password and fail against a good
record.

### Installing

The protocol itself is **not** in this SDK. CONTRACT.md §23.1 forbids an SDK
from implementing OPAQUE — it needs an oblivious PRF, `hash_to_curve`,
`expand_message_xmd`, an envelope construction and a three-message AKE, and
eleven independent implementations of that is eleven chances to be subtly and
silently wrong. What ships here is a `ctypes` binding to
`libaxiam_opaque_ffi`, the same implementation the AXIAM server links.

That library is a Rust `cdylib` published as a per-platform asset on the
[axiam release page](https://github.com/ilpanich/axiam/releases), not a PyPI
distribution — so there is no `axiam-sdk[opaque]` extra, and a name that
installed nothing while reading as though it installed the thing would be worse
than its absence. Put the file on the loader path, or point an environment
variable at it:

```bash
export AXIAM_OPAQUE_LIBRARY=/opt/axiam/libaxiam_opaque_ffi.so
```

Ask before you need it:

```python
if client.opaque_available():
    result = client.login_opaque(user, password)
else:
    result = client.login(user, password)
```

It reports rather than raising, so an application can choose the password path
up front instead of discovering the gap mid-exchange. When it is absent,
`login_opaque` raises a `NetworkError` naming the artifact and the environment
variable — never something that looks like a wrong password.

### Two things that will bite you

**It blocks, and on `AsyncAxiamClient` it blocks the event loop.** The KSF is
CPU-bound: Argon2id at 19 MiB by default, tens to hundreds of milliseconds. That
cost is what makes a stolen record expensive to attack even by someone holding
the OPRF seed. On a server handling other requests, wrap the call in
`asyncio.to_thread`.

**What it protects, and what it does not.** A TLS-terminating proxy, an
accidentally verbose request log, or a heap dump on the server cannot capture a
plaintext password, because the server never has one — and a stolen record
database is not offline-crackable on its own without the tenant's OPRF seed,
which is the pre-computation resistance SRP could not offer. It does **not**
protect against a compromised AXIAM server.

See [`examples/opaque_login.py`](./examples/opaque_login.py).

## WebAuthn and passkeys (§24)

A passkey ceremony is **two exchanges stacked**: one with an *authenticator*,
which needs a platform API, and one with *AXIAM*, which is four ordinary JSON
round trips. Python has no authenticator, so this SDK ships the second half.

That is not a consolation prize. A Python service completing a ceremony that ran
on an Android or iOS handset is the relying party exactly as a browser is — and
§24.6b rule 2 forbids the alternative outright: an SDK must not emulate an
authenticator in software, because a "credential" held in process memory is not
a second factor.

### The three-step shape

```python
from axiam_sdk import AxiamClient, webauthn_request_json

client = AxiamClient(base_url=..., tenant_slug="acme", org_slug="globex")

challenge = client.webauthn_discoverable_start()

# The JSON form every platform authenticator API takes (§24.6a) — the exact
# string Android's CreatePublicKeyCredentialRequest and a browser's
# parseCreationOptionsFromJSON() both want.
response_json = your_device_channel(webauthn_request_json(challenge))

session = client.webauthn_discoverable_finish(
    state_token=challenge.state_token,
    response=response_json,  # the platform's string, verbatim
)
```

The client is authenticated when that returns — §24.3 rule 1 is not a "MAY
adopt". `webauthn_register_start`/`_finish` and
`webauthn_authenticate_start`/`_finish` follow the same shape, for enrolling a
credential and for a passkey used as a second factor after `login()` answered
`mfa_required`.

Both `*_finish` operations take either a parsed mapping or the platform's own
JSON string. Requiring a caller to destructure one into a dict this SDK
immediately re-serializes is three chances to corrupt a signed buffer in service
of nothing.

### What the SDK will not do

**It never adjusts an option.** The server generates the challenge and chooses
`residentKey`, `userVerification`, the attestation conveyance, the exclusion list
and the timeout; this SDK carries all of it through unchanged and posts the
answer back unchanged. Not because those fields are hard — because they are not,
and relaxing `userVerification` to `"preferred"` because a test authenticator
kept prompting weakens a ceremony the server believes it configured. The server
cannot catch it: an assertion produced under weaker options is a valid assertion.

**It never parses `state_token`.** It is opaque, it is a `SecretStr`, and it goes
straight back to the matching `*_finish`.

### Classifying a device's failure

Every platform reports a ceremony failure as one opaque type whose only
machine-readable part is a name — so a handset can relay just that name, and a
Python service can turn it into the same five outcomes a browser would see:

```python
from axiam_sdk import WebauthnFailure, classify_webauthn_error, webauthn_error_message

failure = classify_webauthn_error(name_relayed_by_the_device)
if failure is WebauthnFailure.ALREADY_REGISTERED:
    ...  # the only outcome whose remedy is "use a different device"
show(webauthn_error_message(failure))
```

`CANCELLED` covers **both** an explicit refusal and a silent timeout. The
WebAuthn spec deliberately refuses to distinguish them, because telling a website
which one happened leaks whether an authenticator was present — so the copy does
not accuse anyone of cancelling, and the distinction must not be recovered by
timing the call.

### Two error rows that are not the generic mapping

- A **`403` on `webauthn_register_finish`** is the tenant's attestation policy
  refusing *this authenticator* — an AAGUID that is not allow-listed, a missing
  FIDO certification, a revoked status — not a permission problem with the user.
  The server's message is surfaced verbatim, because it is the only way the
  person holding the key learns a different one would work.
- A **`503` on `webauthn_register_start`** means attestation is required and the
  FIDO metadata service has no usable snapshot. A server configuration state,
  not a transient failure, and deliberately **not** retried.

Worked example: [`examples/webauthn_relying_party.py`](examples/webauthn_relying_party.py).

## Account lifecycle and MFA enrolment (§25)

§1 locks the *middle* of an account's life — `login`, `verify_mfa`, `refresh`,
`logout` all assume an account that already exists, is verified, and already has
its second factor. These nine operations are how it gets there.

```python
enrolment = client.mfa_enroll()
render_qr(enrolment.totp_uri.get_secret_value())
client.mfa_confirm(totp_code=code_typed_by_user)  # → True once it is live
```

`secret_base32` and `totp_uri` are both `SecretStr`, and the URI is the one that
matters: it *is* `otpauth://…?secret=…`, so it contains the secret it sits beside.
Wrapping only the secret would have wrapped nothing — the URI is the field that
actually reaches a log, because it is the field you hand to a QR renderer.

### `login()` has a third outcome

`LoginResult` gains `mfa_setup_required` and `setup_token`. The server has always
been able to answer `403 mfa_setup_required` for an account in a tenant that
requires MFA; it used to reach you as an `AuthzError`, saying you lacked
permission to log in when what the server said was recoverable.

```python
result = client.login(email, password)
if result.mfa_setup_required:
    enrolment = client.mfa_setup_enroll(setup_token=result.setup_token)
    render_qr(enrolment.totp_uri.get_secret_value())
    client.mfa_setup_confirm(setup_token=result.setup_token, totp_code=code)
```

Additive here rather than a new variant, because this model has always been one
type with flags rather than a discriminated union — so nothing that reads
`mfa_required` today has to change. A genuine authorization refusal is still an
`AuthzError`: the SDK matches on the body's discriminant, not on the `403` alone.

### Email verification and password reset

```python
client.verify_email(token=token_from_link, tenant_id=tenant_id)
client.resend_verification(email=email, tenant_id=tenant_id)
client.request_password_reset(email=email)
```

`request_password_reset` returns normally **whether or not the address exists**,
and this SDK exposes no way to tell them apart. Any signal distinguishing them —
including one inferred from timing — turns the endpoint into the account
enumeration oracle its uniform response exists to prevent.

Setting the new password takes one extra call on any tenant that might have
OPAQUE enabled, because the client has to build a registration record and cannot
know the parameters before it has a token to ask with:

```python
context = client.password_reset_context(token=token)
client.confirm_password_reset(
    token=token,
    new_password=new_password,
    tenant_id=tenant_id,
    opaque=client.opaque_enrollment(new_password) if context.opaque else None,
)
```

The context discloses no identity, and a `404` covers unknown, expired and
already-consumed without distinguishing them.

Worked example: [`examples/account_lifecycle.py`](examples/account_lifecycle.py).

## Pushed authorization requests (§26)

PAR (RFC 9126) moves the authorization request off the browser: the client POSTs
`scope`, `redirect_uri`, `state` and the PKCE challenge straight to AXIAM over an
authenticated back channel and puts an opaque `request_uri` in the redirect, so
what travels through the user agent is a random string that cannot be edited into
meaning something else.

Required for a FAPI 2.0 client — `profile: "fapi2"` refuses a registration that
does not set `require_par`.

```python
configuration = client.oidc_discover()
request = client.oidc_begin(configuration=configuration, redirect_uri=uri, scope="openid profile")

pushed = client.oidc_par(
    request=request,
    redirect_uri=uri,
    scope="openid profile",
    configuration=configuration,
    tenant_id=tenant_id,
)
redirect(pushed.authorization_url)

# …on the callback, unchanged by PAR:
tokens = client.oidc_exchange(
    code=code,
    redirect_uri=uri,
    nonce=pushed.nonce,
    code_verifier=pushed.code_verifier,
    tenant_id=tenant_id,
)
```

`oidc_begin` still does the computing — there is no second generator for `state`,
`nonce` and PKCE — and `pushed.code_verifier` is the one it produced, so there is
exactly one value to keep.

Three things that are easy to get wrong:

1. **The endpoint answers `201`, not `200`.** RFC 9126 §2.2 specifies Created, and
   a success predicate written `== 200` treats every successful push as a failure.
2. **The authorization URL carries exactly `client_id` and `request_uri`.** The
   server *refuses* a request mixing a `request_uri` with inline authorization
   parameters rather than merging them, and re-adding them "for compatibility"
   restores the parameter-confusion attack the refusal prevents.
3. **`request_uri` is single-use and short-lived.** There is nothing to retry with
   it; the safe recovery is a fresh push. `oidc_par` is correspondingly never
   retried on a `5xx` or a transport failure — it is a POST that creates state.

Worked example: [`examples/par_login.py`](examples/par_login.py).

## Device authorization grant (§14)

RFC 8628 — signing in a device that cannot show a browser: a TV, a CLI, a
headless commissioning tool. `device_authorize`, `device_poll` and the composed
`device_login`, on both `AxiamClient` and `AsyncAxiamClient`.

```python
def show(auth: DeviceAuthorization) -> None:
    # Called BEFORE the first poll. Display it however the device can —
    # screen, QR code, e-ink panel. The SDK never prints it for you.
    print(f"visit {auth.verification_uri} and enter {auth.user_code}")


tokens = client.device_login(show, scope="openid profile")
```

The polling rules are where implementations go wrong, so they are worth
stating:

- **`slow_down` raises the interval permanently.** An SDK that backs off for
  one round and returns to the original interval will be told to slow down
  again, forever.
- **`access_denied` and `expired_token` stay distinct.** A human said no,
  versus nobody answered — the only information the device can act on.
- **Polling stops at `expires_in`**, even if the server has not yet said
  `expired_token`.
- **A `5xx` mid-poll is not terminal.** A server restart must not lose a grant
  the user has already approved.

`device_code` is a `SecretStr`; `user_code` deliberately is not — it exists to
be read aloud, and wrapping it would defeat the one thing it is for.

`device_authorize` sends no `client_secret` and does not refuse a client built
without one: a device that cannot show a browser cannot keep a secret either.
The async `device_login` **awaits** an async callback before polling, so a
device that needs to await a paint still satisfies §14.3 rule 2.

Per §14.3 rule 4, `device_login` **returns** the token set rather than adopting
it, matching this SDK's `login_client_credentials` posture. See
[`examples/device_login.py`](./examples/device_login.py).

## Token exchange (§15)

RFC 8693 — a service holding a user's token exchanging it for a *narrower* one
before calling the next service.

```python
from axiam_sdk import ACCESS_TOKEN_TYPE

exchanged = client.token_exchange(
    subject_token=user_token,
    subject_token_type=ACCESS_TOKEN_TYPE,  # required (§15.1), no default
    scopes=["orders:read"],
    audience="orders-service",
)
```

Most of what this method does is refuse to be helpful, and each refusal is
deliberate:

- **No default `actor_token`.** Omitting it asks for *impersonation*; the SDK
  will not quietly substitute the client's own session token and turn that into
  a delegation.
- **No auto-narrowing after `invalid_scope`.** The server refuses rather than
  silently narrowing precisely so the caller finds out here.
- **No refresh token, ever** — `ExchangedToken` has no such field, so there is
  nothing to synthesise. Re-run the exchange.
- **No adoption.** The issued token is handed onward in one call; adopting it
  would silently re-privilege every later call this client makes. A MUST NOT,
  where `login_client_credentials` adoption is a MAY.

See [`examples/token_exchange.py`](./examples/token_exchange.py).

### External-IdP subject tokens (§15.7)

The same method exchanges a token minted by a **trusted external IdP** — a
partner's Entra, Okta or Keycloak — for an AXIAM token scoped to what the
resolved AXIAM user may actually do. There is no separate operation:

```python
from axiam_sdk._oidc import JWT_TOKEN_TYPE

exchanged = client.token_exchange(
    subject_token=partner_token,
    subject_token_type=JWT_TOKEN_TYPE,  # named, never guessed
    scopes=["read:orders"],
    audience="https://orders.internal",
)
```

- **`subject_token_type` is yours to state, and is required** (§15.1). The SDK
  never decodes the subject token to pick it, and never overrides what you
  named. There is no default — omitting it raises `TypeError` before any wire
  call, because a default would be the SDK choosing for you.
- **No actor token.** Delegation across a trust boundary is unsupported in v1;
  sending one is `invalid_request`, which the SDK will not work around by
  dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose description is
  `the subject token's issuer is not configured for token exchange` means *fix
  the AXIAM trust configuration*. Every other `invalid_grant` means *fix your
  token*, and is deliberately generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the
  partner issuer; never strip it, and never read it as an authorization input.
  It also cannot be exchanged again — exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

## Logout — RP-initiated and back-channel (§12.7)

`logout_url` builds the redirect; `verify_logout_token` validates a token the
OP **pushed** to your back-channel endpoint.

```python
url = client.logout_url(id_token=stored_id_token)

# …and at your registered backchannel_logout_uri:
verified = client.verify_logout_token(logout_token)
if verified.sid is not None:
    end_session(verified.sid)  # that session ONLY
```

The verifier is where the security weight sits — the input arrives unsolicited
and instructs you to terminate a session. It checks the signature (same JWKS
path, same `kid`-required discipline as §12.4), `iss`, `aud`, that `events`
carries the back-channel-logout key (**the only thing separating a logout token
from an ID token**), that `nonce` is *absent* (its presence is how an ID token
gets replayed as one), that something is named, and freshness.

It returns `sid`/`sub`/`jti` rather than a bare `bool`: you have to know
*which* session to end. **Dedup on `jti` yourself** — delivery is at-least-once,
so a valid token legitimately arrives twice; the SDK has no durable store and
an in-memory guard would silently drop a real second logout after a restart.

See [`examples/logout.py`](./examples/logout.py).

## Webhook signature verification (§13)

`axiam_sdk.webhook.verify_webhook(secret, signature_header, body)` verifies the
`X-Axiam-Signature: t=<unix_seconds>,v1=<hex>` header AXIAM sends on every webhook
delivery — HMAC-SHA256 over `"<timestamp>.<raw_body>"`, compared in constant time,
with a two-sided freshness window (default 300s):

```python
from axiam_sdk.webhook import WebhookVerifyError, verify_webhook


# Flask: request.get_data() is the RAW bytes off the wire. Do NOT verify
# against request.get_json() re-dumped — re-serializing changes key order/
# whitespace and breaks the MAC (CONTRACT.md §13.3 rule 1).
@app.post("/webhooks/axiam")
def axiam_webhook():
    try:
        event = verify_webhook(
            secret=WEBHOOK_SECRET,  # a pydantic.SecretStr or plain str
            signature_header=request.headers["X-Axiam-Signature"],
            body=request.get_data(),  # raw bytes, NOT re-serialized JSON
        )
    except WebhookVerifyError:
        return "invalid signature", 400

    # X-Axiam-Delivery (event.delivery_id, if you pass it through — see
    # below) is the at-least-once dedup key: retries replay a validly-
    # signed delivery inside the freshness window, so keep a short-lived
    # seen-set if double-processing an event would be unsafe.
    ...
    return "", 200
```

FastAPI is the same shape with `await request.body()` in place of
`request.get_data()` — both give you the exact raw bytes the server signed;
`await request.json()` does not, for the same re-serialization reason.

`verify_webhook` also accepts `event_type`/`delivery_id` (pass the raw
`X-Axiam-Event`/`X-Axiam-Delivery` header values straight through — neither
is covered by the MAC) so the returned `WebhookEvent` carries them, a
`tolerance` override (seconds, default 300), and a `now` injection seam for
tests. `WebhookVerifyError`'s message never includes the expected/computed
signature or the secret.

## gRPC stub generation (D-04)

`pip install`-ing this package does not require `buf`/`protoc` — the
generated gRPC stubs (`src/axiam_sdk/grpc/gen/`) are committed and shipped
in both the wheel and the sdist. Contributors regenerating them locally run:

```bash
bash scripts/gen_grpc.sh
```

CI regenerates the same way and fails the build on any drift
(`git diff --exit-code`) between the committed stubs and a fresh
regeneration from `proto/axiam/v1/`.

## TLS policy (§6)

`httpx` clients are constructed with `verify=True` hardcoded; the only
escape hatch is an explicit `custom_ca` parameter (a CA bundle path or
`ssl.SSLContext`) — there is no boolean bypass anywhere in this SDK,
including the examples. CI enforces this with a dedicated grep gate.

### mTLS / client certificates (§6.1)

For IoT devices and service accounts that authenticate by **mutual TLS**, pass
a PEM client-certificate chain plus its PEM private key (each `str` or
`bytes`). The same identity is applied to both the REST and gRPC transports of
the client, and presenting it **never** relaxes server verification — strict
TLS (`§6`) stays fully on.

```python
from axiam_sdk import AxiamClient

with open("device-cert.pem", "rb") as f:
    client_cert = f.read()
with open("device-key.pem", "rb") as f:
    client_key = f.read()

client = AxiamClient(
    base_url="https://axiam.example.com",
    tenant_slug="acme",
    custom_ca="/etc/axiam/org-ca.pem",  # server trust (optional; system roots by default)
    client_cert=client_cert,  # PEM cert chain (str or bytes)
    client_key=client_key,  # PEM private key (str or bytes)
)
# AsyncAxiamClient(...) takes the identical client_cert=/client_key= parameters.
```

`client_cert` and `client_key` must be supplied together (only one is a
construction-time error), and a non-PEM value is rejected at construction. The
private key is secret material: it is loaded straight into the TLS stack and is
never logged, stored as a public attribute, or exposed via a getter (`§6.1`
rule 3 / `§7`). The gRPC authorization clients accept the same
`client_cert=`/`client_key=` parameters.

## Development

```bash
pip install -e ".[dev,fastapi,django]"
pytest tests
mypy --strict src
ruff check .
ruff format --check .
```

Coverage (as CI runs it, reported to Coveralls):

```bash
pytest --cov=axiam_sdk --cov-report=lcov
```

## Client quality-of-life (CONTRACT.md §16–§19)

### Retry policy (§16)

Read-only authorization checks — `check_access`, `can`, `batch_check`, on both the sync and
async clients — retry transient failures under the contract's normative table: **3 attempts**
(1 initial + 2 retries), 200 ms base, 5 s cap, **full jitter** (uniform over `[0, backoff]`),
and `Retry-After` honored as a **floor**.

This SDK had no §16 policy before — only §9.3's refresh-then-retry-once, which is a different
mechanism. §11.2 rule 5 had been requiring one since it was written.

Only failures that could plausibly succeed on a second attempt are retried: transport errors,
`408`, `429`, `5xx`. A `401` or `403` is an answer, not a transport failure, and surfaces after
exactly one attempt. Nothing that changes server state is ever retried.

```python
# Turn it off if you own your own retry layer — you know your deadline, this SDK doesn't.
client = AxiamClient(base_url=..., tenant_slug="acme", retry_enabled=False)
```

There is deliberately no knob for the attempt cap, base delay or delay cap: §16.1 forbids
raising them, and eleven SDKs agreeing on one table is the point.

### Deterministic shutdown (§18)

`client.close()` (sync) and `await client.aclose()` (async) release local resources. Both are
idempotent, and any call afterwards raises `NetworkError` naming the cause rather than silently
reconnecting.

**Neither logs out.** They never reach the network. The server-side session deliberately
outlives the client object — that is what lets a process restart and resume — so a `close()`
that logged out would silently end every user's session on each deploy. Call `logout()` first
if ending the session is what you want.

### Telemetry hooks (§19)

Wire metrics without this package depending on any metrics library:

```python
from axiam_sdk import AxiamClient, RequestEnd, Retry, TelemetryEvent


def sink(event: TelemetryEvent) -> None:
    if isinstance(event, RequestEnd):
        histogram.record(event.duration_ms, {"op": event.operation, "outcome": event.outcome})
    elif isinstance(event, Retry):
        counter.add(1, {"op": event.operation, "attempt": event.attempt})


client = AxiamClient(base_url=..., tenant_slug="acme", telemetry_hook=sink)
```

- **A hook that raises cannot fail the operation that fired it.** Telemetry is not permitted to
  fail an authorization check.
- **No event payload can carry a token.** The event dataclasses are frozen with a fixed field
  set — this surface exists to be shipped to a metrics backend.
- **Path templates, not URLs**, so a metric label cannot become a cardinality bomb.

One `RequestStart`/`RequestEnd` pair is emitted **per attempt**, so you can count real wire
calls. See [`examples/telemetry_hook.py`](examples/telemetry_hook.py) for the OpenTelemetry
mapping.

### Decision memo (§17) — opt-in, off by default

An optional TTL-bounded cache for `check_access` results. **Disabled by default**, because
§11.2 rule 6's ban on caching authorization decisions is still the default behaviour.

```python
client = AxiamClient(base_url=..., tenant_slug="acme", decision_memo_ttl_ms=5000)  # 0 = off
```

**What you are accepting.** The staleness bound is the TTL, in *both* directions: a grant
revoked on the server can still read as allowed for up to the TTL, and a grant just added can
still read as denied for up to the TTL.

> **Reads-your-own-writes is not guaranteed.** An admin UI that grants a role and immediately
> re-checks is the case that breaks, and it breaks silently. If that is your workload, leave
> this off.

The TTL is clamped to 5000 ms rather than rejected. Allows and denies are memoized identically
— asymmetric caching would leak which outcome occurred through latency. Failures are never
memoized: caching a transport error as a deny would turn a blip into a TTL-long outage. The
memo is cleared on `login`, `verify_mfa`, `refresh` and `logout`, since entries are keyed by
subject rather than by session. It is thread-safe.
