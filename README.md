# axiam-sdk (Python)

Official Python client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **Repository:** [github.com/ilpanich/axiam-python-sdk](https://github.com/ilpanich/axiam-python-sdk)
- **PyPI package:** `axiam-sdk`
- **Registry:** [pypi.org/project/axiam-sdk](https://pypi.org/project/axiam-sdk/) _(reserved, not yet published)_
- **Version tags:** `vX.Y.Z`
- **API docs:** [ilpanich.github.io/axiam-python-sdk](https://ilpanich.github.io/axiam-python-sdk/)
- **License:** Apache-2.0
- **Python:** `>=3.10` (D-11)

## Contract conformance

This SDK conforms to CONTRACT.md §1–§11.

See [`CONTRACT.md`](./CONTRACT.md) for the full cross-language behavioral contract.

## Status

Implemented (Phase 19). `AxiamClient` (sync) and the dedicated
`AsyncAxiamClient` (async, SDK-Q08) each expose the same canonical operation
names — `login`, `verify_mfa`, `refresh`, `logout`, `check_access`, `can`,
`batch_check` — as sync or `async def` methods respectively (never an
`async_*`-prefixed twin on the sync class). Each client owns its own session,
cookie jar, and single-flight refresh guard. gRPC (sync `grpcio` + async
`grpc.aio`), AMQP (async-only `aio-pika`), a FastAPI dependency, and a Django
middleware are all available. Six runnable examples live under
[`examples/`](./examples).

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
# tenant (§5). TLS is always verify=True (§6); the only escape hatch is an
# explicit custom_ca parameter, never a boolean bypass.
with AxiamClient(base_url="https://localhost:8443", tenant_slug="acme") as client:
    result = client.login(email, password)
    if result.mfa_required:
        result = client.verify_mfa(result.mfa_token, totp_code)
    print(result.session_id, result.expires_in)
```

```python
import asyncio
from axiam_sdk import AsyncAxiamClient

async def main() -> None:
    async with AsyncAxiamClient(base_url="https://localhost:8443", tenant_slug="acme") as client:
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
results = client.batch_check([
    AccessCheck(action="resource:read", resource_id=resource_id),
    AccessCheck(action="resource:delete", resource_id=resource_id, scope="admin"),
])
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
