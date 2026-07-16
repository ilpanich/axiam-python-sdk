"""FastAPI ``Depends(...)`` dependency-injection integration (D-09, CONTRACT.md §10/§11).

Verifies an AXIAM access token LOCALLY (no per-request round-trip to the
AXIAM server on a JWKS cache hit) via :class:`axiam_sdk._jwks.JwksVerifier`
and returns the authenticated identity (``user_id``, ``tenant_id``,
``roles``) for injection into a FastAPI route via ``Depends(...)``.

This module is a **dependency-only** integration (D-09) — there is
deliberately no ASGI-middleware variant. It is imported ONLY as
``axiam_sdk.fastapi`` (never from the top-level ``axiam_sdk/__init__.py``,
see Anti-Pattern/T-19-22) so that pure-REST/gRPC/AMQP consumers of
``axiam-sdk`` are never forced to install ``fastapi``.

Security-critical invariant — cross-tenant token replay defense (T-19-19):
the AXIAM JWKS is organization-wide, not tenant-scoped, so a token that is
signature-valid may still belong to a *different* tenant. This dependency
enforces ``claims["tenant_id"] == configured_tenant`` BEFORE any claim is
trusted further — mirrors ``the Go SDK's middleware/nethttp.go`` lines 78-95.

Security-critical invariant — expiry (T-19-20): ``JwksVerifier.verify()``
checks the signature only, not ``exp`` (documented on that class). This
dependency independently rejects an expired-but-signature-valid token.

Security-critical invariant — no token leakage (T-19-21): no raw token
value is ever included in any ``HTTPException`` detail.

CSRF (cookie double-submit, CONTRACT.md §3): a request authenticated via
the ``axiam_access`` COOKIE is not CSRF-immune the way a ``Authorization:
Bearer`` header request is — a cross-site attacker cannot set arbitrary
request headers, but a same-site cookie is attached to cross-site requests
automatically by the browser. For any cookie-sourced credential on a
state-changing method (anything other than GET/HEAD/OPTIONS), this
dependency additionally requires the ``X-CSRF-Token`` request header to be
present and equal (constant-time) to the ``axiam_csrf`` cookie value,
rejecting with 403 on mismatch/absence. This mirrors, locally, the same
double-submit check the AXIAM server performs on its own endpoints (§3) —
see also ``the Java SDK's .../AxiamAuthenticationFilter.java`` for the same
pattern applied to the Spring integration.

CONTRACT.md §11 — declarative authorization helpers: :func:`require_access`
and :func:`require_role` are an *additive* per-endpoint authorization layer
built strictly on top of the authentication pipeline above (shared via the
internal :func:`_authenticate` helper both :func:`require_authenticated_user`
and :func:`require_access` compose with — the §10 verification path, JWKS,
tenant check, CSRF, is never re-implemented or bypassed). ``require_access``
resolves a target resource UUID from the request (§11.3 precedence:
``resource_id`` literal, then ``resource_param`` path parameter, then a
``resolver`` callback), then calls :class:`~axiam_sdk.AsyncAxiamClient`'s
``check_access(...)`` with ``subject_id`` set to the *authenticated caller's*
``user_id`` (§11.2) — never this SDK client's own, typically
service-account, identity. Error mapping (§11.2, §2): unauthenticated -> 401
``authentication_failed``; denied or ``AuthzError`` -> 403
``authorization_denied``; missing/unparseable resource id -> 400
``invalid_request``; ``AuthError``/``NetworkError`` while calling the authz
endpoint (the SDK client could not obtain a decision) -> **fail closed** with
503 ``authz_unavailable``, per §11.2.5's "never allow on transport failure"
rule. No decision caching (§11.2.6) — every call is a fresh authz-endpoint
round-trip. Deny/error paths never log or echo the token (§11.2.8).
``require_role`` is a local, no-round-trip check against the already-
verified identity's ``roles`` (§11.2.9) — it is NOT a substitute for
``require_access``'s authoritative, resource-level server check.
"""

from __future__ import annotations

import hmac
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from fastapi import HTTPException, Request

from axiam_sdk._async_client import AsyncAxiamClient
from axiam_sdk._errors import AuthError, AuthzError, NetworkError
from axiam_sdk._jwks import JwksVerifier

#: Standardized "missing credentials" / "invalid or expired token" / tenant
#: mismatch failures all surface as 401 (CONTRACT.md §10, mirrors
#: nethttp.go's writeError(..., http.StatusUnauthorized, "authentication_failed", ...)).
_AUTH_FAILED_STATUS = 401

#: CSRF double-submit failures surface as 403 (CONTRACT.md §3), mirroring
#: the AXIAM server's own AuthorizationDenied -> "authorization_denied" (403)
#: mapping (crates/axiam-api-rest/src/error.rs) rather than 401.
_CSRF_FAILED_STATUS = 403

_CSRF_COOKIE_NAME = "axiam_csrf"
_CSRF_HEADER_NAME = "x-csrf-token"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: §11.2.5 error mapping for the declarative authorization helpers, layered
#: on top of the §10 statuses above.
_AUTHZ_DENIED_STATUS = 403
_INVALID_REQUEST_STATUS = 400
_AUTHZ_UNAVAILABLE_STATUS = 503


@dataclass(frozen=True)
class AxiamUser:
    """The authenticated identity injected by :func:`require_authenticated_user`.

    Mirrors the Go middleware's ``User`` struct (``user_id``, ``tenant_id``,
    ``roles``) — CONTRACT.md §10's minimum identity fields.
    """

    user_id: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Credential:
    """A verified-candidate token plus whether it was sourced from the
    ``axiam_access`` cookie (as opposed to the ``Authorization`` header) —
    needed to decide whether the CSRF double-submit check applies."""

    value: str
    from_cookie: bool


def _extract_token(request: Request) -> _Credential:
    """Extract the bearer token from ``Authorization: Bearer <token>``,
    falling back to the ``axiam_access`` session cookie.

    Ported 1:1 from ``the Go SDK's middleware/nethttp.go``'s ``extractToken``
    (lines 109-125): Bearer header first, cookie fallback second, standardized
    401 with no token value on failure — this exact ordering is a Shared
    Pattern (19-PATTERNS.md) also used by the Django middleware.
    """
    header = request.headers.get("authorization")
    if header:
        scheme, _, credentials = header.strip().partition(" ")
        if scheme.lower() == "bearer" and credentials.strip():
            return _Credential(credentials.strip(), from_cookie=False)
        raise HTTPException(
            status_code=_AUTH_FAILED_STATUS, detail="missing authentication credentials"
        )

    cookie = request.cookies.get("axiam_access")
    if cookie:
        return _Credential(cookie, from_cookie=True)

    raise HTTPException(
        status_code=_AUTH_FAILED_STATUS, detail="missing authentication credentials"
    )


def _assert_csrf_valid(request: Request) -> None:
    """Cookie double-submit check (CONTRACT.md §3): the ``X-CSRF-Token``
    request header must be present and equal, constant-time, to the
    ``axiam_csrf`` cookie value. Raises ``HTTPException`` 403 on
    mismatch/absence.

    Only called for cookie-sourced credentials on state-changing methods
    (see ``_dependency``) — a Bearer-header request is CSRF-immune by
    construction, since a cross-site attacker cannot set arbitrary request
    headers.
    """
    header = request.headers.get(_CSRF_HEADER_NAME)
    cookie = request.cookies.get(_CSRF_COOKIE_NAME)
    if not header or not cookie or not hmac.compare_digest(header, cookie):
        raise HTTPException(status_code=_CSRF_FAILED_STATUS, detail="CSRF validation failed")


async def _authenticate(
    request: Request, verifier: JwksVerifier, configured_tenant: str
) -> AxiamUser:
    """The shared extract/CSRF/verify/exp/tenant authentication pipeline
    (CONTRACT.md §10) underlying both :func:`require_authenticated_user` and
    :func:`require_access` (CONTRACT.md §11.2.1: the declarative
    authorization helper MUST run strictly after, and never duplicate or
    bypass, this same verification path).

    1. Extracts the token (Authorization Bearer, else ``axiam_access`` cookie).
    2. When the credential is cookie-sourced AND the request method is
       state-changing (not GET/HEAD/OPTIONS), enforces the CSRF
       double-submit check (CONTRACT.md §3) before verification proceeds —
       raises ``HTTPException`` 403 on failure.
    3. Verifies it locally via ``verifier.verify()`` (signature + ``sub`` only).
    4. Independently checks ``exp`` — the verifier does not (T-19-20).
    5. Enforces ``claims["tenant_id"] == configured_tenant`` BEFORE trusting
       any claim further (cross-tenant replay defense, T-19-19).
    6. Returns :class:`AxiamUser` on success; raises ``HTTPException`` 401 on
       any authentication failure, never including the raw token value.
    """
    credential = _extract_token(request)

    if credential.from_cookie and request.method.upper() not in _SAFE_METHODS:
        _assert_csrf_valid(request)

    token = credential.value

    try:
        claims = verifier.verify(token)
        # SDK-11: coerce ``exp`` to float INSIDE the verify try/except so a
        # signature-valid token carrying a non-numeric ``exp`` (e.g. a
        # string) maps to the normal invalid-token -> 401 path rather than
        # a ValueError/TypeError propagating as an unhandled 500. Preserves
        # the "malformed token -> 401" invariant (CONTRACT.md §10).
        exp = claims.get("exp")
        exp_ts = float(exp) if exp is not None else None
    except Exception as exc:
        raise HTTPException(
            status_code=_AUTH_FAILED_STATUS, detail="invalid or expired token"
        ) from exc

    if exp_ts is not None and time.time() >= exp_ts:
        raise HTTPException(status_code=_AUTH_FAILED_STATUS, detail="invalid or expired token")

    # Cross-tenant replay defense (T-19-19): the JWKS is organization-wide,
    # not tenant-scoped, so a signature-valid token may belong to a
    # different tenant. MUST be enforced before any claim is trusted
    # further (mirrors nethttp.go lines 78-95).
    tenant_id = claims.get("tenant_id")
    if not tenant_id or tenant_id != configured_tenant:
        raise HTTPException(
            status_code=_AUTH_FAILED_STATUS,
            detail="token tenant_id does not match the configured tenant",
        )

    # WR-02: ``dict.get("scope", "")`` returns ``None`` (not ``""``) when
    # the claim is PRESENT with an explicit JSON ``null`` value, and
    # ``list(None)`` raises TypeError — which would propagate AFTER the
    # verify() try/except above and surface as an unhandled 500 for an
    # otherwise signature-valid token. ``claims.get("scope") or ""`` maps
    # both absent AND null scope to empty roles, matching how an absent
    # scope is already handled (CONTRACT.md §10: malformed claims must
    # still degrade to a standardized 401, never a 500).
    roles_claim = claims.get("scope") or ""
    roles = roles_claim.split() if isinstance(roles_claim, str) else list(roles_claim)

    subject = claims.get("sub")
    if not subject:
        raise HTTPException(status_code=_AUTH_FAILED_STATUS, detail="invalid or expired token")

    return AxiamUser(user_id=subject, tenant_id=tenant_id, roles=roles)


def require_authenticated_user(
    verifier: JwksVerifier, configured_tenant: str
) -> Callable[[Request], Awaitable[AxiamUser]]:
    """Factory returning a ``Depends(...)``-compatible async dependency
    (mirrors the Go middleware's ``Middleware(verifier, configuredTenant,
    opts...)`` factory pattern, D-09).

    Usage::

        @app.get("/me")
        async def me(user: AxiamUser = Depends(require_authenticated_user(verifier, "acme"))):
            ...

    The returned dependency delegates to :func:`_authenticate` for the full
    extract/CSRF/verify/exp/tenant pipeline — see that function's docstring
    for the exact steps. Returns :class:`AxiamUser` on success; raises
    ``HTTPException`` 401 on any authentication failure, never including the
    raw token value.
    """

    async def _dependency(request: Request) -> AxiamUser:
        """The actual ``Depends(...)``-injected coroutine — delegates
        entirely to :func:`_authenticate` (see :func:`require_authenticated_user`'s
        docstring for the pipeline it runs)."""
        return await _authenticate(request, verifier, configured_tenant)

    return _dependency


def _resolve_resource_id(
    request: Request,
    *,
    resource_id: str | None,
    resource_param: str | None,
    resolver: Callable[[Request], str] | None,
) -> str:
    """Resolve and validate the target resource UUID per CONTRACT.md
    §11.2.3's precedence order: a literal ``resource_id``, else the
    ``resource_param`` path parameter, else the ``resolver`` callback.

    A missing or unparseable resource value is a programming error surfaced
    as ``HTTPException`` 400 (§11.2.5) — never a silent allow, never a
    nil/empty-UUID fallback.
    """
    raw: object
    if resource_id is not None:
        raw = resource_id
    elif resource_param is not None:
        raw = request.path_params.get(resource_param)
        if raw is None:
            raise HTTPException(
                status_code=_INVALID_REQUEST_STATUS,
                detail={
                    "error": "invalid_request",
                    "message": f"missing path parameter {resource_param!r}",
                },
            )
    else:
        assert resolver is not None  # enforced by require_access at construction time
        try:
            raw = resolver(request)
        except Exception as exc:
            raise HTTPException(
                status_code=_INVALID_REQUEST_STATUS,
                detail={"error": "invalid_request", "message": "resource resolver failed"},
            ) from exc

    try:
        uuid.UUID(str(raw))
    except (ValueError, AttributeError, TypeError) as exc:
        raise HTTPException(
            status_code=_INVALID_REQUEST_STATUS,
            detail={"error": "invalid_request", "message": "resource id is not a valid UUID"},
        ) from exc
    return str(raw)


def require_access(
    verifier: JwksVerifier,
    configured_tenant: str,
    client: AsyncAxiamClient,
    action: str,
    *,
    resource_param: str | None = None,
    resource_id: str | None = None,
    resolver: Callable[[Request], str] | None = None,
    scope: str | None = None,
) -> Callable[[Request], Awaitable[AxiamUser]]:
    """Factory returning a ``Depends(...)``-compatible async dependency that
    requires an AXIAM authorization check for ``action`` on a resource
    resolved from the request (CONTRACT.md §11).

    Composes with, and runs strictly after, the same authentication pipeline
    :func:`require_authenticated_user` uses (:func:`_authenticate` — never a
    separate/duplicated token-verification path, §11.2.1).

    Usage::

        @app.get("/docs/{doc_id}")
        async def get_doc(
            doc_id: str,
            user: AxiamUser = Depends(
                require_access(verifier, "acme", client, "read", resource_param="doc_id")
            ),
        ):
            ...

    Exactly one of ``resource_id`` (a literal UUID, for singleton resources),
    ``resource_param`` (a path parameter name), or ``resolver`` (a
    ``request -> str`` callback for anything else — body fields, headers,
    composite lookups) must be supplied (§11.2.3); this is validated eagerly
    at factory-construction time, not per-request.

    The returned dependency:
    1. Authenticates the request via :func:`_authenticate` (401 on failure).
    2. Resolves and validates the resource UUID (400 on a missing/unparseable
       value, §11.2.3).
    3. Calls ``client.check_access(action, resource_id, scope=scope,
       subject_id=<authenticated user_id>)`` — ``subject_id`` is always the
       *request's* authenticated caller, never this client's own (often
       service-account) identity (§11.2.2).
    4. Denied (``allowed=False`` or an ``AuthzError`` from the server, e.g. the
       client lacks ``authz:check_as``) -> ``HTTPException`` 403
       ``authorization_denied``.
    5. A transport failure (``AuthError``/``NetworkError`` — the SDK could not
       obtain a decision at all) -> **fail closed** with ``HTTPException`` 503
       ``authz_unavailable`` (§11.2.5) — never allow, never retry beyond the
       client's own bounded single-flight refresh.
    6. On success, returns the same :class:`AxiamUser` so the handler keeps
       the caller's identity (roles etc.) without a second lookup.

    No decision caching (§11.2.6): every call performs a fresh
    ``check_access`` round-trip. Deny/error paths never log or echo the raw
    token (§11.2.8).
    """
    resource_sources = [
        source for source in (resource_id, resource_param, resolver) if source is not None
    ]
    if len(resource_sources) != 1:
        raise ValueError(
            "require_access requires exactly one of resource_id, resource_param, or resolver"
        )

    async def _dependency(request: Request) -> AxiamUser:
        """The actual ``Depends(...)``-injected coroutine — authenticate,
        resolve the resource, then perform the authorization check (see
        :func:`require_access`'s docstring for the full pipeline)."""
        user = await _authenticate(request, verifier, configured_tenant)
        target_resource_id = _resolve_resource_id(
            request,
            resource_id=resource_id,
            resource_param=resource_param,
            resolver=resolver,
        )

        try:
            result = await client.check_access(
                action, target_resource_id, scope=scope, subject_id=user.user_id
            )
        except AuthzError as exc:
            raise HTTPException(
                status_code=_AUTHZ_DENIED_STATUS,
                detail={
                    "error": "authorization_denied",
                    "message": f"caller lacks permission for action {action!r}",
                },
            ) from exc
        except (AuthError, NetworkError) as exc:
            # §11.2.5: fail closed — a transport failure while calling the
            # authz endpoint is "couldn't decide", never a silent allow.
            raise HTTPException(
                status_code=_AUTHZ_UNAVAILABLE_STATUS,
                detail={
                    "error": "authz_unavailable",
                    "message": "authorization service unavailable",
                },
            ) from exc

        if not result.allowed:
            raise HTTPException(
                status_code=_AUTHZ_DENIED_STATUS,
                detail={
                    "error": "authorization_denied",
                    "message": f"caller lacks permission for action {action!r}",
                },
            )
        return user

    return _dependency


def require_role(
    verifier: JwksVerifier, configured_tenant: str, *roles: str
) -> Callable[[Request], Awaitable[AxiamUser]]:
    """Factory returning a ``Depends(...)``-compatible async dependency that
    requires the authenticated identity's verified ``roles`` to contain at
    least one of ``roles`` (CONTRACT.md §11).

    A **local** check only — reads the claims already verified by
    :func:`_authenticate`; it never calls the AXIAM server. Cheaper but
    coarser than :func:`require_access`, and documented (§11.2.9) as NOT a
    substitute for the authoritative, resource-level check: role names are
    tenant-defined and callers should still gate any resource-specific
    action behind :func:`require_access`.

    Usage::

        @app.delete("/admin/reset")
        async def reset(user: AxiamUser = Depends(require_role(verifier, "acme", "admin"))):
            ...
    """

    async def _dependency(request: Request) -> AxiamUser:
        """The actual ``Depends(...)``-injected coroutine — authenticate,
        then check the verified identity's roles locally (see
        :func:`require_role`'s docstring)."""
        user = await _authenticate(request, verifier, configured_tenant)
        if not any(role in user.roles for role in roles):
            raise HTTPException(
                status_code=_AUTHZ_DENIED_STATUS,
                detail={
                    "error": "authorization_denied",
                    "message": "caller lacks a required role",
                },
            )
        return user

    return _dependency


__all__ = [
    "AsyncAxiamClient",
    "AxiamUser",
    "JwksVerifier",
    "require_access",
    "require_authenticated_user",
    "require_role",
]
