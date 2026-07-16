"""Django view decorators layering CONTRACT.md §11 declarative authorization
on top of ``request.axiam_user`` (D-10 continuation).

:func:`require_auth`, :func:`require_access`, and :func:`require_role` are an
*additive* per-view authorization layer built strictly on top of
:class:`~axiam_sdk.django.middleware.AxiamAuthMiddleware` — they read
``request.axiam_user`` (set by that middleware on a successfully verified
request) and never perform their own token extraction/verification, so the
§10 verification path (JWKS, tenant check, §3 CSRF) is never duplicated or
bypassed. If ``request.axiam_user`` is absent — the middleware is not
installed, or the request failed authentication and the middleware already
short-circuited before reaching this view — every decorator here responds
401 ``authentication_failed`` with a message hinting that the middleware may
not be installed.

This module is imported ONLY as ``axiam_sdk.django.decorators`` (never from
the top-level ``axiam_sdk/__init__.py``), so pure-REST/gRPC/AMQP consumers of
``axiam-sdk`` are never forced to install ``django`` (mirrors
``axiam_sdk.django.middleware``'s own import discipline).

Security-critical invariant — subject propagation (CONTRACT.md §11.2.2):
:func:`require_access` calls the sync :class:`~axiam_sdk.AxiamClient`'s
``check_access(...)`` with ``subject_id`` set to the *authenticated
request's* ``user_id`` — never this client's own (often service-account)
identity. Omitting ``subject_id`` would check the service account's own
permissions instead of the end user's.

Security-critical invariant — no token leakage: no raw token value is ever
included in any response body here (``request.axiam_user`` carries no token
material — see :class:`~axiam_sdk.django.middleware.AxiamUser` — and
``check_access`` failures are mapped to static messages only).

Async views (CONTRACT.md §11, decision recorded in the SDK auth-helpers
plan §6): the authorization pipeline itself (reading ``request.axiam_user``,
resolving the resource, calling the sync ``AxiamClient``) is always run
synchronously — mirroring how ``AxiamAuthMiddleware._authenticate`` is
itself fully sync regardless of dispatch mode — and only the call *into* the
wrapped view is conditionally awaited, via
``asgiref.sync.iscoroutinefunction``, when the view itself is a coroutine
function.
"""

from __future__ import annotations

import functools
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

from asgiref.sync import iscoroutinefunction
from django.http import HttpRequest, HttpResponse, JsonResponse

from axiam_sdk._client import AxiamClient
from axiam_sdk._errors import AuthError, AuthzError, NetworkError
from axiam_sdk.django.middleware import AxiamUser

#: Standardized 401 JSON error body shape (CONTRACT.md §10/§11) — mirrors
#: ``axiam_sdk.django.middleware``'s own ``_error_response`` shape.
_AUTH_FAILED_STATUS = 401

#: §11.2.5 error mapping for the declarative authorization helpers.
_AUTHZ_DENIED_STATUS = 403
_INVALID_REQUEST_STATUS = 400
_AUTHZ_UNAVAILABLE_STATUS = 503

_View = TypeVar("_View", bound=Callable[..., Any])


def _missing_middleware_response() -> JsonResponse:
    """Standardized 401 JSON response for a view guarded by one of this
    module's decorators when ``request.axiam_user`` is absent — either
    :class:`~axiam_sdk.django.middleware.AxiamAuthMiddleware` is not
    installed, or the request never passed its authentication check."""
    return JsonResponse(
        {
            "error": "authentication_failed",
            "message": (
                "request.axiam_user is not set — is "
                "axiam_sdk.django.middleware.AxiamAuthMiddleware installed?"
            ),
        },
        status=_AUTH_FAILED_STATUS,
    )


def _authenticated_user(request: HttpRequest) -> AxiamUser | None:
    """Read ``request.axiam_user`` (set by ``AxiamAuthMiddleware``) without
    raising — ``None`` when absent, so callers can degrade to
    :func:`_missing_middleware_response` (CONTRACT.md §11.2.1: never a
    separate/duplicated authentication path)."""
    user = getattr(request, "axiam_user", None)
    return user if isinstance(user, AxiamUser) else None


def _wrap(view: _View, guard: Callable[..., HttpResponse | None]) -> _View:
    """Wrap ``view`` so ``guard(request, *args, **kwargs)`` runs first; a
    non-``None`` return short-circuits with that response, otherwise the
    original ``view`` is called (awaited when ``view`` is a coroutine
    function, per this module's async-view dispatch decision, see module
    docstring)."""
    if iscoroutinefunction(view):

        @functools.wraps(view)
        async def async_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            """Async dispatch path: run the (sync) guard, then await the
            wrapped coroutine view if it passed."""
            error = guard(request, *args, **kwargs)
            if error is not None:
                return error
            return await view(request, *args, **kwargs)

        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(view)
    def sync_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        """Sync dispatch path: run the guard, then call the wrapped view if
        it passed."""
        error = guard(request, *args, **kwargs)
        if error is not None:
            return error
        return view(request, *args, **kwargs)

    return sync_wrapper  # type: ignore[return-value]


def require_auth(view: _View) -> _View:
    """View decorator requiring an authenticated AXIAM identity
    (CONTRACT.md §11) — pure sugar over
    :class:`~axiam_sdk.django.middleware.AxiamAuthMiddleware` for call sites
    that want the requirement spelled out per-view. Responds 401
    ``authentication_failed`` when ``request.axiam_user`` is absent.

    Usage::

        @require_auth
        def my_view(request):
            user = request.axiam_user
            ...
    """

    def _guard(request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse | None:
        """Return the standardized 401 response when unauthenticated, else
        ``None`` to let the view proceed."""
        if _authenticated_user(request) is None:
            return _missing_middleware_response()
        return None

    return _wrap(view, _guard)


def require_access(
    client: AxiamClient,
    action: str,
    *,
    resource_param: str = "pk",
    scope: str | None = None,
) -> Callable[[_View], _View]:
    """View decorator factory requiring an AXIAM authorization check for
    ``action`` on a resource resolved from the view's keyword arguments
    (CONTRACT.md §11).

    Usage::

        @require_access(client, "documents:read", resource_param="doc_id")
        def get_document(request, doc_id):
            ...

    ``resource_param`` (default ``"pk"``, Django's own singular-object
    convention) names the view kwarg — typically a captured URL path
    converter, e.g. ``path("documents/<uuid:doc_id>/", ...)`` — carrying the
    resource UUID (CONTRACT.md §11.2.3). A missing or unparseable value is a
    programming error surfaced as 400 ``invalid_request`` — never a silent
    allow, never a nil/empty-UUID fallback.

    The check is made with ``subject_id`` set to the *authenticated
    request's* ``user_id`` (CONTRACT.md §11.2.2) — never this ``client``'s
    own (often service-account) identity. Denied (``allowed=False`` or an
    ``AuthzError`` from the server, e.g. the client lacks
    ``authz:check_as``) responds 403 ``authorization_denied``. A transport
    failure (``AuthError``/``NetworkError`` — the SDK could not obtain a
    decision at all) **fails closed** with 503 ``authz_unavailable``
    (CONTRACT.md §11.2.5) — never allow, never retry beyond the client's own
    bounded refresh. No decision caching (§11.2.6): every request performs a
    fresh ``check_access`` call.
    """

    def decorator(view: _View) -> _View:
        """Bind ``action``/``resource_param``/``scope`` to a guard wrapping
        ``view`` (see :func:`require_access`'s docstring for the pipeline)."""

        def _guard(request: HttpRequest, *_args: Any, **kwargs: Any) -> HttpResponse | None:
            """Authenticate, resolve + validate the resource id, then
            perform the authorization check — returns a JSON error response
            on any failure, or ``None`` to let the view proceed."""
            user = _authenticated_user(request)
            if user is None:
                return _missing_middleware_response()

            raw = kwargs.get(resource_param)
            try:
                uuid.UUID(str(raw))
            except (ValueError, AttributeError, TypeError):
                return JsonResponse(
                    {
                        "error": "invalid_request",
                        "message": f"missing or invalid resource id for {resource_param!r}",
                    },
                    status=_INVALID_REQUEST_STATUS,
                )
            resource_id = str(raw)

            try:
                result = client.check_access(
                    action, resource_id, scope=scope, subject_id=user.user_id
                )
            except AuthzError:
                return JsonResponse(
                    {
                        "error": "authorization_denied",
                        "message": f"caller lacks permission for action {action!r}",
                    },
                    status=_AUTHZ_DENIED_STATUS,
                )
            except (AuthError, NetworkError):
                # §11.2.5: fail closed — a transport failure while calling
                # the authz endpoint is "couldn't decide", never a silent
                # allow.
                return JsonResponse(
                    {
                        "error": "authz_unavailable",
                        "message": "authorization service unavailable",
                    },
                    status=_AUTHZ_UNAVAILABLE_STATUS,
                )

            if not result.allowed:
                return JsonResponse(
                    {
                        "error": "authorization_denied",
                        "message": f"caller lacks permission for action {action!r}",
                    },
                    status=_AUTHZ_DENIED_STATUS,
                )
            return None

        return _wrap(view, _guard)

    return decorator


def require_role(*roles: str) -> Callable[[_View], _View]:
    """View decorator factory requiring the authenticated identity's
    verified ``roles`` to contain at least one of ``roles`` (CONTRACT.md
    §11).

    A **local** check only — reads ``request.axiam_user.roles`` already
    attached by the middleware; it never calls the AXIAM server. Cheaper but
    coarser than :func:`require_access`, and documented (§11.2.9) as NOT a
    substitute for the authoritative, resource-level check: role names are
    tenant-defined and callers should still gate any resource-specific
    action behind :func:`require_access`.

    Usage::

        @require_role("admin", "auditor")
        def reset_view(request):
            ...
    """

    def decorator(view: _View) -> _View:
        """Bind ``roles`` to a guard wrapping ``view`` (see
        :func:`require_role`'s docstring for the pipeline)."""

        def _guard(request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse | None:
            """Return a 403/401 JSON response on failure, else ``None`` to
            let the view proceed."""
            user = _authenticated_user(request)
            if user is None:
                return _missing_middleware_response()
            if not any(role in user.roles for role in roles):
                return JsonResponse(
                    {
                        "error": "authorization_denied",
                        "message": "caller lacks a required role",
                    },
                    status=_AUTHZ_DENIED_STATUS,
                )
            return None

        return _wrap(view, _guard)

    return decorator


__all__ = ["require_access", "require_auth", "require_role"]
