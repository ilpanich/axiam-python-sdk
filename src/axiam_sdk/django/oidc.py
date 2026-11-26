"""Django "Login with AXIAM" view-pair helper (CONTRACT.md §12).

:func:`oidc_login_views` builds the two Django views a redirect-based OIDC
login needs — a login-redirect view (``oidc_begin``) and a callback view
(``oidc_exchange``) — sharing ONE :class:`~axiam_sdk.OidcStateStore` instance
between them, since only ``state`` survives the round trip through the IdP
and the other two (``nonce``, ``code_verifier``) must be parked somewhere
the callback request can reach (CONTRACT.md §12.3 rule 1 — the SDK itself is
stateless).

Both views delegate entirely to the shared §12 core already on the sync
:class:`~axiam_sdk.AxiamClient` passed in (``oidc_discover``/``oidc_begin``/
``oidc_exchange``) and to the existing session-cookie machinery in
``_session.py`` — this module adds no token handling of its own.

This module is imported ONLY as ``axiam_sdk.django.oidc`` (never from the
top-level ``axiam_sdk/__init__.py``), so pure-REST/gRPC/AMQP consumers of
``axiam-sdk`` are never forced to install ``django`` (mirrors
``axiam_sdk.django.middleware``'s own import discipline).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import httpx
from django.core.exceptions import DisallowedRedirect
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse

from axiam_sdk._client import AxiamClient
from axiam_sdk._errors import AuthError, NetworkError
from axiam_sdk._models import OidcTokenSet
from axiam_sdk._oidc_binding import (
    BINDING_COOKIE_MAX_AGE_SECONDS,
    BindingCookieSpec,
    binding_cookie_spec,
    binding_matches,
    encode_redirect_location,
    new_binding,
    resolve_return_to,
)
from axiam_sdk._oidc_state import MemoryOidcStateStore, OidcStateEntry, OidcStateStore

#: §12 login-glue HTTP status mapping (port-brief-addendum item 19,
#: CONTRACT.md §12) — framework-handler behavior, not contract-specified.
_INVALID_REQUEST_STATUS = 400
_AUTH_FAILED_STATUS = 401
_UNAVAILABLE_STATUS = 503
_SERVER_ERROR_STATUS = 500

_LOGGER = logging.getLogger("axiam_sdk")

#: The uniform refusal for an unknown, expired, already-used or unbound ``state``.
_UNKNOWN_STATE_MESSAGE = "unknown, expired, or already-used login state"


def _set_binding_cookie(
    response: HttpResponse, spec: BindingCookieSpec, value: str, max_age: int
) -> None:
    """Set (or, with an empty ``value`` and ``max_age=0``, clear) the binding
    cookie: ``HttpOnly``, ``SameSite=Lax``, ``Path=/``, no ``Domain``, and
    ``Secure`` unless the plain-HTTP loopback fallback name is in use."""
    response.set_cookie(
        spec.name,
        value,
        max_age=max_age,
        path="/",
        secure=spec.secure,
        httponly=True,
        samesite="Lax",
    )


def oidc_login_views(
    client: AxiamClient,
    *,
    redirect_uri: str,
    store: OidcStateStore | None = None,
    scope: str | list[str] | None = None,
    tenant_id: str | None = None,
    success_redirect: str | None = None,
    on_success: Callable[[OidcTokenSet, OidcStateEntry], None] | None = None,
    on_success_request: Callable[[OidcTokenSet, OidcStateEntry, HttpRequest], None] | None = None,
    allow_return_to: Callable[[str], bool] | None = None,
) -> tuple[Callable[[HttpRequest], HttpResponse], Callable[[HttpRequest], HttpResponse]]:
    """Build a ``(login_view, callback_view)`` pair implementing "Login with
    AXIAM" (CONTRACT.md §12) for a Django URLconf.

    Usage::

        login_view, callback_view = oidc_login_views(
            client, redirect_uri="https://app.example.com/oidc/callback"
        )

        urlpatterns = [
            path("oidc/login", login_view),
            path("oidc/callback", callback_view),
        ]

    Args:
        client: The :class:`~axiam_sdk.AxiamClient` driving the flow —
            already configured with ``client_id``/``client_secret``.
        redirect_uri: The relying party's own callback URL — must be the
            public URL of ``callback_view`` and is replayed verbatim on the
            token exchange.
        store: Where in-flight login state is parked between the two
            requests. Defaults to a fresh
            :class:`~axiam_sdk.MemoryOidcStateStore` (single-process only —
            supply a shared store for a multi-instance deployment). The
            SAME store instance backs both returned views.
        scope: Requested scope; ``openid`` is added automatically when
            absent (§12.1 rule 4).
        tenant_id: Tenant UUID for the token endpoint's required
            ``tenant_id`` query parameter (CONTRACT.md §12.3 rule 4).
            Defaults to the client's own resolved tenant context (e.g. from
            a prior ``login()``) when omitted.
        success_redirect: Where to send the browser after a successful
            login. Falls back to the ``return_to`` query parameter captured
            at login time **when it is a same-origin relative path** (see
            ``allow_return_to``), then to a JSON summary.
        on_success: Called with the validated token set and the consumed
            state entry once the exchange succeeds — the hook where an
            application establishes its OWN session (sign a cookie, write a
            session row, ...). The SDK deliberately does not do this: what a
            session means is the application's decision.
        on_success_request: As ``on_success``, with the Django request that
            completed the sign-in as a third argument, so the application
            creates its session on that request without reaching for ambient
            context (CONTRACT.md §12.8 rule 2; ``on_success`` keeps its
            two-argument signature). When both are given, ``on_success`` runs
            first. Either runs only after the browser binding and the §12.4
            checks have both succeeded.
        allow_return_to: Optional predicate that may **widen** the
            ``return_to`` rule (CONTRACT.md §12.8 rule 3) — e.g. an allowlist
            of the application's other origins. Consulted, when the entry is
            stored and again before redirecting, only for a value the default
            rule (a single leading ``/``; no ``//`` or ``/\\`` prefix; no
            backslash or control character) refuses; a predicate that raises
            accepts nothing. There is no default predicate.

    **Browser binding (CONTRACT.md §12.8 rule 1, contract 1.68).** The login
    view sets a ``__Host-axiam_oidc_bind`` cookie (``HttpOnly; Secure;
    SameSite=Lax; Path=/``; ``axiam_oidc_bind`` without ``Secure`` on an
    ``http://localhost`` ``redirect_uri``) and the callback completes only for
    the browser that presents it; every callback response clears it. The
    ``OidcStateStore`` you supply MUST persist ``OidcStateEntry.binding_digest``.

    Returns:
        A ``(login_view, callback_view)`` tuple of plain Django view
        functions, ready to wire into ``urlpatterns``.
    """
    state_store: OidcStateStore = store if store is not None else MemoryOidcStateStore()
    cookie_spec = binding_cookie_spec(redirect_uri)

    def login_view(request: HttpRequest) -> HttpResponse:
        """Step 1 — build the authorization request, park its state, and
        redirect the browser (CONTRACT.md §12.1 ``oidc_begin``)."""
        return_to = request.GET.get("return_to")
        try:
            configuration = client.oidc_discover()
            authorization_request = client.oidc_begin(
                configuration=configuration, redirect_uri=redirect_uri, scope=scope
            )
        except (AuthError, NetworkError, httpx.HTTPError):
            # A login route that cannot reach AXIAM must fail closed with
            # 503 rather than redirect the browser somewhere half-built.
            # `httpx.HTTPError` covers a raw transport failure (connection
            # refused, timeout, DNS, TLS) that this SDK's transport layer
            # does not itself wrap into `NetworkError`.
            return JsonResponse(
                {"error": "oidc_unavailable", "message": "could not start the OIDC login flow"},
                status=_UNAVAILABLE_STATUS,
            )

        # A new binding for every login; a cookie this request presents is never reused.
        binding_value, digest = new_binding()
        state_store.save(
            OidcStateEntry(
                state=authorization_request.state,
                nonce=authorization_request.nonce,
                code_verifier=authorization_request.code_verifier,
                redirect_uri=redirect_uri,
                return_to=resolve_return_to(return_to, allow_return_to),
                binding_digest=digest,
            )
        )
        response = HttpResponseRedirect(authorization_request.url)
        _set_binding_cookie(response, cookie_spec, binding_value, BINDING_COOKIE_MAX_AGE_SECONDS)
        return response

    def callback_view(request: HttpRequest) -> HttpResponse:
        """Step 2 — validate the callback, consume the stored state, check
        the browser binding, exchange the code, and respond (CONTRACT.md
        §12.1 ``oidc_exchange``, §12.8).

        Failure mapping (port-brief-addendum item 19): IdP returned
        ``error=...`` -> 401; ``state``/``code`` missing -> 400; ``state``
        unknown/expired/already-used, or no matching binding cookie -> the
        same uniform 401; any §12.4 ID-token failure or ``OAuthProtocolError``
        -> 401; a transport failure -> 503; an unexpected failure (the state
        store is down, an ``on_success*`` hook raised) -> a generic 500 with no
        detail. Every response clears the binding cookie, so an application's
        own exception handling does not see these errors (CONTRACT.md §12.8
        rule 1 (d) puts the cookie clear first).
        """
        try:
            response = _complete(request)
        except Exception as exc:  # noqa: BLE001 -- the cookie is cleared on EVERY outcome
            # §12.8 rule 1 (d): the state is already consumed by now, and the browser's binding
            # cookie must not outlive it. An exception that left this view would reach Django's
            # error handling with no way to attach a cookie, so an unexpected failure (the state
            # store is down, ``on_success`` raised, a bug) is answered here with a generic 500
            # that clears the cookie. Only the exception's type is logged, never its message.
            # This is the documented deviation from propagating to the application's own
            # exception handling (README, "Login glue").
            _LOGGER.error(
                "axiam_sdk: the OIDC login callback failed unexpectedly (%s)",
                type(exc).__qualname__,
            )
            response = JsonResponse(
                {"error": "server_error", "message": "the login callback failed"},
                status=_SERVER_ERROR_STATUS,
            )
        _set_binding_cookie(response, cookie_spec, "", 0)
        return response

    def _complete(request: HttpRequest) -> HttpResponse:
        """The callback proper; :func:`callback_view` clears the binding
        cookie on whatever this returns."""
        error = request.GET.get("error")
        if error:
            error_description = request.GET.get("error_description")
            message = f"{error}: {error_description}" if error_description else error
            return JsonResponse(
                {"error": "authentication_failed", "message": message},
                status=_AUTH_FAILED_STATUS,
            )

        state = request.GET.get("state")
        code = request.GET.get("code")
        if not state or not code:
            return JsonResponse(
                {
                    "error": "invalid_request",
                    "message": "callback is missing the state or code query parameter",
                },
                status=_INVALID_REQUEST_STATUS,
            )

        # Single-use consume (§12.3 rule 1): a replayed callback finds nothing.
        # ALWAYS before the binding comparison (§12.8 rule 1 (c)): the state is
        # spent whatever happens next, so a refused callback cannot be retried.
        entry = state_store.consume(state)
        if entry is None or not binding_matches(
            entry.binding_digest, request.COOKIES.get(cookie_spec.name)
        ):
            # One answer for "unknown state" and "wrong browser", so the
            # refusal does not say which check failed. No token request, no
            # success callback.
            return JsonResponse(
                {
                    "error": "authentication_failed",
                    "message": _UNKNOWN_STATE_MESSAGE,
                },
                status=_AUTH_FAILED_STATUS,
            )

        try:
            tokens = client.oidc_exchange(
                code=code,
                code_verifier=entry.code_verifier,
                redirect_uri=entry.redirect_uri,
                nonce=entry.nonce,
                tenant_id=tenant_id,
            )
        except (NetworkError, httpx.HTTPError):
            return JsonResponse(
                {
                    "error": "oidc_unavailable",
                    "message": "the AXIAM token endpoint is unreachable",
                },
                status=_UNAVAILABLE_STATUS,
            )
        except AuthError as exc:
            # AuthError (including OAuthProtocolError and every §12.4
            # reason code): a login that cannot be proven is a failed login.
            return JsonResponse(
                {"error": "authentication_failed", "message": exc.message},
                status=_AUTH_FAILED_STATUS,
            )

        if on_success is not None:
            on_success(tokens, entry)
        if on_success_request is not None:
            on_success_request(tokens, entry, request)

        # Checked again here (§12.8 rule 3): the store may be the integrator's
        # and the entry older glue's.
        destination = success_redirect or resolve_return_to(entry.return_to, allow_return_to)
        if destination:
            # Decision 7: the adapter writes the percent-encoded form, itself, at this point --
            # not left to HttpResponseRedirect, which would re-encode ``^`` and ``|`` and keep a
            # stray ``%``.
            try:
                # Django's own scheme allow-list (``allowed_schemes``) still applies: a target it
                # refuses (``javascript:`` admitted by a predicate) is treated as refused.
                location = encode_redirect_location(destination)
                redirect = HttpResponseRedirect(location)
            except DisallowedRedirect:
                redirect = None
            if redirect is not None:
                redirect["Location"] = location
                return redirect

        body: dict[str, Any] = {"authenticated": True, "expires_in": tokens.expires_in}
        if tokens.id_claims is not None:
            body["sub"] = tokens.id_claims.sub
        return JsonResponse(body)

    return login_view, callback_view


__all__ = ["oidc_login_views"]
