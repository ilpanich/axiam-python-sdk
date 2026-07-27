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

from collections.abc import Callable
from typing import Any

import httpx
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse

from axiam_sdk._client import AxiamClient
from axiam_sdk._errors import AuthError, NetworkError
from axiam_sdk._models import OidcTokenSet
from axiam_sdk._oidc_state import MemoryOidcStateStore, OidcStateEntry, OidcStateStore

#: §12 login-glue HTTP status mapping (port-brief-addendum item 19,
#: CONTRACT.md §12) — framework-handler behavior, not contract-specified.
_INVALID_REQUEST_STATUS = 400
_AUTH_FAILED_STATUS = 401
_UNAVAILABLE_STATUS = 503


def oidc_login_views(
    client: AxiamClient,
    *,
    redirect_uri: str,
    store: OidcStateStore | None = None,
    scope: str | list[str] | None = None,
    tenant_id: str | None = None,
    success_redirect: str | None = None,
    on_success: Callable[[OidcTokenSet, OidcStateEntry], None] | None = None,
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
            at login time, then to a JSON summary.
        on_success: Called with the validated token set and the consumed
            state entry once the exchange succeeds — the hook where an
            application establishes its OWN session (sign a cookie, write a
            session row, ...). The SDK deliberately does not do this: what a
            session means is the application's decision.

    Returns:
        A ``(login_view, callback_view)`` tuple of plain Django view
        functions, ready to wire into ``urlpatterns``.
    """
    state_store: OidcStateStore = store if store is not None else MemoryOidcStateStore()

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

        state_store.save(
            OidcStateEntry(
                state=authorization_request.state,
                nonce=authorization_request.nonce,
                code_verifier=authorization_request.code_verifier,
                redirect_uri=redirect_uri,
                return_to=return_to,
            )
        )
        return HttpResponseRedirect(authorization_request.url)

    def callback_view(request: HttpRequest) -> HttpResponse:
        """Step 2 — validate the callback, consume the stored state,
        exchange the code, and respond (CONTRACT.md §12.1 ``oidc_exchange``).

        Failure mapping (port-brief-addendum item 19): IdP returned
        ``error=...`` -> 401; ``state``/``code`` missing -> 400; ``state``
        unknown/expired/already-used -> 401; any §12.4 ID-token failure or
        ``OAuthProtocolError`` -> 401; a transport failure -> 503.
        """
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
        entry = state_store.consume(state)
        if entry is None:
            return JsonResponse(
                {
                    "error": "authentication_failed",
                    "message": "unknown, expired, or already-used login state",
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

        destination = success_redirect or entry.return_to
        if destination:
            return HttpResponseRedirect(destination)

        body: dict[str, Any] = {"authenticated": True, "expires_in": tokens.expires_in}
        if tokens.id_claims is not None:
            body["sub"] = tokens.id_claims.sub
        return JsonResponse(body)

    return login_view, callback_view


__all__ = ["oidc_login_views"]
