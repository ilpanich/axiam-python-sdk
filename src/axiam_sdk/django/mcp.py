"""``serve_protected_resource_metadata`` for Django (CONTRACT.md §28.3).

This module is imported ONLY as ``axiam_sdk.django.mcp`` (never from the
top-level ``axiam_sdk/__init__.py`` or from ``axiam_sdk.django.middleware``),
so pure-REST/gRPC/AMQP consumers of ``axiam-sdk`` are never forced to install
``django`` — the same import discipline
``axiam_sdk.django.middleware``/``axiam_sdk.django.decorators`` already
follow.

**Divergence from the TypeScript reference (T9b) and from this SDK's own
FastAPI port, documented rather than papered over:** Express, Fastify and
FastAPI all expose one central "application/router" object that
``serve_protected_resource_metadata(app, metadata)`` registers a route on
directly. Django has no such object — URL routing is declarative
(``urlpatterns``, a plain list assembled once in ``urls.py``), so there is
nothing for this function to call ``.get(path, handler)`` on. The Django
idiom's own router **is** that list, so this port's ``app`` parameter is the
project's ``urlpatterns`` list, appended to in place — the closest structural
analogue, not a reach for signature parity at the cost of reading like Django
code.

The second divergence follows from the first: CONTRACT.md §28.5 rule 3 asks
an SDK that "can see both the guard and a ``protected_resource_metadata``
value configured on the same application" to cross-check them at startup.
Express/Fastify/FastAPI all pass the shared session/verifier object into
``serveProtectedResourceMetadata`` itself, because that object is visible
where routes are registered. In a Django project ``urls.py`` does not
typically construct (and should not need to construct) the
``JwksVerifier`` ``settings.py``-configures for
``AxiamAuthMiddleware`` — so this function takes the two raw
values (``expected_audience``, ``resource_metadata_url``) directly, read from
``django.conf.settings`` by the caller, rather than a verifier object. Pass
neither and nothing is cross-checked, exactly as passing no ``guard``/
``verifier`` skips the check on the other three ports.
"""

from __future__ import annotations

import json

from django.http import HttpRequest, HttpResponse
from django.urls import URLPattern, path

from axiam_sdk._mcp import ProtectedResourceMetadata
from axiam_sdk.management._errors import FieldError, ValidationError

__all__ = ["serve_protected_resource_metadata"]


def serve_protected_resource_metadata(
    urlpatterns: list[URLPattern],
    metadata: ProtectedResourceMetadata,
    *,
    expected_audience: str | None = None,
    resource_metadata_url: str | None = None,
) -> ProtectedResourceMetadata:
    """``serve_protected_resource_metadata(urlpatterns, metadata)``
    (CONTRACT.md §28.3) — append the one ``GET`` route that serves the RFC
    9728 protected-resource metadata document to ``urlpatterns``, and return
    the same ``metadata`` value so a guard's ``resource_metadata_url`` can be
    fed from it.

    See the module docstring for why ``urlpatterns`` — a plain, mutable list
    — is this port's ``app``: Django has no central application/router object
    the way Express, Fastify and FastAPI do.

    **The path is derived, not chosen, and exactly one route is appended.**
    Call this once per resource; the derived paths of two different
    resources cannot collide.

    The response is ``200`` with ``Content-Type: application/json``, the
    document as its body, ``Cache-Control: public, max-age=3600`` and
    ``Access-Control-Allow-Origin: *`` — the last because an MCP client
    running in a browser cannot read the document without it, and it is safe
    precisely because the response is identical for every caller (§28.3
    rule 4). It carries no ``Access-Control-Allow-Credentials``.

    **This route answers without a credential**, but only once
    ``AxiamAuthMiddleware`` (registered globally, per this project's
    ``settings.MIDDLEWARE``) is told to exempt it — via its own
    ``settings.AXIAM_RESOURCE_METADATA_URL``, read independently of this
    call. Append this route to ``urlpatterns`` at the application root: a
    Django ``include()`` mounted under a prefix would serve the document at
    a path the derived URL does not name.

    Args:
        urlpatterns: The project's (or app's) URL pattern list — this
            function appends one entry to it in place, mirroring how
            Express/Fastify/FastAPI register on the caller's own router
            object.
        metadata: The value :func:`~axiam_sdk.protected_resource_metadata`
            returned.
        expected_audience: Optionally, this deployment's
            ``settings.AXIAM_EXPECTED_AUDIENCE`` — passing it (together with
            ``resource_metadata_url``) applies CONTRACT.md §28.5 rule 3: it
            must equal ``metadata.document.resource``, or this call raises.
        resource_metadata_url: Optionally, this deployment's
            ``settings.AXIAM_RESOURCE_METADATA_URL`` — passing it (together
            with ``expected_audience``) applies §28.5 rule 3: it must equal
            ``metadata.metadata_url``, or this call raises. Omit both where
            nothing needs cross-checking here — ``metadata.metadata_url`` is
            how both sides are configured from one constant instead.

    Returns:
        ``metadata``, unchanged — returned for symmetry with
        :func:`~axiam_sdk.protected_resource_metadata`.

    Raises:
        ValidationError: when either of ``expected_audience``/
            ``resource_metadata_url`` is given and does not match
            ``metadata``.
    """
    if resource_metadata_url is not None or expected_audience is not None:
        if resource_metadata_url != metadata.metadata_url:
            raise ValidationError(
                "serve_protected_resource_metadata",
                400,
                f"resource_metadata_url: is {resource_metadata_url!r} but this document is "
                f"published at {metadata.metadata_url!r} — the challenge would point at a "
                "document that is not this resource server's (CONTRACT.md §28)",
                [
                    FieldError(
                        field="resource_metadata_url",
                        message="does not equal the document's metadata_url",
                    )
                ],
            )
        if expected_audience != metadata.document.resource:
            raise ValidationError(
                "serve_protected_resource_metadata",
                400,
                f"expected_audience: is {expected_audience!r} but this document announces "
                f"{metadata.document.resource!r} — the document would announce one identifier "
                "while the guard checked aud against another, so every token the flow "
                "produced would be refused (CONTRACT.md §28)",
                [
                    FieldError(
                        field="expected_audience",
                        message="does not equal the document's resource",
                    )
                ],
            )

    # §28.3 rule 4: the response is identical for every caller, so there is
    # nothing per-request to build.
    body = json.dumps(metadata.document.to_dict()).encode("utf-8")

    def _view(_request: HttpRequest) -> HttpResponse:
        """The unauthenticated view serving the document (§28.3 rules 1-4)."""
        response = HttpResponse(body, content_type="application/json")
        response["Cache-Control"] = "public, max-age=3600"
        response["Access-Control-Allow-Origin"] = "*"
        return response

    urlpatterns.append(path(metadata.metadata_path.lstrip("/"), _view))
    return metadata
