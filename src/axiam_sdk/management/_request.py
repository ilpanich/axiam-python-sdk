"""The one request path every §27 management operation goes through.

§27.8 is explicit that the generated layer MUST sit on the SDK's existing
request path and MUST NOT build its own. That is what this module is: 146
generated operations all funnel into :func:`send_management` (or its async
twin), so they inherit §3 (CSRF), §4 (the cookie jar), §5 (``X-Tenant-ID``),
§6 (TLS), §9 (the single-flight refresh guard), §16 (retry) and §19 (telemetry)
by construction rather than by 146 opportunities to forget one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import httpx

from axiam_sdk._errors import AuthError, error_from_http_status
from axiam_sdk._retry import retry_async, retry_sync
from axiam_sdk.management._errors import (
    ConflictError,
    NotFoundError,
    ValidationError,
    parse_field_errors,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk._async_client import AsyncAxiamClient
    from axiam_sdk._client import AxiamClient

ManagementMethod = Literal["GET", "POST", "PUT", "DELETE"]
"""The HTTP verbs this surface uses."""

__all__ = ["ManagementCall"]


@dataclass(frozen=True)
class ManagementCall:
    """One management call, fully resolved."""

    operation: str
    """``"users.create"`` — the registry's namespace-qualified operation name."""

    method: ManagementMethod
    """The HTTP verb. Only ``GET`` is retry-eligible (§27.4 rule 8)."""

    path_template: str
    """``"/api/v1/users/{user_id}"``, ids **not** substituted — the §19.1 label."""

    path: str
    """The same path with ids substituted, ready to send."""

    query: dict[str, str | None] = field(default_factory=dict)
    """Query parameters; ``None`` values are dropped rather than sent empty."""

    body: Any = None
    """The request body, already converted to its wire shape."""

    def params(self) -> dict[str, str]:
        """The query parameters actually sent, with the unset ones dropped."""
        return {k: v for k, v in self.query.items() if v is not None}


def _require_session(client: Any, call: ManagementCall) -> None:
    """Refuse a management call with no session (§27.4 rule 1).

    Letting the request go out trades a clear local error for a 401 that then
    enters the §9 refresh guard and fails there, two indirections from the
    actual mistake.

    Raises:
        AuthError: when no ``axiam_access`` cookie is present.
    """
    from axiam_sdk._client import ACCESS_COOKIE

    if not client._session.cookie_value(ACCESS_COOKIE):
        raise AuthError(
            f"{call.operation}: no active session — call login() before using the management API"
        )


def send_management(client: AxiamClient, call: ManagementCall) -> Any:
    """Issue a management request synchronously and return its parsed body.

    Only ``GET`` is routed through the §16 retry runner (§27.4 rule 8). No write
    here is retriable, not even the ones that look idempotent — generating a
    certificate twice mints two, and rotating a secret twice invalidates the one
    the caller already stored.
    """
    # §18.1 rule 4: use-after-close is an error, never a silent reconnect.
    client._ensure_open()
    _require_session(client, call)

    def attempt(n: int) -> Any:
        """One §16 attempt, with its §19 request pair."""
        request = client._session.sync_client.build_request(
            call.method, call.path, params=call.params(), json=call.body
        )
        with client._telemetry.request(call.operation, call.method, call.path_template, n) as span:
            response = client._session._send_sync(request)
            if response.status_code == httpx.codes.UNAUTHORIZED:
                response = client._retry_after_refresh_sync(request)
            span.status = response.status_code
            _raise_for_status(call, response)
            span.outcome = "success"
            return _parsed(response)

    if call.method != "GET":
        return attempt(1)
    return retry_sync(
        attempt,
        operation=call.operation,
        enabled=client._retry_enabled,
        telemetry=client._telemetry,
    )


async def send_management_async(client: AsyncAxiamClient, call: ManagementCall) -> Any:
    """Async twin of :func:`send_management`, with identical semantics."""
    client._ensure_open()
    _require_session(client, call)

    async def attempt(n: int) -> Any:
        """One §16 attempt, with its §19 request pair."""
        request = client._session.async_client.build_request(
            call.method, call.path, params=call.params(), json=call.body
        )
        with client._telemetry.request(call.operation, call.method, call.path_template, n) as span:
            response = await client._session._send_async(request)
            if response.status_code == httpx.codes.UNAUTHORIZED:
                response = await client._retry_after_refresh_async(request)
            span.status = response.status_code
            _raise_for_status(call, response)
            span.outcome = "success"
            return _parsed(response)

    if call.method != "GET":
        return await attempt(1)
    return await retry_async(
        attempt,
        operation=call.operation,
        enabled=client._retry_enabled,
        telemetry=client._telemetry,
    )


def _parsed(response: httpx.Response) -> Any:
    """The response body, or ``None`` for the 204s this surface returns."""
    if response.status_code == httpx.codes.NO_CONTENT or not response.content:
        return None
    return response.json()


def _raise_for_status(call: ManagementCall, response: httpx.Response) -> None:
    """Map a failed management response onto the §2 taxonomy.

    Delegates to the shared :func:`~axiam_sdk._errors.error_from_http_status`
    for everything §27 does not classify, so the two mappers cannot drift: this
    function's whole job is the three statuses §27.4 rule 7 names, and 404 is
    the one §2 genuinely lacks.

    Raises:
        NotFoundError: on 404.
        ConflictError: on 409.
        ValidationError: on 400 or 422.
        Exception: whatever the §2 mapper returns for every other failure.
    """
    status = response.status_code
    if 200 <= status < 300:
        return

    detail = _describe(response)
    if status == httpx.codes.NOT_FOUND:
        raise NotFoundError(
            call.operation,
            f"{call.operation}: not found (or not visible to this tenant){detail}",
        )
    if status == httpx.codes.CONFLICT:
        raise ConflictError(call.operation, f"{call.operation}: conflict{detail}")
    if status in (httpx.codes.BAD_REQUEST, httpx.codes.UNPROCESSABLE_ENTITY):
        raise ValidationError(
            call.operation,
            status,
            f"{call.operation}: request rejected{detail}",
            parse_field_errors(_body(response)),
        )
    raise error_from_http_status(status, f"{call.operation}{detail}", response=response)


def _body(response: httpx.Response) -> Any:
    """The parsed error body, or ``None`` when it is absent or not JSON."""
    try:
        return response.json()
    except ValueError:
        return None


def _describe(response: httpx.Response) -> str:
    """A short suffix naming the server's complaint, where it made one."""
    body = _body(response)
    if isinstance(body, dict):
        message = body.get("message") or body.get("error")
        if isinstance(message, str) and message:
            return f": {message}"
    text = response.text
    if body is None and text:
        return f": {text[:200]}"
    return ""
