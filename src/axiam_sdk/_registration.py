"""RFC 7592 client configuration — CONTRACT.md §28.12 (contract 1.53).

A client that registered itself through ``POST /oauth2/register`` (RFC 7591)
receives, once, a ``registration_client_uri`` and a
``registration_access_token``. With those two it can read, replace and delete
**its own** registration: ``read_client_registration``,
``update_client_registration`` and ``delete_client_registration``, on both
:class:`~axiam_sdk.AxiamClient` and :class:`~axiam_sdk.AsyncAxiamClient`.

Four rules shape all three (§28.12.2):

1. **The URI is used verbatim, and only at the configured AXIAM.** A URI whose
   scheme, host or port differs from the client's base URL — or an ``http``
   URI unless the base URL is ``http`` on a loopback host — is refused locally,
   before any request: the token is a bearer, and a helper that followed a URI
   to another origin would hand it to whoever wrote the URI.
2. **The token travels in ``Authorization: Bearer`` only** — never in the
   query, never in a body.
3. **It is not the SDK's session.** These requests go out on a transport with
   no cookie jar and no redirect following, carry no SDK access token, cookie,
   CSRF token or ``X-Tenant-ID``, and a ``401`` from them never reaches the §9
   refresh guard.
4. **Neither write is retried.** An update that reached the server and lost its
   response has already rotated the token; a delete whose ``204`` was lost
   would read ``401`` on a retry. Only the read follows §16, and never on a
   ``4xx`` other than ``408`` / ``429``.

This module holds what the sync and async clients share; the methods
themselves live on the two clients.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from axiam_sdk._errors import NetworkError, error_from_oauth2_response

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk.management._errors import ValidationError

__all__ = ["ClientRegistration"]

#: The members ``update_client_registration`` never sends (§28.12.2 rule 4).
#: The first four the server refuses with ``400 invalid_request`` when present;
#: ``client_secret`` it never accepts back.
SERVER_STATED_MEMBERS = (
    "registration_access_token",
    "registration_client_uri",
    "client_secret_expires_at",
    "client_id_issued_at",
    "client_secret",
)

_STRING_MEMBERS = (
    "client_name",
    "token_endpoint_auth_method",
    "scope",
    "registration_client_uri",
    "jwks_uri",
)
_INT_MEMBERS = ("client_id_issued_at", "client_secret_expires_at")
_LIST_MEMBERS = ("redirect_uris", "grant_types", "response_types")
_SECRET_MEMBERS = ("client_secret", "registration_access_token")

#: The hosts §28.12.2 rule 1 accepts an ``http`` base URL on.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class ClientRegistration(BaseModel):
    """An RFC 7591 §3.2.1 / RFC 7592 §3 client information response.

    ``registration_access_token`` and ``client_secret`` are
    :class:`~pydantic.SecretStr` (§28.12.4): ``repr``, ``str`` and every JSON
    rendering show ``'**********'``; ``.get_secret_value()`` reads them.

    **Decoded tolerantly.** Every member the server sent that this type does
    not name — and a named member of an unexpected type — is kept verbatim in
    :attr:`extra` (RFC 7591 §3.2.1 lets a server add members). An update is a
    **full replacement**: a member a read returned and an update left out is a
    member the server deletes, so passing a read's result straight to
    ``update_client_registration`` sends it back intact, ``jwks`` / ``jwks_uri``
    and the CIBA ``backchannel_*`` members included.
    """

    model_config = ConfigDict(extra="forbid")

    client_id: str
    """The client's ``client_id``."""

    client_id_issued_at: int | None = None
    """When the client id was issued (seconds since the epoch). Never sent on an
    update."""

    client_name: str | None = None
    """The registered display name."""

    redirect_uris: list[str] = Field(default_factory=list)
    """The registered redirect URIs."""

    grant_types: list[str] = Field(default_factory=list)
    """The registered grant types."""

    response_types: list[str] = Field(default_factory=list)
    """The registered response types."""

    token_endpoint_auth_method: str | None = None
    """How the client authenticates at the token endpoint. The server refuses an
    update that changes it."""

    scope: str | None = None
    """The registered scope, space-separated."""

    registration_client_uri: str | None = None
    """Where this registration is read, replaced and deleted. Never sent on an
    update."""

    client_secret_expires_at: int | None = None
    """When the client secret expires (``0`` = never). Never sent on an update."""

    jwks: dict[str, Any] | None = None
    """The client's JWK Set, for a ``private_key_jwt`` client."""

    jwks_uri: str | None = None
    """Where the client's JWK Set is published."""

    client_secret: SecretStr | None = None
    """The client secret — present only on the registration response itself,
    never on a read or an update. Never sent back. **Secret.**"""

    registration_access_token: SecretStr | None = None
    """The registration access token — present on the registration response
    and, **rotated**, on every update response; absent on a read. Never sent in
    a body. **Secret.**"""

    extra: dict[str, Any] = Field(default_factory=dict)
    """Every other member of the response, verbatim."""

    @model_validator(mode="before")
    @classmethod
    def _tolerate(cls, data: Any) -> Any:
        """Split a raw response into the named members and :attr:`extra`.

        A named member of an unexpected type is moved to ``extra`` rather than
        failing the decode or being dropped (a replacement must not lose what
        the server holds) — except the two secrets, which are dropped instead,
        since ``extra`` is rendered in full by ``repr``.
        """
        if not isinstance(data, dict) or "extra" in data:
            return data
        raw = dict(data)
        out: dict[str, Any] = {}
        kept: dict[str, Any] = {}

        def take(key: str, accept: Any) -> None:
            """Move ``key`` to ``out`` when ``accept(value)``, else to ``kept``."""
            if key not in raw:
                return
            value = raw.pop(key)
            if accept(value):
                out[key] = value
            elif value is not None:
                kept[key] = value

        for key in _STRING_MEMBERS:
            take(key, lambda v: isinstance(v, str))
        for key in _INT_MEMBERS:
            take(key, lambda v: isinstance(v, int) and not isinstance(v, bool))
        for key in _LIST_MEMBERS:
            take(key, lambda v: isinstance(v, list) and all(isinstance(i, str) for i in v))
        take("jwks", lambda v: isinstance(v, dict))
        for key in _SECRET_MEMBERS:
            value = raw.pop(key, None)
            if isinstance(value, SecretStr):
                out[key] = value
            elif isinstance(value, str):
                out[key] = SecretStr(value)
        if "client_id" in raw:
            out["client_id"] = raw.pop("client_id")
        out["extra"] = {**raw, **kept}
        return out

    def update_body(self) -> dict[str, Any]:
        """The RFC 7592 §2.2 replacement body (§28.12.2 rule 4).

        Every member — :attr:`extra` included — but the five the server states
        (``registration_access_token``, ``registration_client_uri``,
        ``client_secret_expires_at``, ``client_id_issued_at``,
        ``client_secret``), with ``client_id`` set to this registration's own.
        A list member is sent when it is non-empty or was present on the read.
        """
        body: dict[str, Any] = {
            k: v for k, v in self.extra.items() if k not in SERVER_STATED_MEMBERS
        }
        body["client_id"] = self.client_id
        for key in ("client_name", "token_endpoint_auth_method", "scope", "jwks_uri"):
            value = getattr(self, key)
            if value is not None:
                body[key] = value
        for key in _LIST_MEMBERS:
            value = getattr(self, key)
            if value or key in self.model_fields_set:
                body[key] = list(value)
        if self.jwks is not None:
            body["jwks"] = self.jwks
        return body


def _origin(url: httpx.URL) -> tuple[str, str, int | None]:
    """``(scheme, host, port-or-default)``, lower-cased, for "same origin"."""
    scheme = url.scheme.lower()
    default = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, url.host.lower(), url.port if url.port is not None else default


def check_registration_uri(base_url: str, uri: str, operation: str) -> httpx.URL:
    """§28.12.2 rule 1: accept ``uri`` only at the configured AXIAM origin.

    Returns the URI as given — query included, nothing rebuilt.

    Raises:
        ValidationError: the local refusal, before any request. Its message
            names no part of the URI: it is caller input, and an error
            message is the one most often logged.
    """

    # Imported here: ``axiam_sdk.management`` transitively imports the client
    # modules that import this one (the reason ``_mcp._refuse`` does the same).
    from axiam_sdk.management._errors import local_refusal

    def refuse(why: str) -> ValidationError:
        """The rule-1 refusal for ``operation``."""
        return local_refusal(
            operation, "registration_client_uri", f"{why} (CONTRACT.md §28.12.2 rule 1)"
        )

    try:
        parsed = httpx.URL(uri)
    except (httpx.InvalidURL, TypeError):
        raise refuse("not an absolute URL") from None
    scheme = parsed.scheme.lower()
    if not parsed.is_absolute_url or not parsed.host:
        raise refuse("not an absolute URL")
    if scheme not in ("https", "http"):
        raise refuse("must be an https URL")
    base = httpx.URL(base_url)
    if _origin(parsed) != _origin(base):
        raise refuse(
            "not at the configured AXIAM origin (scheme, host and port must match the "
            "client's base URL)"
        )
    if scheme == "http" and base.host.lower() not in _LOOPBACK_HOSTS:
        raise refuse("must be https unless the base URL is http on a loopback host")
    return parsed


def registration_request(
    method: str,
    url: httpx.URL,
    token: SecretStr | str,
    body: dict[str, Any] | None = None,
) -> httpx.Request:
    """A bare RFC 7592 request: the bearer, ``Accept``, and a JSON body on ``PUT``.

    Built as a bare :class:`httpx.Request` — never through a client's
    ``build_request`` — so no cookie of any jar is merged into it.
    """
    secret = token.get_secret_value() if isinstance(token, SecretStr) else token
    headers = {"Authorization": f"Bearer {secret}", "Accept": "application/json"}
    if body is None:
        return httpx.Request(method, url, headers=headers)
    return httpx.Request(method, url, headers=headers, json=body)


def registration_error(response: httpx.Response, operation: str) -> Exception:
    """§28.12.3: a body with a non-empty ``error`` is an ``OAuthProtocolError``
    at any status (``error_description`` optional); otherwise §2 by status."""
    return error_from_oauth2_response(
        response.status_code,
        response,
        f"{operation} failed with HTTP {response.status_code}",
        description_optional=True,
    )


def decode_registration(response: httpx.Response, operation: str) -> ClientRegistration:
    """A ``200`` body as a :class:`ClientRegistration`, or the §28.12.3 error.

    Raises:
        OAuthProtocolError: the server's protocol answer.
        NetworkError: a body that is not a JSON object with a ``client_id``.
    """
    if not response.is_success:
        raise registration_error(response, operation)
    try:
        raw = response.json()
    except ValueError:
        raise NetworkError(f"{operation}: the response is not JSON") from None
    if not isinstance(raw, dict) or not isinstance(raw.get("client_id"), str):
        raise NetworkError(f"{operation}: the response is not a client registration")
    return ClientRegistration.model_validate(raw)
