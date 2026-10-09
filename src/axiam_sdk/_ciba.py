"""CIBA — client-initiated backchannel authentication, CONTRACT.md §33
(contract 1.58; CIBA Core 1.0, poll and ping modes).

A client that already knows whom it wants to authenticate asks AXIAM to
authenticate that user **on another device**; AXIAM notifies the user, who
approves or refuses on the console. The client then collects the tokens at the
token endpoint -- by polling, or once after AXIAM *pings* it.

Four operations, on both :class:`~axiam_sdk.AxiamClient` and
:class:`~axiam_sdk.AsyncAxiamClient`:

========================  ===========================================================
``ciba_initiate``         ``POST /oauth2/bc-authorize``. **Never retried.**
``ciba_poll``             one token request with ``urn:openid:params:grant-type:ciba``
``ciba_await``            polls to a terminal outcome, honouring ``interval`` and
                          ``slow_down``
``ciba_handle_ping``      verifies a ping's bearer and returns its ``auth_req_id``;
                          no I/O, synchronous on both clients
========================  ===========================================================

Two things a caller must not read into a success:

* **A successful ``ciba_initiate`` proves nothing about the user** (§33.3 rule
  4). AXIAM answers a hint that names nobody, a locked user and a real one
  identically, and the only signal that a user did not answer is
  ``expired_token``. Nothing here reports that a user "exists" or "was
  notified".
* **A ping says the request was decided, never how** (§33.2). Call
  ``ciba_poll`` after answering the ping; the outcome -- tokens,
  ``access_denied`` or ``expired_token`` -- comes from the token endpoint.

The client always authenticates, by the credential this SDK was built with
(``client_secret`` sent as ``client_secret_post``, or the §6.1 client
certificate for a ``tls_client_auth`` client); a client built with neither is
refused locally. ``auth_req_id``, ``client_notification_token``, the signing
key and the signed ``request`` are secrets (§33.5).

This module holds what the two clients share; the I/O methods live on them.
"""

from __future__ import annotations

import hmac
import json
import secrets
import time
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any, Literal, Protocol

import httpx
import jwt
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from axiam_sdk._errors import (
    AuthError,
    NetworkError,
    OAuthProtocolError,
    error_from_http_status,
    error_from_oauth2_response,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk.management._errors import ValidationError

__all__ = [
    "CIBA_GRANT_TYPE",
    "CIBA_SLOW_DOWN_INCREMENT_SECONDS",
    "DEFAULT_CIBA_INTERVAL_SECONDS",
    "SIGNED_REQUEST_LIFETIME_SECONDS",
    "AsyncCibaClock",
    "CibaAccessDeniedError",
    "CibaClock",
    "CibaExpiredTokenError",
    "CibaInitiateResponse",
    "CibaRequestSigner",
    "SystemCibaClock",
]

CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba"
"""``grant_type`` of the CIBA token request (CIBA Core §10.1)."""

DEFAULT_CIBA_INTERVAL_SECONDS = 5
"""The interval used when the initiate response carries none (§33.7 rule 2)."""

CIBA_SLOW_DOWN_INCREMENT_SECONDS = 5
"""Seconds added to the interval per ``slow_down``, permanently (§33.7 rule 3)."""

SIGNED_REQUEST_LIFETIME_SECONDS = 300
"""The lifetime of a signed request this SDK mints: five minutes, inside the
server's sixty-minute bound on ``exp - nbf`` (§33.2)."""

CibaSigningAlg = Literal["PS256", "ES256", "EdDSA"]
"""The algorithms a signed CIBA request may use (§33.2)."""

CibaDelivery = Literal["poll", "ping"]
"""How the client receives the outcome, as it registered."""

#: Set on an error ``ciba_poll`` raised for a decisive non-protocol answer (a
#: ``4xx`` without an ``error`` member, an unreadable ``200``), so
#: ``ciba_await`` does not mistake its ``NetworkError`` for a transient one.
_TERMINAL = "_axiam_ciba_terminal"


class CibaAccessDeniedError(OAuthProtocolError):
    """``access_denied`` at a CIBA poll: **the user refused** (§33.4).

    Distinct from :class:`CibaExpiredTokenError` -- a person said no, rather
    than nobody answering -- and the client acts differently on each.
    """


class CibaExpiredTokenError(OAuthProtocolError):
    """``expired_token`` at a CIBA poll: **nobody decided in time** (§33.4).

    Raised by the server, or locally by ``ciba_await`` when the request's
    ``expires_in`` has passed (§33.7 rule 4) -- the same type either way.
    """


def typed_poll_error(error: OAuthProtocolError) -> OAuthProtocolError:
    """The §33.4 subtype for ``access_denied`` / ``expired_token``, else ``error``."""
    if error.error == "access_denied":
        return CibaAccessDeniedError(error.error, error.error_description)
    if error.error == "expired_token":
        return CibaExpiredTokenError(error.error, error.error_description)
    return error


def local_expiry() -> CibaExpiredTokenError:
    """The client-side deadline refusal (§33.7 rule 4)."""
    return CibaExpiredTokenError(
        "expired_token",
        "the CIBA request expired before it was decided (client-side deadline from "
        "expires_in; CONTRACT.md §33.7 rule 4)",
    )


def mark_terminal(error: Exception) -> Exception:
    """Flag ``error`` as decisive for ``ciba_await`` and return it."""
    setattr(error, _TERMINAL, True)
    return error


def poll_step(error: Exception) -> Literal["pending", "slow_down", "transient", "terminal"]:
    """What one failed ``ciba_poll`` means for ``ciba_await`` (§33.3 rule 6, §33.7)."""
    if isinstance(error, OAuthProtocolError):
        if error.error == "authorization_pending":
            return "pending"
        if error.error == "slow_down":
            return "slow_down"
        # §33.3 rule 13: a 429's body is `rate_limit_exceeded`, never terminal
        # for a poll.
        if error.error == "rate_limit_exceeded":
            return "transient"
        return "terminal"
    if isinstance(error, NetworkError) and not getattr(error, _TERMINAL, False):
        return "transient"
    return "terminal"


class CibaInitiateResponse(BaseModel):
    """``CibaInitiateResponse`` (§33.2), plus when it was received."""

    model_config = ConfigDict(frozen=True)

    auth_req_id: SecretStr
    """The request's id at the token endpoint -- a bearer credential for the
    grant (§33.5). Never parse or length-check it. **Secret.**"""

    expires_in: int
    """The request's lifetime, seconds -- authoritative (§33.7 rule 4)."""

    interval: int = DEFAULT_CIBA_INTERVAL_SECONDS
    """The minimum seconds between token requests: the response's value, or
    :data:`DEFAULT_CIBA_INTERVAL_SECONDS` when it was absent or zero."""

    received_at: float = Field(default_factory=time.monotonic)
    """When the response was received (``time.monotonic()`` seconds);
    ``ciba_await``'s deadline is this plus ``expires_in``."""


class CibaClock(Protocol):
    """The clock ``ciba_await`` waits on -- injectable, so its schedule is
    testable without sleeping (§33.8 tests 6 and 7)."""

    def now(self) -> float:
        """The current monotonic time, seconds."""
        ...  # pragma: no cover - protocol

    def sleep(self, seconds: float) -> None:
        """Wait ``seconds``."""
        ...  # pragma: no cover - protocol


class AsyncCibaClock(Protocol):
    """:class:`CibaClock` for ``AsyncAxiamClient.ciba_await``."""

    def now(self) -> float:
        """The current monotonic time, seconds."""
        ...  # pragma: no cover - protocol

    async def sleep(self, seconds: float) -> None:
        """Wait ``seconds``."""
        ...  # pragma: no cover - protocol


class SystemCibaClock:
    """The real clock: ``time.monotonic`` and ``time.sleep``."""

    def now(self) -> float:
        """``time.monotonic()``."""
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        """``time.sleep(seconds)``."""
        time.sleep(seconds)


class AsyncSystemCibaClock:
    """The real async clock: ``time.monotonic`` and ``asyncio.sleep``."""

    def now(self) -> float:
        """``time.monotonic()``."""
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        """``await asyncio.sleep(seconds)``."""
        import asyncio

        await asyncio.sleep(seconds)


def _refusal(operation: str, field: str, message: str) -> ValidationError:
    """The SDK's local ``ValidationError`` (imported late: see ``_mcp._refuse``)."""
    from axiam_sdk.management._errors import local_refusal

    return local_refusal(operation, field, message)


class CibaRequestSigner:
    """The key and algorithm for the signed request form (§33.2, CIBA Core
    §7.1.1). **Both are the caller's**: there is no default for either, and the
    SDK signs under exactly the algorithm given -- the one the client registered
    as ``backchannel_authentication_request_signing_alg``.

    The key is held only as a prepared signing key; ``repr`` shows the
    algorithm and ``kid``, never the key.
    """

    def __init__(
        self, alg: CibaSigningAlg, private_key: SecretStr | str | bytes, kid: str | None = None
    ) -> None:
        """Build a signer from a PEM private key (PKCS#8 for ``EdDSA`` and
        ``ES256``; PKCS#1 or PKCS#8 for ``PS256``) and its algorithm.

        A key that parses is not yet a key for this algorithm, so the
        constructor proves it signs (probe-sign) before accepting it.

        Raises:
            ValidationError: locally, before any request, for an unknown
                algorithm, an empty key, or a key that does not sign under
                ``alg``. The message names neither the key nor any part of it.
        """

        def refuse() -> ValidationError:
            """The construction refusal."""
            return _refusal(
                "ciba_initiate",
                "signing_key",
                "the key is not a private key that signs under the given algorithm "
                "(CONTRACT.md §33.2)",
            )

        if alg not in ("PS256", "ES256", "EdDSA"):
            raise _refusal(
                "ciba_initiate", "alg", "must be one of PS256, ES256, EdDSA (CONTRACT.md §33.2)"
            )
        material = (
            private_key.get_secret_value() if isinstance(private_key, SecretStr) else private_key
        )
        if not material:
            raise refuse()
        try:
            prepared = jwt.get_algorithm_by_name(alg).prepare_key(material)
            jwt.encode({"probe": True}, prepared, algorithm=alg)
        except Exception:  # noqa: BLE001 - any failure to sign is the one refusal
            raise refuse() from None
        self._alg: CibaSigningAlg = alg
        self._key = prepared
        self._kid = kid

    @property
    def alg(self) -> CibaSigningAlg:
        """The algorithm this signer uses."""
        return self._alg

    @property
    def kid(self) -> str | None:
        """The ``kid`` header value, if any."""
        return self._kid

    def __repr__(self) -> str:
        """The algorithm and ``kid``; never the key."""
        return f"CibaRequestSigner(alg={self._alg!r}, kid={self._kid!r}, key=**********)"

    __str__ = __repr__

    def sign(self, members: Mapping[str, Any], *, client_id: str, audience: str) -> str:
        """The CIBA Core §7.1.1 ``request``: every member inside the JWT, plus
        ``iss`` = ``client_id``, ``aud`` = the issuer, ``iat`` = ``nbf`` = now,
        ``exp`` = now + :data:`SIGNED_REQUEST_LIFETIME_SECONDS` and a fresh
        128-bit ``jti``."""
        now = int(time.time())
        claims = dict(members)
        claims.update(
            {
                "iss": client_id,
                "aud": audience,
                "iat": now,
                "nbf": now,
                "exp": now + SIGNED_REQUEST_LIFETIME_SECONDS,
                "jti": secrets.token_hex(16),
            }
        )
        headers = {"kid": self._kid} if self._kid else None
        return jwt.encode(claims, self._key, algorithm=self._alg, headers=headers)


def initiate_members(
    *,
    scope: str,
    login_hint: str | None,
    id_token_hint: str | None,
    binding_message: str | None,
    requested_expiry: int | None,
    acr_values: str | None,
    resource: str | None,
    delivery: CibaDelivery,
    client_notification_token: SecretStr | str | None,
) -> dict[str, Any]:
    """The authentication-request members the caller set, exactly those
    (§33.2), with ``requested_expiry`` an integer (the form sends it as a
    string, the signed form as a JSON number).

    Raises:
        ValidationError: locally, before any request: both hints or neither; a
            ping-mode request without a non-empty ``client_notification_token``;
            a poll-mode request carrying one; an unknown delivery mode.
    """
    if (login_hint is None) == (id_token_hint is None):
        raise _refusal(
            "ciba_initiate",
            "login_hint",
            "set exactly one of login_hint and id_token_hint (CONTRACT.md §33.2)",
        )
    token = (
        client_notification_token.get_secret_value()
        if isinstance(client_notification_token, SecretStr)
        else client_notification_token
    )
    if delivery == "ping":
        if not token:
            raise _refusal(
                "ciba_initiate",
                "client_notification_token",
                "a ping-mode request needs a non-empty client_notification_token: without "
                "one AXIAM has nothing to ping with (CONTRACT.md §33.2)",
            )
    elif delivery == "poll":
        if token is not None:
            raise _refusal(
                "ciba_initiate",
                "client_notification_token",
                "a poll-mode request carries no client_notification_token (CONTRACT.md §33.2)",
            )
    else:
        raise _refusal("ciba_initiate", "delivery", "must be poll or ping (CONTRACT.md §33)")
    members: dict[str, Any] = {"scope": scope}
    if login_hint is not None:
        members["login_hint"] = login_hint
    if id_token_hint is not None:
        members["id_token_hint"] = id_token_hint
    if binding_message is not None:
        members["binding_message"] = binding_message
    if requested_expiry is not None:
        members["requested_expiry"] = int(requested_expiry)
    if acr_values is not None:
        members["acr_values"] = acr_values
    if resource is not None:
        members["resource"] = resource
    if token is not None:
        members["client_notification_token"] = token
    return members


def initiate_form(
    members: Mapping[str, Any],
    auth: Mapping[str, str],
    signer: CibaRequestSigner | None,
    issuer: str,
) -> dict[str, str]:
    """The ``bc-authorize`` form: client authentication, then either every
    member (plain) or only ``request`` (signed, §33.2: "nothing else beside it
    except the client's authentication")."""
    form = dict(auth)
    if signer is None:
        form.update({k: str(v) for k, v in members.items()})
    else:
        form["request"] = signer.sign(members, client_id=auth["client_id"], audience=issuer)
    return form


def initiate_response(response: httpx.Response) -> CibaInitiateResponse:
    """A ``200`` as :class:`CibaInitiateResponse`, or the §33.4 error.

    Raises:
        OAuthProtocolError: any body with an ``error`` member, at any status.
        NetworkError: a body that is not ``{auth_req_id, expires_in, ...}``.
    """
    if not response.is_success:
        raise ciba_error(response, "ciba_initiate")
    try:
        wire = response.json()
    except ValueError:
        raise NetworkError("ciba_initiate: the response is not JSON") from None
    auth_req_id = wire.get("auth_req_id") if isinstance(wire, dict) else None
    expires_in = wire.get("expires_in") if isinstance(wire, dict) else None
    if not isinstance(auth_req_id, str) or not isinstance(expires_in, int):
        raise NetworkError("ciba_initiate: the response is not a CibaInitiateResponse")
    interval = wire.get("interval")
    return CibaInitiateResponse(
        auth_req_id=SecretStr(auth_req_id),
        expires_in=expires_in,
        interval=(
            interval
            if isinstance(interval, int) and not isinstance(interval, bool) and interval > 0
            else DEFAULT_CIBA_INTERVAL_SECONDS
        ),
    )


def ciba_error(response: httpx.Response, operation: str) -> Exception:
    """§33.4: a body with a non-empty ``error`` is an ``OAuthProtocolError``
    at any status (``access_denied`` / ``expired_token`` as their subtypes);
    otherwise §2 by status."""
    error = error_from_oauth2_response(
        response.status_code,
        response,
        f"{operation} failed with HTTP {response.status_code}",
        description_optional=True,
    )
    return typed_poll_error(error) if isinstance(error, OAuthProtocolError) else error


def ciba_poll_error(response: httpx.Response) -> Exception:
    """A failed ``ciba_poll``: :func:`ciba_error`, except that a ``5xx`` maps by
    status (§2: ``NetworkError``) **whatever its body**.

    AXIAM's own token endpoint answers an internal failure
    ``500 {"error":"server_error"}``, and ``503 {"error":"temporarily_unavailable"}``
    is the same kind of answer: on ``ciba_poll`` both are retried under §16 and
    never end ``ciba_await`` (CONTRACT.md §33.4, §33.7 rule 5, §34.2 P8 --
    which prevails over §33.4's "at any status" for this operation only).
    """
    status = response.status_code
    if 500 <= status <= 599:
        return error_from_http_status(status, f"ciba_poll failed with HTTP {status}", response)
    return ciba_error(response, "ciba_poll")


def poll_form(auth_req_id: SecretStr | str, auth: Mapping[str, str]) -> dict[str, str]:
    """The CIBA token request form (CIBA Core §10.1)."""
    value = auth_req_id.get_secret_value() if isinstance(auth_req_id, SecretStr) else auth_req_id
    return {"grant_type": CIBA_GRANT_TYPE, "auth_req_id": value, **auth}


def _header_pairs(
    headers: Mapping[str, Any] | Iterable[tuple[Any, Any]],
) -> list[tuple[str, str]]:
    """Headers in any framework's shape as ``(name, value)`` string pairs.

    Prefers a multi-valued view (``multi_items()``) so a duplicated header is
    seen twice; a plain mapping can hold each name once only.
    """
    if hasattr(headers, "multi_items"):
        raw: Iterable[tuple[Any, Any]] = headers.multi_items()
    elif isinstance(headers, Mapping):
        raw = headers.items()
    else:
        raw = headers
    pairs: list[tuple[str, str]] = []
    for name, value in raw:
        if isinstance(name, bytes):
            name = name.decode("latin-1")
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        pairs.append((str(name), str(value)))
    return pairs


def handle_ping(
    headers: Mapping[str, Any] | Iterable[tuple[Any, Any]],
    body: bytes | str,
    expected_token: SecretStr | str,
) -> SecretStr:
    """The pure §33.1 ping check behind both clients' ``ciba_handle_ping``.

    Raises:
        AuthError: the ``Authorization`` header is not exactly ``Bearer``, one
            space and the expected token (compared in constant time with
            :func:`hmac.compare_digest`), or there is not exactly one. The
            message names no value.
        ValidationError: the body is not a JSON object with a non-empty string
            ``auth_req_id``.
    """
    refused = AuthError(
        "ciba ping refused: the Authorization header is not the expected bearer (CONTRACT.md §33.1)"
    )
    values = [v for n, v in _header_pairs(headers) if n.lower() == "authorization"]
    if len(values) != 1:
        raise refused
    value = values[0]
    scheme, space, token = value.partition(" ")
    if not space or scheme.lower() != "bearer" or not token:
        raise refused
    expected = (
        expected_token.get_secret_value()
        if isinstance(expected_token, SecretStr)
        else expected_token
    )
    if not expected or not hmac.compare_digest(
        token.encode("utf-8", "surrogateescape"), expected.encode("utf-8", "surrogateescape")
    ):
        raise refused
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        raise _refusal("ciba_handle_ping", "body", "the ping body is not JSON") from None
    auth_req_id = parsed.get("auth_req_id") if isinstance(parsed, dict) else None
    if not isinstance(auth_req_id, str) or not auth_req_id:
        raise _refusal(
            "ciba_handle_ping",
            "auth_req_id",
            "the ping body carries no non-empty auth_req_id string",
        )
    return SecretStr(auth_req_id)
