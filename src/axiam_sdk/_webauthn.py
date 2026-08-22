"""WebAuthn and passkeys — CONTRACT.md §24.

A passkey ceremony is **two exchanges stacked**: one with an *authenticator*,
which needs a platform API, and one with *AXIAM*, which is four ordinary JSON
round trips. Python has no authenticator, so this SDK ships the second half —
which is not a consolation prize. A Python service completing a ceremony that
ran on a handset, or driving a virtual authenticator in a test, is the relying
party exactly as a browser is.

What that means concretely:

* **§24.1–§24.5, the relying-party layer** — implemented here in full.
* **§24.6a, the JSON bridge** — :func:`webauthn_request_json` hands the
  challenge to whatever runs the ceremony in the JSON form every platform
  authenticator API speaks, and every ``*_finish`` takes the platform's
  response JSON string directly.
* **§24.6b, the linked-API helper** — deliberately absent. §24.6b rule 2
  forbids emulating an authenticator in software: a "credential" held in
  process memory is not a second factor, and shipping one under this section's
  name would make the SDK the weakest link in a mechanism chosen for being the
  strongest.

The rule everything obeys is §24.0: the server chooses every option and
verifies every response, so this module carries both through untouched. It does
not default a field, normalize one, or re-encode a buffer.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, SecretStr

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk._session import _Session

__all__ = [
    "WebauthnChallenge",
    "WebauthnCredential",
    "WebauthnFailure",
    "WebauthnLoginResult",
    "WebauthnWorkspace",
    "classify_webauthn_error",
    "webauthn_error_message",
    "webauthn_request_json",
]


class WebauthnChallenge(BaseModel):
    """A started ceremony: the server's options plus the token binding a
    response to them.

    ``challenge`` is the raw wire value, unparsed — a ``{"publicKey": {...}}``
    mapping carrying base64url buffers exactly as the server sent them. Hand it
    to the authenticator **unchanged** (§24.0), or call
    :func:`webauthn_request_json` for the string a platform API takes.

    ``state_token`` is a bearer credential for the length of the ceremony —
    one that leaks inside that window is a ceremony an attacker can try to
    complete — so it is a ``SecretStr`` (§24.5). It is **opaque**: the SDK
    never decodes it, and neither should a caller.
    """

    challenge: dict[str, Any]
    state_token: SecretStr

    model_config = {"frozen": True}


class WebauthnCredential(BaseModel):
    """A credential the user just enrolled — the ``201`` body of
    ``register/finish``."""

    id: str
    credential_id: str
    name: str
    credential_type: str
    created_at: str
    last_used_at: str | None = None

    model_config = {"frozen": True}


class WebauthnLoginResult(BaseModel):
    """The outcome of a completed passkey sign-in.

    The client is **already authenticated** when this is returned (§24.3
    rule 1) — the tokens come back as well because a caller may want to hand
    them onward, not because adoption was optional.
    """

    access_token: SecretStr
    refresh_token: SecretStr
    session_id: str
    expires_in: int

    model_config = {"frozen": True}


class WebauthnWorkspace(BaseModel):
    """The workspace a usernameless ceremony runs inside.

    Unlike the five tenant-scoped ``/oauth2/*`` operations of §12.1 rule 2,
    this endpoint **accepts slugs**, so a slug-only client can run a
    discoverable sign-in. The SDK fills these from its own configured identity
    when the caller passes nothing.
    """

    org_id: str | None = None
    org_slug: str | None = None
    tenant_id: str | None = None
    tenant_slug: str | None = None

    model_config = {"frozen": True}


class WebauthnFailure(str, Enum):
    """A ceremony failure a caller can say something useful about (§24.6b
    rule 5).

    Five outcomes, and the first two are the ones that matter.
    """

    CANCELLED = "cancelled"
    ALREADY_REGISTERED = "already_registered"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


# Every platform reports a ceremony failure as one opaque type whose only
# machine-readable part is a name. Translating that once beats translating it
# in every caller — and a Python service is a plausible place to do it, because
# an Android or iOS client can relay the name it caught.
_FAILURE_BY_NAME = {
    # NotAllowedError covers BOTH an explicit refusal and a silent timeout.
    # The WebAuthn spec deliberately refuses to distinguish them, because
    # telling a website which one happened leaks whether an authenticator was
    # present. "cancelled" is the honest label for both, and it must not be
    # recovered by timing the call.
    "notallowederror": WebauthnFailure.CANCELLED,
    "canceled": WebauthnFailure.CANCELLED,
    "cancelled": WebauthnFailure.CANCELLED,
    # The authenticator already holds a credential for this account: the server
    # sent it in `excludeCredentials` and the authenticator refused to silently
    # mint a second. The exclusion list working, not a failure — and the only
    # classification whose remedy is "use a different device".
    "invalidstateerror": WebauthnFailure.ALREADY_REGISTERED,
    "aborterror": WebauthnFailure.TIMEOUT,
    "timeout": WebauthnFailure.TIMEOUT,
    "notsupportederror": WebauthnFailure.UNSUPPORTED,
    "securityerror": WebauthnFailure.UNSUPPORTED,
}

_FAILURE_MESSAGES = {
    WebauthnFailure.CANCELLED: ("The request was cancelled or timed out. You can try again."),
    WebauthnFailure.ALREADY_REGISTERED: (
        "This device is already registered on your account. Try a different device, "
        "or remove the existing one first."
    ),
    WebauthnFailure.TIMEOUT: ("The request timed out before it completed. Please try again."),
    WebauthnFailure.UNSUPPORTED: (
        "This browser or device cannot be used for passkeys. Try a different browser, "
        "or use another sign-in method."
    ),
    WebauthnFailure.UNKNOWN: "Something went wrong. Please try again.",
}


def classify_webauthn_error(error: object) -> WebauthnFailure:
    """Map a platform ceremony error to its canonical classification (§24.6b
    rule 5).

    Accepts anything a caller can get hold of: an exception, an error name
    relayed from a browser or an Android ``CreateCredentialException``, an
    ``ASAuthorizationError`` code by name. Everything unrecognized is
    :attr:`WebauthnFailure.UNKNOWN` rather than a raise — a classifier that can
    fail is one more thing for an error handler to handle.
    """
    if isinstance(error, str):
        name: str | None = error
    elif isinstance(error, BaseException):
        name = type(error).__name__
    else:
        name = getattr(error, "name", None)
        if not isinstance(name, str):
            name = None
    if name is None:
        return WebauthnFailure.UNKNOWN
    return _FAILURE_BY_NAME.get(name.strip().lower(), WebauthnFailure.UNKNOWN)


def webauthn_error_message(failure: WebauthnFailure) -> str:
    """Copy for each failure, safe to show a user.

    The ``cancelled`` string deliberately does not accuse anyone of
    cancelling: the same classification covers a silent timeout, and the spec
    will not say which happened.
    """
    return _FAILURE_MESSAGES[failure]


def webauthn_request_json(challenge: WebauthnChallenge | dict[str, Any]) -> str:
    """The challenge in the JSON form every platform authenticator API takes
    (§24.6a rule 1).

    This is the string an Android app passes to
    ``CreatePublicKeyCredentialRequest`` or ``GetPublicKeyCredentialOption``,
    and the value a browser passes to
    ``PublicKeyCredential.parseCreationOptionsFromJSON()``. It is the inner
    options object: the ``publicKey`` wrapper belongs to the DOM's
    ``CredentialCreationOptions`` and the platform JSON APIs do not want it.

    Pure local computation, no I/O. Nothing is defaulted, dropped or reordered
    on the way through (§24.0).
    """
    raw = challenge.challenge if isinstance(challenge, WebauthnChallenge) else challenge
    return json.dumps(raw.get("publicKey", raw), separators=(",", ":"))


def coerce_authenticator_response(response: dict[str, Any] | str, operation: str) -> dict[str, Any]:
    """Accept either a mapping or the platform's own JSON string (§24.6a
    rule 2).

    Android's Credential Manager hands back ``registrationResponseJson`` /
    ``authenticationResponseJson``, and a browser hands back
    ``credential.toJSON()``. Making a caller destructure one of those into a
    mapping this SDK immediately re-serializes is three chances to corrupt a
    signed buffer in service of nothing, so the string is taken directly.

    Parsing is value-preserving: every field in these messages is a string or a
    plain object, so what reaches the server is what the authenticator
    produced.

    :meta private:
    """
    if not isinstance(response, str):
        return response
    try:
        parsed = json.loads(response)
    except ValueError as exc:  # pragma: no cover - exercised by the test suite
        raise TypeError(
            f"{operation}: the authenticator response string is not valid JSON. Pass the "
            "platform's response JSON verbatim (CONTRACT.md §24.6a)."
        ) from exc
    if not isinstance(parsed, dict):
        raise TypeError(
            f"{operation}: the authenticator response must be a JSON object (CONTRACT.md §24.6a)."
        )
    return parsed


class _WebauthnMixin:
    """Body builders and response parsers shared by the sync and async clients.

    Everything except the six HTTP sends lives here. Duplicating the shapes
    across the two client classes is how they end up disagreeing about which
    field is called what — the same reasoning the OPAQUE helpers in
    ``_client.py`` are written down with.

    The attributes below are declared (not assigned) for ``mypy --strict``'s
    benefit — ``_AxiamClientBase.__init__`` initializes them, since a mixin's
    own ``__init__`` is never called under multiple inheritance. Same pattern
    as :class:`~axiam_sdk._oidc._OidcMixin`.
    """

    _session: _Session
    _org_slug: str | None
    _org_id: str | None

    # Paths, in the order §24.1 lists them.
    _WA_REGISTER_START = "/api/v1/auth/webauthn/register/start"
    _WA_REGISTER_FINISH = "/api/v1/auth/webauthn/register/finish"
    _WA_AUTH_START = "/api/v1/auth/webauthn/authenticate/start"
    _WA_AUTH_FINISH = "/api/v1/auth/webauthn/authenticate/finish"
    _WA_DISCOVERABLE_START = "/api/v1/auth/webauthn/authenticate/discoverable/start"
    _WA_DISCOVERABLE_FINISH = "/api/v1/auth/webauthn/authenticate/discoverable/finish"

    def _webauthn_discoverable_body(self, workspace: WebauthnWorkspace | None) -> dict[str, Any]:
        """Build the discoverable ``start`` body (§24.1).

        The workspace comes from the client's own configuration unless the
        caller overrides it. Only fields that actually have a value are
        emitted: the server takes either form at either level, and sending
        ``null`` for the ones it does not have is indistinguishable from asking
        it to resolve nothing.
        """
        from axiam_sdk._errors import AuthError  # local: avoids an import cycle

        body: dict[str, Any] = {}
        org_id = (workspace.org_id if workspace else None) or self._org_id
        org_slug = (workspace.org_slug if workspace else None) or self._org_slug
        tenant_id = workspace.tenant_id if workspace else None
        tenant_slug = (workspace.tenant_slug if workspace else None) or self._session.tenant_slug

        if org_id:
            body["org_id"] = org_id
        elif org_slug:
            body["org_slug"] = org_slug
        else:
            raise AuthError(
                "webauthn_discoverable_start needs an organization: construct the client "
                "with one, or pass it in the workspace argument (CONTRACT.md §24.1)."
            )

        if tenant_id:
            body["tenant_id"] = tenant_id
        elif tenant_slug:
            body["tenant_slug"] = tenant_slug
        else:  # pragma: no cover - tenant_slug is required at construction
            raise AuthError("webauthn_discoverable_start needs a tenant (CONTRACT.md §24.1).")
        return body

    @staticmethod
    def _webauthn_register_finish_body(
        state_token: SecretStr | str,
        credential_name: str,
        response: dict[str, Any] | str,
    ) -> dict[str, Any]:
        """Build the ``register/finish`` body — response carried verbatim."""
        return {
            "state_token": _expose(state_token),
            "credential_name": credential_name,
            "response": coerce_authenticator_response(response, "webauthn_register_finish"),
        }

    @staticmethod
    def _webauthn_finish_body(
        state_token: SecretStr | str,
        response: dict[str, Any] | str,
        operation: str,
    ) -> dict[str, Any]:
        """Build either ``authenticate/finish`` body — response carried verbatim."""
        return {
            "state_token": _expose(state_token),
            "response": coerce_authenticator_response(response, operation),
        }

    def _require_webauthn_session(self, operation: str) -> None:
        """§24.1: ``register/*`` needs a session, and the refusal is raised
        client-side with **no wire call** — the shape §1.1 rule 3 requires of
        ``get_user_info``.

        The signal is the access cookie rather than a separate flag: this SDK
        has never kept one, and a second source of truth for "am I signed in"
        is a second thing to get out of step with the jar.
        """
        from axiam_sdk._client import ACCESS_COOKIE
        from axiam_sdk._errors import AuthError

        if not self._session.cookie_value(ACCESS_COOKIE):
            raise AuthError(
                f"{operation} requires an authenticated session: enrol a passkey while "
                "signed in (CONTRACT.md §24.1)."
            )

    def _webauthn_challenge(self, response: Any, operation: str) -> WebauthnChallenge:
        """Parse a ``start`` response, carrying the options through untouched."""
        from axiam_sdk._errors import error_from_http_status

        if response.status_code != 200:
            raise error_from_http_status(
                response.status_code, f"{operation} failed", response=response
            )
        wire = response.json()
        return WebauthnChallenge(
            challenge=wire["challenge"],
            state_token=SecretStr(wire["state_token"]),
        )

    def _webauthn_credential(self, response: Any) -> WebauthnCredential:
        """Parse the ``201`` from ``register/finish``.

        A ``403`` here is the tenant's attestation policy refusing **this
        authenticator** — an AAGUID that is not allow-listed, a missing FIDO
        certification, a revoked status — not a permission problem with the
        user. §24.4 rule 1 keeps the server's message verbatim, because it is
        the only way the person holding the key learns that a different one
        would work; ``error_from_http_status`` already carries it.
        """
        from axiam_sdk._errors import error_from_http_status

        if response.status_code not in (200, 201):
            raise error_from_http_status(
                response.status_code, "webauthn_register_finish failed", response=response
            )
        wire = response.json()
        return WebauthnCredential(
            id=wire["id"],
            credential_id=wire["credential_id"],
            name=wire["name"],
            credential_type=wire["credential_type"],
            created_at=wire["created_at"],
            last_used_at=wire.get("last_used_at"),
        )

    def _webauthn_login_result(self, response: Any, operation: str) -> WebauthnLoginResult:
        """Parse either ``authenticate/finish`` response.

        Adoption itself is the caller's job — the sync and async clients each
        absorb the cookie triple through their own machinery — because there is
        no shared send here to hang it off.
        """
        from axiam_sdk._errors import error_from_http_status

        if response.status_code != 200:
            raise error_from_http_status(
                response.status_code, f"{operation} failed", response=response
            )
        wire = response.json()
        return WebauthnLoginResult(
            access_token=SecretStr(wire["access_token"]),
            refresh_token=SecretStr(wire["refresh_token"]),
            session_id=wire["session_id"],
            expires_in=wire["expires_in"],
        )


def _expose(value: SecretStr | str) -> str:
    """Unwrap a ``SecretStr`` at the point of handing it to the transport."""
    return value.get_secret_value() if isinstance(value, SecretStr) else value
