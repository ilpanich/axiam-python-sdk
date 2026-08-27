"""Account lifecycle and MFA enrolment — CONTRACT.md §25.

§1 locked the *middle* of an account's life: ``login``, ``verify_mfa``,
``refresh`` and ``logout`` all assume an account that already exists, is
verified, and already has its second factor. These nine operations are how an
account gets into that state. None of them is new server surface — all nine
have been live and unreachable-from-an-SDK since before §1 was written, which
meant every application hand-rolled a POST against a path this SDK also knew.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, SecretStr

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk._session import _Session

__all__ = [
    "MfaEnrollment",
    "PasswordResetContext",
]


class MfaEnrollment(BaseModel):
    """A TOTP enrolment offer.

    **The factor is not active yet.** It becomes active when ``mfa_confirm``
    accepts a code derived from this secret — which is why §25.2 rule 4 forbids
    a composed one-call helper here: the human step in the middle, scanning the
    URI and reading a code, is not something a helper can wait for, and one
    that returned after ``mfa_enroll`` would report MFA as enabled when it is
    not.

    Both fields are secret, and ``totp_uri`` is the one that matters: it is
    ``otpauth://totp/...?secret=<secret_base32>``, so it *contains* the secret
    beside it. An SDK that wrapped the secret and left the URI bare would have
    wrapped nothing — the URI is the field that actually reaches a log, because
    it is the field a caller hands to a QR renderer (§25.3).
    """

    secret_base32: SecretStr
    totp_uri: SecretStr

    model_config = {"frozen": True}


class PasswordResetContext(BaseModel):
    """The effective OPAQUE policy for the account a reset token belongs to.

    Discloses no identity. Contract 1.26 removed the username from this
    response when OPAQUE replaced SRP — OPAQUE has no identity in its key
    derivation, so nothing needed it, and an unauthenticated endpoint that
    confirms which account a token belongs to is an oracle worth not having
    (§25.4 rule 2).
    """

    opaque: dict[str, Any] | None = None

    model_config = {"frozen": True}


class _AccountMixin:
    """Body builders and response parsers shared by the sync and async clients.

    The attributes below are declared (not assigned) for ``mypy --strict``'s
    benefit, exactly as :class:`~axiam_sdk._oidc._OidcMixin` declares its own.
    """

    _session: _Session
    _org_slug: str | None

    _AC_MFA_ENROLL = "/api/v1/auth/mfa/enroll"
    _AC_MFA_CONFIRM = "/api/v1/auth/mfa/confirm"
    _AC_MFA_SETUP_ENROLL = "/api/v1/auth/mfa/setup/enroll"
    _AC_MFA_SETUP_CONFIRM = "/api/v1/auth/mfa/setup/confirm"
    _AC_VERIFY_EMAIL = "/api/v1/auth/verify-email"
    _AC_RESEND_VERIFICATION = "/api/v1/auth/resend-verification"
    _AC_RESEND_OWN_VERIFICATION = "/api/v1/users/me/resend-verification"
    _AC_RESET = "/api/v1/auth/reset"
    _AC_RESET_CONFIRM = "/api/v1/auth/reset/confirm"
    _AC_RESET_CONTEXT = "/api/v1/auth/reset/context"

    def _password_reset_body(
        self,
        *,
        email: str,
        org_slug: str | None,
        tenant_id: str | None,
        tenant_slug: str | None,
    ) -> dict[str, Any]:
        """Build the ``POST /api/v1/auth/reset`` body (§25.1).

        Slugs are accepted here, as on ``login`` — this is not an
        ``/oauth2/*`` endpoint and §12.1 rule 2's UUID requirement does not
        reach it.
        """
        body: dict[str, Any] = {"email": email}
        resolved_org = org_slug or self._org_slug
        resolved_tenant_slug = tenant_slug or self._session.tenant_slug
        if resolved_org:
            body["org_slug"] = resolved_org
        if tenant_id:
            body["tenant_id"] = tenant_id
        elif resolved_tenant_slug:
            body["tenant_slug"] = resolved_tenant_slug
        return body

    @staticmethod
    def _password_reset_confirm_body(
        *,
        token: SecretStr | str,
        new_password: SecretStr | str,
        tenant_id: str,
        opaque: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Build the ``POST /api/v1/auth/reset/confirm`` body (§25.1)."""
        body: dict[str, Any] = {
            "token": _expose(token),
            "new_password": _expose(new_password),
            "tenant_id": tenant_id,
        }
        if opaque is not None:
            body["opaque"] = opaque
        return body

    def _mfa_enrollment(self, response: Any, operation: str) -> MfaEnrollment:
        """Parse an ``MfaEnrollResponse``."""
        from axiam_sdk._errors import error_from_http_status

        if response.status_code != 200:
            raise error_from_http_status(
                response.status_code, f"{operation} failed", response=response
            )
        wire = response.json()
        return MfaEnrollment(
            secret_base32=SecretStr(wire["secret_base32"]),
            totp_uri=SecretStr(wire["totp_uri"]),
        )

    def _mfa_confirmed(self, response: Any) -> bool:
        """Parse an ``MfaConfirmResponse``."""
        from axiam_sdk._errors import error_from_http_status

        if response.status_code != 200:
            raise error_from_http_status(
                response.status_code, "mfa_confirm failed", response=response
            )
        return bool(response.json().get("mfa_enabled", False))

    def _reset_context(self, response: Any) -> PasswordResetContext:
        """Parse a ``ResetContextResponse``.

        A ``404`` means unknown, expired **or** already-consumed, deliberately
        without distinguishing them; this SDK does not distinguish them either
        (§25.4 rule 3).
        """
        from axiam_sdk._errors import error_from_http_status

        if response.status_code != 200:
            raise error_from_http_status(
                response.status_code, "password_reset_context failed", response=response
            )
        wire = response.json() or {}
        return PasswordResetContext(opaque=wire.get("opaque"))

    def _expect_no_content(self, response: Any, operation: str) -> None:
        """Raise for anything that is not a success on the bodyless operations."""
        from axiam_sdk._errors import error_from_http_status

        if response.status_code not in (200, 202, 204):
            raise error_from_http_status(
                response.status_code, f"{operation} failed", response=response
            )


def _expose(value: SecretStr | str) -> str:
    """Unwrap a ``SecretStr`` at the point of handing it to the transport."""
    return value.get_secret_value() if isinstance(value, SecretStr) else value
