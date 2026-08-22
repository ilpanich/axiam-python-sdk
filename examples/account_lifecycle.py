"""Account lifecycle and MFA enrolment — CONTRACT.md §25.

The operations that get an account into the state §1's ``login``/``verify_mfa``/
``refresh``/``logout`` already assume: email verification, both MFA enrolment
paths, and password reset.

Run: AXIAM_BASE_URL=... python examples/account_lifecycle.py
"""

from __future__ import annotations

import os

from axiam_sdk import AxiamClient

BASE_URL = os.environ.get("AXIAM_BASE_URL", "https://iam.example.com")
TENANT_ID = os.environ.get("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111")


def enrol_totp(client: AxiamClient, code_from_user: str) -> None:
    """Voluntary enrolment, by a signed-in user.

    Two calls, and deliberately no one-call helper: the human step in the
    middle — scanning the URI, reading a code off a phone — is not something a
    composed helper can wait for, and one that returned after ``mfa_enroll``
    would report MFA as enabled when it is not (§25.2 rule 4).
    """
    enrolment = client.mfa_enroll()

    # `totp_uri` CONTAINS the secret: it is `otpauth://...?secret=...`. Both are
    # SecretStr for that reason, and the URI is the one that actually reaches a
    # log, because it is the one you hand to a QR renderer (§25.3).
    render_qr(enrolment.totp_uri.get_secret_value())

    if client.mfa_confirm(totp_code=code_from_user):
        print("TOTP is now active")


def sign_in(client: AxiamClient, email: str, password: str, code_from_user: str) -> None:
    """Sign in, handling the enrolment a tenant may demand.

    Before contract 1.28 the ``403 mfa_setup_required`` answer reached callers
    as an ``AuthzError`` — telling them they lacked permission to log in, when
    what the server said was recoverable and came with the means to recover. It
    is an outcome now (§25.2 rule 1), which is the whole reason this function
    can be written at all.
    """
    result = client.login(email, password)

    if result.mfa_setup_required:
        assert result.setup_token is not None
        enrolment = client.mfa_setup_enroll(setup_token=result.setup_token)
        render_qr(enrolment.totp_uri.get_secret_value())
        # This completes the login that was interrupted, and adopts credentials
        # exactly as `login()` would have (§25.2 rule 2).
        client.mfa_setup_confirm(setup_token=result.setup_token, totp_code=code_from_user)
        print("enrolled and signed in")
    elif result.mfa_required:
        assert result.mfa_token is not None
        client.verify_mfa(result.mfa_token, code_from_user)
        print("signed in with the second factor")
    else:
        print("signed in")


def verify_an_email(client: AxiamClient, token_from_link: str) -> None:
    """Confirm an address from the link in the verification mail."""
    client.verify_email(token=token_from_link, tenant_id=TENANT_ID)
    print("email verified")


def start_a_password_reset(client: AxiamClient, email: str) -> None:
    """Ask for a reset mail.

    Returns normally **whether or not the address exists**, and this SDK
    exposes no way to tell the difference. That is not an omission to improve
    on: any signal distinguishing them — including one inferred from timing —
    turns the endpoint into the account enumeration oracle its uniform response
    exists to prevent (§25.4).
    """
    client.request_password_reset(email=email)
    print("if that address has an account, a reset mail is on its way")


def finish_a_password_reset(client: AxiamClient, token_from_link: str, new_password: str) -> None:
    """Set the new password.

    The context call is not optional on a tenant that might have OPAQUE enabled
    (§23): the client has to build a registration record, and building one
    needs parameters it cannot know before it has a token to ask with. Sending
    a plaintext password to a tenant in ``opaque_mode: required`` is refused,
    and refused late.
    """
    context = client.password_reset_context(token=token_from_link)
    opaque = client.opaque_enrollment(new_password) if context.opaque else None

    client.confirm_password_reset(
        token=token_from_link,
        new_password=new_password,
        tenant_id=TENANT_ID,
        opaque=opaque,
    )
    print("password changed")


def render_qr(totp_uri: str) -> None:
    """Stand-in for showing the enrolment URI to a human."""
    print(f"scan this: {totp_uri[:32]}…")


def main() -> None:
    """Construct a client and show what a caller would do with it."""
    with AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_slug="globex") as client:
        start_a_password_reset(client, "alice@example.com")


if __name__ == "__main__":
    main()
