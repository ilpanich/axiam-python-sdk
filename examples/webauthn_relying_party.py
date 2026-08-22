"""WebAuthn / passkeys from Python — CONTRACT.md §24.

Python has no authenticator, so this SDK ships the **relying-party** half of a
passkey ceremony: the four JSON round trips with AXIAM. That is not a
consolation prize. A Python service completing a ceremony that ran on an
Android or iOS handset is the relying party exactly as a browser is, and this
is the shape that service takes.

What the service does:

  1. Ask AXIAM for a challenge.
  2. Hand the client the challenge in its platform JSON form (§24.6a) — the
     exact string Android's ``CreatePublicKeyCredentialRequest`` and a
     browser's ``parseCreationOptionsFromJSON()`` both take.
  3. Take the client's response JSON back, unaltered, and post it to AXIAM.

Nothing here emulates an authenticator. §24.6b rule 2 forbids it: a
"credential" held in process memory is not a second factor.

Run: AXIAM_BASE_URL=... python examples/webauthn_relying_party.py
"""

from __future__ import annotations

import os

from axiam_sdk import (
    AuthError,
    AxiamClient,
    WebauthnFailure,
    classify_webauthn_error,
    webauthn_error_message,
    webauthn_request_json,
)

BASE_URL = os.environ.get("AXIAM_BASE_URL", "https://iam.example.com")
ORG_SLUG = os.environ.get("AXIAM_ORG_SLUG", "globex")
TENANT_SLUG = os.environ.get("AXIAM_TENANT_SLUG", "acme")


def enrol_a_passkey(client: AxiamClient, credential_name: str) -> None:
    """Enrol a passkey for the signed-in user, driving the device over your own
    channel."""
    challenge = client.webauthn_register_start()

    # Step 2. This string goes to the device untouched — every WebAuthn option
    # is a security parameter the server chose, and a client that "helpfully"
    # adjusts one has weakened a ceremony the server believes it configured
    # (§24.0).
    request_json = webauthn_request_json(challenge)
    response_json = send_to_device_and_await_reply(request_json)

    # Step 3. The response goes back byte-for-byte: it is the input to a
    # signature check over bytes this process did not produce.
    credential = client.webauthn_register_finish(
        state_token=challenge.state_token,
        credential_name=credential_name,
        response=response_json,
    )
    print(f"enrolled {credential.credential_type} {credential.name!r}")


def sign_in_with_a_passkey(client: AxiamClient) -> None:
    """Usernameless sign-in, driven from a service.

    The workspace still has to be named — a discoverable credential is resolved
    inside one tenant — but it comes from the client's own configuration, and
    this endpoint accepts slugs.
    """
    challenge = client.webauthn_discoverable_start()
    response_json = send_to_device_and_await_reply(webauthn_request_json(challenge))

    session = client.webauthn_discoverable_finish(
        state_token=challenge.state_token, response=response_json
    )
    # The client is authenticated now — §24.3 rule 1 is not "MAY adopt".
    print(f"signed in, session {session.session_id}, expires in {session.expires_in}s")


def sign_in_with_password_then_passkey(client: AxiamClient, email: str, password: str) -> None:
    """Passkey as a second factor, continuing a password login."""
    result = client.login(email, password)

    if result.mfa_setup_required:
        # §25.2 rule 1 — see examples/account_lifecycle.py.
        print("this tenant requires MFA and this account has none")
        return
    if not result.mfa_required:
        print("signed in with the password alone")
        return

    assert result.mfa_token is not None
    challenge = client.webauthn_authenticate_start(challenge_token=result.mfa_token)
    response_json = send_to_device_and_await_reply(webauthn_request_json(challenge))
    client.webauthn_authenticate_finish(state_token=challenge.state_token, response=response_json)
    print("signed in with a passkey as the second factor")


def report_a_device_failure(error_name_from_device: str) -> None:
    """Translate a failure the device reported into one vocabulary.

    Every platform reports a ceremony failure as one opaque type whose only
    machine-readable part is a name, so a device can relay just that. The five
    outcomes are the same everywhere, and ``already_registered`` is the one
    worth separating: the authenticator already holds a credential for this
    account and refused to mint a second, so the remedy is a different device
    rather than another attempt.
    """
    failure = classify_webauthn_error(error_name_from_device)
    if failure is WebauthnFailure.ALREADY_REGISTERED:
        print("this device is already enrolled — try another")
    print(webauthn_error_message(failure))


def send_to_device_and_await_reply(request_json: str) -> str:
    """Stand-in for your own channel to the device.

    In a real deployment this is a websocket to a mobile app, a push
    notification, a QR-code handshake — whatever carries the string there and
    the answer back. Both directions are opaque to this process, which is the
    point.
    """
    raise NotImplementedError(
        "wire this to your own device channel; it must return the platform's "
        "registrationResponseJson / authenticationResponseJson verbatim"
    )


def main() -> None:
    """Construct a client and show what a caller would do with it."""
    with AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG, org_slug=ORG_SLUG) as client:
        try:
            sign_in_with_a_passkey(client)
        except NotImplementedError as exc:
            print(f"example stub: {exc}")
        except AuthError as exc:
            print(f"sign-in failed: {exc}")


if __name__ == "__main__":
    main()
