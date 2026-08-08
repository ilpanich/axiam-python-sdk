"""Device Authorization Grant (CONTRACT.md §14) — signing in a device that
cannot show a browser.

The shape this example is really demonstrating: the SDK hands you the user
code and verification URI *before* it starts polling, and what you do with
them is yours. Here that is ``print``; on a real device it is a screen, a QR
code, or an e-ink panel. The SDK never prints them for you (§14.3 rule 2).

Run: ``python examples/device_login.py``
"""

from __future__ import annotations

import os

from axiam_sdk import AxiamClient, DeviceAuthorization, OAuthProtocolError


def main() -> None:
    """Run the device grant to completion and report the outcome."""
    base_url = os.environ.get("AXIAM_BASE_URL", "https://localhost:8443")
    tenant_id = os.environ.get("AXIAM_TENANT_ID", "11111111-2222-3333-4444-555555555555")
    client_id = os.environ.get("AXIAM_OIDC_CLIENT_ID", "my-device")

    # No client secret: a device that cannot show a browser cannot keep one
    # either, and §14.1 makes `device_authorize` unauthenticated for that
    # reason.
    client = AxiamClient(base_url=base_url, tenant_slug="acme", client_id=client_id)

    def show(authorization: DeviceAuthorization) -> None:
        """Called BEFORE the first poll. Display, then the SDK waits."""
        print(f"\n  To sign in, visit: {authorization.verification_uri}")
        print(f"  and enter code:    {authorization.user_code}")
        if authorization.verification_uri_complete:
            # Prefer this when the device can render a QR code — the user then
            # types nothing at all. Never build it yourself when it is absent:
            # the format is the server's to choose (§14.3).
            print(f"  or go straight to: {authorization.verification_uri_complete}")
        print("\nWaiting for approval…")

    try:
        tokens = client.device_login(show, scope="openid profile", tenant_id=tenant_id)
    except OAuthProtocolError as exc:
        # The two failure modes worth telling apart — a human said no, versus
        # nobody answered. Collapsing them loses the only information the
        # device can act on (§14.2 rule 3): whether re-prompting could help.
        if exc.error == "access_denied":
            print("The user refused the request.")
        elif exc.error == "expired_token":
            print("Nobody answered before the code expired.")
        else:
            raise
        return

    # §14.3 rule 4 (contract 1.7): this SDK returns the tokens; adopting them
    # is the application's decision, matching its login_client_credentials
    # posture.
    print(f"Signed in. Access token expires in {tokens.expires_in}s.")
    if tokens.id_claims is not None:
        print(f"Subject: {tokens.id_claims.sub}")


if __name__ == "__main__":
    main()
