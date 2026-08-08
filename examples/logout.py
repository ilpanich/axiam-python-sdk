"""RP-initiated and back-channel logout (CONTRACT.md §12.7).

Two halves that close each other's hole. Without the first, a user who logs out
of your app stays logged in at AXIAM and is silently signed back in on the next
"Login with AXIAM". Without the second, a user who logs out *of AXIAM* stays
logged in at your app indefinitely, because nothing tells you — which is what
leaves live sessions behind when an admin revokes a compromised account.

Run: ``python examples/logout.py``
"""

from __future__ import annotations

import os

from axiam_sdk import AuthError, AxiamClient


def main() -> None:
    """Build a logout redirect, then verify an inbound back-channel token."""
    base_url = os.environ.get("AXIAM_BASE_URL", "https://localhost:8443")
    client_id = os.environ.get("AXIAM_OIDC_CLIENT_ID", "my-app")

    client = AxiamClient(base_url=base_url, tenant_slug="acme", client_id=client_id)

    # -----------------------------------------------------------------
    # Half 1: the user clicked "log out" in YOUR app.
    # -----------------------------------------------------------------

    # The ID token you stored at login. It is what identifies *which* session
    # to end — a signed statement rather than a parameter anyone could send.
    # AXIAM does not check its expiry (a logging-out user's ID token has
    # usually expired already), but it does check the signature.
    stored_id_token = os.environ.get("AXIAM_ID_TOKEN", "the-id-token-from-login")

    url = client.logout_url(
        id_token=stored_id_token,
        post_logout_redirect_uri="https://app.example.com/goodbye",
        # `state` is yours to generate and yours to check when it comes back.
        # The SDK passes it through and never invents one, because the value
        # only means something to the app that will receive it.
        state="csrf-value-you-stored-in-the-session",
    )

    # Redirect the browser here. Note what the SDK did NOT do: it did not clear
    # this client's own session. Whether your local session ends is your
    # decision — a backend holding a service-account session must not lose it
    # because a *user* logged out.
    print(f"Redirect the user agent to:\n  {url}")

    # The redirect URI is honoured only if it exactly matches your client's
    # registered post_logout_redirect_uris — a separate list from
    # redirect_uris. The SDK does not pre-check it against a local copy
    # (§12.7.2 rule 3): that copy would drift and would reject a URI an
    # operator had just registered. If it does not match, AXIAM still logs the
    # user out and renders its own page.

    # -----------------------------------------------------------------
    # Half 2: AXIAM tells YOU a session ended.
    # -----------------------------------------------------------------
    #
    # Mount this at the backchannel_logout_uri you registered. AXIAM POSTs
    # `logout_token=<jwt>`, form-encoded.

    inbound = os.environ.get("AXIAM_LOGOUT_TOKEN")
    if not inbound:
        return

    try:
        verified = client.verify_logout_token(inbound)
    except AuthError as exc:
        # Answer 400 and log. Do not end anything: an unverifiable token is not
        # a logout instruction, and treating it as one would make your endpoint
        # a denial-of-service primitive for anyone who can reach it.
        print(f"rejected logout token: {exc}")
        return

    # Dedup on `jti` in YOUR store. Delivery is at-least-once, so a valid token
    # legitimately arrives twice — that is a retry, not an attack. The SDK
    # deliberately does not dedup: it has no durable store, and an in-memory
    # guard would silently drop a real second logout after a restart.
    print(f"logout token {verified.jti} verified")

    if verified.sid is not None:
        # End THAT session only. Falling back to "every session for this user"
        # is over-reach AXIAM itself refuses to make — the user's other devices
        # are still signed in on purpose.
        print(f"end session {verified.sid} only")
    else:
        print(f"no sid: this token names only sub {verified.sub}")


if __name__ == "__main__":
    main()
