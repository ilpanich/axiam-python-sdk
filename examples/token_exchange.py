"""Token Exchange (CONTRACT.md §15) — narrowing a user's token before calling
the next service.

The situation: an API gateway holds a user's access token and needs to call an
orders service. Forwarding the user's token verbatim over-privileges that call
and leaves the second hop unable to tell the caller from the user; using the
gateway's own service credentials has the right privileges but loses the user
entirely. The exchange gives you both.

Run: ``python examples/token_exchange.py``
"""

from __future__ import annotations

import os

from axiam_sdk import AxiamClient, OAuthProtocolError


def main() -> None:
    """Exchange a user's token for a narrower one and report what was granted."""
    base_url = os.environ.get("AXIAM_BASE_URL", "https://localhost:8443")
    tenant_id = os.environ.get("AXIAM_TENANT_ID", "11111111-2222-3333-4444-555555555555")
    client_id = os.environ.get("AXIAM_OIDC_CLIENT_ID", "api-gateway")
    client_secret = os.environ.get("AXIAM_OIDC_CLIENT_SECRET", "gateway-secret")

    # The user's token, as it would arrive on an inbound request.
    user_token = os.environ.get("AXIAM_SUBJECT_TOKEN", "the-users-access-token")

    # Unlike §14's device, an exchanging client is a confidential service and
    # authenticates.
    client = AxiamClient(
        base_url=base_url,
        tenant_slug="acme",
        client_id=client_id,
        client_secret=client_secret,
    )

    try:
        # Delegation: "the gateway, acting on behalf of the user". Supplying an
        # actor_token is what makes it delegation; omitting it asks for
        # impersonation instead — a different operation with different risk,
        # which the server refuses unless this client holds that grant. The SDK
        # will not pick for you (§15.2 rule 1).
        exchanged = client.token_exchange(
            subject_token=user_token,
            scopes=["orders:read"],
            audience="orders-service",
            tenant_id=tenant_id,
        )
    except OAuthProtocolError as exc:
        # Each names something an operator must fix rather than something to
        # retry.
        if exc.error == "unauthorized_client":
            print("This client may not exchange, or may not impersonate — a registration fact.")
        elif exc.error == "invalid_scope":
            # Do NOT re-send with fewer scopes: the server refused rather than
            # silently narrowing precisely so you would find out here.
            print("You asked for a scope the user does not hold.")
        elif exc.error == "invalid_grant":
            # Cross-tenant collapses into this on purpose; do not try to tell
            # the cases apart.
            print("The subject token is invalid, expired, or from another tenant.")
        raise

    # Read what you actually got. On success the granted scope may still be
    # narrower than requested (§15.2 rule 7) — the client's registration bounds
    # it, and assuming the request was honoured verbatim is how a caller ends
    # up surprised at the *next* service.
    print(
        f"exchanged for {exchanged.expires_in}s, "
        f"granted scope: {exchanged.scope or '(server default)'}"
    )

    # Hand it onward in ONE outbound call. It is not this client's session:
    # adopting it would silently re-privilege every later call the gateway
    # makes, and the narrowed token would make most of them fail far from here
    # (rule 5). There is also no refresh token, ever — re-run the exchange
    # (rule 4).
    _authorization_header = f"Bearer {exchanged.access_token.get_secret_value()}"


if __name__ == "__main__":
    main()
