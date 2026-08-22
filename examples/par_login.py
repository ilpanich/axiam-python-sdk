"""Pushed Authorization Requests — CONTRACT.md §26 (RFC 9126).

PAR moves the authorization request off the browser. Instead of putting
``scope``, ``redirect_uri``, ``state`` and the PKCE challenge into a URL the
user agent carries, the client POSTs them straight to AXIAM over an
authenticated back channel and puts an opaque ``request_uri`` in the redirect.
What travels through the browser is then a random string that cannot be edited
into meaning something else.

Required for a FAPI 2.0 client: ``profile: "fapi2"`` refuses a registration
that does not set ``require_par``, so such a client cannot authorize any other
way.

Run: AXIAM_CLIENT_ID=... AXIAM_CLIENT_SECRET=... python examples/par_login.py
"""

from __future__ import annotations

import os

from axiam_sdk import AxiamClient, OidcTokenSet, PushedAuthorizationRequest

BASE_URL = os.environ.get("AXIAM_BASE_URL", "https://iam.example.com")
TENANT_ID = os.environ.get("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111")
REDIRECT_URI = os.environ.get("AXIAM_REDIRECT_URI", "https://app.example.com/auth/callback")
SCOPE = "openid profile email"


def begin(client: AxiamClient) -> PushedAuthorizationRequest:
    """Start a login by pushing the request.

    ``oidc_begin`` still does the computing — §26.2 rule 1 forbids a second
    generator for ``state``, ``nonce`` and PKCE, so ``oidc_par`` pushes what it
    produced rather than producing its own.
    """
    configuration = client.oidc_discover()
    request = client.oidc_begin(configuration=configuration, redirect_uri=REDIRECT_URI, scope=SCOPE)

    pushed = client.oidc_par(
        request=request,
        redirect_uri=REDIRECT_URI,
        scope=SCOPE,
        configuration=configuration,
        tenant_id=TENANT_ID,
    )

    # Exactly two query parameters: `client_id` and `request_uri`. Not
    # `response_type`, not `scope`, not `state` — the server REFUSES a request
    # carrying both a `request_uri` and any inline authorization parameter
    # rather than merging them, because merging is where parameter confusion
    # lives (§26.2 rule 2). Do not "helpfully" re-add them.
    print(f"redirect the browser to {pushed.authorization_url}")

    # Store `state`, `nonce` and `code_verifier` against the browser session,
    # as you would without PAR. `request_uri` is single-use and short-lived;
    # there is nothing to retry with it if the redirect fails (§26.2 rule 3).
    return pushed


def complete(
    client: AxiamClient,
    pushed: PushedAuthorizationRequest,
    code: str,
    returned_state: str,
) -> OidcTokenSet:
    """Finish the login. Unchanged by PAR — same grant, same verifier."""
    if returned_state != pushed.state:
        raise ValueError("state mismatch — abandon this login")

    return client.oidc_exchange(
        code=code,
        redirect_uri=REDIRECT_URI,
        nonce=pushed.nonce,
        # The verifier `oidc_begin` produced, carried through the push. One
        # value, so there is no second place for the two to disagree (rule 6).
        code_verifier=pushed.code_verifier,
        tenant_id=TENANT_ID,
    )


def main() -> None:
    """Construct a client and push one authorization request."""
    with AxiamClient(
        base_url=BASE_URL,
        tenant_slug=TENANT_ID,
        client_id=os.environ.get("AXIAM_CLIENT_ID", "axiam-rp"),
        client_secret=os.environ.get("AXIAM_CLIENT_SECRET"),
    ) as client:
        begin(client)


if __name__ == "__main__":
    main()
