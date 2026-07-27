"""oidc_login.py demonstrates the OIDC/SSO relying-party helpers
(CONTRACT.md §12): "Login with AXIAM" via authorization-code + PKCE,
refreshing an OidcTokenSet, service-account client_credentials login, and
token introspection/revocation — on both the sync AxiamClient and the
dedicated async AsyncAxiamClient (SDK-Q08).

The nine canonical operations are: oidc_discover, oidc_begin, oidc_exchange,
oidc_refresh, login_client_credentials, introspect, revoke, sso_start, and
sso_complete. This example exercises the ones a typical backend-app
"Login with AXIAM" integration and its machine-to-machine counterpart need;
see README.md's "OIDC / SSO relying-party helpers (§12)" section for the
federation SSO pair (sso_start/sso_complete).

Stateless by contract (§12.3 rule 1): oidc_begin returns state/nonce/
code_verifier and stores NONE of them — this example keeps them in local
variables standing in for your own HTTP session. See
axiam_sdk.fastapi.oidc_login_router / axiam_sdk.django.oidc.oidc_login_views
for ready-made framework glue that does this bookkeeping via
MemoryOidcStateStore (or your own OidcStateStore) automatically.

This example is illustrative/compilable — it reads connection details from
environment variables and does not require a live AXIAM server to
byte-compile. Running it end-to-end requires a reachable AXIAM server
matching the configured base URL, and a browser to complete the
authorization-code redirect by hand (this is a backend RP demo, not a full
web app — see the FastAPI/Django glue for that).

Run: python examples/oidc_login.py
"""

from __future__ import annotations

import asyncio
import os

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, OAuthProtocolError


def getenv(key: str, fallback: str) -> str:
    return os.environ.get(key, fallback)


def sync_oidc_login() -> None:
    base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
    tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")
    tenant_id = getenv("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")
    client_id = getenv("AXIAM_OIDC_CLIENT_ID", "my-backend-app")
    client_secret = getenv("AXIAM_OIDC_CLIENT_SECRET", "changeme")
    redirect_uri = getenv("AXIAM_OIDC_REDIRECT_URI", "https://app.example.com/oidc/callback")

    # client_id/client_secret are constructor-time OIDC configuration
    # (CONTRACT.md T1 reference judgment call #21 — never a per-call
    # argument, since the client_id also has to match the ID token's aud).
    # tenant_slug is still the non-optional §5 tenant identifier used by the
    # rest of the SDK; tenant_id (a UUID) is what the /oauth2/* endpoints
    # require as a query parameter (§12.3 rule 4) — this example passes it
    # explicitly since no login()/refresh() has resolved one from a cookie
    # session yet.
    client = AxiamClient(
        base_url=base_url,
        tenant_slug=tenant_slug,
        client_id=client_id,
        client_secret=client_secret,
    )

    # 1. Discover the OIDC provider (cached >=5 minutes, single-flight).
    configuration = client.oidc_discover()

    # 2. Build the authorization request — pure local computation, no
    # network I/O. Persist state/nonce/code_verifier yourself (§12.3 rule 1);
    # here we just keep them as local variables for the demo.
    authorization_request = client.oidc_begin(
        configuration=configuration,
        redirect_uri=redirect_uri,
        scope="openid profile email",
    )
    print(f"Redirect the user's browser to:\n  {authorization_request.url}\n")
    print(f"(state={authorization_request.state}, nonce={authorization_request.nonce})")

    # 3. After the user authenticates and the browser is redirected back to
    # redirect_uri with ?code=...&state=..., exchange the code for tokens.
    # This example cannot complete a real browser redirect, so it stops
    # here in illustrative mode unless an authorization code is supplied.
    auth_code = os.environ.get("AXIAM_OIDC_AUTH_CODE")
    if not auth_code:
        print("Set AXIAM_OIDC_AUTH_CODE to continue past the authorization redirect.")
        return

    try:
        tokens = client.oidc_exchange(
            code=auth_code,
            code_verifier=authorization_request.code_verifier,
            redirect_uri=redirect_uri,
            nonce=authorization_request.nonce,
            tenant_id=tenant_id,
        )
    except OAuthProtocolError as exc:
        # RFC 6749 protocol error (e.g. invalid_grant) — a language-idiomatic
        # AuthError sub-type, so `except AuthError` also still matches it.
        print(f"OAuth2 protocol error: {exc.error} — {exc.error_description}")
        return
    except AuthError as exc:
        # Covers every §12.4 ID-token validation failure too (exc.reason is
        # one of the seven contract-fixed reason codes).
        print(f"login failed: {exc} (reason={exc.reason})")
        return

    print(f"Access token expires in {tokens.expires_in}s")
    if tokens.id_claims is not None:
        print(f"Authenticated subject: {tokens.id_claims.sub}")

    # 4. Refresh the token set later, under the shared §9 single-flight guard.
    if tokens.refresh_token is not None:
        refreshed = client.oidc_refresh(refresh_token=tokens.refresh_token, tenant_id=tenant_id)
        print(f"Refreshed access token expires in {refreshed.expires_in}s")

    # 5. Introspect/revoke require confidential-client credentials (already
    # configured above via client_secret).
    result = client.introspect(token=tokens.access_token, tenant_id=tenant_id)
    print(f"Introspection: active={result.active}, sub={result.sub}")

    client.revoke(token=tokens.access_token, tenant_id=tenant_id)
    print("Access token revoked.")


def sync_service_account_login() -> None:
    """M2M login via `client_credentials` — no user, no browser, no
    `openid` scope, no `id_token` in the response (CONTRACT.md §12.1)."""
    base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
    tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")
    tenant_id = getenv("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")
    client_id = getenv("AXIAM_SERVICE_CLIENT_ID", "my-service-account")
    client_secret = getenv("AXIAM_SERVICE_CLIENT_SECRET", "changeme")

    client = AxiamClient(
        base_url=base_url,
        tenant_slug=tenant_slug,
        client_id=client_id,
        client_secret=client_secret,
    )
    try:
        tokens = client.login_client_credentials(tenant_id=tenant_id, scope="authz:check")
    except AuthError as exc:
        print(f"service-account login failed: {exc}")
        return
    print(f"Service-account access token expires in {tokens.expires_in}s")


async def async_oidc_refresh_example() -> None:
    """The async twin — same canonical method names as `async def`
    (SDK-Q08), on the dedicated AsyncAxiamClient."""
    base_url = getenv("AXIAM_BASE_URL", "https://localhost:8443")
    tenant_slug = getenv("AXIAM_TENANT_SLUG", "acme")
    tenant_id = getenv("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")
    client_id = getenv("AXIAM_OIDC_CLIENT_ID", "my-backend-app")

    async with AsyncAxiamClient(
        base_url=base_url, tenant_slug=tenant_slug, client_id=client_id
    ) as client:
        refresh_token = os.environ.get("AXIAM_OIDC_REFRESH_TOKEN")
        if not refresh_token:
            print("Set AXIAM_OIDC_REFRESH_TOKEN to run the async oidc_refresh demo.")
            return
        try:
            tokens = await client.oidc_refresh(refresh_token=refresh_token, tenant_id=tenant_id)
        except AuthError as exc:
            print(f"async oidc_refresh failed: {exc}")
            return
        print(f"(async) refreshed access token expires in {tokens.expires_in}s")


if __name__ == "__main__":
    sync_oidc_login()
    sync_service_account_login()
    asyncio.run(async_oidc_refresh_example())
