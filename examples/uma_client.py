"""UMA 2.0 (CONTRACT.md §20) — the **client** half of the pair.

Run ``examples/uma_resource_server.py`` first; this program talks to it.

The flow, which is the whole reason UMA exists:

1. Ask for the invoice with the user's ordinary token. The resource server
   refuses — but its 403 carries ``WWW-Authenticate: UMA`` naming a ticket and
   an authorization server.
2. **Parse** the challenge. Note what happens next, and what does not: parsing
   performs no exchange (§20.3). The ``as_uri`` in that header is a host the
   *server we just failed against* chose; auto-redeeming would send the user's
   token wherever a 403 pointed.
3. Decide to trust it, then **exchange** the ticket for an RPT.
4. Retry with the RPT.

Step 3 is a decision, not a formality — this example makes it explicitly, by
comparing the nominated ``as_uri`` against the issuer this client already
trusts, and refusing when they differ.

Run: ``python examples/uma_client.py``
"""

from __future__ import annotations

import asyncio
import os

import httpx

from axiam_sdk import AsyncAxiamClient, uma_parse_challenge

BASE_URL = os.environ.get("AXIAM_BASE_URL", "https://localhost:8443")
TENANT = os.environ.get("AXIAM_TENANT_SLUG", "acme")
TENANT_ID = os.environ.get("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")
CLIENT_ID = os.environ.get("AXIAM_OIDC_CLIENT_ID", "invoices-client")
CLIENT_SECRET = os.environ.get("AXIAM_OIDC_CLIENT_SECRET", "client-secret")

# The resource server printed this id when it registered.
INVOICE_ID = os.environ.get("AXIAM_INVOICE_ID", "00000000-0000-0000-0000-000000000000")
RESOURCE_SERVER = os.environ.get("AXIAM_RESOURCE_SERVER", "http://127.0.0.1:8081")

# The requesting party's own token — what this program would normally send and,
# in step 3, the `claim_token` that names *who* is asking.
USER_TOKEN = os.environ.get("AXIAM_USER_TOKEN", "the-requesting-partys-access-token")


async def main() -> None:
    """Run the four steps against a live resource server."""
    # The exchange is a token-endpoint grant, so this client is confidential.
    client = AsyncAxiamClient(
        base_url=BASE_URL,
        tenant_slug=TENANT,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret=CLIENT_SECRET,
        oidc_tenant_id=TENANT_ID,
    )
    url = f"{RESOURCE_SERVER}/invoices/{INVOICE_ID}"

    async with httpx.AsyncClient() as http:
        # ---- 1. The refusal ----
        refused = await http.get(url, headers={"Authorization": f"Bearer {USER_TOKEN}"})
        print(f"first attempt: {refused.status_code}")

        header = refused.headers.get("WWW-Authenticate")
        if header is None:
            # A resource server that refuses without a challenge is telling you
            # it has nothing to offer — there is no ticket to redeem, and
            # retrying the same request would be pointless.
            print("no WWW-Authenticate header: this refusal is not actionable.")
            return

        # ---- 2. Parse, and only parse ----
        challenge = uma_parse_challenge(header)
        if challenge is None or challenge.ticket is None:
            print("the challenge names no ticket; nothing to redeem.")
            return

        # Print the *parsed* fields, never the raw header. The header contains
        # `ticket="..."`, and §20.6 is explicit that the ticket's 60-second life
        # does not make it harmless: for those 60 seconds it is the credential
        # that converts into an RPT, so a header in a log line is a live
        # credential in a log line. `realm` and `as_uri` are not secrets and are
        # the two fields you actually need to look at.
        print(f"challenge: realm={challenge.realm!r} as_uri={challenge.as_uri!r} ticket=[REDACTED]")

        # ---- 3. The trust decision ----
        #
        # This is the step §20.3 exists to keep in the caller's hands. The SDK
        # parsed the header and stopped; deciding whether to send the user's
        # token to the host it names is this program's call, and it is a real
        # one — a compromised or merely misconfigured resource server could
        # nominate anything here.
        trusted = (await client.oidc_discover()).issuer
        nominated = challenge.as_uri
        if nominated is not None and nominated.rstrip("/") != trusted.rstrip("/"):
            print(f"refusing to redeem: as_uri {nominated} is not our issuer {trusted}.")
            print("this is the auto-exchange §20.3 forbids, and why it forbids it.")
            return
        print("as_uri matches the issuer we already trust; redeeming.")

        # ---- 4. Exchange, then retry ----
        #
        # One request. A ticket is spent whether or not this succeeds (§20.2
        # rule 6), so on failure the next step is a *new* ticket — which means
        # going back to step 1, not resending this one.
        try:
            rpt = await client.uma_exchange_ticket(challenge.ticket, USER_TOKEN)
        except Exception as error:  # noqa: BLE001 - an example, not a library path
            print(f"exchange failed: {error}")
            print("the ticket is spent either way — request a new one by retrying the call.")
            return
        print(f"got an RPT, valid for {rpt.expires_in}s")

        allowed = await http.get(
            url, headers={"Authorization": f"Bearer {rpt.access_token.get_secret_value()}"}
        )
        print(f"second attempt: {allowed.status_code}")
        if allowed.is_success:
            print(f"body: {allowed.text}")


if __name__ == "__main__":
    asyncio.run(main())
