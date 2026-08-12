"""UMA 2.0 (CONTRACT.md §20) — the **resource-server** half of the pair.

The situation: this service holds invoices that belong to *users*, not to
itself. When someone asks for one, the useful answer is not just "no" — it is
"not with what you're carrying, and here is where to go and get better". That
actionable refusal is what UMA adds over plain RBAC.

What this shows, in order:

1. Mint a **PAT** — a client-credentials token carrying ``uma_protection``.
   §20.2 rule 1 requires a *client* token: a minted ticket is bound to the
   ``client_id`` that minted it, so a user token cannot stand in.
2. **Register** the resource this service guards. The returned ``id`` *is* the
   AXIAM resource id — there is no parallel resource store to keep in sync.
3. Guard a route with ``require_access(..., uma_challenge=...)``, so a denial
   carries ``WWW-Authenticate: UMA`` with a fresh ticket.

Its counterpart is ``examples/uma_client.py``, which consumes that header.

Run: ``uvicorn examples.uma_resource_server:app --port 8081`` — ``GET
/invoices/{invoice_id}`` is the guarded route.
"""

from __future__ import annotations

import asyncio
import os

from fastapi import Depends, FastAPI

from axiam_sdk import (
    UMA_PROTECTION_SCOPE,
    AsyncAxiamClient,
    ResourceSet,
    UmaChallenger,
)
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk.fastapi import AxiamUser, require_access

BASE_URL = os.environ.get("AXIAM_BASE_URL", "https://localhost:8443")
TENANT = os.environ.get("AXIAM_TENANT_SLUG", "acme")
TENANT_ID = os.environ.get("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000")
CLIENT_ID = os.environ.get("AXIAM_OIDC_CLIENT_ID", "invoices-resource-server")
CLIENT_SECRET = os.environ.get("AXIAM_OIDC_CLIENT_SECRET", "resource-server-secret")


async def _bootstrap(client: AsyncAxiamClient) -> tuple[str, UmaChallenger]:
    """Mint the PAT, register the resource, and build the challenger.

    Returns the registered resource id and the challenger the guard uses.
    """
    # ---- 1. The PAT ----
    #
    # §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not a
    # user token, and not this client's ambient session — the SDK will not
    # substitute either, and the Protection API would refuse them anyway.
    session = await client.login_client_credentials(scope=UMA_PROTECTION_SCOPE)
    pat = session.access_token

    # ---- 2. Registration ----
    #
    # Registering the same name twice creates two resources, so a real service
    # registers once at provisioning time and stores the id, or reconciles by
    # listing. Inline here because it is the step that shows the id is the AXIAM
    # resource id.
    registered = await client.uma_register_resource(
        pat,
        ResourceSet(
            name="invoice-7",
            type="invoice",
            # The declared scopes are the allow-list the permission endpoint
            # validates a ticket request against. A resource registered with
            # none can never appear in a ticket.
            resource_scopes=["invoices:read", "invoices:approve"],
        ),
    )

    # ---- 3. The challenger ----
    #
    # `as_uri` names where the caller should redeem the ticket. Read it from the
    # discovery document rather than assembling it by hand — a deployment is
    # free to move its endpoints, which is why §12.3 rule 6 forbids hardcoding
    # them.
    configuration = await client.oidc_discover()
    challenger = UmaChallenger(
        realm="invoices", as_uri=configuration.issuer, pat=pat, client=client
    )
    assert registered.id is not None, "the server assigns an id on registration"
    return registered.id, challenger


client = AsyncAxiamClient(
    base_url=BASE_URL,
    tenant_slug=TENANT,
    oidc_client_id=CLIENT_ID,
    oidc_client_secret=CLIENT_SECRET,
    oidc_tenant_id=TENANT_ID,
)
invoice_id, challenger = asyncio.get_event_loop().run_until_complete(_bootstrap(client))
print(f"registered invoice-7 as {invoice_id}")
print(f"try:  curl -i http://127.0.0.1:8081/invoices/{invoice_id}")

app = FastAPI()
verifier = JwksVerifier(BASE_URL)

# The load-bearing argument is `uma_challenge`. Without it this is an ordinary
# §11 dependency and a denial is a bare 403. With it, the denial carries a ticket
# and the caller can act on it.
#
# Built once at module scope rather than inline in the signature: the factory is
# a real call, and FastAPI's `Depends` default would re-run it per request.
guard = Depends(
    require_access(
        verifier,
        TENANT,
        client,
        "invoices:read",
        resource_param="invoice_id",
        uma_challenge=challenger,
    )
)


@app.get("/invoices/{invoice_id}")
async def read_invoice(invoice_id: str, user: AxiamUser = guard) -> dict[str, object]:
    """Reached only when the engine allowed it — including honouring any deny
    rule, which UMA does not bypass: the ticket asks for the same action this
    check just evaluated, so the same grants and denies apply."""
    return {
        "id": invoice_id,
        "total": "42.00",
        "currency": "EUR",
        "reader": user.user_id,
    }
