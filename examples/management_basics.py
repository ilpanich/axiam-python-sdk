"""The CONTRACT §27 management surface, end to end.

Namespaces, paging, sparse updates, the error sub-types and one-time secrets --
the five things a caller meets first. Everything here has an ``await`` twin on
``AsyncAxiamClient``; the surface is identical.

    AXIAM_URL=https://axiam.example.com \\
    AXIAM_TENANT=acme \\
    AXIAM_ADMIN=admin@example.com \\
    AXIAM_ADMIN_PASSWORD=... \\
    python examples/management_basics.py
"""

from __future__ import annotations

import os
import secrets

from pydantic import SecretStr

from axiam_sdk import AxiamClient
from axiam_sdk.management import (
    ConflictError,
    NotFoundError,
    PageRequest,
    ValidationError,
    models,
)

BASE_URL = os.environ.get("AXIAM_URL", "https://axiam.example.com")
TENANT_SLUG = os.environ.get("AXIAM_TENANT", "acme")
ADMIN = os.environ.get("AXIAM_ADMIN", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("AXIAM_ADMIN_PASSWORD", "")


def main() -> None:
    """Walk the surface once."""
    with AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG) as client:
        client.login(ADMIN, ADMIN_PASSWORD)

        # --- Handles cost nothing -------------------------------------------
        # Acquiring one performs no I/O (§27.2 rule 1). There is nothing to
        # cache and nothing to close.
        users = client.users

        # --- Paging ---------------------------------------------------------
        # `total` is the size of the whole set, not of this page. That is the
        # distinction §27.4 rule 4 exists to preserve.
        page = users.list(PageRequest(limit=25))
        print(f"{len(page.items)} of {page.total} users; more? {page.has_more()}")

        # `list_all` walks to exhaustion. It stops on an empty page even if the
        # server's `total` disagrees, so a misreporting server costs one wasted
        # request rather than an unbounded loop.
        everyone = users.list_all(PageRequest(limit=100))
        print(f"walked {len(everyone)} users")

        # --- Search --------------------------------------------------------
        # The term rides on the page request rather than being a third argument
        # on each of the twenty `list` methods, and that is what makes
        # `list_all` carry it across the whole walk: a walk that filtered page
        # one and not page two would hand back the matches followed by the
        # unfiltered tail.
        #
        # The SERVER filters, before offset/limit, so `total` counts matches --
        # filtering the page here in Python would give you neither that nor a
        # page count that belongs to the set it labels.
        matches = users.list(PageRequest(limit=25, search="ada"))
        print(f"{matches.total} users match 'ada'")

        # Blank is the same request as unset: `PageRequest(search="")` and
        # `PageRequest(search="   ")` send no `search` key at all. A box that
        # fires on every keystroke sends one of those the moment it is cleared,
        # and "rows containing the empty string" is a different question from
        # "all rows" -- so this pair issues the identical request.
        cleared = users.list(PageRequest(limit=25, search="   "))
        print(f"a cleared box asks for everything again: {cleared.total} users")

        # The server caps the term's length. This SDK does not copy that cap: a
        # truncation the server would not have made is a silently different
        # query, with nothing to say so.

        # --- Open enums ----------------------------------------------------
        # `TenantKind` is `Literal["standard", "organization"] | str`. The
        # widening is not laziness: a bare Literal is validated strictly by
        # pydantic, so the next kind the server adds would raise on the WHOLE
        # response -- taking down every tenant on the page over one field of one
        # of them, including the ones you were after (§27.11 rule 1).
        for tenant in client.tenants.list_all(PageRequest(limit=100))[:1]:
            # `kind` is None on a row written before organization scope
            # existed; read that as "standard".
            print(f"tenant {tenant.slug!r} kind={tenant.kind!r}")

        # --- Two other Nones that are not zero ------------------------------
        # MtlsTrustAnchorResponse.trusted_anchors is None when NOTHING WAS
        # RELOADED -- not when the listener trusts zero CAs. Only one of those
        # two states is a problem.
        #
        # Certificate.bound_service_account_id is resolved by `list` and is None
        # on `get`. The SDK spends no second request filling it in behind you.
        certs = client.certificates.list(PageRequest(limit=5))
        for cert in certs.items[:1]:
            print(f"cert {cert.id} bound to {cert.bound_service_account_id!r}")

        # A bare-array read is a list, not a page -- modelling it as a page
        # would give it a `total` that only ever equalled `len(items)`.
        for resource in client.resources.list_all(PageRequest(limit=100))[:1]:
            scopes = client.scopes.list(resource.id)
            print(f"resource {resource.name!r} has {len(scopes)} scopes")

        # --- Creating, and the error sub-types ------------------------------
        username = f"demo-{secrets.token_hex(4)}"
        try:
            created = users.create(
                models.CreateUserRequest(
                    username=username,
                    email=f"{username}@example.test",
                    # A secret, so it is a SecretStr: redacted from every repr,
                    # log line and JSON rendering, and unwrapped in exactly one
                    # place on the way to the socket.
                    password=SecretStr(secrets.token_urlsafe(24)),
                )
            )
        except ConflictError as err:
            # 409 -- a uniqueness or state conflict. Never retried: the server
            # is telling the truth, and a retry produces the same answer one
            # round-trip later.
            print(f"already taken: {err}")
            return
        except ValidationError as err:
            # 400/422 -- usually the *user's* input, not a bug in the caller.
            # This is why §27 splits it out of §2's NetworkError: an
            # application needs to tell it from a broken socket without
            # matching on message text.
            for field in err.fields:
                print(f"  rejected {field.field}: {field.message}")
            return

        print(f"created {created.username} ({created.id})")

        # --- Sparse updates -------------------------------------------------
        # This body carries one field, so the wire body has exactly one key.
        # What you leave out is left unchanged -- it is omitted entirely rather
        # than sent as null (§27.4 rule 5).
        users.update(created.id, models.UpdateUserRequest(email="moved@example.test"))

        # --- Scope overrides ------------------------------------------------
        # `{org_id}` and `{tenant_id}` default from the client. A platform-admin
        # token legitimately administers another tenant, so every handle that
        # needs one exposes an override -- and returns a NEW handle, leaving the
        # original alone.
        other = os.environ.get("AXIAM_OTHER_TENANT")
        if other:
            print(client.settings.for_tenant(other).get_tenant_override())

        # --- 404 is an authorization outcome --------------------------------
        # The server answers identically for "does not exist" and "belongs to
        # another tenant", on purpose: a distinguishable answer would let a
        # caller enumerate another tenant's ids. So NotFoundError is an
        # AuthzError, and `except AuthzError` written before §27 still catches it.
        users.delete(created.id)
        try:
            users.get(created.id)
        except NotFoundError as err:
            print(f"gone, as expected: {err}")


if __name__ == "__main__":
    main()
