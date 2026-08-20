"""CONTRACT.md §23 — OPAQUE (RFC 9807) login, with the password-login fallback.

    AXIAM_URL=https://axiam.example \
    AXIAM_ORG=acme AXIAM_TENANT=default \
    AXIAM_USER=alice AXIAM_PASSWORD='…' \
      python examples/opaque_login.py

What is worth reading here is the ordering and the error handling, not the
happy path: OPAQUE is attempted first so a tenant on ``opaque_mode: optional``
actually gets OPAQUE logins, and the one failure that is not "wrong password"
is handled distinctly.

The protocol comes from ``libaxiam_opaque_ffi`` — CONTRACT.md §23.1 forbids an
SDK from writing its own — which is a per-platform release asset rather than a
PyPI package, so there is no extra to install. Put it on the loader path, or
point ``AXIAM_OPAQUE_LIBRARY`` at the file. ``opaque_available()`` reports
whether this installation has it, which is why the script can choose the
password path up front instead of discovering the gap mid-login.
"""

from __future__ import annotations

import os
import sys

from axiam_sdk import AuthError, AxiamClient, NetworkError

client = AxiamClient(
    base_url=os.environ["AXIAM_URL"],
    tenant_slug=os.environ["AXIAM_TENANT"],
    org_slug=os.environ["AXIAM_ORG"],
)

user = os.environ["AXIAM_USER"]
password = os.environ["AXIAM_PASSWORD"]

with client:
    if not client.opaque_available():
        print("libaxiam_opaque_ffi is not installed — using password login")
        result = client.login(user, password)
    else:
        try:
            # OPAQUE first, password second. The reverse order — password
            # login, OPAQUE only when refused — would mean a tenant running
            # `opaque_mode: optional` never sees a single OPAQUE login, which
            # is the mode operators run for the whole of a migration.
            print("attempting OPAQUE (the pause is the KSF, and it is the point)…")
            result = client.login_opaque(user, password)
            print("signed in over OPAQUE — the password never left this process")

        except NetworkError as exc:
            if "opaque_mode is disabled" not in str(exc):
                # A KSF this build cannot perform, or a cost outside the
                # accepted band. A configuration problem: falling back would
                # hide it, and the plaintext would go to the server anyway.
                raise
            # A property of the tenant, not of the credentials — and a
            # NetworkError rather than an AuthError precisely so it cannot be
            # mistaken for a bad password.
            print("tenant has OPAQUE disabled — falling back to password login")
            result = client.login(user, password)

        except AuthError as exc:
            # This covers BOTH halves of the mutual authentication: the
            # envelope only opens under the right password, and KE2's MAC only
            # verifies if the server actually holds the record. A wrong
            # password and a server that cannot prove itself are
            # indistinguishable here by design — so do NOT retry over the
            # password path, which would hand the plaintext to an endpoint that
            # just failed to prove it holds the record (§23.4 rule 7).
            print(f"login failed: {exc}", file=sys.stderr)
            print("Not retrying with a password.", file=sys.stderr)
            raise SystemExit(1) from exc

    if result.mfa_required:
        assert result.mfa_token is not None
        code = input("MFA code: ")
        result = client.verify_mfa(result.mfa_token, code)

    print(f"session {result.session_id}")
