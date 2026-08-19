"""CONTRACT.md §23 — SRP-6a login, with the password-login fallback.

    AXIAM_URL=https://axiam.example \
    AXIAM_ORG=acme AXIAM_TENANT=default \
    AXIAM_USER=alice AXIAM_PASSWORD='…' \
      python examples/srp_login.py

What is worth reading here is the ordering and the error handling, not the
happy path: SRP is attempted first so a tenant on ``srp_mode: optional``
actually gets SRP logins, and the two failure modes that are not "wrong
password" are handled distinctly.

Argon2id needs the optional extra: ``pip install axiam-sdk[srp]``. A tenant on
``pbkdf2_sha256`` works without it.
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
    try:
        # SRP first, password second. The reverse order — password login, SRP
        # only when refused — would mean a tenant running `srp_mode: optional`
        # never sees a single SRP login, which is the mode operators run for
        # the whole of a migration.
        print("attempting SRP (the pause is the KDF, and it is the point)…")
        result = client.login_srp(user, password)
        print("signed in over SRP — the password never left this process")

    except NetworkError as exc:
        if "does not offer Secure Remote Password" not in str(exc):
            raise
        # A property of the tenant, not of the credentials — and a NetworkError
        # rather than an AuthError precisely so it cannot be mistaken for a bad
        # password.
        print("tenant has SRP disabled — falling back to password login")
        result = client.login(user, password)

    except AuthError as exc:
        if "failed to prove" not in str(exc):
            raise
        # The endpoint that answered could not prove it holds this account's
        # verifier, so it is not the server it claims to be. Do NOT retry over
        # the password path: that hands the same endpoint the plaintext it just
        # failed to prove it deserves.
        print(f"ABORTED: {exc}", file=sys.stderr)
        print(
            "Not retrying with a password — this endpoint does not hold the verifier.",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    if result.mfa_required:
        code = input("MFA code: ")
        result = client.verify_mfa(result.challenge_token, code)

    print(f"session {result.session_id}")

    # ── Enrolment ────────────────────────────────────────────────────────
    #
    # The server cannot compute a verifier — it never sees the plaintext — so
    # one has to be sent with any request that sets a password. The tenant's
    # group and KDF come from GET /api/v1/auth/me for an authenticated caller,
    # or GET /api/v1/auth/reset/context for a reset-token holder.
    srp = client.srp_enrollment(
        # The USERNAME, always. `x` is derived over `username ":" password`; a
        # user may sign in with their email, but only the username is inside
        # the KDF, so enrolling against an email produces a verifier no login
        # can satisfy.
        identity=user,
        password="the new password",
        group="rfc5054_4096",
        kdf="argon2id",
    )
    print("verifier ready to send as the request's `srp` field:", srp["group"], srp["kdf"])

    client.logout()
