"""Enforcing CONTRACT.md §10.1 rule 9 in a resource server — the full rule,
covering certificate-bound (RFC 8705) and DPoP-bound (RFC 9449) tokens.

Run with::

    python examples/sender_constrained_guard.py

What rule 9 actually says
-------------------------

A token carrying ``cnf`` is **not** a bearer token. Accepting one without
proving the caller holds the confirmed key converts it back into a bearer token
and discards the whole protection the operator turned on.

Three cases are worth internalising, because they are the ones implemented
wrongly:

1. **An unbound token is still accepted** — no certificate, no proof. Rule 9 is
   not "require evidence from everybody".
2. **A ``cnf`` naming both methods is a conjunction.** Two constraints means
   two; satisfying the more convenient one is not compliance.
3. **A ``cnf`` this SDK cannot interpret is refused**, never read as
   unconstrained — including an *empty* one.
"""

from __future__ import annotations

import os

from axiam_sdk._errors import AuthError
from axiam_sdk._jwks import (
    JwksVerifier,
    certificate_thumbprint_s256,
    verify_token_binding,
)


def verified_dpop_thumbprint(request: object) -> str | None:
    """The ``jkt`` of a DPoP proof you have **already verified** against this
    request's method, URI, ``iat`` and ``jti``.

    Returning a thumbprint here asserts the proof checked out. Lifting it off
    an unverified proof would let a proof captured from any other endpoint
    authorize this one — which is why this is a separate, deliberate step
    rather than something the SDK reads out of a header for you.
    """
    return None


def guard(request: object, token: str) -> str:
    """Authorize one request, applying rules 1-9."""
    verifier = JwksVerifier(os.environ.get("AXIAM_BASE_URL", "https://axiam.example.com"))

    # Rules 1-8: signature, expiry, issuer, audience. NOT rule 9 — this call
    # has no transport to ask, which is exactly why the binding check is
    # separate rather than something you can forget to opt into.
    claims = verifier.verify_access_token(token, expected_tenant_id=os.environ["AXIAM_TENANT_ID"])

    # The thumbprint must come from the connection, never a header the caller
    # can set: a forgeable input makes the mechanism decorative.
    peer_der = getattr(request, "peer_certificate_der", None)
    certificate_thumbprint = certificate_thumbprint_s256(peer_der) if peer_der is not None else None

    # Rule 9. Returns immediately for an unbound token, so adopting this does
    # not break existing deployments.
    verify_token_binding(
        claims,
        certificate_thumbprint=certificate_thumbprint,
        dpop_thumbprint=verified_dpop_thumbprint(request),
    )

    return str(claims["sub"])


if __name__ == "__main__":
    try:
        print(guard(object(), "…the access token from the Authorization header…"))
    except AuthError as exc:
        print(f"refused: {exc}")
