"""PKCE + CSPRNG primitives for the OIDC relying-party flow (CONTRACT.md
§12.1 "``oidc_begin`` inputs and construction", RFC 7636).

The stdlib's :mod:`secrets`, :mod:`hashlib`, and :mod:`base64` cover
everything needed — CSPRNG, SHA-256, and base64url — so this module adds NO
new runtime dependency (port-brief-addendum "CI gates" section, criterion 4).
Deliberately tiny, pure, and synchronous: ``oidc_begin`` performs no network
I/O (CONTRACT.md §12.1), and every value here is derived locally.

**S256 only.** ``plain`` is not implemented, not reachable, and not
configurable: there is no code path in this SDK that can emit
``code_challenge_method=plain`` (mirrors ``the TypeScript SDK's
src/node/oidcPkce.ts``).
"""

from __future__ import annotations

import base64
import hashlib
import secrets

#: The only PKCE code-challenge method this SDK emits (RFC 7636 §4.2,
#: CONTRACT.md §12.1 rule 3). ``plain`` is intentionally absent.
CODE_CHALLENGE_METHOD_S256 = "S256"

#: Entropy, in bytes, of a generated ``state``/``nonce``/``code_verifier``.
#:
#: CONTRACT.md §12.1 rule 1 requires at least 16 bytes (128 bits) and
#: RECOMMENDS 32; rule 2 RECOMMENDS 32 bytes for the verifier, which
#: base64url-encodes to exactly 43 characters — the minimum RFC 7636 §4.1
#: length, drawn only from the unreserved set ``[A-Za-z0-9-._~]``.
CSPRNG_BYTES = 32


def random_url_safe_token(num_bytes: int = CSPRNG_BYTES) -> str:
    """Generate a URL-safe random token: ``num_bytes`` CSPRNG bytes,
    base64url-encoded **without** padding (RFC 4648 §5).

    Used for both ``state`` and ``nonce``, which CONTRACT.md §12.3 rule 2
    classes as **non-secret**: they are returned as plain strings, are
    echoed through the browser's address bar by construction, and are safe
    to log.
    """
    raw = secrets.token_bytes(num_bytes)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_code_verifier() -> str:
    """Generate a fresh PKCE ``code_verifier`` (RFC 7636 §4.1): 32 CSPRNG
    bytes base64url-encoded without padding, i.e. 43 characters from the
    unreserved set.

    The caller is responsible for wrapping the result in the SDK's
    ``Sensitive`` equivalent (``pydantic.SecretStr``) — CONTRACT.md §12.5
    makes the verifier secret **for its whole lifetime**, including while it
    sits in the :class:`~axiam_sdk._models.AuthorizationRequest` handed back
    to the caller and in any ``OidcStateStore`` entry.
    """
    return random_url_safe_token(CSPRNG_BYTES)


def compute_code_challenge(code_verifier: str) -> str:
    """Derive the PKCE ``code_challenge`` from a verifier:
    ``BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))``, unpadded
    (RFC 7636 §4.2, CONTRACT.md §12.1 rule 3).

    The verifier is hashed as ASCII exactly as the RFC specifies. Every SDK
    MUST include the RFC 7636 Appendix B test vector as a unit test
    (verifier ``dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`` -> challenge
    ``E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM``).

    The challenge is a one-way digest and is **not** secret — it travels in
    the authorization URL — so it is returned as a plain string.
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
