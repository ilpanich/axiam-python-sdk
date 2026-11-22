"""Identity members read from verified access-token claims (CONTRACT.md §10, §11.2).

Shared by the FastAPI dependency and the Django middleware, which stay mutually independent
optional extras and so import this neutral module rather than each other.

Contract 1.68 (N15, D-1): the identity's ``roles`` are the token's ``roles`` claim and nothing
else. The ``scope`` claim names what the *client* asked for, not what the user holds, so it is
never mapped onto roles; the granted scopes are a separate member (``scopes``) that
``require_scope`` checks.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def roles_from_claims(claims: Mapping[str, Any]) -> list[str] | None:
    """The ``roles`` claim as a list of role names, or ``None`` when the claim is absent, ``null``
    or is not a JSON array of strings (§11.2 rule 11 (b)): every ``require_role`` then fails
    closed. An empty array ``[]`` is returned as ``[]`` — "the scope was granted and the user
    holds no role" — and callers keep it distinguishable from ``None`` (``roles_claim_present``)."""
    value = claims.get("roles")
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


def scopes_from_claims(claims: Mapping[str, Any]) -> list[str]:
    """The ``scope`` claim split on single spaces (RFC 6749 §3.3); empty when it is absent,
    ``null`` or not a string (§11.2 rule 11 (d))."""
    value = claims.get("scope")
    if isinstance(value, str):
        return [scope for scope in value.split(" ") if scope]
    return []
