"""AMQP HMAC-SHA256 verification (CONTRACT.md §8).

Port of the canonical protocol implemented by the Rust server in
``crates/axiam-amqp/src/messages.rs`` (``sign_payload``/``verify_payload``).
This module cannot import that crate (the SDK MUST NOT depend on server
crates), so the algorithm is reimplemented here and proven correct against a
real server-signed fixture in ``tests/test_amqp_hmac.py`` (Assumption A2 /
Pitfall 2 -- see 19-RESEARCH.md).

**Verify the received bytes, dispatch the same bytes (server #882, D-5).** The
server writes ``hmac_signature`` as the *last* member of the wire JSON and signs
the bytes that precede it. The canonical bytes are therefore the delivery body
with that trailing ``,"hmac_signature":"<64 hex>"`` member cut out of the
closing brace -- never a re-serialization of a parsed message. Re-serializing
fails a genuine message whenever this SDK's encoder and ``serde_json`` disagree
(``json.dumps`` escapes every non-ASCII character by default), and it lets a
handler be given a different parse than the one that was verified (C2: a
duplicate key collapses in ``json.loads`` and vanishes on re-serialization).
The value handed to a caller is parsed from the verified canonical bytes, with
duplicate and case-variant keys refused.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

#: The member the server appends last: ``,"hmac_signature":"`` + 64 hex digits + ``"`` + ``}``.
SIGNATURE_MEMBER = b',"hmac_signature":"'
SIGNATURE_HEX_LENGTH = 64
SIGNATURE_TAIL = b'"}'
_HEX64 = re.compile(rb"[0-9a-fA-F]{64}")


def cut_trailing_signature(body: bytes) -> tuple[bytes, bytes] | None:
    """Remove the final ``,"hmac_signature":"<64 hex>"`` member from ``body``.

    Returns ``(canonical, signature_hex)`` -- ``canonical`` being the rest closed with ``}`` --
    or ``None`` when ``body`` does not end in exactly that member. Never repaired by
    re-serializing.
    """
    suffix_length = len(SIGNATURE_MEMBER) + SIGNATURE_HEX_LENGTH + len(SIGNATURE_TAIL)
    if len(body) <= suffix_length or not body.endswith(SIGNATURE_TAIL):
        return None
    start = len(body) - suffix_length
    if body[start : start + len(SIGNATURE_MEMBER)] != SIGNATURE_MEMBER:
        return None
    signature = body[start + len(SIGNATURE_MEMBER) : len(body) - len(SIGNATURE_TAIL)]
    if _HEX64.fullmatch(signature) is None:
        return None
    return body[:start] + b"}", signature


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that refuses an object with a repeated key."""
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("a duplicate key")
        seen[key] = value
    return seen


def strict_json_object(raw: bytes) -> dict[str, Any]:
    """Parse ``raw`` as exactly one JSON object with unambiguous keys.

    Refuses trailing content (whitespace included: nothing may follow the closing brace), a
    duplicate key at any depth, and two top-level keys that are equal under Unicode case folding
    (a decoder that matches keys case-insensitively would otherwise read a different message from
    the same bytes).

    Raises:
        ValueError: ``raw`` is not such an object. The message names the fact, never a value.
    """
    try:
        text = raw.decode("utf-8")
        if text[-1:] in (" ", "\t", "\n", "\r"):
            raise ValueError("trailing whitespace")
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as exc:
        raise ValueError("the body is not a JSON object") from exc
    except ValueError as exc:  # JSONDecodeError, UnicodeDecodeError, the duplicate-key refusal
        if str(exc) == "a duplicate key":
            raise
        raise ValueError("the body is not a JSON object") from exc
    if not isinstance(parsed, dict):
        raise ValueError("the body is not a JSON object")
    if len({key.casefold() for key in parsed}) != len(parsed):
        raise ValueError("keys that differ only by case")
    return parsed


def verify_and_decode(signing_key: bytes, body: bytes) -> dict[str, Any] | None:
    """Verify ``body`` and return the message parsed from the verified bytes.

    The signature is HMAC-SHA256 over ``body`` with its trailing ``hmac_signature`` member cut
    out (see the module docstring), compared in constant time. The returned object is parsed
    from those same canonical bytes -- it never contains ``hmac_signature`` -- so the caller acts
    on exactly what was verified.

    Returns ``None`` (never raises) for: a body that does not end in the signature member, a
    non-hex or wrong-length signature, a wrong key or tampered body, trailing content, a body
    that is not one JSON object, and a duplicate or case-variant key. The signature and the
    computed digest are never logged or returned (T-19-03).
    """
    cut = cut_trailing_signature(body)
    if cut is None:
        return None
    canonical, signature = cut
    computed = hmac.new(signing_key, canonical, hashlib.sha256).digest()
    if not hmac.compare_digest(computed, bytes.fromhex(signature.decode("ascii"))):
        return None
    try:
        return strict_json_object(canonical)
    except ValueError:
        return None


def verify_hmac(signing_key: bytes, body: bytes) -> bool:
    """Verify an HMAC-SHA256 signature over an AMQP message body.

    ``True`` only if :func:`verify_and_decode` accepts ``body``: the HMAC over the received bytes
    (trailing ``hmac_signature`` member removed, no re-serialization) matches, and those bytes
    are one JSON object with no duplicate key. Never raises. Callers that go on to use the
    message MUST use :func:`verify_and_decode` and act on the object it returns, not parse
    ``body`` a second time.
    """
    return verify_and_decode(signing_key, body) is not None
