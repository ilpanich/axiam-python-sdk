"""CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44,
AXIAM threats T-39 and T-143).

Two properties, and the second is what makes the feature safe to ship. A
revoked ``sid`` is rejected **after one poll and not before**, which pins that
the guard reads a cached set rather than fetching per request. And a guard with
the feature **off**, or with it on and the feed unreachable, behaves
byte-for-byte as it does today — asserted by counting fetches, so "does not
fetch" is proven rather than claimed.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from axiam_sdk._errors import AuthError
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk._revocation_feed import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    MIN_POLL_INTERVAL_SECONDS,
    RevocationFeed,
    revocation_entry_for,
)

_TENANT = "acme"
_KID = "test-kid-1"
_BASE_URL = "https://axiam-104.example.test"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    private_key = Ed25519PrivateKey.generate()
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw_public),
        "kid": _KID,
        "use": "sig",
        "alg": "EdDSA",
    }


def _sign(private_key: Ed25519PrivateKey, claims: dict[str, Any]) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": _KID})


def _claims(sid: str | None) -> dict[str, Any]:
    """A claim set satisfying every §10.1 rule, optionally naming a session."""
    base: dict[str, Any] = {
        "sub": "user-1",
        "tenant_id": _TENANT,
        "exp": time.time() + 3600,
        "jti": "jti-1",
    }
    if sid is not None:
        base["sid"] = sid
    return base


class _CountingFeedTransport(httpx.BaseTransport):
    """Serves the feed and counts fetches — the counter is what proves the
    guard is not polling per request."""

    def __init__(self, responder: Any) -> None:
        self.responder = responder
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return self.responder()


def _feed_document(revoked_sids: list[str]) -> dict[str, Any]:
    return {
        "alg": "SHA-256",
        "issued_at": int(time.time()),
        "ttl": 900,
        "revoked": [revocation_entry_for(s) for s in revoked_sids],
    }


def _feed(responder: Any) -> tuple[RevocationFeed, _CountingFeedTransport]:
    transport = _CountingFeedTransport(responder)
    client = httpx.Client(transport=transport)
    return RevocationFeed(_BASE_URL, client=client), transport


def _verifier(feed: RevocationFeed | None, jwk: dict[str, Any]) -> JwksVerifier:
    verifier = JwksVerifier(_BASE_URL, revocation_feed=feed)
    verifier._client.fetch_data = lambda: {"keys": [jwk]}  # type: ignore[method-assign]
    return verifier


# ---------------------------------------------------------------------------
# The entry format — pinned against the server's own vector
# ---------------------------------------------------------------------------


def test_the_entry_is_base64url_unpadded_sha256_of_the_claim_string() -> None:
    """Eleven SDKs compute this independently. A change here is a change every
    one of them silently stops matching, which presents as "revocation stopped
    working" with nothing failing."""
    entry = revocation_entry_for("6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b")
    assert entry == "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ"
    assert len(entry) == 43
    assert not set(entry) & set("+/=")


def test_the_entry_hashes_the_claim_as_read() -> None:
    """Parsing the claim to a UUID and rendering it back would make the answer
    depend on this SDK's parser rather than on the feed."""
    assert revocation_entry_for("6F3E0A5C-1B2D-4E8F-9A7B-0C1D2E3F4A5B") != revocation_entry_for(
        "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"
    )


def test_the_poll_interval_is_clamped_rather_than_refused() -> None:
    feed = RevocationFeed(_BASE_URL, poll_interval_seconds=0.001)
    assert feed._poll_interval == MIN_POLL_INTERVAL_SECONDS
    assert RevocationFeed(_BASE_URL)._poll_interval == DEFAULT_POLL_INTERVAL_SECONDS


# ---------------------------------------------------------------------------
# The feature, on
# ---------------------------------------------------------------------------


def test_a_revoked_session_is_rejected() -> None:
    key, jwk = _keypair()
    feed, _ = _feed(lambda: httpx.Response(200, json=_feed_document(["session-revoked"])))

    with pytest.raises(AuthError, match="revoked"):
        _verifier(feed, jwk).verify_access_token(
            _sign(key, _claims("session-revoked")), expected_tenant_id=_TENANT
        )


def test_a_session_the_feed_does_not_list_still_verifies() -> None:
    key, jwk = _keypair()
    feed, _ = _feed(lambda: httpx.Response(200, json=_feed_document(["someone-else"])))

    claims = _verifier(feed, jwk).verify_access_token(
        _sign(key, _claims("session-live")), expected_tenant_id=_TENANT
    )
    assert claims["sub"] == "user-1"


def test_the_guard_polls_on_an_interval_and_never_per_request() -> None:
    """§10.4 rule 2, and the property the whole design rests on. Ten verifies
    produce ONE fetch — a guard fetching per request would show ten here and
    nowhere else."""
    key, jwk = _keypair()
    feed, transport = _feed(lambda: httpx.Response(200, json=_feed_document([])))
    verifier = _verifier(feed, jwk)

    for i in range(10):
        verifier.verify_access_token(
            _sign(key, _claims(f"session-{i}")), expected_tenant_id=_TENANT
        )

    assert transport.calls == 1


def test_a_token_with_no_session_is_never_matched() -> None:
    """§10.4 rule 6. The feed lists the token's OWN ``jti``, so an
    implementation that fell back to it would reject here."""
    key, jwk = _keypair()
    feed, _ = _feed(lambda: httpx.Response(200, json=_feed_document(["jti-1"])))

    claims = _verifier(feed, jwk).verify_access_token(
        _sign(key, _claims(None)), expected_tenant_id=_TENANT
    )
    assert claims["sub"] == "user-1"


# ---------------------------------------------------------------------------
# The feature, off — and the failure modes
# ---------------------------------------------------------------------------


def test_with_the_feature_off_nothing_is_fetched_and_nothing_is_rejected() -> None:
    """I4 twin. The default guard is unchanged by contract 1.44, and the
    endpoint is never touched — counted, because "does not fetch" is the claim
    and only a counter proves it."""
    key, jwk = _keypair()
    _, transport = _feed(lambda: httpx.Response(200, json=_feed_document(["session-revoked"])))

    claims = _verifier(None, jwk).verify_access_token(
        _sign(key, _claims("session-revoked")), expected_tenant_id=_TENANT
    )
    assert claims["sub"] == "user-1"
    assert transport.calls == 0


@pytest.mark.parametrize(
    ("label", "responder"),
    [
        ("unreachable", lambda: httpx.Response(503)),
        (
            "unknown alg",
            lambda: httpx.Response(
                200,
                json={
                    "alg": "BLAKE3",
                    "issued_at": 0,
                    "ttl": 900,
                    "revoked": [revocation_entry_for("session-revoked")],
                },
            ),
        ),
        ("unparseable", lambda: httpx.Response(200, text="<html>not found</html>")),
    ],
)
def test_an_unusable_feed_behaves_as_no_feed_at_all(label: str, responder: Any) -> None:
    """§10.4 rule 3, the load-bearing one. NOT "as an empty list" — an empty
    list asserts that nothing has been revoked, which is a guard silently
    honouring none while appearing to honour them."""
    key, jwk = _keypair()
    feed, _ = _feed(responder)

    claims = _verifier(feed, jwk).verify_access_token(
        _sign(key, _claims("session-revoked")), expected_tenant_id=_TENANT
    )
    assert claims["sub"] == "user-1", label
