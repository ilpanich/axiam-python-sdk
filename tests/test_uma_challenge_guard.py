"""The §20.3 emit half, wired into the §11 guards (FastAPI and Django).

``uma_challenge=`` turns a denial from a bare 403 into a 403 that tells the
caller where to obtain authority. Everything asserted here is about the *deny*
path, because that is the only path that mints anything:

1. A denial with a challenger mints exactly one ticket and emits it.
2. An allow mints nothing — a guard that minted on the happy path would put a
   Protection API call in front of every authorized request.
3. A minting failure still denies, without a challenge. An outage must not turn
   a deny into a 500, and must never turn it into an allow.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from axiam_sdk import AsyncAxiamClient, UmaChallenger, uma_parse_challenge
from axiam_sdk._jwks import JwksVerifier
from axiam_sdk.fastapi import AxiamUser, require_access

BASE_URL = "https://axiam-uma-guard.example.test"
CHECK_URL = f"{BASE_URL}/api/v1/authz/check"
PERM_URL = f"{BASE_URL}/uma2/perm"
RESOURCE_ID = "99999999-8888-7777-6666-555555555555"
PAT = "pat-token-value"
TICKET = "ticket-value"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _keypair(kid: str) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    private_key = Ed25519PrivateKey.generate()
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw_public),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }


@pytest.fixture
def eddsa_keypair() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    return _keypair("test-kid-1")


@pytest.fixture
def verifier(eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]]) -> JwksVerifier:
    _private_key, jwk_dict = eddsa_keypair
    v = JwksVerifier(BASE_URL)
    v._client.fetch_data = lambda: {"keys": [jwk_dict]}  # type: ignore[method-assign]
    return v


def _token(private_key: Ed25519PrivateKey) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    claims = {"sub": "user-1", "tenant_id": "acme", "exp": time.time() + 3600}
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": "test-kid-1"})


def _app(
    verifier: JwksVerifier,
    client: AsyncAxiamClient,
    action: str = "invoices:read",
    challenger: UmaChallenger | None = None,
) -> FastAPI:
    app = FastAPI()
    dependency = require_access(
        verifier, "acme", client, action, resource_param="doc_id", uma_challenge=challenger
    )

    @app.get("/docs/{doc_id}")
    async def get_doc(
        doc_id: str,
        user: AxiamUser = Depends(dependency),  # noqa: B008
    ) -> dict[str, object]:
        return {"user_id": user.user_id, "doc_id": doc_id}

    return app


def _challenger(client: AsyncAxiamClient) -> UmaChallenger:
    return UmaChallenger(
        realm="invoices", as_uri="https://id.example", pat=SecretStr(PAT), client=client
    )


def test_a_denial_mints_one_ticket_and_emits_the_challenge(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"allowed": False, "reason": "no matching grant"})
    )
    perm = respx_mock.post(PERM_URL).mock(return_value=httpx.Response(201, json={"ticket": TICKET}))
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    test_client = TestClient(_app(verifier, client, challenger=_challenger(client)))

    response = test_client.get(
        f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {_token(private_key)}"}
    )

    assert response.status_code == 403, "the challenge is additive, not a redirect"
    assert perm.call_count == 1, "one ticket, not two"

    # The emitted header is the one the consuming half parses — the round trip is
    # the point of shipping both halves.
    parsed = uma_parse_challenge(response.headers["WWW-Authenticate"])
    assert parsed is not None
    assert parsed.realm == "invoices"
    assert parsed.as_uri == "https://id.example"
    assert parsed.ticket is not None
    assert parsed.ticket.get_secret_value() == TICKET


def test_the_ticket_asks_for_the_action_that_was_refused(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(CHECK_URL).mock(return_value=httpx.Response(200, json={"allowed": False}))
    perm = respx_mock.post(PERM_URL).mock(return_value=httpx.Response(201, json={"ticket": TICKET}))
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    test_client = TestClient(
        _app(verifier, client, action="invoices:approve", challenger=_challenger(client))
    )

    test_client.get(
        f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {_token(private_key)}"}
    )

    # §20.2: the UMA scope is the AXIAM *action*. Asking for anything else would
    # mint a ticket for authority other than the one just refused — and would
    # break the deny-override property the server relies on.
    import json

    body = json.loads(perm.calls[0].request.content)
    assert body == [{"resource_id": RESOURCE_ID, "resource_scopes": ["invoices:approve"]}]


def test_an_allow_mints_nothing(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(CHECK_URL).mock(return_value=httpx.Response(200, json={"allowed": True}))
    perm = respx_mock.post(PERM_URL).mock(return_value=httpx.Response(201, json={"ticket": TICKET}))
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    test_client = TestClient(_app(verifier, client, challenger=_challenger(client)))

    response = test_client.get(
        f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {_token(private_key)}"}
    )

    assert response.status_code == 200
    # A guard that minted on the happy path would put a Protection API call — and
    # a live credential — in front of every authorized request.
    assert perm.call_count == 0


def test_a_minting_failure_still_denies_without_a_challenge(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(CHECK_URL).mock(return_value=httpx.Response(200, json={"allowed": False}))
    perm = respx_mock.post(PERM_URL).mock(return_value=httpx.Response(500))
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    test_client = TestClient(_app(verifier, client, challenger=_challenger(client)))

    response = test_client.get(
        f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {_token(private_key)}"}
    )

    # Failure is not escalation: the caller was going to be refused, and a
    # Protection API outage must not turn that into a 500 — nor into an allow.
    assert response.status_code == 403
    assert "WWW-Authenticate" not in response.headers
    assert perm.call_count >= 1


def test_without_a_challenger_a_denial_is_the_plain_403_it_always_was(
    eddsa_keypair: tuple[Ed25519PrivateKey, dict[str, Any]],
    verifier: JwksVerifier,
    respx_mock: respx.MockRouter,
) -> None:
    private_key, _jwk = eddsa_keypair
    respx_mock.post(CHECK_URL).mock(return_value=httpx.Response(200, json={"allowed": False}))
    perm = respx_mock.post(PERM_URL).mock(return_value=httpx.Response(201, json={"ticket": TICKET}))
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    test_client = TestClient(_app(verifier, client))

    response = test_client.get(
        f"/docs/{RESOURCE_ID}", headers={"Authorization": f"Bearer {_token(private_key)}"}
    )

    # Opt-in means opt-in: an application that never asked for UMA semantics gets
    # no Protection API traffic from its guards.
    assert response.status_code == 403
    assert "WWW-Authenticate" not in response.headers
    assert perm.call_count == 0


def test_the_challenger_never_renders_its_pat() -> None:
    """§7: a challenger is configuration an application may reasonably log, and
    the PAT inside it is not."""
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    rendered = repr(_challenger(client))
    assert PAT not in rendered
    assert "invoices" in rendered
