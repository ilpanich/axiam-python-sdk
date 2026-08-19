"""Transport-level tests for ``login_srp`` (CONTRACT.md §23).

The arithmetic is covered by ``test_srp_vectors.py`` against the shared
cross-language vectors. What is left to prove here is the *behaviour around it*:
that the password is never sent, that the server's ``M2`` is checked and a
mismatch is fatal, that a tenant with SRP disabled is distinguishable from a bad
password, and that the identity fed to the KDF comes from the server.

The fake server here computes real SRP — it derives the verifier from the same
password the test uses — so a successful exchange is a genuine one rather than a
hard-coded string that could drift from the implementation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AuthError, AxiamClient, NetworkError
from axiam_sdk._srp import GROUPS, SrpKdf, _hash, _multiplier, _pad, compute_verifier, derive_x

BASE_URL = "https://example.test"
CHALLENGE_URL = f"{BASE_URL}/api/v1/auth/srp/challenge"
VERIFY_URL = f"{BASE_URL}/api/v1/auth/srp/verify"
LOGIN_URL = f"{BASE_URL}/api/v1/auth/login"

PASSWORD = "correct horse battery staple"
USERNAME = "alice"
GROUP = GROUPS["rfc5054_2048"]
KDF = SrpKdf("pbkdf2_sha256", 1000)


def _access_token() -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "tenant_id": "tenant-uuid-1",
                    "org_id": "org-uuid-1",
                    "jti": "session-uuid-1",
                    "exp": 9999999999,
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.fake-signature"


class FakeSrpServer:
    """A server that performs the real exchange.

    Its verifier is derived from ``password``, so the only way a test passes is
    if the SDK genuinely completed SRP — not because a fixture string happened
    to match.
    """

    def __init__(self, password: str = PASSWORD, identity: str = USERNAME) -> None:
        self.identity = identity
        self.salt = secrets.token_bytes(32)
        x = derive_x(identity, password, self.salt, KDF)
        self.verifier = int(compute_verifier(GROUP, x), 16)
        self.b_priv = int.from_bytes(secrets.token_bytes(32), "big") | (1 << 255)
        self.k = _multiplier(GROUP)
        self.b_pub = (self.k * self.verifier + pow(GROUP.g, self.b_priv, GROUP.n)) % GROUP.n
        self.seen_bodies: list[dict] = []

    def challenge(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.seen_bodies.append(body)
        self.a_pub = int(body["client_public"], 16)
        return httpx.Response(
            200,
            json={
                "srp_session": "sealed-session",
                "identity": self.identity,
                "salt": self.salt.hex(),
                "group": GROUP.name,
                "kdf": KDF.kdf,
                "iterations": KDF.iterations,
                "b_pub": _pad(self.b_pub, GROUP.byte_len).hex(),
            },
        )

    def _server_proof(self, client_proof_hex: str) -> str:
        u = _hash_int_pair(self.a_pub, self.b_pub)
        s = pow((self.a_pub * pow(self.verifier, u, GROUP.n)) % GROUP.n, self.b_priv, GROUP.n)
        session_key = _hash(_pad(s, GROUP.byte_len))
        return _hash(
            _pad(self.a_pub, GROUP.byte_len), bytes.fromhex(client_proof_hex), session_key
        ).hex()

    def verify(self, request: httpx.Request, *, proof: str | None = None) -> httpx.Response:
        body = json.loads(request.content)
        self.seen_bodies.append(body)
        return httpx.Response(
            200,
            json={
                "user": {"id": "user-1"},
                "session_id": "session-uuid-1",
                "expires_in": 900,
                "server_proof": proof
                if proof is not None
                else self._server_proof(body["client_proof"]),
            },
            headers=[
                ("Set-Cookie", f"axiam_access={_access_token()}; Path=/; HttpOnly"),
                ("X-CSRF-Token", "csrf-token-1"),
            ],
        )


def _hash_int_pair(a: int, b: int) -> int:
    return int.from_bytes(
        hashlib.sha256(_pad(a, GROUP.byte_len) + _pad(b, GROUP.byte_len)).digest(), "big"
    )


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_srp_login_completes_and_never_sends_the_password(respx_mock: respx.MockRouter) -> None:
    server = FakeSrpServer()
    respx_mock.post(CHALLENGE_URL).mock(side_effect=server.challenge)
    respx_mock.post(VERIFY_URL).mock(side_effect=server.verify)

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        result = client.login_srp(USERNAME, PASSWORD)

    assert result.mfa_required is False
    assert result.session_id == "session-uuid-1"

    # The point of the whole exercise: nothing that went out carried the
    # password, in any field.
    for body in server.seen_bodies:
        assert PASSWORD not in json.dumps(body)
        assert "password" not in body


@pytest.mark.asyncio
async def test_async_srp_login_completes(respx_mock: respx.MockRouter) -> None:
    server = FakeSrpServer()
    respx_mock.post(CHALLENGE_URL).mock(side_effect=server.challenge)
    respx_mock.post(VERIFY_URL).mock(side_effect=server.verify)

    async with AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        result = await client.login_srp(USERNAME, PASSWORD)

    assert result.mfa_required is False


def test_the_identity_used_is_the_servers_not_the_typed_one(
    respx_mock: respx.MockRouter,
) -> None:
    """§23.3 rule 2.

    A user signs in with their email; the verifier is bound to their username.
    An SDK that fed the typed value to the KDF would derive a different ``x``
    and fail — so this passing is the proof it uses the server's answer.
    """
    server = FakeSrpServer(identity=USERNAME)
    respx_mock.post(CHALLENGE_URL).mock(side_effect=server.challenge)
    respx_mock.post(VERIFY_URL).mock(side_effect=server.verify)

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        result = client.login_srp("alice@example.com", PASSWORD)

    assert result.mfa_required is False


# ---------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------


def test_a_wrong_password_is_an_auth_error(respx_mock: respx.MockRouter) -> None:
    server = FakeSrpServer()
    respx_mock.post(CHALLENGE_URL).mock(side_effect=server.challenge)
    respx_mock.post(VERIFY_URL).mock(
        return_value=httpx.Response(401, json={"error": "authentication_failed"})
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(AuthError):
            client.login_srp(USERNAME, "wrong password")


def test_a_server_that_cannot_prove_itself_is_refused(respx_mock: respx.MockRouter) -> None:
    """§23.3 rule 6.

    A wrong ``M2`` means the endpoint does not hold this account's verifier, so
    it is not the server it claims to be. The session it offered must be
    refused rather than used — otherwise the client has proved itself to the
    server without the server proving itself to the client, which is half the
    protocol.
    """
    server = FakeSrpServer()
    respx_mock.post(CHALLENGE_URL).mock(side_effect=server.challenge)
    respx_mock.post(VERIFY_URL).mock(
        side_effect=lambda request: server.verify(request, proof="00" * 32)
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(AuthError, match="failed to prove"):
            client.login_srp(USERNAME, PASSWORD)


def test_a_missing_server_proof_is_refused(respx_mock: respx.MockRouter) -> None:
    # An older or partial server that omits the field entirely must not be
    # treated as having proved itself.
    server = FakeSrpServer()
    respx_mock.post(CHALLENGE_URL).mock(side_effect=server.challenge)
    respx_mock.post(VERIFY_URL).mock(
        return_value=httpx.Response(
            200, json={"user": {"id": "user-1"}, "session_id": "s", "expires_in": 900}
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(AuthError, match="failed to prove"):
            client.login_srp(USERNAME, PASSWORD)


def test_srp_disabled_is_a_network_error_a_caller_can_fall_back_on(
    respx_mock: respx.MockRouter,
) -> None:
    """A 404 is a property of the tenant, not of the credentials.

    NetworkError rather than AuthError so an application can fall back to
    ``login()`` — and so a user is never shown "invalid password" for a password
    that is perfectly good.
    """
    respx_mock.post(CHALLENGE_URL).mock(return_value=httpx.Response(404))

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(NetworkError, match="does not offer Secure Remote Password"):
            client.login_srp(USERNAME, PASSWORD)


def test_an_unimplemented_group_is_refused_rather_than_guessed(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post(CHALLENGE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "srp_session": "s",
                "identity": USERNAME,
                "salt": "ab" * 32,
                "group": "rfc5054_1024",
                "kdf": "pbkdf2_sha256",
                "iterations": 1000,
                "b_pub": "ab" * 128,
            },
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(NetworkError, match="does not implement"):
            client.login_srp(USERNAME, PASSWORD)


# ---------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------


def test_srp_enrollment_produces_a_well_formed_body() -> None:
    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        body = client.srp_enrollment(
            USERNAME, PASSWORD, group="rfc5054_2048", kdf="pbkdf2_sha256", iterations=1000
        )

    assert body["group"] == "rfc5054_2048"
    assert body["kdf"] == "pbkdf2_sha256"
    assert len(body["salt"]) == 64
    assert len(body["verifier"]) == 512  # padded to the 2048-bit group width
    # PBKDF2 carries no argon2 parameters.
    assert "memory_kib" not in body
    assert "parallelism" not in body


def test_each_enrolment_gets_a_fresh_salt_and_verifier() -> None:
    # A reused salt would make every verifier in a tenant equally attackable
    # with a single precomputation.
    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        first = client.srp_enrollment(USERNAME, PASSWORD, kdf="pbkdf2_sha256", iterations=1000)
        second = client.srp_enrollment(USERNAME, PASSWORD, kdf="pbkdf2_sha256", iterations=1000)
    assert first["salt"] != second["salt"]
    assert first["verifier"] != second["verifier"]


def test_srp_available_is_true_for_python() -> None:
    # Python has arbitrary-precision ints and hashlib; unlike PHP, nothing here
    # is conditional on an extension being compiled in.
    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        assert client.srp_available() is True
