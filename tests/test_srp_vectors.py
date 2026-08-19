"""CONTRACT.md §23.7 conformance: replay the cross-language SRP vectors.

``srp-test-vectors.json`` is generated from the AXIAM server implementation and
vendored into every SDK. Eleven independent SRP implementations do not
interoperate by accident; this is the file that says whether this one does.

§23.7 rule 1 requires every intermediate to be reproduced, not only the final
proof — an SDK that gets ``u`` wrong should find out at ``u`` rather than at
"login sometimes fails".
"""

from __future__ import annotations

import json
import pathlib

import pytest

from axiam_sdk._errors import NetworkError
from axiam_sdk._srp import (
    GROUPS,
    SrpClientSession,
    SrpKdf,
    _hash,
    _multiplier,
    _pad,
    argon2_available,
    compute_verifier,
    derive_x,
    generate_salt,
    parse_group,
    verify_server_proof,
)

_VECTORS = json.loads((pathlib.Path(__file__).parent.parent / "srp-test-vectors.json").read_text())[
    "vectors"
]


def _is_probable_prime(n: int) -> bool:
    """Miller-Rabin with fixed bases — deterministic, and strong at these sizes."""
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n < 2:
        return False
    for p in bases:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# ---------------------------------------------------------------------------
# §23.4 group constants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(GROUPS))
def test_every_modulus_is_a_safe_prime_of_the_advertised_width(name: str) -> None:
    """A transcription slip here is a silent, total break.

    Client and server would still agree with each other while the discrete-log
    hardness the protocol rests on quietly vanished — a round-trip test cannot
    catch it, because both sides share the same wrong constant.
    """
    group = GROUPS[name]
    assert group.n.bit_length() == group.byte_len * 8
    assert _is_probable_prime(group.n), f"{name} modulus is not prime"
    assert _is_probable_prime((group.n - 1) // 2), f"{name} is not a safe prime"
    # g generates the order-q subgroup iff g^q == N-1 for a safe prime.
    assert pow(group.g, (group.n - 1) // 2, group.n) == group.n - 1


def test_an_unknown_group_is_refused_rather_than_guessed() -> None:
    # Guessing would mean computing in a group whose safety this SDK has not
    # verified — potentially one whose discrete log the server knows.
    with pytest.raises(NetworkError, match="does not implement"):
        parse_group("rfc5054_1024")


# ---------------------------------------------------------------------------
# PAD()
# ---------------------------------------------------------------------------


def test_pad_left_pads_to_the_group_width() -> None:
    assert _pad(1, 4) == b"\x00\x00\x00\x01"
    assert _pad(0x0102, 2) == b"\x01\x02"


# ---------------------------------------------------------------------------
# §23.7 vectors
# ---------------------------------------------------------------------------


def test_the_fixtures_cover_the_cases_they_exist_for() -> None:
    # If these stop holding, everything below silently stops testing the two
    # things it was built to test.
    assert _VECTORS
    assert any(v["salt"].startswith("00") for v in _VECTORS), "no leading-zero salt"
    assert any(v["x"].startswith("00") for v in _VECTORS), "no leading-zero x"
    assert any(not v["identity"].isascii() for v in _VECTORS), "no non-ASCII identity"
    for name in ("rfc5054_2048", "rfc5054_3072", "rfc5054_4096"):
        assert any(v["group"] == name for v in _VECTORS), f"no fixture covers {name}"


@pytest.mark.parametrize(
    "vector", _VECTORS, ids=[f"{v['group']}/{v['identity']}" for v in _VECTORS]
)
def test_every_intermediate_reproduces(vector: dict[str, str]) -> None:
    group = parse_group(vector["group"])
    n = group.n
    x = int(vector["x"], 16) % n

    # k = H(N | PAD(g))
    assert _pad(_multiplier(group), 32).hex() == vector["k"]

    # v = g^x mod N
    assert compute_verifier(group, bytes.fromhex(vector["x"])) == vector["verifier"]

    # A = g^a mod N, B = (k*v + g^b) mod N
    a = int(vector["a_priv"], 16)
    b = int(vector["b_priv"], 16)
    a_pub = pow(group.g, a, n)
    assert _pad(a_pub, group.byte_len).hex() == vector["a_pub"]

    k = _multiplier(group)
    b_pub = (k * pow(group.g, x, n) + pow(group.g, b, n)) % n
    assert _pad(b_pub, group.byte_len).hex() == vector["b_pub"]

    # u = H(PAD(A) | PAD(B))
    u = int.from_bytes(_hash(_pad(a_pub, group.byte_len), _pad(b_pub, group.byte_len)), "big")
    assert _pad(u, 32).hex() == vector["u"]

    # S and K, from the client's derivation.
    kgx = (k * pow(group.g, x, n)) % n
    base = ((b_pub % n) + n - kgx) % n
    s = pow(base, a + u * x, n)
    assert _pad(s, group.byte_len).hex() == vector["session_secret"]
    assert _hash(_pad(s, group.byte_len)).hex() == vector["session_key"]


@pytest.mark.parametrize(
    "vector", _VECTORS, ids=[f"{v['group']}/{v['identity']}" for v in _VECTORS]
)
def test_the_public_api_produces_the_contract_proofs(vector: dict[str, str]) -> None:
    """Drives the real session, with ``a`` pinned to the vector's value.

    Otherwise this would only test the module-private helpers rather than the
    code path a login actually takes.
    """
    group = parse_group(vector["group"])
    session = SrpClientSession._with_fixed_ephemeral(group, vector["a_priv"])
    assert session.client_public == vector["a_pub"]

    proofs = session.finish(
        vector["identity"], vector["salt"], vector["b_pub"], bytes.fromhex(vector["x"])
    )
    assert proofs.client_proof == vector["client_proof"]
    assert proofs.expected_server_proof == vector["server_proof"]


# ---------------------------------------------------------------------------
# §23.3 refusals
# ---------------------------------------------------------------------------


def test_a_server_public_value_congruent_to_zero_is_refused() -> None:
    """The classic SRP break.

    A client that accepts B ≡ 0 derives a predictable S and would authenticate
    against a server that never knew the verifier.
    """
    session = SrpClientSession.begin(GROUPS["rfc5054_2048"])
    for b_pub in ("00", "0" * 512):
        with pytest.raises(NetworkError, match="invalid public value"):
            session.finish("alice", "ab" * 32, b_pub, b"\x01" * 32)


def test_malformed_server_input_is_an_error_rather_than_a_crash() -> None:
    session = SrpClientSession.begin(GROUPS["rfc5054_2048"])
    with pytest.raises(NetworkError):
        session.finish("alice", "ab" * 32, "zzzz", b"\x01" * 32)
    with pytest.raises(NetworkError):
        session.finish("alice", "not-hex", "abcd", b"\x01" * 32)


def test_a_fresh_ephemeral_is_used_for_every_exchange() -> None:
    first = SrpClientSession.begin(GROUPS["rfc5054_2048"])
    second = SrpClientSession.begin(GROUPS["rfc5054_2048"])
    assert first.client_public != second.client_public


def test_an_unknown_kdf_is_refused_rather_than_substituted() -> None:
    # Substituting derives a different x and surfaces as "invalid password" —
    # the single most misleading failure this code could produce.
    with pytest.raises(NetworkError, match="scrypt"):
        SrpKdf.from_wire("scrypt", 1)


def test_argon2id_requires_its_own_parameters() -> None:
    with pytest.raises(NetworkError):
        SrpKdf.from_wire("argon2id", 2, memory_kib=None, parallelism=1)
    with pytest.raises(NetworkError):
        SrpKdf.from_wire("argon2id", 2, memory_kib=19456, parallelism=None)
    assert SrpKdf.from_wire("argon2id", 2, 19456, 1).kdf == "argon2id"


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------


def test_x_binds_identity_password_and_salt() -> None:
    # Every one of these must change the output, or a verifier would be
    # replayable against a different account or a different salt.
    kdf = SrpKdf("pbkdf2_sha256", 1000)
    base = derive_x("alice", "pw", b"salt", kdf)
    assert len(base) == 32
    assert derive_x("alice", "pw", b"salt", kdf) == base
    assert derive_x("bob", "pw", b"salt", kdf) != base
    assert derive_x("alice", "pw2", b"salt", kdf) != base
    assert derive_x("alice", "pw", b"salt2", kdf) != base


def test_the_identity_separator_collides_but_the_salt_makes_it_harmless() -> None:
    """``identity ":" password`` is ambiguous, and this demonstrates it.

    ("alice", "bob:pw") and ("alice:bob", "pw") both concatenate to
    "alice:bob:pw" and derive the identical x. RFC 5054 §2.6 has the same
    property and AXIAM keeps the format, so the collision is real.

    It is not exploitable, and the reason is the salt rather than the separator:
    every credential gets 32 fresh random bytes, so two accounts never share
    one. Asserted rather than left implicit so that anyone who later changes the
    salt to something derived finds out here that they have just made this
    collision reachable.
    """
    kdf = SrpKdf("pbkdf2_sha256", 1000)
    assert derive_x("alice", "bob:pw", b"salt", kdf) == derive_x("alice:bob", "pw", b"salt", kdf)
    assert derive_x("alice", "bob:pw", b"salt-a", kdf) != derive_x(
        "alice:bob", "pw", b"salt-b", kdf
    )


@pytest.mark.skipif(not argon2_available(), reason="argon2-cffi not installed")
def test_argon2id_derives_a_32_byte_key() -> None:
    # Low memory so the test stays fast; the code path is identical to the
    # 19 MiB production parameters.
    kdf = SrpKdf("argon2id", iterations=1, memory_kib=8192, parallelism=1)
    assert len(derive_x("alice", "pw", b"saltsaltsaltsalt", kdf)) == 32


def test_argon2id_without_the_extra_names_the_install_command() -> None:
    """A tenant on AXIAM's default KDF must produce an actionable error.

    Not a silent fallback to PBKDF2: that would derive a different x and report
    "invalid password" for a password that is entirely correct.
    """
    if argon2_available():
        pytest.skip("argon2-cffi is installed; the failure path is unreachable")
    kdf = SrpKdf("argon2id", iterations=2, memory_kib=19456, parallelism=1)
    with pytest.raises(NetworkError, match=r"argon2-cffi"):
        derive_x("alice", "pw", b"salt", kdf)


# ---------------------------------------------------------------------------
# §23.3 rule 6 — server proof
# ---------------------------------------------------------------------------


def test_verify_server_proof_accepts_a_match_and_nothing_else() -> None:
    proof = _VECTORS[0]["server_proof"]
    assert verify_server_proof(proof, proof)
    assert not verify_server_proof(proof, proof[:-1] + ("b" if proof.endswith("a") else "a"))
    assert not verify_server_proof(proof, proof[:32])
    assert not verify_server_proof(proof, "")
    assert not verify_server_proof(proof, None)


def test_each_enrolment_gets_a_fresh_salt() -> None:
    # A reused salt would make every verifier in a tenant equally attackable
    # with one precomputation.
    first, second = generate_salt(), generate_salt()
    assert len(first) == 64
    assert first != second
