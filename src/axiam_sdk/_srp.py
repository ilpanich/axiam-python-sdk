"""SRP-6a client — CONTRACT.md §23.

Protocol only: no HTTP, no client, no session. That half has to agree
byte-for-byte with ten other language implementations, and keeping it free of
transport is what lets it be checked directly against the vendored
``srp-test-vectors.json`` with no server and no mock.

What SRP buys, and what it does not
-----------------------------------

The password never leaves this process. What crosses the wire is ``A`` and a
proof, neither of which is useful to anyone who does not already hold the
account's verifier — so a TLS-terminating proxy, an accidentally verbose request
log, or a heap dump on the server can no longer capture a plaintext password,
because the server never has one.

It does **not** protect against a compromised AXIAM server. Nothing in this
module's documentation, or in the SDK's README, may claim otherwise.

Runtime requirements
--------------------

Only the standard library: Python's ``int`` is arbitrary-precision, ``pow`` does
modular exponentiation, and ``hashlib`` supplies SHA-256 and PBKDF2. Argon2id
comes from ``argon2-cffi`` when installed; without it, a tenant on
``argon2id`` — AXIAM's default — raises :class:`NetworkError` naming the KDF,
per §23.3 rule 4, rather than silently substituting PBKDF2 and deriving a
different ``x``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Final

from ._errors import NetworkError

# ---------------------------------------------------------------------------
# Groups (RFC 5054 Appendix A)
# ---------------------------------------------------------------------------
#
# Embedded as constants and never taken from the server. A server-supplied
# modulus is a server-supplied trapdoor: a hostile server could hand over a
# group whose discrete logarithm it knows and recover ``x`` — and therefore the
# password — from the exchange. §23.4 makes embedding these mandatory.
#
# A transcription slip here is a silent, total break: client and server would
# still agree with each other while the hardness assumption the whole protocol
# rests on quietly vanished, and a round-trip test could not catch it because
# both sides share the same wrong value. ``test_srp_vectors.py`` therefore
# asserts each modulus is the advertised width, prime, a safe prime, and that
# ``g`` generates the large subgroup.

_N_2048: Final = int(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
    16,
)

_N_3072: Final = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)

_N_4096: Final = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
    16,
)


@dataclass(frozen=True)
class SrpGroup:
    """One RFC 5054 Appendix A safe-prime group."""

    name: str
    n: int
    g: int
    byte_len: int


GROUPS: Final[dict[str, SrpGroup]] = {
    "rfc5054_2048": SrpGroup("rfc5054_2048", _N_2048, 2, 256),
    "rfc5054_3072": SrpGroup("rfc5054_3072", _N_3072, 5, 384),
    "rfc5054_4096": SrpGroup("rfc5054_4096", _N_4096, 5, 512),
}

#: AXIAM's default group, and the one an exchange opens in before the server
#: has named one.
DEFAULT_GROUP: Final = "rfc5054_4096"


def parse_group(name: str) -> SrpGroup:
    """Look up a group by its wire name.

    An unrecognised name is refused rather than guessed at (§23.4): the
    alternative is computing in a group whose safety this SDK has not verified.

    :raises NetworkError: for an unknown group. ``NetworkError`` rather than
        ``AuthError`` per §23.3 rule 4 — this is a client-side capability gap,
        and calling it an authentication failure would send a user off to reset
        a password that works.
    """
    group = GROUPS.get(name)
    if group is None:
        raise NetworkError(
            f"this SDK does not implement the SRP group this tenant requires ({name})"
        )
    return group


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def _pad(value: int, byte_len: int) -> bytes:
    """``PAD(x)``: big-endian bytes, left-padded with zeros to the group width.

    Every hash input in SRP-6a is padded to the modulus width. Skipping it is
    *the* SRP interop bug — two implementations agree until a value happens to
    carry a leading zero byte, and then roughly one login in 256 fails in a way
    that reads as a flaky network rather than a defect. The vendored vectors are
    built with a leading-zero salt and ``x`` specifically to catch it.
    """
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if len(raw) >= byte_len:
        return raw
    return b"\x00" * (byte_len - len(raw)) + raw


def _hash(*parts: bytes) -> bytes:
    """SHA-256 over the concatenation of *parts* (§23.3: SHA-256 throughout)."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def _hash_int(*parts: bytes) -> int:
    """:func:`_hash`, read back as a big-endian integer."""
    return int.from_bytes(_hash(*parts), "big")


def _multiplier(group: SrpGroup) -> int:
    """``k = H(N | PAD(g))`` — depends only on the group."""
    return _hash_int(_pad(group.n, group.byte_len), _pad(group.g, group.byte_len))


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SrpKdf:
    """The KDF and cost parameters a challenge named."""

    kdf: str
    iterations: int
    memory_kib: int | None = None
    parallelism: int | None = None

    @classmethod
    def from_wire(
        cls,
        kdf: str,
        iterations: int,
        memory_kib: int | None = None,
        parallelism: int | None = None,
    ) -> SrpKdf:
        """Build from a challenge response, refusing anything unimplemented.

        :raises NetworkError: for an unknown KDF, or for ``argon2id`` without
            its own parameters.
        """
        if kdf == "argon2id":
            if memory_kib is None or parallelism is None:
                raise NetworkError(
                    "SRP challenge named argon2id but carried no memory cost or parallelism"
                )
            return cls(kdf, iterations, memory_kib, parallelism)
        if kdf == "pbkdf2_sha256":
            return cls(kdf, iterations)
        raise NetworkError(
            f"this SDK cannot perform the key-derivation function this tenant requires ({kdf})"
        )


def argon2_available() -> bool:
    """Whether Argon2id can be performed in this environment.

    ``argon2-cffi`` is an extra rather than a hard dependency: it carries a
    compiled wheel, and a consumer whose tenant uses ``pbkdf2_sha256`` — or who
    never calls SRP — should not be made to install one. Install it with
    ``pip install axiam-sdk[srp]``.
    """
    try:
        import argon2.low_level  # noqa: F401
    except ImportError:
        return False
    return True


def derive_x(identity: str, password: str, salt: bytes, kdf: SrpKdf) -> bytes:
    """Derive the SRP private key ``x`` from the password.

    ``x = KDF(identity ":" password, salt)`` (§23.3 rule 3) — a memory-hard KDF
    rather than RFC 5054's bare hash, because a bare-hash verifier would be
    *cheaper* to attack offline than the Argon2id hashes AXIAM already stores,
    making adoption a net regression at rest.

    ``identity`` MUST be the value from the challenge response, never what the
    user typed (§23.3 rule 2): a user may sign in with a username *or* an email
    while only one of the two is bound into ``x``.

    This is deliberately slow. Argon2id at AXIAM's defaults allocates 19 MiB and
    takes tens to hundreds of milliseconds — that cost is what makes a stolen
    verifier expensive to attack. On an async runtime, treat a call as blocking
    work and run it in a thread.

    :raises NetworkError: when the named KDF cannot be performed here.
    """
    secret = f"{identity}:{password}".encode()

    if kdf.kdf == "argon2id":
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise NetworkError(
                "this tenant requires argon2id for SRP, which needs the optional "
                "`argon2-cffi` dependency: pip install axiam-sdk[srp]"
            ) from exc
        return hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=kdf.iterations,
            memory_cost=kdf.memory_kib or 19456,
            parallelism=kdf.parallelism or 1,
            hash_len=32,
            type=Type.ID,
        )

    if kdf.kdf == "pbkdf2_sha256":
        return hashlib.pbkdf2_hmac("sha256", secret, salt, kdf.iterations, dklen=32)

    raise NetworkError(
        f"this SDK cannot perform the key-derivation function this tenant requires ({kdf.kdf})"
    )


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


def compute_verifier(group: SrpGroup, x: bytes) -> str:
    """Compute the verifier ``v = g^x mod N`` for enrolment, as lowercase hex.

    This is the only value derived from the password that the server ever
    receives, and it is computationally infeasible to invert.
    """
    x_int = int.from_bytes(x, "big") % group.n
    return _pad(pow(group.g, x_int, group.n), group.byte_len).hex()


@dataclass(frozen=True)
class SrpProofs:
    """The two proofs a finished exchange produces."""

    client_proof: str
    """``M1``, lowercase hex — send this to ``/auth/srp/verify``."""

    expected_server_proof: str
    """The ``M2`` the server must return.

    A caller MUST compare the server's ``server_proof`` against this and discard
    the session on mismatch (§23.3 rule 6). Skipping it keeps the half of SRP
    that authenticates the client to the server and throws away the half that
    authenticates the server to the client — leaving an endpoint that never knew
    the verifier indistinguishable from the real one.
    """


class SrpClientSession:
    """One SRP exchange in progress.

    Holds the client's private ephemeral ``a``, generated fresh per exchange
    (§23.3 rule 7) and never exposed.
    """

    __slots__ = ("_a_priv", "_group", "client_public")

    def __init__(self, group: SrpGroup, a_priv: int) -> None:
        """Bind an exchange to *group* and the ephemeral secret *a_priv*.

        Prefer :meth:`begin`, which draws ``a`` from the CSPRNG. This
        constructor exists so the §23.7 vectors can pin it.
        """
        self._group = group
        self._a_priv = a_priv
        self.client_public: str = _pad(pow(group.g, a_priv, group.n), group.byte_len).hex()
        """``A = g^a mod N``, lowercase hex — send with the challenge request."""

    @classmethod
    def begin(cls, group: SrpGroup) -> SrpClientSession:
        """Start an exchange: pick a fresh ``a`` and compute ``A``.

        ``a`` is 256 bits from the platform CSPRNG. Reusing it across exchanges
        would leak the relationship between two session secrets, which is why
        there is no way to supply one.
        """
        return cls(group, int.from_bytes(secrets.token_bytes(32), "big") | (1 << 255))

    @classmethod
    def _with_fixed_ephemeral(cls, group: SrpGroup, a_priv_hex: str) -> SrpClientSession:
        """Conformance seam: build a session with a caller-chosen ``a``.

        §23.7 requires reproducing the shared vectors, and a vector pins ``a`` so
        the exchange is deterministic. Without this, a conformance test would
        have to reimplement :meth:`finish` — testing a copy of the code rather
        than the code.

        Private, and never to be called from application code: reusing ``a`` is a
        real weakness, which is why :meth:`begin` offers no way to do it.
        """
        return cls(group, int(a_priv_hex, 16))

    def finish(self, identity: str, salt_hex: str, server_public_hex: str, x: bytes) -> SrpProofs:
        """Finish the exchange from the server's challenge.

        ``identity`` MUST be the ``identity`` field of the challenge response,
        not what the user typed (§23.3 rule 2).

        :raises NetworkError: when the server's ``B`` or ``u`` is degenerate —
            a broken or hostile server, not a wrong password.
        """
        group = self._group
        n = group.n

        try:
            b_pub = int(server_public_hex, 16)
            salt = bytes.fromhex(salt_hex)
        except ValueError as exc:
            raise NetworkError("SRP: the server's challenge is not valid hex") from exc

        # B ≡ 0 (mod N) means a broken or hostile server (§23.3 rule 5). Refuse
        # before doing any work with it.
        if b_pub % n == 0:
            raise NetworkError("SRP: the server returned an invalid public value (B ≡ 0 mod N)")

        a_pub = int(self.client_public, 16)
        k = _multiplier(group)
        x_int = int.from_bytes(x, "big") % n

        u = _hash_int(_pad(a_pub, group.byte_len), _pad(b_pub, group.byte_len))
        if u == 0:
            raise NetworkError("SRP: the server returned an invalid scrambling parameter (u = 0)")

        # S = (B - k*g^x)^(a + u*x) mod N. Python's `%` already normalises a
        # negative left operand, but the `+ n` is kept for symmetry with the
        # other ten implementations, whose languages do not.
        kgx = (k * pow(group.g, x_int, n)) % n
        base = ((b_pub % n) + n - kgx) % n
        s = pow(base, self._a_priv + u * x_int, n)
        session_key = _hash(_pad(s, group.byte_len))

        h_n = _hash(_pad(n, group.byte_len))
        h_g = _hash(_pad(group.g, group.byte_len))
        xored = bytes(a ^ b for a, b in zip(h_n, h_g, strict=True))
        h_i = _hash(identity.encode())

        m1 = _hash(
            xored,
            h_i,
            salt,
            _pad(a_pub, group.byte_len),
            _pad(b_pub, group.byte_len),
            session_key,
        )
        m2 = _hash(_pad(a_pub, group.byte_len), m1, session_key)

        return SrpProofs(client_proof=m1.hex(), expected_server_proof=m2.hex())


def verify_server_proof(expected: str, actual: str | None) -> bool:
    """Constant-time comparison of the server's proof against the expected one.

    ``M2`` is not a secret the client guards, so constant-time here is
    belt-and-braces — but it costs nothing and keeps the habit intact where it
    does matter.
    """
    if not actual:
        return False
    return hmac.compare_digest(expected, actual)


def generate_salt() -> str:
    """A fresh 32-byte salt for enrolment, as lowercase hex (§23.3 rule 11)."""
    return secrets.token_bytes(32).hex()
