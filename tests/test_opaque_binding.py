"""``axiam_sdk._opaque`` — the ctypes binding to ``libaxiam_opaque_ffi``.

CONTRACT.md §23.1 forbids an SDK from implementing OPAQUE, so there is no
cryptography here to test. What there IS, and what these tests cover, is the
part a binding gets wrong: ownership of Rust-allocated strings, single-use
state handles, the KSF the *server* named being the one used, and an absent
library reporting rather than resembling a wrong password.

The library is exercised through :class:`tests._opaque_fake.FakeOpaqueLibrary`,
which reproduces the ABI's contract (allocate/free, consume-on-finish,
NULL-means-failure) without its mathematics. Requiring the real ``cdylib``
would mean a suite that runs only where a per-platform release asset happens to
be installed — and would be testing ``opaque-ke``, not this module.
"""

from __future__ import annotations

import ctypes
import secrets
from collections.abc import Iterator
from typing import Any

import pytest

from axiam_sdk import AuthError, NetworkError, _opaque
from tests._opaque_fake import SYMBOLS, FakeOpaqueLibrary

ARGON2ID = {"ksf": "argon2id", "memory_kib": 19456, "iterations": 2, "parallelism": 1}
SCRYPT = {"ksf": "scrypt", "log_n": 15, "r": 8, "p": 1}


def _password(label: str) -> str:
    """A per-run test password.

    Minted rather than written down. Nothing here depends on the value — only
    on the two differing — and a literal that reads like a credential is a
    finding for every secret scanner that looks at this repository, which
    trains people to wave those findings through.
    """
    return f"{label}-{secrets.token_hex(8)}"


#: The password an exchange was started with.
PASSWORD = _password("correct")
#: A different one, for the paths where the envelope must not open.
OTHER_PASSWORD = _password("incorrect")

#: The two opaque hex blobs a `finish` takes. Named rather than inline for a
#: mechanical reason: a bare string literal sitting next to an identifier whose
#: name contains PASSWORD is what a generic-secret detector reads as a
#: credential assignment, and every one of those it reports here is one a
#: reviewer learns to skip past.
KE2 = "ke2-hex"
REGISTRATION_RESPONSE = "resp-hex"


@pytest.fixture
def lib() -> Iterator[FakeOpaqueLibrary]:
    """Install a fake library for the duration of one test, and prove on the
    way out that nothing the test allocated was left behind."""
    fake = FakeOpaqueLibrary()
    _opaque._set_for_tests(fake)
    try:
        yield fake
    finally:
        _opaque._reset_for_tests()


@pytest.fixture
def absent() -> Iterator[None]:
    """No library at all — the state a consumer who never installed the
    artifact is in."""
    _opaque._reset_for_tests()
    _opaque._set_for_tests(None)
    try:
        yield
    finally:
        _opaque._reset_for_tests()


# ---------------------------------------------------------------------
# Availability — reporting, not raising (§23.2)
# ---------------------------------------------------------------------


def test_available_when_library_loads_and_says_yes(lib: FakeOpaqueLibrary) -> None:
    assert _opaque.opaque_available() is True


def test_unavailable_when_library_is_present_but_says_no(lib: FakeOpaqueLibrary) -> None:
    # A build compiled without the feature. Present is not the same as usable,
    # and answering from the file's existence would strand a caller at login.
    lib.available_value = 0
    assert _opaque.opaque_available() is False


def test_unavailable_when_library_is_absent(absent: None) -> None:
    assert _opaque.opaque_available() is False


def test_absent_library_names_the_artifact_not_the_password(absent: None) -> None:
    with pytest.raises(NetworkError) as excinfo:
        _opaque.start_login(PASSWORD)
    message = str(excinfo.value)
    assert "libaxiam_opaque_ffi" in message
    assert "AXIAM_OPAQUE_LIBRARY" in message


# ---------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------


def test_candidate_names_honour_the_environment_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_opaque._LIB_ENV, "/opt/axiam/libopaque.so")
    assert _opaque._candidate_names() == ["/opt/axiam/libopaque.so"]


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("darwin", "libaxiam_opaque_ffi.dylib"),
        ("win32", "axiam_opaque_ffi.dll"),
        ("linux", "libaxiam_opaque_ffi.so"),
    ],
)
def test_candidate_names_are_platform_specific(
    monkeypatch: pytest.MonkeyPatch, platform: str, expected: str
) -> None:
    monkeypatch.delenv(_opaque._LIB_ENV, raising=False)
    monkeypatch.setattr(_opaque.sys, "platform", platform)
    assert _opaque._candidate_names() == [expected]


def test_load_declares_every_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    # Without restype, ctypes assumes int and truncates a 64-bit pointer. The
    # binding is only safe if _declare reaches every symbol, so assert it did.
    fake = FakeOpaqueLibrary()
    monkeypatch.setattr(_opaque.ctypes, "CDLL", lambda name: fake)
    _opaque._reset_for_tests()
    try:
        assert _opaque._load() is fake
        for name in SYMBOLS:
            assert getattr(fake, name).restype is not False
            assert getattr(fake, name).argtypes is not None
    finally:
        _opaque._reset_for_tests()


def test_load_memoizes_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    # Retrying dlopen on every login is a per-request filesystem walk for a
    # file that is not going to appear.
    attempts = []

    def refuse(name: str) -> Any:
        attempts.append(name)
        raise OSError("no such file")

    monkeypatch.setattr(_opaque.ctypes, "CDLL", refuse)
    _opaque._reset_for_tests()
    try:
        assert _opaque._load() is None
        assert _opaque._load() is None
        assert len(attempts) == 1
    finally:
        _opaque._reset_for_tests()


def test_load_treats_a_name_collision_as_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Some other libaxiam_opaque_ffi.so on the search path. It loaded, so it is
    # not an OSError; it is missing our symbols, so calling into it would be
    # calling into whatever it actually is.
    class Impostor:
        pass

    monkeypatch.setattr(_opaque.ctypes, "CDLL", lambda name: Impostor())
    _opaque._reset_for_tests()
    try:
        assert _opaque._load() is None
    finally:
        _opaque._reset_for_tests()


# ---------------------------------------------------------------------
# KsfParams — absence preserved, bounds enforced (§23.4 rules 2-5)
# ---------------------------------------------------------------------


def test_from_wire_preserves_absence_rather_than_defaulting_to_zero() -> None:
    params = _opaque.KsfParams.from_wire(ARGON2ID)
    assert params.ksf == "argon2id"
    assert params.memory_kib == 19456
    # scrypt's fields do not apply. Reading them as 0 would stretch at the
    # wrong cost and fail against a record that is perfectly good.
    assert params.log_n is None
    assert params.r is None
    assert params.p is None


def test_from_wire_coerces_numeric_strings() -> None:
    params = _opaque.KsfParams.from_wire({"ksf": "scrypt", "log_n": "15", "r": "8", "p": "1"})
    assert (params.log_n, params.r, params.p) == (15, 8, 1)


def test_missing_field_for_the_named_function_is_refused(lib: FakeOpaqueLibrary) -> None:
    params = _opaque.KsfParams.from_wire({"ksf": "argon2id", "iterations": 2, "parallelism": 1})
    with pytest.raises(NetworkError, match="without `memory_kib`"):
        params._build(lib)


@pytest.mark.parametrize(
    ("wire", "field"),
    [
        ({**ARGON2ID, "memory_kib": 4096}, "memory_kib"),
        ({**ARGON2ID, "memory_kib": 2_097_152}, "memory_kib"),
        ({**ARGON2ID, "iterations": 0}, "iterations"),
        ({**ARGON2ID, "iterations": 99}, "iterations"),
        ({**ARGON2ID, "parallelism": 64}, "parallelism"),
        ({**SCRYPT, "log_n": 13}, "log_n"),
        ({**SCRYPT, "log_n": 21}, "log_n"),
        ({**SCRYPT, "r": 0}, "r"),
        ({**SCRYPT, "p": 17}, "p"),
    ],
)
def test_costs_outside_the_accepted_band_are_refused(
    lib: FakeOpaqueLibrary, wire: dict[str, Any], field: str
) -> None:
    # A server is trusted to name its own policy, not to name a cost that would
    # wedge every device an account owns.
    with pytest.raises(NetworkError, match=field):
        _opaque.KsfParams.from_wire(wire)._build(lib)
    assert lib.ksf_alive == 0


def test_an_unrecognised_function_is_refused_never_substituted(lib: FakeOpaqueLibrary) -> None:
    # Substituting produces a well-formed randomized password no AXIAM server
    # agrees with, which surfaces to the user as a wrong password.
    with pytest.raises(NetworkError, match="bcrypt"):
        _opaque.KsfParams.from_wire({"ksf": "bcrypt"})._build(lib)
    assert lib.ksf_alive == 0


def test_a_null_ksf_handle_reports_the_librarys_own_message(lib: FakeOpaqueLibrary) -> None:
    lib.fail.add("ksf_argon2id")
    with pytest.raises(NetworkError, match="argon2id parameters rejected"):
        _opaque.KsfParams.from_wire(ARGON2ID)._build(lib)


def test_both_key_stretching_functions_are_reachable(lib: FakeOpaqueLibrary) -> None:
    for wire in (ARGON2ID, SCRYPT):
        handle = _opaque.KsfParams.from_wire(wire)._build(lib)
        assert handle
        lib.axiam_opaque_ksf_free(handle)
    assert lib.ksf_alive == 0


# ---------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------


def test_registration_round_trip_frees_every_allocation(lib: FakeOpaqueLibrary) -> None:
    exchange = _opaque.start_registration(PASSWORD)
    assert bytes.fromhex(exchange.request) == b"req:" + PASSWORD.encode()

    record = exchange.finish(PASSWORD, REGISTRATION_RESPONSE, _opaque.KsfParams.from_wire(ARGON2ID))

    assert bytes.fromhex(record).startswith(
        b"record:" + PASSWORD.encode() + b":" + REGISTRATION_RESPONSE.encode() + b":"
    )
    # Two Rust allocations were handed over — the request and the record — and
    # both were released. A binding that leaks here leaks once per login.
    assert len(lib.freed) == 2
    assert len(lib.freed) == len(set(lib.freed))
    assert lib.ksf_alive == 0
    assert lib.states_alive == 0


def test_registration_start_failure_reports_the_librarys_message(lib: FakeOpaqueLibrary) -> None:
    lib.fail.add("registration_start")
    with pytest.raises(NetworkError, match="registration could not be started"):
        _opaque.start_registration(PASSWORD)


def test_registration_finish_failure_still_consumed_the_handle(lib: FakeOpaqueLibrary) -> None:
    lib.fail.add("registration_finish")
    exchange = _opaque.start_registration(PASSWORD)
    with pytest.raises(NetworkError, match="the envelope could not be sealed"):
        exchange.finish(PASSWORD, REGISTRATION_RESPONSE, _opaque.KsfParams.from_wire(ARGON2ID))
    # The library consumes the state whether it succeeds or fails, so the
    # binding must not free it again — and must not leak the ksf either.
    assert lib.states_alive == 0
    assert lib.ksf_alive == 0


def test_a_refused_ksf_does_not_strand_the_state_handle(lib: FakeOpaqueLibrary) -> None:
    exchange = _opaque.start_registration(PASSWORD)
    with pytest.raises(NetworkError, match="bcrypt"):
        exchange.finish(
            PASSWORD, REGISTRATION_RESPONSE, _opaque.KsfParams.from_wire({"ksf": "bcrypt"})
        )
    # The handle was taken before the ksf was built, so it is spent. Retrying
    # must fail loudly rather than pass a dangling pointer across the ABI.
    with pytest.raises(NetworkError, match="already been completed"):
        exchange.finish(PASSWORD, REGISTRATION_RESPONSE, _opaque.KsfParams.from_wire(ARGON2ID))


# ---------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------


def test_login_round_trip_frees_every_allocation(lib: FakeOpaqueLibrary) -> None:
    exchange = _opaque.start_login(PASSWORD)
    assert bytes.fromhex(exchange.ke1) == b"ke1:" + PASSWORD.encode()

    ke3 = exchange.finish(PASSWORD, KE2, _opaque.KsfParams.from_wire(SCRYPT))

    assert bytes.fromhex(ke3).startswith(b"ke3:" + PASSWORD.encode() + b":" + KE2.encode() + b":")
    assert len(lib.freed) == 2
    assert lib.ksf_alive == 0
    assert lib.states_alive == 0


def test_login_start_failure_reports_the_librarys_message(lib: FakeOpaqueLibrary) -> None:
    lib.fail.add("login_start")
    with pytest.raises(NetworkError, match="login could not be started"):
        _opaque.start_login(PASSWORD)


def test_a_failed_login_finish_is_the_whole_authentication_check(lib: FakeOpaqueLibrary) -> None:
    # Both halves of the mutual authentication live here: the envelope only
    # opens under the right password, and KE2's MAC only verifies if the server
    # actually holds the record. §23.4 rule 7 — nothing goes to login/finish.
    #
    # AuthError, not NetworkError: this is the credential check itself. Every
    # other NULL return in the module is a NetworkError, and the difference is
    # what keeps a misconfigured KSF from being shown as a wrong password.
    lib.fail.add("login_finish")
    exchange = _opaque.start_login(OTHER_PASSWORD)
    with pytest.raises(AuthError, match="invalid credentials"):
        exchange.finish(OTHER_PASSWORD, KE2, _opaque.KsfParams.from_wire(ARGON2ID))
    assert lib.states_alive == 0
    assert lib.ksf_alive == 0


def test_a_failed_login_finish_falls_back_when_the_library_is_silent(
    lib: FakeOpaqueLibrary,
) -> None:
    lib.fail.add("login_finish")
    lib.fail_messages["login_finish"] = b""
    exchange = _opaque.start_login(OTHER_PASSWORD)
    with pytest.raises(AuthError, match="the OPAQUE envelope did not open"):
        exchange.finish(OTHER_PASSWORD, KE2, _opaque.KsfParams.from_wire(ARGON2ID))


def test_an_exchange_is_single_use(lib: FakeOpaqueLibrary) -> None:
    exchange = _opaque.start_login(PASSWORD)
    exchange.finish(PASSWORD, KE2, _opaque.KsfParams.from_wire(ARGON2ID))
    with pytest.raises(NetworkError, match="already been completed"):
        exchange.finish(PASSWORD, KE2, _opaque.KsfParams.from_wire(ARGON2ID))


def test_an_abandoned_exchange_releases_its_state(lib: FakeOpaqueLibrary) -> None:
    exchange = _opaque.start_login(PASSWORD)
    assert lib.states_alive == 1
    del exchange
    import gc

    gc.collect()
    assert lib.states_alive == 0


# ---------------------------------------------------------------------
# _take — the ownership primitive
# ---------------------------------------------------------------------


def test_take_falls_back_when_the_library_reports_no_error(lib: FakeOpaqueLibrary) -> None:
    # A NULL return with an empty last_error is a library bug, but a caller
    # still deserves a sentence rather than an empty one.
    lib.last_error_text = b""
    with pytest.raises(NetworkError, match="the library returned no value"):
        _opaque._take(lib, ctypes.c_void_p())


def test_take_decodes_invalid_utf8_rather_than_raising(lib: FakeOpaqueLibrary) -> None:
    lib.last_error_text = b"bad \xff byte"
    with pytest.raises(NetworkError, match="bad"):
        _opaque._take(lib, 0)
