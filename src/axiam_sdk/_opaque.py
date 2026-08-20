"""OPAQUE (RFC 9807) — the protocol half, bound over the shared C ABI.

This module contains **no cryptography**. Its predecessor, ``_srp.py``, was 441
lines of modular exponentiation, ``PAD()`` and transcript hashing, because SRP
is arithmetic every language can express and so every AXIAM client wrote its
own. OPAQUE is not — it needs an oblivious PRF, ``hash_to_curve``,
``expand_message_xmd``, an envelope construction and a three-message AKE — so
``CONTRACT.md`` §23.1 forbids an SDK from implementing it. What is here is a
``ctypes`` binding to ``libaxiam_opaque_ffi``, the same implementation the
AXIAM server links and every other SDK binds.

Loading
-------

The shared library is **optional**, exactly as ``argon2-cffi`` was for SRP: a
consumer whose tenant does not use OPAQUE should not be made to install a
compiled artifact. It is not a PyPI package — there is no ``[opaque]`` extra to
install, because the artifact is a Rust ``cdylib`` published as a GitHub release
asset of ``ilpanich/axiam``, one per platform. Put it on the loader path or
point ``AXIAM_OPAQUE_LIBRARY`` at it. When it is absent
:func:`opaque_available` returns ``False`` and the login path raises
:class:`NetworkError` saying exactly that, rather than throwing something that
looks like a wrong password.

Ownership
---------

Every non-NULL ``char *`` the library returns is Rust-allocated and must be
released with ``axiam_opaque_string_free``; every state handle is single-use
and is consumed by its ``finish``. Both rules are enforced here rather than
being left to callers — :func:`_take` frees on the way out, and the exchange
classes null their handle once spent, so a double-finish raises a Python error
instead of passing a dangling pointer across the ABI.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import threading
from dataclasses import dataclass
from typing import Any

from ._errors import AuthError, NetworkError

#: Cost bands, matching ``axiam_opaque::AxiamKsf`` (§23.4 rule 4).
#:
#: A server is trusted to name its own policy, not to name a cost that would
#: wedge every device an account owns. The library range-checks too; doing it
#: here as well means the refusal carries a Python-side message naming the
#: field, which a caller can act on.
_BOUNDS: dict[str, tuple[int, int]] = {
    "memory_kib": (8192, 1_048_576),
    "iterations": (1, 10),
    "parallelism": (1, 16),
    "log_n": (14, 20),
    "r": (1, 16),
    "p": (1, 16),
}

_LIB_ENV = "AXIAM_OPAQUE_LIBRARY"

_lock = threading.Lock()
_lib: ctypes.CDLL | None = None
_load_attempted = False


def _candidate_names() -> list[str]:
    """Platform filenames for the shared library, most specific first.

    ``AXIAM_OPAQUE_LIBRARY`` wins when set — the escape hatch for a deployment
    that vendors the artifact somewhere the loader would not look, which is the
    normal case for a container image that ships it alongside the application
    rather than installing it system-wide.
    """
    override = os.environ.get(_LIB_ENV)
    if override:
        return [override]
    if sys.platform == "darwin":
        return ["libaxiam_opaque_ffi.dylib"]
    if sys.platform == "win32":
        return ["axiam_opaque_ffi.dll"]
    return ["libaxiam_opaque_ffi.so"]


def _declare(lib: ctypes.CDLL) -> None:
    """Pin every signature.

    Not optional hygiene: without ``restype`` ctypes assumes ``int``, which
    truncates a 64-bit pointer to 32 bits on most platforms and produces a
    segfault at a place unrelated to the mistake.
    """
    c_char_p = ctypes.c_char_p
    c_void_p = ctypes.c_void_p

    lib.axiam_opaque_string_free.argtypes = [c_void_p]
    lib.axiam_opaque_string_free.restype = None

    lib.axiam_opaque_last_error.argtypes = []
    lib.axiam_opaque_last_error.restype = c_char_p

    lib.axiam_opaque_available.argtypes = []
    lib.axiam_opaque_available.restype = ctypes.c_int32

    lib.axiam_opaque_ksf_argon2id.argtypes = [ctypes.c_uint32] * 3
    lib.axiam_opaque_ksf_argon2id.restype = c_void_p

    lib.axiam_opaque_ksf_scrypt.argtypes = [ctypes.c_uint8, ctypes.c_uint32, ctypes.c_uint32]
    lib.axiam_opaque_ksf_scrypt.restype = c_void_p

    lib.axiam_opaque_ksf_free.argtypes = [c_void_p]
    lib.axiam_opaque_ksf_free.restype = None

    lib.axiam_opaque_registration_start.argtypes = [c_char_p, ctypes.POINTER(c_void_p)]
    lib.axiam_opaque_registration_start.restype = c_void_p

    lib.axiam_opaque_registration_finish.argtypes = [
        c_void_p,
        c_char_p,
        c_char_p,
        c_void_p,
        ctypes.POINTER(c_void_p),
    ]
    lib.axiam_opaque_registration_finish.restype = c_void_p

    lib.axiam_opaque_registration_free.argtypes = [c_void_p]
    lib.axiam_opaque_registration_free.restype = None

    lib.axiam_opaque_login_start.argtypes = [c_char_p, ctypes.POINTER(c_void_p)]
    lib.axiam_opaque_login_start.restype = c_void_p

    lib.axiam_opaque_login_finish.argtypes = [
        c_void_p,
        c_char_p,
        c_char_p,
        c_void_p,
        ctypes.POINTER(c_void_p),
        ctypes.POINTER(c_void_p),
    ]
    lib.axiam_opaque_login_finish.restype = c_void_p

    lib.axiam_opaque_login_free.argtypes = [c_void_p]
    lib.axiam_opaque_login_free.restype = None


def _load() -> ctypes.CDLL | None:
    """Load the library once per process, memoizing failure as well as success.

    Memoizing the failure matters: retrying ``dlopen`` on every login would be a
    per-request filesystem walk for a file that is not going to appear.
    """
    global _lib, _load_attempted
    with _lock:
        if _load_attempted:
            return _lib
        _load_attempted = True
        for name in _candidate_names():
            try:
                lib = ctypes.CDLL(name)
            except OSError:
                continue
            try:
                _declare(lib)
            except AttributeError:
                # The file loaded but is not this library — a name collision on
                # the search path. Treat it as absent rather than calling into
                # whatever it actually is.
                continue
            _lib = lib
            return _lib
        return None


def _reset_for_tests() -> None:
    """Forget the memoized load. Test-only."""
    global _lib, _load_attempted
    with _lock:
        _lib = None
        _load_attempted = False


def _set_for_tests(lib: Any) -> None:
    """Inject a library, bypassing the loader. Test-only."""
    global _lib, _load_attempted
    with _lock:
        _lib = lib
        _load_attempted = True


def opaque_available() -> bool:
    """Whether this installation can perform OPAQUE (§23.2).

    Reports rather than raising, so an application can choose the password path
    before attempting a login instead of discovering the gap mid-exchange.
    """
    lib = _load()
    return lib is not None and bool(lib.axiam_opaque_available())


def _require() -> ctypes.CDLL:
    """The library, or a refusal that names the artifact rather than the user.

    Absent is a deployment fact, so it must never surface as anything a caller
    could mistake for a wrong password.
    """
    lib = _load()
    if lib is None:
        raise NetworkError(
            "OPAQUE is not available: the shared library "
            "`libaxiam_opaque_ffi` could not be loaded. Download the asset for "
            "your platform from the axiam release page, then put it on the "
            "loader path or point AXIAM_OPAQUE_LIBRARY at the file."
        )
    return lib


def _last_error(lib: ctypes.CDLL, fallback: str) -> str:
    """The library's description of the last failure, or *fallback*.

    A NULL return with nothing behind it is a library bug, but a caller still
    deserves a sentence rather than an empty one.
    """
    raw = lib.axiam_opaque_last_error()
    if not raw:
        return fallback
    text: str = raw.decode("utf-8", "replace")
    return text


def _take(lib: ctypes.CDLL, ptr: Any) -> str:
    """Take ownership of a returned string, freeing the Rust allocation."""
    if not ptr:
        raise NetworkError(f"OPAQUE: {_last_error(lib, 'the library returned no value')}")
    try:
        return ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8")  # type: ignore[union-attr]
    finally:
        lib.axiam_opaque_string_free(ptr)


@dataclass(frozen=True)
class KsfParams:
    """The key-stretching fields a ``*/start`` response carries.

    Flat and optional, matching the wire format: fields that do not apply to
    the named function are **absent, not zero**. Reading a missing
    ``memory_kib`` as ``0`` would stretch with the wrong cost and fail against
    a record that is perfectly good (§23.4 rule 5).
    """

    ksf: str
    memory_kib: int | None = None
    iterations: int | None = None
    parallelism: int | None = None
    log_n: int | None = None
    r: int | None = None
    p: int | None = None

    @classmethod
    def from_wire(cls, wire: dict[str, Any]) -> KsfParams:
        """Read the flat fields, preserving absence."""

        def opt(name: str) -> int | None:
            """Absent stays absent; present is coerced (JSON may carry it as a
            string)."""
            value = wire.get(name)
            return None if value is None else int(value)

        return cls(
            ksf=str(wire.get("ksf", "")),
            memory_kib=opt("memory_kib"),
            iterations=opt("iterations"),
            parallelism=opt("parallelism"),
            log_n=opt("log_n"),
            r=opt("r"),
            p=opt("p"),
        )

    def _require(self, name: str, value: int | None) -> int:
        """One cost the named function needs, present and within its band."""
        if value is None:
            raise NetworkError(f"OPAQUE: the server named ksf `{self.ksf}` without `{name}`")
        low, high = _BOUNDS[name]
        if not low <= value <= high:
            raise NetworkError(
                f"OPAQUE: the server named {name}={value} for `{self.ksf}`, "
                f"outside the accepted {low}..{high}"
            )
        return value

    def _build(self, lib: ctypes.CDLL) -> Any:
        """Build the library's KSF handle from what the **server** named.

        Never from local defaults, and never cached across exchanges: a
        credential enrolled under one cost keeps working after a tenant raises
        its policy, so a client that guessed would derive a different randomized
        password and fail against a good record (§23.4 rule 2).

        An unrecognised function is refused, never substituted — substituting
        produces a well-formed randomized password no AXIAM server agrees with,
        surfacing to the user as a wrong password (§23.4 rule 3).
        """
        if self.ksf == "argon2id":
            handle = lib.axiam_opaque_ksf_argon2id(
                self._require("memory_kib", self.memory_kib),
                self._require("iterations", self.iterations),
                self._require("parallelism", self.parallelism),
            )
        elif self.ksf == "scrypt":
            handle = lib.axiam_opaque_ksf_scrypt(
                self._require("log_n", self.log_n),
                self._require("r", self.r),
                self._require("p", self.p),
            )
        else:
            raise NetworkError(
                "OPAQUE: this SDK cannot perform the key-stretching function "
                f"the server named (`{self.ksf}`)"
            )
        if not handle:
            raise NetworkError(f"OPAQUE: {_last_error(lib, 'invalid KSF parameters')}")
        return handle


class _Exchange:
    """Shared handle bookkeeping for the two exchanges.

    The handle is single-use: the library consumes it in ``finish`` whether that
    succeeds or fails. Nulling it here means a second call raises a Python error
    rather than handing a dangling pointer across the ABI, and ``__del__``
    releases an exchange the caller abandoned.
    """

    _free_name = ""

    def __init__(self, lib: ctypes.CDLL, handle: Any, first_message: str) -> None:
        """Adopt *handle*, which this object now owns and must release exactly
        once."""
        self._lib = lib
        self._handle: Any = handle
        self._first = first_message

    def _consume(self) -> Any:
        """Spend the handle, or refuse if it is already spent."""
        if not self._handle:
            raise NetworkError("OPAQUE: this exchange has already been completed")
        handle, self._handle = self._handle, None
        return handle

    def __del__(self) -> None:  # pragma: no cover - depends on GC timing
        """Release an exchange the caller abandoned — a login started and never
        finished still holds Rust-side state."""
        handle, self._handle = getattr(self, "_handle", None), None
        if handle:
            getattr(self._lib, self._free_name)(handle)


class RegistrationExchange(_Exchange):
    """One in-flight enrolment."""

    _free_name = "axiam_opaque_registration_free"

    @property
    def request(self) -> str:
        """Hex ``RegistrationRequest``, for ``register/start``."""
        return self._first

    def finish(self, password: str, registration_response: str, ksf: KsfParams) -> str:
        """Seal the envelope, returning the hex ``RegistrationRecord``."""
        handle = self._consume()
        ksf_handle = ksf._build(self._lib)
        try:
            record = self._lib.axiam_opaque_registration_finish(
                handle,
                password.encode("utf-8"),
                registration_response.encode("utf-8"),
                ksf_handle,
                None,
            )
            return _take(self._lib, record)
        finally:
            self._lib.axiam_opaque_ksf_free(ksf_handle)


class LoginExchange(_Exchange):
    """One in-flight login."""

    _free_name = "axiam_opaque_login_free"

    @property
    def ke1(self) -> str:
        """Hex ``KE1``, for ``login/start``."""
        return self._first

    def finish(self, password: str, ke2: str, ksf: KsfParams) -> str:
        """Open the envelope, returning the hex ``KE3``.

        A failure here is the *whole* of the client's authentication check, and
        covers both halves of the mutual authentication: the envelope only opens
        under the right password, and ``KE2``'s MAC only verifies if the server
        actually holds the record. Nothing may be sent afterwards (§23.4
        rule 7) — so this raises :class:`AuthError`, not the
        :class:`NetworkError` every other NULL return in this module produces.

        The distinction is the whole reason this method does not simply defer to
        :func:`_take`. A wrong password, an account that does not exist and a
        server that does not hold the record are indistinguishable by design and
        are all authentication failures; a KSF the server named that this build
        cannot perform is a configuration problem, and reporting it as "invalid
        password" would send an operator looking in the wrong place.
        """
        handle = self._consume()
        ksf_handle = ksf._build(self._lib)
        try:
            ke3 = self._lib.axiam_opaque_login_finish(
                handle,
                password.encode("utf-8"),
                ke2.encode("utf-8"),
                ksf_handle,
                None,
                None,
            )
            if not ke3:
                raise AuthError(
                    "invalid credentials: "
                    + _last_error(self._lib, "the OPAQUE envelope did not open")
                )
            return _take(self._lib, ke3)
        finally:
            self._lib.axiam_opaque_ksf_free(ksf_handle)


def start_registration(password: str) -> RegistrationExchange:
    """Blind the password. The returned ``request`` goes to ``register/start``."""
    lib = _require()
    out = ctypes.c_void_p()
    handle = lib.axiam_opaque_registration_start(password.encode("utf-8"), ctypes.byref(out))
    if not handle:
        raise NetworkError(f"OPAQUE: {_last_error(lib, 'registration could not be started')}")
    return RegistrationExchange(lib, handle, _take(lib, out))


def start_login(password: str) -> LoginExchange:
    """Blind the password. The returned ``ke1`` goes to ``login/start``."""
    lib = _require()
    out = ctypes.c_void_p()
    handle = lib.axiam_opaque_login_start(password.encode("utf-8"), ctypes.byref(out))
    if not handle:
        raise NetworkError(f"OPAQUE: {_last_error(lib, 'login could not be started')}")
    return LoginExchange(lib, handle, _take(lib, out))
