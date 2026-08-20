"""A stand-in for ``libaxiam_opaque_ffi``, for testing the ctypes binding.

``_opaque.py`` contains no cryptography — it is ownership bookkeeping over a C
ABI — and that is exactly the part a test can and should cover without the real
artifact present. The artifact is a Rust ``cdylib`` published per platform, so a
suite that required it would only run where it happened to be installed, and
would test ``opaque-ke`` rather than this module.

What this fake reproduces is the ABI's *contract*, not its mathematics:

* every ``char *`` returned is heap-allocated and must be freed exactly once
  with ``axiam_opaque_string_free``;
* a state handle is CONSUMED by its ``finish``, success or failure;
* a NULL return means failure, described by ``axiam_opaque_last_error``.

It records frees and outstanding handles so a test can assert the binding
honours all three, and it can be told to fail any entry point on demand.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

#: Every symbol ``_opaque._declare`` pins. Listing them here means a signature
#: added upstream without a fake counterpart fails ``_declare`` loudly (the
#: AttributeError path) rather than being silently untested.
SYMBOLS = (
    "axiam_opaque_string_free",
    "axiam_opaque_last_error",
    "axiam_opaque_available",
    "axiam_opaque_ksf_argon2id",
    "axiam_opaque_ksf_scrypt",
    "axiam_opaque_ksf_free",
    "axiam_opaque_registration_start",
    "axiam_opaque_registration_finish",
    "axiam_opaque_registration_free",
    "axiam_opaque_login_start",
    "axiam_opaque_login_finish",
    "axiam_opaque_login_free",
)


class _Fn:
    """One exported function, with the ``argtypes``/``restype`` slots ctypes
    writes to. ``_declare`` assigning them is the point — a fake that rejected
    the assignment would not exercise the loader path at all."""

    def __init__(self, impl: Callable[..., Any]) -> None:
        self._impl = impl
        self.argtypes: Any = None
        self.restype: Any = None

    def __call__(self, *args: Any) -> Any:
        return self._impl(*args)


class FakeOpaqueLibrary:
    """An in-process implementation of the C ABI, faithful about ownership."""

    def __init__(self) -> None:
        self._buffers: dict[int, Any] = {}
        self._states: dict[int, str] = {}
        self._next_handle = 0x1000
        #: Pointers passed to ``axiam_opaque_string_free``, in order. A leak is
        #: an allocation that never appears here; a double free appears twice.
        self.freed: list[int] = []
        #: Live KSF handles. Must be back to zero once an exchange finishes.
        self.ksf_alive = 0
        #: Outstanding state handles — nonzero after an abandoned exchange.
        self.states_alive = 0
        self.available_value = 1
        self.last_error_text = b""
        #: Entry-point names that should return NULL instead of working.
        self.fail: set[str] = set()
        #: Entry-point names that should RAISE rather than return NULL. Models
        #: the library throwing across ctypes — a wrong argument type raises
        #: ``ctypes.ArgumentError``, which is neither a NULL return nor
        #: something the binding declared, and must still not escape as a
        #: bare traceback.
        self.raises: dict[str, BaseException] = {}
        #: Override the text ``last_error`` reports for a failing entry point.
        #: Setting one to ``b""`` models a library that failed without saying
        #: why — a bug, but one the binding still has to produce a sentence for.
        self.fail_messages: dict[str, bytes] = {}
        for name in SYMBOLS:
            setattr(self, name, _Fn(getattr(self, f"_{name}")))

    # -- allocation ----------------------------------------------------

    def _alloc_hex(self, payload: bytes) -> int:
        """Allocate a hex string. Every value this ABI returns is hex, so a
        fake that returned raw bytes would let a binding bug survive."""
        return self._alloc(payload.hex().encode("ascii"))

    def _alloc(self, data: bytes) -> int:
        buf = ctypes.create_string_buffer(data)
        addr = ctypes.cast(buf, ctypes.c_void_p).value
        assert addr is not None
        self._buffers[addr] = buf
        return addr

    def _handle(self, kind: str) -> int:
        self._next_handle += 0x10
        self._states[self._next_handle] = kind
        self.states_alive += 1
        return self._next_handle

    def _consume(self, handle: int, kind: str) -> None:
        assert self._states.pop(handle, None) == kind, f"handle {handle:#x} was not a live {kind}"
        self.states_alive -= 1

    def _fail(self, name: str, message: bytes) -> bool:
        if name in self.raises:
            raise self.raises[name]
        if name in self.fail:
            self.last_error_text = self.fail_messages.get(name, message)
            return True
        return False

    # -- exported functions --------------------------------------------

    def _axiam_opaque_string_free(self, ptr: Any) -> None:
        addr = ptr if isinstance(ptr, int) else ptr.value
        assert addr in self._buffers, f"free of {addr!r}, which this library never allocated"
        self.freed.append(addr)
        del self._buffers[addr]

    def _axiam_opaque_last_error(self) -> bytes:
        return self.last_error_text

    def _axiam_opaque_available(self) -> int:
        return self.available_value

    def _axiam_opaque_ksf_argon2id(self, memory_kib: int, iterations: int, parallelism: int) -> int:
        if self._fail("ksf_argon2id", b"argon2id parameters rejected"):
            return 0
        self.ksf_alive += 1
        return 0xA000 + memory_kib + iterations + parallelism

    def _axiam_opaque_ksf_scrypt(self, log_n: int, r: int, p: int) -> int:
        if self._fail("ksf_scrypt", b"scrypt parameters rejected"):
            return 0
        self.ksf_alive += 1
        return 0xB000 + log_n + r + p

    def _axiam_opaque_ksf_free(self, ptr: Any) -> None:
        assert ptr, "free of a NULL ksf handle"
        self.ksf_alive -= 1

    def _axiam_opaque_registration_start(self, password: bytes, out_request: Any) -> int:
        if self._fail("registration_start", b"registration could not be started"):
            return 0
        out_request._obj.value = self._alloc_hex(b"req:" + password)
        return self._handle("registration")

    def _axiam_opaque_registration_finish(
        self,
        state: int,
        password: bytes,
        registration_response: bytes,
        ksf: int,
        out_export_key: Any,
    ) -> int:
        self._consume(state, "registration")
        if self._fail("registration_finish", b"the envelope could not be sealed"):
            return 0
        assert ksf, "registration_finish called with a NULL ksf"
        return self._alloc_hex(
            b"record:" + password + b":" + registration_response + f":{ksf:x}".encode()
        )

    def _axiam_opaque_registration_free(self, ptr: int) -> None:
        self._consume(ptr, "registration")

    def _axiam_opaque_login_start(self, password: bytes, out_ke1: Any) -> int:
        if self._fail("login_start", b"login could not be started"):
            return 0
        out_ke1._obj.value = self._alloc_hex(b"ke1:" + password)
        return self._handle("login")

    def _axiam_opaque_login_finish(
        self,
        state: int,
        password: bytes,
        ke2: bytes,
        ksf: int,
        out_session_key: Any,
        out_export_key: Any,
    ) -> int:
        self._consume(state, "login")
        if self._fail("login_finish", b"the envelope did not open"):
            return 0
        assert ksf, "login_finish called with a NULL ksf"
        return self._alloc_hex(b"ke3:" + password + b":" + ke2 + f":{ksf:x}".encode())

    def _axiam_opaque_login_free(self, ptr: int) -> None:
        self._consume(ptr, "login")
