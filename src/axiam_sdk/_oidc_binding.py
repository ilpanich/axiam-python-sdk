"""Login-glue decisions shared by the Django and FastAPI "Login with AXIAM" glue
(CONTRACT.md §12.8, contract 1.68; audit findings C7 and C6).

One module, so the cookie name, its attributes, the digest comparison and the ``return_to`` rule
cannot drift between frameworks. Nothing here touches a request or a response: each adapter does
its own cookie I/O (``set_cookie`` on its own response class) from the values computed here.

**C7 -- browser binding.** The login route draws 32 random bytes, sets them (base64url, no
padding) as an ``HttpOnly; Secure; SameSite=Lax; Path=/`` ``__Host-`` cookie and stores the
SHA-256 of that value on the state entry as ``binding_digest``. The callback consumes the entry
first and then compares the presented cookie against the digest in constant time. The cookie value
is credential-adjacent: it is never logged and is sent in no header, query or body other than its
own ``Set-Cookie``.

**C6 -- ``return_to``.** Only a same-origin relative path is honoured, checked when the entry is
stored and again before redirecting.

**Redirect target encoding (login-glue-binding Decision 7).** The ``Location`` header of the
callback's ``302`` carries the percent-encoded form of the destination. Each adapter produces it
with :func:`encode_redirect_location` at the point where it writes the header; the application is
never asked to encode, and its hooks never see the encoded value.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

#: The binding cookie's name. The ``__Host-`` prefix makes a browser refuse it unless it is
#: ``Secure``, ``Path=/`` and carries no ``Domain``, so a sibling subdomain cannot plant it.
BINDING_COOKIE_NAME = "__Host-axiam_oidc_bind"

#: The plain-HTTP loopback development name (§12.8 rule 1 (b)). A browser will not store a
#: ``Secure`` cookie over ``http://localhost``, so the ``__Host-`` name cannot work there.
BINDING_COOKIE_LOOPBACK_NAME = "axiam_oidc_bind"

#: ``Max-Age`` of the binding cookie: the state store's maximum TTL (§12.3 rule 1).
BINDING_COOKIE_MAX_AGE_SECONDS = 600

#: Random bytes in a binding value (§12.8 rule 1 (a)).
_BINDING_BYTES = 32

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class BindingCookieSpec:
    """The cookie name and ``Secure`` flag one ``redirect_uri`` selects. Every other attribute is
    fixed: ``HttpOnly``, ``SameSite=Lax``, ``Path=/``, no ``Domain``."""

    name: str
    secure: bool


def binding_cookie_spec(redirect_uri: str) -> BindingCookieSpec:
    """The binding cookie's name and ``Secure`` flag for ``redirect_uri`` (§12.8 rule 1 (b)).

    A pure function of the configured ``redirect_uri``: the fallback name, without ``Secure``,
    only for ``http:`` on ``localhost``, ``127.0.0.1`` or ``[::1]``. Every ``https:`` URI, and
    plain HTTP to any other host, gets ``__Host-axiam_oidc_bind`` (which a browser drops over
    plain HTTP to a non-loopback host, so every callback fails closed -- intended). There is no
    way to select the fallback anywhere else.
    """
    try:
        parts = urlsplit(redirect_uri)
        host = parts.hostname
    except ValueError:
        return BindingCookieSpec(BINDING_COOKIE_NAME, secure=True)
    if parts.scheme.lower() == "http" and host is not None and host.lower() in _LOOPBACK_HOSTS:
        return BindingCookieSpec(BINDING_COOKIE_LOOPBACK_NAME, secure=False)
    return BindingCookieSpec(BINDING_COOKIE_NAME, secure=True)


def binding_digest(value: str) -> str:
    """Lower-case hex SHA-256 of the ASCII bytes of the binding value as set in the cookie."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_binding() -> tuple[str, str]:
    """Draw a fresh binding: ``(cookie value, digest to store on the entry)``.

    A new value for every login; a cookie the login request itself presents is never reused.
    """
    value = base64.urlsafe_b64encode(secrets.token_bytes(_BINDING_BYTES)).rstrip(b"=").decode()
    return value, binding_digest(value)


def binding_matches(stored_digest: str | None, presented: str | None) -> bool:
    """Whether ``presented`` (the cookie the callback received) is the value ``stored_digest``
    was taken from -- compared in constant time, over encoded bytes (so a non-ASCII value is a
    mismatch, never a ``TypeError``). A missing cookie, an entry with no digest (written by
    pre-1.68 glue) and a different digest are all ``False``."""
    if not presented or not stored_digest:
        return False
    return hmac.compare_digest(stored_digest.encode(), binding_digest(presented).encode())


def is_safe_return_to(value: str | None) -> bool:
    """CONTRACT.md §12.8 rule 3: a same-origin relative path.

    It starts with a single ``/``, does not start with ``//`` or ``/\\``, and contains no ``\\``
    and no control character (U+0000-U+001F, U+007F) anywhere.
    """
    if not isinstance(value, str) or not value.startswith("/"):
        return False
    if value.startswith(("//", "/\\")) or "\\" in value:
        return False
    return not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def resolve_return_to(
    value: str | None, allow_return_to: Callable[[str], bool] | None = None
) -> str | None:
    """``value`` when it may be redirected to, else ``None`` (§12.8 rule 3).

    The default rule decides first. ``allow_return_to`` is consulted **only** for a value the
    default rule refuses, and honours it only when the predicate returns ``True``; a predicate
    that raises accepts nothing. Used when the entry is stored and again before redirecting.
    """
    if value is None or value == "":
        return None
    if is_safe_return_to(value):
        return value
    if allow_return_to is not None:
        try:
            if allow_return_to(value) is True:
                return value
        except Exception:
            return None
    return None


#: What :func:`encode_redirect_location` leaves as it is, besides ``A-Z a-z 0-9`` (``%`` is handled
#: on its own). The backslash is KEPT (Decision 7: a MUST); the default ``return_to`` rule never
#: lets one reach here, only an integrator's predicate can.
_LOCATION_SAFE = frozenset("!#$&'()*+,-./:;=?@[\\]^_|~")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def encode_redirect_location(destination: str) -> str:
    """The percent-encoded form of ``destination``, for a ``Location`` header.

    Every character outside ``A-Z a-z 0-9`` and ``! # $ & ' ( ) * + , - . / : ; = ? @ [ \\ ] ^ _ |
    ~`` is UTF-8 percent-encoded with upper-case hex (space ``%20``, ``e`` with acute ``%C3%A9``,
    CR ``%0D``, LF ``%0A``, ``"`` ``%22``). A ``%`` that already starts a well-formed escape
    (``%`` and two hex digits) is kept, so an already-encoded value is not encoded twice; any
    other ``%`` becomes ``%25`` (``/%%41`` gives ``/%25%41``). Every lone surrogate -- Python
    strings can carry them, UTF-8 input cannot -- is replaced by U+FFFD before encoding,
    adjacent ones included, and never raises. The result is pure ASCII with no byte below
    ``0x21``, so a
    CR or LF in the destination can never split the header or inject another one.
    """
    out: list[str] = []
    length = len(destination)
    for index, char in enumerate(destination):
        if char == "%":
            if (
                index + 2 < length
                and destination[index + 1] in _HEX_DIGITS
                and destination[index + 2] in _HEX_DIGITS
            ):
                out.append("%")
            else:
                out.append("%25")
        elif char.isascii() and (char.isalnum() or char in _LOCATION_SAFE):
            out.append(char)
        else:
            if 0xD800 <= ord(char) <= 0xDFFF:
                char = "\ufffd"
            out.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
    return "".join(out)
