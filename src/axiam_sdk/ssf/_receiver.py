"""The SSF receiver helper — CONTRACT.md §32.7 (contract 1.56).

See the package docstring (:mod:`axiam_sdk.ssf`) for the overview. This module
holds the verification core shared by :class:`SsfReceiver` and
:class:`AsyncSsfReceiver`, and the two receivers themselves, which differ only
in how they perform I/O.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import inspect
import json
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import quote

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwt.algorithms import OKPAlgorithm
from pydantic import SecretStr

from axiam_sdk._errors import AuthError, NetworkError, network_error_from_transport
from axiam_sdk._retry import retry_async, retry_sync, status_is_retryable

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk._async_client import AsyncAxiamClient
    from axiam_sdk._client import AxiamClient

__all__ = [
    "ACCOUNT_DISABLED",
    "ACCOUNT_ENABLED",
    "ACCOUNT_PURGED",
    "ASSURANCE_LEVEL_CHANGE",
    "CREDENTIAL_CHANGE",
    "MIN_REPLAY_WINDOW_SECONDS",
    "SESSION_REVOKED",
    "STREAM_UPDATED",
    "VERIFICATION",
    "AsyncReplayStore",
    "AsyncSsfReceiver",
    "MemoryReplayStore",
    "RefusedSet",
    "ReplayStore",
    "SecurityEvent",
    "SetErr",
    "SetFailureReason",
    "SetVerificationError",
    "SsfPollResult",
    "SsfReceiver",
]

# ---------------------------------------------------------------------------
# Event types (§32.6) — open: a SET of another type still verifies.
# ---------------------------------------------------------------------------

SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
"""CAEP session revoked."""

CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
"""CAEP credential change."""

ASSURANCE_LEVEL_CHANGE = (
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
)
"""CAEP assurance level change."""

ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
"""RISC account disabled."""

ACCOUNT_ENABLED = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
"""RISC account enabled."""

ACCOUNT_PURGED = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
"""RISC account purged."""

VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification"
"""SSF verification."""

STREAM_UPDATED = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
"""SSF stream updated."""

MIN_REPLAY_WINDOW_SECONDS = 7 * 24 * 60 * 60
"""The replay window's floor **and** default: seven days, the transmitter's
buffer retention (§32.6). A shorter window would forget a ``jti`` the
transmitter can still re-send, so one is refused at construction."""

#: How long a fetched JWKS is used before it is fetched again unprompted.
_JWKS_LIFESPAN_SECONDS = 300.0

#: The minimum interval between two forced refetches on an unknown ``kid``
#: (§32.7 step 4: "no more often than once a minute").
_FORCED_REFETCH_MIN_INTERVAL_SECONDS = 60.0

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class SetFailureReason(str, Enum):
    """Why :meth:`SsfReceiver.verify_set` refused a SET (§32.7), one per step."""

    MALFORMED = "malformed"
    """Not three base64url parts decoding to a JSON header and payload (step 1)."""

    INVALID_TYPE = "invalid_type"
    """``typ`` is not ``secevent+jwt`` / ``application/secevent+jwt`` (step 2)."""

    INVALID_KEY = "invalid_key"
    """``alg`` not ``EdDSA``, no key for ``kid`` after one refetch, or a bad
    signature (steps 3-5)."""

    INVALID_ISSUER = "invalid_issuer"
    """``iss`` is not the configured issuer (step 6)."""

    INVALID_AUDIENCE = "invalid_audience"
    """``aud`` does not name the configured audience (step 7)."""

    INVALID_REQUEST = "invalid_request"
    """``exp`` or ``sub`` present; ``jti``, ``iat`` or ``sub_id`` absent or
    mistyped; ``events`` not exactly one member (step 8)."""

    REPLAYED = "replayed"
    """The ``jti`` was already seen inside the replay window (step 9)."""

    def push_error_code(self) -> str:
        """The RFC 8935 §2.4 ``err`` to answer a push with, or to send in a
        poll's ``setErrs``.

        The reason itself where RFC 8935 defines the code (``invalid_key``,
        ``invalid_issuer``, ``invalid_audience``, ``invalid_request``) and
        ``invalid_request`` for ``malformed``, ``invalid_type`` and
        ``replayed``, which it does not: RFC 8935 §2.4 has ``invalid_request``,
        ``invalid_key``, ``invalid_issuer``, ``invalid_audience``,
        ``authentication_failed`` and ``access_denied`` only.
        """
        if self in (
            SetFailureReason.MALFORMED,
            SetFailureReason.INVALID_TYPE,
            SetFailureReason.REPLAYED,
        ):
            return "invalid_request"
        return str(self.value)


class SetVerificationError(AuthError):
    """A SET refusal (§32.7): an :class:`~axiam_sdk.AuthError` whose
    :attr:`reason` is the step's code and :attr:`set_failure_reason` the
    typed value. The message names the step, never a claim value."""

    def __init__(self, reason: SetFailureReason, detail: str) -> None:
        """Build the refusal for ``reason`` with a fixed ``detail``."""
        super().__init__(f"SET refused ({reason.value}): {detail}", reason=reason.value)
        self.set_failure_reason = reason


@dataclass(frozen=True)
class SetErr:
    """An RFC 8936 ``setErrs`` entry: ``{"err": ..., "description"?: ...}``."""

    err: str
    """The RFC 8935 §2.4 code."""

    description: str | None = None
    """Optional text. AXIAM never stores it (§32.6)."""

    @classmethod
    def from_reason(cls, reason: SetFailureReason) -> SetErr:
        """The entry for a refusal: its :meth:`SetFailureReason.push_error_code`."""
        return cls(err=reason.push_error_code())

    def to_wire(self) -> dict[str, str]:
        """The JSON object sent in ``setErrs``."""
        wire = {"err": self.err}
        if self.description is not None:
            wire["description"] = self.description
        return wire


@dataclass(frozen=True)
class SecurityEvent:
    """A verified Security Event Token (§32.7's result)."""

    jti: str
    """The SET's unique id."""

    iat: int | float
    """When it was issued, seconds since the epoch."""

    iss: str
    """The issuer, equal to the configured one."""

    aud: Any
    """The audience as sent: one string, or an array containing yours."""

    txn: str | None
    """The transaction id shared by every SET one operation produced."""

    event_type: str
    """The single ``events`` key -- an event-type URI (e.g. :data:`SESSION_REVOKED`)."""

    event: dict[str, Any]
    """That event's object, opaque to the helper."""

    sub_id: dict[str, Any]
    """The RFC 9493 subject identifier, opaque to the helper."""


@dataclass(frozen=True)
class RefusedSet:
    """One SET a poll returned and the helper refused."""

    jti: str
    """The key the transmitter returned the SET under."""

    reason: SetFailureReason
    """Why it was refused. Pass ``SetErr.from_reason(reason)`` in the next
    poll's ``set_errs``."""


@dataclass(frozen=True)
class SsfPollResult:
    """What :meth:`SsfReceiver.poll` returns."""

    events: list[SecurityEvent] = field(default_factory=list)
    """The SETs that verified, in the order the transmitter's map listed them."""

    more_available: bool = False
    """Whether the transmitter holds more."""

    refused: list[RefusedSet] = field(default_factory=list)
    """The SETs that did not verify."""

    unjudged: list[str] = field(default_factory=list)
    """The keys of the SETs left **unjudged** by a failure that is no verdict on
    a SET -- a JWKS or discovery fetch that failed, a replay store that could
    not answer (§34.2 P1, P3). They are in neither ``events`` nor ``refused``
    and their ``jti`` was **not** recorded: neither acknowledge nor refuse them,
    and the transmitter offers them again. Verification stops at the first such
    failure, so every SET after it is listed here too."""

    unjudged_error: Exception | None = None
    """The failure that left ``unjudged`` unjudged (a :class:`NetworkError` for
    a fetch, the store's own exception for a store), or ``None``."""


class ReplayStore(Protocol):
    """Remembers the ``jti`` values already accepted, for step 9.

    Pluggable so a receiver running several instances can share one store
    (§32.7). :class:`MemoryReplayStore` is the default. :class:`AsyncSsfReceiver`
    also takes an :class:`AsyncReplayStore`.

    **Fail closed** (§34.2 P4): a store that cannot answer -- its backend is
    down, a call timed out -- MUST raise, never return ``True``. The receiver
    treats the exception as no verdict on the SET: ``verify_set`` raises it,
    ``poll`` leaves that SET unjudged and unrecorded.
    """

    def check_and_record(self, jti: str, window_seconds: float) -> bool:
        """Record ``jti`` for ``window_seconds`` and return ``True``, or return
        ``False`` without recording when it is already held. MUST be atomic:
        two concurrent calls with one ``jti`` must not both see ``True``.
        Raise when the store cannot answer."""
        ...  # pragma: no cover - protocol


class AsyncReplayStore(Protocol):
    """:class:`ReplayStore` with a coroutine ``check_and_record``, for
    :class:`AsyncSsfReceiver` over an asynchronous backend (a shared cache
    reached through an async driver). The same atomicity and fail-closed rules
    apply."""

    async def check_and_record(self, jti: str, window_seconds: float) -> bool:
        """Async :meth:`ReplayStore.check_and_record`."""
        ...  # pragma: no cover - protocol


class MemoryReplayStore:
    """The in-memory :class:`ReplayStore`: one process, lost on restart.

    Bounded in time -- an entry is forgotten after its window -- but **not in
    count**: it holds every ``jti`` accepted within the window (§34.2 P4).
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Build an empty store; ``clock`` is injectable for tests."""
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_record(self, jti: str, window_seconds: float) -> bool:
        """Atomically refuse a held ``jti`` or record a new one (expired ones
        are forgotten first)."""
        now = self._clock()
        with self._lock:
            self._seen = {k: exp for k, exp in self._seen.items() if exp > now}
            if jti in self._seen:
                return False
            self._seen[jti] = now + window_seconds
            return True


TokenValue = SecretStr | str
"""A bearer as the provider may return it: wrapped or bare."""

AccessTokenProvider = Callable[[], TokenValue]
"""Supplies the bearer :meth:`SsfReceiver.poll` presents -- a client-credentials
access token carrying ``ssf.manage`` (e.g. ``login_client_credentials``)."""

AsyncAccessTokenProvider = Callable[[], TokenValue | Awaitable[TokenValue]]
""":data:`AccessTokenProvider` for :class:`AsyncSsfReceiver`; may be a coroutine."""


def _b64(part: str) -> bytes:
    """Strict base64url decode (no padding required, nothing else accepted).

    An empty part decodes to no bytes: an unsigned ``alg: none`` token is then
    refused at step 3 as ``invalid_key``, which is what it is.
    """
    if any(c not in _B64URL for c in part):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _json_object(part: str) -> dict[str, Any] | None:
    """A base64url part decoded to a JSON object, or ``None``."""
    try:
        value = json.loads(_b64(part))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _check_url(label: str, url: str) -> str:
    """``url`` if it is ``https``, or ``http`` on a loopback host (§6).

    Raises:
        NetworkError: otherwise -- never a SET verdict.
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError):
        raise NetworkError(f"{label} is not an absolute URL") from None
    scheme = parsed.scheme.lower()
    if scheme == "https" or (scheme == "http" and parsed.host.lower() in _LOOPBACK_HOSTS):
        return url
    raise NetworkError(f"{label} must be an https URL (http only on a loopback host)")


@dataclass(frozen=True)
class _Parsed:
    """A SET after steps 1-4's local part: what the key lookup needs."""

    kid: str
    signing_input: bytes
    signature: bytes
    claims: dict[str, Any]


class _ReceiverCore:
    """Configuration, the JWKS cache and the pure verification steps shared by
    both receivers."""

    def __init__(
        self,
        *,
        base_url: str,
        issuer: str,
        audience: str,
        jwks_uri: str | None,
        discovery_url: str | None,
        replay_window_seconds: float,
        clock: Callable[[], float],
    ) -> None:
        """Validate the configuration locally, before any I/O.

        Raises:
            ValidationError: a replay window below seven days, an empty issuer
                or audience, or not exactly one of ``jwks_uri`` /
                ``discovery_url``.
        """
        from axiam_sdk.management._errors import local_refusal

        if replay_window_seconds < MIN_REPLAY_WINDOW_SECONDS:
            raise local_refusal(
                "ssf.receiver",
                "replay_window",
                "must be at least seven days, the transmitter's buffer retention "
                "(CONTRACT.md §32.7)",
            )
        if not issuer or not audience:
            raise local_refusal(
                "ssf.receiver", "issuer", "issuer and audience are required (CONTRACT.md §32.7)"
            )
        if (jwks_uri is None) == (discovery_url is None):
            raise local_refusal(
                "ssf.receiver",
                "jwks_uri",
                "set exactly one of jwks_uri and discovery_url (CONTRACT.md §32.7)",
            )
        self.base_url = base_url
        self.issuer = issuer
        self.audience = audience
        self.jwks_uri = jwks_uri
        self.discovery_url = discovery_url
        self.replay_window = replay_window_seconds
        self.clock = clock
        self.keys: dict[str, jwt.PyJWK] | None = None
        self.fetched_at = 0.0
        self.last_forced: float | None = None

    def __repr__(self) -> str:
        """The configuration, never the provider."""
        source = (
            f"jwks_uri={self.jwks_uri!r}"
            if self.jwks_uri
            else f"discovery_url={self.discovery_url!r}"
        )
        return f"issuer={self.issuer!r}, audience={self.audience!r}, {source}"

    # -- step 1-4 (local part) ------------------------------------------------

    @staticmethod
    def parse(set_token: str) -> _Parsed:
        """Steps 1-3 and the presence of ``kid``.

        Raises:
            SetVerificationError: ``malformed``, ``invalid_type`` or ``invalid_key``.
        """
        parts = set_token.split(".") if isinstance(set_token, str) else []
        if len(parts) != 3:
            raise SetVerificationError(SetFailureReason.MALFORMED, "not three base64url parts")
        try:
            signature = _b64(parts[2])
        except (ValueError, binascii.Error):
            raise SetVerificationError(
                SetFailureReason.MALFORMED, "the signature is not base64url"
            ) from None
        header = _json_object(parts[0])
        claims = _json_object(parts[1])
        if header is None or claims is None:
            raise SetVerificationError(
                SetFailureReason.MALFORMED, "the header or payload is not a JSON object"
            )
        typ = header.get("typ")
        if not isinstance(typ, str) or typ.lower() not in (
            "secevent+jwt",
            "application/secevent+jwt",
        ):
            raise SetVerificationError(SetFailureReason.INVALID_TYPE, "typ is not secevent+jwt")
        if header.get("alg") != "EdDSA":
            raise SetVerificationError(SetFailureReason.INVALID_KEY, "alg is not EdDSA")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise SetVerificationError(SetFailureReason.INVALID_KEY, "no kid")
        # `jwk` and `x5c` header members are never read (§32.9).
        return _Parsed(
            kid=kid,
            signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
            signature=signature,
            claims=claims,
        )

    # -- the JWKS cache ------------------------------------------------------

    def needs_fetch(self) -> bool:
        """Whether the cache is empty or past its lifespan."""
        return self.keys is None or self.clock() - self.fetched_at >= _JWKS_LIFESPAN_SECONDS

    def may_force(self) -> bool:
        """Whether an unknown ``kid`` may trigger a refetch now (once a minute)."""
        return (
            self.last_forced is None
            or self.clock() - self.last_forced >= _FORCED_REFETCH_MIN_INTERVAL_SECONDS
        )

    def store_jwks(self, response: httpx.Response, *, forced: bool) -> None:
        """Replace the cache from a JWKS response.

        Raises:
            NetworkError: a failed or unparseable fetch -- not a SET verdict.
        """
        if forced:
            self.last_forced = self.clock()
        if not response.is_success:
            raise NetworkError(f"ssf: the JWKS fetch failed with HTTP {response.status_code}")
        try:
            document = response.json()
        except ValueError:
            raise NetworkError("ssf: the JWKS is not JSON") from None
        entries = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise NetworkError("ssf: the JWKS has no keys array")
        keys: dict[str, jwt.PyJWK] = {}
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("kid"), str):
                continue
            try:
                keys[entry["kid"]] = jwt.PyJWK(entry)
            except jwt.PyJWTError:
                continue  # a key this helper cannot use is a key it does not have
        self.keys = keys
        self.fetched_at = self.clock()

    def discovered_jwks_uri(self, response: httpx.Response) -> str:
        """The ``jwks_uri`` of an SSF configuration document whose ``issuer``
        is the configured one.

        Raises:
            NetworkError: a failed fetch, another issuer or no ``jwks_uri``.
        """
        if not response.is_success:
            raise NetworkError(
                f"ssf: the SSF configuration fetch failed with HTTP {response.status_code}"
            )
        try:
            document = response.json()
        except ValueError:
            raise NetworkError("ssf: the SSF configuration is not JSON") from None
        if not isinstance(document, dict) or document.get("issuer") != self.issuer:
            raise NetworkError("ssf: the SSF configuration's issuer is not the configured issuer")
        jwks_uri = document.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            raise NetworkError("ssf: the SSF configuration carries no jwks_uri")
        return _check_url("jwks_uri", jwks_uri)

    # -- steps 5-8 -----------------------------------------------------------

    def judge(
        self, parsed: _Parsed, key: jwt.PyJWK | None, expected_jti: str | None
    ) -> SecurityEvent:
        """Steps 5-8 for a SET whose ``kid`` resolved to ``key`` (or did not);
        step 9, the replay store, is the receiver's (:func:`_replayed`).

        Raises:
            SetVerificationError: at the first failing step.
        """
        if key is None:
            raise SetVerificationError(SetFailureReason.INVALID_KEY, "no key for kid in the JWKS")
        # Only an Ed25519 key verifies here: a JWK of another type under the
        # right `kid` is a key this SET cannot have been signed with.
        if not isinstance(key.key, Ed25519PublicKey) or not OKPAlgorithm().verify(
            parsed.signing_input, key.key, parsed.signature
        ):
            raise SetVerificationError(
                SetFailureReason.INVALID_KEY, "the signature does not verify"
            )
        claims = parsed.claims
        iss = claims.get("iss")
        if iss != self.issuer:
            raise SetVerificationError(
                SetFailureReason.INVALID_ISSUER, "iss is not the configured issuer"
            )
        aud = claims.get("aud")
        if not (
            aud == self.audience or (isinstance(aud, list) and any(a == self.audience for a in aud))
        ):
            raise SetVerificationError(
                SetFailureReason.INVALID_AUDIENCE, "aud does not name this receiver"
            )
        if "exp" in claims or "sub" in claims:
            raise SetVerificationError(
                SetFailureReason.INVALID_REQUEST, "a SET carries no exp and no sub"
            )
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise SetVerificationError(SetFailureReason.INVALID_REQUEST, "no jti")
        iat = claims.get("iat")
        if isinstance(iat, bool) or not isinstance(iat, int | float):
            raise SetVerificationError(SetFailureReason.INVALID_REQUEST, "no numeric iat")
        sub_id = claims.get("sub_id")
        if not isinstance(sub_id, dict):
            raise SetVerificationError(SetFailureReason.INVALID_REQUEST, "no sub_id object")
        events = claims.get("events")
        if not isinstance(events, dict) or len(events) != 1:
            raise SetVerificationError(
                SetFailureReason.INVALID_REQUEST, "events must have exactly one member"
            )
        if expected_jti is not None and expected_jti != jti:
            raise SetVerificationError(
                SetFailureReason.INVALID_REQUEST, "the poll key is not the SET's jti"
            )
        ((event_type, event),) = events.items()
        txn = claims.get("txn")
        return SecurityEvent(
            jti=jti,
            iat=iat,
            iss=iss,
            aud=aud,
            txn=txn if isinstance(txn, str) else None,
            event_type=event_type,
            event=event if isinstance(event, dict) else {},
            sub_id=sub_id,
        )

    # -- poll ----------------------------------------------------------------

    def poll_url(self, stream_id: str) -> str:
        """``{base URL}/ssf/v1/poll/{stream_id}``, the id path-escaped."""
        return f"{self.base_url.rstrip('/')}/ssf/v1/poll/{quote(stream_id, safe='')}"

    @staticmethod
    def poll_body(
        max_events: int | None,
        return_immediately: bool | None,
        ack: Sequence[str] | None,
        set_errs: Mapping[str, SetErr] | None,
    ) -> dict[str, Any]:
        """The RFC 8936 body: only the members the caller set, as given."""
        body: dict[str, Any] = {}
        if max_events is not None:
            body["maxEvents"] = max_events
        if return_immediately is not None:
            body["returnImmediately"] = return_immediately
        if ack is not None:
            body["ack"] = list(ack)
        if set_errs is not None:
            body["setErrs"] = {jti: entry.to_wire() for jti, entry in set_errs.items()}
        return body

    @staticmethod
    def poll_error(response: httpx.Response) -> Exception:
        """A failed poll mapped like a management call (400 -> ValidationError,
        404 -> NotFoundError, ...)."""
        from axiam_sdk.management._request import ManagementCall, _raise_for_status

        call = ManagementCall(
            operation="ssf.poll",
            method="POST",
            path_template="/ssf/v1/poll/{stream_id}",
            path=response.request.url.path,
        )
        try:
            _raise_for_status(call, response)
        except Exception as exc:  # noqa: BLE001 - the mapped error is the result
            return exc
        return NetworkError("ssf.poll: unexpected status")  # pragma: no cover - 2xx never here

    @staticmethod
    def poll_reply(response: httpx.Response) -> tuple[list[tuple[str, Any]], bool]:
        """The ``sets`` map as ``(jti, SET)`` pairs, and ``moreAvailable``.

        Raises:
            NetworkError: a body that is not the RFC 8936 JSON object.
        """
        try:
            reply = response.json()
        except ValueError:
            raise NetworkError("ssf.poll: the response is not JSON") from None
        if not isinstance(reply, dict):
            raise NetworkError("ssf.poll: the response is not a JSON object")
        sets = reply.get("sets")
        pairs = list(sets.items()) if isinstance(sets, dict) else []
        return pairs, reply.get("moreAvailable") is True


def _replayed() -> SetVerificationError:
    """Step 9's refusal: the store already held the ``jti``."""
    return SetVerificationError(SetFailureReason.REPLAYED, "jti already seen")


def _bearer(token: TokenValue) -> dict[str, str]:
    """The poll's headers: the provider's bearer, and JSON."""
    value = token.get_secret_value() if isinstance(token, SecretStr) else token
    return {"Authorization": f"Bearer {value}", "Accept": "application/json"}


def _left_unjudged(
    result: SsfPollResult, pairs: list[tuple[str, Any]], jti: str, failure: Exception
) -> SsfPollResult:
    """``result`` with the SET under ``jti`` and every one after it left
    unjudged by ``failure`` (§34.2 P1): none of them was recorded."""
    keys = [key for key, _ in pairs]
    return replace(result, unjudged=keys[keys.index(jti) :], unjudged_error=failure)


def _no_provider() -> AuthError:
    """The local refusal of a poll without a token provider."""
    return AuthError(
        "ssf.poll needs an access_token_provider (a client-credentials token carrying "
        "ssf.manage; CONTRACT.md §32.7)"
    )


class SsfReceiver:
    """The SSF receiver helper (CONTRACT.md §32.7), over a sync client.

    ``client`` supplies the transport -- its §6 TLS policy fetches the JWKS, and
    its base URL is the transmitter root :meth:`poll` calls -- but none of its
    session: every request here goes out on the session-free transport.
    """

    def __init__(
        self,
        client: AxiamClient,
        *,
        issuer: str,
        audience: str,
        jwks_uri: str | None = None,
        discovery_url: str | None = None,
        access_token_provider: AccessTokenProvider | None = None,
        replay_window_seconds: float = MIN_REPLAY_WINDOW_SECONDS,
        replay_store: ReplayStore | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Configure the receiver: ``issuer`` (compared to ``iss`` exactly),
        ``audience`` (the stream's), exactly one of ``jwks_uri`` /
        ``discovery_url`` (an SSF configuration document whose ``issuer`` must
        equal ``issuer`` and whose ``jwks_uri`` is used), the poll bearer's
        provider, and the replay window (at least seven days) and store.

        Raises:
            ValidationError: locally, for a configuration §32.7 refuses.
        """
        self._client = client
        self._core = _ReceiverCore(
            base_url=client._session.base_url,
            issuer=issuer,
            audience=audience,
            jwks_uri=jwks_uri,
            discovery_url=discovery_url,
            replay_window_seconds=replay_window_seconds,
            clock=clock,
        )
        self._store: ReplayStore = replay_store or MemoryReplayStore()
        self._provider = access_token_provider
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        """The configuration, never the provider or a key."""
        return f"SsfReceiver({self._core!r})"

    def _get(self, url: str) -> httpx.Response:
        """A session-free ``GET``, transport failures as ``NetworkError``."""
        try:
            return self._client._session.bare_sync_client.send(httpx.Request("GET", url))
        except httpx.TransportError as exc:
            raise network_error_from_transport("ssf", exc) from None

    def _fetch_jwks(self, *, forced: bool) -> None:
        """(Re)load the JWKS, resolving the discovery document first if needed."""
        core = self._core
        if core.jwks_uri is None:
            assert core.discovery_url is not None
            core.jwks_uri = core.discovered_jwks_uri(
                self._get(_check_url("discovery_url", core.discovery_url))
            )
        core.store_jwks(self._get(_check_url("jwks_uri", core.jwks_uri)), forced=forced)

    def _key_for(self, kid: str) -> jwt.PyJWK | None:
        """The key for ``kid``: cached, or after one forced refetch at most."""
        with self._lock:
            core = self._core
            if core.needs_fetch():
                self._fetch_jwks(forced=False)
            assert core.keys is not None
            if kid not in core.keys and core.may_force():
                self._fetch_jwks(forced=True)
            return core.keys.get(kid)

    def _verify(self, set_token: str, expected_jti: str | None) -> SecurityEvent:
        """Steps 1-9, the key lookup between them; the ``jti`` is recorded last."""
        parsed = self._core.parse(set_token)
        event = self._core.judge(parsed, self._key_for(parsed.kid), expected_jti)
        if not self._store.check_and_record(event.jti, self._core.replay_window):
            raise _replayed()
        return event

    def verify_set(self, set_token: str) -> SecurityEvent:
        """Verify one compact SET (§32.7), refusing at the first failing step:

        1. three base64url parts, a JSON header and payload [``malformed``];
        2. ``typ`` ``secevent+jwt`` or ``application/secevent+jwt``, any case
           [``invalid_type``];
        3. ``alg`` exactly ``EdDSA`` [``invalid_key``];
        4. the ``kid`` in the configured JWKS -- on a miss, one refetch, at
           most once a minute [``invalid_key``];
        5. the Ed25519 signature [``invalid_key``];
        6. ``iss`` equal to the configured issuer [``invalid_issuer``];
        7. ``aud`` equal to, or an array containing, the audience
           [``invalid_audience``];
        8. no ``exp``, no ``sub``; a non-empty ``jti``, a numeric ``iat``, an
           object ``sub_id``; exactly one ``events`` member [``invalid_request``];
        9. a ``jti`` not seen within the replay window [``replayed``] --
           recorded only once steps 1-8 passed.

        A SET that verifies has been **recorded**: verifying it again is
        ``replayed``. Answer a push refusal with ``400 {"err":
        exc.set_failure_reason.push_error_code()}``.

        Raises:
            SetVerificationError: the refusal, an ``AuthError`` carrying the
                reason.
            NetworkError: the JWKS (or discovery document) could not be
                fetched -- not a verdict on the SET.
            Exception: whatever the replay store raised when it could not
                answer -- not a verdict either; the ``jti`` was not recorded.
        """
        return self._verify(set_token, None)

    def poll(
        self,
        stream_id: str,
        *,
        max_events: int | None = None,
        return_immediately: bool | None = None,
        ack: Sequence[str] | None = None,
        set_errs: Mapping[str, SetErr] | None = None,
    ) -> SsfPollResult:
        """Poll the stream's RFC 8936 endpoint, ``{root}/ssf/v1/poll/{stream_id}``,
        with a bearer from ``access_token_provider``, and verify every SET.

        ``ack`` and ``set_errs`` are sent exactly as given, and only when given.
        **Nothing is acknowledged on your behalf**: acknowledge, on the next
        call, the ``jti`` values you processed, and pass each refused one in
        ``set_errs`` (``SetErr.from_reason(refused.reason)``) -- except a
        ``replayed`` one, which this receiver accepted earlier: acknowledge it
        (§34.2 P2). A SET you neither acknowledge nor refuse is re-offered --
        and, having been recorded when it verified, then reads as ``replayed``.

        Retried per §16 on a transport failure, ``5xx``, ``408`` or ``429``,
        never on another ``4xx`` (``400`` is a ``ValidationError``, ``404`` a
        ``NotFoundError``). A SET whose verified ``jti`` is not its map key is
        refused ``invalid_request``, a non-string SET ``malformed``.

        **Never keeps a ``jti`` it does not return** (§34.2 P1): a failure that
        is no verdict on a SET -- a JWKS or discovery fetch that fails, a replay
        store that cannot answer -- stops verification there. The SETs judged
        before it are returned as usual; that SET and every one after it are
        listed in ``unjudged`` with the failure in ``unjudged_error``, are not
        recorded, and are offered again by the transmitter: neither acknowledge
        nor refuse them.

        Raises:
            AuthError: locally, when no ``access_token_provider`` was configured.
        """
        self._client._ensure_open()
        if self._provider is None:
            raise _no_provider()
        core = self._core
        url = core.poll_url(stream_id)
        body = core.poll_body(max_events, return_immediately, ack, set_errs)
        headers = _bearer(self._provider())

        def attempt(_: int) -> httpx.Response | Exception:
            """One §16 attempt; a decisive failure is returned, not raised."""
            request = httpx.Request("POST", url, headers=headers, json=body)
            try:
                response = self._client._session.bare_sync_client.send(request)
            except httpx.TransportError as exc:
                raise network_error_from_transport("ssf.poll", exc) from None
            if response.is_success:
                return response
            error = core.poll_error(response)
            if status_is_retryable(response.status_code):
                raise error
            return error

        outcome = retry_sync(
            attempt,
            operation="ssf.poll",
            enabled=self._client._retry_enabled,
            telemetry=self._client._telemetry,
        )
        if isinstance(outcome, Exception):
            raise outcome
        pairs, more = core.poll_reply(outcome)
        result = SsfPollResult(more_available=more)
        for jti, set_token in pairs:
            if not isinstance(set_token, str):
                result.refused.append(RefusedSet(jti, SetFailureReason.MALFORMED))
                continue
            try:
                result.events.append(self._verify(set_token, jti))
            except SetVerificationError as refusal:
                result.refused.append(RefusedSet(jti, refusal.set_failure_reason))
            except Exception as failure:  # noqa: BLE001 - no verdict (§34.2 P1, P3)
                return _left_unjudged(result, pairs, jti, failure)
        return result


class AsyncSsfReceiver:
    """The SSF receiver helper (CONTRACT.md §32.7), over an async client.

    Identical to :class:`SsfReceiver` -- the same configuration, the same nine
    steps, the same poll -- with ``await``. The ``access_token_provider`` may
    return the token or an awaitable of it.
    """

    def __init__(
        self,
        client: AsyncAxiamClient,
        *,
        issuer: str,
        audience: str,
        jwks_uri: str | None = None,
        discovery_url: str | None = None,
        access_token_provider: AsyncAccessTokenProvider | None = None,
        replay_window_seconds: float = MIN_REPLAY_WINDOW_SECONDS,
        replay_store: ReplayStore | AsyncReplayStore | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """See :class:`SsfReceiver`. ``replay_store`` may also be an
        :class:`AsyncReplayStore`, whose ``check_and_record`` is awaited.

        Raises:
            ValidationError: locally, for a configuration §32.7 refuses.
        """
        self._client = client
        self._core = _ReceiverCore(
            base_url=client._session.base_url,
            issuer=issuer,
            audience=audience,
            jwks_uri=jwks_uri,
            discovery_url=discovery_url,
            replay_window_seconds=replay_window_seconds,
            clock=clock,
        )
        self._store: ReplayStore | AsyncReplayStore = replay_store or MemoryReplayStore()
        self._provider = access_token_provider
        self._lock: asyncio.Lock | None = None

    def __repr__(self) -> str:
        """The configuration, never the provider or a key."""
        return f"AsyncSsfReceiver({self._core!r})"

    async def _get(self, url: str) -> httpx.Response:
        """A session-free ``GET``, transport failures as ``NetworkError``."""
        try:
            return await self._client._session.bare_async_client.send(httpx.Request("GET", url))
        except httpx.TransportError as exc:
            raise network_error_from_transport("ssf", exc) from None

    async def _fetch_jwks(self, *, forced: bool) -> None:
        """(Re)load the JWKS, resolving the discovery document first if needed."""
        core = self._core
        if core.jwks_uri is None:
            assert core.discovery_url is not None
            core.jwks_uri = core.discovered_jwks_uri(
                await self._get(_check_url("discovery_url", core.discovery_url))
            )
        core.store_jwks(await self._get(_check_url("jwks_uri", core.jwks_uri)), forced=forced)

    async def _key_for(self, kid: str) -> jwt.PyJWK | None:
        """The key for ``kid``: cached, or after one forced refetch at most."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            core = self._core
            if core.needs_fetch():
                await self._fetch_jwks(forced=False)
            assert core.keys is not None
            if kid not in core.keys and core.may_force():
                await self._fetch_jwks(forced=True)
            return core.keys.get(kid)

    async def _verify(self, set_token: str, expected_jti: str | None) -> SecurityEvent:
        """Steps 1-9, the key lookup between them; the ``jti`` is recorded last,
        awaiting an :class:`AsyncReplayStore`."""
        parsed = self._core.parse(set_token)
        event = self._core.judge(parsed, await self._key_for(parsed.kid), expected_jti)
        fresh = self._store.check_and_record(event.jti, self._core.replay_window)
        if inspect.isawaitable(fresh):
            fresh = await fresh
        if not fresh:
            raise _replayed()
        return event

    async def verify_set(self, set_token: str) -> SecurityEvent:
        """Async twin of :meth:`SsfReceiver.verify_set`.

        Raises:
            SetVerificationError: the refusal.
            NetworkError: the JWKS could not be fetched.
        """
        return await self._verify(set_token, None)

    async def poll(
        self,
        stream_id: str,
        *,
        max_events: int | None = None,
        return_immediately: bool | None = None,
        ack: Sequence[str] | None = None,
        set_errs: Mapping[str, SetErr] | None = None,
    ) -> SsfPollResult:
        """Async twin of :meth:`SsfReceiver.poll`. **Nothing is acknowledged on
        your behalf**, and a ``jti`` is never kept that is not returned: SETs a
        failed fetch or store left unjudged are in ``unjudged``, unrecorded.

        Raises:
            AuthError: locally, when no ``access_token_provider`` was configured.
        """
        self._client._ensure_open()
        if self._provider is None:
            raise _no_provider()
        core = self._core
        url = core.poll_url(stream_id)
        body = core.poll_body(max_events, return_immediately, ack, set_errs)
        token = self._provider()
        if inspect.isawaitable(token):
            token = await token
        headers = _bearer(token)

        async def attempt(_: int) -> httpx.Response | Exception:
            """One §16 attempt; a decisive failure is returned, not raised."""
            request = httpx.Request("POST", url, headers=headers, json=body)
            try:
                response = await self._client._session.bare_async_client.send(request)
            except httpx.TransportError as exc:
                raise network_error_from_transport("ssf.poll", exc) from None
            if response.is_success:
                return response
            error = core.poll_error(response)
            if status_is_retryable(response.status_code):
                raise error
            return error

        outcome = await retry_async(
            attempt,
            operation="ssf.poll",
            enabled=self._client._retry_enabled,
            telemetry=self._client._telemetry,
        )
        if isinstance(outcome, Exception):
            raise outcome
        pairs, more = core.poll_reply(outcome)
        result = SsfPollResult(more_available=more)
        for jti, set_token in pairs:
            if not isinstance(set_token, str):
                result.refused.append(RefusedSet(jti, SetFailureReason.MALFORMED))
                continue
            try:
                result.events.append(await self._verify(set_token, jti))
            except SetVerificationError as refusal:
                result.refused.append(RefusedSet(jti, refusal.set_failure_reason))
            except Exception as failure:  # noqa: BLE001 - no verdict (§34.2 P1, P3)
                return _left_unjudged(result, pairs, jti, failure)
        return result
