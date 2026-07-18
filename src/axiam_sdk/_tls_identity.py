"""Shared client-certificate (mTLS) identity helpers (CONTRACT.md §6.1).

AXIAM authenticates IoT devices and service accounts by **mutual TLS**: the
client presents an X.509 identity certificate (signed by the tenant's
organization CA) alongside its PEM private key. This module holds the small,
transport-agnostic helpers that both the REST session (``_session.py``, httpx)
and the gRPC TLS builder (``grpc/_tls.py``) use to accept that identity as a
PEM certificate chain plus a PEM private key, given as ``str`` or ``bytes``.

Security note (CONTRACT.md §6.1 rule 3 / §7): the private key is secret
material. Nothing in this module logs it, exposes it via a public getter, or
retains it as a module-level attribute — callers pass it straight through into
the platform TLS stack. Strict server verification (§6) is never relaxed by
presenting a client certificate; this identity path is kept separate from all
server-verification code so the CI TLS-bypass lint gate is not tripped.
"""

from __future__ import annotations


def normalize_pem(value: str | bytes) -> bytes:
    """Coerce a PEM certificate chain or private key into ``bytes``.

    The public ``client_cert``/``client_key`` parameters accept either a
    ``str`` (PEM text) or ``bytes`` (raw PEM) per CONTRACT.md §6.1; the TLS
    stacks (``ssl.SSLContext`` files and ``grpc.ssl_channel_credentials``)
    ultimately want bytes. A ``str`` is encoded as UTF-8; ``bytes`` is returned
    unchanged.

    Args:
        value: The PEM certificate chain or private key, as ``str`` or
            ``bytes``.

    Returns:
        The same PEM material as ``bytes``.
    """
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def validate_client_identity(
    client_cert: str | bytes | None, client_key: str | bytes | None
) -> None:
    """Validate that a client certificate and private key were supplied together.

    mTLS is opt-in (CONTRACT.md §6.1 rule 5): omitting both leaves the SDK's
    default bearer-cookie behavior unchanged. But an identity is only usable as
    a *pair* — a certificate without its key (or vice versa) is a configuration
    error and MUST fail at construction time (rule 1).

    Args:
        client_cert: The PEM certificate chain, or ``None``.
        client_key: The PEM private key, or ``None``.

    Raises:
        ValueError: if exactly one of ``client_cert``/``client_key`` is given.
    """
    if (client_cert is None) != (client_key is None):
        raise ValueError(
            "client_cert and client_key must be provided together to configure "
            "mTLS (CONTRACT.md §6.1); received only one of the two"
        )
