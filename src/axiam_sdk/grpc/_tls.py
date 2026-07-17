"""Strict-TLS gRPC channel credentials (CF-03/SC#3, T-19-12).

Mirrors ``the Go SDK's grpc/tls.go``: builds channel credentials via
``grpc.ssl_channel_credentials`` — root certs from a caller-supplied custom
CA PEM when provided, else the system trust roots. This module never
constructs a plaintext/unencrypted channel anywhere in this package
(T-19-12; CI grep gate in 19-07). The only escape hatch is ``custom_ca`` (a
CA bundle PEM path), never a boolean bypass.
"""

from __future__ import annotations

import grpc
import grpc.aio

from axiam_sdk._tls_identity import normalize_pem, validate_client_identity


def build_channel_credentials(
    custom_ca: str | None = None,
    client_cert: str | bytes | None = None,
    client_key: str | bytes | None = None,
) -> grpc.ChannelCredentials:
    """Build strict TLS channel credentials via ``grpc.ssl_channel_credentials``.

    When ``custom_ca`` is supplied, it is read as a PEM-encoded CA bundle
    file path and used as the root certificate for verification (mirrors
    the Go SDK's ``customCAPEM`` parameter). When omitted, ``grpc`` falls
    back to the system trust roots. Certificate verification is never
    disabled by this function — this is the ONLY TLS-related construction
    point the gRPC transport exposes (CONTRACT.md §6, SC#3 absolute
    prohibition).

    When ``client_cert``/``client_key`` are supplied (mutual TLS, CONTRACT.md
    §6.1), the PEM certificate chain and PEM private key are passed straight to
    ``grpc.ssl_channel_credentials`` (which accepts PEM ``bytes`` directly), so
    the same client identity applies to the gRPC transport as to REST (§6.1
    rule 4). They must be supplied together; presenting a client certificate
    never relaxes server verification (§6.1 rule 2). The private key is secret
    material and is neither logged nor retained here (§6.1 rule 3 / §7).

    Args:
        custom_ca: Optional path to a PEM CA bundle used as the verification
            root; ``None`` falls back to the system trust roots.
        client_cert: Optional PEM client-certificate chain (``str`` or
            ``bytes``) for mTLS; must be given together with ``client_key``.
        client_key: Optional PEM private key (``str`` or ``bytes``) matching
            ``client_cert``; must be given together with ``client_cert``.

    Returns:
        Strict ``grpc.ChannelCredentials`` for a secure channel.

    Raises:
        ValueError: if exactly one of ``client_cert``/``client_key`` is given.
    """
    validate_client_identity(client_cert, client_key)

    root_certificates: bytes | None = None
    if custom_ca:
        with open(custom_ca, "rb") as f:
            root_certificates = f.read()

    private_key: bytes | None = normalize_pem(client_key) if client_key is not None else None
    certificate_chain: bytes | None = (
        normalize_pem(client_cert) if client_cert is not None else None
    )

    return grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain,
    )
