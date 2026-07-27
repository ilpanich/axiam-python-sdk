"""Typed Pydantic v2 models (D-06/D-07/D-21).

Token-bearing fields use ``SecretStr`` (D-07) — it *is* the Python §7
``Sensitive`` type: it redacts its value in ``repr``/``str``/``model_dump``
and only exposes the raw value via ``.get_secret_value()``.
"""

from __future__ import annotations

from pydantic import BaseModel, SecretStr


class LoginResult(BaseModel):
    """Result of ``AxiamClient.login()`` / ``AsyncAxiamClient.login()`` (D-21, SDK-Q08).

    A single model with a literal ``mfa_required: bool`` field — the caller
    checks the flag, and if true, calls ``verify_mfa(mfa_token, code)``.

    ``mfa_token`` is the SDK's field-name for the server's wire-level
    ``challenge_token`` (``MfaRequiredResponse.challenge_token`` /
    ``MfaVerifyRequest.challenge_token`` in
    ``crates/axiam-api-rest/src/handlers/auth.rs``) — a snake_case-preserving
    rename matching this SDK's ``verify_mfa(mfa_token, code)`` signature.
    """

    mfa_required: bool
    mfa_token: SecretStr | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    session_id: str | None = None
    expires_in: int | None = None

    model_config = {"frozen": True}


class User(BaseModel):
    """An authenticated identity, as returned by ``GET /api/v1/auth/me`` or
    resolved locally from a verified JWT's claims."""

    user_id: str
    tenant_id: str
    username: str | None = None
    email: str | None = None
    permissions: list[str] = []

    model_config = {"frozen": True}


class AccessCheck(BaseModel):
    """A single authorization check request (``check_access``/``can``)."""

    action: str
    resource_id: str
    scope: str | None = None

    model_config = {"frozen": True}


class AccessResult(BaseModel):
    """The result of a single authorization check."""

    allowed: bool
    reason: str | None = None

    model_config = {"frozen": True}


class BatchCheckResult(BaseModel):
    """The result of a batch authorization check (``batch_check``) — one
    ``AccessResult`` per input ``AccessCheck``, in the same order."""

    results: list[AccessResult]

    model_config = {"frozen": True}


class OidcConfiguration(BaseModel):
    """The OIDC Discovery 1.0 metadata document served by ``GET
    /.well-known/openid-configuration`` (wire schema ``OidcDiscoveryDocument``,
    CONTRACT.md §12.1). Every field is required by the server's schema.

    Field names keep their wire (snake_case) spelling deliberately — this
    IS a protocol document, cross-referenced against OIDC Discovery 1.0 /
    RFC 8414 by field name, so renaming would be a lossy translation
    (mirrors ``the TypeScript SDK's src/node/oidcTypes.ts``).

    ``issuer`` is the **authoritative** issuer for ID-token validation
    (CONTRACT.md §12.4 rule 3). It may legitimately differ from the client's
    ``base_url`` when AXIAM runs behind a proxy, so this SDK never rejects a
    document on an issuer/base-URL mismatch (§12.3 rule 6). Likewise
    ``jwks_uri`` is read from here rather than hardcoded.
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    revocation_endpoint: str
    introspection_endpoint: str
    response_types_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    scopes_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    claims_supported: list[str]
    grant_types_supported: list[str]

    model_config = {"frozen": True}


class IdTokenClaims(BaseModel):
    """The decoded, **already-validated** ID-token claim set carried by
    ``OidcTokenSet.id_claims`` (CONTRACT.md §12.1).

    Claim names are kept verbatim in their JWT/OIDC spelling (``iss``,
    ``sub``, ``aud``, ...) rather than renamed: they are protocol
    identifiers a caller cross-references against OIDC Core. ``extra =
    "allow"`` is mandated by §12.1 — the ID token's full claim set is not
    enumerated by ``openapi.json`` (the field is typed as an opaque string
    there), so unknown claims MUST be preserved and MUST NOT be rejected.
    """

    iss: str
    sub: str
    aud: str | list[str]
    exp: int
    iat: int
    nbf: int | None = None
    nonce: str | None = None
    azp: str | None = None

    model_config = {"frozen": True, "extra": "allow"}


class AuthorizationRequest(BaseModel):
    """The result of ``oidc_begin`` — everything the caller needs to start
    an authorization-code + PKCE login (CONTRACT.md §12.1).

    **The caller owns this state** (§12.3 rule 1). The SDK stores nothing:
    it keeps no copy of ``state``, ``nonce``, or ``code_verifier`` in
    process-global state or any implicit cache. Persist all three in your
    own HTTP session (or in an ``OidcStateStore``), redirect the browser to
    ``url``, and pass ``nonce`` + ``code_verifier`` back into
    ``oidc_exchange`` when the code arrives.
    """

    url: str
    state: str
    nonce: str
    code_verifier: SecretStr

    model_config = {"frozen": True}


class OidcTokenSet(BaseModel):
    """A token set returned by the OAuth2 token endpoint (wire schema
    ``TokenResponse``), returned by ``oidc_exchange``, ``oidc_refresh``, and
    ``login_client_credentials`` (CONTRACT.md §12.1).

    ``access_token``, ``refresh_token``, and ``id_token`` are ``SecretStr``
    (§12.5) — the Python §7 ``Sensitive`` equivalent: ``repr``/``str``/
    ``model_dump`` all redact them, and the raw value is reachable only
    through ``.get_secret_value()``.

    ``id_claims`` is present exactly when ``id_token`` is, and holds the
    **already-validated** claim set (§12.4) — validation happens before
    this object is ever constructed, so an ``OidcTokenSet`` in your hands is
    never partially trusted (§12.4 rule 7).
    """

    access_token: SecretStr
    token_type: str
    expires_in: int
    scope: str | None = None
    refresh_token: SecretStr | None = None
    id_token: SecretStr | None = None
    id_claims: IdTokenClaims | None = None

    model_config = {"frozen": True}


class IntrospectionResult(BaseModel):
    """The RFC 7662 introspection result (wire schema
    ``IntrospectionResponse``, CONTRACT.md §12.1). Only ``active`` is
    guaranteed; the server omits the metadata fields for an inactive
    token."""

    active: bool
    sub: str | None = None
    client_id: str | None = None
    scope: str | None = None
    token_type: str | None = None
    exp: int | None = None
    iat: int | None = None

    model_config = {"frozen": True}


class SsoStartResult(BaseModel):
    """The result of ``sso_start`` (wire schema ``OidcStartResponse``,
    CONTRACT.md §12.1).

    There is deliberately **no nonce**: on the federation path the nonce
    never leaves the server (§12.1 note 7). Round-trip ``state`` into
    ``sso_complete`` unmodified — the server stores it single-use with a
    10-minute TTL and recovers the whole login context from it.
    """

    authorize_url: str
    state: str
    expires_in_secs: int

    model_config = {"frozen": True}


class SsoCompleteResult(BaseModel):
    """The result of ``sso_complete`` (wire schema
    ``SsoLoginSuccessResponse``, CONTRACT.md §12.1).

    Carries **no token material** — the session arrives as ``Set-Cookie``,
    so the §4 cookie jar is what actually captures it (§12.1 note 6)."""

    user_id: str
    session_id: str
    expires_in: int
    redirect_uri: str

    model_config = {"frozen": True}


class UserInfo(BaseModel):
    """The authenticated caller's OIDC-style identity claims returned by the
    gRPC-only ``get_user_info`` operation (CONTRACT.md §1.1) — the low-latency
    counterpart of the server's REST ``GET /oauth2/userinfo`` endpoint.

    ``sub``, ``tenant_id`` and ``org_id`` are always populated. ``email`` is
    present only when the access token carries the ``email`` scope, and
    ``preferred_username`` only with the ``profile`` scope; the server gates
    these exactly as the REST endpoint does, and the SDK maps an absent
    protobuf ``optional`` field to ``None``."""

    sub: str
    tenant_id: str
    org_id: str
    email: str | None = None
    preferred_username: str | None = None

    model_config = {"frozen": True}
