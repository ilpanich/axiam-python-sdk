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
    """Whether the checked action is permitted.

    **This field alone carries the outcome.** :attr:`reason_code` explains it
    and never contradicts it.
    """

    reason: str | None = None
    """Human-readable explanation, when the server sent one."""

    reason_code: str | None = None
    """Machine-readable decision reason (CONTRACT.md §11 rule 9, B1
    deny-override): ``"allowed"``, ``"no_grant"`` or ``"denied_by_rule"``.

    **The two refusals mean opposite things to the person on the other end.**
    ``no_grant`` says *ask an admin for access*; ``denied_by_rule`` says *an
    admin has already decided*. An application that cannot tell them apart
    sends users to raise tickets that will be refused — which is why the
    contract forbids collapsing them into a bare ``False``.

    ``None`` when the server omits the field: a newer SDK against an older
    server treats it as absent, never as an error. An unrecognised value is
    surfaced verbatim and never changes :attr:`allowed`, which is why this is
    a plain ``str`` rather than an enum — a code the SDK has never heard of
    still reaches the caller intact.
    """

    model_config = {"frozen": True}


class ReasonCode:
    """The three ``reason_code`` values CONTRACT.md §11 rule 9 defines.

    Constants rather than an ``Enum``, so an unrecognised server value is
    still a valid :attr:`AccessResult.reason_code` and reaches the caller — an
    ``Enum`` would force the SDK to drop it or raise on it.
    """

    ALLOWED = "allowed"
    """An allow grant matched and no deny did."""

    NO_GRANT = "no_grant"
    """Nothing matched — default deny. *Ask an admin for access.*"""

    DENIED_BY_RULE = "denied_by_rule"
    """An explicit deny rule matched and overrode any allow. *An admin has
    already decided.*"""


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

    device_authorization_endpoint: str | None = None
    """RFC 8628 device authorization endpoint (§14.1).

    Optional because a server that does not implement the device grant does
    not advertise it, and because this document may come from a non-AXIAM OP.
    Its absence is an error at call time, never a cue to build the URL by
    concatenation.
    """

    end_session_endpoint: str | None = None
    """OIDC RP-Initiated Logout 1.0 endpoint (§12.7.2 rule 1).

    Optional for the same reason, and the rule is stricter here: §12.7.2
    rule 1 forbids synthesising this URL from the issuer. Code that
    concatenates works against AXIAM and breaks against every other OP the
    same application is pointed at.
    """

    backchannel_logout_supported: bool | None = None
    """Whether the OP sends back-channel logout tokens."""

    backchannel_logout_session_supported: bool | None = None
    """Whether those logout tokens carry ``sid``. AXIAM always sends it."""

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


class DeviceAuthorization(BaseModel):
    """The ``DeviceAuthorizationResponse`` — what the device shows its user,
    plus the ``device_code`` it polls with (CONTRACT.md §14.1).

    ``device_code`` is a :class:`~pydantic.SecretStr` (§14.5): a bearer
    credential for the lifetime of the grant. ``user_code`` deliberately is
    **not** — it exists to be read aloud and typed by a human, and wrapping it
    would defeat the one thing it is for. Neither may be logged; displaying
    ``user_code`` is the caller's job.
    """

    device_code: SecretStr
    """The device's polling credential (§14.5 secret)."""

    user_code: str
    """The short code the human types into the verification page."""

    verification_uri: str
    """Where the human goes to enter :attr:`user_code`."""

    verification_uri_complete: str | None = None
    """The verification URI with the user code already embedded, when the
    server sent one — prefer it when the device can render a QR code.

    Never synthesised by concatenation when absent (§14.3): its format is the
    server's to choose.
    """

    expires_in: int
    """Seconds until the grant expires. Polling stops here (§14.2 rule 4)."""

    interval: int
    """Seconds between polls, from the response, defaulted to 5 s when the
    server omitted it (§14.2 rule 2)."""

    model_config = {"frozen": True}


class ExchangedToken(BaseModel):
    """The result of an RFC 8693 exchange (wire schema
    ``TokenExchangeResponse``, CONTRACT.md §15.1).

    **There is no ``refresh_token`` field, and that is deliberate** (§15.2
    rule 4). RFC 8693 issues none, so the model cannot represent one: an
    application that wants a fresh exchanged token re-runs the exchange. This
    result also never enters the §9 single-flight refresh guard — there is
    nothing to refresh.
    """

    access_token: SecretStr
    """The issued token (§15.5 secret)."""

    issued_token_type: str
    """What the server actually issued. Mandatory in RFC 8693 §2.2.1 and
    surfaced rather than dropped (§15.2 rule 6), so a client that asked for
    one type and got another can tell."""

    token_type: str
    """The token type (``Bearer``)."""

    expires_in: int
    """Lifetime in seconds — never longer than the subject token's remaining
    life, since the server caps it so an exchange cannot launder lifetime."""

    scope: str | None = None
    """**The granted scope, which may be narrower than requested** even on
    success (§15.2 rule 7). Read it rather than assuming the request was
    honoured verbatim."""

    model_config = {"frozen": True}


class VerifiedLogoutToken(BaseModel):
    """What a verified back-channel logout token names (CONTRACT.md §12.7.3).

    Deliberately **not** a bare ``bool``: the RP has to know *which* session to
    end, and a verifier that only says "valid" would force the caller to
    re-parse the token themselves, with none of the checks this model is proof
    of.
    """

    sid: str | None = None
    """The session that ended. **When present, end only this session** —
    falling back to "every session for ``sub``" is over-reach the AXIAM server
    itself refuses to make."""

    sub: str | None = None
    """The subject whose session ended."""

    jti: str
    """Replay identifier.

    **The RP dedups on this, not the SDK.** Back-channel delivery is
    at-least-once with retry, so a valid token legitimately arrives twice; the
    SDK has no durable store and an in-memory guard would silently drop a real
    second logout after a restart. Surfaced, never consumed.
    """

    model_config = {"frozen": True}
