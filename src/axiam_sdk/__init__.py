"""Official Python client SDK for AXIAM (Access eXtended Identity and
Authorization Management).

Re-exports the public surface: the sync :class:`AxiamClient` and async
:class:`AsyncAxiamClient` REST entry points, the ``AuthError``/``AuthzError``/
``NetworkError`` exception taxonomy (CONTRACT.md §2), and the request/response
models (``LoginResult``, ``User``, ``AccessCheck``, ``AccessResult``,
``BatchCheckResult``, ``UserInfo``). See CONTRACT.md §1-§10 for the
cross-language behavioral contract this SDK conforms to.

This module MUST remain importable with ONLY the runtime dependencies
declared in ``[project.dependencies]`` (httpx, grpcio, aio-pika, pydantic,
PyJWT) — the optional web-framework integrations (``axiam_sdk.fastapi``,
``axiam_sdk.django``, see ``[project.optional-dependencies]``) MUST NOT be
imported from here.
"""

from axiam_sdk._account import MfaEnrollment, PasswordResetContext
from axiam_sdk._async_client import AsyncAxiamClient
from axiam_sdk._client import AxiamClient
from axiam_sdk._errors import AuthError, AuthzError, NetworkError, OAuthProtocolError
from axiam_sdk._models import (
    AccessCheck,
    AccessResult,
    AuthorizationRequest,
    BatchCheckResult,
    DeviceAuthorization,
    ExchangedToken,
    IdTokenClaims,
    IntrospectionResult,
    LoginResult,
    OidcConfiguration,
    OidcTokenSet,
    PushedAuthorizationRequest,
    ReasonCode,
    RequestedPermission,
    RequestingPartyToken,
    ResourceSet,
    RptPermission,
    SsoCompleteResult,
    SsoStartResult,
    UmaChallenge,
    User,
    UserInfo,
    VerifiedLogoutToken,
)
from axiam_sdk._oidc import (
    ACCESS_TOKEN_TYPE,
    JWT_TOKEN_TYPE,
    UMA_CLAIM_TOKEN_FORMAT,
    UMA_PROTECTION_SCOPE,
    UMA_TICKET_GRANT_TYPE,
    UmaChallenger,
    uma_challenge_header,
    uma_parse_challenge,
)
from axiam_sdk._oidc_state import MemoryOidcStateStore, OidcStateEntry, OidcStateStore
from axiam_sdk._webauthn import (
    WebauthnChallenge,
    WebauthnCredential,
    WebauthnFailure,
    WebauthnLoginResult,
    WebauthnWorkspace,
    classify_webauthn_error,
    webauthn_error_message,
    webauthn_request_json,
)

__version__ = "1.0.0b02"

from axiam_sdk._decision_memo import DecisionMemo
from axiam_sdk._telemetry import (
    Refresh,
    RequestEnd,
    RequestStart,
    Retry,
    TelemetryEvent,
    TelemetryHook,
)

__all__ = [
    "ACCESS_TOKEN_TYPE",
    "JWT_TOKEN_TYPE",
    # §17 decision memo, §19 telemetry hooks (D5).
    "DecisionMemo",
    "TelemetryEvent",
    "TelemetryHook",
    "RequestStart",
    "RequestEnd",
    "Retry",
    "Refresh",
    "__version__",
    "AxiamClient",
    "AsyncAxiamClient",
    "LoginResult",
    "User",
    "AccessCheck",
    "AccessResult",
    "DeviceAuthorization",
    "ExchangedToken",
    "RequestedPermission",
    "RequestingPartyToken",
    "ResourceSet",
    "RptPermission",
    "UmaChallenge",
    "UmaChallenger",
    "uma_parse_challenge",
    "uma_challenge_header",
    "UMA_TICKET_GRANT_TYPE",
    "UMA_PROTECTION_SCOPE",
    "UMA_CLAIM_TOKEN_FORMAT",
    "ReasonCode",
    "VerifiedLogoutToken",
    "BatchCheckResult",
    "UserInfo",
    "AuthError",
    "AuthzError",
    "NetworkError",
    "OAuthProtocolError",
    "OidcConfiguration",
    "IdTokenClaims",
    "AuthorizationRequest",
    "OidcTokenSet",
    "IntrospectionResult",
    "SsoStartResult",
    "SsoCompleteResult",
    "OidcStateStore",
    "OidcStateEntry",
    "MemoryOidcStateStore",
    # §24 WebAuthn / passkeys. The relying-party layer is on both clients; the
    # helpers below are §24.6a's JSON bridge and §24.6b rule 5's error
    # classification, both of which work with no authenticator present.
    "WebauthnChallenge",
    "WebauthnCredential",
    "WebauthnFailure",
    "WebauthnLoginResult",
    "WebauthnWorkspace",
    "classify_webauthn_error",
    "webauthn_error_message",
    "webauthn_request_json",
    # §25 account lifecycle and MFA enrolment.
    "MfaEnrollment",
    "PasswordResetContext",
    # §26 pushed authorization requests (RFC 9126).
    "PushedAuthorizationRequest",
]
