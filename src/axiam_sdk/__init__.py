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
    ReasonCode,
    SsoCompleteResult,
    SsoStartResult,
    User,
    UserInfo,
    VerifiedLogoutToken,
)
from axiam_sdk._oidc_state import MemoryOidcStateStore, OidcStateEntry, OidcStateStore

__version__ = "1.0.0a24"

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
]
