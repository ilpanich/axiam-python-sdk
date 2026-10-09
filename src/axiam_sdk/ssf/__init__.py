"""The SSF receiver helper — CONTRACT.md §32.7 (contract 1.56).

AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC
security events as Security Event Tokens (RFC 8417) to the relying parties a
tenant administrator registered (the §27 ``ssf`` namespace,
``client.ssf``). This package is for the **relying party** that receives them,
a different audience from that namespace:

- :meth:`SsfReceiver.verify_set` verifies one compact SET -- pushed to your
  endpoint (RFC 8935) or returned by a poll -- in the contract's fixed order,
  and refuses at the first failure with a :class:`SetVerificationError` (an
  :class:`~axiam_sdk.AuthError`) whose :attr:`~SetVerificationError.set_failure_reason`
  names the step.
- :meth:`SsfReceiver.poll` calls the stream's poll endpoint (RFC 8936), verifies
  every returned SET and hands back the verified and the refused apart.

:class:`AsyncSsfReceiver` is the same over :class:`~axiam_sdk.AsyncAxiamClient`.
Neither transmits, signs or registers anything, and neither trusts a key it did
not fetch from the configured JWKS: no ``jwk`` or ``x5c`` header member is
honoured (§32.9).
"""

from axiam_sdk.ssf._receiver import (
    ACCOUNT_DISABLED,
    ACCOUNT_ENABLED,
    ACCOUNT_PURGED,
    ASSURANCE_LEVEL_CHANGE,
    CREDENTIAL_CHANGE,
    MIN_REPLAY_WINDOW_SECONDS,
    SESSION_REVOKED,
    STREAM_UPDATED,
    VERIFICATION,
    AccessTokenProvider,
    AsyncAccessTokenProvider,
    AsyncSsfReceiver,
    MemoryReplayStore,
    RefusedSet,
    ReplayStore,
    SecurityEvent,
    SetErr,
    SetFailureReason,
    SetVerificationError,
    SsfPollResult,
    SsfReceiver,
)

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
    "AccessTokenProvider",
    "AsyncAccessTokenProvider",
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
