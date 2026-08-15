"""A runnable reactor — CONTRACT.md §22.

Three hooks in one process:

- ``token.pre_issue`` — enrich the token with ``ext.`` claims (mutable).
- ``login.post_auth`` — veto a sign-in from an embargoed region, or demand
  step-up MFA (veto-only).
- ``grant.pre_assign`` — four-eyes: refuse a self-granted admin role
  (veto-only).

Run it::

    export AXIAM_AMQP_URL='amqps://reactor:secret@broker.example.com:5671/%2f'
    export AXIAM_TENANT_ID='11111111-1111-1111-1111-111111111111'
    export AXIAM_REACTOR_ID='99999999-9999-9999-9999-999999999999'
    export AXIAM_AMQP_SIGNING_KEY_HEX='…64 hex chars…'
    python examples/reactor.py

Before this runs, register the reactor (§22.9)::

    curl -X POST https://axiam.example.com/api/v1/reactors \\
      -H "Authorization: Bearer $ADMIN_TOKEN" \\
      -H 'Content-Type: application/json' \\
      -d '{
            "name": "example-reactor",
            "events": ["token.pre_issue", "login.post_auth", "grant.pre_assign"],
            "mode": "intercept",
            "priority": 10,
            "timeout_ms": 500
          }'

The response carries the ``id`` this process needs as ``AXIAM_REACTOR_ID``, and
the server declares the queue. **This process declares nothing** (§22.1).

Note what the registration deliberately omits: ``failure_policy``. Two of the
three events default to ``fail_closed``, and §22.8 says the strictest default
wins — so this reactor being unreachable **denies** logins and grants, while
token enrichment keeps flowing. That is the right shape, and it is why naming
the policy explicitly is usually a mistake.

What this example does not do
-----------------------------
It hooks none of the three hot-path decision operations, because §22.7 makes
them un-hookable: a reactor round-trip is milliseconds and the check path's
budget is microseconds. External input on an authorization decision belongs in
a **deny grant**, which the engine evaluates at hot-path cost.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal

from axiam_sdk import TelemetryEvent
from axiam_sdk.amqp import (
    GRANT_PRE_ASSIGN,
    LOGIN_POST_AUTH,
    TOKEN_PRE_ISSUE,
    ReactorConfig,
    ReactorDecision,
    ReactorEvent,
    abstain,
    aio_pika_dialer,
    allow,
    default_failure_policy_for,
    deny,
    event_spec,
    mutate,
    patch_field_allowed,
    reactor_queue_name,
    reactor_serve,
    require_step_up,
)

LOGGER = logging.getLogger("example.reactor")


def env(name: str) -> str:
    """Read a required environment variable, or fail loudly."""
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} must be set")
    return value


def on_telemetry(event: TelemetryEvent) -> None:
    """Print one line per finished dispatch (§19).

    ``path_template`` is the registry event name — a bounded label set, never a
    correlation id.
    """
    if type(event).__name__ == "RequestEnd":
        LOGGER.info(
            "reactor %s finished in %.1fms: %s",
            event.path_template,  # type: ignore[union-attr]
            event.duration_ms,  # type: ignore[union-attr]
            event.outcome,  # type: ignore[union-attr]
        )


async def decide(event: ReactorEvent) -> ReactorDecision:
    """Answer one event with one of §22.10's three answers.

    The payload is tenant business data: readable by design, but do not log it
    at info level (§22.12).
    """
    if event.event == TOKEN_PRE_ISSUE:
        return enrich_token(event)
    if event.event == LOGIN_POST_AUTH:
        return screen_login(event)
    if event.event == GRANT_PRE_ASSIGN:
        return four_eyes(event)
    # An event we did not register for should never arrive. Abstaining publishes
    # nothing and lets the failure policy decide, which is the honest answer to
    # "I do not know what this is".
    return abstain()


def enrich_token(event: ReactorEvent) -> ReactorDecision:
    """Add ``ext.`` claims to a token being issued.

    ``token.pre_issue`` is the one mutable event here, and its allow-list is the
    ``ext.`` namespace and nothing else — ``sub``, ``aud``, ``exp`` and every
    other standard claim are unreachable, because none of them begins with
    ``ext.``.
    """
    sub = event.payload.get("sub")
    if not isinstance(sub, str):
        return allow()

    patch = {"ext.cost_center": f"cc-{len(sub)}", "ext.department": "engineering"}

    # A chained event carries what an earlier reactor already decided, so you
    # can decide against the state that will actually commit. It is read-only
    # context — do NOT copy it into your own patch; the server merges (§22.6).
    prior = event.chain_patch
    if prior is not None and "ext.department" in prior:
        # A higher-priority reactor will overwrite ours anyway, so do not
        # contest the key.
        del patch["ext.department"]

    # Optional self-check. The runtime will NOT prune a forbidden key for you
    # (§22.4 rule 1): one bad key rejects the whole patch server-side, and
    # silently dropping it would leave you believing a field was set.
    spec = event_spec(TOKEN_PRE_ISSUE)
    if spec is not None:
        for key in patch:
            if not patch_field_allowed(spec, key):
                LOGGER.warning(
                    "patch key %s is outside the allow-list; the whole patch will reject", key
                )

    return mutate(patch)


def screen_login(event: ReactorEvent) -> ReactorDecision:
    """Veto or step-up an interactive sign-in.

    ``login.post_auth`` fires on password sign-in, on SAML ACS and on the OIDC
    callback — after the credentials verify and before any session or token is
    issued (§22.5).
    """
    ip = event.payload.get("ip")
    ip = ip if isinstance(ip, str) else ""

    if ip.startswith("198.51.100."):
        # A deny with no reason still denies; the reason is for the audit trail.
        return deny("embargoed region")

    if ip.startswith("203.0.113."):
        # `require_mfa` rides on `allow` and is valid on this event only.
        #
        # Caveat worth knowing: the federated paths (SAML ACS, OIDC callback)
        # have no step-up branch, so a `require_mfa` answer there FAILS the
        # sign-in rather than being dropped. A reactor that needs step-up on a
        # federated login answers `deny` and drives enrolment out of band.
        return require_step_up()

    return allow()


def four_eyes(event: ReactorEvent) -> ReactorDecision:
    """Refuse a self-granted admin role.

    ``grant.pre_assign`` is veto-only: it can refuse a role assignment, and it
    cannot rewrite one.
    """
    actor = event.payload.get("actor_id")
    subject = event.payload.get("subject_id")
    role = event.payload.get("role")

    if role == "admin" and isinstance(actor, str) and actor == subject:
        return deny("admin cannot be self-granted; needs a second approver")
    return allow()


async def main() -> None:
    """Wire the runtime up and serve until SIGINT."""
    logging.basicConfig(level=logging.INFO)
    tenant_id = env("AXIAM_TENANT_ID")
    reactor_id = env("AXIAM_REACTOR_ID")

    # The tenant's HKDF-derived AMQP subkey (§8 v2), fetched from the management
    # API. NEVER hard-code one; it is a credential (§22.12) and this runtime
    # never logs it.
    signing_key = bytes.fromhex(env("AXIAM_AMQP_SIGNING_KEY_HEX"))

    # The strictest default among the events we registered for (§22.8). Shown
    # here because it is worth knowing before you go live, not because the SDK
    # needs it: the server derives it from the registration.
    policy = default_failure_policy_for([TOKEN_PRE_ISSUE, LOGIN_POST_AUTH, GRANT_PRE_ASSIGN])
    LOGGER.info("failure policy when this reactor is unreachable: %s", policy)
    LOGGER.info("consuming %s (declared by the server)", reactor_queue_name(tenant_id, reactor_id))

    served = asyncio.create_task(
        reactor_serve(
            # amqps:// only — a plaintext URL is refused here, not downgraded (§8b).
            aio_pika_dialer(
                env("AXIAM_AMQP_URL"), ca_bundle=os.environ.get("AXIAM_AMQP_CA_BUNDLE")
            ),
            ReactorConfig(
                tenant_id=tenant_id,
                reactor_id=reactor_id,
                signing_key=signing_key,
                logger=LOGGER,
                telemetry_hook=on_telemetry,
            ),
            decide,
        )
    )

    # SIGINT drains the in-flight event and returns (§18) — it does not abandon
    # a dispatch the server is still waiting on.
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, served.cancel)

    try:
        await served
    except asyncio.CancelledError:
        LOGGER.info("shut down; in-flight events were drained")


if __name__ == "__main__":
    asyncio.run(main())
