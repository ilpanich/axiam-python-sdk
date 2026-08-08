"""Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).

The rule exists because the two refusals mean **opposite things to the person
on the other end**: ``no_grant`` says *ask an admin for access*,
``denied_by_rule`` says *an admin has already decided*. An application that
cannot tell them apart sends users to raise tickets that will be refused.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from axiam_sdk import AccessCheck, AsyncAxiamClient, AxiamClient, ReasonCode

BASE_URL = "https://axiam-authz.test"
CHECK_URL = f"{BASE_URL}/api/v1/authz/check"
BATCH_URL = f"{BASE_URL}/api/v1/authz/check/batch"
RESOURCE_ID = "11111111-2222-3333-4444-555555555555"


def _client() -> AxiamClient:
    return AxiamClient(base_url=BASE_URL, tenant_slug="acme")


def _mock_check(respx_mock: respx.MockRouter, body: dict[str, Any]) -> None:
    respx_mock.post(CHECK_URL).mock(return_value=httpx.Response(200, json=body))


def test_an_allow_surfaces_the_allowed_reason_code(respx_mock: respx.MockRouter) -> None:
    _mock_check(respx_mock, {"allowed": True, "reason_code": "allowed"})

    decision = _client().check_access(action="read", resource_id=RESOURCE_ID)

    assert decision.allowed is True
    assert decision.reason_code == ReasonCode.ALLOWED


def test_no_grant_and_denied_by_rule_are_not_collapsed(respx_mock: respx.MockRouter) -> None:
    _mock_check(respx_mock, {"allowed": False, "reason_code": "no_grant"})
    no_grant = _client().check_access(action="read", resource_id=RESOURCE_ID)

    respx_mock.reset()
    _mock_check(respx_mock, {"allowed": False, "reason_code": "denied_by_rule"})
    by_rule = _client().check_access(action="read", resource_id=RESOURCE_ID)

    # Both are refusals…
    assert no_grant.allowed is False
    assert by_rule.allowed is False
    # …and the SDK must not reduce them to that shared False.
    assert no_grant.reason_code == ReasonCode.NO_GRANT
    assert by_rule.reason_code == ReasonCode.DENIED_BY_RULE
    assert no_grant.reason_code != by_rule.reason_code


def test_an_unknown_reason_code_is_surfaced_verbatim(respx_mock: respx.MockRouter) -> None:
    # §11 rule 9: an SDK that does not recognise a code MUST surface it
    # unchanged and MUST NOT let it affect the outcome, which `allowed` carries
    # alone. This is what lets the server add a fourth code without breaking
    # every deployed SDK.
    _mock_check(respx_mock, {"allowed": False, "reason_code": "denied_by_some_future_thing"})

    decision = _client().check_access(action="read", resource_id=RESOURCE_ID)

    assert decision.allowed is False
    assert decision.reason_code == "denied_by_some_future_thing"


def test_an_unknown_reason_code_does_not_flip_an_allow(respx_mock: respx.MockRouter) -> None:
    _mock_check(respx_mock, {"allowed": True, "reason_code": "something-unrecognised"})

    decision = _client().check_access(action="read", resource_id=RESOURCE_ID)

    assert decision.allowed is True, "the outcome is carried by `allowed` alone"


def test_an_older_server_omitting_the_field_is_not_an_error(
    respx_mock: respx.MockRouter,
) -> None:
    # A newer SDK against an older server: the field is simply absent, and that
    # MUST degrade to today's behaviour rather than failing to parse.
    _mock_check(respx_mock, {"allowed": False})
    denied = _client().check_access(action="read", resource_id=RESOURCE_ID)
    assert denied.allowed is False
    assert denied.reason_code is None

    respx_mock.reset()
    _mock_check(respx_mock, {"allowed": True, "reason": "role grants it"})
    allowed = _client().check_access(action="read", resource_id=RESOURCE_ID)
    assert allowed.allowed is True
    assert allowed.reason_code is None
    assert allowed.reason == "role grants it"


@pytest.mark.parametrize("code", [ReasonCode.NO_GRANT, ReasonCode.DENIED_BY_RULE])
def test_can_still_returns_false_for_both_refusals(respx_mock: respx.MockRouter, code: str) -> None:
    # §11 rule 9 is about *reporting*, not enforcement: `can` is the
    # "just tell me yes or no" helper and both refusals answer False
    # identically. An SDK must not start varying enforcement on the code.
    _mock_check(respx_mock, {"allowed": False, "reason_code": code})

    assert _client().can(action="read", resource_id=RESOURCE_ID) is False


def test_batch_check_surfaces_a_reason_code_per_decision(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post(BATCH_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"allowed": True, "reason_code": "allowed"},
                    {"allowed": False, "reason_code": "no_grant"},
                    {"allowed": False, "reason_code": "denied_by_rule"},
                ]
            },
        )
    )

    result = _client().batch_check(
        checks=[
            AccessCheck(action="read", resource_id=RESOURCE_ID),
            AccessCheck(action="write", resource_id=RESOURCE_ID),
            AccessCheck(action="delete", resource_id=RESOURCE_ID),
        ]
    )

    assert [d.reason_code for d in result] == [
        ReasonCode.ALLOWED,
        ReasonCode.NO_GRANT,
        ReasonCode.DENIED_BY_RULE,
    ]


@pytest.mark.asyncio
async def test_async_check_access_surfaces_the_reason_code(
    respx_mock: respx.MockRouter,
) -> None:
    _mock_check(respx_mock, {"allowed": False, "reason_code": "denied_by_rule"})

    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme")
    decision = await client.check_access(action="read", resource_id=RESOURCE_ID)

    assert decision.allowed is False
    assert decision.reason_code == ReasonCode.DENIED_BY_RULE
