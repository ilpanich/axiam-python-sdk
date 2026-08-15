"""CONTRACT.md §22.13 "Registry" and "Hot path" — the allow-list rules.

These need no broker and no fixture: the registry is the offline mirror of the
server's ``EVENT_REGISTRY``, and every claim §22.5 makes about the
namespace-prefix rule is a row in a table here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from axiam_sdk.amqp import (
    DEFAULT_REACTOR_MAX_IN_FLIGHT,
    DEFAULT_REACTOR_TIMEOUT_MS,
    EVENT_REGISTRY,
    GRANT_PRE_ASSIGN,
    LOGIN_POST_AUTH,
    MAX_REACTOR_TIMEOUT_MS,
    MIN_REACTOR_TIMEOUT_MS,
    REACTOR_CHAIN_CEILING_MS,
    REACTOR_EVENT_NAMES,
    TOKEN_PRE_ISSUE,
    USER_PRE_CREATE,
    USER_PRE_UPDATE,
    default_failure_policy_for,
    event_spec,
    patch_field_allowed,
)

_SOURCE_DIR = Path(__file__).resolve().parent.parent / "src" / "axiam_sdk" / "amqp"

#: The three non-hookable hot-path operations, assembled at runtime from their
#: halves so that a plain source scan for them over the reactor modules finds
#: nothing — and so this test file's own text cannot be what the scan matches on.
EXCLUDED_HOT_PATH = tuple(
    f"{prefix}.{op}"
    for prefix, op in (("authz", "check"), ("authz", "check_batch"), ("token", "introspect"))
)


def _spec(name: str):  # type: ignore[no-untyped-def]
    """Look a registry entry up, failing loudly rather than returning ``None``."""
    found = event_spec(name)
    assert found is not None, name
    return found


class TestRegistryContents:
    """§22.5 — five events, with the mutability and defaults the table states."""

    def test_carries_every_row_in_the_server_order(self) -> None:
        """The five v1 events, in ``EVENT_REGISTRY`` order."""
        assert REACTOR_EVENT_NAMES == (
            "token.pre_issue",
            "login.post_auth",
            "user.pre_create",
            "user.pre_update",
            "grant.pre_assign",
        )
        assert all(spec.interceptable for spec in EVENT_REGISTRY)

    def test_states_the_mutability_and_default_policy_of_each_row(self) -> None:
        """Only ``token.pre_issue`` defaults open — which is why §22.8 composes."""
        assert _spec(TOKEN_PRE_ISSUE).mutable
        assert _spec(TOKEN_PRE_ISSUE).default_failure_policy == "fail_open"
        assert not _spec(LOGIN_POST_AUTH).mutable
        assert _spec(LOGIN_POST_AUTH).default_failure_policy == "fail_closed"
        assert _spec(USER_PRE_CREATE).mutable
        assert _spec(USER_PRE_CREATE).default_failure_policy == "fail_closed"
        assert _spec(USER_PRE_UPDATE).mutable_fields == _spec(USER_PRE_CREATE).mutable_fields
        assert not _spec(GRANT_PRE_ASSIGN).mutable
        assert _spec(GRANT_PRE_ASSIGN).default_failure_policy == "fail_closed"
        assert len([s for s in EVENT_REGISTRY if s.default_failure_policy == "fail_open"]) == 1

    def test_has_no_entry_for_a_name_outside_it(self) -> None:
        """``event_spec`` is the only lookup, and it does not guess."""
        assert event_spec("token.pre_issue.extra") is None
        assert event_spec("") is None

    def test_states_the_budget_constants_at_the_contract_values(self) -> None:
        """§22.8's table, so a reactor author sizing a pool has the numbers."""
        assert DEFAULT_REACTOR_TIMEOUT_MS == 500
        assert MIN_REACTOR_TIMEOUT_MS == 1
        assert MAX_REACTOR_TIMEOUT_MS == 5_000
        assert REACTOR_CHAIN_CEILING_MS == 5_000
        assert DEFAULT_REACTOR_MAX_IN_FLIGHT == 64


class TestHotPathExclusion:
    """§22.7 — a normative MUST NOT, asserted on the list rather than a comment."""

    @pytest.mark.parametrize("name", EXCLUDED_HOT_PATH)
    def test_is_absent_from_every_constant_this_sdk_exposes(self, name: str) -> None:
        """No registry row, no name constant, no lookup hit."""
        assert name not in REACTOR_EVENT_NAMES
        assert name not in {spec.name for spec in EVENT_REGISTRY}
        assert event_spec(name) is None

    @pytest.mark.parametrize("name", EXCLUDED_HOT_PATH)
    def test_is_absent_from_the_reactor_source_entirely(self, name: str) -> None:
        """Not in a constant, not in a tuple, not in a doc example.

        The exclusion is honoured by absence, so the gate needs no judgement
        call about which mentions are innocent — the names appear nowhere.
        """
        for path in sorted(_SOURCE_DIR.glob("_reactor*.py")):
            assert name not in path.read_text(encoding="utf-8"), f"{path.name} names {name}"

    @pytest.mark.parametrize("name", EXCLUDED_HOT_PATH)
    def test_composes_fail_closed_rather_than_guessing_open(self, name: str) -> None:
        """The server refuses such a registration; guessing open is the one
        guess that could weaken a decision."""
        assert default_failure_policy_for([name]) == "fail_closed"


class TestNamespacePrefixRule:
    """§22.5 — an allow-list entry ending in ``.`` is a namespace prefix."""

    @pytest.mark.parametrize("field_name", ["ext.department", "ext.a.b.c", "ext.x"])
    def test_admits_a_field_inside_the_namespace(self, field_name: str) -> None:
        """At least one character after the dot is all it takes."""
        assert patch_field_allowed(_spec(TOKEN_PRE_ISSUE), field_name)

    @pytest.mark.parametrize(
        "field_name", ["ext.", "ext", "extra", "external_id", "evil.ext.department"]
    )
    def test_refuses_everything_the_contract_lists_as_refused(self, field_name: str) -> None:
        """``ext.`` names the namespace, not a claim; a string prefix is not a
        namespace match; and a suffix match is not a match at all."""
        assert not patch_field_allowed(_spec(TOKEN_PRE_ISSUE), field_name)

    @pytest.mark.parametrize(
        "claim",
        [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nbf",
            "jti",
            "scope",
            "scp",
            "azp",
            "act",
            "client_id",
        ],
    )
    def test_refuses_every_standard_claim_on_token_pre_issue(self, claim: str) -> None:
        """None of them begins with ``ext.``, so the one rule is the whole reason.

        A hook that can rewrite ``sub`` is a hook that can mint a token for
        anyone, and a CORRECTLY SIGNED reply setting it is refused exactly as a
        forged one is.
        """
        assert not patch_field_allowed(_spec(TOKEN_PRE_ISSUE), claim)

    @pytest.mark.parametrize("field_name", ["email", "username", "metadata.source", "metadata.a.b"])
    def test_admits_the_user_event_allow_list(self, field_name: str) -> None:
        """The exact-name half of the list, which the prefix rule does not reach."""
        assert patch_field_allowed(_spec(USER_PRE_CREATE), field_name)
        assert patch_field_allowed(_spec(USER_PRE_UPDATE), field_name)

    @pytest.mark.parametrize(
        "field_name",
        [
            "password",
            "password_hash",
            "tenant_id",
            "id",
            "roles",
            "is_admin",
            "metadata",
            "metadata.",
            "usernames",
            "emails",
        ],
    )
    def test_refuses_the_user_event_denials_including_bare_metadata(self, field_name: str) -> None:
        """Bare ``metadata`` is refused by the same prefix rule as bare ``ext``."""
        assert not patch_field_allowed(_spec(USER_PRE_CREATE), field_name)

    @pytest.mark.parametrize("event", [LOGIN_POST_AUTH, GRANT_PRE_ASSIGN])
    @pytest.mark.parametrize("field_name", ["ext.department", "username", "email", "role", "x"])
    def test_a_veto_only_event_accepts_no_patch_field_at_all(
        self, event: str, field_name: str
    ) -> None:
        """Not mutable means not mutable, whatever the field is called."""
        assert _spec(event).mutable_fields == ()
        assert not patch_field_allowed(_spec(event), field_name)


class TestFailurePolicyComposition:
    """§22.8 — the strictest default wins, in either array order."""

    def test_inherits_fail_open_only_when_every_event_defaults_open(self) -> None:
        """One open event, alone, is the only way to get ``fail_open``."""
        assert default_failure_policy_for([TOKEN_PRE_ISSUE]) == "fail_open"
        assert default_failure_policy_for((TOKEN_PRE_ISSUE,)) == "fail_open"

    @pytest.mark.parametrize(
        "name", [LOGIN_POST_AUTH, USER_PRE_CREATE, USER_PRE_UPDATE, GRANT_PRE_ASSIGN]
    )
    def test_inherits_fail_closed_when_any_event_defaults_closed(self, name: str) -> None:
        """Four of the five rows default closed."""
        assert default_failure_policy_for([name]) == "fail_closed"

    def test_is_order_independent_which_is_the_must_not(self) -> None:
        """ "Take the first event's default" would let the order of a JSON array
        decide whether an unreachable fraud check passes."""
        assert default_failure_policy_for([TOKEN_PRE_ISSUE, LOGIN_POST_AUTH]) == "fail_closed"
        assert default_failure_policy_for([LOGIN_POST_AUTH, TOKEN_PRE_ISSUE]) == "fail_closed"

    @pytest.mark.parametrize(
        "events",
        [
            [],
            ["not.an.event"],
            [TOKEN_PRE_ISSUE, "not.an.event"],
            [TOKEN_PRE_ISSUE, 42],
            "token.pre_issue",
            None,
        ],
    )
    def test_treats_anything_it_cannot_recognise_as_fail_closed(self, events: object) -> None:
        """An empty list, an unknown name, a non-string entry, or a value that is
        not a sequence of names at all: every one of them is ``fail_closed``.

        This is the one registry helper an admin UI is likely to call with
        whatever came back off a wire, and guessing open on input this SDK does
        not understand is the guess that weakens a decision.
        """
        assert default_failure_policy_for(events) == "fail_closed"
