"""CONTRACT.md §22.13 — the required reactor tests, run against the vectors.

``testdata/reactor_v2_reference_vectors.json`` was produced by the AXIAM
server's own reactor sign path and ships beside the §8 vectors, under the SAME
master key, tenant and derived subkey — so the one loader below serves both
files, exactly as §22.13 intends. Nothing here hand-rolls an expectation: every
byte string and every MAC is read from the fixture.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from axiam_sdk.amqp import (
    LOGIN_POST_AUTH,
    REACTOR_EXCHANGE,
    TOKEN_PRE_ISSUE,
    build_reactor_reply,
    canonical_event_bytes,
    canonical_reply_bytes,
    event_spec,
    is_fresh,
    patch_field_allowed,
    reactor_queue_name,
    reactor_reply_signature_valid,
    reactor_routing_key,
    sign_reactor_reply,
    to_chrono_rfc3339,
    verify_event,
)

_TESTDATA = Path(__file__).resolve().parent.parent / "testdata"


def _load(name: str) -> dict[str, Any]:
    """Read one fixture file — the single loader §22.13 says serves both."""
    data: dict[str, Any] = json.loads((_TESTDATA / name).read_text(encoding="utf-8"))
    return data


REACTOR_VECTORS = _load("reactor_v2_reference_vectors.json")
HMAC_VECTORS = _load("v2_reference_vectors.json")

#: The tenant's HKDF-derived AMQP subkey, as both fixtures committed it.
SUBKEY = bytes.fromhex(REACTOR_VECTORS["hkdf"]["derived_subkey_hex"])
SKEW = float(REACTOR_VECTORS["freshness_skew_secs"])
VERIFIED_AT = datetime.fromisoformat(REACTOR_VECTORS["verified_at"].replace("Z", "+00:00"))


def _hmac_hex(key: bytes, message: bytes) -> str:
    """HMAC-SHA256 computed here, so assertions check the SDK's canonical BYTES."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _event_wire_body(vector: dict[str, Any]) -> dict[str, Any]:
    """Return the bytes the server actually put on the wire, parsed.

    **Read this before reaching for ``vector["message"]``.** The fixture stores
    each ``message`` object with its keys in ALPHABETICAL order, because that is
    how the generator's JSON writer emitted them; the authoritative wire order
    lives in ``canonical_signed_json``. The signed bytes are order-sensitive, so
    a verifier must be fed the wire body — which is exactly what a broker
    delivers — and not the fixture's convenience copy.
    """
    wire = vector["canonical_signed_json"].replace(
        '"hmac_signature":null', f'"hmac_signature":"{vector["hmac_signature_hex"]}"'
    )
    body: dict[str, Any] = json.loads(wire)
    return body


def _reply_from_vector(message: dict[str, Any]) -> dict[str, Any]:
    """Rebuild a reply from a vector's ``message`` through the SDK's own builder.

    Going through the builder rather than copying the dict is the point: the
    assertion then exercises the field order and every omission rule.
    """
    return build_reactor_reply(
        message["correlation_id"],
        message["tenant_id"],
        message["event"],
        message["decision"],
        reason=message.get("reason"),
        patch=message.get("patch"),
        require_mfa=message.get("require_mfa", False),
        nonce=message["nonce"],
        issued_at=datetime.fromisoformat(message["issued_at"].replace("Z", "+00:00")),
    )


def _reply_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Every committed reply vector this SDK's builder can reproduce.

    The ``key_version_too_old`` vector is excluded here and asserted separately:
    it was downgraded to 1 AFTER signing, to pin the server's rejection ORDER,
    and this SDK's builder always stamps the current version.
    """
    out: list[tuple[str, dict[str, Any]]] = []
    for group in ("reactor_to_server", "rejected_replies"):
        for name, vector in REACTOR_VECTORS[group].items():
            if not isinstance(vector, dict) or "message" not in vector:
                continue
            if vector["message"].get("key_version", 2) < 2:
                continue
            out.append((f"{group}.{name}", vector))
    return out


class TestOneLoaderServesBothFixtures:
    """§22.13 preamble — the reactor vectors share the §8 vectors' provenance."""

    def test_shares_master_key_tenant_and_derived_subkey(self) -> None:
        """Same master key, tenant and derived subkey as the §8 fixture."""
        assert REACTOR_VECTORS["master_signing_key_hex"] == HMAC_VECTORS["master_signing_key_hex"]
        assert REACTOR_VECTORS["tenant_id"] == HMAC_VECTORS["tenant_id"]
        assert REACTOR_VECTORS["hkdf"] == HMAC_VECTORS["hkdf"]
        assert REACTOR_VECTORS["key_version"] == 2

    def test_derives_the_subkey_with_the_section8_hkdf_parameters(self) -> None:
        """§22.2 adds no new cryptography: the §8 HKDF parameters, unchanged."""
        master = bytes.fromhex(REACTOR_VECTORS["master_signing_key_hex"])
        salt = REACTOR_VECTORS["hkdf"]["app_salt_utf8"].encode()
        info = (
            REACTOR_VECTORS["hkdf"]["domain_tag_utf8"].encode()
            + bytes([REACTOR_VECTORS["key_version"]])
            + bytes.fromhex(REACTOR_VECTORS["tenant_id"].replace("-", ""))
        )
        # HKDF-SHA256, extract then expand. L is 32, one SHA-256 block, so the
        # expand loop is a single iteration with the 0x01 counter.
        prk = hmac.new(salt, master, hashlib.sha256).digest()
        okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        assert okm.hex() == REACTOR_VECTORS["hkdf"]["derived_subkey_hex"]


class TestTopology:
    """§22.1 — the exchange, queue and routing keys the fixture committed."""

    def test_renders_the_committed_topology(self) -> None:
        """The SDK's formatters agree with the server's ``protocol.rs``."""
        tenant = REACTOR_VECTORS["tenant_id"]
        reactor = REACTOR_VECTORS["reactor_id"]
        topology = REACTOR_VECTORS["topology"]
        assert REACTOR_EXCHANGE == topology["exchange"]
        assert topology["exchange_type"] == "topic"
        assert reactor_queue_name(tenant, reactor) == topology["queue"]
        assert (
            reactor_routing_key(tenant, TOKEN_PRE_ISSUE) == topology["routing_key_token_pre_issue"]
        )
        assert (
            reactor_routing_key(tenant, LOGIN_POST_AUTH) == topology["routing_key_login_post_auth"]
        )


class TestSignDirection:
    """§22.13 "Sign direction" — every reply vector, byte-for-byte."""

    @pytest.mark.parametrize(("name", "vector"), _reply_vectors())
    def test_reproduces_canonical_bytes_and_recomputes_the_mac(
        self, name: str, vector: dict[str, Any]
    ) -> None:
        """Rebuild each committed reply and match its bytes and its MAC."""
        reply = _reply_from_vector(vector["message"])
        canonical = canonical_reply_bytes(reply)
        assert canonical.decode() == vector["canonical_signed_json"], name
        assert _hmac_hex(SUBKEY, canonical) == vector["hmac_signature_hex"], name

        signed = sign_reactor_reply(reply, SUBKEY)
        assert signed["hmac_signature"] == vector["hmac_signature_hex"]
        assert reactor_reply_signature_valid(signed, SUBKEY)

    def test_covers_at_least_the_nine_reproducible_vectors(self) -> None:
        """A guard against the parametrization silently collecting nothing."""
        assert len(_reply_vectors()) >= 9

    def test_cannot_reproduce_the_downgraded_key_version_vector(self) -> None:
        """The builder always stamps the current version, so there is no code
        path here that emits a body the server would refuse on ``key_version``
        alone. Asserted rather than skipped silently."""
        vector = REACTOR_VECTORS["rejected_replies"]["key_version_too_old"]
        assert vector["message"]["key_version"] == 1
        assert _reply_from_vector(vector["message"])["key_version"] == 2

    def test_omits_require_mfa_when_false_and_reason_patch_when_absent(self) -> None:
        """§22.13: assert the omission rules directly, not just the values."""
        reply = _reply_from_vector(REACTOR_VECTORS["reactor_to_server"]["allow"]["message"])
        assert "require_mfa" not in reply

        raw = canonical_reply_bytes(reply).decode()
        assert "require_mfa" not in raw
        assert "reason" not in raw
        assert "patch" not in raw
        assert raw.endswith('"hmac_signature":null}')

        # And the other half: true IS serialized, right after `decision`.
        mfa = _reply_from_vector(REACTOR_VECTORS["reactor_to_server"]["require_mfa"]["message"])
        assert '"decision":"allow","require_mfa":true' in canonical_reply_bytes(mfa).decode()

    def test_signs_hmac_signature_as_null_not_omitted(self) -> None:
        """The §8 omission rule does NOT reproduce a reactor MAC.

        This is the one canonicalization difference between §22 and §8's own two
        message types, and it produces a signature that never verifies with no
        other symptom.
        """
        vector = REACTOR_VECTORS["reactor_to_server"]["allow"]
        canonical = vector["canonical_signed_json"]
        omitted = canonical.replace(',"hmac_signature":null', "")
        assert omitted != canonical
        assert _hmac_hex(SUBKEY, omitted.encode()) != vector["hmac_signature_hex"]

    def test_sorts_patch_keys_because_the_server_signs_a_btreemap(self) -> None:
        """The server's ``patch`` is a ``BTreeMap``; the signed bytes are sorted."""
        reply = build_reactor_reply(
            "c", "t", TOKEN_PRE_ISSUE, "mutate", patch={"ext.zebra": "1", "ext.alpha": "2"}
        )
        assert '"patch":{"ext.alpha":"2","ext.zebra":"1"}' in canonical_reply_bytes(reply).decode()

    def test_formats_issued_at_the_way_chrono_does(self) -> None:
        """``AutoSi``: no fraction on a whole second, else three or six digits.

        Python's own ``isoformat`` renders UTC as ``+00:00`` and carries six
        digits the moment ``microsecond`` is non-zero, so signing over what it
        produces and having the server re-serialize ``…T12:00:00Z`` is a
        ``bad_signature`` with no other symptom.
        """
        assert to_chrono_rfc3339(datetime(2026, 7, 10, 12, 0, 0, 0, timezone.utc)) == (
            "2026-07-10T12:00:00Z"
        )
        assert to_chrono_rfc3339(datetime(2026, 7, 10, 12, 0, 0, 123000, timezone.utc)) == (
            "2026-07-10T12:00:00.123Z"
        )
        assert to_chrono_rfc3339(datetime(2026, 7, 10, 12, 0, 0, 123456, timezone.utc)) == (
            "2026-07-10T12:00:00.123456Z"
        )
        # A naive datetime is read as UTC; a non-UTC aware one is converted.
        assert to_chrono_rfc3339(datetime(2026, 7, 10, 12, 0, 0)) == "2026-07-10T12:00:00Z"
        assert (
            to_chrono_rfc3339(datetime(2026, 7, 10, 14, 0, 0, tzinfo=timezone(timedelta(hours=2))))
            == "2026-07-10T12:00:00Z"
        )

        # The committed vectors are all whole seconds — exactly the case a naive
        # isoformat() gets wrong.
        reply = _reply_from_vector(REACTOR_VECTORS["reactor_to_server"]["allow"]["message"])
        assert reply["issued_at"] == "2026-07-10T12:00:00Z"

    def test_emits_non_ascii_as_utf8_rather_than_escaping_it(self) -> None:
        """``ensure_ascii`` must be off: ``serde_json`` escapes no non-ASCII.

        Python's ``json.dumps`` escapes every non-ASCII character into a
        ``\\uXXXX`` sequence by default, so a deny reason carrying an accented
        character would be signed over bytes the server never reconstructs.
        """
        reply = build_reactor_reply(
            "c", "t", LOGIN_POST_AUTH, "deny", reason="région embargoée — refusé"
        )
        raw = canonical_reply_bytes(reply)
        assert "région embargoée — refusé".encode() in raw
        assert b"\\u00e9" not in raw
        signed = sign_reactor_reply(reply, SUBKEY)
        assert reactor_reply_signature_valid(signed, SUBKEY)


class TestVerifyDirection:
    """§22.13 "Verify direction" — every event vector, and every tamper."""

    def test_verifies_every_event_vector_under_the_subkey_and_no_other(self) -> None:
        """The committed events verify, and fail under any other key."""
        for name, vector in REACTOR_VECTORS["server_to_reactor"].items():
            body = _event_wire_body(vector)
            canonical = canonical_event_bytes(body)
            assert canonical is not None, name
            assert canonical.decode() == vector["canonical_signed_json"], name
            assert _hmac_hex(SUBKEY, canonical) == vector["hmac_signature_hex"], name

            event, rejection = verify_event(body, SUBKEY, VERIFIED_AT, SKEW)
            assert rejection is None, name
            assert event is not None
            assert event.event == vector["message"]["event"]
            assert event.timeout_ms == vector["message"]["timeout_ms"]
            assert reactor_routing_key(event.tenant_id, event.event) == vector["routing_key"]

            _, wrong = verify_event(body, b"a different key", VERIFIED_AT, SKEW)
            assert wrong == "bad_signature", name

    @pytest.mark.parametrize("field_name", ["payload", "timeout_ms", "tenant_id", "nonce"])
    def test_refuses_a_tampered_field(self, field_name: str) -> None:
        """§22.13: tampering after signing invalidates the MAC."""
        body = _event_wire_body(REACTOR_VECTORS["server_to_reactor"]["token_pre_issue"])
        tampers: dict[str, Any] = {
            "payload": {"sub": "root", "client_id": "portal"},
            "timeout_ms": 60_000,
            "tenant_id": "33333333-3333-3333-3333-333333333333",
            "nonce": "dddddddd-dddd-dddd-dddd-dddddddddddd",
        }
        body[field_name] = tampers[field_name]
        assert verify_event(body, SUBKEY, VERIFIED_AT, SKEW) == (None, "bad_signature")

    def test_refuses_key_version_below_two_before_the_signature_is_computed(self) -> None:
        """§22.2: the floor is checked before anything else about the body.

        The downgrade breaks the MAC, so a verifier that checked the signature
        first would report ``bad_signature`` instead — which is what makes the
        ordering assertable at all.
        """
        body = _event_wire_body(REACTOR_VECTORS["server_to_reactor"]["token_pre_issue"])
        body["key_version"] = 1
        assert verify_event(body, SUBKEY, VERIFIED_AT, SKEW) == (None, "key_version_too_old")
        assert (
            REACTOR_VECTORS["rejected_replies"]["key_version_too_old"]["expected_rejection"]
            == "key_version_too_old"
        )

    def test_refuses_an_issued_at_outside_the_window_in_both_directions(self) -> None:
        """A future timestamp is not "extra fresh" (§22.2)."""
        body = _event_wire_body(REACTOR_VECTORS["server_to_reactor"]["token_pre_issue"])
        late = VERIFIED_AT + timedelta(seconds=SKEW + 1)
        early = VERIFIED_AT - timedelta(seconds=SKEW + 1)
        assert verify_event(body, SUBKEY, late, SKEW) == (None, "stale")
        assert verify_event(body, SUBKEY, early, SKEW) == (None, "stale")
        # Exactly on the boundary is still fresh.
        assert verify_event(body, SUBKEY, VERIFIED_AT + timedelta(seconds=SKEW), SKEW)[1] is None

    def test_the_reply_side_stale_vectors_carry_valid_signatures(self) -> None:
        """Both halves of §22.13's "both directions" requirement.

        These two vectors have perfectly valid MACs — only the freshness gate
        refuses them, which is the point.
        """
        for name in ("stale", "stale_future"):
            vector = REACTOR_VECTORS["rejected_replies"][name]
            assert vector["expected_rejection"] == "stale"
            signed = sign_reactor_reply(_reply_from_vector(vector["message"]), SUBKEY)
            assert reactor_reply_signature_valid(signed, SUBKEY)
            issued = datetime.fromisoformat(signed["issued_at"].replace("Z", "+00:00"))
            assert not is_fresh(issued, VERIFIED_AT, SKEW)

    def test_refuses_an_event_with_no_signature_at_all(self) -> None:
        """An unsigned event is not a weak event — it is not an event."""
        body = _event_wire_body(REACTOR_VECTORS["server_to_reactor"]["token_pre_issue"])
        del body["hmac_signature"]
        assert canonical_event_bytes(body) is None
        assert verify_event(body, SUBKEY, VERIFIED_AT, SKEW) == (None, "bad_signature")


class TestReplay:
    """§22.13 "Replay" — the correlation binding and the nonce binding."""

    def test_the_correlation_replay_vector_is_refused_against_another_correlation(self) -> None:
        """Identical bytes, valid signature, inside the window — still refused.

        A captured reply re-presented against any other event is
        ``wrong_correlation``: a perfectly valid signature does not make it the
        answer to another question.
        """
        vector = REACTOR_VECTORS["rejected_replies"]["correlation_replay"]
        signed = sign_reactor_reply(_reply_from_vector(vector["message"]), SUBKEY)
        assert reactor_reply_signature_valid(signed, SUBKEY)
        assert vector["expected_rejection"] == "wrong_correlation"
        assert signed["correlation_id"] != vector["verify_against_correlation_id"]
        assert (
            vector["hmac_signature_hex"]
            == REACTOR_VECTORS["reactor_to_server"]["allow"]["hmac_signature_hex"]
        )

    def test_two_replies_differing_only_in_nonce_carry_different_macs(self) -> None:
        """The ``nonce_binding`` pair, reproduced from the SDK's own builder."""
        binding = REACTOR_VECTORS["nonce_binding"]
        base = dict(REACTOR_VECTORS["reactor_to_server"]["allow"]["message"])

        first = sign_reactor_reply(
            _reply_from_vector({**base, "nonce": binding["nonce_a"]}), SUBKEY
        )
        second = sign_reactor_reply(
            _reply_from_vector({**base, "nonce": binding["nonce_b"]}), SUBKEY
        )
        assert first["hmac_signature"] == binding["hmac_a_hex"]
        assert second["hmac_signature"] == binding["hmac_b_hex"]
        assert first["hmac_signature"] != second["hmac_signature"]

    def test_mints_a_fresh_nonce_for_every_reply(self) -> None:
        """A constant nonce removes the only uniqueness a reply body carries."""
        first = build_reactor_reply("c", "t", LOGIN_POST_AUTH, "allow")
        second = build_reactor_reply("c", "t", LOGIN_POST_AUTH, "allow")
        assert first["nonce"] != second["nonce"]
        assert first["key_version"] == 2


class TestReplyConstruction:
    """§22.13 "Reply construction" — mutate, unfiltered patches, require_mfa."""

    def test_sends_a_forbidden_patch_key_unfiltered(self) -> None:
        """§22.4 rule 1: the SDK must NOT silently drop ``sub``."""
        vector = REACTOR_VECTORS["rejected_replies"]["forbidden_patch_field"]
        assert vector["expected_rejection"] == "forbidden_patch_field:sub"

        signed = sign_reactor_reply(_reply_from_vector(vector["message"]), SUBKEY)
        wire = json.dumps(signed)
        assert '"decision": "mutate"' in wire
        assert '"sub": "root"' in wire
        assert '"ext.department": "eng"' in wire
        assert signed["hmac_signature"] == vector["hmac_signature_hex"]

        spec = event_spec(TOKEN_PRE_ISSUE)
        assert spec is not None
        assert not patch_field_allowed(spec, "sub")
        assert patch_field_allowed(spec, "ext.department")

    def test_builds_a_mutation_as_mutate_never_allow_plus_patch(self) -> None:
        """§22.4 rule 2 is unspellable: the allow constructors take no patch."""
        mutation = _reply_from_vector(REACTOR_VECTORS["reactor_to_server"]["mutate"]["message"])
        assert mutation["decision"] == "mutate"
        assert len(mutation["patch"]) == 2

        allowed = _reply_from_vector(REACTOR_VECTORS["reactor_to_server"]["allow"]["message"])
        assert allowed["decision"] == "allow"
        assert "patch" not in allowed

    def test_recognises_a_mutation_on_a_veto_only_event_locally(self) -> None:
        """``not_mutable`` is knowable from the registry before sending."""
        vector = REACTOR_VECTORS["rejected_replies"]["mutation_on_veto_only_event"]
        assert vector["expected_rejection"] == "not_mutable"
        spec = event_spec(vector["message"]["event"])
        assert spec is not None
        assert not spec.mutable
        assert not patch_field_allowed(spec, "role")

    def test_carries_a_deny_reason_through_and_omits_it_when_absent(self) -> None:
        """A deny with no reason still denies; the server substitutes its own."""
        vector = REACTOR_VECTORS["reactor_to_server"]["deny"]
        assert vector["expected_outcome"]["reason"] == "embargoed region"

        with_reason = sign_reactor_reply(_reply_from_vector(vector["message"]), SUBKEY)
        assert with_reason["reason"] == "embargoed region"
        assert with_reason["hmac_signature"] == vector["hmac_signature_hex"]

        unexplained = build_reactor_reply("c", "t", LOGIN_POST_AUTH, "deny")
        assert "reason" not in unexplained
        assert unexplained["decision"] == "deny"

    def test_an_unsigned_reply_never_validates(self) -> None:
        """A reply is an instruction to change a token; unsigned is not a reply."""
        unsigned = build_reactor_reply("c", "t", LOGIN_POST_AUTH, "allow")
        assert unsigned["hmac_signature"] is None
        assert not reactor_reply_signature_valid(unsigned, SUBKEY)
        # A non-hex signature is a mismatch, not an exception.
        assert not reactor_reply_signature_valid({**unsigned, "hmac_signature": "zz"}, SUBKEY)
