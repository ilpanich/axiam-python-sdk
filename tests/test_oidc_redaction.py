"""Redaction tests for the new §12 secret fields (CONTRACT.md §12.5):
``access_token``, ``refresh_token``, ``id_token``, ``client_secret``, and
``code_verifier`` MUST never appear in ``repr``/``str``/serialized output.
``state``/``nonce`` are NOT secrets (§12.3 rule 2) and ARE expected to
appear as plain strings."""

from __future__ import annotations

from pydantic import SecretStr

from axiam_sdk import AuthorizationRequest, OidcTokenSet
from axiam_sdk._oidc_state import OidcStateEntry

SECRET_CODE_VERIFIER = "super-secret-code-verifier-value"
SECRET_ACCESS_TOKEN = "super-secret-access-token-value"  # noqa: S105 - test fixture, not real
SECRET_REFRESH_TOKEN = "super-secret-refresh-token-value"  # noqa: S105
SECRET_ID_TOKEN = "super-secret-id-token-value"  # noqa: S105
PLAIN_STATE = "plain-state-value-not-secret"
PLAIN_NONCE = "plain-nonce-value-not-secret"


def test_authorization_request_redacts_code_verifier_but_not_state_or_nonce() -> None:
    request = AuthorizationRequest(
        url="https://axiam.example.test/oauth2/authorize?x=1",
        state=PLAIN_STATE,
        nonce=PLAIN_NONCE,
        code_verifier=SecretStr(SECRET_CODE_VERIFIER),
    )

    rendered = repr(request) + str(request)
    assert SECRET_CODE_VERIFIER not in rendered
    # state/nonce are plain, non-secret strings (§12.3 rule 2) — they DO
    # appear, proving the redaction above is selective, not blanket.
    assert PLAIN_STATE in rendered
    assert PLAIN_NONCE in rendered


def test_authorization_request_model_dump_redacts_code_verifier() -> None:
    request = AuthorizationRequest(
        url="https://axiam.example.test/oauth2/authorize",
        state=PLAIN_STATE,
        nonce=PLAIN_NONCE,
        code_verifier=SecretStr(SECRET_CODE_VERIFIER),
    )
    dumped = request.model_dump()
    assert SECRET_CODE_VERIFIER not in str(dumped)
    assert request.code_verifier.get_secret_value() == SECRET_CODE_VERIFIER


def test_authorization_request_model_dump_json_redacts_code_verifier() -> None:
    """F-11: ``model_dump_json()`` — the actual structured-serialization
    sink a caller would use to persist/transmit an ``AuthorizationRequest``
    — must redact ``code_verifier``. Unlike plain ``model_dump()``, this
    does not rely on ``str()`` of a returned ``SecretStr`` object; the JSON
    string itself must not contain the raw value."""
    request = AuthorizationRequest(
        url="https://axiam.example.test/oauth2/authorize",
        state=PLAIN_STATE,
        nonce=PLAIN_NONCE,
        code_verifier=SecretStr(SECRET_CODE_VERIFIER),
    )
    dumped_json = request.model_dump_json()
    assert SECRET_CODE_VERIFIER not in dumped_json
    assert PLAIN_STATE in dumped_json
    assert PLAIN_NONCE in dumped_json

    dumped_json_mode = request.model_dump(mode="json")
    assert SECRET_CODE_VERIFIER not in str(dumped_json_mode)
    assert isinstance(dumped_json_mode["code_verifier"], str)


def test_oidc_token_set_redacts_all_three_secret_fields() -> None:
    token_set = OidcTokenSet(
        access_token=SecretStr(SECRET_ACCESS_TOKEN),
        token_type="Bearer",
        expires_in=900,
        refresh_token=SecretStr(SECRET_REFRESH_TOKEN),
        id_token=SecretStr(SECRET_ID_TOKEN),
    )

    rendered = repr(token_set) + str(token_set) + str(token_set.model_dump())
    assert SECRET_ACCESS_TOKEN not in rendered
    assert SECRET_REFRESH_TOKEN not in rendered
    assert SECRET_ID_TOKEN not in rendered


def test_oidc_token_set_secrets_are_reachable_only_via_get_secret_value() -> None:
    token_set = OidcTokenSet(
        access_token=SecretStr(SECRET_ACCESS_TOKEN), token_type="Bearer", expires_in=900
    )
    assert token_set.access_token.get_secret_value() == SECRET_ACCESS_TOKEN


def test_oidc_token_set_model_dump_json_redacts_all_three_secret_fields() -> None:
    """F-11: the structured-serialization sink. ``model_dump_json()`` and
    ``model_dump(mode="json")`` must redact ``access_token``,
    ``refresh_token``, and ``id_token`` in the emitted JSON/JSON-mode value
    itself, not merely when that value is later ``str()``-ed."""
    token_set = OidcTokenSet(
        access_token=SecretStr(SECRET_ACCESS_TOKEN),
        token_type="Bearer",
        expires_in=900,
        refresh_token=SecretStr(SECRET_REFRESH_TOKEN),
        id_token=SecretStr(SECRET_ID_TOKEN),
    )

    dumped_json = token_set.model_dump_json()
    assert SECRET_ACCESS_TOKEN not in dumped_json
    assert SECRET_REFRESH_TOKEN not in dumped_json
    assert SECRET_ID_TOKEN not in dumped_json

    dumped_json_mode = token_set.model_dump(mode="json")
    rendered = str(dumped_json_mode)
    assert SECRET_ACCESS_TOKEN not in rendered
    assert SECRET_REFRESH_TOKEN not in rendered
    assert SECRET_ID_TOKEN not in rendered
    # In JSON mode the dumped values are already plain redacted strings,
    # unlike plain model_dump()'s SecretStr objects (see the test below).
    assert dumped_json_mode["access_token"] == "**********"


def test_oidc_token_set_plain_model_dump_does_not_itself_redact() -> None:
    """F-11 (documentation correctness): plain ``model_dump()`` (pydantic's
    python mode, the default) does NOT redact by itself — it returns the
    ``SecretStr`` object unchanged, so the raw value stays reachable off the
    returned dict via ``.get_secret_value()``. The existing
    ``test_oidc_token_set_redacts_all_three_secret_fields`` only appears to
    show redaction because it wraps the result in ``str(...)``, which
    invokes ``SecretStr.__str__``. This test pins down the precise,
    non-obvious behaviour so the docstring claim above cannot regress into
    the imprecise "``model_dump`` redacts" claim it used to make."""
    token_set = OidcTokenSet(
        access_token=SecretStr(SECRET_ACCESS_TOKEN), token_type="Bearer", expires_in=900
    )
    dumped = token_set.model_dump()
    assert isinstance(dumped["access_token"], SecretStr)
    assert dumped["access_token"].get_secret_value() == SECRET_ACCESS_TOKEN


def test_oidc_state_entry_redacts_code_verifier() -> None:
    entry = OidcStateEntry(
        state=PLAIN_STATE,
        nonce=PLAIN_NONCE,
        code_verifier=SecretStr(SECRET_CODE_VERIFIER),
        redirect_uri="https://app.test/callback",
    )
    rendered = repr(entry) + str(entry)
    assert SECRET_CODE_VERIFIER not in rendered
    assert PLAIN_STATE in rendered
    assert PLAIN_NONCE in rendered


def test_client_secret_is_redacted_on_the_client() -> None:
    from axiam_sdk import AxiamClient

    client = AxiamClient(
        base_url="https://axiam.example.test",
        tenant_slug="acme",
        client_id="rp-1",
        client_secret="super-secret-client-secret-value",
    )
    rendered = repr(client._oidc_client_secret) + str(client._oidc_client_secret)
    assert "super-secret-client-secret-value" not in rendered
