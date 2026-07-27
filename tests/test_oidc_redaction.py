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
