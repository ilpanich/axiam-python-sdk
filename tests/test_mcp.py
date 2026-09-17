"""Regression tests for the framework-independent half of CONTRACT.md §28
(MCP resource-server helpers, RFC 9728 + RFC 6750): §28.9 required tests 1
and 2, run directly against :func:`axiam_sdk.protected_resource_metadata`
and :func:`axiam_sdk.bearer_challenge` — no HTTP server needed, mirroring
how the TypeScript reference (T9b) splits these two into
``mcp.contract.test.ts`` and leaves the three that need a live guard to the
per-framework suites (``test_fastapi_mcp.py``, ``test_django_mcp.py``).

The fixture below is §28.9's own, verbatim, so a divergence from another
SDK's port is visible as a different expected value rather than a different
test.
"""

from __future__ import annotations

import pytest

from axiam_sdk import (
    ProtectedResourceMetadata,
    bearer_challenge,
    protected_resource_metadata,
)
from axiam_sdk._mcp import is_metadata_document_request, mcp_guard_challenges
from axiam_sdk.management import ValidationError

RESOURCE = "https://mcp.example.com/mcp"
AUTHORIZATION_SERVERS = ["https://axiam.example.com"]
SCOPES_SUPPORTED = ["mcp:read", "mcp:tools"]
RESOURCE_DOCUMENTATION = "https://mcp.example.com/docs"

METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
METADATA_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
EXPECTED_AUDIENCE = "https://mcp.example.com/mcp"


def _fixture(**overrides: object) -> ProtectedResourceMetadata:
    kwargs: dict[str, object] = {
        "resource": RESOURCE,
        "authorization_servers": AUTHORIZATION_SERVERS,
        "scopes_supported": SCOPES_SUPPORTED,
        "resource_documentation": RESOURCE_DOCUMENTATION,
    }
    kwargs.update(overrides)
    return protected_resource_metadata(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §28.9 test 1 — document shape, and the validation negatives
# ---------------------------------------------------------------------------


def test_fixture_produces_the_exact_document_shape() -> None:
    metadata = _fixture()
    assert metadata.document.to_dict() == {
        "resource": RESOURCE,
        "authorization_servers": AUTHORIZATION_SERVERS,
        "scopes_supported": SCOPES_SUPPORTED,
        "bearer_methods_supported": ["header"],
        "resource_documentation": RESOURCE_DOCUMENTATION,
    }
    assert metadata.metadata_path == METADATA_PATH
    assert metadata.metadata_url == METADATA_URL


@pytest.mark.parametrize(
    ("resource", "expected_path"),
    [
        ("https://mcp.example.com", "/.well-known/oauth-protected-resource"),
        ("https://mcp.example.com/", "/.well-known/oauth-protected-resource"),
        ("https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp"),
        ("https://mcp.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp/"),
        ("https://mcp.example.com/a/b", "/.well-known/oauth-protected-resource/a/b"),
    ],
)
def test_metadata_path_derivation_table(resource: str, expected_path: str) -> None:
    metadata = _fixture(resource=resource)
    assert metadata.metadata_path == expected_path


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"resource": "mcp.example.com/mcp"}, id="relative-resource"),
        pytest.param({"resource": "https://mcp.example.com/mcp#frag"}, id="resource-fragment"),
        pytest.param({"resource": "https://mcp.example.com/mcp?q=1"}, id="resource-query"),
        pytest.param({"resource": "http://mcp.example.com/mcp"}, id="http-non-loopback"),
        pytest.param({"authorization_servers": []}, id="empty-authorization-servers"),
        pytest.param(
            {"authorization_servers": ["https://axiam.example.com?q=1"]},
            id="authorization-server-query",
        ),
        pytest.param(
            {"authorization_servers": ["https://axiam.example.com#frag"]},
            id="authorization-server-fragment",
        ),
        pytest.param(
            {"authorization_servers": ["https://axiam.example.com", "https://axiam.example.com"]},
            id="duplicate-authorization-server",
        ),
        pytest.param({"scopes_supported": ["mcp:read", "mcp:read"]}, id="duplicate-scope"),
        pytest.param({"bearer_methods_supported": ["query"]}, id="bearer-methods-query"),
        pytest.param(
            {"bearer_methods_supported": ["header", "body"]}, id="bearer-methods-header-and-body"
        ),
    ],
)
def test_validation_negatives_refuse_and_register_no_route(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _fixture(**kwargs)


def test_http_on_loopback_host_is_accepted() -> None:
    metadata = _fixture(
        resource="http://127.0.0.1/mcp",
        authorization_servers=["https://axiam.example.com"],
    )
    assert metadata.document.resource == "http://127.0.0.1/mcp"


def test_http_on_ipv6_loopback_host_is_accepted() -> None:
    metadata = _fixture(
        resource="http://[::1]/mcp",
        authorization_servers=["https://axiam.example.com"],
    )
    assert metadata.document.resource == "http://[::1]/mcp"


def test_empty_resource_string_is_refused() -> None:
    with pytest.raises(ValidationError):
        _fixture(resource="")


def test_authority_only_form_with_empty_authority_is_refused() -> None:
    with pytest.raises(ValidationError):
        _fixture(resource="https:///mcp")


def test_scope_containing_a_space_is_refused() -> None:
    with pytest.raises(ValidationError):
        _fixture(scopes_supported=["mcp read"])


def test_empty_scopes_supported_is_accepted_and_omits_the_member() -> None:
    metadata = _fixture(scopes_supported=[])
    assert "scopes_supported" not in metadata.document.to_dict()
    assert metadata.document.scopes_supported is None


def test_absent_resource_documentation_omits_the_member_not_null() -> None:
    metadata = _fixture(resource_documentation=None)
    document = metadata.document.to_dict()
    assert "resource_documentation" not in document
    assert metadata.document.resource_documentation is None


# ---------------------------------------------------------------------------
# §28.9 test 2 — challenge quoting
# ---------------------------------------------------------------------------


def test_vector_1_no_credential_presented() -> None:
    assert bearer_challenge(METADATA_URL) == f'Bearer resource_metadata="{METADATA_URL}"'


def test_vector_2_credential_presented_and_rejected() -> None:
    assert (
        bearer_challenge(METADATA_URL, error="invalid_token")
        == f'Bearer error="invalid_token", resource_metadata="{METADATA_URL}"'
    )


def test_vector_3_scope_failure_403() -> None:
    expected = (
        f'Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="{METADATA_URL}"'
    )
    assert bearer_challenge(METADATA_URL, error="insufficient_scope", scope="mcp:tools") == expected


def test_vector_4_all_four_parameters() -> None:
    assert bearer_challenge(
        METADATA_URL,
        error="invalid_request",
        error_description="The access token is malformed",
        scope="mcp:read mcp:tools",
    ) == (
        'Bearer error="invalid_request", error_description="The access token is malformed", '
        f'scope="mcp:read mcp:tools", resource_metadata="{METADATA_URL}"'
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"error": "invalid_grant"}, id="unknown-error-code"),
        pytest.param({"error_description": 'has a " in it'}, id="error-description-quote"),
        pytest.param({"error_description": "has a \\ in it"}, id="error-description-backslash"),
        pytest.param({"error_description": "has a \n in it"}, id="error-description-newline"),
        pytest.param({"error_description": "has a é in it"}, id="error-description-non-ascii"),
        pytest.param({"scope": " mcp:read"}, id="scope-leading-space"),
        pytest.param({"scope": "mcp:read  mcp:tools"}, id="scope-doubled-space"),
        pytest.param({"scope": ""}, id="scope-empty"),
    ],
)
def test_challenge_refusals_raise_rather_than_escape(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        bearer_challenge(METADATA_URL, **kwargs)  # type: ignore[arg-type]


def test_resource_metadata_containing_space_is_refused() -> None:
    with pytest.raises(ValidationError):
        bearer_challenge("https://mcp.example.com/a b")


# ---------------------------------------------------------------------------
# Internal wiring: mcp_guard_challenges / is_metadata_document_request
# ---------------------------------------------------------------------------


def test_is_metadata_document_request_rejects_non_get_head_methods() -> None:
    challenges = mcp_guard_challenges(EXPECTED_AUDIENCE, METADATA_URL, "test")
    assert challenges is not None
    assert is_metadata_document_request(challenges, "GET", METADATA_PATH) is True
    assert is_metadata_document_request(challenges, "HEAD", METADATA_PATH) is True
    assert is_metadata_document_request(challenges, "POST", METADATA_PATH) is False
    assert is_metadata_document_request(challenges, "GET", "/somewhere/else") is False


def test_is_metadata_document_request_is_false_when_mcp_is_off() -> None:
    assert is_metadata_document_request(None, "GET", METADATA_PATH) is False


def test_refusal_never_produces_an_escaped_challenge() -> None:
    """Assert the refused values raise rather than silently escaping into a
    challenge containing a literal ``\\"`` — CONTRACT.md §28.9 test 2's
    closing instruction."""
    with pytest.raises(ValidationError) as excinfo:
        bearer_challenge(METADATA_URL, error_description='has a " in it')
    assert '\\"' not in str(excinfo.value)
