"""Extra coverage for ``_errors`` branches not hit by ``test_error_redaction``:
a 403 whose body is not JSON (the ValueError -> body=None guard) and
``error_from_grpc_status`` classification when given a bare status name/int
rather than a ``grpc.StatusCode`` member (the normalization loop).
"""

from __future__ import annotations

import httpx

from axiam_sdk._errors import (
    AuthError,
    AuthzError,
    NetworkError,
    error_from_grpc_status,
    error_from_http_status,
)


def test_403_with_non_json_body_leaves_fields_none() -> None:
    """A 403 whose body is not valid JSON must not raise — the parse
    ValueError is caught and action/resource_id stay None."""
    response = httpx.Response(
        403,
        content=b"not json at all",
        request=httpx.Request("POST", "https://example.test/api/v1/authz/check"),
    )
    err = error_from_http_status(403, "forbidden", response=response)
    assert isinstance(err, AuthzError)
    assert err.action is None
    assert err.resource_id is None


def test_403_with_json_array_body_leaves_fields_none() -> None:
    """A 403 whose body decodes to a non-object (array) is ignored — the
    isinstance(body, dict) guard keeps action/resource_id None."""
    response = httpx.Response(
        403,
        json=["not", "an", "object"],
        request=httpx.Request("POST", "https://example.test/api/v1/authz/check"),
    )
    err = error_from_http_status(403, "forbidden", response=response)
    assert isinstance(err, AuthzError)
    assert err.action is None


def test_grpc_status_by_int_code_maps_to_auth_error() -> None:
    """UNAUTHENTICATED's numeric code (16) normalizes to the StatusCode
    member and maps to AuthError."""
    err = error_from_grpc_status(16, "no creds")
    assert isinstance(err, AuthError)


def test_grpc_status_by_name_maps_to_authz_error() -> None:
    """A bare status *name* string normalizes to the member and maps to
    AuthzError for PERMISSION_DENIED."""
    err = error_from_grpc_status("PERMISSION_DENIED", "denied")
    assert isinstance(err, AuthzError)


def test_grpc_status_unknown_code_falls_back_to_network_error() -> None:
    """A code that matches no member stays un-normalized and falls through
    to the NetworkError default."""
    err = error_from_grpc_status(9999, "weird")
    assert isinstance(err, NetworkError)
