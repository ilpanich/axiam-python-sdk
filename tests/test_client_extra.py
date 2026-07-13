"""Extra coverage for the sync ``AxiamClient`` / shared ``_AxiamClientBase``
error and body-building branches not already hit by ``test_client_login.py``.

Targets the guard/validation paths: malformed-token segment count, the
``org_id`` login-body branch, the ``scope`` authz-body branch, the
absorb/refresh/logout "no cookie / no claim" AuthError guards, and the
``_refresh_identifiers`` tenant_id/org_id resolution failures. All offline
(respx or pure helper calls).
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from axiam_sdk import AuthError, AxiamClient, NetworkError
from axiam_sdk._client import _AxiamClientBase, _decode_unverified_claims

BASE_URL = "https://example.test"


def _token(payload: dict[str, object]) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.fake-signature"


def _make_access_token(
    *,
    tenant_id: str = "tenant-uuid-1",
    org_id: str = "org-uuid-1",
    jti: str = "session-uuid-1",
) -> str:
    return _token(
        {"sub": "u", "tenant_id": tenant_id, "org_id": org_id, "jti": jti, "exp": 9999999999}
    )


def _set_cookie(name: str, value: str, path: str = "/") -> tuple[str, str]:
    return ("Set-Cookie", f"{name}={value}; Path={path}; HttpOnly")


# ---------------------------------------------------------------------
# _decode_unverified_claims — malformed segment count (line 46)
# ---------------------------------------------------------------------


def test_decode_rejects_wrong_segment_count() -> None:
    with pytest.raises(AuthError, match="expected 3 segments"):
        _decode_unverified_claims("only.two")
    with pytest.raises(AuthError, match="expected 3 segments"):
        _decode_unverified_claims("a.b.c.d")


# ---------------------------------------------------------------------
# login body: org_id branch (line 161)
# ---------------------------------------------------------------------


def test_login_body_includes_org_id_when_configured(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    route = respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie("axiam_access", access)],
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme", org_id="org-uuid-9") as client:
        client.login("user@example.com", "password123")

    sent = json.loads(route.calls.last.request.content)
    assert sent["org_id"] == "org-uuid-9"
    assert "org_slug" not in sent


# ---------------------------------------------------------------------
# absorb: 200 login without axiam_access cookie (line 220)
# ---------------------------------------------------------------------


def test_login_200_without_access_cookie_raises(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200, json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900}
        )
    )

    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(AuthError, match="did not set the axiam_access cookie"):
            client.login("user@example.com", "password123")


# ---------------------------------------------------------------------
# check_access scope branch (line 328)
# ---------------------------------------------------------------------


def test_check_access_sends_scope(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie("axiam_access", access)],
        )
    )
    route = respx_mock.post(f"{BASE_URL}/api/v1/authz/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None})
    )

    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    client.login("user@example.com", "password123")
    client.check_access("users:read", "user-42", scope="field:email")
    client.close()

    sent = json.loads(route.calls.last.request.content)
    assert sent["scope"] == "field:email"


# ---------------------------------------------------------------------
# refresh: no token guard (line 394)
# ---------------------------------------------------------------------


def test_sync_refresh_without_login_raises() -> None:
    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(AuthError, match="no access token to refresh"):
            client.refresh()


# ---------------------------------------------------------------------
# refresh response 200 without a fresh cookie (line 290)
# ---------------------------------------------------------------------


def test_handle_refresh_response_200_without_access_cookie_raises() -> None:
    # A 200 refresh response that leaves NO axiam_access in the cookie jar
    # must raise rather than silently returning a None token (line 290).
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    response = httpx.Response(
        200,
        json={"expires_in": 900},
        request=httpx.Request("POST", f"{BASE_URL}/api/v1/auth/refresh"),
    )
    with pytest.raises(AuthError, match="did not set axiam_access"):
        client._handle_refresh_response(response)
    client.close()


# ---------------------------------------------------------------------
# logout (lines 307-314, 425-432)
# ---------------------------------------------------------------------


def test_sync_logout_success(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token(jti="session-jti-77")
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie("axiam_access", access)],
        )
    )
    route = respx_mock.post(f"{BASE_URL}/api/v1/auth/logout").mock(
        return_value=httpx.Response(200, json={})
    )

    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    client.login("user@example.com", "password123")
    client.logout()
    client.close()

    sent = json.loads(route.calls.last.request.content)
    assert sent["session_id"] == "session-jti-77"


def test_sync_logout_error_status_raises(respx_mock: respx.MockRouter) -> None:
    access = _make_access_token()
    respx_mock.post(f"{BASE_URL}/api/v1/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={"user": {"id": "user-1"}, "session_id": "s1", "expires_in": 900},
            headers=[_set_cookie("axiam_access", access)],
        )
    )
    respx_mock.post(f"{BASE_URL}/api/v1/auth/logout").mock(
        return_value=httpx.Response(500, json={"error": "boom"})
    )

    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    client.login("user@example.com", "password123")
    with pytest.raises(NetworkError):
        client.logout()
    client.close()


def test_logout_without_session_raises() -> None:
    with AxiamClient(base_url=BASE_URL, tenant_slug="acme") as client:
        with pytest.raises(AuthError, match="no active session to log out"):
            client.logout()


def test_session_id_for_logout_requires_jti() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    # Seed a cookie whose token carries no jti claim.
    no_jti = _token({"sub": "u", "tenant_id": "t", "org_id": "o", "exp": 9999999999})
    client._session.sync_client.cookies.set("axiam_access", no_jti)
    with pytest.raises(AuthError, match="no session id"):
        client._session_id_for_logout()
    client.close()


# ---------------------------------------------------------------------
# _refresh_identifiers resolution failures (lines 253, 256)
# ---------------------------------------------------------------------


def test_refresh_identifiers_missing_tenant_id() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    token = _token({"sub": "u", "org_id": "o", "exp": 9999999999})
    with pytest.raises(AuthError, match="tenant_id could not be resolved"):
        client._refresh_identifiers(token)
    client.close()


def test_refresh_identifiers_missing_org_id() -> None:
    # No org_id configured and the token carries no org_id claim either.
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    assert client.resolved_org_id() is None
    token = _token({"sub": "u", "tenant_id": "t", "exp": 9999999999})
    with pytest.raises(AuthError, match="org_id could not be resolved"):
        client._refresh_identifiers(token)
    client.close()


def test_refresh_identifiers_resolves_both() -> None:
    client = AxiamClient(base_url=BASE_URL, tenant_slug="acme")
    token = _token({"sub": "u", "tenant_id": "t-1", "org_id": "o-1", "exp": 9999999999})
    tenant_id, org_id = client._refresh_identifiers(token)
    assert (tenant_id, org_id) == ("t-1", "o-1")
    client.close()


# ---------------------------------------------------------------------
# _AxiamClientBase is directly constructible with the shared logic.
# ---------------------------------------------------------------------


def test_base_login_body_omits_org_when_none() -> None:
    base = _AxiamClientBase(base_url=BASE_URL, tenant_slug="acme")
    body = base._login_body("u@example.com", "pw")
    assert "org_id" not in body and "org_slug" not in body
    assert body["tenant_slug"] == "acme"
