"""RFC 7592 client configuration — CONTRACT.md §28.12.6's five required tests.

Every token here is generated at run time: a literal would be a credential in
the repository, and the redaction test needs a value no fixture shares. Failure
messages never print a secret or a rendering that may hold one (fixed text and
offsets only).
"""

from __future__ import annotations

import json
import secrets
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr

from axiam_sdk import (
    AsyncAxiamClient,
    AuthError,
    AxiamClient,
    ClientRegistration,
    NetworkError,
    OAuthProtocolError,
)
from axiam_sdk.management import ValidationError
from tests.management_support import (
    BASE_URL,
    TENANT_ID,
    TENANT_SLUG,
    with_async_client,
    with_client,
)

CLIENT = "dcr-client-1"
REGISTRATION_PATH = f"/oauth2/register/{CLIENT}"
REGISTRATION_URI = f"{BASE_URL}{REGISTRATION_PATH}?tenant_id={TENANT_ID}"


def fresh_token() -> str:
    """A 43-character base64url value, like the server's, random per call."""
    return secrets.token_urlsafe(32)


def assert_no_fragment(haystack: str, secret: str) -> None:
    """No 8-character substring of ``secret`` appears in ``haystack``.

    Fails with an offset only: printing the haystack or the fragment would put
    the secret into the test log.
    """
    for i in range(len(secret) - 7):
        if secret[i : i + 8] in haystack:
            pytest.fail(f"an 8-character fragment of a secret (offset {i}) was rendered")


def registration_body(**extra: Any) -> dict[str, Any]:
    """A server ``ClientRegistration`` body, with ``extra`` members merged in."""
    body: dict[str, Any] = {
        "client_id": CLIENT,
        "client_id_issued_at": 1_700_000_000,
        "client_name": "Agent",
        "redirect_uris": ["https://agent.example.test/cb"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "scope": "openid",
        "registration_client_uri": REGISTRATION_URI,
        "jwks_uri": "https://agent.example.test/jwks",
    }
    body.update(extra)
    return body


def route(router: respx.MockRouter, method: str, response: httpx.Response) -> respx.Route:
    """Mount ``method`` on the registration URI (any query)."""
    return router.request(method, url__startswith=f"{BASE_URL}{REGISTRATION_PATH}").mock(
        return_value=response
    )


# ── 1. Origin refusal ────────────────────────────────────────────────────────


def test_a_uri_at_another_origin_is_refused_locally_and_nothing_is_sent() -> None:
    """Another host, another port, ``http`` against ``https``: local refusal."""
    token = SecretStr(fresh_token())
    with with_client() as (router, client):
        routes = [
            router.request(m, url__regex=r".*/oauth2/register/.*").mock(
                return_value=httpx.Response(200, json=registration_body())
            )
            for m in ("GET", "PUT", "DELETE")
        ]
        for uri in (
            f"https://elsewhere.test{REGISTRATION_PATH}",
            f"https://management.test:8443{REGISTRATION_PATH}",
            f"http://management.test{REGISTRATION_PATH}",
            f"ftp://management.test{REGISTRATION_PATH}",
            REGISTRATION_PATH,
            "https://[::1/not-a-url",
        ):
            with pytest.raises(ValidationError):
                client.read_client_registration(uri, token)
            with pytest.raises(ValidationError):
                client.delete_client_registration(uri, token)
            with pytest.raises(ValidationError):
                client.update_client_registration(uri, token, ClientRegistration(client_id=CLIENT))
        assert all(r.call_count == 0 for r in routes)


def test_http_is_accepted_only_against_an_http_loopback_base() -> None:
    """§28.12.2 rule 1's one exception: an ``http`` base URL on loopback."""
    token = fresh_token()
    base = "http://127.0.0.1:8080"
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{base}{REGISTRATION_PATH}").mock(
            return_value=httpx.Response(200, json=registration_body())
        )
        client = AxiamClient(base_url=base, tenant_slug=TENANT_SLUG)
        assert client.read_client_registration(f"{base}{REGISTRATION_PATH}", token).client_id
        client.close()
    internal = AxiamClient(base_url="http://iam.internal:8080", tenant_slug=TENANT_SLUG)
    with pytest.raises(ValidationError):
        internal.read_client_registration(f"http://iam.internal:8080{REGISTRATION_PATH}", token)
    internal.close()


# ── 2. Header only ───────────────────────────────────────────────────────────


def test_read_and_delete_send_the_bearer_only_and_keep_the_query_verbatim() -> None:
    """A real logged-in session is present; none of it rides along."""
    token = fresh_token()
    with with_client() as (router, client):
        assert client._session.cookie_value("axiam_access"), "the session exists"
        reads = route(router, "GET", httpx.Response(200, json=registration_body()))
        deletes = route(router, "DELETE", httpx.Response(204))

        read = client.read_client_registration(REGISTRATION_URI, SecretStr(token))
        assert read.client_id == CLIENT
        assert read.registration_access_token is None
        assert client.delete_client_registration(REGISTRATION_URI, token) is None

        for call in (*reads.calls, *deletes.calls):
            request = call.request
            if request.headers.get("authorization") != f"Bearer {token}":
                pytest.fail("the request did not carry exactly the registration bearer")
            assert "cookie" not in request.headers, "no session cookie"
            assert "x-csrf-token" not in request.headers
            assert "x-tenant-id" not in request.headers
            assert request.content == b"", "no body"
            assert request.url.query == f"tenant_id={TENANT_ID}".encode()


# ── 3. Update body ───────────────────────────────────────────────────────────


def test_update_drops_the_five_server_stated_members_and_returns_the_rotated_token() -> None:
    """Rule 4's body, and the rotated token handed back."""
    rotated = fresh_token()
    with with_client() as (router, client):
        puts = route(
            router,
            "PUT",
            httpx.Response(200, json=registration_body(registration_access_token=rotated)),
        )
        metadata = ClientRegistration.model_validate(
            registration_body(
                registration_access_token=fresh_token(),
                client_secret=fresh_token(),
                client_secret_expires_at=0,
                backchannel_token_delivery_mode="poll",
            )
        )
        metadata.client_name = "Agent v2"
        updated = client.update_client_registration(
            REGISTRATION_URI, SecretStr(fresh_token()), metadata
        )
        assert updated.registration_access_token is not None
        if updated.registration_access_token.get_secret_value() != rotated:
            pytest.fail("the rotated token was not returned")

        assert puts.call_count == 1
        body = json.loads(puts.calls[0].request.content)
        for gone in (
            "registration_access_token",
            "registration_client_uri",
            "client_secret_expires_at",
            "client_id_issued_at",
            "client_secret",
        ):
            assert gone not in body, gone
        assert body["client_id"] == CLIENT
        assert body["client_name"] == "Agent v2"
        assert body["jwks_uri"] == "https://agent.example.test/jwks"
        assert body["backchannel_token_delivery_mode"] == "poll", "unknown members round-trip"


def test_an_update_answered_503_is_not_retried() -> None:
    """A retry-enabled client sends exactly one ``PUT``."""
    with with_client() as (router, client):
        assert client._retry_enabled
        puts = route(router, "PUT", httpx.Response(503))
        metadata = ClientRegistration.model_validate(registration_body())
        with pytest.raises(NetworkError):
            client.update_client_registration(REGISTRATION_URI, fresh_token(), metadata)
        assert puts.call_count == 1


def test_a_delete_answered_503_is_not_retried_and_a_read_is() -> None:
    """Delete once; the read MAY be retried per §16."""
    with with_client() as (router, client):
        deletes = route(router, "DELETE", httpx.Response(503))
        reads = route(router, "GET", httpx.Response(503))
        with pytest.raises(NetworkError):
            client.delete_client_registration(REGISTRATION_URI, fresh_token())
        assert deletes.call_count == 1
        with pytest.raises(NetworkError):
            client.read_client_registration(REGISTRATION_URI, fresh_token())
        assert reads.call_count > 1


def test_a_read_is_never_retried_on_a_bodiless_400() -> None:
    """§28.12.2 rule 5: a 4xx other than 408/429 is decisive."""
    with with_client() as (router, client):
        reads = route(router, "GET", httpx.Response(400))
        with pytest.raises(NetworkError):
            client.read_client_registration(REGISTRATION_URI, fresh_token())
        assert reads.call_count == 1


def test_a_transport_failure_is_a_network_error_and_an_unusable_body_too() -> None:
    """Connection errors and a body that is not a registration map to §2."""
    with with_client() as (router, client):
        client._retry_enabled = False
        route(router, "GET", httpx.Response(200, json=["not", "an", "object"]))
        with pytest.raises(NetworkError):
            client.read_client_registration(REGISTRATION_URI, fresh_token())
        router.routes.clear()
        router.request("PUT", url__startswith=f"{BASE_URL}{REGISTRATION_PATH}").mock(
            side_effect=httpx.ConnectError("refused")
        )
        router.request("DELETE", url__startswith=f"{BASE_URL}{REGISTRATION_PATH}").mock(
            side_effect=httpx.ConnectError("refused")
        )
        router.request("GET", url__startswith=f"{BASE_URL}{REGISTRATION_PATH}").mock(
            side_effect=httpx.ConnectError("refused")
        )
        metadata = ClientRegistration(client_id=CLIENT)
        with pytest.raises(NetworkError):
            client.update_client_registration(REGISTRATION_URI, fresh_token(), metadata)
        with pytest.raises(NetworkError):
            client.delete_client_registration(REGISTRATION_URI, fresh_token())
        with pytest.raises(NetworkError):
            client.read_client_registration(REGISTRATION_URI, fresh_token())
        router.routes.clear()
        route(router, "GET", httpx.Response(200, text="not json"))
        with pytest.raises(NetworkError):
            client.read_client_registration(REGISTRATION_URI, fresh_token())


# ── 4. Errors ────────────────────────────────────────────────────────────────


def test_a_401_invalid_token_is_an_oauth_protocol_error_and_refreshes_nothing() -> None:
    """The §9 guard is never entered — the refresh route records no call."""
    with with_client() as (router, client):
        refresh = router.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
            return_value=httpx.Response(500)
        )
        route(
            router,
            "GET",
            httpx.Response(
                401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                json={"error": "invalid_token"},
            ),
        )
        with pytest.raises(OAuthProtocolError) as excinfo:
            client.read_client_registration(REGISTRATION_URI, fresh_token())
        assert excinfo.value.error == "invalid_token"
        assert refresh.call_count == 0


def test_a_400_invalid_client_metadata_is_an_oauth_protocol_error_and_204_is_ok() -> None:
    """Dispatched on ``error``; a ``204`` on delete returns normally."""
    with with_client() as (router, client):
        route(
            router,
            "PUT",
            httpx.Response(
                400, json={"error": "invalid_client_metadata", "error_description": "scope"}
            ),
        )
        route(router, "DELETE", httpx.Response(204))
        with pytest.raises(OAuthProtocolError) as excinfo:
            client.update_client_registration(
                REGISTRATION_URI,
                fresh_token(),
                ClientRegistration.model_validate(registration_body()),
            )
        assert excinfo.value.error == "invalid_client_metadata"
        assert excinfo.value.error_description == "scope"
        client.delete_client_registration(REGISTRATION_URI, fresh_token())


def test_a_bodiless_401_is_an_auth_error() -> None:
    """No ``error`` member: §2 by status."""
    with with_client() as (router, client):
        route(router, "DELETE", httpx.Response(401))
        with pytest.raises(AuthError) as excinfo:
            client.delete_client_registration(REGISTRATION_URI, fresh_token())
        assert not isinstance(excinfo.value, OAuthProtocolError)


# ── 5. Redaction ─────────────────────────────────────────────────────────────


def test_neither_the_token_nor_the_secret_reaches_any_rendering() -> None:
    """``repr``, ``str``, JSON and an operation's errors hold neither secret."""
    token = fresh_token()
    secret = fresh_token()
    registration = ClientRegistration.model_validate(
        registration_body(registration_access_token=token, client_secret=secret)
    )
    for rendering in (
        repr(registration),
        str(registration),
        registration.model_dump_json(),
        json.dumps(registration.model_dump(mode="json")),
    ):
        assert_no_fragment(rendering, token)
        assert_no_fragment(rendering, secret)
    assert "client_secret" not in registration.update_body()

    with with_client() as (router, client):
        route(router, "GET", httpx.Response(401, json={"error": "invalid_token"}))
        with pytest.raises(OAuthProtocolError) as excinfo:
            client.read_client_registration(REGISTRATION_URI, token)
        assert_no_fragment(f"{excinfo.value} {excinfo.value!r}", token)
        with pytest.raises(ValidationError) as refused:
            client.read_client_registration("https://elsewhere.test/r", token)
        assert_no_fragment(f"{refused.value} {refused.value!r}", token)


def test_decoding_keeps_unknown_and_mistyped_members_and_drops_mistyped_secrets() -> None:
    """Tolerant decode: nothing the server holds is lost on a round trip."""
    r = ClientRegistration.model_validate(
        {
            "client_id": "c1",
            "client_secret": 42,
            "client_id_issued_at": "not-a-number",
            "redirect_uris": "https://a",
            "jwks": "not-an-object",
            "client_name": None,
            "backchannel_token_delivery_mode": "poll",
        }
    )
    assert r.client_secret is None
    assert r.extra["client_id_issued_at"] == "not-a-number"
    assert r.extra["backchannel_token_delivery_mode"] == "poll"
    body = r.update_body()
    assert "client_id_issued_at" not in body
    assert body["redirect_uris"] == "https://a"
    assert body["jwks"] == "not-an-object"
    assert "grant_types" not in body, "a list never on the read is not invented"
    assert ClientRegistration.model_validate(r.model_dump()) == r, "a dump re-validates"
    built = ClientRegistration(client_id="c2", client_secret=SecretStr("x"), jwks={"keys": []})
    assert built.client_secret is not None
    assert built.update_body() == {"client_id": "c2", "jwks": {"keys": []}}


# ── The async client carries the same three names ────────────────────────────


@pytest.mark.asyncio
async def test_the_async_client_carries_the_same_three_operations() -> None:
    """Read (retried on 503), update and delete (not retried), and refusals."""
    token = fresh_token()
    rotated = fresh_token()
    async with with_async_client() as (router, client):
        reads = router.request("GET", url__startswith=f"{BASE_URL}{REGISTRATION_PATH}").mock(
            side_effect=[httpx.Response(503), httpx.Response(200, json=registration_body())]
        )
        puts = route(
            router,
            "PUT",
            httpx.Response(200, json=registration_body(registration_access_token=rotated)),
        )
        deletes = route(router, "DELETE", httpx.Response(204))

        read = await client.read_client_registration(REGISTRATION_URI, token)
        assert reads.call_count == 2
        updated = await client.update_client_registration(REGISTRATION_URI, token, read)
        assert updated.registration_access_token is not None
        if updated.registration_access_token.get_secret_value() != rotated:
            pytest.fail("the rotated token was not returned")
        await client.delete_client_registration(REGISTRATION_URI, token)
        assert puts.call_count == 1 and deletes.call_count == 1
        for call in (*reads.calls, *puts.calls, *deletes.calls):
            assert "cookie" not in call.request.headers

        router.routes.clear()
        route(router, "GET", httpx.Response(400))
        failing_put = route(router, "PUT", httpx.Response(503))
        failing_delete = route(router, "DELETE", httpx.Response(400, json={"error": "x"}))
        with pytest.raises(NetworkError):
            await client.read_client_registration(REGISTRATION_URI, token)
        with pytest.raises(NetworkError):
            await client.update_client_registration(REGISTRATION_URI, token, read)
        with pytest.raises(OAuthProtocolError):
            await client.delete_client_registration(REGISTRATION_URI, token)
        assert failing_put.call_count == 1 and failing_delete.call_count == 1

        router.routes.clear()
        for method in ("GET", "PUT", "DELETE"):
            router.request(method, url__startswith=f"{BASE_URL}{REGISTRATION_PATH}").mock(
                side_effect=httpx.ConnectError("refused")
            )
        client._retry_enabled = False
        with pytest.raises(NetworkError):
            await client.read_client_registration(REGISTRATION_URI, token)
        with pytest.raises(NetworkError):
            await client.update_client_registration(REGISTRATION_URI, token, read)
        with pytest.raises(NetworkError):
            await client.delete_client_registration(REGISTRATION_URI, token)

        with pytest.raises(ValidationError):
            await client.read_client_registration("https://elsewhere.test/r", token)


@pytest.mark.asyncio
async def test_closing_the_async_client_closes_its_bare_transport() -> None:
    """The session-free transport is released with the client (§18)."""
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
    bare = client._session.bare_async_client
    await client.aclose()
    assert bare.is_closed
    sync = AxiamClient(base_url=BASE_URL, tenant_slug=TENANT_SLUG)
    sync_bare = sync._session.bare_sync_client
    sync.close()
    assert sync_bare.is_closed
