"""Device grant client authentication -- CONTRACT.md §14.1 rule 2, §14.6 (contract 1.62).

Since 1.1.0 both device endpoints authenticate the client by the method it is
registered for, and an SDK client sends the credential it was configured with at
**both** ``device_authorize`` and every ``device_poll``, by the rules of its other
token requests (§34.6 items m and t):

* a client **secret** is the ``client_secret`` form member -- for a
  ``client_secret_basic`` registration too: no SDK sends ``Authorization: Basic`` to
  an ``/oauth2/*`` route (§12.1 rule 3);
* an **mTLS** client presents its certificate on the connection;
* a **public** client sends none, and is neither refused client-side nor given one;
* the poll names its client (``client_id``) on every poll;
* a ``401 invalid_client`` from either endpoint is an ``OAuthProtocolError``, sent
  once, never refreshed.

This SDK has no ``private_key_jwt`` assertion and generates no DPoP proof, so those
two forms have no test here; the README says so.
"""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient, OAuthProtocolError, OidcConfiguration
from tests._oidc_testkit import (
    BASE_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    DEVICE_AUTHORIZATION_ENDPOINT,
    DEVICE_CODE,
    MTLS_DEVICE_AUTHORIZATION_ENDPOINT,
    MTLS_TOKEN_ENDPOINT,
    device_authorization_response,
    discovery_document,
    discovery_document_with_aliases,
)
from tests.test_mtls_client_cert import _free_port, _MtlsPki

TENANT_ID = "11111111-1111-1111-1111-111111111111"
TOKEN_ENDPOINT = f"{BASE_URL}/oauth2/token"


def _form(request: httpx.Request) -> dict[str, str]:
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    return dict(parse_qsl(request.content.decode()))


def _mount(
    respx_mock: respx.MockRouter, document: dict[str, Any] | None = None
) -> tuple[respx.Route, respx.Route]:
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=document or discovery_document())
    )
    authorize = respx_mock.post(DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    poll = respx_mock.post(TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            200, json={"access_token": "t", "token_type": "Bearer", "expires_in": 900}
        )
    )
    return authorize, poll


def _client(**kwargs: Any) -> AxiamClient:
    return AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, **kwargs)


# ---------------------------------------------------------------------------
# A confidential client: the secret in the form body at BOTH endpoints
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("registration", ["client_secret_post", "client_secret_basic"])
def test_a_client_secret_goes_in_the_body_at_both_endpoints_and_no_authorization_header(
    respx_mock: respx.MockRouter, registration: str
) -> None:
    """§14.6: ``client_secret`` in the body at ``device_authorize`` and every poll, no
    ``Authorization`` header at either, whichever way the client is registered."""
    document = discovery_document(token_endpoint_auth_methods_supported=[registration])
    authorize, poll = _mount(respx_mock, document)
    client = _client(client_secret=CLIENT_SECRET)

    client.device_authorize(scope="openid", tenant_id=TENANT_ID)
    client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert authorize.call_count == 1 and poll.call_count == 2
    for call in (authorize.calls[0], poll.calls[0], poll.calls[1]):
        assert _form(call.request)["client_secret"] == CLIENT_SECRET
        assert _form(call.request)["client_id"] == CLIENT_ID
        assert "authorization" not in call.request.headers, (
            "§12.1 rule 3: never Authorization: Basic"
        )
        assert CLIENT_SECRET not in str(call.request.url), "the secret is never a query parameter"
        assert call.request.url.params["tenant_id"] == TENANT_ID
        assert "tenant_id" not in _form(call.request)


def test_the_poll_form_still_carries_the_grant_and_the_device_code(
    respx_mock: respx.MockRouter,
) -> None:
    """The grant type and the code are untouched by the added credential."""
    _, poll = _mount(respx_mock)
    _client(client_secret=CLIENT_SECRET).device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    form = _form(poll.calls[0].request)
    assert form == {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": DEVICE_CODE,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }


def test_device_login_sends_the_secret_and_client_id_on_every_poll(
    respx_mock: respx.MockRouter,
) -> None:
    """The composed helper: authorize once, then each poll names the client and authenticates."""
    authorize, poll = _mount(respx_mock)
    poll.mock(
        side_effect=[
            httpx.Response(400, json={"error": "authorization_pending", "error_description": "p"}),
            httpx.Response(
                200, json={"access_token": "t", "token_type": "Bearer", "expires_in": 900}
            ),
        ]
    )

    tokens = _client(client_secret=CLIENT_SECRET).device_login(
        lambda _auth: None, tenant_id=TENANT_ID
    )

    assert tokens.access_token.get_secret_value() == "t"
    assert _form(authorize.calls[0].request)["client_secret"] == CLIENT_SECRET
    assert poll.call_count == 2
    for call in poll.calls:
        assert _form(call.request)["client_secret"] == CLIENT_SECRET
        assert _form(call.request)["client_id"] == CLIENT_ID
        assert "authorization" not in call.request.headers


def test_the_secret_is_never_rendered(respx_mock: respx.MockRouter) -> None:
    """§14.5: the credential is ``Sensitive`` exactly as at the other token requests."""
    _mount(respx_mock)
    client = _client(client_secret=CLIENT_SECRET)
    authorization = client.device_authorize(tenant_id=TENANT_ID)
    for rendering in (repr(authorization), str(authorization), repr(client)):
        assert CLIENT_SECRET not in rendering


@pytest.mark.asyncio
async def test_the_async_client_sends_it_at_both_endpoints_too(
    respx_mock: respx.MockRouter,
) -> None:
    """§14.4: the same three names, the same wire, on ``AsyncAxiamClient``."""
    authorize, poll = _mount(respx_mock)
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )

    await client.device_authorize(tenant_id=TENANT_ID)
    await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    for call in (authorize.calls[0], poll.calls[0]):
        assert _form(call.request)["client_secret"] == CLIENT_SECRET
        assert _form(call.request)["client_id"] == CLIENT_ID
        assert "authorization" not in call.request.headers


# ---------------------------------------------------------------------------
# A public client: no credential at either, not refused
# ---------------------------------------------------------------------------


def test_a_public_client_sends_client_id_and_no_credential_and_is_not_refused(
    respx_mock: respx.MockRouter,
) -> None:
    """§14.1 rule 1 / §14.6: neither a ``client_secret`` nor any other credential."""
    authorize, poll = _mount(respx_mock)
    client = _client()

    client.device_authorize(tenant_id=TENANT_ID)
    client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    for call in (authorize.calls[0], poll.calls[0]):
        form = _form(call.request)
        assert form["client_id"] == CLIENT_ID
        assert not {k for k in form if k.startswith("client_") and k != "client_id"}, form
        assert "authorization" not in call.request.headers


@pytest.mark.asyncio
async def test_a_public_async_client_sends_none_either(respx_mock: respx.MockRouter) -> None:
    """Async twin of the public-client case."""
    authorize, poll = _mount(respx_mock)
    client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)

    await client.device_authorize(tenant_id=TENANT_ID)
    await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    for call in (authorize.calls[0], poll.calls[0]):
        assert set(_form(call.request)) <= {
            "client_id",
            "grant_type",
            "device_code",
            "scope",
        }, _form(call.request)


# ---------------------------------------------------------------------------
# An mTLS client: the certificate, at both endpoints, nothing in the body
# ---------------------------------------------------------------------------


class _Recorder:
    """An HTTPS server that REQUIRES a client certificate and records, per request,
    whether one was presented, the path, the headers and the form."""

    def __init__(self, pki: _MtlsPki) -> None:
        """Bind on an ephemeral localhost port."""
        self.port = _free_port()
        self.seen: list[dict[str, Any]] = []
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("content-length", "0"))
                form = dict(parse_qsl(self.rfile.read(length).decode()))
                peer = self.connection.getpeercert()  # type: ignore[attr-defined]
                outer.seen.append(
                    {
                        "path": self.path.split("?")[0],
                        "peer_cn": dict(x[0] for x in peer["subject"]).get("commonName")
                        if peer
                        else None,
                        "authorization": self.headers.get("authorization"),
                        "form": form,
                    }
                )
                if self.path.startswith("/oauth2/device_authorization"):
                    body = device_authorization_response()
                else:
                    body = {"access_token": "t", "token_type": "Bearer", "expires_in": 900}
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: object) -> None:
                return

        class _Quiet(http.server.HTTPServer):
            def handle_error(self, *args: object) -> None:
                return

        self._httpd = _Quiet(("localhost", self.port), _Handler)
        self._httpd.socket = pki.server_ssl_context().wrap_socket(
            self._httpd.socket, server_side=True
        )
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        """The ``https://localhost:<port>`` origin."""
        return f"https://localhost:{self.port}"

    def __enter__(self) -> _Recorder:
        """Start serving."""
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        """Stop serving."""
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def recorder(tmp_path: Path) -> Iterator[tuple[_Recorder, _MtlsPki]]:
    """A running certificate-requiring server and its PKI."""
    pki = _MtlsPki(tmp_path)
    with _Recorder(pki) as server:
        yield server, pki


def test_an_mtls_client_presents_its_certificate_at_both_endpoints(
    recorder: tuple[_Recorder, _MtlsPki],
) -> None:
    """A real handshake against a server that requires a client certificate: both
    ``device_authorize`` and the poll present it, and the body carries no secret."""
    server, pki = recorder
    configuration = OidcConfiguration.model_validate(
        discovery_document(
            issuer=server.base_url,
            token_endpoint=f"{server.base_url}/oauth2/token",
            device_authorization_endpoint=f"{server.base_url}/oauth2/device_authorization",
        )
    )
    client = AxiamClient(
        base_url=server.base_url,
        tenant_slug="acme",
        client_id=CLIENT_ID,
        custom_ca=str(pki.ca_path),
        client_cert=pki.client_cert_pem,
        client_key=pki.client_key_pem,
    )
    try:
        client.device_authorize(tenant_id=TENANT_ID, configuration=configuration)
        client.device_poll(
            device_code=DEVICE_CODE, tenant_id=TENANT_ID, configuration=configuration
        )
    finally:
        client.close()

    assert [s["path"] for s in server.seen] == ["/oauth2/device_authorization", "/oauth2/token"]
    for seen in server.seen:
        assert seen["peer_cn"] == "axiam-device", "the client certificate was presented"
        assert seen["authorization"] is None
        assert seen["form"]["client_id"] == CLIENT_ID
        assert "client_secret" not in seen["form"]


def test_an_mtls_client_uses_the_alias_endpoints_for_both(respx_mock: respx.MockRouter) -> None:
    """§21.3 rule 2: over mTLS the discovery aliases are preferred, for both device calls."""
    from tests._oidc_testkit import client_identity_pem

    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document_with_aliases())
    )
    authorize = respx_mock.post(MTLS_DEVICE_AUTHORIZATION_ENDPOINT).mock(
        return_value=httpx.Response(200, json=device_authorization_response())
    )
    poll = respx_mock.post(MTLS_TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(
            200, json={"access_token": "t", "token_type": "Bearer", "expires_in": 900}
        )
    )
    cert_pem, key_pem = client_identity_pem()
    client = _client(client_cert=cert_pem, client_key=key_pem)

    client.device_authorize(tenant_id=TENANT_ID)
    client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert authorize.call_count == 1 and poll.call_count == 1
    for call in (authorize.calls[0], poll.calls[0]):
        assert "client_secret" not in _form(call.request)
        assert _form(call.request)["client_id"] == CLIENT_ID
        assert "authorization" not in call.request.headers


# ---------------------------------------------------------------------------
# 401 invalid_client (§14.2 rules 5 and 8)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", ["authorize", "poll"])
def test_a_401_invalid_client_is_an_oauth_protocol_error_sent_once_and_never_refreshed(
    respx_mock: respx.MockRouter, endpoint: str
) -> None:
    """Either operation: ``OAuthProtocolError(error='invalid_client')``, one request, no
    retry, and the §9 refresh guard is never entered (no ``/auth/refresh`` call)."""
    authorize, poll = _mount(respx_mock)
    refresh = respx_mock.post(f"{BASE_URL}/api/v1/auth/refresh").mock(
        return_value=httpx.Response(200, json={})
    )
    denied = httpx.Response(
        401, json={"error": "invalid_client", "error_description": "client authentication failed"}
    )
    target = authorize if endpoint == "authorize" else poll
    target.mock(return_value=denied)
    client = _client(client_secret="a-wrong-secret")

    with pytest.raises(OAuthProtocolError) as raised:
        if endpoint == "authorize":
            client.device_authorize(tenant_id=TENANT_ID)
        else:
            client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)

    assert raised.value.error == "invalid_client"
    assert target.call_count == 1, "terminal: never retried"
    assert refresh.call_count == 0, "a failed client authentication is not an expired session"
    assert "a-wrong-secret" not in str(raised.value)


def test_device_login_stops_on_invalid_client_at_the_first_poll(
    respx_mock: respx.MockRouter,
) -> None:
    """Terminal in the composed loop too: the poll is not repeated."""
    _, poll = _mount(respx_mock)
    poll.mock(
        return_value=httpx.Response(
            401, json={"error": "invalid_client", "error_description": "no longer holds the grant"}
        )
    )
    with pytest.raises(OAuthProtocolError) as raised:
        _client(client_secret=CLIENT_SECRET).device_login(lambda _a: None, tenant_id=TENANT_ID)
    assert raised.value.error == "invalid_client"
    assert poll.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["authorize", "poll"])
async def test_the_async_client_maps_invalid_client_the_same_way(
    respx_mock: respx.MockRouter, endpoint: str
) -> None:
    """Async twin of the ``401`` case."""
    authorize, poll = _mount(respx_mock)
    target = authorize if endpoint == "authorize" else poll
    target.mock(
        return_value=httpx.Response(
            401, json={"error": "invalid_client", "error_description": "denied"}
        )
    )
    client = AsyncAxiamClient(
        base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID, client_secret=CLIENT_SECRET
    )
    with pytest.raises(OAuthProtocolError) as raised:
        if endpoint == "authorize":
            await client.device_authorize(tenant_id=TENANT_ID)
        else:
            await client.device_poll(device_code=DEVICE_CODE, tenant_id=TENANT_ID)
    assert raised.value.error == "invalid_client"
    assert target.call_count == 1
