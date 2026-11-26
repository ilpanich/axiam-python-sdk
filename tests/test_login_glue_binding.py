"""CONTRACT.md §12.8 -- login glue: browser binding (C7) and ``return_to`` (C6).

Every case runs against BOTH glue adapters (Django ``oidc_login_views`` and FastAPI
``oidc_login_router``) through one adapter-neutral ``Flow``. Only the IdP is mocked: the token
endpoint is a respx route whose call count proves "no exchange" on a refused callback, and the
ID token is really signed so a successful callback is a real §12.4-validated exchange.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json as jsonlib
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs, urlsplit

import django
import httpx
import pytest
import respx
from django.conf import settings as django_settings
from django.test import RequestFactory
from fastapi import FastAPI
from fastapi.testclient import TestClient

if not django_settings.configured:
    django_settings.configure(DEBUG=True, USE_TZ=True)
    django.setup()

from axiam_sdk import AsyncAxiamClient, AxiamClient, MemoryOidcStateStore  # noqa: E402
from axiam_sdk.django.oidc import oidc_login_views  # noqa: E402
from axiam_sdk.fastapi import oidc_login_router  # noqa: E402
from tests._oidc_testkit import (  # noqa: E402
    BASE_URL,
    CLIENT_ID,
    FakeJwksEndpoint,
    discovery_document,
    make_ed25519_keypair_and_jwk,
    make_id_token_claims,
    sign_id_token,
)

HTTPS_REDIRECT = "https://app.test/oidc/callback"
LOOPBACK_REDIRECT = "http://localhost:8000/oidc/callback"
PLAIN_HTTP_REDIRECT = "http://app.test/oidc/callback"
TENANT_ID = "77777777-7777-7777-7777-777777777777"
HOST_NAME = "__Host-axiam_oidc_bind"
LOOPBACK_NAME = "axiam_oidc_bind"
UNIFORM_MESSAGE = "unknown, expired, or already-used login state"


@dataclass
class Result:
    status: int
    location: str | None
    body: dict[str, Any]
    set_cookies: list[str]
    header_names: list[str] = field(default_factory=list)


@dataclass
class Login:
    state: str
    nonce: str
    set_cookies: list[str]
    status: int


def _parse(set_cookie: str) -> tuple[str, str, dict[str, str]]:
    jar: SimpleCookie = SimpleCookie()
    jar.load(set_cookie)
    morsel = next(iter(jar.values()))
    attrs = {k.lower(): v for k, v in morsel.items() if v not in ("", None)}
    return morsel.key, morsel.value, attrs


def _binding_cookie(set_cookies: list[str]) -> tuple[str, str, dict[str, Any]]:
    for raw in set_cookies:
        name, value, attrs = _parse(raw)
        if name in (HOST_NAME, LOOPBACK_NAME) and value:
            return name, value, attrs
    raise AssertionError(f"no binding cookie in {set_cookies!r}")


@dataclass
class Flow:
    """One adapter wired to a mock IdP. ``login()`` / ``callback()`` are adapter-neutral."""

    adapter: str
    store: MemoryOidcStateStore
    respx_mock: respx.MockRouter
    private_key: Any
    jwk: dict[str, Any]
    success_calls: list[tuple[Any, ...]] = field(default_factory=list)
    hook_order: list[str] = field(default_factory=list)
    request_headers: list[Any] = field(default_factory=list)
    _login: Any = None
    _callback: Any = None

    @property
    def token_requests(self) -> int:
        return sum(1 for c in self.respx_mock.calls if c.request.url.path == "/oauth2/token")

    def login(self, return_to: str | None = None) -> Login:
        return self._login(return_to)

    def callback(self, state: str, cookie: str | None, **params: str) -> Result:
        self._mock_token_endpoint(state)
        return self._callback(state, cookie, params)

    def _mock_token_endpoint(self, state: str) -> None:
        # The real IdP echoes the login's nonce inside the ID token.
        nonce = self._nonces[state]
        id_token = sign_id_token(
            self.private_key, self.jwk["kid"], make_id_token_claims(nonce=nonce)
        )
        self.respx_mock.post(f"{BASE_URL}/oauth2/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "access-1",
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "id_token": id_token,
                    "scope": "openid",
                },
            )
        )

    _nonces: dict[str, str] = field(default_factory=dict)


def _build_flow(adapter: str, respx_mock: respx.MockRouter, **kwargs: Any) -> Flow:
    redirect_uri = kwargs.pop("redirect_uri", HTTPS_REDIRECT)
    use_request_hook = kwargs.pop("request_hook", False)
    both_hooks = kwargs.pop("both_hooks", False)
    failing_hook = kwargs.pop("failing_hook", False)
    respx_mock.get(f"{BASE_URL}/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json=discovery_document())
    )
    private_key, jwk = make_ed25519_keypair_and_jwk()
    store = MemoryOidcStateStore()
    flow = Flow(adapter, store, respx_mock, private_key, jwk)

    if adapter == "django":
        client = AxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
        FakeJwksEndpoint([jwk]).bind_to_client(client)

        def on_success(tokens: object, entry: object) -> None:
            flow.hook_order.append("on_success")
            if failing_hook:
                raise RuntimeError("SECRET-HOOK-FAILURE")
            flow.success_calls.append((tokens, entry))

        def on_success_request(tokens: object, entry: object, request: object) -> None:
            flow.hook_order.append("on_success_request")
            flow.success_calls.append((tokens, entry, request))

        hooks: dict[str, Any] = {"on_success": on_success}
        if use_request_hook:
            hooks = {"on_success_request": on_success_request}
        if both_hooks:
            hooks = {"on_success": on_success, "on_success_request": on_success_request}
        login_view, callback_view = oidc_login_views(
            client,
            redirect_uri=redirect_uri,
            store=store,
            tenant_id=TENANT_ID,
            **hooks,
            **kwargs,
        )

        def _login(return_to: str | None) -> Login:
            params = {"return_to": return_to} if return_to is not None else {}
            response = login_view(RequestFactory().get("/oidc/login", params))
            query = parse_qs(urlsplit(response.headers["Location"]).query)
            flow._nonces[query["state"][0]] = query["nonce"][0]
            return Login(
                query["state"][0],
                query["nonce"][0],
                [m.OutputString() for m in response.cookies.values()],
                response.status_code,
            )

        def _callback(state: str, cookie: str | None, extra: dict[str, str]) -> Result:
            params = {"state": state, "code": "idp-code-1", **extra}
            extra_meta = {"HTTP_COOKIE": cookie} if cookie else {}
            request = RequestFactory().get("/oidc/callback", params, **extra_meta)
            try:
                response = callback_view(request)
            except Exception:
                # What Django does with a view that raises: its own 500 page, which carries
                # none of the view's headers or cookies.
                return Result(500, None, {}, [], [])
            body = jsonlib.loads(response.content) if response.content else {}
            return Result(
                response.status_code,
                response.headers.get("Location"),
                body,
                [m.OutputString() for m in response.cookies.values()],
                [name.lower() for name in response.headers],
            )

    else:
        async_client = AsyncAxiamClient(base_url=BASE_URL, tenant_slug="acme", client_id=CLIENT_ID)
        FakeJwksEndpoint([jwk]).bind_to_client(async_client)

        async def on_success(tokens: object, entry: object) -> None:
            flow.hook_order.append("on_success")
            if failing_hook:
                raise RuntimeError("SECRET-HOOK-FAILURE")
            flow.success_calls.append((tokens, entry))

        async def on_success_request(tokens: object, entry: object, request: object) -> None:
            flow.hook_order.append("on_success_request")
            flow.success_calls.append((tokens, entry, request))

        hooks = {"on_success": on_success}
        if use_request_hook:
            hooks = {"on_success_request": on_success_request}
        if both_hooks:
            hooks = {"on_success": on_success, "on_success_request": on_success_request}
        app = FastAPI()
        app.include_router(
            oidc_login_router(
                async_client,
                redirect_uri=redirect_uri,
                store=store,
                tenant_id=TENANT_ID,
                **hooks,
                **kwargs,
            )
        )
        http = TestClient(app, follow_redirects=False, raise_server_exceptions=False)

        def _login(return_to: str | None) -> Login:
            params = {"return_to": return_to} if return_to is not None else {}
            response = http.get("/login", params=params)
            query = parse_qs(urlsplit(response.headers["location"]).query)
            flow._nonces[query["state"][0]] = query["nonce"][0]
            return Login(
                query["state"][0],
                query["nonce"][0],
                response.headers.get_list("set-cookie"),
                response.status_code,
            )

        def _callback(state: str, cookie: str | None, extra: dict[str, str]) -> Result:
            params = {"state": state, "code": "idp-code-1", **extra}
            headers = {"cookie": cookie} if cookie else {}
            response = http.get("/callback", params=params, headers=headers)
            try:
                body = response.json() if response.content else {}
            except ValueError:  # Starlette's plain-text 500 for an unhandled exception
                body = {}
            if "detail" in body:  # HTTPException-shaped error body
                body = body["detail"]
            return Result(
                response.status_code,
                response.headers.get("location"),
                body,
                response.headers.get_list("set-cookie"),
                [name.lower() for name in response.headers.keys()],
            )

    flow._login = _login
    flow._callback = _callback
    return flow


@pytest.fixture(params=["django", "fastapi"])
def adapter(request: pytest.FixtureRequest) -> str:
    return str(request.param)


def _cookie_header(set_cookies: list[str]) -> str | None:
    """The ``Cookie`` header a browser would send back; ``None`` when the login set no binding
    cookie (so the C6 cases still exercise the redirect on code that sets none)."""
    try:
        name, value, _attrs = _binding_cookie(set_cookies)
    except AssertionError:
        return None
    return f"{name}={value}"


def _assert_cleared(result: Result, name: str = HOST_NAME) -> None:
    cleared = [(n, v, a) for n, v, a in (_parse(c) for c in result.set_cookies) if n == name]
    assert cleared, f"binding cookie {name} not cleared: {result.set_cookies!r}"
    _n, value, attrs = cleared[-1]
    assert value == ""
    assert str(attrs.get("max-age")) == "0"


def _assert_uniform_401(result: Result) -> None:
    assert result.status == 401
    assert result.body == {"error": "authentication_failed", "message": UNIFORM_MESSAGE}


# --- C7: the login sets the binding cookie ------------------------------------------------


def test_login_sets_host_prefixed_binding_cookie(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()
    name, value, attrs = _binding_cookie(login.set_cookies)

    assert name == HOST_NAME
    assert len(value) == 43  # 32 random bytes, base64url, no padding
    assert "=" not in value
    assert attrs.get("httponly") is True
    assert attrs.get("secure") is True
    assert attrs.get("samesite", "").lower() == "lax"
    assert attrs.get("path") == "/"
    assert "domain" not in attrs
    assert 0 < int(attrs["max-age"]) <= 600

    entry = flow.store.consume(login.state)
    assert entry is not None
    assert entry.binding_digest == hashlib.sha256(value.encode("ascii")).hexdigest()


def test_each_login_draws_a_fresh_binding_value(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock)
    first = _binding_cookie(flow.login().set_cookies)[1]
    second = _binding_cookie(flow.login().set_cookies)[1]
    assert first != second


def test_loopback_http_redirect_uri_uses_the_fallback_name_without_secure(
    adapter, respx_mock
) -> None:
    flow = _build_flow(adapter, respx_mock, redirect_uri=LOOPBACK_REDIRECT)
    login = flow.login()
    name, value, attrs = _binding_cookie(login.set_cookies)

    assert name == LOOPBACK_NAME
    assert "secure" not in attrs
    assert attrs.get("httponly") is True
    assert attrs.get("samesite", "").lower() == "lax"
    assert attrs.get("path") == "/"

    ok = flow.callback(login.state, f"{name}={value}")
    assert ok.status == 200


def test_loopback_callback_ignores_the_host_prefixed_name(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock, redirect_uri=LOOPBACK_REDIRECT)
    login = flow.login()
    _name, value, _attrs = _binding_cookie(login.set_cookies)

    result = flow.callback(login.state, f"{HOST_NAME}={value}")

    _assert_uniform_401(result)
    assert flow.token_requests == 0


def test_https_callback_ignores_the_loopback_name(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()
    _name, value, _attrs = _binding_cookie(login.set_cookies)

    result = flow.callback(login.state, f"{LOOPBACK_NAME}={value}")

    _assert_uniform_401(result)
    assert flow.token_requests == 0


def test_plain_http_non_loopback_still_uses_the_host_prefixed_name(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock, redirect_uri=PLAIN_HTTP_REDIRECT)
    name, _value, attrs = _binding_cookie(flow.login().set_cookies)
    assert name == HOST_NAME
    assert attrs.get("secure") is True


# --- C7: the callback ----------------------------------------------------------------------


def test_callback_without_the_cookie_is_the_uniform_401_with_no_exchange(
    adapter, respx_mock
) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()
    right_cookie = _cookie_header(login.set_cookies)

    result = flow.callback(login.state, None)

    _assert_uniform_401(result)
    assert flow.token_requests == 0
    assert flow.success_calls == []
    _assert_cleared(result)

    # The 401 consumed the entry: the right cookie no longer helps.
    retry = flow.callback(login.state, right_cookie)
    _assert_uniform_401(retry)
    assert flow.token_requests == 0
    assert flow.success_calls == []


def test_callback_with_another_logins_cookie_is_the_uniform_401(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock)
    victim_login = flow.login()
    attacker_login = flow.login()
    attacker_cookie = _cookie_header(attacker_login.set_cookies)

    result = flow.callback(victim_login.state, attacker_cookie)

    _assert_uniform_401(result)
    assert flow.token_requests == 0
    assert flow.success_calls == []
    _assert_cleared(result)


def test_callback_from_the_browser_that_started_the_login_succeeds(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock, request_hook=True)
    login = flow.login()
    cookie = _cookie_header(login.set_cookies)

    result = flow.callback(login.state, cookie)

    assert result.status == 200
    assert result.body["authenticated"] is True
    assert flow.token_requests == 1
    assert len(flow.success_calls) == 1
    tokens, entry, request = flow.success_calls[0]
    assert entry.state == login.state
    assert request is not None  # §12.8 rule 2: the success callback receives the request
    _assert_cleared(result)

    replay = flow.callback(login.state, cookie)
    _assert_uniform_401(replay)
    assert len(flow.success_calls) == 1


def test_entry_with_no_binding_digest_is_refused(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()
    cookie = _cookie_header(login.set_cookies)
    entry = flow.store.consume(login.state)
    assert entry is not None
    flow.store.save(dataclasses.replace(entry, binding_digest=None))

    result = flow.callback(login.state, cookie)

    _assert_uniform_401(result)
    assert flow.token_requests == 0
    assert flow.success_calls == []


@pytest.mark.parametrize(
    "params",
    [
        {"error": "access_denied", "error_description": "nope"},
    ],
)
def test_idp_error_callback_clears_the_cookie(adapter, respx_mock, params) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()
    result = flow.callback(login.state, _cookie_header(login.set_cookies), **params)
    assert result.status == 401
    _assert_cleared(result)


def test_unknown_state_callback_clears_the_cookie(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()
    flow._nonces["unknown-state"] = login.nonce
    result = flow.callback("unknown-state", _cookie_header(login.set_cookies))
    _assert_uniform_401(result)
    _assert_cleared(result)


# --- C6: return_to ------------------------------------------------------------------------

UNSAFE_RETURN_TO = [
    "https://evil.example/x",
    "//evil.example/x",
    "/\\evil.example",
    "/a\\b",
    "/a\r",
    "/a\nb",
    "/a\x00",
    "/a\x7f",
    "evil.example/x",
    "javascript:alert(1)",
]


@pytest.mark.parametrize("return_to", UNSAFE_RETURN_TO)
def test_unsafe_return_to_is_dropped_at_login(adapter, respx_mock, return_to) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login(return_to)
    entry = flow.store.consume(login.state)
    assert entry is not None
    assert entry.return_to is None


@pytest.mark.parametrize("return_to", UNSAFE_RETURN_TO)
def test_unsafe_return_to_stored_directly_is_not_followed(adapter, respx_mock, return_to) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()
    cookie = _cookie_header(login.set_cookies)
    entry = flow.store.consume(login.state)
    assert entry is not None
    flow.store.save(dataclasses.replace(entry, return_to=return_to))

    result = flow.callback(login.state, cookie)

    assert result.status == 200, "falls back to the JSON summary"
    assert result.location is None
    assert result.body["authenticated"] is True


def test_safe_return_to_is_stored_and_followed(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login("/dashboard?tab=1")
    result = flow.callback(login.state, _cookie_header(login.set_cookies))
    assert result.status == 302
    assert result.location == "/dashboard?tab=1"


def test_success_redirect_still_wins_over_a_valid_return_to(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock, success_redirect="https://app.test/home")
    login = flow.login("/dashboard")
    result = flow.callback(login.state, _cookie_header(login.set_cookies))
    assert result.location == "https://app.test/home"


def test_allow_return_to_predicate_widens_the_rule_for_refused_values_only(
    adapter, respx_mock
) -> None:
    def allow(value: str) -> bool:
        return value == "https://app.example/x"

    flow = _build_flow(adapter, respx_mock, allow_return_to=allow)

    good = flow.login("https://app.example/x")
    ok = flow.callback(good.state, _cookie_header(good.set_cookies))
    assert ok.status == 302
    assert ok.location == "https://app.example/x"

    bad = flow.login("https://evil.example/x")
    refused = flow.callback(bad.state, _cookie_header(bad.set_cookies))
    assert refused.status == 200
    assert refused.location is None


def test_allow_return_to_predicate_is_also_consulted_before_redirecting(
    adapter, respx_mock
) -> None:
    flow = _build_flow(adapter, respx_mock, allow_return_to=lambda value: True)
    login = flow.login()
    cookie = _cookie_header(login.set_cookies)
    entry = flow.store.consume(login.state)
    assert entry is not None
    flow.store.save(dataclasses.replace(entry, return_to="https://elsewhere.example/y"))
    result = flow.callback(login.state, cookie)
    assert result.location == "https://elsewhere.example/y"


def test_a_throwing_predicate_accepts_nothing(adapter, respx_mock) -> None:
    def boom(value: str) -> bool:
        raise RuntimeError("predicate failure")

    flow = _build_flow(adapter, respx_mock, allow_return_to=boom)
    login = flow.login("https://evil.example/x")
    entry = flow.store.consume(login.state)
    assert entry is not None
    assert entry.return_to is None


# --- GLUE-R1-4: a refusal spends the state -------------------------------------------------


def test_the_state_is_spent_by_a_refusal_with_another_browsers_cookie(adapter, respx_mock) -> None:
    """The victim's own cookie, presented AFTER the attacker's refused attempt, no longer
    completes the login: the entry was consumed before the cookie was compared (§12.8 rule 1
    (c)), so a refused callback cannot be retried."""
    flow = _build_flow(adapter, respx_mock)
    victim_login = flow.login()
    victim_cookie = _cookie_header(victim_login.set_cookies)
    attacker_cookie = _cookie_header(flow.login().set_cookies)

    refused = flow.callback(victim_login.state, attacker_cookie)
    _assert_uniform_401(refused)
    _assert_cleared(refused)

    retry = flow.callback(victim_login.state, victim_cookie)
    _assert_uniform_401(retry)
    assert flow.token_requests == 0, "no token request, ever"
    assert flow.success_calls == []
    assert flow.store.consume(victim_login.state) is None, "the entry is gone"


# --- GLUE-R1-5: the cookie is cleared on EVERY callback outcome, errors included ---------------


def _assert_generic_500(result: Result) -> None:
    assert result.status == 500
    assert "SECRET" not in jsonlib.dumps(result.body)
    assert result.body.get("error") == "server_error", result.body


def test_a_throwing_success_hook_still_clears_the_cookie(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock, failing_hook=True)
    login = flow.login()

    result = flow.callback(login.state, _cookie_header(login.set_cookies))

    assert flow.hook_order == ["on_success"]
    assert result.status == 500
    _assert_cleared(result)
    _assert_generic_500(result)


def test_a_failing_state_store_still_clears_the_cookie(adapter, respx_mock, monkeypatch) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()

    def outage(state: str) -> None:
        raise ConnectionError("SECRET-redis-down")

    monkeypatch.setattr(flow.store, "consume", outage)
    result = flow.callback(login.state, _cookie_header(login.set_cookies))

    assert result.status == 500
    _assert_cleared(result)
    _assert_generic_500(result)
    assert flow.token_requests == 0 and flow.success_calls == []


def test_an_unexpected_error_in_the_exchange_still_clears_the_cookie(
    adapter, respx_mock, monkeypatch
) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login()
    target = AxiamClient if adapter == "django" else AsyncAxiamClient

    if adapter == "django":

        def boom(self: Any, **kwargs: Any) -> Any:
            raise ValueError("SECRET-internal-bug")

    else:

        async def boom(self: Any, **kwargs: Any) -> Any:
            raise ValueError("SECRET-internal-bug")

    monkeypatch.setattr(target, "oidc_exchange", boom)
    result = flow.callback(login.state, _cookie_header(login.set_cookies))

    assert result.status == 500
    _assert_cleared(result)
    _assert_generic_500(result)


# --- PYT-R1-6: the success callback receives the callback request, in the documented order -----


def test_the_success_callback_receives_the_callback_request(adapter, respx_mock) -> None:
    from django.http import HttpRequest
    from starlette.requests import Request

    flow = _build_flow(adapter, respx_mock, request_hook=True)
    login = flow.login()
    result = flow.callback(login.state, _cookie_header(login.set_cookies))
    assert result.status == 200

    _tokens, entry, request = flow.success_calls[0]
    assert entry.state == login.state
    if adapter == "django":
        assert isinstance(request, HttpRequest)
        assert request.GET["state"] == login.state, "the request that completed the sign-in"
        assert request.path == "/oidc/callback"
    else:
        assert isinstance(request, Request)
        assert request.query_params["state"] == login.state
        assert request.url.path == "/callback"


def test_both_success_hooks_run_in_the_documented_order(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock, both_hooks=True)
    login = flow.login()
    result = flow.callback(login.state, _cookie_header(login.set_cookies))

    assert result.status == 200
    assert flow.hook_order == ["on_success", "on_success_request"], "on_success runs first"
    assert len(flow.success_calls) == 2
    assert len(flow.success_calls[0]) == 2 and len(flow.success_calls[1]) == 3


# --- Decision 7: the adapter writes the percent-encoded redirect target ------------------------


def _location_cases() -> list[tuple[str, str, str]]:
    return [
        ("space", "/a b", "/a%20b"),
        ("non-ASCII", "/caf\u00e9", "/caf%C3%A9"),
        ("euro sign", "/\u20ac", "/%E2%82%AC"),
        ("already encoded", "/a%20b", "/a%20b"),
        ("stray percent", "/100%", "/100%25"),
        ("malformed escape", "/a%zz", "/a%25zz"),
        ("percent before an escape", "/%%41", "/%25%41"),
        ("truncated escape", "/a%2", "/a%252"),
        ("characters the rule leaves alone", "/x?a=b&c|d^e~f", "/x?a=b&c|d^e~f"),
        ("quote and angle brackets", '/a"<b>', "/a%22%3Cb%3E"),
    ]


@pytest.mark.parametrize(
    ("name", "return_to", "expected"), _location_cases(), ids=[c[0] for c in _location_cases()]
)
def test_the_location_header_is_the_percent_encoded_return_to(
    adapter, respx_mock, name, return_to, expected
) -> None:
    flow = _build_flow(adapter, respx_mock)
    login = flow.login(return_to)

    result = flow.callback(login.state, _cookie_header(login.set_cookies))

    assert result.status == 302
    assert result.location == expected
    assert result.location.isascii() and all(0x20 < ord(c) < 0x7F for c in result.location)
    _assert_cleared(result)
    assert len(flow.success_calls) == 1


def test_a_crlf_value_admitted_by_the_predicate_cannot_split_the_header(
    adapter, respx_mock
) -> None:
    flow = _build_flow(adapter, respx_mock, allow_return_to=lambda value: True)
    login = flow.login("/a\r\nSet-Cookie: injected=1")

    result = flow.callback(login.state, _cookie_header(login.set_cookies))

    assert result.status == 302
    assert result.location == "/a%0D%0ASet-Cookie:%20injected=1"
    cookie_names = [_parse(c)[0] for c in result.set_cookies]
    assert "injected" not in cookie_names, "no header was injected"
    _assert_cleared(result)
    assert len(flow.success_calls) == 1


def test_a_backslash_admitted_by_the_predicate_is_kept_unencoded(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock, allow_return_to=lambda value: True)
    login = flow.login("/a\\b")
    result = flow.callback(login.state, _cookie_header(login.set_cookies))
    assert result.status == 302
    assert result.location == "/a\\b"


def test_a_non_ascii_success_redirect_is_encoded_too(adapter, respx_mock) -> None:
    flow = _build_flow(adapter, respx_mock, success_redirect="/caf\u00e9/\u20ac")
    login = flow.login()

    result = flow.callback(login.state, _cookie_header(login.set_cookies))

    assert result.status == 302
    assert result.location == "/caf%C3%A9/%E2%82%AC"
    _assert_cleared(result)
    assert len(flow.success_calls) == 1


def test_adjacent_lone_surrogates_do_not_crash_the_encoder() -> None:
    from axiam_sdk._oidc_binding import encode_redirect_location

    assert encode_redirect_location("/\ud800\ud800") == "/%EF%BF%BD%EF%BF%BD"


def test_a_lone_surrogate_in_a_stored_destination_does_not_make_the_encoder_throw(
    adapter, respx_mock
) -> None:
    flow = _build_flow(adapter, respx_mock, allow_return_to=lambda value: True)
    login = flow.login()
    cookie = _cookie_header(login.set_cookies)
    entry = flow.store.consume(login.state)
    assert entry is not None
    flow.store.save(dataclasses.replace(entry, return_to="/a\ud800b"))

    result = flow.callback(login.state, cookie)

    assert result.status == 302
    assert result.location == "/a%EF%BF%BDb"
    _assert_cleared(result)
    assert len(flow.success_calls) == 1


def test_the_binding_digest_stays_out_of_the_entry_repr() -> None:
    """PYT-R1-5: §12.8 rule 1 (e) -- not secret, not logged either. A store that logs
    ``repr(entry)`` must not emit it."""
    from pydantic import SecretStr

    from axiam_sdk import OidcStateEntry

    digest = hashlib.sha256(b"binding").hexdigest()
    entry = OidcStateEntry(
        state="s",
        nonce="n",
        code_verifier=SecretStr("v" * 43),
        redirect_uri=HTTPS_REDIRECT,
        binding_digest=digest,
    )
    assert digest not in repr(entry) and digest not in str(entry)
    assert entry.binding_digest == digest, "still readable and compared"
    assert dataclasses.replace(entry, state="s2").binding_digest == digest


# --- the in-memory store is bounded -------------------------------------------------------


def test_memory_store_evicts_the_oldest_entry_beyond_its_cap() -> None:
    from pydantic import SecretStr

    from axiam_sdk import OidcStateEntry

    store = MemoryOidcStateStore(max_entries=3)

    def entry(n: int) -> OidcStateEntry:
        return OidcStateEntry(
            state=f"s{n}", nonce="n", code_verifier=SecretStr("v"), redirect_uri=HTTPS_REDIRECT
        )

    for n in range(5):
        store.save(entry(n))

    assert store.size == 3
    assert store.consume("s0") is None
    assert store.consume("s1") is None
    assert store.consume("s4") is not None


def test_memory_store_default_cap_is_ten_thousand() -> None:
    from axiam_sdk._oidc_state import DEFAULT_MAX_ENTRIES

    assert DEFAULT_MAX_ENTRIES == 10_000
