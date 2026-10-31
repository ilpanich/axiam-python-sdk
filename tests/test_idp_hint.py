"""``idp_hint`` on ``oidc_begin`` and ``oidc_par`` -- CONTRACT.md §12.1 (the
``idp_hint`` paragraph) and §26.2 rule 8 (contract 1.65).

The five required tests, by the contract's names, on both clients.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest
import respx

from axiam_sdk import AsyncAxiamClient, AxiamClient, OidcConfiguration
from tests._oidc_testkit import BASE_URL, CLIENT_ID, PAR_ENDPOINT, discovery_document

REDIRECT_URI = "https://app.test/callback"
TENANT_ID = "11111111-1111-1111-1111-111111111111"
REQUEST_URI = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"
EIGHT = {
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
}


def _config() -> OidcConfiguration:
    return OidcConfiguration.model_validate(discovery_document())


def _params(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlsplit(url).query, keep_blank_values=True)


def _client(async_: bool) -> AxiamClient | AsyncAxiamClient:
    cls = AsyncAxiamClient if async_ else AxiamClient
    return cls(base_url=BASE_URL, tenant_slug=TENANT_ID, client_id=CLIENT_ID)  # type: ignore[arg-type]


async def _begin(async_: bool, **kwargs: Any) -> Any:
    client = _client(async_)
    result = client.oidc_begin(configuration=_config(), redirect_uri=REDIRECT_URI, **kwargs)
    return await result if async_ else result  # type: ignore[misc]


ASYNC = pytest.mark.parametrize("async_", [False, True], ids=["sync", "async"])


@ASYNC
@pytest.mark.parametrize(
    "hint",
    [
        "corp-okta",
        "33333333-3333-3333-3333-333333333333",
        "Google",  # not case-folded
        "a b&c=d/e+f%g?h#i é",  # percent-encoding round-trips intact
    ],
)
async def test_idp_hint_emitted_once(async_: bool, hint: str) -> None:
    request = await _begin(async_, idp_hint=hint)

    params = _params(request.url)
    assert [value for key, value in params if key == "axiam_idp_hint"] == [hint]
    # The other eight are unchanged and there is nothing else.
    assert {key for key, _ in params} == EIGHT | {"axiam_idp_hint"}
    assert len(params) == 9
    assert dict(params)["state"] == request.state
    assert dict(params)["nonce"] == request.nonce
    assert "kc_idp_hint" not in dict(params)


@ASYNC
async def test_idp_hint_omitted_when_unset(async_: bool) -> None:
    request = await _begin(async_)

    params = _params(request.url)
    assert {key for key, _ in params} == EIGHT
    assert len(params) == 8
    assert "axiam_idp_hint" not in dict(params)
    assert "kc_idp_hint" not in dict(params)


@ASYNC
async def test_idp_hint_not_duplicated(async_: bool) -> None:
    # Set: the option is the single source; a same-named extra is dropped.
    request = await _begin(
        async_, idp_hint="corp-okta", extra_params={"axiam_idp_hint": "other", "ui_locales": "it"}
    )
    params = _params(request.url)
    assert [value for key, value in params if key == "axiam_idp_hint"] == ["corp-okta"]
    assert dict(params)["ui_locales"] == "it"

    # Unset: an additional parameter of that name passes through, still once.
    passthrough = await _begin(async_, extra_params={"axiam_idp_hint": "other"})
    assert [v for k, v in _params(passthrough.url) if k == "axiam_idp_hint"] == ["other"]


@ASYNC
async def test_idp_hint_bounds(async_: bool) -> None:
    with pytest.raises(ValueError, match="idp_hint"):
        await _begin(async_, idp_hint="")
    with pytest.raises(ValueError, match="256"):
        await _begin(async_, idp_hint="a" * 257)
    # 257 BYTES, not characters: 129 two-byte characters is over the bound.
    with pytest.raises(ValueError, match="256"):
        await _begin(async_, idp_hint="é" * 129)

    exactly = "a" * 256
    request = await _begin(async_, idp_hint=exactly)
    assert [v for k, v in _params(request.url) if k == "axiam_idp_hint"] == [exactly]
    two_byte = "é" * 128
    request = await _begin(async_, idp_hint=two_byte)
    assert [v for k, v in _params(request.url) if k == "axiam_idp_hint"] == [two_byte]


@ASYNC
async def test_idp_hint_is_not_trimmed_or_judged(async_: bool) -> None:
    """§12.1 rule 2: nothing beyond emptiness and length -- not trimmed, not
    parsed as a UUID, not checked against the kind-name list."""
    for hint in (" padded ", "not-a-known-provider", "kc_idp_hint", "GOOGLE"):
        request = await _begin(async_, idp_hint=hint)
        assert [v for k, v in _params(request.url) if k == "axiam_idp_hint"] == [hint]


@ASYNC
@respx.mock
async def test_par_idp_hint_in_pushed_body(async_: bool) -> None:
    route = respx.post(PAR_ENDPOINT).mock(
        return_value=httpx.Response(201, json={"request_uri": REQUEST_URI, "expires_in": 90})
    )
    client = _client(async_)
    config = _config()

    async def push(**kwargs: Any) -> Any:
        authorization = await _begin(async_)
        result = client.oidc_par(
            request=authorization,
            redirect_uri=REDIRECT_URI,
            configuration=config,
            tenant_id=TENANT_ID,
            **kwargs,
        )
        return await result if async_ else result  # type: ignore[misc]

    pushed = await push(idp_hint="corp-okta")
    form = parse_qsl(route.calls.last.request.content.decode())
    assert [v for k, v in form if k == "axiam_idp_hint"] == ["corp-okta"]
    assert "kc_idp_hint" not in dict(form)
    # The authorization URL built from the request_uri carries exactly two parameters.
    assert {k for k, _ in _params(pushed.authorization_url)} == {"client_id", "request_uri"}
    assert len(_params(pushed.authorization_url)) == 2
    assert "idp" not in pushed.authorization_url

    # Without a hint the field is absent, and the URL is still exactly two parameters.
    pushed = await push()
    form = parse_qsl(route.calls.last.request.content.decode())
    assert "axiam_idp_hint" not in dict(form)
    assert {k for k, _ in _params(pushed.authorization_url)} == {"client_id", "request_uri"}

    # Bounds are §12.1's, and a refused hint pushes nothing.
    before = len(route.calls)
    with pytest.raises(ValueError, match="idp_hint"):
        await push(idp_hint="")
    with pytest.raises(ValueError, match="256"):
        await push(idp_hint="a" * 257)
    assert len(route.calls) == before


@ASYNC
@respx.mock
async def test_par_idp_hint_from_begin_url_pushed(async_: bool) -> None:
    """D-N36: ``oidc_begin(idp_hint=...)`` then ``oidc_par(request)`` with no
    argument pushes the begin URL's hint, once; the redirect stays two parameters."""
    route = respx.post(PAR_ENDPOINT).mock(
        return_value=httpx.Response(201, json={"request_uri": REQUEST_URI, "expires_in": 90})
    )
    client = _client(async_)
    authorization = await _begin(async_, idp_hint="corp-okta")
    result = client.oidc_par(
        request=authorization,
        redirect_uri=REDIRECT_URI,
        configuration=_config(),
        tenant_id=TENANT_ID,
    )
    pushed = await result if async_ else result  # type: ignore[misc]

    form = parse_qsl(route.calls.last.request.content.decode())
    assert [v for k, v in form if k == "axiam_idp_hint"] == ["corp-okta"]
    assert "kc_idp_hint" not in dict(form)
    assert {k for k, _ in _params(pushed.authorization_url)} == {"client_id", "request_uri"}
    assert len(_params(pushed.authorization_url)) == 2


@ASYNC
@respx.mock
async def test_par_idp_hint_argument_wins(async_: bool) -> None:
    """D-N36: the ``oidc_par`` argument beats the begin URL's hint."""
    route = respx.post(PAR_ENDPOINT).mock(
        return_value=httpx.Response(201, json={"request_uri": REQUEST_URI, "expires_in": 90})
    )
    client = _client(async_)
    authorization = await _begin(async_, idp_hint="corp-okta")
    result = client.oidc_par(
        request=authorization,
        redirect_uri=REDIRECT_URI,
        configuration=_config(),
        tenant_id=TENANT_ID,
        idp_hint="other",
    )
    pushed = await result if async_ else result  # type: ignore[misc]

    form = parse_qsl(route.calls.last.request.content.decode())
    assert [v for k, v in form if k == "axiam_idp_hint"] == ["other"]
    assert "corp-okta" not in route.calls.last.request.content.decode()
    assert {k for k, _ in _params(pushed.authorization_url)} == {"client_id", "request_uri"}
