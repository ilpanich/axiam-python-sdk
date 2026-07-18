"""Shared REST session: one cookie jar, CSRF capture, tenant header
injection, lazily-built sync+async httpx clients (CF-01/CF-02/CF-03).

Mirrors ``the Go SDK's client.go``'s ``decorateRequest``/``captureCSRFFromResponse``/
``doRequest`` choke-point pattern and
``the TypeScript SDK's src/rest/session.ts``'s shared-session shape, adapted to
Python's sync+async duality (D-01).

CRITICAL — cookie-jar sharing (Assumption A1, empirically verified against
the pinned httpx 0.27.2): passing the SAME httpx cookie-jar wrapper instance
to both ``httpx.Client(cookies=...)`` and ``httpx.AsyncClient(cookies=...)``
does NOT share the underlying jar — the wrapper class's constructor copies
an existing wrapper argument's entries into a brand-new
``http.cookiejar.CookieJar()`` (see httpx's ``_models.py``). The only way to
get genuine sharing is to construct a raw ``http.cookiejar.CookieJar()``
directly and pass THAT to both clients — the wrapper constructor takes a
raw ``CookieJar`` as-is (the ``else`` branch) instead of copying it. This
module therefore owns one ``http.cookiejar.CookieJar`` and passes it,
wrapped once in a single wrapper instance, to both clients' ``cookies=``
kwarg — see ``sync_client``/``async_client`` below.
"""

from __future__ import annotations

import os
import ssl
import tempfile
import threading
from typing import TYPE_CHECKING, Any

import httpx

from axiam_sdk._tls_identity import normalize_pem, validate_client_identity
from axiam_sdk.token.refresh_guard import RefreshGuard

if TYPE_CHECKING:
    from http.cookiejar import CookieJar


def _looks_like_pem(value: str) -> bool:
    """Heuristically decide whether ``custom_ca`` is inline PEM text rather
    than a filesystem path.

    ``custom_ca`` has historically been a CA-bundle *file path* (the existing,
    still-supported form). When the mTLS ``SSLContext`` path is active, the
    same value may instead be inline PEM (``str``/``bytes`` content), which
    must be fed to ``load_verify_locations(cadata=...)`` rather than treated as
    a path. A value containing a PEM ``BEGIN`` armor line is inline data; any
    other value is treated as a path (``cafile``), preserving current
    behavior.

    Args:
        value: The ``custom_ca`` string to classify.

    Returns:
        ``True`` if ``value`` contains a PEM armor line (inline data),
        ``False`` if it should be treated as a filesystem path.
    """
    return "-----BEGIN" in value


# HTTP methods that echo the captured CSRF token per CONTRACT.md §3
# (non-browser: capture-from-response-header, echo-on-state-changing-request).
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_DEFAULT_CONNECT_TIMEOUT = 10.0
_DEFAULT_READ_TIMEOUT = 30.0


class _Session:
    """Shared REST session state. Not part of the public API (PEP 8
    leading-underscore convention — see the Phase 19 research notes
    Recommended Project Structure).

    Owns:
    - the single shared cookie jar (``http.cookiejar.CookieJar``), passed to
      BOTH the lazily-built sync ``httpx.Client`` and async
      ``httpx.AsyncClient`` (Assumption A1, see module docstring);
    - CSRF token capture/echo, guarded by a ``threading.Lock`` since it is
      touched from both the sync and async request-issuing code paths;
    - the ``RefreshGuard`` (from 19-02) — a single instance shared by both
      the sync and async call paths on this session;
    - TLS config: ``verify=True`` hardcoded unless ``custom_ca`` is
      supplied — NEVER ``False`` (CF-03/SC#3). There is no parameter on this
      class, or on ``AxiamClient``, that could carry a boolean TLS bypass.
    """

    def __init__(
        self,
        base_url: str,
        tenant_slug: str,
        *,
        custom_ca: str | None = None,
        client_cert: str | bytes | None = None,
        client_key: str | bytes | None = None,
        timeout: httpx.Timeout | None = None,
        logger: Any = None,
    ) -> None:
        """Build the session state shared by the lazily-constructed sync and
        async httpx clients.

        Args:
            base_url: The AXIAM server's base URL; also used to derive
                ``_base_host`` for the same-origin header-injection guard in
                :meth:`_prepare_request`.
            tenant_slug: Injected as ``X-Tenant-ID`` on every same-origin
                request (CONTRACT.md §5).
            custom_ca: The sole *server*-trust override (§6) — a PEM CA
                bundle path (or inline PEM), or ``None`` for strict default
                verification. Never a boolean.
            client_cert: Optional PEM client-certificate chain (``str`` or
                ``bytes``) presented for mTLS client authentication
                (CONTRACT.md §6.1). Must be given together with
                ``client_key``. Presenting it never relaxes server
                verification.
            client_key: Optional PEM private key (``str`` or ``bytes``)
                matching ``client_cert`` (CONTRACT.md §6.1). Secret material:
                it is loaded straight into the TLS stack and is never stored
                as an attribute, logged, or exposed via a getter (§7).
            timeout: Overrides the default httpx connect/read/write/pool
                timeouts when supplied.
            logger: An injectable logger (D-15); stored as-is, not wrapped.

        Raises:
            ValueError: if exactly one of ``client_cert``/``client_key`` is
                supplied, or if the supplied client identity is not valid PEM.
        """
        self.base_url = base_url
        # Host of our own origin — used to gate tenant/CSRF header injection
        # so those secrets never travel to a different host (defense in depth
        # against a cross-origin request or a followed redirect).
        self._base_host = httpx.URL(base_url).host
        self.tenant_slug = tenant_slug
        self._timeout = timeout or httpx.Timeout(
            connect=_DEFAULT_CONNECT_TIMEOUT,
            read=_DEFAULT_READ_TIMEOUT,
            write=_DEFAULT_READ_TIMEOUT,
            pool=_DEFAULT_CONNECT_TIMEOUT,
        )
        # SC#3/CF-03: the ONLY TLS escape hatch is a custom-CA path/bundle —
        # never a boolean. When no client certificate is configured, `_verify`
        # is either None->True (strict system-trust verification) or the
        # custom CA path/bundle httpx accepts directly, EXACTLY as before. A
        # boolean bypass value is never assigned here.
        #
        # When a client certificate IS configured (mTLS, §6.1), `_verify`
        # becomes a strict `ssl.SSLContext` that (a) keeps full server
        # verification on and (b) additionally loads the client identity via
        # `load_cert_chain`. Server-trust and client-identity code stay in
        # separate methods so the CI TLS-bypass lint gate is never tripped.
        validate_client_identity(client_cert, client_key)
        self._verify: bool | str | ssl.SSLContext
        if client_cert is not None and client_key is not None:
            self._verify = self._build_mtls_context(custom_ca, client_cert, client_key)
        else:
            self._verify = custom_ca if custom_ca else True

        # Assumption A1: share ONE raw http.cookiejar.CookieJar between both
        # clients by wrapping it in exactly one cookie-jar wrapper instance
        # and handing that same instance's `.jar` to both — see module
        # docstring for why constructing a fresh wrapper per client does
        # NOT share state.
        self._cookies = httpx.Cookies()

        self._csrf_token: str | None = None
        self._csrf_lock = threading.Lock()

        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

        # Shared single-flight refresh guard (19-02) — one instance for
        # both the sync and async REST call paths on this session.
        self.refresh_guard = RefreshGuard()

        self._logger = logger

    def _build_mtls_context(
        self,
        custom_ca: str | None,
        client_cert: str | bytes,
        client_key: str | bytes,
    ) -> ssl.SSLContext:
        """Build a strict ``ssl.SSLContext`` that keeps full server
        verification on AND presents the configured client identity (mTLS,
        CONTRACT.md §6.1).

        Starts from :func:`ssl.create_default_context` (``check_hostname`` on,
        ``verify_mode=CERT_REQUIRED``) so server verification is never weakened
        by presenting a client certificate (§6.1 rule 2). The existing
        ``custom_ca`` server-trust override is preserved: an inline PEM value
        is added via ``load_verify_locations(cadata=...)`` and a path value via
        ``cafile=...``. The client identity is then loaded with
        ``load_cert_chain``.

        The PEM cert/key are written to files only because ``load_cert_chain``
        requires paths; they live in a ``0o700`` temporary directory with
        ``0o600`` files for the duration of the load and are unlinked
        immediately afterward (the context holds the parsed identity in
        memory). The private key is never retained on ``self`` (§7).

        Args:
            custom_ca: Optional server-trust override (path or inline PEM).
            client_cert: PEM client-certificate chain (``str`` or ``bytes``).
            client_key: PEM private key (``str`` or ``bytes``).

        Returns:
            A configured strict ``ssl.SSLContext`` suitable for httpx
            ``verify=``.

        Raises:
            ValueError: if the supplied client identity is not valid PEM.
        """
        context = ssl.create_default_context()
        if custom_ca:
            if _looks_like_pem(custom_ca):
                context.load_verify_locations(cadata=custom_ca)
            else:
                context.load_verify_locations(cafile=custom_ca)

        cert_pem = normalize_pem(client_cert)
        key_pem = normalize_pem(client_key)
        # load_cert_chain needs file paths; hold the secret key on disk for the
        # shortest possible window — a 0o700 tempdir with 0o600 files, unlinked
        # as soon as the context has parsed the identity into memory.
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "client_cert.pem")
            key_path = os.path.join(tmpdir, "client_key.pem")
            for path, data in ((cert_path, cert_pem), (key_path, key_pem)):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
            try:
                context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            except ssl.SSLError as exc:
                raise ValueError(
                    "client_cert/client_key is not a valid PEM client identity (CONTRACT.md §6.1)"
                ) from exc
        return context

    @property
    def sync_client(self) -> httpx.Client:
        """Lazily-built sync httpx client — constructed on first use, not
        in ``__init__`` (avoids opening a sync connection pool a purely
        async caller never needs)."""
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                base_url=self.base_url,
                cookies=self._shared_jar(),
                timeout=self._timeout,
                verify=self._verify,
            )
        return self._sync_client

    @property
    def async_client(self) -> httpx.AsyncClient:
        """Lazily-built async httpx client — constructed on first use, not
        in ``__init__``."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url,
                cookies=self._shared_jar(),
                timeout=self._timeout,
                verify=self._verify,
            )
        return self._async_client

    def _shared_jar(self) -> CookieJar:
        """Return the single raw ``http.cookiejar.CookieJar`` backing this
        session's cookie-jar wrapper (Assumption A1). Handing this raw jar
        to ``httpx.Client(cookies=...)``/``httpx.AsyncClient`` makes both
        clients wrap the SAME jar object (the wrapper constructor takes a
        raw ``CookieJar`` as-is instead of copying it), so a cookie set via
        one paradigm is visible via the other."""
        return self._cookies.jar

    def _prepare_request(self, request: httpx.Request) -> None:
        """Single choke-point request decorator (mirrors Go's
        ``decorateRequest``): sets ``X-Tenant-ID`` on every request and
        echoes the captured CSRF token on state-changing methods.

        Defense in depth: if the request targets a host other than this
        session's own origin (e.g. a request built against an absolute
        third-party URL, or a followed redirect), skip injection so the
        tenant identifier and CSRF token are never leaked cross-origin. A
        relative/host-less request (the normal case, merged against
        ``base_url``) is treated as same-origin and decorated as before."""
        req_host = request.url.host
        if req_host and req_host != self._base_host:
            return
        request.headers["X-Tenant-ID"] = self.tenant_slug
        if request.method.upper() in _STATE_CHANGING_METHODS:
            token = self._get_csrf_token()
            if token:
                request.headers["X-CSRF-Token"] = token

    def _capture_csrf(self, response: httpx.Response) -> None:
        """Capture a freshly observed ``X-CSRF-Token`` response header
        value (CONTRACT.md §3 non-browser CSRF capture), guarded by a lock
        since this is called from both sync and async request paths."""
        token = response.headers.get("X-CSRF-Token")
        if token:
            with self._csrf_lock:
                self._csrf_token = token

    def _get_csrf_token(self) -> str | None:
        """Read the most recently captured CSRF token, if any, guarded by
        the same lock as :meth:`_capture_csrf` (called from both sync and
        async request paths). Returns ``None`` before any response has set
        the ``X-CSRF-Token`` header."""
        with self._csrf_lock:
            return self._csrf_token

    def _send_sync(self, request: httpx.Request) -> httpx.Response:
        """Single choke point for every sync REST call (mirrors Go's
        ``doRequest``): decorate -> send -> capture CSRF."""
        self._prepare_request(request)
        response = self.sync_client.send(request)
        self._capture_csrf(response)
        return response

    async def _send_async(self, request: httpx.Request) -> httpx.Response:
        """Async twin of :meth:`_send_sync`."""
        self._prepare_request(request)
        response = await self.async_client.send(request)
        self._capture_csrf(response)
        return response

    def cookie_value(self, name: str) -> str | None:
        """Read a named cookie's current value out of the shared jar.

        The server sets ``axiam_refresh`` (and, on a refresh response, a
        fresh ``axiam_access``) Path-scoped to ``/api/v1/auth/refresh``
        (Pitfall 4) while the initial login sets ``axiam_access`` at
        ``Path=/`` — the jar can therefore legitimately hold two distinct
        cookie entries with the same name at different paths, which
        ``httpx.Cookies.get()`` rejects as ambiguous (``CookieConflict``).
        Disambiguate by preferring the entry with the MOST SPECIFIC
        (longest) path, since that is always the one the most recent
        request/response actually targeted.
        """
        matches = [cookie for cookie in self._cookies.jar if cookie.name == name]
        if not matches:
            return None
        best = max(matches, key=lambda cookie: len(cookie.path or ""))
        return best.value

    def close(self) -> None:
        """Close the sync httpx client, if constructed (D-19). Never
        constructs a client merely to close it."""
        if self._sync_client is not None:
            self._sync_client.close()

    async def aclose(self) -> None:
        """Close the async httpx client, if constructed (D-19). Never
        constructs a client merely to close it."""
        if self._async_client is not None:
            await self._async_client.aclose()
