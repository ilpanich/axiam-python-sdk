"""MCP resource-server helpers (CONTRACT.md §28, RFC 9728 + RFC 6750).

The ONE §28 implementation both the FastAPI dependency and the Django
middleware/decorators are built on — mirrors how ``_jwks.py`` is the one §10.1
verification path and ``_oidc.py`` the one §12 core.

§28.0: this SDK implements the RESOURCE SERVER's half and nothing else. AXIAM
is the authorization server and implements none of §28; the MCP client's half
(parsing a challenge, fetching a document, deciding whether to trust the
authorization server it names) is deliberately not in this contract version,
for the same reason §20.3 (UMA) stops at parsing a ticket.

**No operation here performs network I/O**, so §16 (retry) and §9
(single-flight refresh) do not apply and nothing in this module touches the
SDK client's own session. All three canonical operations are pure local
computation, like ``oidc_begin`` (§12.1) and ``uma_parse_challenge`` (§20.5).

**Nothing here is a source of truth about a token.** The document is a claim
a resource server publishes about itself; the challenge is a hint it gives a
caller that already failed. Whether a request is authorized stays §10.1's and
§11's decision, unchanged and unreachable from here.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal, NoReturn

from axiam_sdk._models import ReasonCode

#: RFC 9728 §3.1's well-known prefix — the segment inserted between a
#: resource's authority and its path to reach the document that describes it.
PROTECTED_RESOURCE_METADATA_PREFIX = "/.well-known/oauth-protected-resource"

#: The three hosts §28.2 rule 2 lets an ``http`` URL use, and the only ones.
#:
#: They are AXIAM's RFC 8252 §7.3 loopback hosts, reused verbatim. There is
#: deliberately no flag, environment variable or debug build that widens
#: this: a resource server reachable over plaintext on a routable host
#: publishes an identifier an attacker can impersonate.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "[::1]", "localhost"})

#: RFC 6750 §3.1's three error codes — the complete vocabulary a challenge
#: may name (§28.4).
BearerChallengeError = Literal["invalid_request", "invalid_token", "insufficient_scope"]

_BEARER_CHALLENGE_ERRORS = frozenset({"invalid_request", "invalid_token", "insufficient_scope"})

# ---------------------------------------------------------------------------
# Refusals (§28.2, §28.4, §28.5) — always ValidationError, never a new type
# ---------------------------------------------------------------------------


def _refuse(operation: str, field: str, message: str) -> NoReturn:
    """Raise §28's refusal.

    §28.6 pins the error taxonomy: "§28's refusals are ``ValidationError``;
    no new type". ``status`` names the HTTP code an AXIAM server would answer
    with for the same rejected field — **400** — even though no server was
    asked and no request was made. ``operation`` names the §28 operation
    that refused, the way a management refusal names ``users.get``.

    Imports :class:`~axiam_sdk.management.ValidationError` locally rather
    than at module level: ``axiam_sdk.management`` transitively imports
    ``axiam_sdk._oidc``, which imports ``axiam_sdk._jwks`` (CONTRACT.md
    §28.5's home for a guard's precomputed challenges) — a module-level
    import here would be a circular one for any caller that reaches this
    module through that chain, and this function is never on a hot path.
    """
    from axiam_sdk.management._errors import FieldError, ValidationError

    raise ValidationError(
        operation,
        400,
        f"{field}: {message} (CONTRACT.md §28)",
        [FieldError(field=field, message=message)],
    )


# ---------------------------------------------------------------------------
# Character classes (RFC 6749 Appendix A) — §28.2 rule 5, §28.4
# ---------------------------------------------------------------------------


def _is_nqchar(code: int) -> bool:
    """``NQCHAR``: ``%x21`` / ``%x23``-``%x5B`` / ``%x5D``-``%x7E``. No
    space, no ``"``, no ``\\``, no control character, no non-ASCII."""
    return code == 0x21 or (0x23 <= code <= 0x5B) or (0x5D <= code <= 0x7E)


def _is_nqschar(code: int) -> bool:
    """``NQSCHAR``: ``NQCHAR`` plus the space (``%x20``)."""
    return code == 0x20 or _is_nqchar(code)


def _is_all(value: str, predicate: Callable[[int], bool]) -> bool:
    """``True`` iff every character of ``value`` satisfies ``predicate``
    applied to its code point."""
    return all(predicate(ord(ch)) for ch in value)


# ---------------------------------------------------------------------------
# Absolute-URI parsing (§28.2 rules 1, 2, 3, 7)
# ---------------------------------------------------------------------------

#: ``scheme://authority[path][?query][#fragment]``, matched against the
#: caller's string exactly as given.
#:
#: Deliberately not a normalising URL parser: normalising a value (case
#: folding, resolving ``..`` segments, appending an inferred path) is exactly
#: what §28.2 forbids doing to make a value pass, and §28.3 derives the
#: document's own path from this string, so what is validated must be what
#: was written.
_ABSOLUTE_URI = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)([^?#]*)(\?[^#]*)?(#[\s\S]*)?$")


@dataclass(frozen=True)
class _ParsedUri:
    """The pieces of an absolute URI, sliced out of the caller's string
    without normalisation."""

    #: The scheme, verbatim (compared case-insensitively, stored as written).
    scheme: str
    #: The authority, verbatim — ``userinfo@host:port`` included.
    authority: str
    #: The path component: empty, or starting with ``/``. A trailing slash
    #: is preserved.
    path: str
    #: Whether the string carried a ``?``, even an empty one.
    has_query: bool
    #: Whether the string carried a ``#``, even an empty one.
    has_fragment: bool


def _parse_absolute_uri(raw: str) -> _ParsedUri | None:
    """Match ``raw`` against :data:`_ABSOLUTE_URI` and slice out its pieces,
    or ``None`` when it is not an absolute URI with a non-empty authority."""
    match = _ABSOLUTE_URI.match(raw)
    if not match:
        return None
    authority = match.group(2) or ""
    if authority == "":
        return None
    return _ParsedUri(
        scheme=match.group(1) or "",
        authority=authority,
        path=match.group(3) or "",
        has_query=match.group(4) is not None,
        has_fragment=match.group(5) is not None,
    )


def _host_of(authority: str) -> str:
    """The host inside an authority: ``userinfo@`` stripped, port stripped,
    an IPv6 literal's brackets kept (so ``[::1]`` compares as §28.2 rule 2
    spells it).

    Stripping ``userinfo`` is what makes ``http://localhost@evil.example.com/``
    a refusal rather than a loopback pass — the host there is
    ``evil.example.com``.
    """
    at = authority.rfind("@")
    hostport = authority[at + 1 :] if at >= 0 else authority
    if hostport.startswith("["):
        close = hostport.find("]")
        return hostport if close < 0 else hostport[: close + 1]
    colon = hostport.find(":")
    return hostport if colon < 0 else hostport[:colon]


@dataclass(frozen=True)
class _UriPolicy:
    """How much of §28.2 rule 1 a particular member is held to — rule 7 and
    §28.4's ``resource_metadata`` relax two parts of it."""

    #: ``True`` for ``resource_documentation`` (§28.2 rule 7) and
    #: ``resource_metadata`` (§28.4): a page for a human may be parameterised.
    allow_query: bool
    allow_fragment: bool


_IDENTIFIER = _UriPolicy(allow_query=False, allow_fragment=False)
_LOCATOR = _UriPolicy(allow_query=True, allow_fragment=True)


def _require_absolute_uri(
    operation: str, field: str, raw: object, policy: _UriPolicy
) -> _ParsedUri:
    """§28.2 rules 1 and 2, applied to one member. Returns the parse so a
    caller that needs the path (§28.3) does not parse twice."""
    if not isinstance(raw, str) or raw == "":
        _refuse(operation, field, "must be a non-empty absolute URI")
    parsed = _parse_absolute_uri(raw)
    if parsed is None:
        _refuse(
            operation,
            field,
            f"must be an absolute URI with a scheme and an authority, not {raw!r}",
        )
    if parsed.has_query and not policy.allow_query:
        _refuse(operation, field, "must carry no query — §28.3 derives the metadata path from it")
    if parsed.has_fragment and not policy.allow_fragment:
        _refuse(operation, field, "must carry no fragment")
    scheme = parsed.scheme.lower()
    if scheme == "https":
        return parsed
    if scheme == "http" and _host_of(parsed.authority).lower() in _LOOPBACK_HOSTS:
        return parsed
    _refuse(
        operation,
        field,
        f"must use https — http is accepted only on 127.0.0.1, [::1] or localhost, "
        f"and {raw!r} is neither",
    )


# ---------------------------------------------------------------------------
# §28.1 / §28.2 — protected_resource_metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProtectedResourceMetadataDocument:
    """The RFC 9728 §2 document, carrying **at most** the five members §28.2
    permits, in that order, and no others.

    Two members are **omitted rather than emitted empty or null** by
    :meth:`to_dict`: ``scopes_supported`` when the caller passed no scopes,
    and ``resource_documentation`` when the caller passed none.
    """

    #: The resource identifier this server publishes for itself — the string
    #: an RFC 8707 ``resource`` parameter carries and the ``aud`` the guard
    #: checks.
    resource: str
    #: The issuer identifiers of the authorization servers that guard this
    #: resource. At least one, each verbatim.
    authorization_servers: tuple[str, ...]
    #: The scope tokens this resource server understands, in the caller's
    #: order. ``None`` when the caller passed none (member omitted).
    scopes_supported: tuple[str, ...] | None
    #: Always ``("header",)`` in this contract version — §10's guard reads a
    #: bearer credential from the ``Authorization`` header alone.
    bearer_methods_supported: tuple[str, ...]
    #: A human-readable documentation page. ``None`` when the caller passed
    #: none (member omitted; never emitted as ``null``).
    resource_documentation: str | None

    def to_dict(self) -> dict[str, object]:
        """Serialize to the exact JSON shape and member order §28.2 fixes."""
        document: dict[str, object] = {
            "resource": self.resource,
            "authorization_servers": list(self.authorization_servers),
        }
        if self.scopes_supported:
            document["scopes_supported"] = list(self.scopes_supported)
        document["bearer_methods_supported"] = list(self.bearer_methods_supported)
        if self.resource_documentation is not None:
            document["resource_documentation"] = self.resource_documentation
        return document


@dataclass(frozen=True)
class ProtectedResourceMetadata:
    """What :func:`protected_resource_metadata` (and
    :func:`~axiam_sdk.fastapi.serve_protected_resource_metadata`) return: the
    document, the path it is served at, and the URL that path resolves to.

    :attr:`metadata_url` exists so that an integrator feeds the guard's
    ``resource_metadata_url`` option (§28.5) from the value derived here
    rather than by retyping the string — retyping is how the two come to
    disagree, and a challenge pointing at a document that is not this
    resource server's is worse than no challenge at all.
    """

    #: The RFC 9728 §2 document, ready to serialize.
    document: ProtectedResourceMetadataDocument
    #: The absolute path the document is served at, derived from the
    #: resource per §28.3 — never chosen.
    metadata_path: str
    #: :attr:`metadata_path` resolved against the resource's scheme and
    #: authority. Feed this to the guard's ``resource_metadata_url``.
    metadata_url: str


def _derive_metadata_path(resource_path: str) -> str:
    """§28.3's derivation: RFC 9728 §3.1 inserts the well-known segment
    between the authority and the path. An empty path and a bare ``/`` both
    reach the root form; anything else is appended, **trailing slash
    included** — it is part of the identifier a client compares, and two
    resources that differ only by it are two resources."""
    if resource_path in ("", "/"):
        return PROTECTED_RESOURCE_METADATA_PREFIX
    return PROTECTED_RESOURCE_METADATA_PREFIX + resource_path


def protected_resource_metadata(
    resource: str,
    authorization_servers: Sequence[str],
    scopes_supported: Sequence[str],
    bearer_methods_supported: Sequence[str] = ("header",),
    resource_documentation: str | None = None,
) -> ProtectedResourceMetadata:
    """``protected_resource_metadata(...)`` (CONTRACT.md §28.1) — build and
    validate the RFC 9728 protected-resource metadata document this server
    publishes about itself, and derive the path and URL it is served at.

    **Validation happens here and it refuses; it never repairs.** Every
    §28.2 rule is checked before any route exists and before any request is
    served, and a violation raises :class:`~axiam_sdk.NetworkError`'s
    :class:`~axiam_sdk.management.ValidationError` sub-type. Nothing is
    normalised, trimmed, lowercased or re-encoded to make it pass: a value
    that needs adjusting is a configuration mistake an operator fixes in one
    line, and a helper that quietly fixed it would publish a document
    describing a resource server that does not exist.

    **Nothing in the document may come from a request** (§28.2 rule 8). Both
    ``resource`` and ``authorization_servers`` are configuration; this SDK
    offers no option to build either from the ``Host`` header, the
    ``Forwarded``/``X-Forwarded-*`` family or the request URL, because a
    document assembled from the request is a document an attacker can point
    at an authorization server of their choosing — the whole handshake
    redirected with one header.

    Args:
        resource: The resource identifier. Absolute, ``https`` (or ``http``
            on a loopback host), with no query and no fragment. A trailing
            slash is significant.
        authorization_servers: The issuer identifiers of the authorization
            servers guarding it — at least one, no duplicates, no query, no
            fragment.
        scopes_supported: The scope tokens this resource server understands.
            Order is preserved, duplicates are refused, and an empty
            sequence omits the member.
        bearer_methods_supported: Defaults to ``("header",)``, and
            ``("header",)`` is the only accepted value in this contract
            version.
        resource_documentation: Optional documentation page for a human. May
            carry a query and a fragment; omitted from the document when
            absent.

    Returns:
        The validated :class:`ProtectedResourceMetadata`.

    Raises:
        ValidationError: when any §28.2 rule is violated.

    Example::

        metadata = protected_resource_metadata(
            resource="https://mcp.example.com/mcp",
            authorization_servers=["https://axiam.example.com"],
            scopes_supported=["mcp:read", "mcp:tools"],
        )
        metadata.metadata_path  # '/.well-known/oauth-protected-resource/mcp'
        metadata.metadata_url   # 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp'
    """
    op = "protected_resource_metadata"

    # Rule 1 + rule 2.
    parsed = _require_absolute_uri(op, "resource", resource, _IDENTIFIER)

    # Rule 3 + rule 4: at least one entry, each an issuer verbatim, no duplicates.
    servers = list(authorization_servers)
    if len(servers) == 0:
        _refuse(
            op,
            "authorization_servers",
            "must name at least one authorization server — a document that names "
            "none answers none of the question the client asked",
        )
    seen_servers: set[str] = set()
    resolved_servers: list[str] = []
    for issuer in servers:
        _require_absolute_uri(op, "authorization_servers", issuer, _IDENTIFIER)
        if issuer in seen_servers:
            _refuse(op, "authorization_servers", f"duplicate entry {issuer!r}")
        seen_servers.add(issuer)
        resolved_servers.append(issuer)

    # Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty omits.
    seen_scopes: set[str] = set()
    resolved_scopes: list[str] = []
    for scope in scopes_supported:
        if scope == "" or not _is_all(scope, _is_nqchar):
            _refuse(
                op,
                "scopes_supported",
                f"{scope!r} is not a scope token — one or more NQCHAR (no space, "
                "no '\"', no '\\\\', no control character, no non-ASCII)",
            )
        if scope in seen_scopes:
            _refuse(op, "scopes_supported", f"duplicate scope {scope!r}")
        seen_scopes.add(scope)
        resolved_scopes.append(scope)

    # Rule 6: exactly ["header"].
    methods = list(bearer_methods_supported)
    if len(methods) != 1 or methods[0] != "header":
        _refuse(
            op,
            "bearer_methods_supported",
            f"must be exactly ['header'] in this contract version — §10's guard "
            f"reads a bearer credential from the Authorization header alone, so "
            f"{methods!r} would describe behaviour this SDK does not have",
        )

    # Rule 7: absolute URL, query and fragment permitted, omitted when absent.
    if resource_documentation is not None:
        _require_absolute_uri(op, "resource_documentation", resource_documentation, _LOCATOR)

    document = ProtectedResourceMetadataDocument(
        resource=resource,
        authorization_servers=tuple(resolved_servers),
        scopes_supported=tuple(resolved_scopes) if resolved_scopes else None,
        bearer_methods_supported=("header",),
        resource_documentation=resource_documentation,
    )

    metadata_path = _derive_metadata_path(parsed.path)
    return ProtectedResourceMetadata(
        document=document,
        metadata_path=metadata_path,
        metadata_url=f"{parsed.scheme}://{parsed.authority}{metadata_path}",
    )


# ---------------------------------------------------------------------------
# §28.4 — bearer_challenge
# ---------------------------------------------------------------------------


def bearer_challenge(
    resource_metadata_url: str,
    error: BearerChallengeError | None = None,
    error_description: str | None = None,
    scope: str | None = None,
) -> str:
    """``bearer_challenge(...)`` (CONTRACT.md §28.4) — build the **value** of
    a ``WWW-Authenticate`` header, never the whole header line and never a
    mapping. The caller sets the header.

    Parameters appear in a fixed order — ``error``, ``error_description``,
    ``scope``, ``resource_metadata`` — separated by exactly ``, ``.
    ``resource_metadata`` is always present; the other three are omitted
    when not given.

    **Every value is quoted and no value is ever escaped.** RFC 6750 §3
    restricts each parameter to a character set that cannot contain ``"`` or
    ``\\``, so a value needing an escape is a value that does not belong in
    a challenge: this function refuses it rather than escaping, truncating
    or stripping it. A challenge is built from the code's own constants and
    a route's own configuration, so an invalid one is a programming error,
    not a runtime condition to degrade around.

    Args:
        resource_metadata_url: The document's URL — the one parameter that
            is always present. May carry a query and a fragment.
        error: One of RFC 6750 §3.1's three codes, or ``None`` when the
            request carried no authentication information at all.
        error_description: A human-readable description, for an application
            building **its own** challenge for its own 400. The SDK's own
            guards never set it: expired, not yet valid, wrong tenant, wrong
            audience, bad signature, an unsatisfiable ``cnf``, a revoked
            ``sid`` — §28.4 makes all of them ``invalid_token``,
            indistinguishably. Every distinction a 401 draws for an
            unauthenticated stranger is an oracle.
        scope: The scope the route asked for, verbatim — one or more tokens
            joined by a single space.

    Returns:
        The ``WWW-Authenticate`` header value.

    Raises:
        ValidationError: when any parameter is outside RFC 6750's syntax.

    Example::

        bearer_challenge(metadata.metadata_url)
        # 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'

        bearer_challenge(metadata.metadata_url, error="insufficient_scope", scope="mcp:tools")
        # 'Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://.../mcp"'
    """
    op = "bearer_challenge"
    params: list[str] = []

    if error is not None:
        if error not in _BEARER_CHALLENGE_ERRORS:
            _refuse(
                op,
                "error",
                "must be one of invalid_request, invalid_token, insufficient_scope — "
                f"RFC 6750 §3.1 defines no others, and {error!r} is not among them",
            )
        params.append(f'error="{error}"')

    if error_description is not None:
        if (
            not isinstance(error_description, str)
            or error_description == ""
            or not _is_all(error_description, _is_nqschar)
        ):
            _refuse(
                op,
                "error_description",
                "must be one or more NQSCHAR (no '\"', no '\\\\', no control character, "
                "no non-ASCII) — a value needing an escape does not belong in a challenge",
            )
        params.append(f'error_description="{error_description}"')

    if scope is not None:
        if not isinstance(scope, str) or scope == "":
            _refuse(op, "scope", "must be one or more scope tokens joined by a single space")
        for token in scope.split(" "):
            if token == "" or not _is_all(token, _is_nqchar):
                _refuse(
                    op,
                    "scope",
                    f"{scope!r} is not a space-joined list of scope tokens — no leading, "
                    "trailing or doubled space, and no empty token",
                )
        params.append(f'scope="{scope}"')

    _require_absolute_uri(op, "resource_metadata", resource_metadata_url, _LOCATOR)
    if not _is_all(resource_metadata_url, _is_nqchar):
        _refuse(
            op,
            "resource_metadata",
            "must carry no '\"', no '\\\\', no space and no control character — a "
            "correctly encoded URL cannot, so one that does has not been encoded",
        )
    params.append(f'resource_metadata="{resource_metadata_url}"')

    return f"Bearer {', '.join(params)}"


# ---------------------------------------------------------------------------
# §28.5 — the resource_metadata_url guard option (framework-internal wiring)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class McpGuardChallenges:
    """The §28 challenge values a guard emits, all built once at
    guard-construction time so that an invalid one is a startup failure
    rather than a surprise on the 401 path.

    Not part of §28.1's canonical operation set — internal wiring shared by
    :mod:`axiam_sdk.fastapi` and :mod:`axiam_sdk.django`, the way
    ``mcpCore.ts``'s equivalent type is internal to the TypeScript SDK's
    Express/Fastify surfaces.
    """

    #: §28.4 vector 1 — the request carried **no** authentication
    #: information, so RFC 6750 §3 says not to name an error.
    no_credential: str
    #: §28.4 vector 2 — a credential was presented and rejected. The only
    #: thing the 401 ever says about why.
    invalid_token: str
    #: §28.4 vector 3 — present only where the route named a scope; emitted
    #: on a ``no_grant`` denial and nowhere else.
    insufficient_scope: str | None
    #: The document's path, exempted from authentication where the guard is
    #: applied globally (§28.3 rule 2).
    metadata_path: str


def mcp_guard_challenges(
    expected_audience: str | None,
    resource_metadata_url: str | None,
    operation: str,
    scope: str | None = None,
) -> McpGuardChallenges | None:
    """Validate a guard's §28 configuration and precompute the challenges it
    will emit. Called by every guard factory at construction time —
    route-setup time, never per-request.

    Returns ``None`` when ``resource_metadata_url`` is unset: §28 is opt-in,
    and with the option absent the guard behaves exactly as it did before
    §28 existed — no header on any response, no status changed, no body
    changed.

    **``expected_audience`` is mandatory once ``resource_metadata_url`` is
    set**, and the refusal names both options. A resource server that
    publishes "tokens for me carry this ``aud``" and then does not check
    ``aud`` has published a claim it does not honour, and a token minted for
    a *different* resource server opens it. That is the confusion RFC 8707
    exists to prevent, so this is a refusal rather than a warning.

    Args:
        expected_audience: §10.1 row 6's expected audience, under whatever
            name the caller's guard already gives it. §28 adds no second
            audience option.
        resource_metadata_url: §28.5's option: the URL of this resource
            server's metadata document. Setting it is what turns §28 on.
        operation: The guard factory's name, so the refusal says which guard
            refused.
        scope: The route's ``scope`` argument, where it has one (§28.5
            rule 5).

    Raises:
        ValidationError: when ``resource_metadata_url`` is set without an
            expected audience, or when either it or ``scope`` is outside
            §28.4's syntax.
    """
    if resource_metadata_url is None:
        return None

    if not expected_audience:
        _refuse(
            operation,
            "resource_metadata_url",
            "requires expected_audience to be set on the same guard (CONTRACT.md "
            "§28.5 rule 2) — announcing a resource identifier obliges this server "
            "to check that an inbound token's aud is that identifier, and a "
            "resource server that announces itself without checking is opened by "
            "a token minted for somebody else",
        )

    parsed = _require_absolute_uri(
        operation, "resource_metadata_url", resource_metadata_url, _LOCATOR
    )
    insufficient_scope = (
        bearer_challenge(resource_metadata_url, error="insufficient_scope", scope=scope)
        if scope is not None
        else None
    )
    return McpGuardChallenges(
        no_credential=bearer_challenge(resource_metadata_url),
        invalid_token=bearer_challenge(resource_metadata_url, error="invalid_token"),
        insufficient_scope=insufficient_scope,
        metadata_path=parsed.path or "/",
    )


def challenge_for_401(challenges: McpGuardChallenges, credential_presented: bool) -> str:
    """Pick between §28.4's first two vectors for a 401: ``invalid_token``
    when the request carried a credential, no ``error`` at all when it
    carried none.

    §28.4 is explicit that the absent ``error`` is not an oversight — RFC
    6750 §3 says a resource server SHOULD NOT name an error code when the
    request carried no authentication information, because no credential is
    not a bad credential, and a client has to be able to tell the two apart.
    """
    return challenges.invalid_token if credential_presented else challenges.no_credential


def challenge_for_403(challenges: McpGuardChallenges | None, reason_code: str | None) -> str | None:
    """§28.5 rule 5: the one class of 403 that carries a challenge, and only
    it.

    A ``no_grant`` denial on a route that named a scope means *ask for
    more*, which is exactly what a challenge invites a client to do. A
    ``denied_by_rule`` denial means *an administrator has already decided*,
    and challenging on it sends an MCP client all the way around the
    authorization loop to arrive at the identical 403. An absent or
    unrecognised ``reason_code`` — an older server, a value this SDK
    predates — is not eligible either: §11.2 rule 9 requires an unknown code
    to leave the outcome alone, and the outcome here is a header-free 403.
    """
    if challenges is None or challenges.insufficient_scope is None:
        return None
    return challenges.insufficient_scope if reason_code == ReasonCode.NO_GRANT else None


def is_metadata_document_request(
    challenges: McpGuardChallenges | None, method: str | None, path: str | None
) -> bool:
    """Is this request the unauthenticated ``GET``/``HEAD`` of the metadata
    document?

    §28.3 rule 2 requires the document to be reachable with no credential of
    any kind, and requires the SDK to exempt the path explicitly where the
    §10 guard is applied globally — Django's ``AxiamAuthMiddleware`` is the
    case that applies here; a document that 401s cannot start the handshake
    it exists to start.

    The exemption is derived from ``resource_metadata_url``, so it exists
    only where §28 is configured and covers exactly the one path that option
    names.
    """
    if challenges is None or not isinstance(path, str):
        return False
    verb = (method or "").upper()
    if verb not in ("GET", "HEAD"):
        return False
    return path == challenges.metadata_path


__all__ = [
    "PROTECTED_RESOURCE_METADATA_PREFIX",
    "BearerChallengeError",
    "ProtectedResourceMetadata",
    "ProtectedResourceMetadataDocument",
    "bearer_challenge",
    "protected_resource_metadata",
]
