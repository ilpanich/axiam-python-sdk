"""Local checks the generated §27 surface runs before any I/O.

The generator (``scripts/gen_management.py``, ``PRECHECKS``) emits a call to a
function here at the top of an operation's call builder, so a body the contract
says must never reach the wire is refused with the SDK's local
``ValidationError`` and no request is made. Nothing here performs I/O.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from axiam_sdk.management._errors import local_refusal

if TYPE_CHECKING:  # pragma: no cover - typing only
    from axiam_sdk.management.models import ParseSamlSpMetadata

__all__ = ["parse_sp_metadata_exactly_one"]


def parse_sp_metadata_exactly_one(body: ParseSamlSpMetadata) -> None:
    """§29.2: ``ParseSamlSpMetadata`` is **exactly one** of ``metadata_xml`` and
    ``metadata_url``.

    Both or neither is a local ``ValidationError``, raised before any request --
    never a request the server refuses. ``ParseSamlSpMetadata.from_url`` and
    ``.from_xml`` build only the valid shapes.

    Raises:
        ValidationError: for both members, or neither.
    """
    has_xml = body.metadata_xml is not None
    has_url = body.metadata_url is not None
    if has_xml and has_url:
        raise local_refusal(
            "saml.parse_sp_metadata",
            "metadata_xml",
            "set exactly one of metadata_xml and metadata_url, not both (CONTRACT.md §29.2)",
        )
    if not has_xml and not has_url:
        raise local_refusal(
            "saml.parse_sp_metadata",
            "metadata_url",
            "set exactly one of metadata_xml and metadata_url (CONTRACT.md §29.2)",
        )
