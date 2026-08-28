"""The CONTRACT §27 management API.

147 operations across 24 namespaces, reached as ``client.<namespace>.<operation>``
(and equivalently ``client.management.<namespace>.<operation>``). The namespace
handles and the models they carry are generated from ``management-registry.json``
and ``openapi.json`` by ``scripts/gen_management.py``; everything else in this
package -- paging, scope resolution, the request path, the error sub-types and
the declarative layer -- is written by hand, because §27.8 makes those the parts
an SDK owns.

Acquiring a handle performs no I/O (§27.2 rule 1)::

    users = client.users                      # no request
    page = users.list(PageRequest(limit=50))  # one request
    everyone = users.list_all()               # as many as the set needs

The same surface exists on :class:`~axiam_sdk.AsyncAxiamClient` with ``await``.
"""

from __future__ import annotations

from axiam_sdk.management._errors import (
    ConflictError,
    FieldError,
    NotFoundError,
    ValidationError,
)
from axiam_sdk.management._page import Page, PageRequest
from axiam_sdk.management._scope import NamespaceScope
from axiam_sdk.management._wire import ManagementModel

__all__ = [
    "ConflictError",
    "FieldError",
    "ManagementModel",
    "NamespaceScope",
    "NotFoundError",
    "Page",
    "PageRequest",
    "ValidationError",
]
