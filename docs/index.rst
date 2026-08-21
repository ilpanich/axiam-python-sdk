AXIAM Python SDK
================

Official Python client for `AXIAM <https://github.com/ilpanich/axiam>`_, an
open-source IAM server. The SDK covers the full client contract — REST, gRPC
and AMQP transports, OAuth2/OIDC relying-party helpers, UMA, webhook signature
verification and OPAQUE.

This is the API reference, generated from the docstrings in the source. For
task-oriented material — installation, quickstart, framework integrations,
performance notes — start with the
`README <https://github.com/ilpanich/axiam-python-sdk#readme>`_, and consult
``CONTRACT.md`` in the repository for the normative cross-SDK behaviour every
AXIAM client implements.

.. note::

   AXIAM is multi-tenant and has no default tenant. ``login`` and ``refresh``
   need organization context as well, because a tenant slug is unique only
   within an organization. TLS verification is always on; the only escape
   hatch is supplying your own CA, never a boolean bypass.

Installation
------------

.. code-block:: console

   pip install axiam-sdk

Optional extras: ``[fastapi]``, ``[django]`` for framework integrations, and
``[speed]`` to swap in ``uvloop`` on Linux and macOS.

API reference
-------------

.. Only the root package is listed: ``:recursive:`` already walks every
   submodule, so naming them again documents each one twice and Sphinx warns
   about the duplicate object descriptions.

.. autosummary::
   :toctree: _autosummary
   :recursive:

   axiam_sdk

.. toctree::
   :hidden:
   :maxdepth: 2

   self

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
