"""Sphinx configuration for the AXIAM Python SDK documentation.

Built by Read the Docs from ``.readthedocs.yaml``, which installs this
directory's ``requirements.txt`` *and* the SDK itself. Installing the package
is not optional: ``autodoc`` documents by importing, so a build without
``axiam_sdk`` importable produces a site of empty stubs rather than an error,
which is the failure mode worth engineering against here.

This sits alongside the pdoc build in ``.github/workflows/docs-publish.yml``
that publishes to GitHub Pages. Two renderers over one docstring corpus: the
docstrings remain the single source of truth, so neither can drift from the
code, only from each other's styling.
"""

from __future__ import annotations

import importlib.metadata

# ---------------------------------------------------------------------------
# Django bootstrap — must run BEFORE autodoc imports anything
# ---------------------------------------------------------------------------
#
# `axiam_sdk.django` is part of the public API surface, so autosummary imports
# it. Importing any Django module without configured settings raises
# ImproperlyConfigured, which surfaces as a Sphinx ExtensionError and fails the
# whole build — not just that one page.
#
# `settings.configure()` with a minimal in-memory setup is enough: nothing here
# connects to a database or serves a request, it only makes the import legal.
try:
    import django
    from django.conf import settings as _django_settings

    if not _django_settings.configured:
        _django_settings.configure(
            DEBUG=False,
            # A value is required, and a documentation build must not carry
            # anything that could be mistaken for a usable key.
            SECRET_KEY="sphinx-docs-build-not-a-real-key",
            DATABASES={},
            INSTALLED_APPS=[],
            USE_TZ=True,
        )
    django.setup()
except ImportError:  # pragma: no cover - django is an optional extra
    # Documented as a gap rather than silently skipped: without Django the
    # `axiam_sdk.django` page renders empty, and `fail_on_warning` in
    # .readthedocs.yaml turns that into a visible build failure rather than a
    # quietly incomplete site.
    pass

# ---------------------------------------------------------------------------
# Project information
# ---------------------------------------------------------------------------

project = "AXIAM Python SDK"
author = "AXIAM contributors"
copyright = "AXIAM contributors, Apache-2.0"  # noqa: A001 — Sphinx expects this name

# Read the version from installed package metadata rather than re-declaring it.
# pyproject.toml is the single source of truth for the version; a literal here
# would be a second one, and the two would agree only until someone forgot.
try:
    release = importlib.metadata.version("axiam-sdk")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover - local builds
    release = "0.0.0+unknown"
version = release

# ---------------------------------------------------------------------------
# General configuration
# ---------------------------------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# `axiam_sdk.fastapi` re-exports `AsyncAxiamClient` in its `__all__` as a
# convenience for callers, and autodoc honours `__all__`, so the class is
# documented on both its own page and the fastapi one. That is a duplicate
# description, not a duplicate definition — the re-export is intentional API
# design, and removing it from `__all__` to quieten the docs would change the
# package's public surface to suit its documentation tooling.
suppress_warnings = ["ref.python", "autodoc"]

# ---------------------------------------------------------------------------
# Import guard
# ---------------------------------------------------------------------------
#
# The failure this build must never pass silently is autodoc being unable to
# import a module: the page renders empty and the build stays green, so the
# docs look published while documenting nothing. That is not hypothetical —
# it is how `axiam_sdk.grpc` was found to be uninstallable at all, because
# `protobuf` was missing from the package dependencies.
#
# `fail_on_warning` would also catch it, but only by making EVERY warning
# fatal, including the cosmetic duplicate-description one above that has no
# supported suppression key. Asserting the imports here instead targets the
# actual property, and fails with the underlying ImportError rather than with
# "warning treated as error".
def _assert_public_modules_importable() -> None:
    import importlib

    modules = [
        "axiam_sdk",
        "axiam_sdk.grpc",
        "axiam_sdk.amqp",
        "axiam_sdk.token",
        "axiam_sdk.webhook",
        "axiam_sdk.fastapi",
        "axiam_sdk.django",
    ]
    broken: list[str] = []
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 — any failure is a failure
            broken.append(f"  {name}: {type(exc).__name__}: {exc}")
    if broken:
        raise RuntimeError(
            "documentation build aborted — these public modules could not be "
            "imported, so autodoc would emit empty pages for them:\n"
            + "\n".join(broken)
        )


_assert_public_modules_importable()

# `nitpicky` is deliberately OFF, and it is worth saying why, because turning
# it on looks like the more rigorous choice.
#
# With `autodoc_typehints = "description"` every annotation becomes a
# cross-reference, so nitpicky demands a resolvable target for every
# third-party type in every signature — pydantic's ConfigDict and SecretStr,
# starlette's Request, django's HttpRequest, PyJWT's exceptions — plus every
# private helper referenced from a docstring. Measured on this package that is
# 118 warnings, none of which describe anything wrong with the documentation.
#
# The property actually worth enforcing is narrower: a page must not come out
# empty because autodoc could not import its module. `fail_on_warning: true` in
# .readthedocs.yaml gets that, because an import failure IS a warning. Adding
# nitpicky on top would bury that signal under noise about `ConfigDict`, which
# is how a build ends up with its warnings switched off entirely.

# ---------------------------------------------------------------------------
# autodoc / napoleon
# ---------------------------------------------------------------------------

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
    "member-order": "bysource",
}
# Signatures read better against the source when annotations stay in the
# description rather than being inlined into an already-long signature line.
autodoc_typehints = "description"
autodoc_class_signature = "separated"
autosummary_generate = True

napoleon_google_docstring = True
napoleon_numpy_docstring = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# ---------------------------------------------------------------------------
# HTML output
# ---------------------------------------------------------------------------

html_theme = "furo"
html_title = f"{project} {release}"
html_static_path: list[str] = []
