"""version_compatibility.py reports the running interpreter against the range
of Python versions this SDK declares support for.

The SDK is *built* against its floor (the oldest interpreter still receiving
upstream security fixes) and *tested* against the newest GA release, so a
deployment anywhere between those two is covered by CI. This example reads
that range out of the installed package metadata rather than hardcoding it, so
it stays correct across SDK upgrades — the same metadata `pip` consults when
it decides whether to install at all.

Useful as a container-image preflight or a startup assertion: it turns "the
SDK probably works on this base image" into something a process can check and
fail loudly on, rather than a `SyntaxError` five imports deep.

This example is illustrative/compilable — it reads nothing from the network
and does not require a live AXIAM server to byte-compile.

Run: python examples/version_compatibility.py
"""

from __future__ import annotations

import re
import sys
from importlib import metadata

DISTRIBUTION = "axiam-sdk"

# "Programming Language :: Python :: 3.12" — the bare ":: 3" classifier has no
# minor version and is skipped.
_CLASSIFIER_RE = re.compile(r"^Programming Language :: Python :: (\d+)\.(\d+)$")


def supported_range() -> tuple[tuple[int, int], tuple[int, int]]:
    """Return (floor, newest) as (major, minor) pairs, from package metadata."""
    dist = metadata.metadata(DISTRIBUTION)
    versions = sorted(
        (int(m.group(1)), int(m.group(2)))
        for m in (_CLASSIFIER_RE.match(c) for c in dist.get_all("Classifier") or [])
        if m is not None
    )
    if not versions:
        raise RuntimeError(f"{DISTRIBUTION} metadata declares no per-minor Python classifiers")
    return versions[0], versions[-1]


def fmt(version: tuple[int, int]) -> str:
    return f"{version[0]}.{version[1]}"


def main() -> None:
    running = (sys.version_info.major, sys.version_info.minor)

    try:
        floor, newest = supported_range()
    except metadata.PackageNotFoundError:
        print(f"{DISTRIBUTION} is not installed — run `pip install {DISTRIBUTION}`")
        raise SystemExit(2) from None

    print(f"running interpreter: {fmt(running)} ({sys.executable})")
    print(f"{DISTRIBUTION} supports: {fmt(floor)} .. {fmt(newest)}")

    if running < floor:
        # pip would have refused this install; the usual way to arrive here is
        # a wheel copied between images, or a vendored site-packages.
        print(
            f"UNSUPPORTED: {fmt(running)} is below the {fmt(floor)} floor. "
            "Imports may fail on syntax this SDK relies on."
        )
        raise SystemExit(1)

    if running > newest:
        # Not an error. The SDK is pure Python and forward-compatible; this
        # interpreter is simply newer than the last one CI has proven.
        print(
            f"UNTESTED: {fmt(running)} is newer than {fmt(newest)}, the newest "
            "release this SDK's CI builds against. Expected to work — the "
            "wheel is pure Python — but not yet proven by a green build."
        )
        return

    print(f"SUPPORTED: {fmt(running)} is inside the tested range.")


if __name__ == "__main__":
    main()
