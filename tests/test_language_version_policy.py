"""Language-version support policy — D-11 (floor), D-18 (CI matrix).

The SDK states which Python versions it supports in three places that no
compiler and no packaging tool ever checks against one another:

1. ``requires-python`` in ``pyproject.toml`` — what ``pip`` enforces at install
   time, and the only one of the three that can actually refuse an install;
2. the ``Programming Language :: Python :: X.Y`` trove classifiers — what PyPI
   renders and what the README badge is generated from;
3. the ``python-version`` matrix in ``.github/workflows/sdk-ci-python.yml`` —
   the only one that is ever *executed*.

These drift apart silently and in both directions. A classifier can claim a
release nothing has ever built on, and CI can go green on an interpreter the
package metadata would refuse to install on. Neither shows up as a failure;
both are wrong in a way a user only discovers at ``pip install`` time.

The policy pinned here is floor + newest: the gating matrix runs exactly the
two ends of the declared range, because those are the legs that catch
breakage. The floor rejects syntax and stdlib APIs the declared minimum does
not have; the newest catches removals and deprecations that have turned into
errors. Everything between them sits between two green legs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - only taken on the 3.10 floor leg
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sdk-ci-python.yml"

# A trove classifier for a concrete minor release, e.g.
# "Programming Language :: Python :: 3.12". The bare ":: 3" classifier carries
# no minor and is deliberately not matched.
_CLASSIFIER_RE = re.compile(r"^Programming Language :: Python :: (\d+)\.(\d+)$")

# `python-version: ['3.10', '3.14']` in the workflow's test matrix.
_MATRIX_RE = re.compile(r"^\s*python-version:\s*\[(?P<versions>[^\]]*)\]\s*$", re.M)

# `requires-python = ">=3.10"`. The policy is a simple inclusive floor: if this
# ever grows an upper bound or a second clause, the parse below should fail
# loudly rather than quietly interpret half of it.
_REQUIRES_RE = re.compile(r"^>=\s*(\d+)\.(\d+)$")

Version = tuple[int, int]


def _fmt(version: Version) -> str:
    return f"{version[0]}.{version[1]}"


@pytest.fixture(scope="module")
def pyproject() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


@pytest.fixture(scope="module")
def declared_floor(pyproject: dict) -> Version:
    raw = pyproject["project"]["requires-python"]
    match = _REQUIRES_RE.match(raw.strip())
    assert match is not None, (
        f"requires-python is {raw!r}, which this policy test cannot interpret. "
        "The support policy is a single inclusive floor (`>=X.Y`); if that has "
        "deliberately changed, update this test rather than loosening the regex."
    )
    return int(match.group(1)), int(match.group(2))


@pytest.fixture(scope="module")
def classifier_versions(pyproject: dict) -> list[Version]:
    found = []
    for classifier in pyproject["project"]["classifiers"]:
        match = _CLASSIFIER_RE.match(classifier)
        if match is not None:
            found.append((int(match.group(1)), int(match.group(2))))
    assert found, "pyproject declares no per-minor Python trove classifiers"
    return sorted(found)


@pytest.fixture(scope="module")
def ci_matrix_versions() -> list[Version]:
    matches = _MATRIX_RE.findall(CI_WORKFLOW.read_text(encoding="utf-8"))
    assert len(matches) == 1, (
        f"expected exactly one `python-version:` matrix in {CI_WORKFLOW.name}, "
        f"found {len(matches)}. A second matrix would mean this test is only "
        "checking one of them."
    )
    versions = []
    for entry in matches[0].split(","):
        cleaned = entry.strip().strip("'\"")
        if not cleaned:
            continue
        major, _, minor = cleaned.partition(".")
        versions.append((int(major), int(minor)))
    return sorted(versions)


def test_requires_python_floor_matches_lowest_classifier(
    declared_floor: Version, classifier_versions: list[Version]
) -> None:
    """`pip` and PyPI must agree on where support starts.

    A classifier below `requires-python` advertises a version pip will refuse
    to install on; a floor below the lowest classifier means the package
    installs somewhere PyPI never claimed to support.
    """
    assert classifier_versions[0] == declared_floor, (
        f"requires-python floor is {_fmt(declared_floor)} but the lowest trove "
        f"classifier is {_fmt(classifier_versions[0])}"
    )


def test_classifiers_cover_the_range_without_gaps(
    classifier_versions: list[Version],
) -> None:
    """Every minor release between floor and newest is claimed.

    A gap here is never intentional — it is what a forgotten classifier looks
    like when a new interpreter is added at the top.
    """
    major = classifier_versions[0][0]
    assert all(v[0] == major for v in classifier_versions), (
        "classifiers span more than one major version, which this policy does not model"
    )
    minors = [v[1] for v in classifier_versions]
    expected = list(range(minors[0], minors[-1] + 1))
    assert minors == expected, (
        f"classifiers skip {sorted(set(expected) - set(minors))} between "
        f"{_fmt(classifier_versions[0])} and {_fmt(classifier_versions[-1])}"
    )


def test_ci_matrix_is_exactly_floor_and_newest(
    classifier_versions: list[Version], ci_matrix_versions: list[Version]
) -> None:
    """D-18: the gating matrix is the two ends of the declared range.

    Not a subset of them and not all of them — exactly those two. Dropping the
    floor leg means the declared minimum is never compiled against; dropping
    the newest leg means the SDK stops learning about the interpreter most new
    users are actually on.
    """
    expected = [classifier_versions[0], classifier_versions[-1]]
    assert ci_matrix_versions == expected, (
        f"CI matrix runs {[_fmt(v) for v in ci_matrix_versions]} but the "
        f"declared range is {_fmt(expected[0])}..{_fmt(expected[1])}, so the "
        f"floor+newest policy wants {[_fmt(v) for v in expected]}"
    )


def test_ci_never_builds_an_undeclared_interpreter(
    declared_floor: Version,
    classifier_versions: list[Version],
    ci_matrix_versions: list[Version],
) -> None:
    """CI going green is only meaningful for versions we actually claim."""
    declared = set(classifier_versions)
    for version in ci_matrix_versions:
        assert version >= declared_floor, (
            f"CI builds {_fmt(version)}, below the declared floor {_fmt(declared_floor)}"
        )
        assert version in declared, f"CI builds {_fmt(version)} but no trove classifier claims it"


def test_running_interpreter_is_declared_supported(
    declared_floor: Version, classifier_versions: list[Version]
) -> None:
    """The interpreter running this suite is inside the supported range.

    This is the leg that catches the matrix and the metadata being edited in
    opposite directions: whichever version CI actually launched, the package
    claims it.
    """
    running = (sys.version_info.major, sys.version_info.minor)
    assert running >= declared_floor, (
        f"tests are running on {_fmt(running)}, below the declared floor {_fmt(declared_floor)}"
    )
    assert running <= classifier_versions[-1], (
        f"tests are running on {_fmt(running)}, above the newest declared "
        f"version {_fmt(classifier_versions[-1])} — add the classifier"
    )
