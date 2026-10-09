"""The runtime dependency on ``cryptography`` is declared, not inherited.

PyJWT verifies and signs EdDSA, ES256 and PS256 only through ``cryptography``,
and plain ``PyJWT`` does not install it. This SDK verifies EdDSA access, ID and
logout tokens, DPoP proofs and SSF SETs (CONTRACT §32.7), and signs CIBA
requests (§33.2), so ``cryptography`` is a runtime requirement. It used to
arrive in the development environment only through ``twine`` -> ``keyring`` ->
``SecretStorage``, which is why CI never noticed that a clean ``pip install``
could not verify a single token. Both halves are pinned here: the metadata
declares it, and the interpreter running the suite actually has it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import jwt.algorithms

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - only taken on the 3.10 floor leg
    import tomli as tomllib

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_pyjwt_is_required_with_its_crypto_extra() -> None:
    """``PyJWT[crypto]`` is a runtime dependency, not plain ``PyJWT``."""
    deps = tomllib.loads(PYPROJECT.read_text())["project"]["dependencies"]
    pyjwt = [d for d in deps if d.lower().startswith("pyjwt")]
    assert len(pyjwt) == 1, deps
    assert pyjwt[0].lower().startswith("pyjwt[crypto]"), pyjwt[0]
    assert any(d.lower().startswith("cryptography") for d in deps), deps


def test_the_installed_pyjwt_can_use_the_asymmetric_algorithms() -> None:
    """The algorithms the SDK verifies and signs with are actually available."""
    assert jwt.algorithms.has_crypto
    supported = jwt.algorithms.get_default_algorithms()
    for alg in ("EdDSA", "ES256", "PS256"):
        assert alg in supported, alg
