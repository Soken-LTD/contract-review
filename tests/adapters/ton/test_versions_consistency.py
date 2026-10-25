"""Versions consistency gate: docker/ton-build/versions.json must mirror build.py constants.

This test runs in the standard CI suite (no docker required) and catches any drift between
the JSON source of truth and the Python frozensets. A mismatch means the image and the
code disagree on what versions are supported, which would cause silent unsupported_toolchain
errors or accept a version the image cannot serve.
"""

from __future__ import annotations

import json
from pathlib import Path

from soken_review.adapters.ton.build import FUNC_VERSIONS, TACT_VERSIONS, TOLK_VERSIONS

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_JSON = _REPO_ROOT / "docker" / "ton-build" / "versions.json"


def _load_versions() -> dict:
    return json.loads(_VERSIONS_JSON.read_text())


def test_versions_json_exists() -> None:
    assert _VERSIONS_JSON.exists(), f"versions.json not found at {_VERSIONS_JSON}"


def test_tact_versions_match() -> None:
    v = _load_versions()
    json_set = set(v["tact"])
    assert json_set == TACT_VERSIONS, (
        f"TACT_VERSIONS mismatch.\n"
        f"  In JSON only: {sorted(json_set - TACT_VERSIONS)}\n"
        f"  In build.py only: {sorted(TACT_VERSIONS - json_set)}"
    )


def test_func_versions_match() -> None:
    v = _load_versions()
    json_set = set(v["func"])
    assert json_set == FUNC_VERSIONS, (
        f"FUNC_VERSIONS mismatch.\n"
        f"  In JSON only: {sorted(json_set - FUNC_VERSIONS)}\n"
        f"  In build.py only: {sorted(FUNC_VERSIONS - json_set)}"
    )


def test_tolk_versions_match() -> None:
    v = _load_versions()
    json_set = set(v["tolk"])
    assert json_set == TOLK_VERSIONS, (
        f"TOLK_VERSIONS mismatch.\n"
        f"  In JSON only: {sorted(json_set - TOLK_VERSIONS)}\n"
        f"  In build.py only: {sorted(TOLK_VERSIONS - json_set)}"
    )


def test_default_versions_are_installed() -> None:
    """Default versions used when a request carries no explicit version must be in the sets."""
    assert "1.6.13" in TACT_VERSIONS, "default tact 1.6.13 not in TACT_VERSIONS"
    assert "0.12.0" in TOLK_VERSIONS, "default tolk 0.12.0 not in TOLK_VERSIONS"
    assert "latest" in FUNC_VERSIONS, "default func 'latest' not in FUNC_VERSIONS"


def test_fixture_version_is_installed() -> None:
    """Tact 1.6.5 (used by the FtSquad fixture, EQAvJuEln0lP...) must be in TACT_VERSIONS."""
    assert "1.6.5" in TACT_VERSIONS, (
        "Tact 1.6.5 not in TACT_VERSIONS — cannot rebuild FtSquad fixture "
        "(EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ)"
    )
