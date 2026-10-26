"""Tact multi-version rebuild hash proof (plan v4 06 4.2, 2026-10-25).

Proves that building the FtSquad fixture sources (EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ)
with Tact 1.6.5 and options {debug: false} inside the ton-build image reproduces the exact
code hash recorded by the TON verifier:
  c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea

Fixture sources: tests/fixtures/ton/ftsquad/ (extracted from verifier_FtSquad.pkg).
Compile settings: tests/fixtures/ton/ftsquad/compile_settings.json.

Requires:
  SOKEN_IMAGE_TON_BUILD — ton-build image tag (e.g. soken/ton-build:ci or ghcr.io/soken-ltd/ton-build@sha256:...)
  SOKEN_SANDBOX_RUNTIME — runc (or gvisor)

Skipped unless both env vars are set (same gate as test_e2e_ton.py).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

_needs_image = pytest.mark.skipif(
    not os.environ.get("SOKEN_IMAGE_TON_BUILD"),
    reason="SOKEN_IMAGE_TON_BUILD not set — skipping docker-required rebuild hash test",
)

_FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "ton" / "ftsquad"
_SETTINGS_FILE = _FIXTURE_DIR / "compile_settings.json"
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SBX_ROOT = _REPO_ROOT / ".sbx"

KNOWN_CONTRACT_ADDRESS = "EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ"
EXPECTED_CODE_HASH = "c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea"
TACT_VERSION = "1.6.5"


def _read_fixture_sources() -> dict[str, str]:
    """Read all .tact source files from the fixture directory."""
    sources: dict[str, str] = {}
    base = _FIXTURE_DIR
    for path in sorted(base.rglob("*.tact")):
        rel = path.relative_to(base).as_posix()
        sources[rel] = path.read_text(encoding="utf-8")
    return sources


def test_fixture_sources_present() -> None:
    """Fixture directory must exist and contain the expected source files (no docker needed)."""
    assert _FIXTURE_DIR.exists(), f"Fixture dir missing: {_FIXTURE_DIR}"
    assert _SETTINGS_FILE.exists(), f"Fixture settings missing: {_SETTINGS_FILE}"
    sources = _read_fixture_sources()
    assert "contract/contracts/ft_master.tact" in sources, "ft_master.tact not in fixtures"
    assert "contract/contracts/messages.tact" in sources, "messages.tact not in fixtures"
    assert len(sources) >= 9, f"Expected >= 9 source files, got {len(sources)}"


@_needs_image
def test_rebuild_hash_tact_1_6_5() -> None:
    """Rebuild FtSquad with Tact 1.6.5 inside the sandbox; code hash must match the registry."""
    import sys
    sys.path.insert(0, str(_REPO_ROOT / "src"))

    from soken_review.adapters.base import Candidate, Compiler
    from soken_review.adapters.ton.build import build

    settings = json.loads(_SETTINGS_FILE.read_text())
    sources = _read_fixture_sources()

    assert settings["version"] == TACT_VERSION, (
        f"Fixture compiler version {settings['version']} != expected {TACT_VERSION}"
    )
    assert settings["expected_hash"] == EXPECTED_CODE_HASH

    entrypoint = settings["entrypoint"]  # "contract/contracts/ft_master.tact"
    options = settings.get("options", {})

    # Build a Candidate from the fixture sources
    candidate = Candidate(
        provider="ton_verifier",
        files=sources,
        sha256="0" * 64,
        language="tact",
        compiler=Compiler(version=TACT_VERSION, version_pinned_by="ton_verifier"),
        settings={
            "entry": entrypoint,
            "verifier": {
                "compiler": {
                    "language": "tact",
                    "version": TACT_VERSION,
                    "params": {"options": options},
                }
            },
        },
        std_json_input=None,
        entry_contract=None,
    )

    _SBX_ROOT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=_SBX_ROOT) as tmp:
        result = build(candidate, Path(tmp) / "attempt")

    assert result.status == "ok", (
        f"Build failed: reason={result.reason} stderr={result.stderr_head}"
    )
    assert result.artifacts, "No artifacts produced"

    # Find the FtMaster artifact (the main contract in ft_master.tact)
    hashes = {a.contract: a.runtime for a in result.artifacts}
    print(f"Produced artifacts: {hashes}")

    # The deployed contract EQAvJuEln0lP... has code hash c845917d...; Tact names the output
    # <project>_<Contract>.code.boc, so the FtMaster target is the one ending in FtMaster.
    ftmaster = [name for name in hashes if name == "FtMaster" or name.endswith("_FtMaster")]
    assert ftmaster, f"FtMaster artifact not found in build output. Got: {list(hashes.keys())}"
    ftmaster_hash = hashes[ftmaster[0]]
    assert ftmaster_hash == EXPECTED_CODE_HASH, (
        f"Code hash mismatch for FtMaster (Tact {TACT_VERSION}):\n"
        f"  Got:      {ftmaster_hash}\n"
        f"  Expected: {EXPECTED_CODE_HASH}\n"
        f"  Contract: {KNOWN_CONTRACT_ADDRESS}"
    )
    print(
        f"PASS: FtMaster (Tact {TACT_VERSION}) code hash = {ftmaster_hash} "
        f"[matches {KNOWN_CONTRACT_ADDRESS}]"
    )
