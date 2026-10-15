"""Verifier bundle entrypoint and include_in_command targets are validated like files (review finding)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from soken_review.adapters.ton import fetch as f
from soken_review.adapters.ton.fetch import _bundle_files, bundle_paths_error

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ton"
BUNDLE = json.loads((FIXTURES / "usdt_master_verifier_bundle.json").read_text())
FILES, TARGETS = _bundle_files(BUNDLE["bundle"])


def test_usdt_bundle_accepted() -> None:
    assert bundle_paths_error(BUNDLE["bundle"]["entrypoint"], TARGETS, FILES, "func") is None


@pytest.mark.parametrize("entry,targets", [
    ("-o/x.fc", TARGETS),                       # option-looking entry
    ("jetton-minter.fc", [*TARGETS, "--help.fc"]),
    ("jetton-minter.fc", [*TARGETS, "sub/-x.fc"]),
    ("../jetton-minter.fc", TARGETS),            # not a safe store path
    ("./jetton-minter.fc", TARGETS),             # normalizes, so not exact
    ("jetton-minter.fc", [*TARGETS, "missing.fc"]),  # outside the file set
    ("jetton-minter.fc", [*TARGETS, "stdlib.tolk"]),  # wrong language
    ("stdlib.boc", TARGETS),
    (None, TARGETS),
    ("jetton-minter.fc", [*TARGETS, 7]),
])
def test_bad_paths_rejected(entry, targets) -> None:
    assert bundle_paths_error(entry, targets, FILES, "func")


@pytest.mark.asyncio
async def test_bad_bundle_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = json.loads(json.dumps(BUNDLE["bundle"]))
    bundle["entrypoint"] = "-x.fc"

    async def fake_bundle(client, code_hash):
        return bundle

    monkeypatch.setattr(f, "fetch_verifier_bundle", fake_bundle)
    async with httpx.AsyncClient() as client:
        assert await f.fetch_source_from_verifier(client, BUNDLE["code_hash"]) is None
        bundle["entrypoint"] = BUNDLE["bundle"]["entrypoint"]
        assert await f.fetch_source_from_verifier(client, BUNDLE["code_hash"]) is not None
