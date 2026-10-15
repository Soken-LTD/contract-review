"""tact.config.json: Tact 1.6.13 schema allowlist; documented options reach the compiler and are
recorded, anything else blocks tier A and is not passed (review findings)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.adapters.base import Candidate
from soken_review.adapters.ton import build as b
from soken_review.adapters.ton.provenance import Attempt, Out
from soken_review.adapters.ton.trust_scan import scan_files

JETTON_OPTIONS = {"external": False, "debug": False, "ipfsAbiGetter": False, "interfacesGetter": False,
                  "experimental": {"inline": False}, "safety": {"nullChecks": True},
                  "optimizations": {"alwaysSaveContractData": False,
                                    "internalExternalReceiversOutsideMethodsMap": True},
                  "enableLazyDeploymentCompletedGetter": False}


def _compiled_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, src_cfg: dict) -> tuple[dict, Candidate]:
    work = tmp_path / "attempt"
    (work / "src" / "contracts").mkdir(parents=True)
    (work / "src" / "tact.config.json").write_text(json.dumps(src_cfg))
    seen: dict = {}

    def fake_run(script: str, args: list[str], work_dir: Path, timeout: int) -> tuple[str, int]:
        seen.update(json.loads((work_dir / "tact.config.json").read_text()))
        return "stop", 1

    monkeypatch.setattr(b, "_run", fake_run)
    cand = Candidate(provider="user", files={}, sha256="0" * 64, language="tact", compiler=None,
                     settings={}, std_json_input=None, entry_contract=None)
    b._build_tact(cand, "1.6.13", work)
    return seen, cand


def test_documented_options_and_mode_pass_through(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = {"$schema": "https://x", "projects": [{"name": "Jetton", "path": "./contracts/main.tact",
                                                  "output": "./src/output", "mode": "full",
                                                  "options": JETTON_OPTIONS, "verbose": 1}]}
    seen, cand = _compiled_config(tmp_path, monkeypatch, src)
    assert seen == {"projects": [{"name": "Jetton", "path": "src/contracts/main.tact", "output": "./out",
                                  "options": JETTON_OPTIONS, "mode": "full"}]}
    assert cand.settings["tact_build_config"] == seen
    assert scan_files({"tact.config.json": json.dumps(src)}) == []


def test_invalid_config_compiles_from_name_and_path_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = {"projects": [{"name": "Jetton; rm", "path": "./contracts/main.tact", "output": "/etc",
                         "options": {"debug": True, "unknownFlag": True}, "mode": "x"}]}
    seen, _ = _compiled_config(tmp_path, monkeypatch, src)
    assert seen == {"projects": [{"name": "p0", "path": "src/contracts/main.tact", "output": "./out"}]}


@pytest.mark.parametrize("cfg", [
    {"projects": [{"name": "c", "path": "./src/main.tact", "output": "./o", "options": {"unknownFlag": True}}]},
    {"projects": [{"name": "c", "path": "./src/main.tact", "output": "./o", "options": {"experimental": {"newThing": True}}}]},
    {"projects": [{"name": "c", "path": "./src/main.tact", "output": "./o", "options": {"debug": "yes"}}]},
    {"projects": [{"name": "c", "path": "./src/main.tact", "output": "./o", "options": {"safety": True}}]},
    {"projects": [{"name": "c", "path": "./src/main.tact", "output": "./o", "mode": "fast"}]},
    {"projects": [{"name": "c", "path": "./src/main.tact", "output": "./o", "masterchain": True}]},
    {"projects": [{"name": "c", "path": "./src/main.tact", "output": "./o"}], "extra": 1},
])
def test_outside_schema_untrusted(cfg: dict) -> None:
    assert scan_files({"tact.config.json": json.dumps(cfg)})


def test_jsonc_data_file_skipped() -> None:
    # tact-lang/jetton cspell.json: JSONC with a `// ... Fift-asm` comment before a string
    cspell = '{\n "ignoreRegExpList": [\n  "x", // binary literals in Fift-asm\n  "\\\\b0[xX]"\n ]\n}\n'
    assert scan_files({"cspell.json": cspell}) == []
    assert scan_files({"notes.txt": 'cell f() asm "1 u, PUSHREF";'})   # not JSON: still scanned


def test_options_recorded_in_provenance_checks() -> None:
    cfg = {"projects": [{"name": "Jetton", "path": "src/a.tact", "output": "./out", "options": {"debug": False}}]}
    out = Out(0, "exact", "MATCH_REBUILD", tried=[Attempt(0, "repo", "ok", {"Jetton_Minter": "a" * 64}, build_config=cfg)])
    doc = out.to_json()
    assert doc["checks"] == [{"check": "tact_config", "value": cfg}]
    assert doc["tried"][0]["build_config"] == cfg
