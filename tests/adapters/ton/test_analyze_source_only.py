"""TON analyzers without a build, and the Misti output contract (matrix run 2026-10-25, Forton).

Forton's verified Tact source was pinned (tier B, Tact 1.6.5 not in the image) but analyze
required a successful build, so 0 leads. Misti also never produced a lead: `--output-path` is a
directory in Misti 0.9.0 (it writes `<dir>/warnings.sarif`), while the adapter passed a file path
and read that file, which Misti had created as a directory.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.adapters.ton import analyze as ton_analyze

TACT = """contract C {
    owner: Address;
    receive(msg: Set) {
        self.owner = msg.owner;
    }
}
"""


def _cand(entry: str | None = "contracts/c.tact") -> Candidate:
    return Candidate(provider="ton_verifier", files={"contracts/a.tact": "struct A { x: Int; }\n",
                                                     "contracts/c.tact": TACT},
                     sha256="0" * 64, language="tact", compiler=Compiler("1.6.5", "ton_verifier"),
                     settings={}, std_json_input=None, entry_contract=entry)


def _sarif(results: list[dict[str, Any]]) -> bytes:
    return json.dumps({"runs": [{"tool": {"driver": {"name": "Misti"}}, "results": results}]}).encode()


def _result(rule: str, category: str, line: int = 3) -> dict[str, Any]:
    return {"ruleId": rule, "level": "warning", "properties": {"category": category},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "contracts/c.tact"},
                                                "region": {"startLine": line}}}]}


def test_misti_noise_is_dropped() -> None:
    raw = ton_analyze._parse_misti_sarif(_sarif([
        _result("ExitCodeUsage", "Security"),
        _result("SuboptimalSend", "Optimization"),
        _result("TransitiveImport", "Best Practices"),
        _result("ZeroAddress", "Best Practices", 4),
    ]))
    assert [r["rule_id"] for r in raw] == ["ExitCodeUsage", "ZeroAddress"]
    assert raw[0]["file"] == "contracts/c.tact" and raw[0]["start"] == 3


def test_misti_reads_warnings_sarif_from_the_output_dir(tmp_path: Path, monkeypatch) -> None:
    """Command passes a directory; the reader takes <dir>/warnings.sarif; project root = entry."""
    seen: dict[str, Any] = {}

    def fake_run(argv, **_k):
        seen["argv"] = argv
        out = tmp_path / "attempt.misti" / "out"
        (out / "warnings.sarif").write_bytes(_sarif([_result("ExitCodeUsage", "Security")]))
        cfg = json.loads((tmp_path / "attempt.misti" / "src" / "tact.config.json").read_text())
        seen["project"] = cfg["projects"][0]["path"]
        return MagicMock(returncode=0)

    monkeypatch.setattr(ton_analyze, "_ANALYZE_IMAGE", "ton-build@sha256:test")
    monkeypatch.setattr(ton_analyze, "_DIRECT", False)
    monkeypatch.setattr(ton_analyze.shutil, "which", lambda _n: "/usr/bin/docker")
    monkeypatch.setattr(ton_analyze, "docker_argv", lambda **kw: kw["command"])
    monkeypatch.setattr(ton_analyze, "sandbox_writable_dir", lambda p: p.mkdir(parents=True, exist_ok=True))
    with patch.object(ton_analyze.subprocess, "run", fake_run):
        raw = ton_analyze._run_misti(tmp_path / "attempt", _cand().files, "contracts/c.tact")
    assert raw is not None and [r["rule_id"] for r in raw] == ["ExitCodeUsage"]
    assert seen["argv"][-2:] == ["--output-path", "/work/out"]
    assert seen["project"] == "contracts/c.tact"          # the entry, not the first file by path


def test_failed_build_runs_rules_and_misti_on_the_sources(tmp_path: Path, monkeypatch) -> None:
    calls: dict[str, Any] = {}

    def fake_misti(work_dir, files, entry=None):
        calls["misti"] = (work_dir, sorted(files), entry)
        return [{"tool": "misti@0.9.0", "rule_id": "ExitCodeUsage", "severity_raw": "error",
                 "file": "contracts/c.tact", "start": 4, "end": 4}]

    monkeypatch.setattr(ton_analyze, "_run_misti", fake_misti)
    br = BuildResult(candidate=_cand(), status="failed", reason="unsupported_toolchain")
    leads, static_map, _ = ton_analyze.analyze(br, tmp_path / "attempts" / "source_only")
    assert calls["misti"][0] == tmp_path / "attempts" / "source_only"
    assert calls["misti"][2] == "contracts/c.tact"
    assert static_map["status"] == "ok" and static_map["build"] == "failed"
    assert static_map["analyzer"] == "misti@0.9.0"
    assert any(lead["rule_id"] == "ExitCodeUsage" for lead in leads)
    assert (tmp_path / "attempts" / "source_only.host" / "analyze" / "leads.json").exists()


def test_failed_build_without_source_dir_still_not_run() -> None:
    br = BuildResult(candidate=_cand(), status="failed", reason="unsupported_toolchain")
    leads, static_map, _ = ton_analyze.analyze(br)
    assert leads == [] and static_map == {"status": "not_run", "reason": "build_failed"}


@pytest.mark.asyncio
async def test_pipeline_analyze_uses_sources_when_build_failed(tmp_path: Path) -> None:
    from dataclasses import asdict

    from soken_review.worker import ton_pipeline

    out_dir = tmp_path / "work" / "job_TON00001"
    (out_dir / "cands").mkdir(parents=True)
    cand = _cand()
    (out_dir / "cands" / "0.json").write_text(json.dumps({**asdict(cand), "compiler": asdict(cand.compiler)}))
    (out_dir / "build_result.json").write_text(json.dumps(
        {"status": "failed", "nsloc": 5, "reason": "unsupported_toolchain", "stderr_head": "tact 1.6.5 is not in the image",
         "work_dir": None, "src": 0}))
    sup = MagicMock()
    sup._pin_root = tmp_path / "pins"
    sup._job_dir = lambda job_id: tmp_path / "work" / job_id
    sup._mark_step = AsyncMock()
    sup._after_analyze = AsyncMock()
    lead = {"id": "LEAD-0001", "rule_id": "TON-AUTH-02"}
    fake = MagicMock(return_value=([lead], {"status": "ok", "build": "failed"}, {}))
    with patch.object(ton_pipeline._analyze_mod, "analyze", fake):
        await ton_pipeline._analyze(sup, {"id": 7, "job_id": "job_TON00001", "step": "analyze"},
                                    {"job_id": "job_TON00001"})
    br, source_dir = fake.call_args.args
    assert br.status == "failed" and source_dir == out_dir / "attempts" / "source_only"
    assert json.loads((sup._pin_root / "job_TON00001" / "leads.json").read_text()) == [lead]
    assert sup._after_analyze.call_args.kwargs["degraded"] is False
    assert json.loads((out_dir / "static_map.json").read_text())["build"] == "failed"
