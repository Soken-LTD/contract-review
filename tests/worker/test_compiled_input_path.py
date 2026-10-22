"""`_compiled_input_path`: the map step must read the bytes solc compiled, not the fetched copy."""

from __future__ import annotations

import json
from pathlib import Path

from soken_review.adapters.evm.build import host_build_dir
from soken_review.worker.supervisor import _compiled_input_path


def _ok(work_dir: Path, std_json: bool = True) -> dict:
    return {"status": "ok", "work_dir": str(work_dir), "std_json": std_json, "output_sha256": "x"}


def test_prefers_the_host_build_copy(tmp_path: Path):
    out_dir = tmp_path / "out"
    work = tmp_path / "work"
    host = host_build_dir(work)
    host.mkdir(parents=True)
    (host / "input.json").write_text(json.dumps({"sources": {"A.sol": {"content": "a\r\n"}}}))
    out_dir.mkdir()
    (out_dir / "std_input_0.json").write_text(json.dumps({"std_json_input": {"sources": {}}}))
    assert _compiled_input_path(out_dir, _ok(work)) == host / "input.json"


def test_falls_back_to_fetched_std_input_only_when_the_build_used_it(tmp_path: Path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "std_input_0.json").write_text(json.dumps({"std_json_input": {"sources": {}}}))
    work = tmp_path / "work"  # no host copy
    assert _compiled_input_path(out_dir, _ok(work, std_json=True)) == out_dir / "std_input_0.json"
    assert _compiled_input_path(out_dir, _ok(work, std_json=False)) is None


def test_failed_build_has_no_compiled_input(tmp_path: Path):
    work = tmp_path / "work"
    host = host_build_dir(work)
    host.mkdir(parents=True)
    (host / "input.json").write_text("{}")
    assert _compiled_input_path(tmp_path, {"status": "failed", "work_dir": str(work)}) is None
