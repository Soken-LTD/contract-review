"""Build step scope retry (Lambo.win run 2026-10-27): a repo build that fails on a vendored,
unused file is retried with the closure of the deployable contracts, then without the failing
file; every attempt is recorded in build_result.json, the excluded file is out of scope in the
pin and listed in candidates.json scope_excluded (reason build_excluded)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.pinning.store import PinnedSource
from soken_review.worker import supervisor as sup_mod
from tests.adapters.evm.test_build_scope import LAMBO_TREE, REMAPS, SCOPE

from .test_build_retry import _db_mocks
from .test_supervisor import FakeStore, _make_supervisor

BUILDS = [{"version": v, "longVersion": f"{v}+commit.0000000{i}"} for i, v in enumerate(["0.8.23", "0.8.24", "0.8.28"])]
VENDORED = "src/libraries/1inchV6.sol"
PARSER_ERROR = ("ParserError: Source file requires different compiler version (current compiler is "
                "0.8.28+commit.00000002) - note that nightly builds are considered to be strictly less")


def _prepare(tmp_path: Path, job_id: str, tree: dict[str, str]) -> tuple[Any, dict, Path, Path]:
    store = FakeStore()
    store.add_job(job_id, chain_id=1, address=None)
    step = store.add_step(job_id, "build", container=True, units=2, ram_mb=4096, max_attempts=1)
    pin_root = tmp_path / "pins"
    out_dir = pin_root.parent / "work" / job_id
    src = out_dir / "repo_fetch" / "src"
    for path, text in tree.items():
        (src / path).parent.mkdir(parents=True, exist_ok=True)
        (src / path).write_text(text)
    scope = {p: t for p, t in tree.items() if p.startswith("src/")}
    PinnedSource.from_files({p: t.encode() for p, t in scope.items()}).persist(pin_root, job_id)
    (out_dir / "candidates.json").write_text(json.dumps([{
        "provider": "repo", "sha256": "ab" * 32, "language": "solidity",
        "compiler": {"version": "0.8.28+commit.00000002", "version_pinned_by": "pragma_partial"},
        "settings": {"remappings": REMAPS, "viaIR": True}, "entry_contract": None, "scope_excluded": [],
    }]))
    return _make_supervisor(store, pin_root), step.as_dict(), out_dir, pin_root


async def _run(sup: Any, step: dict, job_id: str, fake_build: Any) -> tuple[list[dict], list[dict]]:
    (conn_ctx, repo), transitions, _ = _db_mocks()
    fields: list[dict] = []

    async def _update(_job_id: str, **kw: Any) -> None:
        fields.append(kw)

    repo.update_job_fields = _update
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.worker.supervisor._build_mod.build", side_effect=fake_build), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value={
             "job_id": job_id, "chain": "evm", "chain_id": 1, "address": None, "source_kind": "repo",
             "source_args": {}, "state": "building"})):
        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_build(step)
    return transitions, fields


@pytest.mark.asyncio
async def test_unused_vendored_file_is_left_out_and_the_reviewed_contracts_build(tmp_path, monkeypatch):
    job_id = "job_LAMBO0001"
    sup, step, out_dir, pin_root = _prepare(tmp_path, job_id, LAMBO_TREE)
    monkeypatch.setattr(sup_mod._solc_select, "load_builds", lambda: BUILDS)
    calls: list[tuple[set[str], str, list[str] | None]] = []

    def fake_build(candidate: Candidate, work_dir: Path | None = None, **_: Any) -> BuildResult:
        calls.append((set(candidate.files), candidate.compiler.version, candidate.build_paths))
        if VENDORED in candidate.files:
            return BuildResult(candidate=candidate, status="failed", nsloc=0, reason="failed",
                               stderr_head=PARSER_ERROR, build_notes={"error_sources": [VENDORED]})
        return BuildResult(candidate=candidate, status="ok", nsloc=9, reason=None, stderr_head=None,
                           work_dir=str(work_dir))

    transitions, fields = await _run(sup, step, job_id, fake_build)

    # full scope, then the closure (unused Curve interface gone), then the closure minus 1inchV6
    assert [len(c[0]) for c in calls] == [len(SCOPE), len(SCOPE) - 1, len(SCOPE) - 2]
    assert calls[0][2] is None and calls[2][2] == sorted(calls[2][0])
    assert VENDORED not in calls[2][0] and "src/LamboFactory.sol" in calls[2][0]
    result = json.loads((out_dir / "build_result.json").read_text())
    assert result["status"] == "ok"
    assert [a.get("scope") for a in result["attempts"]] == [None, "closure", "exclude"]
    assert [a["status"] for a in result["attempts"]] == ["failed", "failed", "ok"]
    assert result["attempts"][2]["excluded"] == [VENDORED]
    assert result["attempts"][2]["version_source"] == sup_mod._solc_select.pinned_by_text("pragma")
    # nSLOC of the reviewed files (the excluded one no longer counts)
    pin = PinnedSource.load(pin_root, job_id)
    assert not pin.get_entry(VENDORED).in_scope and pin.has_path(VENDORED)
    assert pin.get_entry("src/interfaces/Curve/IStableNGPool.sol").in_scope
    assert result["nsloc"] == sup_mod._build_mod._count_nsloc(
        {p: "\n".join(pin.read_all(p)) for p, e in pin.entries.items() if e.in_scope})
    assert {"source_pin": pin.source_pin} in fields
    cands = json.loads((out_dir / "candidates.json").read_text())
    assert cands[0]["scope_excluded"] == [{"path": VENDORED, "reason": "build_excluded"}]
    assert cands[0]["compiler"]["version_pinned_by"] == "pragma"
    assert cands[0]["build_scope"] == {"files": len(SCOPE) - 2, "excluded": 1}
    assert any(t["state"] == "analyzing" for t in transitions)


@pytest.mark.asyncio
async def test_a_failing_file_a_reviewed_contract_imports_keeps_the_build_failed(tmp_path, monkeypatch):
    job_id = "job_LAMBO0002"
    tree = dict(LAMBO_TREE)
    tree["src/LamboToken.sol"] = tree["src/LamboToken.sol"].replace(
        "contract LamboToken", 'import "./libraries/1inchV6.sol";\ncontract LamboToken')
    sup, step, out_dir, pin_root = _prepare(tmp_path, job_id, tree)
    monkeypatch.setattr(sup_mod._solc_select, "load_builds", lambda: BUILDS)
    calls: list[int] = []

    def fake_build(candidate: Candidate, work_dir: Path | None = None, **_: Any) -> BuildResult:
        calls.append(len(candidate.files))
        return BuildResult(candidate=candidate, status="failed", nsloc=0, reason="failed",
                           stderr_head=PARSER_ERROR, build_notes={"error_sources": [VENDORED]})

    _, fields = await _run(sup, step, job_id, fake_build)
    assert len(calls) == 2                       # full, closure; no exclusion
    result = json.loads((out_dir / "build_result.json").read_text())
    assert result["status"] == "failed" and len(result["attempts"]) == 2
    assert PinnedSource.load(pin_root, job_id).get_entry(VENDORED).in_scope
    assert not [f for f in fields if "source_pin" in f]
    assert json.loads((out_dir / "candidates.json").read_text())[0]["scope_excluded"] == []


@pytest.mark.asyncio
async def test_a_missing_compiler_is_not_retried_with_a_narrower_scope(tmp_path, monkeypatch):
    job_id = "job_LAMBO0003"
    sup, step, out_dir, _ = _prepare(tmp_path, job_id, LAMBO_TREE)
    monkeypatch.setattr(sup_mod._solc_select, "load_builds", lambda: BUILDS)
    calls: list[int] = []

    def fake_build(candidate: Candidate, work_dir: Path | None = None, **_: Any) -> BuildResult:
        calls.append(len(candidate.files))
        return BuildResult(candidate=candidate, status="failed", nsloc=0, reason="compiler_binary_missing")

    await _run(sup, step, job_id, fake_build)
    assert calls == [len(SCOPE)]
    assert len(json.loads((out_dir / "build_result.json").read_text())["attempts"]) == 1
