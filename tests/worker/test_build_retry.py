"""Build step: a parse error at the chosen solc is retried once with the newest release that
satisfies every pragma; both attempts land in build_result.json and candidates.json follows the
version that built (1inch farming, held-out run 2026-10-27). Files-mode dependency failures carry
`mode: files` so the status text talks about pasted files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.pinning.store import PinnedSource
from soken_review.worker import supervisor as sup_mod
from soken_review.worker.supervisor import Supervisor, _parse_error_retry_version

from .test_supervisor import FakeStore, _make_supervisor

CUSTOM_ERRORS = "pragma solidity ^0.8.0;\ncontract Farm { error Zero(); function f() external { revert Zero(); } }\n"
BUILDS = [{"version": v, "longVersion": f"{v}+commit.{i:08d}"} for i, v in enumerate(["0.8.0", "0.8.4", "0.8.24"])]
PARSER_ERROR = "ParserError: Expected identifier but got 'error'\n --> contracts/Farm.sol:2:17"


def _candidate(version: str, pinned_by: str = "pragma_guess", provider: str = "user") -> Candidate:
    return Candidate(provider=provider, files={"contracts/Farm.sol": CUSTOM_ERRORS}, sha256="ab" * 32,
                     language="solidity", compiler=Compiler(version=version, version_pinned_by=pinned_by),
                     settings={}, std_json_input=None, entry_contract=None)


def test_retry_version_is_the_newest_satisfying_release(monkeypatch):
    monkeypatch.setattr(sup_mod._solc_select, "load_builds", lambda: BUILDS)
    assert _parse_error_retry_version(_candidate("0.8.0")) == "0.8.24+commit.00000002"
    # already the newest: nothing to retry with
    assert _parse_error_retry_version(_candidate("0.8.24+commit.00000002")) is None
    monkeypatch.setattr(sup_mod._solc_select, "load_builds", lambda: None)
    assert _parse_error_retry_version(_candidate("0.8.0")) is None


def _prepare(tmp_path: Path, job_id: str, source_kind: str, pinned_by: str) -> tuple[Supervisor, dict, Path]:
    store = FakeStore()
    store.add_job(job_id, chain_id=1, address=None)
    step = store.add_step(job_id, "build", container=True, units=2, ram_mb=4096, max_attempts=1)
    out_dir = tmp_path.parent / "work" / job_id
    out_dir.mkdir(parents=True, exist_ok=True)
    PinnedSource.from_files({"contracts/Farm.sol": CUSTOM_ERRORS.encode()}).persist(tmp_path, job_id)
    (out_dir / "candidates.json").write_text(json.dumps([{
        "provider": "user" if source_kind == "files" else "repo", "sha256": "ab" * 32, "language": "solidity",
        "compiler": {"version": "0.8.0", "version_pinned_by": pinned_by}, "settings": {}, "entry_contract": None,
    }]))
    return _make_supervisor(store, tmp_path), step.as_dict(), out_dir


def _db_mocks() -> tuple[Any, list[dict], list[dict]]:
    transitions: list[dict] = []
    completes: list[dict] = []
    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn_ctx.transaction = MagicMock(return_value=txn)
    repo = AsyncMock()

    async def _transition(job_id: str, state: str, **kw: Any) -> None:
        transitions.append({"state": state, **kw})

    async def _complete(step_id: Any, status: str, **kw: Any) -> None:
        completes.append({"status": status, **kw})

    repo.transition = _transition
    repo.complete_step = _complete
    return (conn_ctx, repo), transitions, completes


@pytest.mark.asyncio
async def test_parse_error_is_retried_with_the_newest_release_and_both_attempts_recorded(tmp_path, monkeypatch):
    job_id = "job_RETRY0001"
    sup, step, out_dir = _prepare(tmp_path, job_id, "files", "pragma_guess")
    (conn_ctx, repo), transitions, _ = _db_mocks()
    monkeypatch.setattr(sup_mod._solc_select, "load_builds", lambda: BUILDS)
    calls: list[str] = []

    def fake_build(candidate: Candidate, work_dir: Path | None = None, **_: Any) -> BuildResult:
        calls.append(candidate.compiler.version)
        if candidate.compiler.version == "0.8.0":
            return BuildResult(candidate=candidate, status="failed", nsloc=0, reason="failed", stderr_head=PARSER_ERROR)
        return BuildResult(candidate=candidate, status="ok", nsloc=3, reason=None, stderr_head=None, work_dir=str(work_dir))

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.worker.supervisor._build_mod.build", side_effect=fake_build), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value={
             "job_id": job_id, "chain": "evm", "chain_id": 1, "address": None, "source_kind": "files",
             "source_args": {}, "state": "building"})):
        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_build(step)

    assert calls == ["0.8.0", "0.8.24+commit.00000002"]
    result = json.loads((out_dir / "build_result.json").read_text())
    assert result["status"] == "ok"
    assert [a["version"] for a in result["attempts"]] == ["0.8.0", "0.8.24"]
    assert result["attempts"][0]["status"] == "failed" and "ParserError" in result["attempts"][0]["reason"]
    assert result["attempts"][1] == {"version": "0.8.24", "status": "ok", "reason": None,
                                     "version_source": sup_mod._solc_select.pinned_by_text("pragma")}
    cands = json.loads((out_dir / "candidates.json").read_text())
    assert cands[0]["compiler"] == {"version": "0.8.24+commit.00000002", "version_pinned_by": "pragma"}
    assert cands[0]["compiler_retry"] == {"from": "0.8.0", "reason": "parse_error"}
    assert any(t["state"] == "analyzing" for t in transitions)


@pytest.mark.asyncio
async def test_parse_error_without_a_better_release_keeps_the_first_result(tmp_path, monkeypatch):
    job_id = "job_RETRY0002"
    sup, step, out_dir = _prepare(tmp_path, job_id, "repo", "config")
    (conn_ctx, repo), _, _ = _db_mocks()
    monkeypatch.setattr(sup_mod._solc_select, "load_builds", lambda: [{"version": "0.8.0", "longVersion": "0.8.0+commit.0"}])
    calls: list[str] = []

    def fake_build(candidate: Candidate, work_dir: Path | None = None, **_: Any) -> BuildResult:
        calls.append(candidate.compiler.version)
        return BuildResult(candidate=candidate, status="failed", nsloc=0, reason="failed", stderr_head=PARSER_ERROR)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.worker.supervisor._build_mod.build", side_effect=fake_build), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value={
             "job_id": job_id, "chain": "evm", "chain_id": 1, "address": None, "source_kind": "repo",
             "source_args": {}, "state": "building"})):
        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_build(step)

    assert calls == ["0.8.0"]
    result = json.loads((out_dir / "build_result.json").read_text())
    assert result["status"] == "failed" and len(result["attempts"]) == 1


@pytest.mark.asyncio
async def test_files_mode_missing_import_detail_carries_mode(tmp_path):
    job_id = "job_FILESDEP1"
    sup, step, _out = _prepare(tmp_path, job_id, "files", "pragma")
    (conn_ctx, repo), transitions, _ = _db_mocks()
    missing = BuildResult(candidate=_candidate("0.8.24"), status="failed", nsloc=0,
                          reason="missing_import:@openzeppelin/contracts", stderr_head="Source not found")
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.worker.supervisor._build_mod.build", return_value=missing), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value={
             "job_id": job_id, "chain": "evm", "chain_id": 1, "address": None, "source_kind": "files",
             "source_args": {}, "state": "building"})):
        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_build(step)
    t = [x for x in transitions if x["state"] == "insufficient_source"]
    assert t and t[0]["error_code"] == "E_DEPENDENCY_UNRESOLVED"
    assert t[0]["error_detail"]["mode"] == "files" and t[0]["error_detail"]["packages"] == ["@openzeppelin/contracts"]
