"""TRON jobs build and analyze with the TRON adapters (matrix run 2026-10-25, CRS Token).

The supervisor used to build every non-family job with adapters/evm/build.py, which only knows
binaries.soliditylang.org versions: a Tronscan field such as "tron_0.6.2_Plato_v4.2" ended
`compiler_binary_missing`, the map stayed lexical and no analyzer ran.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.pinning.store import PinnedSource
from tests.worker.test_supervisor import FakeStore, _make_supervisor
from tests.worker.test_supervisor_provenance import _conn

_TRON_CAND = {
    "provider": "tronscan", "sha256": "d" * 64, "language": "solidity",
    "compiler": {"version": "tron_0.6.2_Plato_v4.2", "version_pinned_by": "tronscan"},
    "settings": {"optimizer": {"enabled": True, "runs": 200}}, "entry_contract": "CRSToken.sol:CRSToken",
    "explorer_verified": True, "sourcify_match": None, "untrusted_inputs": False, "fetched_at": None,
}


def _setup(tmp_path: Path, job_id: str, chain: str | None) -> tuple[Any, Any, Path, AsyncMock]:
    store = FakeStore()
    store.add_job(job_id, chain_id=None, address="TRegosVaS1o3DHG85nnW8xYzczPm3xL76K")
    sup = _make_supervisor(store, tmp_path)
    out_dir = tmp_path.parent / "work" / job_id
    out_dir.mkdir(parents=True, exist_ok=True)
    PinnedSource.from_files({"CRSToken.sol": b"pragma solidity ^0.6.0;\ncontract CRSToken {}\n"}).persist(
        tmp_path, job_id)
    (out_dir / "candidates.json").write_text(json.dumps([_TRON_CAND]))
    repo = AsyncMock()
    repo.get.return_value = {"job_id": job_id, "chain": chain}
    sup._pool.connection = MagicMock(return_value=_conn())
    return store, sup, out_dir, repo


@pytest.mark.asyncio
async def test_tron_job_builds_with_build_tron(tmp_path: Path) -> None:
    store, sup, out_dir, repo = _setup(tmp_path, "job_TRON0001", "tron")
    step = store.add_step("job_TRON0001", "build", container=True, units=2, ram_mb=4096, max_attempts=1)
    cand = Candidate(provider="tronscan", files={}, sha256="d" * 64, language="solidity",
                     compiler=Compiler("tron_0.6.2_Plato_v4.2", "tronscan"), settings={},
                     std_json_input=None, entry_contract="CRSToken.sol:CRSToken")
    ok = BuildResult(candidate=cand, status="ok", nsloc=366, work_dir=str(out_dir / "work"),
                     build_notes={"compiler_kind": "upstream_solc", "compiler_used": "0.6.2+commit.bacdbe57"})
    tron = MagicMock(return_value=ok)
    evm = MagicMock(side_effect=AssertionError("evm build must not run for a TRON job"))
    mark = AsyncMock()
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.worker.supervisor._tron_build_mod.build_tron", tron), \
         patch("soken_review.worker.supervisor._build_mod.build", evm), \
         patch.object(sup, "_mark_step", new=mark), \
         patch.object(sup, "_after_build", new=AsyncMock()):
        await sup._run_build(step.as_dict())
    assert tron.call_count == 1
    built = tron.call_args.args[0]
    assert built.compiler.version == "tron_0.6.2_Plato_v4.2"      # the explorer field, untouched
    result = json.loads((out_dir / "build_result.json").read_text())
    assert result["status"] == "ok"
    assert result["compiler_kind"] == "upstream_solc"
    assert result["compiler_used"] == "0.6.2+commit.bacdbe57"
    prov = mark.call_args.kwargs["provenance"]
    assert prov["compiler_kind"] == "upstream_solc"
    assert prov["tier"] != "A"                                     # a substitute never proves the deployment


@pytest.mark.asyncio
async def test_evm_job_keeps_evm_build(tmp_path: Path) -> None:
    store, sup, _out_dir, repo = _setup(tmp_path, "job_TRON0002", "ethereum")
    step = store.add_step("job_TRON0002", "build", container=True, units=2, ram_mb=4096, max_attempts=1)
    failed = BuildResult(candidate=MagicMock(), status="failed", reason="compiler_binary_missing")
    evm = MagicMock(return_value=failed)
    tron = MagicMock(side_effect=AssertionError("tron build must not run for an EVM job"))
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.worker.supervisor._tron_build_mod.build_tron", tron), \
         patch("soken_review.worker.supervisor._build_mod.build", evm), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_resolve_provenance", new=AsyncMock(return_value={"tier": "B"})), \
         patch.object(sup, "_after_build", new=AsyncMock()):
        await sup._run_build(step.as_dict())
    assert evm.call_count == 1


@pytest.mark.asyncio
async def test_tron_job_analyzes_with_tron_analyzer(tmp_path: Path) -> None:
    store, sup, out_dir, repo = _setup(tmp_path, "job_TRON0003", "tron")
    step = store.add_step("job_TRON0003", "analyze", container=True, units=2, ram_mb=6144, max_attempts=1)
    (out_dir / "build_result.json").write_text(json.dumps({"status": "ok", "nsloc": 366}))
    (out_dir / "work_dir.txt").write_text(str(out_dir / "work"))
    lead = {"id": "LEAD-0001", "rule_id": "costly-loop"}
    tron = MagicMock(return_value=([lead], {"status": "ok"}, {}))
    evm = MagicMock(side_effect=AssertionError("evm analyzer must not run for a TRON job"))
    after = AsyncMock()
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.worker.supervisor._tron_analyze_mod.analyze", tron), \
         patch("soken_review.worker.supervisor._analyze_mod.analyze", evm), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_after_analyze", new=after):
        await sup._run_analyze(step.as_dict())
    assert tron.call_count == 1
    assert json.loads((tmp_path / "job_TRON0003" / "leads.json").read_text()) == [lead]
    assert after.call_args.kwargs["degraded"] is False
