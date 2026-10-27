"""Provenance decision in the supervisor (05 13.1, 13.3; 04 section 3).

The tier is set where the supervisor builds: from the solc output it parsed and the runtime it
read in chain_state 0, with the candidate it recorded at fetch (not the one a step returned).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import Artifact, BuildResult, Candidate, Compiler
from soken_review.pinning.store import PinnedSource
from soken_review.worker.supervisor import _std_input_for_build
from tests.adapters.evm.test_compare import IMM, local_runtime, onchain_runtime, x2_for
from tests.worker.test_supervisor import FakeStore, _fake_candidate, _make_supervisor


def _conn() -> AsyncMock:
    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    conn_ctx.transaction = MagicMock(return_value=conn_ctx)
    return conn_ctx


async def _run_build_with(tmp_path: Path, job_id: str, onchain: bytes, *, untrusted: bool = False,
                          write_output: bool = False, chain_id: int = 1,
                          ) -> tuple[dict[str, Any], AsyncMock, Path]:
    """Run _run_build with a fake ok build; return the step provenance and the repo mock."""
    store = FakeStore()
    store.add_job(job_id, chain_id=1, address="0xabcd")
    step = store.add_step(job_id, "build", container=True, units=2, ram_mb=4096, max_attempts=1)
    sup = _make_supervisor(store, tmp_path)
    out_dir = tmp_path.parent / "work" / job_id
    out_dir.mkdir(parents=True, exist_ok=True)
    PinnedSource.from_files({"contracts/Token.sol": b"contract Token {}"}).persist(tmp_path, job_id)
    fake_cand = _fake_candidate()
    fake_cand["untrusted_inputs"] = untrusted
    (out_dir / "candidates.json").write_text(json.dumps([fake_cand]))
    (out_dir / "chain_state.json").write_text(json.dumps(
        {"chain_id": chain_id, "address": "0xabcd", "bytecode": "0x" + onchain.hex(), "block": 123}))

    loc = local_runtime()
    art = Artifact(contract="contracts/Token.sol:Token", creation="", runtime=loc.hex(),
                   immutable_refs=IMM, link_refs={}, source_map="", storage_layout=None)
    # The build returns a candidate of its own claiming trusted inputs; it must not count.
    returned = Candidate(provider="sourcify", files={}, sha256="x", language="solidity",
                         compiler=Compiler("0.8.24", "sourcify"), settings={}, std_json_input=None,
                         entry_contract="contracts/Token.sol:Token", untrusted_inputs=False)
    ok_result = BuildResult(candidate=returned, status="ok", artifacts=[art],
                            auxdata_ranges={art.contract: x2_for(loc)}, work_dir=str(out_dir / "work"))

    def fake_build(*_a: Any, **_k: Any) -> BuildResult:
        if write_output:  # what build.py writes on the host from solc stdout
            (out_dir / "work" / "out").mkdir(parents=True, exist_ok=True)
            output = {"contracts": {"contracts/Token.sol": {"Token": {"evm": {
                "bytecode": {"object": ""},
                "deployedBytecode": {"object": loc.hex(), "immutableReferences": IMM}}}}}}
            (out_dir / "work" / "out" / "output.json").write_text(json.dumps(output))
        return ok_result

    repo_mock = AsyncMock()
    mark = AsyncMock()
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.worker.supervisor._build_mod.build", side_effect=fake_build), \
         patch.object(sup, "_mark_step", new=mark), \
         patch.object(sup, "_after_build", new=AsyncMock()):
        sup._pool.connection = MagicMock(return_value=_conn())
        await sup._run_build(step.as_dict())
    return mark.call_args.kwargs["provenance"], repo_mock, out_dir


@pytest.mark.asyncio
async def test_masked_match_sets_tier_a(tmp_path: Path) -> None:
    prov, repo, out_dir = await _run_build_with(tmp_path, "job_PROV0001", onchain_runtime(hash_byte=0xBB))
    # label_reason and block were added 2026-10-27 so review_status can show the match before the report
    assert prov == {"tier": "A", "dep_match": "metadata_only", "dep_reason": None, "label_reason": None, "block": 123}
    repo.update_job_fields.assert_any_await("job_PROV0001", tier="A")
    dep = json.loads((out_dir / "deployment.json").read_text())
    assert dep["dep"]["comparison"]["immutable_ranges"] == [[10, 42]]
    assert dep["block"] == 123


@pytest.mark.asyncio
async def test_tampered_onchain_byte_is_not_tier_a(tmp_path: Path) -> None:
    bad = bytearray(onchain_runtime())
    bad[60] ^= 1
    prov, repo, _ = await _run_build_with(tmp_path, "job_PROV0002", bytes(bad))
    assert prov["tier"] == "C" and prov["dep_match"] == "mismatch"
    repo.update_job_fields.assert_any_await("job_PROV0002", tier="C")


@pytest.mark.asyncio
async def test_untrusted_flag_recorded_at_fetch_blocks_tier_a(tmp_path: Path) -> None:
    prov, repo, _ = await _run_build_with(tmp_path, "job_PROV0003", onchain_runtime(), untrusted=True)
    assert prov["tier"] == "B" and prov["dep_reason"] == "untrusted_build_inputs"
    repo.update_job_fields.assert_any_await("job_PROV0003", tier="B")


@pytest.mark.asyncio
async def test_restart_reuses_deployment_decision(tmp_path: Path) -> None:
    _, _, out_dir = await _run_build_with(tmp_path, "job_PROV0004", onchain_runtime())
    (out_dir / "build_result.json").write_text(json.dumps({"status": "ok", "work_dir": None}))
    sup = _make_supervisor(FakeStore(), tmp_path)
    repo_mock = AsyncMock()
    mark = AsyncMock()
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch.object(sup, "_mark_step", new=mark), \
         patch.object(sup, "_after_build", new=AsyncMock()):
        sup._pool.connection = MagicMock(return_value=_conn())
        await sup._run_build({"id": 99, "job_id": "job_PROV0004", "step": "build", "seq": 0})
    assert mark.call_args.kwargs["provenance"]["tier"] == "A"
    repo_mock.update_job_fields.assert_any_await("job_PROV0004", tier="A")


def test_std_input_used_only_when_sources_equal_pin(tmp_path: Path) -> None:
    std = {"language": "Solidity", "sources": {"A.sol": {"content": "contract A {}\r\n"}}, "settings": {}}
    (tmp_path / "std_input_0.json").write_text(json.dumps({"std_json_input": std}))
    assert _std_input_for_build(tmp_path, {"A.sol": "contract A {}"}) == std
    assert _std_input_for_build(tmp_path, {"A.sol": "contract B {}"}) is None
    assert _std_input_for_build(tmp_path, {"A.sol": "contract A {}", "B.sol": "x"}) is None
