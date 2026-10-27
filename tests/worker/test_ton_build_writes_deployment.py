"""The TON build step writes deployment.json next to provenance.json (matrix run 2026-10-26).

Forton reached tier A after PR #68 and the render step failed with "tier A provenance requires
deployment.json data": the assembly reads deployment.json, the TON pipeline never wrote it.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.adapters.ton.provenance import MATCH_REBUILD, Attempt, Out
from soken_review.worker import ton_pipeline

from .test_map_step_ton_starknet import _fake_sup, _FakeRepo, _write

HASH = "c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea"
RAW = "0:2f26e1259f494ff1cd98319e2c286c1046dfe49b1982e3de2ff18e134c780e6a"
FRIENDLY = "EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ"
TACT = "contract FtMaster {\n    owner: Address;\n    init(owner: Address) { self.owner = owner; }\n}\n"


@pytest.mark.asyncio
async def test_ton_build_writes_deployment_json_for_tier_a(tmp_path: Path, monkeypatch) -> None:
    repo = _FakeRepo()
    sup = _fake_sup(tmp_path, repo, monkeypatch, ton_pipeline)
    sup._after_build = AsyncMock()
    job = {"job_id": "job_TONDEP01", "chain": "ton", "address": FRIENDLY,
           "source_args": {"kind": "deployed", "chain": "ton", "address": FRIENDLY}}
    out_dir = sup._job_dir(job["job_id"])
    _write(out_dir / "chain_state.json", {"mc_seqno": 101445617, "accounts": {
        RAW: {"status": "active", "code_hash": HASH, "dep_hash": HASH, "code_boc": "b5ee9c72"}}})
    cand = Candidate(provider="ton_verifier", files={"contract/contracts/ft_master.tact": TACT}, sha256="49" * 32,
                     language="tact", compiler=Compiler("1.6.5", "ton_verifier"), settings={},
                     std_json_input=None, entry_contract="contract/contracts/ft_master.tact", explorer_verified=True)
    _write(out_dir / "candidates.json", [{"provider": "ton_verifier", "sha256": "49" * 32, "language": "tact",
                                          "compiler": {"version": "1.6.5", "version_pinned_by": "ton_verifier"},
                                          "entry_contract": cand.entry_contract, "files": list(cand.files)}])
    _write(out_dir / "cands" / "0.json", ton_pipeline._cand_to_json(cand))

    def fake_resolve(_out_dir, _cs, cands):
        out = Out(0, "exact", MATCH_REBUILD, tried=[Attempt(0, "ton_verifier", "ok", {"contract_FtMaster": HASH})],
                  matched_target="contract_FtMaster", dep_hash=HASH, build_hash=HASH)
        return out, {0: BuildResult(candidate=cands[0], status="ok", nsloc=3, work_dir=str(out_dir / "attempts" / "0"))}

    monkeypatch.setattr(ton_pipeline, "_resolve", fake_resolve)
    step = {"id": 7, "job_id": job["job_id"], "step": "build", "seq": 0}
    await ton_pipeline._build(sup, step, job)

    dep = json.loads((out_dir / "deployment.json").read_text())
    assert dep["tier"] == "A" and dep["dep"]["match"] == "exact"
    assert dep["code_hash"] == HASH and dep["block"] == 101445617 and dep["unit"] == "seqno"
    assert dep["address"] == FRIENDLY
    assert dep["candidate"]["compiler"] == "1.6.5"
    assert repo.fields["tier"] == "A"
    assert (out_dir / "provenance.json").exists()
    sup._after_build.assert_awaited_once()
