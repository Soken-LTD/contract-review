"""TRON deployed-address jobs record the runtime in chain_state.json at fetch (matrix run
2026-10-26, CRS Token): without it the build compared nothing and every TRON job was tier B
"deployment given; match not checked", whatever the rebuild produced."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import Candidate, Compiler
from soken_review.worker.supervisor import _TRON_CHAIN_ID, _tron_chain_state
from tests.worker.test_supervisor import FakeStore, _make_supervisor

ADDR = "TRegosVaS1o3DHG85nnW8xYzczPm3xL76K"
RUNTIME = "6080604052" + "ab" * 40


@pytest.mark.asyncio
async def test_tron_chain_state_document():
    with patch("soken_review.adapters.tron.rpc.TronGridClient.eth_block_number", new=AsyncMock(return_value=75_000_000)):
        cs = await _tron_chain_state(ADDR, RUNTIME)
    assert cs["chain_id"] == _TRON_CHAIN_ID == 728126428
    assert cs["address"] == ADDR and cs["bytecode"] == "0x" + RUNTIME and cs["block"] == 75_000_000
    assert cs["self_address"].startswith("0x") and len(cs["self_address"]) == 42


@pytest.mark.asyncio
async def test_tron_chain_state_block_is_optional():
    with patch("soken_review.adapters.tron.rpc.TronGridClient.eth_block_number",
               new=AsyncMock(side_effect=RuntimeError("down"))):
        cs = await _tron_chain_state(ADDR, "0x" + RUNTIME)
    assert cs["block"] is None and cs["bytecode"] == "0x" + RUNTIME


@pytest.mark.asyncio
async def test_tron_fetch_writes_chain_state_with_the_runtime(tmp_path: Path) -> None:
    store = FakeStore()
    store.add_job("job_TRONCS01", chain_id=None, address=ADDR)
    step = store.add_step("job_TRONCS01", "fetch", container=False, units=0, ram_mb=0, max_attempts=3)
    sup = _make_supervisor(store, tmp_path)
    out_dir = tmp_path.parent / "work" / "job_TRONCS01"
    out_dir.mkdir(parents=True, exist_ok=True)
    cand = Candidate(provider="tronscan", files={"CRSToken.sol": "pragma solidity ^0.6.0;\ncontract CRSToken {}\n"},
                     sha256="d" * 64, language="solidity", compiler=Compiler("tron_0.6.2_Plato_v4.2", "tronscan"),
                     settings={}, std_json_input=None, entry_contract="CRSToken.sol:CRSToken", explorer_verified=True)
    job = {"job_id": "job_TRONCS01", "chain": "tron", "chain_id": None, "address": ADDR, "source_kind": "deployed",
           "source_args": {"kind": "deployed", "chain": "tron", "address": ADDR}, "state": "fetching"}
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    repo = AsyncMock()
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.adapters.tron.fetch.fetch_source_tron", new=AsyncMock(return_value=([cand], RUNTIME, None))), \
         patch("soken_review.adapters.tron.rpc.TronGridClient.eth_block_number", new=AsyncMock(return_value=75_000_000)), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job)), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_after_fetch", new=AsyncMock()) as after_fetch:
        sup._pool.connection = MagicMock(return_value=conn)
        await sup._run_fetch(step.as_dict())
    cs = json.loads((out_dir / "chain_state.json").read_text())
    assert cs == {"chain_id": 728126428, "address": ADDR, "self_address": cs["self_address"],
                  "bytecode": "0x" + RUNTIME, "block": 75_000_000}
    assert json.loads((out_dir / "candidates.json").read_text())[0]["provider"] == "tronscan"
    after_fetch.assert_awaited_once()
