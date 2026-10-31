"""review_contract_map, review_facts and detailed read markers over the stored map step output (03 4.4, 4.6, 4.8)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from mcp import Client

import soken_review.tools  # noqa: F401
from soken_review.mapping.facts import fact, load_facts, write_facts
from soken_review.mapping.step import run_map_step
from soken_review.pinning.store import PinnedSource
from soken_review.server import SokenServer
from soken_review.tools.context import MemoryJobContext
from soken_review.tools.read import set_context

pytestmark = pytest.mark.anyio
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map"
JOB = "job_BBBBBBBBBBBBBBBBBBBBBBBBBB"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    ctx = MemoryJobContext(tmp_path)
    ctx.set_state(JOB, "ready")
    set_context(ctx)
    PinnedSource.from_files({"src/Vault.sol": (FIX / "Vault.sol").read_bytes()}).persist(tmp_path, JOB)
    work = tmp_path / "work" / "out"
    work.mkdir(parents=True)
    shutil.copy(FIX / "vault_solc_output.json", work / "output.json")
    run_map_step(
        tmp_path, JOB, solc_output_path=work / "output.json", build_ok=True,
        job={"chain_id": 8453, "address": "0x" + "11" * 20},
        chain_state={"block": 100, "address": "0x" + "11" * 20, "bytecode": "0x6001"},
        candidate={"provider": "sourcify", "compiler": {"version": "0.8.26+commit.8a97fa7a"}},
        nsloc=42, analyzers={"slither": "0.11.6"},
    )
    facts = load_facts(tmp_path, JOB) or []
    facts.append(fact("onchain.balance", 5 * 10**18, unit="wei", unit_id="src/Vault.sol:Vault",
                      source="eth_getBalance at block 100"))
    write_facts(tmp_path, JOB, facts)
    return tmp_path


async def _call(tool: str, args: dict) -> str:
    async with Client(SokenServer()) as c:
        r = await c.call_tool(tool, args)
    assert not r.is_error, r.content[0].text
    return r.content[0].text


async def test_contract_map_concise(root: Path):
    text = await _call("review_contract_map", {"job_id": JOB, "contract": "Vault"})
    lines = text.splitlines()
    assert lines[0] == "contract map full, units 1, page 1"
    assert lines[1] == "unit src/Vault.sol:Vault contract src/Vault.sol:18-58"
    assert lines[2].startswith("  entries 4: ")
    assert "setFee(uint256)" in lines[2] and "withdraw(uint256)" in lines[2]
    assert "onlyOwner holder unknown gates 1" in text
    assert "external address.call at src/Vault.sol:46" in text
    assert "value_transfer address.transfer at src/Vault.sol:52" in text
    assert "feeBps by setFee" in text
    assert lines[-2] == "  upgrade authority: none in code"
    assert lines[-1] == "end"


async def test_contract_map_detailed(root: Path):
    text = await _call("review_contract_map", {"job_id": JOB, "response_format": "detailed", "page_size": 1})
    # abstract Owned is not a deployable unit; its functions show as inherited entries of Vault
    assert text.splitlines()[0] == "contract map full, units 1, page 1"
    assert "  entry Vault.setFee(uint256) external src/Vault.sol:36-38" in text
    assert "    guards: caller_check src/Vault.sol:14" in text
    assert "    calls: external address.call src/Vault.sol:46" in text
    assert text.endswith("end")


async def test_contract_map_lexical_only(root: Path):
    run_map_step(root, JOB, solc_output_path=None, build_ok=False, build_detail="ParserError: Expected ';'")
    text = await _call("review_contract_map", {"job_id": JOB})
    lines = text.splitlines()
    assert lines[0] == "Contract map unavailable"
    assert lines[1] == "build failed: ParserError"     # class only, never compiler text quoting source
    assert lines[2] == "map_status failed; lexical layer only"
    assert "setFee 36-38" in lines[3]


async def test_facts_listing_and_filter(root: Path):
    text = await _call("review_facts", {"job_id": JOB})
    lines = text.splitlines()
    assert lines[0].startswith("facts ")
    keys = [ln.split()[0] for ln in lines[1:-1]]
    assert keys == sorted(keys)
    assert "chain.block 100 block eth_blockNumber at pin, minus one" in lines
    assert "onchain.balance 5000000000000000000 wei eth_getBalance at block 100" in lines
    assert any(ln.startswith("deploy.code_hash 0x") for ln in lines)
    assert "compiler.version 0.8.26 - source candidate (sourcify)" in lines
    only = await _call("review_facts", {"job_id": JOB, "filter": "onchain."})
    assert only.splitlines()[0] == "facts 1 of 1"


async def test_facts_paging(root: Path):
    first = await _call("review_facts", {"job_id": JOB, "page_size": 2})
    assert first.splitlines()[0].startswith("facts 2 of ")
    cursor = first.splitlines()[-1].split()[1]
    second = await _call("review_facts", {"job_id": JOB, "page_size": 2, "cursor": cursor})
    assert second.splitlines()[1] != first.splitlines()[1]


async def test_read_code_detailed_markers(root: Path):
    text = await _call("review_read_code", {"job_id": JOB, "path": "src/Vault.sol", "start_line": 44,
                                            "end_line": 53, "response_format": "detailed"})
    tail = text.split("```")[-1].strip().splitlines()
    assert tail[0] == "flags none"
    assert tail[1] == "map markers"
    assert "src/Vault.sol:45 write balances" in tail
    assert "src/Vault.sol:46 call external address.call" in tail
    assert "src/Vault.sol:52 call value_transfer address.transfer" in tail


async def test_map_artifacts_on_disk(root: Path):
    doc = json.loads((root / JOB / "map" / "map.json").read_text())
    assert [u["id"] for u in doc["semantic"]["units"]] == ["src/Vault.sol:Vault"]
    assert json.loads((root / JOB / "flags.json").read_text()) == []


async def test_contract_map_served_while_analyzing_when_map_full(root: Path):
    """r5 2026-10-31: status showed map_status full in state analyzing, the map answered
    E_JOB_NOT_READY. The map is served once written, with the state named."""
    from soken_review.tools import read as read_mod
    read_mod._get_ctx().set_state(JOB, "analyzing")
    text = await _call("review_contract_map", {"job_id": JOB, "contract": "Vault"})
    first = text.splitlines()[0]
    assert first.startswith("contract map full, units 1, page 1")
    assert "job still analyzing" in first


async def test_contract_map_not_ready_without_map(tmp_path: Path):
    ctx = MemoryJobContext(tmp_path)
    ctx.set_state(JOB, "building")
    set_context(ctx)
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_contract_map", {"job_id": JOB})
    assert "E_JOB_NOT_READY" in r.content[0].text
