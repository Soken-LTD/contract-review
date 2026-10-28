"""A finding that cites chain facts renders with their block (chain access P1; Thena round 4).

The chain facts are the real Thena reads recorded from the free BSC pool (tests/chain), stored
through write_chain_facts exactly as the tool does. The report prints the value with
"(BNB Smart Chain Mainnet, block 130,229,517)" on first use and a Figures used row naming the read
and its block. With SOKEN_PROOF_OUT set, report.json is copied there so the real soken-render
image can turn it into a PDF (scripts/render_sandbox_check.py).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from psycopg.types.json import Jsonb

from soken_review.chain import reads
from soken_review.chain.endpoints import Health
from soken_review.chain.facts import write_chain_facts
from soken_review.chain.proxy import ChainProxy
from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.pinning.store import PinnedSource
from soken_review.report import render
from soken_review.report.assemble import chain_figures, report_facts
from soken_review.report.render import RenderOutcome
from soken_review.tools import report as report_tool
from tests.chain.replay import Replay

from .test_render_flow import PDF

ASYNC = pytest.mark.asyncio(loop_scope="session")
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "chain"
META = json.loads((FIX / "thena_bsc.meta.json").read_text())
VE = "0xfBBF371C9B0B994EebFcC977CEf603F7f31c070D"
THE = "0xf4c8e32eadec4bfe97e0f595add0f4450a863a11"
AT = f"(BNB Smart Chain Mainnet, block {META['block']:,})"

# VotingEscrow excerpt (ThenafiBNB/THENA-Contracts@52d42ca, contracts/VotingEscrow.sol), lines kept
# short; the finding quotes the merge path that adds the merged amount to supply a second time.
CODE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;

contract VotingEscrow {
    uint public supply;
    function merge(uint _from, uint _to) external {
        uint value0 = uint(int256(locked[_from].amount));
        locked[_from] = LockedBalance(0, 0);
        _burn(_from);
        _deposit_for(_to, value0, 0, locked[_to], DepositType.MERGE_TYPE);
    }
    function _deposit_for(uint _tokenId, uint _value, uint unlock_time, LockedBalance memory locked_balance, DepositType deposit_type) internal {
        uint supply_before = supply;
        supply = supply_before + _value;
    }
}
"""

DESCRIPTION = ("merge zeroes the source lock and then calls _deposit_for, which adds the merged amount to supply "
               "again. On chain supply() is {{fact:chain.ve.supply}} while the escrow holds "
               "{{fact:chain.the.balance.ve}} of {{fact:chain.the.symbol}}, so the recorded lock total is more than "
               "twice the tokens locked. A past supply query reverts: getPastTotalSupply answers "
               "{{fact:chain.ve.get_past_total_supply.revert_reason}}.")


async def _chain_facts() -> list[dict]:
    Health.reset()
    job = reads.ChainJob("job_x", "evm", 56, "BNB Smart Chain Mainnet", None, VE)
    replay = Replay(FIX / "thena_bsc.json")   # the batch must match the recording (one Multicall3 call)
    async with ChainProxy(transport=replay, pace=False) as px:
        at = await reads.evm_resolve(px, job, "latest")
        out = reads.Out(job=job, at=at)
        await reads.evm_read(px, out, [
            {"alias": "ve", "address": VE, "kind": "call", "fn": "supply()", "returns": "uint256"},
            {"alias": "ve", "address": VE, "kind": "call", "fn": "token()", "returns": "address"},
            {"alias": "ve", "address": VE, "kind": "call", "fn": "getPastTotalSupply(uint256)",
             "args": [META["past_ts"]], "returns": "uint256"}])
        await reads.evm_balances(px, out, THE, "the", [{"alias": "ve", "address": VE}])
    assert not replay.missing
    return out.facts


def test_chain_figures_and_block_labels_from_records():
    import asyncio

    facts = asyncio.run(_chain_facts())
    printable = report_facts(facts)
    assert printable["chain.ve.supply"]["at"] == AT[1:-1]
    assert printable["chain.the.symbol"]["literal"] is True
    figs = chain_figures({"body": {"description": [{"p": DESCRIPTION}]}}, facts, printable)
    keys = [f["operands"][0]["source"]["fact"] for f in figs]
    assert keys == ["chain.ve.supply", "chain.the.balance.ve", "chain.the.symbol",
                    "chain.ve.get_past_total_supply.revert_reason"]
    assert all(f["operands"][0]["source"]["block_or_slot"] == META["block"] for f in figs)


async def _job(db_pool, tmp_path: Path) -> str:
    jid = new_job_id()
    pin_root = tmp_path / "pins"
    pin = PinnedSource.from_files({"contracts/VotingEscrow.sol": CODE.encode()},
                                  langs={"contracts/VotingEscrow.sol": "solidity"})
    pin.persist(pin_root, jid)
    (pin_root / jid / "leads.json").write_text("[]")
    (pin_root / jid / "facts.json").write_text(json.dumps([
        {"key": "chain.chain_id", "value": "56", "unit": None, "unit_id": None, "source": "job input", "tags": []}]))
    write_chain_facts(pin_root, jid, await _chain_facts())
    work = tmp_path / "work" / jid
    work.mkdir(parents=True)
    (work / "candidates.json").write_text(json.dumps([{"provider": "sourcify", "entry_contract":
                                                       "contracts/VotingEscrow.sol:VotingEscrow",
                                                       "explorer_verified": True, "sourcify_match": "exact_match"}]))
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(job_id=jid, principal_key=report_tool.principal_of(jid), surface="plugin", state="queued",
                          requester_role="third_party_public_code", source_kind="deployed", source_args={},
                          has_deployment=True, chain="evm", chain_id=56, address=VE)
        rid = hashlib.sha256(jid.encode()).hexdigest()
        rid = "".join("abcdefghijklmnopqrstuvwxyz234567"[int(c, 16) * 2] for c in rid[:26])
        await conn.execute("update jobs set state = 'ready', report_id = %s, source_pin = %s where job_id = %s",
                           (rid, pin.source_pin, jid))
        matrix = {"impact_class": "accounting_drift", "magnitude": "unbounded", "trigger": "anyone",
                  "precondition": "none", "reversibility": "irreversible"}
        content = {"title": "Merging two locks counts the merged amount in supply twice",
                   "matrix": matrix, "claimed_severity": "Medium",
                   "body": {"description": [{"p": DESCRIPTION}],
                            "impact": [{"p": "Any consumer of supply, such as an emission or quorum calculation, "
                                             "reads a lock total that only grows with each merge."}],
                            "recommendation": [{"p": "Subtract the merged amount from supply before _deposit_for in "
                                                     "merge, and correct the stored total once."}]}}
        await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
            current_revision, severity, evidence_level, final_id, caps_applied, severity_rule, severity_set_by,
            severity_reason) values (%s,'thena-t5',1,'model','accepted',1,'Medium','reasoning_challenged','M-001',
            %s, 'reviewer Medium', 'reviewer', 'Confirmed on chain at the read block.')""", (jid, []))
        await conn.execute("""insert into finding_revisions (job_id, draft_key, revision, content, content_hash,
            category, category_family, impact_class, computed_severity, severity_rule)
            values (%s,'thena-t5',1,%s,'h','evm.accounting_logic','evm','accounting_drift','Medium','reviewer Medium')""",
                           (jid, Jsonb(content)))
        await conn.execute("insert into finding_quote_ranges values (%s,'thena-t5',1,0,'location','contracts/VotingEscrow.sol',6,11)",
                           (jid,))
        await repo.transition(jid, "finalized")
        await render.queue_render(conn, jid)
    return jid


@ASYNC
async def test_thena_finding_prints_chain_values_with_their_block(db_pool, tmp_path, monkeypatch):
    jid = await _job(db_pool, tmp_path)
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "render-root"))

    def fake(render_dir, *, compact, image, timeout_s=120):
        return RenderOutcome("ok", pages=4, pdf_sha256=hashlib.sha256(PDF).hexdigest(), out_dir=render_dir,
                             result={"compact": compact, "fonts": ["Gilroy-Regular"]}, files={"report.pdf": PDF})

    monkeypatch.setattr(render, "run_container", fake)
    async with db_pool.connection() as conn:
        step = await JobRepo(conn).claim_step(host="t", free_units=4, lease_secs=60, free_ram_mb=8192,
                                              max_units_idle=4, max_ram_idle=8192, render=True)
    assert step and step["job_id"] == jid
    out = await render.run_render_step(db_pool, step, tmp_path / "pins", image="img")
    assert out.code == "ok", out
    async with db_pool.connection() as conn:
        row = await render.report_row(conn, jid)
    prefix = tmp_path / "store" / row["object_prefix"]
    report = json.loads((prefix / "report.json").read_text())
    html = (prefix / "screen.html").read_text()
    figs = report["findings"][0]["evidence"]["figures"]
    assert [f["operands"][0]["source"]["block_or_slot"] for f in figs] == [META["block"]] * 4
    assert report["facts"]["chain.ve.supply"]["at"] == AT[1:-1]
    assert f"335,304,456,968,324,627,407,175,342 {AT}" in html
    assert "150,473,875,546,894,119,406,360,255 token_units" in html
    assert "&quot;THE&quot;" in html or '"THE"' in html
    assert "Panic(0x11): arithmetic underflow or overflow" in html
    assert f"chain.ve.supply, eth_call supply() at {META['block']:,}" in html
    dest = os.environ.get("SOKEN_PROOF_OUT")
    if dest:
        Path(dest).mkdir(parents=True, exist_ok=True)
        shutil.copy(prefix / "report.json", Path(dest) / "thena-report.json")
