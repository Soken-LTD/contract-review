"""A finding verified by a passing fork run (review_verify_on_fork) in report.json and the card.

The card prints "Verified by a test on a local fork of <network> at block N: <test name>" and the
evidence chip of test_verified; the test source prints only under the owner profile (the attack steps
rule), a public copy names it instead. Assembly raises the level only for a passing run bound to the
draft; the analyzer lead of an analyzer-backed finding stays on the card.
"""

from __future__ import annotations

import copy

import pytest

from soken_review.report.assemble import fork_evidence
from soken_review.report.kit import build as kb
from soken_review.report.kit.build import build

from .fixtures import report, with_profile

SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import {Test} from "forge-std/Test.sol";
contract WethDepositTest is Test { function test_depositCreditsBalance() public { assertTrue(true); } }
"""
FORK = {"run_id": "fork-0123456789ab", "network": "Ethereum Mainnet", "block": 26311087,
        "tests": ["WethDepositTest.test_depositCreditsBalance()"], "test_path": "test/Verify.t.sol",
        "test_sha256": "a" * 64, "base_level": "reasoning_challenged", "source": SOURCE}


def _verified(profile: str) -> dict:
    r = with_profile(report(severities=["Medium", "Low"]), profile)
    f = r["findings"][0]
    f["evidence_level"] = "test_verified"
    f["evidence"]["fork_test"] = copy.deepcopy(FORK)
    return r


def _html(r, tmp_path, mode="print") -> str:
    return build(r, tmp_path / f"{mode}-{r['meta']['profile']}", mode=mode).html_path.read_text(encoding="utf-8")


def test_card_prints_the_fork_line_and_the_chip(tmp_path):
    html = _html(_verified("public_review"), tmp_path)
    assert "Verified by a test on a local fork of Ethereum Mainnet at block 26,311,087: " in html
    assert "WethDepositTest.test_depositCreditsBalance()" in html
    assert kb.kit_texts()["evidence_chips"]["test_verified"] in html


def test_test_source_prints_for_the_owner_only(tmp_path):
    public = _html(_verified("public_review"), tmp_path)
    screen = _html(_verified("public_review"), tmp_path, "screen")
    owner = _html(_verified("owner"), tmp_path)
    for doc in (public, screen):
        assert "assertTrue(true)" not in doc
        assert kb.kit_texts()["fork_test_owner_only"] in doc
    assert "assertTrue(true)" in owner and "test/Verify.t.sol" in owner
    assert kb.kit_texts()["fork_test_owner_only"] not in owner


def test_assembly_raises_only_for_a_passing_run_with_a_passed_test():
    row = {"run_id": "fork-0123456789ab", "network": "BNB Smart Chain Mainnet", "block": 5, "test_path": "test/V.t.sol",
           "test_sha256": "b" * 64, "test_source": SOURCE,
           "result": {"status": "passed", "tests": [{"name": "V.test_a()", "status": "passed"},
                                                     {"name": "V.test_b()", "status": "skipped"}]}}
    ev = fork_evidence(row, "analyzer_and_reasoning")
    assert ev["tests"] == ["V.test_a()"] and ev["base_level"] == "analyzer_and_reasoning" and ev["source"] == SOURCE
    assert fork_evidence(None, "reasoning_only") is None
    assert fork_evidence({**row, "result": {"tests": [{"name": "V.t()", "status": "failed"}]}}, "reasoning_only") is None


def test_analyzer_lead_stays_on_a_verified_card(tmp_path):
    r = _verified("public_review")
    f = r["findings"][0]
    f["evidence"]["lead"] = {"analyzer": "slither 0.11.6", "rule_id": "reentrancy-eth"}
    f["evidence"]["fork_test"]["base_level"] = "analyzer_and_reasoning"
    html = _html(r, tmp_path)
    assert "reentrancy-eth" in html and "at block 26,311,087" in html


ASYNC = pytest.mark.asyncio(loop_scope="session")


@ASYNC
async def test_rendered_report_carries_the_passing_run(db_pool, tmp_path, monkeypatch):
    """Through assemble and the render step on Postgres: the Thena finding of the chain facts test,
    with a passing fork run bound to its draft, prints test_verified and the fork line."""
    import hashlib
    import json
    import secrets

    from soken_review.db.job_repo import JobRepo
    from soken_review.report import render
    from soken_review.report.render import RenderOutcome

    from .test_chain_facts_render import META, _job
    from .test_render_flow import PDF

    jid = await _job(db_pool, tmp_path)
    result = {"status": "passed", "tests": [{"name": "SupplyTest.test_mergeCountsTwice()", "status": "passed", "gas": 91234}]}
    async with db_pool.connection() as conn:
        await conn.execute("""insert into fork_runs (run_id, job_id, draft_key, status, chain_id, network, block, test_path,
                                test_sha256, test_source, result, finished_at)
                              values (%s, %s, 'thena-t5', 'passed', 56, 'BNB Smart Chain Mainnet', %s,
                                      'test/Verify.t.sol', %s, %s, %s, now())""",
                           ("fork-" + secrets.token_hex(6), jid, META["block"], "c" * 64, SOURCE, json.dumps(result)))
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
    report_json = json.loads((prefix / "report.json").read_text())
    html = (prefix / "screen.html").read_text()
    f = report_json["findings"][0]
    assert f["evidence_level"] == "test_verified"
    assert f["evidence"]["fork_test"]["base_level"] == "reasoning_challenged"
    assert f["evidence"]["fork_test"]["tests"] == ["SupplyTest.test_mergeCountsTwice()"]
    assert f"Verified by a test on a local fork of BNB Smart Chain Mainnet at block {META['block']:,}: " in html
    assert "SupplyTest.test_mergeCountsTwice()" in html
    assert "assertTrue(true)" not in html            # third-party public code: the source is owner-only
