"""The report's severity table prints the same rule, who set the severity and why as the verdict
payload (reviewer-first, 2026-10-27): columns Rule, Set by, Reason, from the draft's final values,
with the revision's submit-time rule as the fallback for rows older than migration 014."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from psycopg.types.json import Jsonb

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.pinning.store import PinnedSource
from soken_review.report import render
from soken_review.report.render import RenderOutcome
from soken_review.tools import report as report_tool

from .test_render_flow import CODE, PDF

ASYNC = pytest.mark.asyncio(loop_scope="session")
REASON = "The leak per cycle is bounded by the fee rate and the time since the last accrual."


async def _job(db_pool, tmp_path: Path, *, with_final_fields: bool) -> str:
    jid = new_job_id()
    pin_root = tmp_path / "pins"
    pin = PinnedSource.from_files({"src/Vault.sol": CODE.encode()}, langs={"src/Vault.sol": "solidity"})
    pin.persist(pin_root, jid)
    (pin_root / jid / "leads.json").write_text("[]")
    work = tmp_path / "work" / jid
    work.mkdir(parents=True)
    (work / "candidates.json").write_text(json.dumps([{"provider": "sourcify", "entry_contract": "src/Vault.sol:Vault",
                                                       "explorer_verified": True, "sourcify_match": "match"}]))
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(job_id=jid, principal_key=report_tool.principal_of(jid), surface="plugin", state="queued",
                          requester_role="third_party_public_code", source_kind="deployed", source_args={},
                          has_deployment=True, chain="evm", chain_id=8453,
                          address="0xc2181d975c05c8c724b334bcED0764c0b86B1D53")
        rid = hashlib.sha256(jid.encode()).hexdigest()
        rid = "".join("abcdefghijklmnopqrstuvwxyz234567"[int(c, 16) * 2] for c in rid[:26])
        await conn.execute("update jobs set state = 'ready', report_id = %s, source_pin = %s where job_id = %s",
                           (rid, pin.source_pin, jid))
        matrix = {"impact_class": "yield_or_fee_loss", "magnitude": "bounded", "trigger": "anyone",
                  "precondition": "normal_operation", "reversibility": "irreversible"}
        content = {"title": "Fee accrual runs after the share amount is priced",
                   "matrix": matrix, "claimed_severity": "Low", "severity_reason": REASON,
                   "body": {"description": [{"p": "The `withdraw` function accrues after pricing."}],
                            "impact": [{"p": "Depositors pay part of the fee on earlier yield."}],
                            "recommendation": [{"p": "Accrue before pricing."}]}}
        if with_final_fields:
            await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
                current_revision, severity, evidence_level, final_id, caps_applied, severity_rule, severity_set_by,
                severity_reason) values (%s,'draft-1',1,'model','accepted',1,'Low','reasoning_only','L-001',
                %s, 'I2xL3=Medium caps=[RV1:reviewer=Low] set_by=reviewer', 'reviewer', %s)""",
                (jid, ["RV1:reviewer=Low"], REASON))
        else:
            await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
                current_revision, severity, evidence_level, final_id, caps_applied) values
                (%s,'draft-1',1,'model','accepted',1,'Low','reasoning_only','L-001', %s)""", (jid, ["K6"]))
        await conn.execute("""insert into finding_revisions (job_id, draft_key, revision, content, content_hash,
            category, category_family, impact_class, computed_severity, severity_rule)
            values (%s,'draft-1',1,%s,'h','evm.accounting_logic','evm','yield_or_fee_loss','Low','I2xL3=Medium caps=[K6]')""",
            (jid, Jsonb(content)))
        await conn.execute("insert into finding_quote_ranges values (%s,'draft-1',1,0,'location','src/Vault.sol',5,8)",
                           (jid,))
        await repo.transition(jid, "finalized")
        await render.queue_render(conn, jid)
    return jid


async def _render(db_pool, tmp_path, monkeypatch, jid: str) -> tuple[dict, str]:
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "render-root"))

    def fake(render_dir, *, compact, image, timeout_s=120):
        return RenderOutcome("ok", pages=3, pdf_sha256=hashlib.sha256(PDF).hexdigest(), out_dir=render_dir,
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
    return json.loads((prefix / "report.json").read_text()), (prefix / "screen.html").read_text()


@ASYNC
async def test_severity_table_prints_rule_set_by_and_reason(db_pool, tmp_path, monkeypatch):
    jid = await _job(db_pool, tmp_path, with_final_fields=True)
    report, html = await _render(db_pool, tmp_path, monkeypatch, jid)
    basis = report["findings"][0]["evidence"]["basis"]
    assert basis["head"] == ["Impact class", "Magnitude", "Trigger", "Precondition", "Reversibility", "Rule",
                             "Set by", "Reason"]
    row = basis["rows"][0]
    assert row[:5] == ["yield_or_fee_loss", "bounded", "anyone", "normal_operation", "irreversible"]
    assert row[5] == "I2xL3=Medium caps=[RV1:reviewer=Low] set_by=reviewer"
    assert row[6] == "reviewer" and row[7] == REASON
    assert "<th>Set by</th>" in html and REASON in html


@ASYNC
async def test_rows_without_final_fields_fall_back_to_the_submit_rule(db_pool, tmp_path, monkeypatch):
    jid = await _job(db_pool, tmp_path, with_final_fields=False)
    report, _ = await _render(db_pool, tmp_path, monkeypatch, jid)
    row = report["findings"][0]["evidence"]["basis"]["rows"][0]
    assert row[5] == "I2xL3=Medium caps=[K6]"
    assert row[6] == "reviewer"                        # claimed_severity Low equals the printed Low
    assert row[7].startswith("K6: ")
