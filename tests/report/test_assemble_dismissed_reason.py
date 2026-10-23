"""The dismissed-leads table of a report with no Critical and no High carries each lead's
dismissal reason from the `leads` row (road-to-prod item 9); the audit note never prints."""

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


async def _low_only_job(db_pool, tmp_path: Path) -> str:
    jid = new_job_id()
    pin_root = tmp_path / "pins"
    pin = PinnedSource.from_files({"src/Vault.sol": CODE.encode()}, langs={"src/Vault.sol": "solidity"})
    pin.persist(pin_root, jid)
    leads = [
        {"id": "LEAD-0001", "rule_id": "reentrancy-eth", "tools": ["slither@0.11.6"], "category": "evm.reentrancy",
         "analyzer_severity_raw": "High", "severity_norm": "Medium", "file": "src/Vault.sol", "start": 5, "end": 8,
         "state": "open"},
        {"id": "LEAD-0002", "rule_id": "unchecked-call", "tools": ["slither@0.11.6"], "category": "evm.unchecked_call",
         "analyzer_severity_raw": "Low", "severity_norm": "Low", "file": "src/Vault.sol", "start": 6, "end": 6,
         "state": "open"},
    ]
    (pin_root / jid / "leads.json").write_text(json.dumps(leads))
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
        for lead, state, reason in ((leads[0], "dismissed", "fp_guarded"), (leads[1], "dismissed", "not_a_vulnerability")):
            await conn.execute(
                """insert into leads (job_id, lead_id, rule_id, tools, category, category_family, analyzer_severity_raw,
                                      severity_norm, path, start_line, end_line, state, reason)
                   values (%s, %s, %s, %s, %s, 'evm', %s, %s, %s, %s, %s, %s, %s)""",
                (jid, lead["id"], lead["rule_id"], lead["tools"], lead["category"], lead["analyzer_severity_raw"],
                 lead["severity_norm"], lead["file"], lead["start"], lead["end"], state, reason))
        content = {"title": "Balance written after the external call",
                   "body": {"description": [{"p": "The `withdraw` function sends value first."}],
                            "impact": [{"p": "A caller can withdraw twice."}],
                            "recommendation": [{"p": "Write the balance first."}]},
                   "attack_steps": [{"text": "Reenter from the fallback.", "ref": "src/Vault.sol:6"}]}
        await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
            current_revision, severity, evidence_level, final_id) values (%s,'draft-1',1,'model','accepted',1,'Low',
            'reasoning_only','L-001')""", (jid,))
        await conn.execute("""insert into finding_revisions (job_id, draft_key, revision, content, content_hash,
            category, category_family, impact_class, computed_severity, severity_rule)
            values (%s,'draft-1',1,%s,'h','evm.reentrancy','evm','theft_of_funds','Low','S1')""", (jid, Jsonb(content)))
        await conn.execute("insert into finding_quote_ranges values (%s,'draft-1',1,0,'location','src/Vault.sol',5,8)",
                           (jid,))
        await repo.transition(jid, "finalized")
        await render.queue_render(conn, jid)
    return jid


@ASYNC
async def test_dismissed_rows_carry_their_reason(db_pool, tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "render-root"))

    def fake(render_dir, *, compact, image, timeout_s=120):
        return RenderOutcome("ok", pages=3, pdf_sha256=hashlib.sha256(PDF).hexdigest(), out_dir=render_dir,
                             result={"compact": compact, "fonts": ["Gilroy-Regular"]}, files={"report.pdf": PDF})

    monkeypatch.setattr(render, "run_container", fake)
    jid = await _low_only_job(db_pool, tmp_path)
    async with db_pool.connection() as conn:
        step = await JobRepo(conn).claim_step(host="t", free_units=4, lease_secs=60, free_ram_mb=8192,
                                              max_units_idle=4, max_ram_idle=8192, render=True)
    assert step and step["job_id"] == jid
    out = await render.run_render_step(db_pool, step, tmp_path / "pins", image="img")
    assert out.code == "ok", out
    async with db_pool.connection() as conn:
        row = await render.report_row(conn, jid)
    report = json.loads((tmp_path / "store" / row["object_prefix"] / "report.json").read_text())
    rows = report["summary"]["dismissed_leads"]["rows"]
    assert [(r["detector"], r["reason"]) for r in rows] == [("reentrancy-eth", "fp_guarded"),
                                                            ("unchecked-call", "not_a_vulnerability")]
    assert "note" not in rows[0]
    html = (tmp_path / "store" / row["object_prefix"] / "screen.html").read_text()
    assert "<th>Reason</th>" in html and "Guarded at the entry" in html
