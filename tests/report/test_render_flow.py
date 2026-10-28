"""Render step against Postgres (08 3.1 to 3.4, 03 3.2, 4.15): assembly, attempts, reports row, review_report."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest
from psycopg.types.json import Jsonb

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.pinning.store import PinnedSource
from soken_review.report import render
from soken_review.report.render import RenderOutcome
from soken_review.tools import report as report_tool

ASYNC = pytest.mark.asyncio(loop_scope="session")

SECRET_TITLE = "Reentrant withdraw lets a caller drain the vault before the balance write"
CODE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) balances;
    function withdraw(uint256 a) external {
        (bool ok, ) = msg.sender.call{value: a}("");
        balances[msg.sender] -= a;
    }
}
"""
PDF = b"%PDF-1.7\n" + b"0" * 64


async def _job(db_pool, tmp_path: Path, titles: dict[str, str]) -> str:
    jid = new_job_id()
    pin_root = tmp_path / "pins"
    pin = PinnedSource.from_files({"src/Vault.sol": CODE.encode()}, langs={"src/Vault.sol": "solidity"})
    pin.persist(pin_root, jid)
    (pin_root / jid / "leads.json").write_text(json.dumps([
        {"id": "LEAD-0001", "rule_id": "reentrancy-eth", "tools": ["slither@0.11.6"], "category": "evm.reentrancy",
         "analyzer_severity_raw": "High", "severity_norm": "High", "file": "src/Vault.sol", "start": 5, "end": 8,
         "state": "open"}]))
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
        for no, (sev, fid, title, level) in enumerate([("High", "H-001", titles["High"], "analyzer_and_reasoning"),
                                                      ("Low", "L-001", titles["Low"], "reasoning_only")], start=1):
            key = f"draft-{no}"
            content = {"title": title, "body": {"description": [{"p": "The `withdraw` function sends value first."}],
                                                "impact": [{"p": "A caller can withdraw twice."}],
                                                "recommendation": [{"p": "Write the balance first."}]},
                       "attack_steps": [{"text": "Reenter from the fallback.", "ref": "src/Vault.sol:6"}]}
            await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
                current_revision, severity, evidence_level, final_id) values (%s,%s,%s,'model','accepted',1,%s,%s,%s)""",
                               (jid, key, no, sev, level, fid))
            await conn.execute("""insert into finding_revisions (job_id, draft_key, revision, content, content_hash,
                category, category_family, impact_class, computed_severity, severity_rule)
                values (%s,%s,1,%s,'h','evm.reentrancy','evm','theft_of_funds',%s,'S1')""", (jid, key, Jsonb(content), sev))
            await conn.execute("""insert into finding_quote_ranges values (%s,%s,1,0,'location','src/Vault.sol',5,8)""",
                               (jid, key))
            if level == "analyzer_and_reasoning":
                await conn.execute("insert into finding_leads values (%s,%s,1,'LEAD-0001')", (jid, key))
        await repo.transition(jid, "finalized")
        await render.queue_render(conn, jid)
    return jid


async def _claim(db_pool):
    async with db_pool.connection() as conn:
        return await JobRepo(conn).claim_step(host="t", free_units=4, lease_secs=60, free_ram_mb=8192,
                                              max_units_idle=4, max_ram_idle=8192, render=True)


async def _state(db_pool, jid):
    async with db_pool.connection() as conn:
        return (await (await conn.execute("select state, error_detail from jobs where job_id = %s", (jid,))).fetchone())


def _fake(outcomes):
    calls = []

    def run_container(render_dir, *, compact, image, timeout_s=120):
        calls.append(compact)
        code = outcomes.pop(0)
        if code != "ok":
            return RenderOutcome(code, "fake")
        return RenderOutcome("ok", pages=5, pdf_sha256=hashlib.sha256(PDF).hexdigest(), out_dir=render_dir,
                             result={"compact": compact, "fonts": ["Gilroy-Regular"]}, files={"report.pdf": PDF})
    return run_container, calls


@ASYNC
async def test_render_ok_reports_row_and_review_report(db_pool, tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "render-root"))
    fake, _ = _fake(["ok"])
    monkeypatch.setattr(render, "run_container", fake)
    jid = await _job(db_pool, tmp_path, {"High": SECRET_TITLE, "Low": "Balance written after the external call"})
    step = await _claim(db_pool)
    assert step and step["job_id"] == jid
    out = await render.run_render_step(db_pool, step, tmp_path / "pins", image="img")
    assert out.code == "ok"
    assert (await _state(db_pool, jid))[0] == "rendered"
    async with db_pool.connection() as conn:
        row = await render.report_row(conn, jid)
    assert row["pdf_sha256s"] == [hashlib.sha256(PDF).hexdigest()]
    assert row["profile"] == "public_review" and row["out_name"].startswith("Automated_Review_")
    stored = tmp_path / "store" / row["object_prefix"]
    assert (stored / "report.pdf").read_bytes() == PDF
    screen = (stored / "screen.html").read_text()
    # CEO 2026-10-28: the third-party High prints as is on the hosted page (the site copy) as in report.json
    assert SECRET_TITLE in screen and "<script" not in screen
    assert "src/Vault.sol:5-8" in screen and "withheld" not in screen.lower()
    assert SECRET_TITLE in (stored / "report.json").read_text()

    report_tool.set_pool(db_pool)
    res = await report_tool.handle_review_report({"job_id": jid, "page": 1})
    assert res["status"] == "ready" and res["counts"]["High"] == 1 and res["pages"] == 5
    assert res["top"] == {"id": "H-001", "severity": "High", "title": SECRET_TITLE}  # printed as is
    assert SECRET_TITLE[:50] in res["summary_text"] and "withheld" not in json.dumps(res).lower()
    assert res["rows"][0]["location"] == "src/Vault.sol:5-8"
    assert "?e=" in res["url"] and res["manage_url"].startswith(f"https://soken.dev/r/{row['report_id']}/manage#k=")
    assert len(res["summary_text"]) < 2000 and "Manage or delete:" in res["summary_text"]


@ASYNC
async def test_symlinked_render_dir_in_job_tree_is_never_used(db_pool, tmp_path, monkeypatch):
    """A container that could write the job work tree plants work/<job>/render -> host dir: no effect."""
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "render-root"))
    seen = []

    def fake(render_dir, *, compact, image, timeout_s=120):
        seen.append(render_dir)
        assert (render_dir / "in" / "report.json").is_file()
        return RenderOutcome("ok", pages=5, pdf_sha256=hashlib.sha256(PDF).hexdigest(), out_dir=render_dir,
                             result={"compact": False, "fonts": []}, files={"report.pdf": PDF})

    monkeypatch.setattr(render, "run_container", fake)
    jid = await _job(db_pool, tmp_path, {"High": SECRET_TITLE, "Low": "Balance written after the external call"})
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("host file")
    (tmp_path / "work" / jid / "render").symlink_to(victim)
    await render.run_render_step(db_pool, await _claim(db_pool), tmp_path / "pins", image="img")
    assert (await _state(db_pool, jid))[0] == "rendered"
    assert sorted(p.name for p in victim.iterdir()) == ["keep.txt"]
    assert seen[0].parent == tmp_path / "render-root" and not seen[0].exists()  # fresh dir, removed after


@ASYNC
async def test_timeout_retried_then_page_limit_compact(db_pool, tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    monkeypatch.setattr(render, "BACKOFF_S", {2: 0, 3: 0})
    fake, calls = _fake(["timeout", "page_limit", "ok"])
    monkeypatch.setattr(render, "run_container", fake)
    jid = await _job(db_pool, tmp_path, {"High": SECRET_TITLE, "Low": "Balance written after the external call"})
    for _ in range(3):
        step = await _claim(db_pool)
        assert step is not None
        await render.run_render_step(db_pool, step, tmp_path / "pins", image="img")
    assert calls == [False, False, True]
    assert (await _state(db_pool, jid))[0] == "rendered"


@ASYNC
async def test_deterministic_failure_not_retried(db_pool, tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    fake, calls = _fake(["fonts"])
    monkeypatch.setattr(render, "run_container", fake)
    jid = await _job(db_pool, tmp_path, {"High": SECRET_TITLE, "Low": "Balance written after the external call"})
    await render.run_render_step(db_pool, await _claim(db_pool), tmp_path / "pins", image="img")
    state, detail = await _state(db_pool, jid)
    assert state == "render_failed" and detail["detail"] == "fonts" and calls == [False]
    report_tool.set_pool(db_pool)
    res = await report_tool.handle_review_report({"job_id": jid})
    assert res["status"] == "render_failed" and res["code"] == "fonts" and res["url"] is None


@ASYNC
async def test_late_gate_at_assembly(db_pool, tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    fake, calls = _fake(["ok"])
    monkeypatch.setattr(render, "run_container", fake)
    jid = await _job(db_pool, tmp_path, {"High": SECRET_TITLE, "Low": "Balance written " + chr(0x2014) + " after the call"})
    await render.run_render_step(db_pool, await _claim(db_pool), tmp_path / "pins", image="img")
    state, detail = await _state(db_pool, jid)
    assert state == "render_failed" and detail["detail"] == "late_gate" and calls == []


def test_view_signature_expiry_and_tamper(monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_KEY_V1", "k" * 32)
    rid = "a" * 26
    now = time.time()
    lk = report_tool.links(rid, "public_review", 1, now=now)
    e = int(lk["url"].split("e=")[1].split("&")[0])
    s = lk["url"].split("s=")[1]
    assert report_tool.check_view(rid, e, s, now=now)
    assert not report_tool.check_view(rid, e, s, now=e + 1)
    assert not report_tool.check_view(rid, e, s[:-1] + ("a" if s[-1] != "a" else "b"), now=now)
    owner = report_tool.links(rid, "owner", 1)
    assert "?e=" not in owner["url"] and owner["manage_url"] == lk["manage_url"]


def test_summary_text_under_limit_with_sixty_findings():
    from soken_review.report.kit.build import counts, project

    from .fixtures import report

    p = project(report(60))
    text = report_tool.summary_text(p, counts(p["findings"]), report_tool.links("a" * 26, "public_review", 1),
                                    "2026-11-09")
    assert len(text) < 2000 and "and 52 more in the report" in text
    assert "withheld" not in text.lower() and "control of the code" not in text
    assert "| C-001 | Critical | Balance written after the external call in withdraw path 1 | src/Vault.sol:10-14 |" in text


@ASYNC
async def test_other_principal_reads_as_not_found(db_pool, tmp_path, monkeypatch):
    from soken_review.errors import ReviewError

    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "render-root"))
    fake, _ = _fake(["ok"])
    monkeypatch.setattr(render, "run_container", fake)
    jid = await _job(db_pool, tmp_path, {"High": SECRET_TITLE, "Low": "Balance written after the external call"})
    await render.run_render_step(db_pool, await _claim(db_pool), tmp_path / "pins", image="img")
    report_tool.set_pool(db_pool)
    assert (await report_tool.handle_review_report({"job_id": jid}))["status"] == "ready"
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set principal_key = 'other-princ' where job_id = %s", (jid,))
    for job in (jid, new_job_id()):
        with pytest.raises(ReviewError) as e:
            await report_tool.handle_review_report({"job_id": job})
        assert e.value.code == "E_JOB_NOT_FOUND"
