"""Thin flow end to end on the database (thin server design 2026-11-03, sections 1, 3 and 4):
submit with an old matrix payload, the quote check as the only refusal, withdraw, finalize, assembly and the
kit build. Jobs are created with jobs.flow = thin (migration 022, SOKEN_FLOW=thin)."""

from __future__ import annotations

import copy

import pytest

from tests.tools.test_submit_finalize import _VALID_SUBMISSION, _create_ready_job_with_pin

ASYNC = pytest.mark.asyncio(loop_scope="session")

# Every pattern a blocking gate refused before (text gate T-rules, numbers, owner claims, publication words).
FORMER_BLOCKING = (
    "This code is guaranteed safe and fully audited by SOKEN, warranty included; 1,000,000 USDC is at risk. "
    "The owner is the deployer. Visit https://evil.example/claim?x=1 or mail ops@evil.example, see app.evil.io. "
    "Hidden\u202echaracters\u200b and a control\x07char. {{fact:no.such.key}} and {fact:half.form} and {{calc:x}}."
)


async def _wired(db_pool):
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools import withdraw as wd_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    for mod in (submit_mod, fin_mod, wd_mod):
        mod.set_pool(db_pool)
        mod.set_context(MemoryJobContext(pin_root))
    return submit_mod, fin_mod, wd_mod, job_id, pin_root


def _args(job_id: str, key: str, **over) -> dict:
    a = copy.deepcopy(_VALID_SUBMISSION)   # carries matrix, lead_ids and attack_steps: an old client's call
    a.update({"job_id": job_id, "draft_key": key, "claimed_severity": "High"})
    a.update(over)
    return a


async def _one(db_pool, sql: str, params: tuple):
    async with db_pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(sql, params)
        return await cur.fetchone()


@ASYNC
async def test_new_job_is_thin(db_pool):
    _, _, _, job_id, _ = await _wired(db_pool)
    assert (await _one(db_pool, "select flow from jobs where job_id = %s", (job_id,)))[0] == "thin"


@ASYNC
async def test_old_matrix_payload_is_accepted_as_claimed_and_stored_without_ignored_fields(db_pool):
    submit_mod, _, _, job_id, _ = await _wired(db_pool)
    args = _args(job_id, "thin-001", lead_ids=["LEAD-0001"], absence_claims=[], distinct_from=["nope-001"],
                 title="T" * 10 + " a long title " + "x" * 160)
    args["body"]["impact"] = [{"p": FORMER_BLOCKING}]
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is True, res
    assert res["status"] == "accepted" and res["severity_set_by"] == "reviewer"
    assert not {"computed_severity", "calibration", "matrix_cell", "challenge"} & res.keys()
    assert any(w["code"] == "E_FACT_UNKNOWN" for w in res.get("warnings", [])), res.get("warnings")
    row = await _one(db_pool, "select severity, status, calibration_severity, severity_set_by from finding_drafts "
                              "where job_id = %s", (job_id,))
    assert row == ("High", "accepted", None, "reviewer")
    content = (await _one(db_pool, "select content from finding_revisions where job_id = %s", (job_id,)))[0]
    assert not {"matrix", "lead_ids", "absence_claims", "distinct_from"} & content.keys()
    assert content["body"]["impact"][0]["p"] == FORMER_BLOCKING   # printed as written, nothing rewritten


@ASYNC
async def test_quote_check_is_the_only_refusal(db_pool):
    submit_mod, _, _, job_id, _ = await _wired(db_pool)
    bad = _args(job_id, "thin-002")
    bad["quotes"][0]["text"] = "function steal() external {}"
    res = await submit_mod.handle_review_submit_finding(bad)
    assert res["accepted"] is False and [e["code"] for e in res["errors"]] == ["E_QUOTE_MISMATCH"]
    unknown = _args(job_id, "thin-003")
    unknown["quotes"][0]["file"] = "src/Nope.sol"
    res = await submit_mod.handle_review_submit_finding(unknown)
    assert res["accepted"] is False and res["errors"][0]["code"] == "E_FILE_UNKNOWN"
    nosev = _args(job_id, "thin-004")
    del nosev["claimed_severity"]
    res = await submit_mod.handle_review_submit_finding(nosev)
    assert res["accepted"] is False and res["errors"][0]["field"] == "claimed_severity"
    # a category the family does not know is stored as the generic id with a warning
    cat = _args(job_id, "thin-005", category="evm.made_up_thing")
    res = await submit_mod.handle_review_submit_finding(cat)
    assert res["accepted"] is True and any(w["code"] == "E_CATEGORY_UNKNOWN" for w in res["warnings"])
    assert (await _one(db_pool, "select category from finding_revisions where job_id = %s and draft_key = %s",
                       (job_id, "thin-005")))[0] == "evm.other"


@ASYNC
async def test_withdraw_does_not_check_quotes(db_pool):
    submit_mod, _, wd_mod, job_id, _ = await _wired(db_pool)
    assert (await submit_mod.handle_review_submit_finding(_args(job_id, "thin-010")))["accepted"]
    res = await wd_mod.handle_review_withdraw_finding({
        "job_id": job_id, "draft_key": "thin-010", "reason": "disproved", "note": "guarded upstream, see quote",
        "quotes": [{"file": "src/Vault.sol", "start": 1, "end": 1, "text": "not the pinned line"}]})
    assert res["accepted"] is True, res


@ASYNC
async def test_finalize_assembly_and_render_of_former_blocking_text(db_pool, tmp_path):
    from soken_review.pinning.store import PinnedSource
    from soken_review.report.assemble import assemble_report
    from soken_review.report.kit.build import build

    submit_mod, fin_mod, _, job_id, pin_root = await _wired(db_pool)
    args = _args(job_id, "thin-020")
    args["body"]["description"] = [{"p": FORMER_BLOCKING}]
    assert (await submit_mod.handle_review_submit_finding(args))["accepted"]
    fin = await fin_mod.handle_review_finalize({"job_id": job_id})
    assert fin["accepted"] is True and not fin.get("coverage_gaps"), fin
    assert fin["leads_not_reviewed"] == 0
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set source_pin = %s, tier = 'B' where job_id = %s",
                           (PinnedSource.load(pin_root, job_id).source_pin, job_id))
        report, _ = await assemble_report(conn, job_id, pin_root)
    assert report["meta"]["flow"] == "thin"
    assert report["review_coverage"]["areas"] == [] and report["review_coverage"]["leads"] == []
    f = report["findings"][0]
    assert f["severity"] == "High" and f["evidence"]["challenge"] is None and "calibration" not in f
    assert f["evidence"]["basis"]["head"] == ["Severity", "Rule", "Set by", "Reason"]
    assert {k["key"] for k in report["summary"]["kpis"]} >= {"findings", "withdrawn", "ranges_read"}
    text = f["description"][0]["p"]
    assert "\u202e" not in text and "\x07" not in text and "\u200b" not in text
    assert "`https://evil.example/claim?x=1`" in text and "`ops@evil.example`" in text and "`app.evil.io`" in text
    assert "{{" not in text and "fact:no.such.key" in text
    assert "guaranteed safe and fully audited by SOKEN, warranty included" in text   # wording as written
    html = build(report, tmp_path).html_path.read_text(encoding="utf-8")
    assert "Analyzer leads" not in html and "No static analyzer or checklist ran" in html
    assert 'href="https://evil' not in html


@ASYNC
async def test_attack_steps_print_in_the_owner_profile_only(db_pool, tmp_path):
    from soken_review.pinning.store import PinnedSource
    from soken_review.report.assemble import assemble_report
    from soken_review.report.kit.build import build

    submit_mod, fin_mod, _, job_id, pin_root = await _wired(db_pool)
    args = _args(job_id, "thin-030")
    args["attack_steps"] = [{"text": "Call withdraw from the attack contract XSTEPX", "ref": "src/Vault.sol:6"}]
    assert (await submit_mod.handle_review_submit_finding(args))["accepted"]
    assert (await fin_mod.handle_review_finalize({"job_id": job_id}))["accepted"]
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set source_pin = %s, tier = 'B' where job_id = %s",
                           (PinnedSource.load(pin_root, job_id).source_pin, job_id))
        report, _ = await assemble_report(conn, job_id, pin_root)
    assert report["meta"]["profile"] == "public_review"
    html = build(report, tmp_path).html_path.read_text(encoding="utf-8")
    assert "XSTEPX" not in html


@ASYNC
async def test_legacy_job_keeps_the_legacy_assembly_under_the_thin_server(db_pool):
    """A job created before migration 022 (flow legacy) re-renders with its old sections."""
    from soken_review.pinning.store import PinnedSource
    from soken_review.report.assemble import assemble_report

    submit_mod, fin_mod, _, job_id, pin_root = await _wired(db_pool)
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set flow = 'legacy' where job_id = %s", (job_id,))
    assert (await submit_mod.handle_review_submit_finding(_args(job_id, "thin-040")))["accepted"]
    assert (await fin_mod.handle_review_finalize({"job_id": job_id}))["accepted"]
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set source_pin = %s, tier = 'B' where job_id = %s",
                           (PinnedSource.load(pin_root, job_id).source_pin, job_id))
        report, _ = await assemble_report(conn, job_id, pin_root)
    assert "flow" not in report["meta"] and report["review_coverage"]["areas"]


@ASYNC
async def test_status_in_thin_flow(db_pool):
    from soken_review.tools import read as read_mod
    from soken_review.tools import start_status
    from soken_review.tools.context import MemoryJobContext

    _, _, _, job_id, pin_root = await _wired(db_pool)
    start_status.set_pool(db_pool)
    read_mod.set_context(MemoryJobContext(pin_root))
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set analyzer_degraded = true where job_id = %s", (job_id,))
    out = await start_status.handle_review_status({"job_id": job_id})
    assert out["finalize_checks"] == [] and out["source_pinned"] is True
    assert "analyzer_degraded" not in out and "analyzer_note" not in out
    retired = {"review_leads", "review_dismiss_lead", "review_challenge", "review_answer_challenge",
               "review_set_section"}
    assert not set(out["next_tools"]) & retired


@ASYNC
async def test_analyze_step_is_a_no_op_for_thin_jobs(tmp_path):
    import json as _json
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from soken_review.worker.supervisor import Supervisor

    sup = SimpleNamespace(_pin_root=tmp_path / "pins", _job_dir=lambda j: tmp_path / "work" / j,
                          _mark_step=AsyncMock(), _after_analyze=AsyncMock())
    step = {"id": 7, "job_id": "job_" + "D" * 26}
    await Supervisor._run_analyze_thin(sup, step)
    assert _json.loads((tmp_path / "pins" / step["job_id"] / "leads.json").read_text()) == []
    assert _json.loads((tmp_path / "work" / step["job_id"] / "static_map.json").read_text())["status"] == "skipped"
    sup._mark_step.assert_awaited_once_with(7, "done")
    sup._after_analyze.assert_awaited_once_with(step, degraded=False)
