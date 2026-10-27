"""review_finalize on a render_failed job: the reopen rules (blind run 2026-10-26/27).

A server-caused failure (internal, schema, empty_page, layout_overflow, a late gate on server
text, a failure stored before the cause was recorded) reopens the job for free and never makes it
terminal. Only a late gate on the reviewer's own text spends one of MAX_RENDER_RESETS. The call
that reopens the job finalizes it again in the same call (one call, not two).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.report.render import MAX_RENDER_RESETS
from soken_review.tools import finalize as F
from soken_review.tools.context import MemoryJobContext

ASYNC = pytest.mark.asyncio(loop_scope="session")

MODEL_LATE_GATE = {"detail": "late_gate", "note": "T27 'pricing'", "cause": "model",
                   "path": "$.findings[0].title", "secret": "internal path /srv/x"}
SERVER_LATE_GATE = {"detail": "late_gate", "note": "T25 'soken'", "cause": "server", "path": "$.method[2].detail"}
LEGACY_LATE_GATE = {"detail": "late_gate", "note": "T25 'soken'"}  # stored before the cause was recorded
INTERNAL = {"detail": "internal", "note": "'list' object has no attribute 'get'", "cause": "server"}
EMPTY_PAGE = {"detail": "empty_page", "note": '{"page":15,"used":0.0985}', "cause": "server"}
LAYOUT_OVERFLOW = {"detail": "layout_overflow", "note": "page 2 section Scope", "cause": "server"}
SCHEMA = {"detail": "schema", "note": "fact state.initial_minted not in facts", "cause": "server"}


async def _failed_job(conn, detail: dict, render_resets: int = 0) -> str:
    """Create a render_failed job with the given stored failure and render_resets count."""
    jid = new_job_id()
    await JobRepo(conn).create(job_id=jid, principal_key="p", surface="plugin", state="queued",
                               requester_role="third_party_public_code", source_kind="deployed",
                               source_args={}, has_deployment=True, chain="evm")
    await conn.execute(
        "update jobs set state = 'render_failed', error_code = 'E_RENDER_FAILED',"
        " error_detail = %s, render_resets = %s where job_id = %s",
        (json.dumps(detail), render_resets, jid))
    await conn.execute(
        """insert into finding_drafts (job_id, draft_key, finding_no, origin, status, current_revision, final_id)
           values (%s, 'oracle-lag', 1, 'model', 'accepted', 1, 'M-001')""", (jid,))
    await conn.execute(
        """insert into leads (job_id, lead_id, origin, rule_id, tools, category, category_family,
                              analyzer_severity_raw, severity_norm, path, start_line, end_line, state)
           values (%s, 'LEAD-0001', 'analyzer', 'r', array['slither'], 'evm.x', 'evm', 'Low', 'Low',
                   'src/A.sol', 1, 2, 'not_reviewed')""", (jid,))
    return jid


async def _finalize(db_pool, jid: str) -> tuple[dict, str, int, str | None, str]:
    """Call finalize once; return (response, job state, render_resets, draft final_id, lead state)."""
    F.set_pool(db_pool)
    F.set_context(MemoryJobContext(Path(tempfile.mkdtemp()) / "pins"))
    try:
        out = await F.handle_review_finalize({"job_id": jid})
        async with db_pool.connection() as conn:
            row = await (await conn.execute(
                "select state, render_resets from jobs where job_id = %s", (jid,))).fetchone()
            fid = (await (await conn.execute(
                "select final_id from finding_drafts where job_id = %s", (jid,))).fetchone())[0]
            lead = (await (await conn.execute("select state from leads where job_id = %s", (jid,))).fetchone())[0]
            await conn.execute("delete from jobs where job_id = %s", (jid,))
    finally:
        F.set_pool(None)  # type: ignore[arg-type]
    return out, row[0], row[1], fid, lead


@ASYNC
async def test_model_text_failure_reopens_spends_one_reset_and_finalizes_in_the_same_call(db_pool):
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, MODEL_LATE_GATE, render_resets=0)
    out, state, resets, fid, lead = await _finalize(db_pool, jid)
    assert state == "ready" and out["state"] == "ready"
    assert fid is None and lead == "open"
    assert resets == 1, f"a late gate on model text spends one reset, got {resets}"
    assert out["recovered_from"] == {"code": "late_gate", "cause": "model", "rule": "T27 'pricing'"}
    # One call: the reopened job went straight through the finalize checks (open on this bare job).
    assert out["accepted"] is False and out["errors"][0]["code"] == "E_FINALIZE_OPEN"
    assert "revise" in out["hint"]
    text = json.dumps(out)
    assert "T27" in text and "pricing" in text and "/srv/x" not in text


@ASYNC
@pytest.mark.parametrize("detail", [SERVER_LATE_GATE, LEGACY_LATE_GATE, INTERNAL, EMPTY_PAGE, LAYOUT_OVERFLOW, SCHEMA],
                         ids=lambda d: d["detail"] + ("" if "cause" in d else "-legacy"))
async def test_server_caused_failures_reopen_without_spending_a_reset(db_pool, detail):
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, detail, render_resets=1)
    out, state, resets, fid, lead = await _finalize(db_pool, jid)
    assert state == "ready" and out["state"] == "ready"
    assert resets == 1, f"a server-caused failure must not consume a reset, got {resets}"
    assert fid is None and lead == "open"
    assert out["recovered_from"]["cause"] == "server" and out["recovered_from"]["code"] == detail["detail"]
    assert out["errors"][0]["code"] == "E_FINALIZE_OPEN"  # finalize ran in this call
    assert "No text change" not in out["hint"] and "revise" not in out["hint"]


@ASYNC
async def test_model_text_failure_is_terminal_once_the_budget_is_used(db_pool):
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, MODEL_LATE_GATE, render_resets=MAX_RENDER_RESETS)
    out, state, resets, _fid, _lead = await _finalize(db_pool, jid)
    assert state == "render_failed" and out["state"] == "render_failed"
    assert out["errors"][0]["code"] == "E_JOB_TERMINAL"
    assert resets == MAX_RENDER_RESETS


@ASYNC
async def test_server_caused_failure_is_recoverable_even_after_the_budget_is_used(db_pool):
    """The TON job of 2026-10-27 had three server-caused resets recorded; it must still reopen."""
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, INTERNAL, render_resets=MAX_RENDER_RESETS)
    out, state, resets, _fid, _lead = await _finalize(db_pool, jid)
    assert state == "ready" and out["state"] == "ready"
    assert out["recovered_from"] == {"code": "internal", "cause": "server"}
    assert resets == MAX_RENDER_RESETS
