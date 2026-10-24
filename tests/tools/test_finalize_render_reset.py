"""review_finalize on a render_failed job (gate failure recovery, 2026-10-24 GBLIN incident)."""

from __future__ import annotations

import json

import pytest

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.tools import finalize as F

ASYNC = pytest.mark.asyncio(loop_scope="session")


async def _failed_job(conn, render_resets: int = 0) -> str:
    """Create a render_failed job with the given render_resets count already recorded."""
    jid = new_job_id()
    await JobRepo(conn).create(job_id=jid, principal_key="p", surface="plugin", state="queued",
                               requester_role="third_party_public_code", source_kind="deployed",
                               source_args={}, has_deployment=True, chain="evm")
    await conn.execute(
        "update jobs set state = 'render_failed', error_code = 'E_RENDER_FAILED',"
        " error_detail = %s, render_resets = %s where job_id = %s",
        (json.dumps({"detail": "late_gate", "note": "T27 'pricing'", "secret": "internal path /srv/x"}),
         render_resets, jid))
    await conn.execute(
        """insert into finding_drafts (job_id, draft_key, finding_no, origin, status, current_revision, final_id)
           values (%s, 'oracle-lag', 1, 'model', 'accepted', 1, 'M-001')""", (jid,))
    await conn.execute(
        """insert into leads (job_id, lead_id, origin, rule_id, tools, category, category_family,
                              analyzer_severity_raw, severity_norm, path, start_line, end_line, state)
           values (%s, 'LEAD-0001', 'analyzer', 'r', array['slither'], 'evm.x', 'evm', 'Low', 'Low',
                   'src/A.sol', 1, 2, 'not_reviewed')""", (jid,))
    return jid


@ASYNC
async def test_reset_reopens_job_and_hides_internal_detail(db_pool):
    """First reset: job goes to ready, final_id cleared, leads reopened, internals stripped."""
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, render_resets=0)
    F.set_pool(db_pool)
    try:
        out = await F.handle_review_finalize({"job_id": jid})
        async with db_pool.connection() as conn:
            row = (await (await conn.execute(
                "select state, render_resets from jobs where job_id = %s", (jid,))).fetchone())
            state, resets_after = row[0], row[1]
            fid = (await (await conn.execute("select final_id from finding_drafts where job_id = %s", (jid,))).fetchone())[0]
            lead = (await (await conn.execute("select state from leads where job_id = %s", (jid,))).fetchone())[0]
            await conn.execute("delete from jobs where job_id = %s", (jid,))
    finally:
        F.set_pool(None)  # type: ignore[arg-type]
    assert out["state"] == "ready" and state == "ready"
    assert fid is None and lead == "open"
    assert resets_after == 1, f"render_resets should be 1 after first reset, got {resets_after}"
    text = json.dumps(out)
    assert "T27" in text and "pricing" in text and "/srv/x" not in text


@ASYNC
async def test_no_reset_after_three_failed_renders(db_pool):
    """After _MAX_RENDER_RESETS (3) prior resets, finalize must refuse and keep job render_failed."""
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, render_resets=3)
    F.set_pool(db_pool)
    try:
        out = await F.handle_review_finalize({"job_id": jid})
        async with db_pool.connection() as conn:
            state = (await (await conn.execute("select state from jobs where job_id = %s", (jid,))).fetchone())[0]
            await conn.execute("delete from jobs where job_id = %s", (jid,))
    finally:
        F.set_pool(None)  # type: ignore[arg-type]
    assert state == "render_failed"
    assert out["errors"][0]["code"] == "E_JOB_TERMINAL"


@ASYNC
async def test_second_reset_increments_counter(db_pool):
    """Second reset: counter goes 1 -> 2, still allowed."""
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, render_resets=1)
    F.set_pool(db_pool)
    try:
        out = await F.handle_review_finalize({"job_id": jid})
        async with db_pool.connection() as conn:
            row = (await (await conn.execute(
                "select state, render_resets from jobs where job_id = %s", (jid,))).fetchone())
            state, resets_after = row[0], row[1]
            await conn.execute("delete from jobs where job_id = %s", (jid,))
    finally:
        F.set_pool(None)  # type: ignore[arg-type]
    assert state == "ready"
    assert resets_after == 2, f"render_resets should be 2 after second reset, got {resets_after}"
    assert out["state"] == "ready"
