"""review_finalize on a render_failed job (gate failure recovery, 2026-10-24 GBLIN incident)."""

from __future__ import annotations

import json

import pytest

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.tools import finalize as F

ASYNC = pytest.mark.asyncio(loop_scope="session")


async def _failed_job(conn, failed_renders: int) -> str:
    jid = new_job_id()
    await JobRepo(conn).create(job_id=jid, principal_key="p", surface="plugin", state="queued",
                               requester_role="third_party_public_code", source_kind="deployed",
                               source_args={}, has_deployment=True, chain="evm")
    await conn.execute(
        "update jobs set state = 'render_failed', error_code = 'E_RENDER_FAILED', error_detail = %s where job_id = %s",
        (json.dumps({"detail": "late_gate", "note": "T27 'pricing'", "secret": "internal path /srv/x"}), jid))
    await conn.execute(
        """insert into finding_drafts (job_id, draft_key, finding_no, origin, status, current_revision, final_id)
           values (%s, 'oracle-lag', 1, 'model', 'accepted', 1, 'M-001')""", (jid,))
    await conn.execute(
        """insert into leads (job_id, lead_id, origin, rule_id, tools, category, category_family,
                              analyzer_severity_raw, severity_norm, path, start_line, end_line, state)
           values (%s, 'LEAD-0001', 'analyzer', 'r', array['slither'], 'evm.x', 'evm', 'Low', 'Low',
                   'src/A.sol', 1, 2, 'not_reviewed')""", (jid,))
    for _ in range(failed_renders):
        await conn.execute(
            """insert into job_steps (job_id, step, status, container, units, ram_mb, max_attempts)
               values (%s, 'render', 'failed', true, 1, 512, 1)""", (jid,))
    return jid


@ASYNC
async def test_reset_reopens_job_and_hides_internal_detail(db_pool):
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, failed_renders=1)
    F.set_pool(db_pool)
    try:
        out = await F.handle_review_finalize({"job_id": jid})
        async with db_pool.connection() as conn:
            state = (await (await conn.execute("select state from jobs where job_id = %s", (jid,))).fetchone())[0]
            fid = (await (await conn.execute("select final_id from finding_drafts where job_id = %s", (jid,))).fetchone())[0]
            lead = (await (await conn.execute("select state from leads where job_id = %s", (jid,))).fetchone())[0]
            await conn.execute("delete from jobs where job_id = %s", (jid,))
    finally:
        F.set_pool(None)  # type: ignore[arg-type]
    assert out["state"] == "ready" and state == "ready"
    assert fid is None and lead == "open"
    text = json.dumps(out)
    assert "T27" in text and "pricing" in text and "/srv/x" not in text


@ASYNC
async def test_no_reset_after_three_failed_renders(db_pool):
    async with db_pool.connection() as setup:
        jid = await _failed_job(setup, failed_renders=4)
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
