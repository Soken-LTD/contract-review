"""review_status progress while a long step runs (2026-10-26: a Solana build showed 10 percent and
eta_s 3 for four minutes; the median came from no-op mint builds)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.tools.start_status import _compute_eta, _compute_percent

ASYNC = pytest.mark.asyncio(loop_scope="session")


def _steps(elapsed_s: float) -> list[dict]:
    return [{"step": "chain_state", "seq": 0, "status": "done"}, {"step": "fetch", "seq": 0, "status": "done"},
            {"step": "build", "seq": 0, "status": "running",
             "started_at": datetime.now(UTC) - timedelta(seconds=elapsed_s)}]


def test_percent_moves_with_the_running_step():
    assert _compute_percent("building", _steps(0), {"build": 400.0}) == 10
    assert _compute_percent("building", _steps(200), {"build": 400.0}) == 10 + int(25 * 0.5)
    # past the median the step is still running: 90 percent of its share at most
    assert _compute_percent("building", _steps(4000), {"build": 400.0}) == 10 + int(25 * 0.9)


def test_percent_without_medians_uses_the_defaults():
    assert 10 < _compute_percent("building", _steps(30), None) < 35


def test_eta_keeps_a_floor_when_the_running_step_is_past_its_median():
    eta = _compute_eta("building", _steps(240), {"build": 3.0, "analyze": 50.0, "map": 2.0, "chain_state": 1.0})
    assert eta >= 30 + 50 + 2 + 1
    eta_fresh = _compute_eta("building", _steps(40), {"build": 100.0, "analyze": 50.0, "map": 2.0, "chain_state": 1.0})
    assert 111 <= eta_fresh <= 115


@ASYNC
async def test_step_medians_ignore_sub_second_steps(db_pool):
    jid = new_job_id()
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(job_id=jid, principal_key="p", surface="plugin", state="ready",
                          requester_role="third_party_public_code", source_kind="repo", source_args={},
                          has_deployment=False, chain="solana-medians-test")
        for seconds in (0.2, 0.4, 420):
            row = await repo.insert_step(job_id=jid, step="build", container=True, units=2, ram_mb=1, max_attempts=1)
            await conn.execute("update job_steps set status = 'done', started_at = now() - make_interval(secs => %s),"
                               " finished_at = now() where id = %s", (seconds, row["id"]))
    try:
        async with db_pool.connection() as conn:
            medians = await JobRepo(conn).step_medians("solana-medians-test")
    finally:
        async with db_pool.connection() as conn:
            await conn.execute("delete from jobs where job_id = %s", (jid,))
    assert 419 <= medians["build"] <= 421
