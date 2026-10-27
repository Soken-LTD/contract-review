"""review_status on a render_failed job says what review_finalize will do, and the project
documents hint stops once a context_notes section exists (blind run 2026-10-26/27)."""

from __future__ import annotations

import json

import pytest

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.report.render import MAX_RENDER_RESETS, MAX_TOTAL_REOPENS
from soken_review.tools import start_status as S

ASYNC = pytest.mark.asyncio(loop_scope="session")


def _job(**overrides) -> dict:
    job = {
        "job_id": "job_RF00000000000000000000000",
        "state": "render_failed",
        "requester_role": "third_party_public_code",
        "ownership_proven": False,
        "context_items": [],
        "error_code": "E_RENDER_FAILED",
        "error_detail": {"detail": "internal", "note": "'list' object has no attribute 'get'", "cause": "server"},
        "render_resets": 0,
        "map_status": "full",
        "analyzer_degraded": False,
        "tier": None,
        "upload_id": None,
    }
    job.update(overrides)
    return job


MODEL = {"detail": "late_gate", "note": "T27 'pricing'", "cause": "model", "path": "$.findings[0].title"}


def test_server_failure_next_tools_and_fix_say_one_finalize_call():
    out = S._build_status_response(_job(), "concise")
    assert out["next_tools"] == ["review_finalize"]
    fix = out["error"]["fix"]
    assert "review_finalize once" in fix and "No text change" in fix
    assert "again" not in fix.split("review_finalize once")[0]


def test_model_text_failure_within_budget_asks_for_the_revision():
    out = S._build_status_response(_job(error_detail=MODEL, render_resets=MAX_RENDER_RESETS - 1), "concise")
    assert out["next_tools"] == ["review_finalize"]
    assert "revised" in out["error"]["fix"] and "same call" in out["error"]["fix"]


def test_model_text_failure_after_budget_never_points_at_finalize():
    """finalize answers E_JOB_TERMINAL here, so status must not say "call review_finalize"."""
    out = S._build_status_response(_job(error_detail=MODEL, render_resets=MAX_RENDER_RESETS), "concise")
    assert out["next_tools"] == ["review_start"]
    assert "Start a new review" in out["error"]["fix"]
    assert "review_finalize" not in out["error"]["fix"]


def test_server_failure_after_budget_still_points_at_finalize():
    out = S._build_status_response(_job(render_resets=MAX_RENDER_RESETS), "concise")
    assert out["next_tools"] == ["review_finalize"]


def test_total_reopen_cap_points_at_a_new_review_even_for_a_server_cause():
    out = S._build_status_response(_job(render_reopens=MAX_TOTAL_REOPENS), "concise")
    assert out["next_tools"] == ["review_start"]
    assert "Start a new review" in out["error"]["fix"] and "review_finalize" not in out["error"]["fix"]


def test_rendered_and_queued_jobs_keep_review_report():
    assert S._status_next_tools("render_queued", [], []) == ["review_report"]
    assert S._status_next_tools("rendered", [], []) == ["review_report"]
    assert S._status_next_tools("render_failed", [], [], finalize_reopens=False) == ["review_start"]


def test_documents_hint_stops_once_context_notes_is_recorded():
    job = _job(state="ready", error_code=None, error_detail=None)
    with_hint = S._build_status_response(job, "concise")
    assert "context_notes" in with_hint["next_action"]
    without = S._build_status_response(job, "concise", context_notes_recorded=True)
    assert "next_action" not in without


@ASYNC
async def test_review_status_drops_the_documents_hint_after_context_notes(db_pool):
    jid = new_job_id()
    async with db_pool.connection() as conn:
        await JobRepo(conn).create(job_id=jid, principal_key="p", surface="plugin", state="queued",
                                   requester_role="third_party_public_code", source_kind="files",
                                   source_args={}, has_deployment=False, chain="evm")
        await conn.execute("update jobs set state = 'ready' where job_id = %s", (jid,))
    S.set_pool(db_pool)
    try:
        before = await S.handle_review_status({"job_id": jid})
        async with db_pool.connection() as conn:
            await conn.execute(
                """insert into sections (job_id, section, revision, content, content_hash)
                   values (%s, 'context_notes', 1, %s, 'h')""",
                (jid, json.dumps([{"p": "The user has no project documents for this contract."}])))
        after = await S.handle_review_status({"job_id": jid})
        async with db_pool.connection() as conn:
            await conn.execute("delete from jobs where job_id = %s", (jid,))
    finally:
        S.set_pool(None)  # type: ignore[arg-type]
    assert "next_action" in before and "project documents" in before["next_action"].lower()
    assert "next_action" not in after
