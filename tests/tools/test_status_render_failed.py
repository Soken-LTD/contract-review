"""review_status on a render_failed job says what review_finalize will do, and the project
documents hint stops once a context_notes section exists (blind run 2026-10-26/27)."""

from __future__ import annotations

import pytest

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


def test_status_never_carries_the_documents_hint():
    job = _job(state="ready", error_code=None, error_detail=None)
    assert "next_action" not in S._build_status_response(job, "concise")
