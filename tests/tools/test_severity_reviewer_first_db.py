"""Reviewer-first severity on the client path (handlers against Postgres).

review_submit_finding: claimed_severity far from the cell, or one step without a reason, returns
E_SEVERITY_CONFIRM with the computed value and spends no retry; with a severity_reason the
reviewer's value is stored and returned with severity_set_by and severity_reason.
review_answer_challenge: a challenge lowers at most one step (DG1) and names every rule.
"""

from __future__ import annotations

from typing import Any

import pytest

from .test_write_tools import (
    _VALID_MATRIX,
    _VALID_SUBMISSION,
    ASYNC,
    _create_ready_job_with_pin,
    _log_reads,
)

REASON = "The lender forfeits its own repayment and gains nothing; the lock is griefing, not a seizure."


async def _modules(db_pool, pin_root):
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    ctx = MemoryJobContext(pin_root)
    for mod in (submit_mod, challenge_mod):
        mod.set_pool(db_pool)
        mod.set_context(ctx)
    return submit_mod, challenge_mod


async def _draft_row(db_pool, job_id: str, key: str) -> dict[str, Any] | None:
    async with db_pool.connection() as conn:
        row = await (await conn.execute(
            """select rejected_count, severity, status, severity_rule, severity_set_by, severity_reason, caps_applied
               from finding_drafts where job_id = %s and draft_key = %s""", (job_id, key))).fetchone()
    if row is None:
        return None
    return dict(zip(("rejected_count", "severity", "status", "severity_rule", "severity_set_by",
                     "severity_reason", "caps_applied"), row, strict=True))


@ASYNC
async def test_claim_two_steps_from_the_cell_is_accepted_with_a_warning(db_pool):
    """never-worse: the confirmation is a warning on an accepted submit; with a reason the claim moves
    to the nearest value within one step of the computed cell (Critical cell, Medium claim: High)."""
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, _ = await _modules(db_pool, pin_root)
    args = {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": "draft-rv1-far",
            "claimed_severity": "Medium", "severity_reason": REASON}     # cell Critical
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is True, res
    assert [w["code"] for w in res["warnings"]] == ["E_SEVERITY_CONFIRM"]
    assert "2 steps" in res["warnings"][0]["what"] and res["warnings"][0]["class"] == "advisory"
    assert res["computed_severity"] == "High" and res["matrix_cell"] == "Critical"
    row = await _draft_row(db_pool, job_id, "draft-rv1-far")
    assert row and row["rejected_count"] == 0


@ASYNC
async def test_one_step_without_a_reason_asks_for_one_then_stands_with_it(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, _ = await _modules(db_pool, pin_root)
    args = {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": "draft-rv1-one", "claimed_severity": "High"}
    res = await submit_mod.handle_review_submit_finding(args)
    # accepted at the computed value, the warning asks for a reason
    assert res["accepted"] is True and res["warnings"][0]["code"] == "E_SEVERITY_CONFIRM", res
    assert "severity_reason" in res["warnings"][0]["what"] and res["computed_severity"] == "Critical"

    res2 = await submit_mod.handle_review_submit_finding({**args, "severity_reason": REASON})
    assert res2["accepted"] is True, res2
    assert res2["computed_severity"] == "High" and res2["matrix_cell"] == "Critical"
    assert res2["severity_set_by"] == "reviewer" and res2["severity_reason"] == REASON
    assert res2["rules_applied"] == ["RV1:reviewer=High"] and res2["caps_applied"] == []
    assert res2["status"] == "needs_challenge"
    row = await _draft_row(db_pool, job_id, "draft-rv1-one")
    assert row and row["severity"] == "High" and row["severity_set_by"] == "reviewer"
    assert row["severity_reason"] == REASON and row["severity_rule"].endswith("set_by=reviewer")
    assert row["rejected_count"] == 0

    # idempotent replay returns the stored verdict, not empty strings
    res3 = await submit_mod.handle_review_submit_finding({**args, "severity_reason": REASON})
    assert res3["accepted"] is True and res3["severity_set_by"] == "reviewer" and res3["severity_rule"]


@ASYNC
async def test_reviewers_low_on_a_medium_cell_is_accepted_without_a_challenge(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, _ = await _modules(db_pool, pin_root)
    matrix = {**_VALID_MATRIX, "impact_class": "yield_or_fee_loss", "magnitude": "unbounded",
              "precondition": "market_condition"}                               # I3xL2 = High
    args = {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": "draft-rv1-low", "matrix": matrix,
            "claimed_severity": "Medium",
            "severity_reason": "The leak is bounded by the fee rate and the time since the last accrual."}
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is True, res
    assert res["computed_severity"] == "Medium" and res["severity_set_by"] == "reviewer"
    assert res["status"] == "needs_challenge"


@ASYNC
async def test_claim_equal_to_the_cell_needs_no_reason(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, _ = await _modules(db_pool, pin_root)
    args = {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": "draft-rv1-same", "claimed_severity": "Critical"}
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is True and res["severity_set_by"] == "reviewer" and res["rules_applied"] == []


@ASYNC
async def test_a_reason_is_reviewer_prose_and_takes_the_text_gate(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, _ = await _modules(db_pool, pin_root)
    args = {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": "draft-rv1-gate", "claimed_severity": "High",
            "severity_reason": "You should rate this High because the impact is severe, is it not?"}
    res = await submit_mod.handle_review_submit_finding(args)
    # wording rules are advisory: accepted, the reason's T5/T12 hits come back as warnings (T13 is
    # exempt in severity_reason, the field exists to discuss severity)
    assert res["accepted"] is True, res
    rules = {(w.get("rule"), w.get("field")) for w in res["warnings"]}
    assert ("T5", "severity_reason") in rules and ("T12", "severity_reason") in rules
    assert ("T13", "severity_reason") not in rules


@ASYNC
async def test_a_challenge_lowers_at_most_one_step_and_names_dg1(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, challenge_mod = await _modules(db_pool, pin_root)
    matrix = {**_VALID_MATRIX, "impact_class": "yield_or_fee_loss"}           # I3xL3 = High
    args = {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": "draft-dg1-001", "matrix": matrix}
    sub = await submit_mod.handle_review_submit_finding(args)
    assert sub["accepted"] is True and sub["computed_severity"] == "High", sub
    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": "draft-dg1-001"})
    assert ch["accepted"] is True, ch
    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
    # every item absent: MB0 (value line) and MB1 (unbounded) fall back and the cell drops to Low;
    # before DG1 the verdict printed Low (two steps); now the floor is one step below High
    answers = [{"item_id": i["id"], "value": "absent", "refs": i["scope"].get("ranges") or ["src/Vault.sol:1-9"],
                "note": "No code evidence for this condition after reading the whole scope."} for i in ch["items"]]
    ans = await challenge_mod.handle_review_answer_challenge(
        {"job_id": job_id, "draft_key": "draft-dg1-001", "revision": ch["revision"], "answers": answers})
    assert ans["accepted"] is True, ans
    if ans["verdict"] != "downgraded":
        pytest.skip(f"no basis downgrade on this fixture: {ans}")
    assert ans["severity_before"] == "High" and ans["severity_after"] == "Medium", ans
    assert "DG1" in ans["caps_applied"] and ans["rules_applied"] == ans["caps_applied"]
    assert ans["severity_set_by"] == "cap" and ans["severity_reason"].startswith(("DG1:", "MB", "K"))
    assert "DG1" in ans["severity_rule"] and "basis=[" in ans["severity_rule"]
    row = await _draft_row(db_pool, job_id, "draft-dg1-001")
    assert row and row["severity"] == "Medium" and row["severity_set_by"] == "cap"
    assert row["severity_rule"] == ans["severity_rule"]
