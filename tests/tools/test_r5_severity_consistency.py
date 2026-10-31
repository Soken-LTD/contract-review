"""Blind matrix round 5, BakerFi MCP arm (2026-10-31): one severity at every stage, plain revision and
not_applicable messages, guide advice that agrees with the matrix, a warning on a severity jump between
revisions, and documented duplicate_of rules.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from soken_review.engine import gate_policy
from soken_review.engine.severity import SeverityContext, compute_severity, stage_evidence
from soken_review.errors import ReviewError

from .test_challenge_basis_not_covered import _CALL_LINE, _WRITE_LINE, F01_MATRIX, _submit_f01
from .test_write_tools import ASYNC, _create_ready_job_with_pin, _write_minimal_map

RUBRIC = Path(__file__).resolve().parents[2] / "contract" / "rubric"
SRC = Path(__file__).resolve().parents[2] / "src" / "soken_review"


# ── b) K8: the challenge verdict and finalize compute the same severity ─────────────────────────────


def _ctx(phase: str, evidence: str, *, complete: bool = True, attack: bool = True,
         open_dg: bool = False) -> SeverityContext:
    return SeverityContext(phase=phase, evidence_level=evidence, has_attack_steps=attack,
                           open_downgrade_item=open_dg, challenge_complete=complete,
                           has_location_quote=True)


@pytest.mark.parametrize("complete", [True, False])
@pytest.mark.parametrize("attack", [True, False])
@pytest.mark.parametrize("prior", ["reasoning_only", "analyzer_and_reasoning"])
def test_post_challenge_and_finalize_agree(complete: bool, attack: bool, prior: str) -> None:
    post = compute_severity(F01_MATRIX, "post_challenge", _ctx("post_challenge", prior, complete=complete,
                                                               attack=attack))
    # finalize reads the evidence the answer stored and the same inputs
    fin_ctx = _ctx("finalize", post.evidence_level, attack=attack)
    fin_ctx.challenge_skipped = post.evidence_level == "reasoning_only"   # as tools/finalize.py sets it
    fin = compute_severity(F01_MATRIX, "finalize", fin_ctx)
    assert post.severity == fin.severity, (post.severity_rule, fin.severity_rule)
    assert ("K8" in post.caps_applied) == ("K8" in fin.caps_applied)


def test_bakerfi_f01_challenged_with_attack_steps_is_critical_at_answer_time() -> None:
    post = compute_severity(F01_MATRIX, "post_challenge", _ctx("post_challenge", "reasoning_only"))
    assert post.evidence_level == "reasoning_challenged"
    assert post.severity == "Critical" and "K8" not in post.caps_applied


def test_stage_evidence() -> None:
    assert stage_evidence("submit", SeverityContext()) == "reasoning_only"
    assert stage_evidence("submit", SeverityContext(linked_lead_same_cat=True)) == "analyzer_and_reasoning"
    assert stage_evidence("post_challenge", SeverityContext(evidence_level="reasoning_only")) == "reasoning_challenged"
    assert stage_evidence("post_challenge", SeverityContext(evidence_level="reasoning_only",
                                                            challenge_complete=False)) == "reasoning_only"
    assert stage_evidence("finalize", SeverityContext(evidence_level="reasoning_challenged")) == "reasoning_challenged"


# ── c) guide advice agrees with the matrix ─────────────────────────────────────────────────────────


def _notes() -> dict[str, Any]:
    return yaml.safe_load((RUBRIC / "guide_notes.yaml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("ex", _notes()["freeze_classes"]["examples"])
def test_freeze_guide_examples_match_the_matrix(ex: dict[str, str]) -> None:
    matrix = {"impact_class": ex["impact_class"], "magnitude": ex["magnitude"], "trigger": "anyone",
              "precondition": "normal_operation", "reversibility": ex["reversibility"]}
    assert compute_severity(matrix, "submit", SeverityContext()).severity == ex["severity"]


def test_admin_reversible_freeze_has_a_medium_and_the_guide_says_which() -> None:
    from soken_review.tools.guide import _render_topic

    text = _render_topic("severity_inputs", "evm")
    assert "temporary_freeze with\n" not in text
    assert "temporary_freeze with reversibility admin_reversible" in text.replace("\n", " ")
    assert "not temporary_freeze" not in text   # the old advice that jumped Low to High


# ── c) severity jump warning between revisions ────────────────────────────────────────────────────


@ASYNC
async def test_resubmit_that_moves_severity_two_steps_warns_with_the_inputs(db_pool) -> None:
    job_id, pin_root = await _create_ready_job_with_pin(db_pool, chain="solana")
    _write_minimal_map(pin_root, job_id)
    first = await _submit_f01(db_pool, job_id, pin_root)
    assert first["accepted"] is True, first
    from soken_review.tools import submit as submit_mod

    res = await submit_mod.handle_review_submit_finding({
        "job_id": job_id, "draft_key": first["draft_key"], "expected_revision": first["revision"],
        "category": "solana.ata_owner_reassign", "quotes": [first_quote()], "lead_ids": [],
        "matrix": {**F01_MATRIX, "impact_class": "dos_noncore_function"},
        "title": "Borrower can block claim_default by reassigning the owner of the recipient token account",
        "body": {"description": [{"p": "The recipient token account is required with a fixed derived address."}],
                 "impact": [{"p": "The lender loses the seizure path while the loan stays active."}],
                 "recommendation": [{"p": "Make the surplus account optional."}]},
    })
    assert res["accepted"] is True, res
    jump = [w for w in res.get("warnings") or [] if w["code"] == "E_SEVERITY_JUMP"]
    assert jump, res
    assert "impact_class permanent_freeze to dos_noncore_function" in jump[0]["what"]
    assert "—" not in jump[0]["what"] + jump[0]["suggest"]


def first_quote() -> dict[str, Any]:
    from .test_challenge_basis_not_covered import _LOCATION

    return _LOCATION


# ── a) revision frozen, partial answer, not_applicable reasons ────────────────────────────────────


def test_revision_answered_message_does_not_ask_to_resend_the_same_number() -> None:
    env = ReviewError("E_REVISION_ANSWERED", draft="f-01", revision=0, verdict="passed", next=1).envelope()
    assert "Resend with revision 0" not in env["fix"]
    assert "already answered" in env["what"] and "revision 1" in env["fix"]
    assert gate_policy.is_blocking("E_REVISION_ANSWERED", None)


def test_na_reason_message_never_prints_an_empty_list() -> None:
    src = (SRC / "tools" / "challenge.py").read_text(encoding="utf-8")
    assert 'advise("E_CHALLENGE_NA_REASON", reasons=' not in src
    env = ReviewError("E_CHALLENGE_NA_REASON", item="T2", reason="nr_x",
                      allowed="This item takes no not_applicable reason; answer present or absent.").envelope()
    assert "Allowed: ." not in env["fix"] and "T2" in env["what"]


@ASYNC
async def test_second_answer_on_an_answered_revision_says_frozen_and_partial_is_announced(db_pool) -> None:
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool, chain="solana")
    _write_minimal_map(pin_root, job_id)
    sub = await _submit_f01(db_pool, job_id, pin_root)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(MemoryJobContext(pin_root))
    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": sub["draft_key"]})
    items = [i["id"] for i in ch["items"]]
    # answer one item fewer than asked: the answer is recorded, partial, and says so first
    answers = []
    for iid in items[:-1]:
        if iid == "MB0":
            answers.append({"item_id": iid, "value": "present", "quotes": [_CALL_LINE],
                            "note": "The blocked transfer is the seizure from the escrow to the lender."})
        elif iid == "MB1":
            answers.append({"item_id": iid, "value": "present", "quotes": [_WRITE_LINE],
                            "note": "The frozen amount is the whole collateral vault."})
        else:
            answers.append({"item_id": iid, "value": "absent", "refs": ["src/Vault.sol:1-9"],
                            "note": "Nothing in the instruction lets the parties finish without this account."})
    res = await challenge_mod.handle_review_answer_challenge(
        {"job_id": job_id, "draft_key": sub["draft_key"], "revision": sub["revision"], "answers": answers})
    assert res["accepted"] is True and res["complete"] is False, res
    assert res["warnings"][0]["code"] == "E_CHALLENGE_PARTIAL", res["warnings"]
    assert items[-1] in res["warnings"][0]["what"]
    again = await challenge_mod.handle_review_answer_challenge(
        {"job_id": job_id, "draft_key": sub["draft_key"], "revision": sub["revision"], "answers": answers[:-1]})
    assert again["accepted"] is False
    err = again["errors"][0]
    assert err["code"] == "E_REVISION_ANSWERED", err
    assert f"revision {sub['revision'] + 1}" in err["fix"]


# ── d) duplicate_of rules are documented ──────────────────────────────────────────────────────────


def test_every_duplicate_rule_the_server_returns_is_documented() -> None:
    src = (SRC / "tools" / "dismiss.py").read_text(encoding="utf-8")
    used = set(re.findall(r'_dup_error\("([A-Za-z0-9_]+)"\)', src))
    doc = yaml.safe_load((RUBRIC / "lead_links.yaml").read_text(encoding="utf-8"))
    ids = {r["id"] for r in doc["rules"]}
    assert used and used <= ids, used - ids
    assert {"D1_category_mismatch", "D3_no_overlap"} <= used


def test_challenge_rules_topic_lists_the_duplicate_rules_and_the_error_carries_the_text() -> None:
    from soken_review.tools.dismiss import _dup_error
    from soken_review.tools.guide import _render_topic

    text = _render_topic("challenge_rules", "evm")
    assert "D1_category_mismatch" in text and "D3_no_overlap" in text
    env = _dup_error("D3_no_overlap").envelope()
    assert "overlap" in env["what"] and env["fix"].startswith("Add a location quote")
