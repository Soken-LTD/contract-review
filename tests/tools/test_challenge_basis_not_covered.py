"""A NOT_COVERED challenge scope caps the severity (K10); it never zeroes it through forced basis
fallbacks, and every verdict names its cause (Solana blind run 2026-10-26, ata_owner_reassign).

Replayed inputs: F-01 "Borrower can block claim_default by reassigning the owner of their USDC
ATA": permanent_freeze / unbounded / permissionless_role / normal_operation / irreversible, computed
Critical at submit. The location is an Accounts struct that no function span covers, so every item
scope was `not_covered`. The reviewer answered the kill and downgrade items absent, MB0 and MB1
present with quotes matched to the pinned source, MB2 and MB3 absent. The server applied the MB0
and MB1 fallbacks anyway (impact incorrect_accounting, magnitude bounded) and printed Low with
`caps_applied: []`.
"""

from __future__ import annotations

from typing import Any

import pytest

from soken_review.engine.severity import SeverityContext, compute_severity
from soken_review.tools.challenge import _basis_items, basis_fallback, fallback_labels

from .test_write_tools import ASYNC, _create_ready_job_with_pin, _write_minimal_map

F01_MATRIX = {"impact_class": "permanent_freeze", "magnitude": "unbounded", "trigger": "permissionless_role",
              "precondition": "normal_operation", "reversibility": "irreversible"}
F02_MATRIX = {**F01_MATRIX, "reversibility": "admin_reversible"}


def _items_by_id(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {i["id"]: i for i in _basis_items(matrix)}


class TestBasisFallbackDecision:
    def test_present_with_verified_quote_on_not_covered_scope_keeps_the_matrix(self):
        items = _items_by_id(F01_MATRIX)
        assert basis_fallback(items["MB0"], "present", scope_not_covered=True, quote_verified=True) is None
        assert basis_fallback(items["MB1"], "present", scope_not_covered=True, quote_verified=True) is None

    def test_present_without_a_verified_quote_still_falls_back_and_says_why(self):
        items = _items_by_id(F01_MATRIX)
        fb = basis_fallback(items["MB1"], "present", scope_not_covered=True, quote_verified=False)
        assert fb == {"item": "MB1", "field": "magnitude", "value": "bounded", "why": "present_without_verified_quote"}

    def test_answer_against_expectation_falls_back_whatever_the_scope(self):
        items = _items_by_id(F01_MATRIX)
        fb = basis_fallback(items["MB0"], "absent", scope_not_covered=False, quote_verified=False)
        assert fb["field"] == "impact_class" and fb["value"] == "incorrect_accounting_no_fund_effect"
        assert fb["why"] == "answer_differs_from_expected"
        fb2 = basis_fallback(items["MB2"], "present", scope_not_covered=True, quote_verified=True)
        assert fb2["field"] == "precondition" and fb2["value"] == "uncommon_protocol_state"

    def test_non_basis_items_never_fall_back(self):
        assert basis_fallback({"id": "W1", "kind": "kill"}, "present", scope_not_covered=True, quote_verified=True) is None

    def test_fallback_labels_name_item_field_and_value(self):
        assert fallback_labels([{"item": "MB1", "field": "magnitude", "value": "bounded", "why": "x"}]) == \
            ["MB1:magnitude=bounded"]


class TestSeverityReplay:
    """The matrix the reviewer defended, through the post-challenge chain with the scope not covered."""

    def _ctx(self, prior: str = "reasoning_only") -> SeverityContext:
        return SeverityContext(phase="post_challenge", evidence_level=prior, has_attack_steps=True,
                               open_downgrade_item=False, downgrade_items_present=0, scope_not_covered=True,
                               map_unavailable=False, category_generic=False, category_max_severity=None,
                               linked_lead_same_cat=False, token_review=False, has_location_quote=True)

    def test_f01_stays_high_with_the_cap_named(self):
        r = compute_severity(F01_MATRIX, "post_challenge", self._ctx())
        assert r.base == "Critical" and r.severity == "High"
        assert r.caps_applied and set(r.caps_applied) <= {"K8", "K10"}
        assert r.severity_rule.startswith("I4xL3=Critical caps=[")

    def test_f01_with_analyzer_evidence_is_capped_by_k10_only(self):
        r = compute_severity(F01_MATRIX, "post_challenge", self._ctx("analyzer_and_reasoning"))
        assert r.severity == "High" and r.caps_applied == ["K10"]

    def test_f02_passes_as_high(self):
        r = compute_severity(F02_MATRIX, "post_challenge", self._ctx())
        assert r.severity == "High" and r.caps_applied == []

    def test_the_old_forced_fallbacks_were_the_low(self):
        # What the server did before: MB0 and MB1 forced -> I1 -> Low, no cap recorded.
        forced = {**F01_MATRIX, "impact_class": "incorrect_accounting_no_fund_effect", "magnitude": "bounded"}
        r = compute_severity(forced, "post_challenge", self._ctx())
        assert r.severity == "Low" and r.caps_applied == []


# ── handler replay against Postgres ─────────────────────────────────────────

_LOCATION = {"file": "src/Vault.sol", "start": 5, "end": 8, "role": "location",
             "text": ("    function withdraw(uint256 a) external {\n"
                      '        (bool ok, ) = msg.sender.call{value: a}("");\n'
                      "        balances[msg.sender] -= a;\n"
                      "    }")}
_CALL_LINE = {"file": "src/Vault.sol", "start": 6, "end": 6, "text": '        (bool ok, ) = msg.sender.call{value: a}("");'}
_WRITE_LINE = {"file": "src/Vault.sol", "start": 7, "end": 7, "text": "        balances[msg.sender] -= a;"}


async def _submit_f01(db_pool, job_id: str, pin_root) -> dict[str, Any]:
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    return await submit_mod.handle_review_submit_finding({
        "job_id": job_id, "draft_key": "default-blocked-by-ata-owner-reassign",
        "category": "solana.ata_owner_reassign", "quotes": [_LOCATION], "matrix": F01_MATRIX, "lead_ids": [],
        "title": "Borrower can block claim_default by reassigning the owner of the recipient token account",
        "body": {"description": [{"p": "The recipient token account is required with a fixed derived address."}],
                 "impact": [{"p": "The lender loses the seizure path while the loan stays active."}],
                 "recommendation": [{"p": "Make the surplus account optional."}]},
        "attack_steps": [{"text": "The borrower reassigns the owner of the token account.", "ref": "src/Vault.sol:6"}],
    })


@ASYNC
async def test_answer_challenge_on_not_covered_scope_keeps_high_and_names_the_cap(db_pool):
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool, chain="solana")
    _write_minimal_map(pin_root, job_id)          # a semantic layer with no function covering the location
    ctx = MemoryJobContext(pin_root)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    sub = await _submit_f01(db_pool, job_id, pin_root)
    assert sub["accepted"] is True, sub
    assert sub["computed_severity"] == "Critical" and sub["status"] == "needs_challenge"
    draft_key, revision = sub["draft_key"], sub["revision"]

    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": draft_key})
    assert ch["accepted"] is True, ch
    items = {i["id"]: i for i in ch["items"]}
    assert all(i["scope"].get("not_covered") for i in items.values()), items
    assert {"W0", "W0b", "W1", "W3", "W2", "MB0", "MB1", "MB2", "MB3"} <= set(items)

    answers = []
    for iid in items:
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
        {"job_id": job_id, "draft_key": draft_key, "revision": revision, "answers": answers})
    assert res["accepted"] is True, res
    assert res["severity_before"] == "Critical"
    assert res["severity_after"] == "High", res
    assert res["verdict"] == "downgraded"
    assert res["caps_applied"] and all(c.startswith("K") for c in res["caps_applied"]), res
    assert res["severity_rule"].startswith("I4xL3=Critical caps=[") and "basis=" not in res["severity_rule"]

    async with db_pool.connection() as conn:
        row = await (await conn.execute(
            "select severity, matrix_effective, caps_applied from finding_drafts where job_id = %s and draft_key = %s",
            (job_id, draft_key))).fetchone()
    assert row[0] == "High"
    assert row[1]["impact_class"] == "permanent_freeze" and row[1]["magnitude"] == "unbounded"
    assert list(row[2]) == res["caps_applied"]


@ASYNC
async def test_answer_without_quote_on_a_present_basis_item_is_incomplete(db_pool):
    """A present basis answer without a quote is rejected (so it can never be a silent fallback)."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool, chain="solana")
    _write_minimal_map(pin_root, job_id)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(MemoryJobContext(pin_root))
    sub = await _submit_f01(db_pool, job_id, pin_root)
    if sub.get("status") != "needs_challenge":
        pytest.skip("submission did not reach needs_challenge")
    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": sub["draft_key"]})
    answers = [{"item_id": i["id"], "value": "present" if i["id"] == "MB1" else "absent",
                "refs": ["src/Vault.sol:1-9"], "note": "n"} for i in ch["items"]]
    res = await challenge_mod.handle_review_answer_challenge(
        {"job_id": job_id, "draft_key": sub["draft_key"], "revision": sub["revision"], "answers": answers})
    assert res["accepted"] is False
    assert any(e["code"] == "E_CHALLENGE_INCOMPLETE" for e in res["errors"]), res
