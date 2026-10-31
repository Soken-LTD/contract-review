"""Reviewer-first severity rules (2026-10-27, blind run 2026-10-26 judgement section 6 and 9.1).

One test class per rule change: supply_inflation and residual (new matrix values), IRR1
(irreversibility outweighs state rarity), TR1 (retail-token waiver needs an irreversible owner
path), RV1 (thin server 2026-10-31: the reviewer's severity is final, the matrix is a calibration),
challenges never move the severity, the verdict payload (set_by, reason, calibration) and the
rule registry the client can dispute (contract/rubric/severity_rules.yaml).
"""

from __future__ import annotations

from typing import ClassVar

import yaml

from soken_review.contract import CONTRACT_DIR
from soken_review.engine.severity import (
    RULE_TEXT,
    SeverityContext,
    compute_severity,
    explain_rules,
    impact_level,
    rule_text,
)


def _m(**kw: str) -> dict[str, str]:
    base = {"impact_class": "theft_of_funds", "magnitude": "unbounded", "trigger": "anyone",
            "precondition": "normal_operation", "reversibility": "irreversible"}
    base.update(kw)
    return base


_POST = {"phase": "post_challenge", "evidence_level": "reasoning_challenged", "has_attack_steps": True}


class TestSupplyInflation:
    def test_is_a_direct_loss_row(self):
        assert impact_level("supply_inflation", "unbounded", "irreversible") == 4
        assert impact_level("supply_inflation", "bounded", "irreversible") == 2
        assert impact_level("supply_inflation", "residual", "irreversible") == 1
        assert impact_level("supply_inflation", "dust", "irreversible") == 1

    def test_unlimited_mint_by_anyone_is_critical(self):
        r = compute_severity(_m(impact_class="supply_inflation"), "submit", SeverityContext())
        assert r.severity == "Critical" and r.set_by == "matrix"

    def test_bounded_fee_double_count_by_anyone_is_medium(self):
        # TRON CRS F-01: each transfer grows the sum of balances by the burn fee; bound_ref = the fee rate
        r = compute_severity(_m(impact_class="supply_inflation", magnitude="bounded"), "submit", SeverityContext())
        assert r.severity == "Medium"

    def test_reversibility_does_not_reclass_inflation(self):
        # includeAccount can undo an exclusion but not the balances already inflated
        assert impact_level("supply_inflation", "bounded", "admin_reversible") == 2


class TestResidualMagnitude:
    def test_one_level_under_bounded_floor_one(self):
        assert impact_level("theft_of_funds", "residual", "irreversible") == 1
        assert impact_level("yield_or_fee_loss", "residual", "irreversible") == 1
        assert impact_level("griefing_with_victim_loss", "residual", "irreversible") == 1

    def test_magnitude_free_classes_keep_their_value(self):
        assert impact_level("control_takeover", "residual", "irreversible") == 4
        assert impact_level("dos_core_function", "residual", "irreversible") == 2
        assert impact_level("centralization_risk", "residual", "irreversible") == 2

    def test_residual_theft_prints_low_without_the_dust_cap(self):
        # TON FtMaster CreateSquad: whoever creates a squad next takes the stranded master balance
        r = compute_severity(_m(magnitude="residual", precondition="uncommon_protocol_state"), "submit",
                             SeverityContext())
        assert r.severity == "Low" and "K3" not in r.caps_applied

    def test_dust_still_caps_control_takeover_but_residual_does_not(self):
        dust = compute_severity(_m(impact_class="control_takeover", magnitude="dust"), "submit", SeverityContext())
        residual = compute_severity(_m(impact_class="control_takeover", magnitude="residual"), "submit",
                                    SeverityContext())
        assert dust.severity == "Low" and "K3" in dust.caps_applied
        assert residual.severity == "Critical"


class TestIRR1:
    def test_irreversible_unbounded_loss_under_uncommon_state_is_high(self):
        # Apyee F-01: permanent freeze of all funds, anyone, once supply returns to zero
        r = compute_severity(_m(impact_class="permanent_freeze", precondition="uncommon_protocol_state"), "submit",
                             SeverityContext())
        assert r.severity == "High" and r.l_level == 2 and "IRR1" in r.caps_applied
        assert r.severity_rule.startswith("I4xL2=High caps=[IRR1]")

    def test_bounded_loss_keeps_l1(self):
        r = compute_severity(_m(magnitude="bounded", precondition="uncommon_protocol_state"), "submit",
                             SeverityContext())
        assert r.severity == "Low" and "IRR1" not in r.caps_applied

    def test_admin_reversible_freeze_keeps_l1(self):
        r = compute_severity(_m(impact_class="permanent_freeze", precondition="uncommon_protocol_state",
                                reversibility="admin_reversible"), "submit", SeverityContext())
        assert r.severity == "Medium" and "IRR1" not in r.caps_applied

    def test_privileged_trigger_is_not_lifted(self):
        r = compute_severity(_m(trigger="privileged_role", precondition="uncommon_protocol_state"), "submit",
                             SeverityContext())
        assert "IRR1" not in r.caps_applied and r.severity == "Medium"

    def test_other_rare_preconditions_untouched(self):
        r = compute_severity(_m(precondition="external_failure"), "submit", SeverityContext())
        assert r.l_level == 0 and "IRR1" not in r.caps_applied


class TestTR1:
    OWNER_PAUSE: ClassVar[dict[str, str]] = _m(impact_class="permanent_freeze", trigger="privileged_role", reversibility="admin_reversible")
    OWNER_BRICK: ClassVar[dict[str, str]] = _m(impact_class="permanent_freeze", trigger="privileged_role", reversibility="irreversible")

    def test_owner_pause_on_a_retail_token_is_medium_with_k1(self):
        # BNB ANTTIME F-01: the owner can pause transfers; unpause exists; renounce while paused is self-sabotage
        r = compute_severity(self.OWNER_PAUSE, "submit", SeverityContext(token_review=True, has_location_quote=True))
        assert r.severity == "Medium" and "TR1" not in r.caps_applied
        assert r.severity_rule == "I3xL1=Medium set_by=matrix"

    def test_owner_pause_high_cell_is_capped_by_k1_and_named(self):
        m = {**self.OWNER_PAUSE, "impact_class": "theft_of_funds", "reversibility": "admin_reversible"}
        r = compute_severity(m, "submit", SeverityContext(token_review=True))
        assert r.severity == "Medium" and r.l_level == 1

    def test_irreversible_owner_path_waives_k1_and_names_tr1(self):
        r = compute_severity(self.OWNER_BRICK, "submit", SeverityContext(token_review=True, has_location_quote=True))
        assert r.severity == "Critical" and "TR1" in r.caps_applied and "K1" not in r.caps_applied
        assert r.reason.startswith("TR1:")

    def test_no_retail_profile_no_waiver(self):
        r = compute_severity(self.OWNER_BRICK, "submit", SeverityContext(token_review=False))
        assert r.severity == "Medium" and "TR1" not in r.caps_applied

    def test_supply_inflation_by_owner_is_a_direct_loss(self):
        m = _m(impact_class="supply_inflation", trigger="privileged_role")
        r = compute_severity(m, "submit", SeverityContext(token_review=True))
        assert r.severity == "Critical" and "TR1" in r.caps_applied


class TestRV1Submit:
    """Thin server (CEO decision 2026-10-31): the reviewer's claim is the printed severity, always.
    The matrix outcome after every cap is the calibration; the server never confirms or clamps."""
    REASON = "The lender forfeits its own repayment and gains nothing; the block is reversible by the lender."
    HIGH: ClassVar[dict[str, str]] = _m(impact_class="permanent_freeze", trigger="permissionless_role", reversibility="admin_reversible")

    def test_no_claim_prints_the_matrix(self):
        r = compute_severity(self.HIGH, "submit", SeverityContext())
        assert r.severity == "High" and r.set_by == "matrix" and r.reason == "matrix cell, no reviewer proposal"
        assert r.calibration == "High"

    def test_claim_equal_to_the_matrix_is_set_by_reviewer(self):
        r = compute_severity(self.HIGH, "submit", SeverityContext(claimed_severity="High"))
        assert r.severity == "High" and r.set_by == "reviewer" and not r.confirm_needed

    def test_one_step_down_with_reason_stands(self):
        # Solana Lock & Loan F-02: lender self-harm, reviewer Medium, matrix High
        r = compute_severity(self.HIGH, "submit", SeverityContext(claimed_severity="Medium", claimed_reason=self.REASON))
        assert r.severity == "Medium" and r.set_by == "reviewer" and r.reason == self.REASON
        assert r.calibration == "High" and r.computed == "High" and not r.confirm_needed

    def test_one_step_up_with_reason_stands_when_no_cap_binds(self):
        m = _m(magnitude="bounded")   # I2xL3 = Medium
        r = compute_severity(m, "submit", SeverityContext(claimed_severity="High", claimed_reason=self.REASON))
        assert r.severity == "High" and r.set_by == "reviewer" and r.calibration == "Medium"

    def test_a_cap_is_a_calibration_note_never_a_ceiling(self):
        m = _m(magnitude="dust")      # Low, K3
        r = compute_severity(m, "submit", SeverityContext(claimed_severity="Medium", claimed_reason=self.REASON))
        assert r.severity == "Medium" and r.set_by == "reviewer" and not r.confirm_needed
        assert r.calibration == "Low" and "K3: magnitude dust caps at Low" in r.calibration_rule

    def test_a_claim_without_a_reason_stands(self):
        r = compute_severity(self.HIGH, "submit", SeverityContext(claimed_severity="Medium"))
        assert r.severity == "Medium" and r.set_by == "reviewer" and not r.confirm_needed
        assert r.reason == "reviewer's severity"

    def test_two_steps_away_stands_with_the_matrix_as_calibration(self):
        r = compute_severity(self.HIGH, "submit", SeverityContext(claimed_severity="Low", claimed_reason=self.REASON))
        assert r.severity == "Low" and not r.confirm_needed and r.calibration == "High"

    def test_upward_two_steps_stands_too(self):
        r = compute_severity(_m(magnitude="dust"), "submit",
                             SeverityContext(claimed_severity="High", claimed_reason=self.REASON))
        assert r.severity == "High" and r.calibration == "Low" and not r.confirm_needed

    def test_k7_cap_on_an_eoa_owner_is_only_a_calibration(self):
        # Magnum r5 L-001: centralization_risk, reviewer Medium, K7 printed Low (the reviewer was right)
        m = _m(impact_class="centralization_risk", trigger="privileged_role", precondition="none")
        r = compute_severity(m, "submit", SeverityContext(claimed_severity="Medium"))
        assert r.severity == "Medium" and r.calibration == "Low" and "K7" in r.calibration_rule


class TestRV1AfterChallenge:
    REASON = "The amount is bounded by the fee rate and the time since the last accrual, a small leak."

    def test_reviewer_choice_survives_a_passed_challenge(self):
        m = _m(impact_class="yield_or_fee_loss", magnitude="bounded")   # Medium
        ctx = SeverityContext(**_POST, claimed_severity="Low", claimed_reason=self.REASON, severity_before="Low")
        r = compute_severity(m, "post_challenge", ctx)
        assert r.severity == "Low" and r.set_by == "reviewer"

    def test_a_moved_matrix_moves_only_the_calibration(self):
        m = _m(magnitude="dust")      # Low (K3) after a basis fallback; reviewer had Critical
        ctx = SeverityContext(**_POST, claimed_severity="Critical", claimed_reason=self.REASON,
                              severity_before="Critical")
        r = compute_severity(m, "post_challenge", ctx)
        assert r.severity == "Critical" and r.calibration == "Low" and "DG1" not in r.caps_applied


class TestChallengeNeverMovesSeverity:
    def test_downgrade_items_lower_the_calibration_only(self):
        # Apyee F-03: Medium at submit; L3 present (K5) plus MB6 (magnitude dust)
        after_mb6 = _m(impact_class="yield_or_fee_loss", magnitude="dust")
        ctx = SeverityContext(**_POST, downgrade_items_present=1, severity_before="Medium")
        r = compute_severity(after_mb6, "post_challenge", ctx)
        assert r.severity == "Medium" and r.set_by == "matrix"
        assert r.calibration == "Informational" and "K5" in r.caps_applied

    def test_k8_is_a_note_on_an_unchallenged_critical(self):
        ctx = SeverityContext(phase="finalize", evidence_level="reasoning_only", has_attack_steps=False,
                              challenge_skipped=True, severity_before="Critical", claimed_severity="Critical")
        r = compute_severity(_m(), "finalize", ctx)
        assert r.severity == "Critical" and r.calibration == "High" and "K8" in r.caps_applied

    def test_finalize_without_a_claim_keeps_the_submit_outcome(self):
        ctx = SeverityContext(phase="finalize", evidence_level="reasoning_challenged", has_attack_steps=True,
                              downgrade_items_present=1, severity_before="Critical")
        r = compute_severity(_m(), "finalize", ctx)
        assert r.severity == "Critical" and r.calibration == "High"

    def test_submit_ignores_severity_before(self):
        r = compute_severity(_m(magnitude="dust"), "submit", SeverityContext(severity_before="Critical"))
        assert r.severity == "Low" and "DG1" not in r.caps_applied


class TestPayloadAndRegistry:
    def test_every_rule_the_engine_emits_is_in_the_registry(self):
        doc = yaml.safe_load((CONTRACT_DIR / "rubric" / "severity_rules.yaml").read_text(encoding="utf-8"))
        ids = {str(r["id"]) for r in doc["rules"]}
        assert set(RULE_TEXT) <= ids, set(RULE_TEXT) - ids
        assert "max_severity" in ids
        for r in doc["rules"]:
            assert r.get("condition") and r.get("phase")

    def test_rule_text_covers_every_label_shape(self):
        assert rule_text("K1").startswith("trigger privileged_role")
        assert rule_text("RV1:reviewer=Medium").endswith("(reviewer=Medium)")
        assert rule_text("MB1:magnitude=bounded") == "basis item MB1 answered against expectation: magnitude becomes bounded"
        assert rule_text("max_severity:Informational").endswith("at Informational")
        assert rule_text("kill:A1").startswith("kill item A1")

    def test_explain_rules_is_bounded(self):
        text = explain_rules(["K1", "K3", "K6", "K7", "K11", "K8", "K10", "K4", "DG1"], limit=120)
        assert len(text) <= 120 and text.startswith("K1: ")

    def test_severity_rule_names_set_by(self):
        r = compute_severity(_m(), "submit", SeverityContext())
        assert r.severity_rule == "I4xL3=Critical set_by=matrix" and r.rules == r.caps_applied
