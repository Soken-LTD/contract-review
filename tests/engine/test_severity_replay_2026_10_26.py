"""Replay of the eight server overrides of the blind run 2026-10-26 (JUDGEMENT.md sections 1.3, 2.3,
3.3, 4.3, 5.3 and 6). Expected values are the judge's. Each case runs the matrix an honest reviewer
would pick with the 2026-10-27 engine; where the reviewer's number differs from the cell, the case
also runs the reviewer's claimed_severity with a reason, which is the client path.

Before the change the server printed: Solana F-02 High (+1), TON CreateSquad Medium (+1), TRON F-01
and F-02 Low (-1 each), BNB F-01 High (+1), Apyee F-01 Medium (-1), F-03 Informational (-2), F-06
Low (+1). In zero of eight did the override improve on the reviewer.
"""

from __future__ import annotations

from typing import ClassVar

from soken_review.engine.severity import SeverityContext, compute_severity

_POST = {"evidence_level": "reasoning_challenged", "has_attack_steps": True}


def _sev(matrix: dict[str, str], phase: str = "submit", **ctx) -> tuple[str, list[str], str]:
    r = compute_severity(matrix, phase, SeverityContext(phase=phase, **ctx))
    return r.severity, r.caps_applied, r.set_by


class TestSolanaLockAndLoan:
    F02: ClassVar[dict[str, str]] = {"impact_class": "permanent_freeze", "magnitude": "unbounded", "trigger": "permissionless_role",
           "precondition": "normal_operation", "reversibility": "admin_reversible"}   # I3xL3 = High by the cell

    def test_f02_lender_self_harm_prints_the_reviewers_medium(self):
        reason = "The lender gains nothing, forfeits its own repayment, and can lift the block by restoring the ATA."
        sev, rules, by = _sev(self.F02, claimed_severity="Medium", claimed_reason=reason)
        assert (sev, by) == ("Medium", "reviewer") and rules == ["RV1:reviewer=Medium"]

    def test_f02_reclassified_as_griefing_is_medium_by_the_cell(self):
        sev, rules, _ = _sev({**self.F02, "impact_class": "griefing_with_victim_loss"})
        assert sev == "Medium" and rules == []

    def test_f02_without_a_claim_is_still_high_and_says_so(self):
        sev, _, by = _sev(self.F02)
        assert (sev, by) == ("High", "matrix")

    def test_f01_borrower_block_not_covered_scope_applies_no_cap(self):
        """The ata_owner_reassign items shipped empty scopes; K10 capped F-01 at High for ever. A scope
        the map could not supply is no cap since 2026-10-27: the cell (Critical) or the reviewer's
        High with a reason (RV1) prints, never a rule the reviewer cannot answer."""
        f01 = {**self.F02, "reversibility": "irreversible"}
        sev, rules, by = _sev(f01, "post_challenge", **_POST, scope_not_covered=True, severity_before="Critical")
        assert (sev, rules, by) == ("Critical", [], "matrix")
        reason = "The borrower needs the loan to default first and the lender keeps the collateral claim path."
        sev, rules, by = _sev(f01, "post_challenge", **_POST, scope_not_covered=True, severity_before="High",
                              claimed_severity="High", claimed_reason=reason)
        assert (sev, by) == ("High", "reviewer") and rules == ["RV1:reviewer=High"]

    def test_no_contract_map_still_caps_at_high(self):
        f01 = {**self.F02, "reversibility": "irreversible"}
        sev, rules, _ = _sev(f01, "post_challenge", **_POST, map_unavailable=True, severity_before="Critical")
        assert sev == "High" and rules == ["K10"]


class TestTonForton:
    CREATE_SQUAD: ClassVar[dict[str, str]] = {"impact_class": "theft_of_funds", "magnitude": "unbounded", "trigger": "anyone",
                    "precondition": "uncommon_protocol_state", "reversibility": "irreversible"}

    def test_create_squad_with_residual_magnitude_is_low(self):
        sev, rules, _ = _sev({**self.CREATE_SQUAD, "magnitude": "residual"})
        assert sev == "Low" and rules == []

    def test_create_squad_as_filed_now_prints_high_under_irr1_so_the_claim_matters(self):
        # as filed (unbounded) the cell is High under IRR1: the reviewer's Low is two steps away and
        # the server asks for the mitigating classification instead of printing either value
        r = compute_severity(self.CREATE_SQUAD, "submit",
                             SeverityContext(claimed_severity="Low",
                                             claimed_reason="The master balance normally stays close to the storage reserve."))
        assert r.confirm_needed and r.computed == "High"


class TestTronCrs:
    F01: ClassVar[dict[str, str]] = {"impact_class": "supply_inflation", "magnitude": "bounded", "trigger": "anyone",
           "precondition": "normal_operation", "reversibility": "irreversible"}
    F02: ClassVar[dict[str, str]] = {**F01, "reversibility": "admin_reversible"}

    def test_f01_burn_double_count_is_medium(self):
        assert _sev(self.F01)[0] == "Medium"

    def test_f02_stale_exclusion_balance_is_medium(self):
        assert _sev(self.F02)[0] == "Medium"

    def test_the_old_classes_still_compute_low_which_is_why_the_class_was_added(self):
        assert _sev({**self.F01, "impact_class": "spec_deviation_bounded"})[0] == "Low"
        assert _sev({**self.F01, "impact_class": "incorrect_accounting_no_fund_effect"})[0] == "Low"

    def test_f01_survives_a_passed_challenge_at_medium(self):
        sev, _, _ = _sev(self.F01, "post_challenge", **_POST, token_review=True, severity_before="Medium")
        assert sev == "Medium"


class TestBnbAnttime:
    F01: ClassVar[dict[str, str]] = {"impact_class": "permanent_freeze", "magnitude": "unbounded", "trigger": "privileged_role",
           "precondition": "normal_operation", "reversibility": "admin_reversible"}

    def test_owner_pause_on_a_retail_token_is_medium_and_the_rule_is_printed(self):
        r = compute_severity(self.F01, "submit", SeverityContext(token_review=True, has_location_quote=True))
        assert r.severity == "Medium" and r.severity_rule == "I3xL1=Medium set_by=matrix"

    def test_owner_pause_challenged_stays_medium(self):
        sev, _, _ = _sev(self.F01, "post_challenge", **_POST, token_review=True, has_location_quote=True,
                         severity_before="Medium")
        assert sev == "Medium"

    def test_a_pause_with_no_unpause_is_the_retail_threat(self):
        sev, rules, _ = _sev({**self.F01, "reversibility": "irreversible"}, token_review=True)
        assert sev == "Critical" and "TR1" in rules


class TestApyeeV2:
    F01: ClassVar[dict[str, str]] = {"impact_class": "permanent_freeze", "magnitude": "unbounded", "trigger": "anyone",
           "precondition": "uncommon_protocol_state", "reversibility": "irreversible"}
    F03: ClassVar[dict[str, str]] = {"impact_class": "yield_or_fee_loss", "magnitude": "bounded", "trigger": "anyone",
           "precondition": "normal_operation", "reversibility": "irreversible"}
    F06: ClassVar[dict[str, str]] = {"impact_class": "spec_deviation_bounded", "magnitude": "bounded", "trigger": "anyone",
           "precondition": "normal_operation", "reversibility": "irreversible"}

    def test_f01_vault_brick_is_high_at_submit_and_after_the_challenge(self):
        sev, rules, _ = _sev(self.F01)
        assert sev == "High" and rules == ["IRR1"]
        sev2, _, _ = _sev(self.F01, "post_challenge", **_POST, severity_before="High")
        assert sev2 == "High"

    def test_f01_with_the_uncommon_state_cap_still_not_medium_when_mb2_falls_back(self):
        # the reviewer filed normal_operation; MB2 answered present moved it to uncommon_protocol_state
        filed = {**self.F01, "precondition": "normal_operation"}
        assert _sev(filed)[0] == "Critical"
        sev, rules, _ = _sev(self.F01, "post_challenge", **_POST, severity_before="Critical")
        assert sev == "High" and "IRR1" in rules

    def test_f03_two_stacked_downgrades_leave_a_low_not_informational(self):
        assert _sev(self.F03)[0] == "Medium"                       # the cell the judge agrees with
        after_mb6 = {**self.F03, "magnitude": "dust"}              # MB6 answered against expectation
        sev, rules, _ = _sev(after_mb6, "post_challenge", **_POST, downgrade_items_present=1,   # plus L3
                             severity_before="Medium")
        assert sev == "Low" and "DG1" in rules

    def test_f03_the_reviewers_low_stands_at_submit(self):
        sev, _, by = _sev(self.F03, claimed_severity="Low",
                          claimed_reason="The leak per cycle is bounded by the fee rate and the time since the last accrual.")
        assert (sev, by) == ("Low", "reviewer")

    def test_f06_receiver_only_cap_prints_the_reviewers_informational(self):
        assert _sev(self.F06)[0] == "Low"
        sev, _, by = _sev(self.F06, claimed_severity="Informational",
                          claimed_reason="A soft-launch per-address cap that transfers get around; no value at risk.")
        assert (sev, by) == ("Informational", "reviewer")
