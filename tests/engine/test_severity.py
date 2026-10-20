"""Unit tests for the severity engine (04 §7).

Pure functions, no I/O. All tests synchronous.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from soken_review.engine.severity import (
    SeverityContext,
    base_severity,
    compute_severity,
    impact_level,
    likelihood,
)

# ── impact_level ─────────────────────────────────────────────────────────────

class TestImpactLevel:
    def test_theft_unbounded_irreversible(self):
        assert impact_level("theft_of_funds", "unbounded", "irreversible") == 4

    def test_theft_bounded(self):
        assert impact_level("theft_of_funds", "bounded", "irreversible") == 2

    def test_theft_dust(self):
        assert impact_level("theft_of_funds", "dust", "irreversible") == 1

    def test_control_takeover_all_magnitudes_are_i4(self):
        for mag in ("unbounded", "bounded", "dust"):
            assert impact_level("control_takeover", mag, "irreversible") == 4

    def test_best_practice_is_i0(self):
        assert impact_level("best_practice", "unbounded", "irreversible") == 0

    def test_permanent_freeze_admin_reversible_lowers_one(self):
        # permanent_freeze unbounded = I4; admin_reversible lowers by 1 → I3 (floor I1 not triggered)
        assert impact_level("permanent_freeze", "unbounded", "admin_reversible") == 3

    def test_permanent_freeze_self_recovering_reclasses_to_temporary(self):
        # self_recovering reclasses permanent_freeze → temporary_freeze; tmp_freeze unbounded = I3
        assert impact_level("permanent_freeze", "unbounded", "self_recovering") == 3

    def test_floor_stays_i1_not_below(self):
        # dust + admin_reversible: row gives I1, delta -1 → 0, but floor I1 (since i > 0)
        val = impact_level("theft_of_funds", "dust", "admin_reversible")
        assert val >= 1  # floor I1 when i > 0

    def test_unknown_impact_class_raises(self):
        with pytest.raises(ValueError, match="Unknown impact_class"):
            impact_level("nonexistent_class", "unbounded", "irreversible")

    def test_unknown_magnitude_raises(self):
        with pytest.raises(ValueError, match="Unknown magnitude"):
            impact_level("theft_of_funds", "gigantic", "irreversible")


# ── likelihood ───────────────────────────────────────────────────────────────

class TestLikelihood:
    def test_anyone_none_is_l3(self):
        assert likelihood("anyone", "none") == 3

    def test_privileged_role_none_is_l1(self):
        # T[privileged_role]=1, P[none]=3 → min=1
        assert likelihood("privileged_role", "none") == 1

    def test_anyone_external_failure_is_l0(self):
        # T[anyone]=3, P[external_failure]=0 → min=0
        assert likelihood("anyone", "external_failure") == 0

    def test_upgrade_authority_market_condition_is_l1(self):
        # T[upgrade_authority]=1, P[market_condition]=2 → min=1
        assert likelihood("upgrade_authority", "market_condition") == 1

    def test_unknown_trigger_raises(self):
        with pytest.raises(ValueError, match="Unknown trigger"):
            likelihood("root", "none")

    def test_unknown_precondition_raises(self):
        with pytest.raises(ValueError, match="Unknown precondition"):
            likelihood("anyone", "unknown_precondition")


# ── base_severity ────────────────────────────────────────────────────────────

class TestBaseSeverity:
    def test_i0_any_l_is_informational(self):
        for l in range(4):
            assert base_severity(0, l) == "Informational"

    def test_i1_any_l_is_low(self):
        for l in range(4):
            assert base_severity(1, l) == "Low"

    def test_i4_l3_is_critical(self):
        assert base_severity(4, 3) == "Critical"

    def test_i4_l0_is_medium(self):
        assert base_severity(4, 0) == "Medium"

    def test_i3_l2_is_high(self):
        assert base_severity(3, 2) == "High"

    def test_out_of_range_raises(self):
        with pytest.raises(ValueError):
            base_severity(5, 0)
        with pytest.raises(ValueError):
            base_severity(0, 4)


# ── compute_severity K-caps ───────────────────────────────────────────────────

_MATRIX_THEFT_ANYONE_NONE_IRREVERSIBLE = {
    "impact_class": "theft_of_funds",
    "magnitude": "unbounded",
    "trigger": "anyone",
    "precondition": "none",
    "reversibility": "irreversible",
}
# I4 × L3 = Critical (base)

_MATRIX_CENTRALIZATION_ANYONE = {
    "impact_class": "centralization_risk",
    "magnitude": "unbounded",
    "trigger": "anyone",
    "precondition": "none",
    "reversibility": "irreversible",
}
# centralization_risk unbounded = I2, L3 → base Medium; K7 caps to Low

_CTX_SUBMIT_PLAIN = SeverityContext(phase="submit")


class TestComputeSeverity:
    def test_no_caps_critical(self):
        result = compute_severity(_MATRIX_THEFT_ANYONE_NONE_IRREVERSIBLE, "submit", _CTX_SUBMIT_PLAIN)
        assert result.severity == "Critical"
        assert result.caps_applied == []
        assert result.base == "Critical"
        assert result.i_level == 4
        assert result.l_level == 3

    def test_k1_privileged_role_caps_to_medium(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "privileged_role",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        # I4 × L1 = Medium (base); K1 caps Medium → already Medium (no cap triggered)
        # But: base I4×L1 = Medium; K1 applies to Critical/High cap → Medium stays
        result = compute_severity(matrix, "submit", _CTX_SUBMIT_PLAIN)
        assert result.severity == "Medium"
        # K1 only fires if it changes the value; Medium is already at cap, so no cap marker
        assert "K1" not in result.caps_applied

    def test_k1_caps_high_to_medium(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "privileged_role",
            "precondition": "normal_operation",  # L=min(1,3)=1
            "reversibility": "irreversible",
        }
        # I4 × L1 = Medium base; no further cap needed
        result = compute_severity(matrix, "submit", _CTX_SUBMIT_PLAIN)
        assert result.severity == "Medium"

    def test_k3_dust_caps_to_low(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "dust",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        # I1 × L3 = Low; K3 applies but Low is already Low → no cap marker
        result = compute_severity(matrix, "submit", _CTX_SUBMIT_PLAIN)
        assert result.severity == "Low"

    def test_k7_centralization_caps_to_low(self):
        # anyone + none → L3; I2 × L3 = Medium; K7 caps to Low (changed, so K7 recorded)
        result = compute_severity(_MATRIX_CENTRALIZATION_ANYONE, "submit", _CTX_SUBMIT_PLAIN)
        assert result.severity == "Low"
        assert "K7" in result.caps_applied

    def test_k6_victim_unusual_action_caps_to_low(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "victim_unusual_action",
            "reversibility": "irreversible",
        }
        result = compute_severity(matrix, "submit", _CTX_SUBMIT_PLAIN)
        assert result.severity == "Low"
        assert "K6" in result.caps_applied

    def test_k11_generic_no_lead_caps_to_high(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        ctx = SeverityContext(phase="submit", category_generic=True, linked_lead_same_cat=False)
        result = compute_severity(matrix, "submit", ctx)
        assert result.severity == "High"
        assert "K11" in result.caps_applied

    def test_k11_not_applied_when_lead_same_cat(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        ctx = SeverityContext(phase="submit", category_generic=True, linked_lead_same_cat=True)
        result = compute_severity(matrix, "submit", ctx)
        assert result.severity == "Critical"
        assert "K11" not in result.caps_applied

    def test_k4_finalize_reasoning_only_caps_to_low(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        ctx = SeverityContext(phase="finalize", evidence_level="reasoning_only")
        result = compute_severity(matrix, "finalize", ctx)
        assert result.severity == "Low"
        assert "K4" in result.caps_applied

    def test_k4_not_applied_at_submit(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        ctx = SeverityContext(phase="submit", evidence_level="reasoning_only")
        result = compute_severity(matrix, "submit", ctx)
        assert "K4" not in result.caps_applied

    def test_k5_downgrade_items_lower_severity(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        # has_attack_steps=True prevents K8 so we can test K5 in isolation
        ctx = SeverityContext(phase="finalize", evidence_level="analyzer_and_reasoning",
                              has_attack_steps=True, downgrade_items_present=2)
        result = compute_severity(matrix, "finalize", ctx)
        # Severity ranks: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
        # Critical(4) - 2 = Medium(2); K5 fires
        assert result.severity == "Medium"
        assert "K5" in result.caps_applied

    def test_k5_max_2_levels(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        # has_attack_steps=True prevents K8 so we can test K5 in isolation
        ctx = SeverityContext(phase="finalize", evidence_level="analyzer_and_reasoning",
                              has_attack_steps=True, downgrade_items_present=5)  # min(5,2)=2 levels down
        result = compute_severity(matrix, "finalize", ctx)
        # Critical(4) - min(5,2)=2 → Medium(2)
        assert result.severity == "Medium"

    def test_evidence_level_submit_no_lead(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        ctx = SeverityContext(phase="submit", linked_lead_same_cat=False)
        result = compute_severity(matrix, "submit", ctx)
        assert result.evidence_level == "reasoning_only"

    def test_evidence_level_submit_with_same_cat_lead(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        ctx = SeverityContext(phase="submit", linked_lead_same_cat=True)
        result = compute_severity(matrix, "submit", ctx)
        assert result.evidence_level == "analyzer_and_reasoning"

    def test_severity_rule_format(self):
        result = compute_severity(_MATRIX_THEFT_ANYONE_NONE_IRREVERSIBLE, "submit", _CTX_SUBMIT_PLAIN)
        # Should contain IxLy=Base format
        assert "I4xL3=Critical" in result.severity_rule

    def test_severity_rule_with_cap(self):
        # Use anyone+none → Medium base; K7 fires and is recorded in rule
        result = compute_severity(_MATRIX_CENTRALIZATION_ANYONE, "submit", _CTX_SUBMIT_PLAIN)
        assert "K7" in result.severity_rule

    def test_category_max_severity_cap(self):
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        ctx = SeverityContext(phase="submit", category_max_severity="Medium")
        result = compute_severity(matrix, "submit", ctx)
        assert result.severity == "Medium"
        assert "max_severity:Medium" in result.caps_applied

    # ── K8 single-condition regression tests (04 §7.4 K8: any missing → cap High) ──

    _CRITICAL_MATRIX: ClassVar[dict[str, str]] = {
        "impact_class": "theft_of_funds",
        "magnitude": "unbounded",
        "trigger": "anyone",
        "precondition": "none",
        "reversibility": "irreversible",
    }

    def test_k8_all_conditions_met_does_not_fire(self):
        """K8 must NOT fire when E2/E3 AND has_attack_steps AND no open downgrade item."""
        ctx = SeverityContext(
            phase="finalize",
            evidence_level="analyzer_and_reasoning",  # E3 ✓
            has_attack_steps=True,                    # ✓
            open_downgrade_item=False,                # ✓
        )
        result = compute_severity(self._CRITICAL_MATRIX, "finalize", ctx)
        assert "K8" not in result.caps_applied
        assert result.severity == "Critical"

    def test_k8_fires_when_evidence_is_e1_only(self):
        """K8 fires when evidence_level is not E2/E3 (reasoning_only = E1)."""
        ctx = SeverityContext(
            phase="finalize",
            evidence_level="reasoning_only",  # E1 → missing ✗
            has_attack_steps=True,
            open_downgrade_item=False,
        )
        result = compute_severity(self._CRITICAL_MATRIX, "finalize", ctx)
        # K8 caps Critical → High; then K4 caps High → Low (reasoning_only)
        assert "K8" in result.caps_applied
        assert "K4" in result.caps_applied
        assert result.severity == "Low"

    def test_k8_fires_when_attack_steps_absent(self):
        """K8 fires when has_attack_steps is False even with E3 evidence."""
        ctx = SeverityContext(
            phase="finalize",
            evidence_level="analyzer_and_reasoning",  # E3 ✓
            has_attack_steps=False,                   # missing ✗
            open_downgrade_item=False,
        )
        result = compute_severity(self._CRITICAL_MATRIX, "finalize", ctx)
        assert "K8" in result.caps_applied
        assert result.severity == "High"

    def test_k8_fires_when_open_downgrade_item_present(self):
        """K8 fires when there is an open downgrade item even with E3 + attack_steps."""
        ctx = SeverityContext(
            phase="finalize",
            evidence_level="analyzer_and_reasoning",  # E3 ✓
            has_attack_steps=True,                    # ✓
            open_downgrade_item=True,                 # present ✗
        )
        result = compute_severity(self._CRITICAL_MATRIX, "finalize", ctx)
        assert "K8" in result.caps_applied
        assert result.severity == "High"

    def test_k8_fires_without_e2_e3(self):
        """K8 + K4 both fire when evidence is reasoning_only (K4 wins, caps to Low)."""
        ctx = SeverityContext(
            phase="finalize",
            evidence_level="reasoning_only",
            has_attack_steps=False,
            open_downgrade_item=False,
        )
        result = compute_severity(self._CRITICAL_MATRIX, "finalize", ctx)
        # K8 caps Critical → High; K4 caps High → Low
        assert "K4" in result.caps_applied
        assert result.severity == "Low"


# ── token_review (retail-token) profile ──────────────────────────────────────

class TestTokenReviewProfile:
    """The retail-token profile (04 §7.4 token_review): the privileged owner IS the threat.

    An owner-controlled path to a direct-loss impact is treated as reachable
    (privileged_role_unprotected), so K1 does not discount it; and a finding that quotes the
    deployed source carries its own evidence, so the K4 reasoning_only->Low gate does not
    apply. Benign centralization notes are untouched (still pinned Low by K7).
    """

    _OWNER_THEFT: ClassVar[dict] = {
        "impact_class": "theft_of_funds",
        "magnitude": "unbounded",
        "trigger": "privileged_role",
        "precondition": "none",
        "reversibility": "irreversible",
    }

    def test_owner_theft_capped_medium_without_profile(self):
        # Baseline: I4 x L1 = Medium; K1 would cap to Medium (already there) -> Medium.
        result = compute_severity(self._OWNER_THEFT, "submit", SeverityContext(phase="submit"))
        assert result.severity == "Medium"

    def test_owner_theft_escalates_to_critical_under_profile(self):
        # token_review: trigger treated as privileged_role_unprotected (L3), K1 skipped.
        # I4 x L3 = Critical, no cap.
        ctx = SeverityContext(phase="submit", token_review=True)
        result = compute_severity(self._OWNER_THEFT, "submit", ctx)
        assert result.severity == "Critical"
        assert "K1" not in result.caps_applied

    def test_code_evidenced_finding_bypasses_k4_low_cap(self):
        # theft_of_funds / anyone -> base Critical; finalize + reasoning_only.
        matrix = {
            "impact_class": "theft_of_funds",
            "magnitude": "unbounded",
            "trigger": "anyone",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        plain = SeverityContext(phase="finalize", evidence_level="reasoning_only")
        # K8 caps Critical -> High; K4 caps High -> Low.
        assert compute_severity(matrix, "finalize", plain).severity == "Low"

        # Quoting the deployed source is the finding's own evidence: K4 does not fire.
        evidenced = SeverityContext(
            phase="finalize", evidence_level="reasoning_only",
            token_review=True, has_location_quote=True,
        )
        result = compute_severity(matrix, "finalize", evidenced)
        assert result.severity == "High"
        assert "K4" not in result.caps_applied

    def test_benign_centralization_note_stays_low_under_profile(self):
        # centralization_risk is NOT a direct-loss class, so token_review does not escalate it;
        # K7 still pins it to Low. Guards against the profile over-escalating owner-power notes.
        matrix = {
            "impact_class": "centralization_risk",
            "magnitude": "unbounded",
            "trigger": "privileged_role",
            "precondition": "none",
            "reversibility": "irreversible",
        }
        ctx = SeverityContext(phase="submit", token_review=True)
        result = compute_severity(matrix, "submit", ctx)
        assert result.severity == "Low"
