"""Blind matrix round 5 (2026-10-31) friction fixes: aderyn reentrancy category, map readiness,
MB3 admin scope, category checklist notice."""

from __future__ import annotations

from soken_review.adapters.evm.analyze import _category_for
from soken_review.tools.dismiss import _guard_category


def test_aderyn_reentrancy_detectors_map_to_reentrancy():
    for rid in ("reentrancy-state-change", "state-change-after-external-call", "reentrancy"):
        assert _category_for("aderyn@0.6.5", rid) == "evm.reentrancy"
    assert _category_for("aderyn@0.6.5", "large-numeric-literal") == "evm.other"


def test_fp_guarded_category_remaps_old_other_leads():
    old = {"category": "evm.other", "rule_id": "reentrancy-state-change", "tools": ["aderyn@0.6.5"]}
    assert _guard_category(old) == "evm.reentrancy"
    assert _guard_category({"category": "evm.other", "rule_id": "x", "tools": ["aderyn"]}) == "evm.other"
    assert _guard_category({"category": "evm.dos", "rule_id": "reentrancy", "tools": ["aderyn"]}) == "evm.dos"


def test_category_fit_rows_name_real_categories():
    import yaml

    from soken_review.engine import category_fit
    enums = yaml.safe_load((category_fit._FILE.parents[0] / "enums.yaml").read_text())
    ids = {c["id"] for c in enums["categories"]}
    for cat, row in category_fit._doc()["categories"].items():
        assert cat in ids, cat
        if row.get("alternative"):
            assert row["alternative"] in ids, row["alternative"]
    text = yaml.safe_dump(category_fit._doc())
    assert "—" not in text and "–" not in text      # no dashes in client text


def test_arithmetic_checklist_notice_names_kill_items_and_alternative():
    from soken_review.tools.challenge import _category_notice, _kill_hint
    notice = _category_notice("evm", "evm.arithmetic_precision", False)
    assert notice and "P1, P3" in notice and "evm.accounting_logic" in notice
    hint = _kill_hint("evm.arithmetic_precision", "P1")
    assert hint and "P1" in hint and "evm.accounting_logic" in hint
    assert _kill_hint("evm.timestamp", "T1") is None          # no row: no hint
    generic = _category_notice("evm", "evm.accounting_logic", True)
    assert generic and "generic checklist" in generic and "L1" in generic


def test_categories_guide_says_which_category_fits_solvency():
    from soken_review.tools.guide import _topic_categories
    text = "\n".join(_topic_categories("evm"))
    assert "Which category fits" in text
    assert "evm.accounting_logic: wrong bookkeeping, insolvency" in text
