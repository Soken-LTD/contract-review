"""Gate policy (contract/rubric/gate_policy.yaml): every rejection a write tool can return is
classified, unlisted rule ids fail closed, and the publication rewrites are safe and idempotent."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from soken_review.engine import gate_policy
from soken_review.engine.text_gate import check_model_field

SRC = Path(__file__).resolve().parents[2] / "src" / "soken_review"
RUBRIC = Path(__file__).resolve().parents[2] / "contract" / "rubric"
WRITE_TOOLS = ("submit.py", "set_section.py", "challenge.py", "finalize.py")

_VIOLATION_RE = re.compile(r'Violation\(\s*(?:code=)?"(E_[A-Z_]+)",\s*(?:rule_id=)?"([A-Za-z0-9_]+)"')
_ADD_RE = re.compile(r'_add\("([A-Za-z0-9_]+)"')


def _emitted_pairs() -> set[tuple[str, str]]:
    """Every (code, rule id) the text gate, number check, claims, echo and quote engines can emit,
    collected from the sources and the text rule tables, so a new rule is seen without a code change
    here."""
    pairs: set[tuple[str, str]] = set()
    for path in (SRC / "engine").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        pairs.update(_VIOLATION_RE.findall(text))
        if path.name == "text_gate.py":
            pairs.update(("E_TEXT_GATE", r) for r in _ADD_RE.findall(text))
    gate = yaml.safe_load((RUBRIC / "text_gate.yaml").read_text(encoding="utf-8"))
    for rid in list(gate.get("rules") or {}) + list(gate.get("public_rules") or {}) + list(gate.get("rule_help") or {}):
        if re.fullmatch(r"[TP]\d+", rid):
            code = {"T24": "E_ABSENCE_UNRESOLVED", "T31": "E_CODESPAN_NOT_IN_SOURCE"}.get(rid, "E_TEXT_GATE")
            pairs.add((code, rid))
    for row in (yaml.safe_load((RUBRIC / "number_lexer.yaml").read_text(encoding="utf-8")).get("classes") or []):
        res = str(row.get("result", ""))
        for code in re.findall(r"E_[A-Z_]+", res):
            pairs.add((code, row["id"]))
    return pairs


def test_engines_emit_the_rules_this_test_expects():
    pairs = _emitted_pairs()
    assert ("E_TEXT_GATE", "T13") in pairs and ("E_NUMBER_UNSOURCED", "L7") in pairs
    assert ("E_TEXT_GATE", "T5") in pairs        # _add() path
    assert ("E_CLAIM_UNSUPPORTED", "C1") in pairs and ("E_INJECTION_ECHO", "V4") in pairs
    assert len(pairs) > 50


@pytest.mark.parametrize("pair", sorted(_emitted_pairs()), ids=lambda p: f"{p[0]}:{p[1]}")
def test_every_emitted_rule_has_an_explicit_row(pair):
    code, rule = pair
    assert gate_policy.is_classified(code, rule), f"classify {code} rule {rule} in contract/rubric/gate_policy.yaml"


def test_every_code_a_write_tool_returns_is_classified():
    used: set[str] = set()
    for name in WRITE_TOOLS:
        used.update(re.findall(r'ReviewError\(\s*"(E_[A-Z_]+)"', (SRC / "tools" / name).read_text(encoding="utf-8")))
    used.update(re.findall(r'"code": "(E_[A-Z_]+)"', (SRC / "pinning" / "quote_match.py").read_text(encoding="utf-8")))
    used.update(re.findall(r'QuoteMatchError\(\s*"(E_[A-Z_]+)"', (SRC / "pinning" / "quote_match.py").read_text(encoding="utf-8")))
    missing = sorted(c for c in used if not gate_policy.is_classified(c) and c not in ("E_INTERNAL", "E_JOB_NOT_FOUND",
                                                                                        "E_JOB_EXPIRED", "E_FINALIZE_OPEN"))
    assert not missing, missing


def test_unlisted_rule_fails_closed_even_under_an_advisory_code():
    assert gate_policy.disposition("E_TEXT_GATE").cls == "advisory"
    assert gate_policy.disposition("E_TEXT_GATE", "T99").cls == "blocking"
    assert gate_policy.disposition("E_LINEREF_OUTSIDE", "L77").cls == "blocking"
    assert gate_policy.disposition("E_NOT_A_CODE").cls == "blocking"
    assert gate_policy.disposition("E_JOB_NOT_READY", "roles_notes").cls == "blocking"
    assert gate_policy.disposition("E_JOB_NOT_READY", "context_notes").cls == "advisory"


@pytest.mark.parametrize(("code", "rule", "cls"), [
    ("E_QUOTE_MISMATCH", None, "blocking"),
    ("E_NUMBER_UNSOURCED", "L8c", "blocking"),
    ("E_NUMBER_UNSOURCED", "L7", "advisory"),
    ("E_NUMBER_FORMAT", "L9a", "advisory"),
    ("E_NUMBER_FORMAT", "L8b", "blocking"),
    ("E_CALC_SYNTAX", "L0", "blocking"),
    ("E_TEXT_GATE", "T13", "advisory"),
    ("E_TEXT_GATE", "T1", "rewrite"),
    ("E_TEXT_GATE", "T15", "rewrite"),
    ("E_TEXT_GATE", "T14", "blocking"),
    ("E_TEXT_GATE", "T17", "blocking"),
    ("E_TEXT_GATE", "T30", "blocking"),
    ("E_ABSENCE_UNRESOLVED", "T24", "advisory"),
    ("E_CODESPAN_NOT_IN_SOURCE", "T31", "advisory"),
    ("E_TEXT_CONTROL_CHAR", "step0", "blocking"),
    ("E_INJECTION_ECHO", "V4", "blocking"),
    ("E_CLAIM_UNSUPPORTED", "C1", "advisory"),
    ("E_CHALLENGE_SCOPE", None, "advisory"),
    ("E_SEVERITY_CONFIRM", None, "advisory"),
])
def test_classification(code, rule, cls):
    assert gate_policy.disposition(code, rule).cls == cls


def test_every_row_has_a_rationale():
    for code, row in gate_policy.codes().items():
        assert len(str(row.get("why", ""))) >= 15, code
        for rid, sub in (row.get("rules") or {}).items():
            assert len(str(sub.get("why", ""))) >= 10, (code, rid)


def test_finalize_checks_blocking_set():
    blocking = {f"F{i}" for i in range(1, 10) if gate_policy.finalize_check_blocks(f"F{i}")}
    assert blocking == {"F1", "F4", "F6"}


def test_t13_exempt_in_severity_reason():
    assert gate_policy.is_exempt("E_TEXT_GATE", "T13", "severity_reason")
    assert not gate_policy.is_exempt("E_TEXT_GATE", "T13", "description")


@pytest.mark.parametrize(("text", "want"), [
    ("The fee — capped by the owner — is taken twice", "The fee, capped by the owner, is taken twice"),
    ("lines 10–12 hold the loop", "lines 10 to 12 hold the loop"),
    ("stake → mint", "stake to mint"),
    ("deposit -> withdraw", "deposit to withdraw"),
    ("Audited vesting contracts reduce the audit scope", "Reviewed vesting contracts reduce the review scope"),
    ("`audit()` is called by the auditor", "`audit()` is called by the reviewer"),
    ("uses {{fact:a->b}} and — more", "uses {{fact:a->b}} and, more"),
])
def test_rewrites(text, want):
    out, applied = gate_policy.rewrite_text(text, "description")
    assert out == want and applied
    again, applied2 = gate_policy.rewrite_text(out, "description")
    assert again == out and not applied2


def test_title_trailing_period_removed_only_in_titles():
    assert gate_policy.rewrite_text("Owner can drain the vault.", "title")[0] == "Owner can drain the vault"
    assert gate_policy.rewrite_text("Owner can drain the vault.", "description")[0] == "Owner can drain the vault."


def test_rewritten_text_passes_the_rewrite_rules():
    text = "The pool — audited → safe"
    out, _ = gate_policy.rewrite_text(text, "description")
    rules = {v.rule_id for v in check_model_field(out, field="description")}
    assert not rules & {"T1", "T2", "T3", "T15", "T20"}
