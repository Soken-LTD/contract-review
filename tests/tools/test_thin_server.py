"""Thin server (CEO decision 2026-10-31, blind rounds 1 to 5).

1. The reviewer's severity is final: the r5 BakerFi matrix overrides and the Magnum K7 cap replayed
   through submit and finalize print the reviewer's value, with the matrix as a calibration note.
2. One short default guide under a budget; next_tools never names an optional step.
3. Blocking is evidence integrity, publication safety, argument shape and job state only.
4. review_start launches the chain snapshot of the deployment.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from soken_review.engine import gate_policy
from soken_review.tools.context import MemoryJobContext
from soken_review.tools.start_status import _status_next_tools

from .test_write_tools import _VALID_SUBMISSION, ASYNC, _create_ready_job_with_pin

ROOT = Path(__file__).resolve().parents[2]

# ── 1. r5 overrides replayed: the reviewer's severity prints ────────────────────────────────────────

_THEFT = {"impact_class": "theft_of_funds", "magnitude": "unbounded", "trigger": "anyone",
          "precondition": "none", "reversibility": "irreversible"}
_FEE = {"impact_class": "yield_or_fee_loss", "magnitude": "unbounded", "trigger": "anyone",
        "precondition": "normal_operation", "reversibility": "irreversible"}
_FREEZE = {"impact_class": "permanent_freeze", "magnitude": "unbounded", "trigger": "anyone",
           "precondition": "normal_operation", "reversibility": "admin_reversible"}
_SPEC = {"impact_class": "spec_deviation_bounded", "magnitude": "bounded", "trigger": "anyone",
         "precondition": "normal_operation", "reversibility": "irreversible"}
_CENTRAL = {"impact_class": "centralization_risk", "magnitude": "unbounded", "trigger": "privileged_role",
            "precondition": "none", "reversibility": "irreversible"}

# (draft key, r5 finding, matrix the arm sent (approximated from result.md), reviewer's claim,
#  severity the server printed in r5, judge severity)
R5_OVERRIDES = [
    ("bakerfi-c003", "BakerFi strategy treats vault shares as assets", _THEFT, "High", "Critical", "High"),
    ("bakerfi-h002", "BakerFi permissionless harvest erases the performance fee", _FEE, "Medium", "High", "Medium"),
    ("bakerfi-h003", "BakerFi undeploy keeps the deployed amount unchanged", _FEE, "Medium", "High", "Medium"),
    ("bakerfi-h005", "BakerFi undeploy of zero on an empty strategy freezes withdrawals", _FREEZE, "Medium", "High",
     "Medium"),
    ("bakerfi-l005", "BakerFi router dispatch compares the full action word", _SPEC, "Informational", "Low", "Low"),
    ("magnum-l001", "Magnum owner account can confiscate staked positions", _CENTRAL, "Medium", "Low", "Medium"),
]


async def _wire(db_pool, pin_root: Path) -> tuple[Any, Any]:
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import submit as submit_mod

    ctx = MemoryJobContext(pin_root)
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    fin_mod.set_pool(db_pool)
    fin_mod.set_context(ctx)
    return submit_mod, fin_mod


@ASYNC
async def test_r5_overrides_print_the_reviewers_severity(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, fin_mod = await _wire(db_pool, pin_root)
    for key, title, matrix, claim, r5_printed, _judge in R5_OVERRIDES:
        args = {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": key, "matrix": matrix,
                "claimed_severity": claim, "title": title}
        res = await submit_mod.handle_review_submit_finding(args)
        assert res["accepted"] is True, res
        codes = [w["code"] for w in res.get("warnings", [])]
        assert "E_SEVERITY_CONFIRM" not in codes and "challenge" not in res
        assert res["computed_severity"] == claim and res["severity_set_by"] == "reviewer", (key, res)
        assert res["calibration"]["severity"] == r5_printed and res["calibration"]["differs"] is True, (key, res)
        assert "review_challenge" not in res["next_tools"]

    fin = await fin_mod.handle_review_finalize({"job_id": job_id})
    assert fin["accepted"] is True, fin
    async with db_pool.connection() as conn:
        rows = await (await conn.execute(
            "select draft_key, severity, final_id, calibration_severity, calibration_rule, severity_set_by "
            "from finding_drafts where job_id = %s", (job_id,))).fetchall()
    by_key = {r[0]: r for r in rows}
    prefix = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}
    for key, _title, _m, claim, r5_printed, judge in R5_OVERRIDES:
        _k, sev, final_id, cal, rule, set_by = by_key[key]
        assert sev == claim and set_by == "reviewer", (key, sev)
        assert final_id.startswith(prefix[claim] + "-"), (key, final_id)
        # at finalize K8 joins the calibration of the unchallenged Critical cell: High, equal to the claim
        want = "High" if key == "bakerfi-c003" else r5_printed
        assert cal == want and rule, (key, cal, rule)
    assert "K7" in by_key["magnum-l001"][4] and "K8" in by_key["bakerfi-c003"][4]
    # against the judge: r5 printed 1 of 6 right (L-005); the reviewer's values are 5 of 6
    assert sum(by_key[k][1] == j for k, *_x, j in R5_OVERRIDES) == 5
    assert sum(p == j for _k, _t, _m, _c, p, j in R5_OVERRIDES) == 1


@ASYNC
async def test_challenge_answers_never_move_the_severity(db_pool):
    """A complete answer with a downgrade item present: verdict passed, severity unchanged, the
    calibration takes the step (K5)."""
    from soken_review.tools import challenge as challenge_mod

    from .test_write_tools import _log_reads

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, _fin = await _wire(db_pool, pin_root)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(MemoryJobContext(pin_root))
    res = await submit_mod.handle_review_submit_finding(
        {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": "thin-chal", "claimed_severity": "High"})
    assert res["accepted"] and res["status"] == "needs_challenge", res
    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": "thin-chal"})
    downgrades = [i for i in ch["items"] if i["kind"] == "downgrade"]
    if not downgrades:
        pytest.skip("no downgrade item for this category")
    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
    quote = {"file": "src/Vault.sol", "start": 5, "end": 7,
             "text": ("    function withdraw(uint256 a) external {\n"
                      '        (bool ok, ) = msg.sender.call{value: a}("");\n'
                      "        balances[msg.sender] -= a;")}
    answers = []
    for item in ch["items"]:
        if item["id"] == downgrades[0]["id"]:
            answers.append({"item_id": item["id"], "value": "present", "quotes": [quote],
                            "note": "The downgrade condition holds in scope."})
        elif item["kind"] == "kill":
            answers.append({"item_id": item["id"], "value": "absent",
                            "refs": item["scope"].get("ranges") or ["src/Vault.sol:1-9"], "note": "Absent."})
        else:
            answers.append({"item_id": item["id"], "value": "absent",
                            "refs": item["scope"].get("ranges") or ["src/Vault.sol:1-9"], "note": "Absent."})
    ar = await challenge_mod.handle_review_answer_challenge(
        {"job_id": job_id, "draft_key": "thin-chal", "revision": ch["revision"], "answers": answers})
    assert ar["accepted"] is True, ar
    assert ar["severity_before"] == ar["severity_after"] == "High"
    assert ar["verdict"] == "passed"


# ── 2. guide and next_tools ─────────────────────────────────────────────────────────────────────────


def _guide_yaml() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "contract" / "rubric" / "guide.yaml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("chain", ["evm", "solana", "ton", "sui", "starknet"])
def test_default_guide_is_under_its_budget(chain):
    from soken_review.tools.guide import _family_for, _render_topic, start_text

    g = _guide_yaml()["start"]
    assert len(str(g["text"]).strip()) <= g["budget_chars"]
    text = _render_topic("start", chain)
    assert len(text) <= g["budget_total_chars"], len(text)
    body = start_text(_family_for(chain))
    for step in ("review_start", "review_status", "review_read_code", "review_submit_finding", "review_finalize",
                 "review_report", "claimed_severity"):
        assert step in body
    assert "—" not in text and "–" not in text


def test_guide_prose_lives_in_data_not_python():
    """Every topic sentence comes from contract/rubric/guide.yaml: guide.py holds no long string literals."""
    import ast

    src = (ROOT / "src" / "soken_review" / "tools" / "guide.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)) and n.body
                  and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    long_literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                     and len(n.value) > 90 and id(n) not in docstrings]
    assert long_literals == [], long_literals


_OPTIONAL = {"review_challenge", "review_answer_challenge", "review_set_section", "review_add_context",
             "review_dismiss_lead", "review_get_guide", "review_contract_map", "review_leads",
             "review_chain_read", "review_chain_roles", "review_chain_balances"}


@pytest.mark.parametrize("statuses", [[], ["needs_challenge"], ["accepted"], ["needs_text"],
                                      ["accepted", "needs_challenge", "needs_text"]])
def test_next_tools_never_names_an_optional_step(statuses):
    advisory = [{"id": cid, "open": 1, "tool": tool} for cid, tool in
                (("F2", "review_dismiss_lead"), ("F3", "review_answer_challenge"), ("F5", "review_set_section"),
                 ("F7", "review_set_section"), ("F8", "review_submit_finding"), ("F9", "review_set_section"))]
    drafts = [{"status": s} for s in statuses]
    out = _status_next_tools("ready", drafts, advisory)
    assert not (set(out) & _OPTIONAL), out
    assert "review_finalize" in out or not drafts


# ── 3. blocking audit ───────────────────────────────────────────────────────────────────────────────

# The codes the thin-server audit keeps blocking, by reason. A new blocking code must be added here
# with its reason, or classified advisory in gate_policy.yaml.
_BLOCKING_ALLOWED = {
    # evidence integrity: the quote, file and range match the pinned source
    "E_QUOTE_MISMATCH", "E_QUOTE_ELISION", "E_QUOTE_TOO_LONG", "E_FILE_UNKNOWN", "E_RANGE_INVALID",
    "E_FILE_OUT_OF_SCOPE", "E_FIELD_FIXED",
    # numbers from recorded facts, placeholders resolve
    "E_NUMBER_UNSOURCED", "E_NUMBER_FORMAT", "E_NUMBER_UNIT", "E_NUMBER_CONTEXT", "E_CALC_SYNTAX",
    "E_CALC_ROUNDING", "E_PLACEHOLDER_SYNTAX", "E_FINDING_REF_UNKNOWN",
    # publication safety
    "E_INJECTION_ECHO", "E_TEXT_CONTROL_CHAR", "E_TEXT_SCRIPT",
    # argument shape, stale writes, abuse control
    "E_INVALID_ARGUMENT", "E_CATEGORY_UNKNOWN", "E_REVISION_CONFLICT", "E_RETRY_BUDGET", "E_DRAFT_STATUS",
    "E_FINDING_NOT_FOUND", "E_SECTION_INVALID", "E_REVISION_ANSWERED",
    # job state and quota
    "E_JOB_NOT_READY", "E_JOB_FROZEN", "E_JOB_TERMINAL", "E_TIER_D", "E_DAILY_REPORT_LIMIT",
}


def test_only_evidence_safety_shape_and_state_codes_block():
    blocking = {code for code, row in gate_policy.codes().items() if row["class"] == "blocking"}
    assert blocking <= _BLOCKING_ALLOWED, sorted(blocking - _BLOCKING_ALLOWED)
    for code in ("E_QUOTE_TRIVIAL", "E_DISPROVED_LOCKED", "E_ABSENCE_FALSE", "E_SEVERITY_CONFIRM"):
        assert not gate_policy.is_blocking(code), code
    assert not gate_policy.is_blocking("E_CLAIM_UNSUPPORTED", "C1")


def test_text_rules_that_block_are_publication_safety_only():
    doc = yaml.safe_load((ROOT / "contract" / "rubric" / "gate_policy.yaml").read_text(encoding="utf-8"))
    rules = doc["codes"]["E_TEXT_GATE"]["rules"]
    blocking = {rid for rid, row in rules.items() if row["class"] == "blocking"}
    assert blocking == {"T4", "T25", "T10", "T28", "T14", "T27", "T17", "T26", "T30", "P1", "P2", "P3", "P4",
                        "subject_words"}


def test_finalize_blocks_only_on_evidence():
    doc = yaml.safe_load((ROOT / "contract" / "rubric" / "gate_policy.yaml").read_text(encoding="utf-8"))
    blocking = {cid for cid, row in doc["finalize_checks"].items() if row["class"] == "blocking"}
    assert blocking == {"F1", "F4", "F6"}


def test_severity_confirm_is_never_raised():
    src = ROOT / "src" / "soken_review"
    hits = [p for p in src.rglob("*.py") if re.search(r'ReviewError\(\s*"E_SEVERITY_CONFIRM"', p.read_text())]
    assert hits == []


@ASYNC
async def test_trivial_quote_is_a_warning_but_a_mismatch_still_blocks(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod, _fin = await _wire(db_pool, pin_root)
    trivial = {"file": "src/Vault.sol", "start": 1, "end": 1, "role": "context",
               "text": "// SPDX-License-Identifier: MIT"}
    args = {**_VALID_SUBMISSION, "job_id": job_id, "draft_key": "thin-trivial",
            "quotes": [*_VALID_SUBMISSION["quotes"], trivial]}
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is True, res
    assert "E_QUOTE_TRIVIAL" in [w["code"] for w in res["warnings"]]

    wrong = {**trivial, "text": "// SPDX-License-Identifier: GPL"}
    bad = await submit_mod.handle_review_submit_finding(
        {**args, "draft_key": "thin-trivial-2", "quotes": [*_VALID_SUBMISSION["quotes"], wrong]})
    assert bad["accepted"] is False and "E_QUOTE_MISMATCH" in [e["code"] for e in bad["errors"]]


# ── 4. chain state from job start ───────────────────────────────────────────────────────────────────


@ASYNC
async def test_review_start_launches_the_chain_snapshot(db_pool, monkeypatch):
    from soken_review.tools import chain as chain_mod
    from soken_review.tools.start_status import handle_review_start, set_pool

    calls: list[tuple[str, bool]] = []

    async def fake(job_id: str, wait: bool) -> None:
        calls.append((job_id, wait))

    monkeypatch.setattr(chain_mod, "auto_snapshot", fake)
    set_pool(db_pool)
    try:
        res = await handle_review_start({"source": {"kind": "deployed", "chain": "evm", "chain_id": 1,
                                                    "address": "0x" + "d" * 40}})
    finally:
        set_pool(None)  # type: ignore[arg-type]
    assert res["accepted"] is True, res
    assert calls == [(res["job_id"], False)]
    assert res["guide"].startswith("Default path.")
