"""Caracal adapter: parser, source-span mapping, not_run semantics, lead.v1, merge (depth).

Covers:
  - parse_caracal: multi-finding output, multi-line reentrancy message, ANSI stripping,
    `Function X defined in Y` reconstruction, success/empty run
  - to_rows: located finding -> row (category, raw, rule_id, file, lines); unlocated counted;
    out-of-scope span dropped; ambiguous name disambiguated by module path
  - run_caracal not_run semantics: build_not_ok, caracal_toolchain_missing (image unpinned)
  - lead.v1 schema validation via build_leads
  - cross-tool merge: a caracal finding and a scarb-lint hit on the same category + overlapping
    lines collapse into one lead listing both tools (07 5.3)

All tests are unit-level; no Docker or sandbox required.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.starknet.analyze import build_leads, run_caracal
from soken_review.adapters.starknet.caracal import (
    CARACAL_TOOL,
    CARACAL_VERSION,
    category_for,
    detect_argv,
    parse_caracal,
    to_rows,
)
from soken_review.adapters.starknet.source import parse

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "schemas" / "lead.v1.json"
_SCHEMA = json.loads(_SCHEMA_PATH.read_text()) if _SCHEMA_PATH.exists() else {}


# ─── Fixtures: realistic caracal `detect` output and matching source ─────────

# Three findings; reentrancy carries a multi-line, tab-indented message (detectors/reentrancy.rs).
CARACAL_OUTPUT = """\
controlled-library-call Impact: High Confidence: Medium
Library call to a user controlled class hash in erc20::ERC20::upgrade
reentrancy Impact: Medium Confidence: Medium
Reentrancy in erc20::ERC20::transfer
\tExternal call token::ext::call done in erc20::ERC20::transfer
\tVariable written after balances::write in erc20::ERC20::transfer.
dead-code Impact: Low Confidence: Medium
Function helper defined in erc20::ERC20 is never used
"""

# A clean run with no findings (caracal prints nothing to stdout).
CARACAL_EMPTY = ""

# Source whose functions the findings above point at (`transfer`, `upgrade`, `helper`).
ERC20_CAIRO = """\
#[starknet::contract]
mod ERC20 {
    #[storage]
    struct Storage { balances: felt252 }

    #[external(v0)]
    fn transfer(ref self: ContractState, to: felt252, amount: u256) {
        let b = self.balances.read();
        token::ext::call();
        self.balances.write(b + amount);
    }

    #[external(v0)]
    fn upgrade(ref self: ContractState, new_class: felt252) {
        starknet::replace_class_syscall(new_class);
    }

    fn helper(self: @ContractState) -> felt252 {
        0
    }
}
"""


def _parsed(path: str = "src/erc20.cairo", text: str = ERC20_CAIRO):
    return [parse(path, text)]


def _build_result(status: str = "ok", work_dir: str | None = "/tmp/does-not-exist",
                  settings: dict | None = None) -> BuildResult:
    cand = Candidate(provider="repo", files={"src/erc20.cairo": ERC20_CAIRO}, sha256="x",
                     language="cairo", compiler=None, settings=settings or {}, std_json_input=None,
                     entry_contract=None, source_url=None)
    return BuildResult(candidate=cand, status=status, nsloc=0, work_dir=work_dir)


# ─── parse_caracal ───────────────────────────────────────────────────────────

def test_parse_caracal_three_findings():
    findings = parse_caracal(CARACAL_OUTPUT)
    assert [f["detector"] for f in findings] == [
        "controlled-library-call", "reentrancy", "dead-code"]
    assert [f["impact"] for f in findings] == ["High", "Medium", "Low"]
    assert all(f["confidence"] == "Medium" for f in findings)


def test_parse_caracal_reentrancy_multiline_message_and_refs():
    findings = parse_caracal(CARACAL_OUTPUT)
    reent = findings[1]
    # The tab-indented continuation lines belong to the reentrancy message, not a new finding.
    assert "External call" in reent["message"] and "Variable written after" in reent["message"]
    assert "erc20::ERC20::transfer" in reent["refs"]


def test_parse_caracal_defined_in_reconstructs_qualified_name():
    findings = parse_caracal(CARACAL_OUTPUT)
    dead = findings[2]
    # `Function helper defined in erc20::ERC20` -> qualified `erc20::ERC20::helper` is first ref.
    assert dead["refs"][0] == "erc20::ERC20::helper"


def test_parse_caracal_strips_ansi():
    colored = ("\x1b[1;31mcontrolled-library-call Impact: High Confidence: Medium\x1b[0m\n"
               "Library call in erc20::ERC20::upgrade\n")
    findings = parse_caracal(colored)
    assert len(findings) == 1
    assert findings[0]["detector"] == "controlled-library-call"


def test_parse_caracal_empty_run_no_findings():
    assert parse_caracal(CARACAL_EMPTY) == []


# ─── to_rows ──────────────────────────────────────────────────────────────────

def test_to_rows_locates_findings_to_source_spans():
    findings = parse_caracal(CARACAL_OUTPUT)
    rows, unlocated = to_rows(findings, _parsed(), {"src/erc20.cairo"})
    assert unlocated == 0
    by_detector = {r["rule_id"]: r for r in rows}
    transfer = by_detector["caracal:reentrancy"]
    assert transfer["file"] == "src/erc20.cairo"
    assert transfer["category"] == "cairo.reentrancy"
    assert transfer["raw"] == "Medium"
    assert transfer["tool"] == CARACAL_TOOL
    # `transfer` starts at the `fn transfer` line (line 7 of the fixture).
    assert transfer["start"] == 7 and transfer["end"] >= transfer["start"]
    assert by_detector["caracal:controlled-library-call"]["category"] == "cairo.access_control"
    assert by_detector["caracal:dead-code"]["category"] == "cairo.best_practice"


def test_to_rows_unlocated_when_function_unknown():
    out = ("unused-return Impact: Medium Confidence: Medium\n"
           "Unused return value in erc20::ERC20::ghost_function\n")
    rows, unlocated = to_rows(parse_caracal(out), _parsed(), {"src/erc20.cairo"})
    assert rows == [] and unlocated == 1


def test_to_rows_drops_span_out_of_scope():
    findings = parse_caracal(CARACAL_OUTPUT)
    # The file is parsed but not in scope: every finding is treated as unlocated, no row.
    rows, unlocated = to_rows(findings, _parsed(), set())
    assert rows == [] and unlocated == 3


def test_to_rows_disambiguates_duplicate_name_by_module_path():
    a = "mod a {\n    fn init(self: @ContractState) -> felt252 { 0 }\n}\n"
    b = "mod b {\n    fn init(self: @ContractState) -> felt252 { 1 }\n}\n"
    parsed = [parse("src/a.cairo", a), parse("src/b.cairo", b)]
    out = ("dead-code Impact: Low Confidence: Medium\n"
           "Function init defined in pkg::b is never used\n")
    rows, unlocated = to_rows(parse_caracal(out), parsed, {"src/a.cairo", "src/b.cairo"})
    assert unlocated == 0 and len(rows) == 1
    assert rows[0]["file"] == "src/b.cairo"


def test_detect_argv_and_category_defaults():
    assert detect_argv() == ["caracal", "detect", "."]
    assert detect_argv("pkg") == ["caracal", "detect", "pkg"]
    assert category_for("tx-origin") == "cairo.access_control"
    assert category_for("brand-new-detector") == "cairo.best_practice"  # fail-open floor


# ─── run_caracal not_run semantics (fail-closed) ───────────────────────────────

def test_run_caracal_build_not_ok():
    status, findings, reason = run_caracal(_build_result(status="failed", work_dir=None))
    assert status == "not_run" and findings == [] and reason == "build_not_ok"


def test_run_caracal_toolchain_missing_when_image_unpinned(monkeypatch):
    # images.lock.json ships an empty digest for starknet-caracal -> locked_image() is None
    # -> caracal is not_run with caracal_toolchain_missing (checked before docker availability).
    monkeypatch.delenv("SOKEN_IMAGE_STARKNET_CARACAL", raising=False)
    status, findings, reason = run_caracal(_build_result(status="ok"))
    assert status == "not_run" and findings == [] and reason == "caracal_toolchain_missing"


# ─── lead.v1 schema + build_leads ──────────────────────────────────────────────

_VERSIONS = {
    CARACAL_TOOL: CARACAL_VERSION,
    "scarb-lint": "2.13.1",
    "soken-cairo-rules": "0.1.0",
}


@pytest.mark.skipif(not _SCHEMA, reason="lead.v1.json schema not found")
def test_caracal_rows_pass_build_leads_lead_v1():
    findings = parse_caracal(CARACAL_OUTPUT)
    rows, _ = to_rows(findings, _parsed(), {"src/erc20.cairo"})
    leads = build_leads(rows, _VERSIONS)
    assert leads
    for lead in leads:
        jsonschema.validate(lead, _SCHEMA)
    high = next(ld for ld in leads if "caracal:controlled-library-call" in ld["rule_id"])
    assert high["severity_norm"] == "High"   # Impact High -> High
    assert high["tools"] == [f"{CARACAL_TOOL}@{CARACAL_VERSION}"]


@pytest.mark.skipif(not _SCHEMA, reason="lead.v1.json schema not found")
def test_caracal_and_scarb_lint_same_category_lines_merge_to_one_lead():
    """A caracal finding and a scarb-lint hit on the same category + overlapping lines merge
    into a single lead that lists both tools (07 5.3 cross-tool merge in build_leads)."""
    caracal_row = {
        "tool": CARACAL_TOOL, "rule_id": "caracal:dead-code", "category": "cairo.best_practice",
        "raw": "Low", "file": "src/erc20.cairo", "start": 19, "end": 21, "unit": None,
    }
    scarb_row = {
        "tool": "scarb-lint", "rule_id": "scarb-lint:dead_code", "category": "cairo.best_practice",
        "raw": "info", "file": "src/erc20.cairo", "start": 19, "end": 19, "unit": None,
    }
    leads = build_leads([caracal_row, scarb_row], _VERSIONS)
    assert len(leads) == 1
    assert set(leads[0]["tools"]) == {f"{CARACAL_TOOL}@{CARACAL_VERSION}", "scarb-lint@2.13.1"}
