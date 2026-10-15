"""soken-cairo-rules fixtures (07 5.2: one positive and one negative per rule), lint parse, leads."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from soken_review.adapters.starknet.analyze import build_leads, lint_to_hits, parse_lint_output
from soken_review.adapters.starknet.rules import load_rules, run_rules
from soken_review.adapters.starknet.sierra import ClassFacts
from soken_review.adapters.starknet.source import parse

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "tests" / "fixtures" / "starknet" / "rules"
RULE_IDS = [r["id"] for r in load_rules()["rules"]]


@pytest.mark.parametrize("rid", RULE_IDS)
def test_rule_fixtures(rid: str) -> None:
    pos = [h.rule_id for h in run_rules([parse("pos.cairo", (FIX / rid / "pos.cairo").read_text())], None)]
    neg = [h.rule_id for h in run_rules([parse("neg.cairo", (FIX / rid / "neg.cairo").read_text())], None)]
    assert rid in pos and rid not in neg


def test_rule_categories_in_enum() -> None:
    enums = yaml.safe_load((ROOT / "contract" / "rubric" / "enums.yaml").read_text())
    ids = {c["id"] for c in enums["categories"]}
    assert all(r["category"] in ids for r in load_rules()["rules"])
    lint_map = yaml.safe_load((ROOT / "src/soken_review/adapters/starknet/lint_map.yaml").read_text())
    assert all(v["category"] in ids for v in lint_map["lints"].values())


def test_fact_precondition_suppresses_when_facts_disagree() -> None:
    text = (FIX / "CAI-06" / "pos.cairo").read_text()
    no_replace = ClassFacts(frozenset({"storage_read_syscall"}), {"EXTERNAL": frozenset()}, frozenset(), complete=True)
    assert "CAI-06" not in [h.rule_id for h in run_rules([parse("p.cairo", text)], no_replace)]
    with_replace = ClassFacts(frozenset({"replace_class_syscall"}),
                              {"EXTERNAL": frozenset({"replace_class_syscall"})}, frozenset(), complete=True)
    assert "CAI-06" in [h.rule_id for h in run_rules([parse("p.cairo", text)], with_replace)]


def test_comments_and_strings_do_not_match() -> None:
    text = (FIX / "CAI-09" / "neg.cairo").read_text().replace("false)", "false) // deploy_syscall(h, s, c, true)")
    assert "CAI-09" not in [h.rule_id for h in run_rules([parse("n.cairo", text)], None)]


LINT_OUT = """     Linting hello v0.1.0 (/work/tree/Scarb.toml)
warn: Plugin diagnostic: Unnecessary comparison with a boolean value. Use the variable directly.
 --> /work/tree/src/lib.cairo:40:16
            if (x == 0) == true {
warn: Plugin diagnostic: consider using `unwrap_syscall` instead of `unwrap`
 --> /work/tree/src/lib.cairo:49:13
warn: Plugin diagnostic: something new
 --> /work/tree/src/lib.cairo:2:1
warn: Plugin diagnostic: outside
 --> /work/tree/../etc/passwd:1:1
warn: Plugin diagnostic: not pinned
 --> /work/tree/src/other.cairo:1:1
"""


def test_lint_parse_and_map() -> None:
    diags = parse_lint_output(LINT_OUT)
    assert [d["line"] for d in diags] == [40, 49, 2, 1, 1]
    files = {"src/lib.cairo": "\n" * 60}
    rows = lint_to_hits(diags, files, "")
    assert [(r["rule_id"], r["category"], r["raw"]) for r in rows] == [
        ("scarb-lint:bool_comparison", "cairo.best_practice", "info"),
        ("scarb-lint:unwrap_syscall", "cairo.error_handling", "low"),
        ("scarb-lint:unmapped", "cairo.best_practice", "info"),
    ]


def test_leads_are_lead_v1_and_merge() -> None:
    schema = json.loads((ROOT / "contract" / "rubric" / "schemas" / "lead.v1.json").read_text())
    rows = [
        {"tool": "soken-cairo-rules", "rule_id": "soken:CAI-06", "category": "cairo.upgrade", "raw": "high",
         "file": "src/a.cairo", "start": 5, "end": 5, "unit": "src/a.cairo:upgrade"},
        {"tool": "scarb-lint", "rule_id": "scarb-lint:unwrap_syscall", "category": "cairo.upgrade", "raw": "low",
         "file": "src/a.cairo", "start": 5, "end": 6, "unit": None},
        {"tool": "scarb-lint", "rule_id": "scarb-lint:panic", "category": "cairo.error_handling", "raw": "low",
         "file": "src/a.cairo", "start": 9, "end": 9, "unit": None},
    ]
    leads = build_leads(rows, {"soken-cairo-rules": "0.1.0", "scarb-lint": "2.13.1"})
    assert len(leads) == 2 and leads[0]["id"] == "LEAD-0001" and leads[0]["severity_norm"] == "High"
    assert leads[0]["tools"] == ["scarb-lint@2.13.1", "soken-cairo-rules@0.1.0"]
    for lead in leads:
        jsonschema.validate(lead, schema)


# --------------------------------------------------------------------------- scope (mod tree)

def test_scope_follows_mod_tree_not_names() -> None:
    from soken_review.adapters.starknet.units import package_scope

    files = {
        "pkg/src/lib.cairo": "pub mod token;\nmod mocks;\n#[cfg(test)]\nmod tests;\nmod inner {\n    mod deep;\n}\n",
        "pkg/src/token.cairo": "pub mod helpers;\n",
        "pkg/src/token/helpers.cairo": "fn h() {}\n",
        "pkg/src/mocks.cairo": "pub fn backdoor() {}\n",          # compiled in: no cfg(test)
        "pkg/src/tests.cairo": "fn t() {}\n",
        "pkg/src/inner/deep.cairo": "fn d() {}\n",
        "pkg/src/unused.cairo": "fn u() {}\n",
        "other/src/lib.cairo": "fn o() {}\n",
    }
    assert package_scope(files, "pkg") == {
        "pkg/src/lib.cairo", "pkg/src/token.cairo", "pkg/src/token/helpers.cairo", "pkg/src/mocks.cairo",
        "pkg/src/inner/deep.cairo"}
    # Unresolved module file: everything of the package is in scope.
    broken = dict(files)
    del broken["pkg/src/mocks.cairo"]
    assert "pkg/src/tests.cairo" in package_scope(broken, "pkg")


def test_scope_includes_in_tree_path_dependencies() -> None:
    from soken_review.adapters.starknet.units import in_scope_paths

    files = {
        "Scarb.toml": '[workspace]\nmembers = ["a", "b", "c"]\n\n[workspace.dependencies]\nb = { path = "b" }\n',
        "a/Scarb.toml": '[package]\nname = "a"\n\n[dependencies]\nb.workspace = true\n\n[dev-dependencies]\nc = { path = "../c" }\n',
        "b/Scarb.toml": '[package]\nname = "b"\n',
        "c/Scarb.toml": '[package]\nname = "c"\n',
        "a/src/lib.cairo": "mod x;\n", "a/src/x.cairo": "", "b/src/lib.cairo": "", "c/src/lib.cairo": "",
    }
    assert in_scope_paths(files, "a") == {"a/src/lib.cairo", "a/src/x.cairo", "b/src/lib.cairo"}
