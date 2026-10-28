"""Rule tiers (learning-loop design 2026-10-27, 2.2): apply, generator, protection, exploration,
rollback and the review_leads view. Pure tests; the database side is in test_ledger_db.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from mcp import Client

import soken_review.tools  # noqa: F401  # registers the handlers
from soken_review.learning import config as lcfg
from soken_review.learning import tiers
from soken_review.server import SokenServer
from soken_review.tools import read as read_mod
from soken_review.tools.context import MemoryJobContext

JOB = "job_AAAAAAAAAAAAAAAAAAAAAAAAAB"


def _lead(i: int, rule: str, tool: str, sev: str, origin: str = "analyzer") -> dict:
    return {"id": f"LEAD-{i:04d}", "rule_id": rule, "tools": [tool], "category": "evm.other",
            "severity_norm": sev, "file": "src/A.sol", "start": i, "end": i, "state": "open", "origin": origin}


@pytest.fixture
def policy_dir(tmp_path: Path, monkeypatch) -> Path:
    d = tmp_path / "rule_tiers"
    d.mkdir()
    (d / "baseline.yaml").write_text("version: baseline\nrules: []\n")
    (d / "t1.yaml").write_text(yaml.safe_dump({"version": "t1", "rules": [
        {"tool": "slither", "rule": "incorrect-equality", "tier": "demoted", "severity_shift": -1},
        {"tool": "aderyn", "rule": "inconsistent-type-names", "tier": "collapsed", "severity_shift": -2},
        {"tool": "slither", "rule": "calls-loop", "tier": "boosted", "severity_shift": 0},
    ]}))
    monkeypatch.setattr(tiers, "TIERS_DIR", d)
    tiers.load_policy.cache_clear()
    yield d
    tiers.load_policy.cache_clear()


# ── apply ─────────────────────────────────────────────────────────────────────


def test_baseline_returns_leads_unchanged_in_order(policy_dir: Path) -> None:
    leads = [_lead(1, "incorrect-equality", "slither@0.11.6", "Medium"), _lead(2, "x", "aderyn@0.6.8", "Low")]
    out, summary = tiers.apply_tiers(leads, "baseline", JOB)
    assert [x["id"] for x in out] == ["LEAD-0001", "LEAD-0002"]
    assert [x["severity_norm"] for x in out] == ["Medium", "Low"]
    assert all(x["tier"] == "normal" for x in out)
    assert summary["demoted"] == summary["collapsed"] == 0


def test_unknown_version_is_the_baseline(policy_dir: Path) -> None:
    out, summary = tiers.apply_tiers([_lead(1, "incorrect-equality", "slither@0.11.6", "Medium")], "nope", JOB)
    assert out[0]["tier"] == "normal" and summary["version"] == "baseline"


def test_demoted_collapsed_boosted_order_and_severity(policy_dir: Path, monkeypatch) -> None:
    monkeypatch.setitem(lcfg.config()["exploration"], "rate", 0.0)
    leads = [_lead(1, "incorrect-equality", "slither@0.11.6", "Medium"),
             _lead(2, "inconsistent-type-names", "aderyn@0.6.8", "Low"),
             _lead(3, "reentrancy-eth", "slither@0.11.6", "High"),
             _lead(4, "calls-loop", "slither@0.11.6", "Low"),
             _lead(5, "incorrect-equality", "slither@0.11.6", "Medium", origin="previous_report")]
    out, summary = tiers.apply_tiers(leads, "t1", JOB)
    by = {x["id"]: x for x in out}
    assert [x["id"] for x in out] == ["LEAD-0004", "LEAD-0003", "LEAD-0005", "LEAD-0001", "LEAD-0002"]
    assert by["LEAD-0001"]["tier"] == "demoted" and by["LEAD-0001"]["severity_norm"] == "Low"
    assert by["LEAD-0001"]["severity_analyzer"] == "Medium"
    assert by["LEAD-0002"]["tier"] == "collapsed" and by["LEAD-0002"]["severity_norm"] == "Info"
    assert by["LEAD-0005"]["tier"] == "normal"            # carried findings are never tiered
    assert summary["demoted"] == 1 and summary["collapsed"] == 1 and summary["boosted"] == 1
    assert not tiers.listed_by_default("collapsed") and tiers.listed_by_default("demoted")


def test_severity_shift_bounds() -> None:
    assert tiers.shift_severity("Low", -2) == "Info"
    assert tiers.shift_severity("Medium", 3) == "High"      # analyzer leads never show Critical
    assert tiers.shift_severity("High", 1) == "High"


def test_exploration_is_deterministic_capped_and_shows_the_analyzer_severity(policy_dir: Path, monkeypatch) -> None:
    monkeypatch.setitem(lcfg.config()["exploration"], "rate", 1.0)
    monkeypatch.setitem(lcfg.config()["exploration"], "max_per_job", 3)
    leads = [_lead(i, "incorrect-equality", "slither@0.11.6", "Medium") for i in range(1, 11)]
    a, sa = tiers.apply_tiers(leads, "t1", JOB)
    b, _ = tiers.apply_tiers(leads, "t1", JOB)
    explored = [x["id"] for x in a if x["tier"] == "explore"]
    assert len(explored) == 3 and explored == [x["id"] for x in b if x["tier"] == "explore"]
    assert all(x["severity_norm"] == "Medium" for x in a if x["tier"] == "explore")
    assert sa["explore"] == 3 and sa["demoted"] == 7
    assert "calibration sample" in tiers.lead_suffix(next(x for x in a if x["tier"] == "explore"))


def test_rollback_flag_resolves_to_the_baseline(policy_dir: Path) -> None:
    assert tiers.resolve_version({"version": "t1"}) == "t1"
    assert tiers.resolve_version({"version": "t1", "rollback": True}) == "baseline"
    assert tiers.resolve_version({"version": "does-not-exist"}) == "baseline"
    assert tiers.resolve_version(None) == "baseline"


# ── generator ─────────────────────────────────────────────────────────────────


def _stat(tool: str, rule: str, triaged: int, promoted: int, targets: int, principals: int = 1,
          ge_m: int = 0, above: int = 0, max_n: int | None = None) -> dict:
    return {"tool": tool, "rule_id": rule, "triaged": triaged, "promoted": promoted, "targets": targets,
            "principals": principals, "promoted_ge_medium": ge_m, "promoted_above_norm": above,
            "max_principal_n": triaged if max_n is None else max_n}


def test_wilson_matches_the_design_numbers() -> None:
    assert round(tiers.wilson(0, 88)[1], 3) == 0.042           # incorrect-equality UB
    assert round(tiers.wilson(3, 3)[0], 3) == 0.438            # calls-loop LB


def test_generator_demotes_only_with_the_minimum_sample() -> None:
    stats = [_stat("slither", "incorrect-equality", 88, 0, 7),
             _stat("misti", "ExitCodeUsage", 60, 0, 1),                 # one target: insufficient
             _stat("slither", "uninitialized-local", 10, 0, 6)]         # 10 triaged: insufficient
    doc, changes = tiers.compute_tiers(stats, None, "v1", set(), "snap")
    rules = {(r["tool"], r["rule"]): r for r in doc["rules"]}
    assert rules[("slither", "incorrect-equality")]["tier"] == "demoted"
    assert rules[("slither", "incorrect-equality")]["severity_shift"] == -1
    assert ("misti", "ExitCodeUsage") not in rules and ("slither", "uninitialized-local") not in rules
    assert [c["rule"] for c in changes] == ["incorrect-equality"]


def test_protected_rules_are_never_demoted_or_shifted_down() -> None:
    stats = [_stat("soken-lifecycle", "LC-EVM-STALE", 80, 0, 9),             # own lifecycle tool
             _stat("slither", "reentrancy-balance", 80, 0, 9),               # judge-confirmed
             _stat("slither", "unused-return", 80, 6, 9)]
    doc, _ = tiers.compute_tiers(stats, None, "v1", {("slither", "reentrancy-balance")}, "snap")
    rules = {(r["tool"], r["rule"]): r for r in doc["rules"]}
    assert ("soken-lifecycle", "LC-EVM-STALE") not in rules
    assert ("slither", "reentrancy-balance") not in rules
    assert rules[("slither", "unused-return")]["severity_shift"] == -1      # 6 promoted, none >= Medium
    prot = {(p["tool"], p["rule"]) for p in doc["protected"]}
    assert {("soken-lifecycle", "LC-EVM-STALE"), ("slither", "reentrancy-balance")} <= prot


def test_protected_rule_previously_demoted_returns_to_normal() -> None:
    prev = {"version": "v1", "_index": {("soken-lifecycle", "LC-EVM-EMPTY"): {"tier": "demoted", "severity_shift": -1}}}
    doc, changes = tiers.compute_tiers([_stat("soken-lifecycle", "LC-EVM-EMPTY", 5, 3, 2)], prev, "v2", set(), "s")
    assert doc["rules"] == [] and changes[0]["to_tier"] == "normal"


def test_one_step_per_version_collapse_only_after_demoted_and_restore() -> None:
    stat = _stat("aderyn", "x", 200, 0, 12, principals=5, max_n=30)
    d1, _ = tiers.compute_tiers([stat], None, "v1", set(), "s")
    assert d1["rules"][0]["tier"] == "demoted"                               # not straight to collapsed
    prev = {"version": "v1", "_index": {("aderyn", "x"): {**d1["rules"][0]}}}
    d2, _ = tiers.compute_tiers([stat], prev, "v2", set(), "s")
    assert d2["rules"][0]["tier"] == "collapsed" and d2["rules"][0]["severity_shift"] == -2
    good = _stat("aderyn", "x", 40, 20, 12, principals=5, max_n=8)
    prev3 = {"version": "v2", "_index": {("aderyn", "x"): {"tier": "collapsed", "basis": {"p": 0.4}}}}
    d3, _ = tiers.compute_tiers([good], prev3, "v3", set(), "s")
    assert d3["rules"][0]["tier"] == "demoted"                               # restore, one step


def test_principal_share_cap_blocks_collapse_and_boost() -> None:
    one_client = _stat("slither", "calls-loop", 40, 30, 10, principals=3, ge_m=30, max_n=38)
    doc, _ = tiers.compute_tiers([one_client], None, "v1", set(), "s")
    assert doc["rules"] == []                                                # 95% from one principal


def test_swing_holds_the_change_for_review() -> None:
    prev = {"version": "v1", "_index": {("slither", "y"): {"tier": "normal", "severity_shift": 0, "basis": {"p": 0.5}}}}
    doc, changes = tiers.compute_tiers([_stat("slither", "y", 60, 0, 9)], prev, "v2", set(), "s")
    assert doc["rules"] == [] or doc["rules"][0]["tier"] == "normal"
    assert changes and changes[0]["held"] is True and "held" in changes[0]["reason"]


def test_render_diff_names_every_change() -> None:
    doc, changes = tiers.compute_tiers([_stat("slither", "incorrect-equality", 88, 0, 7)], None, "v1", set(), "s")
    diff = tiers.render_diff(doc, changes, [_stat("slither", "incorrect-equality", 88, 0, 7)])
    assert "incorrect-equality" in diff and "normal to demoted" in diff and "—" not in diff


# ── review_leads view ─────────────────────────────────────────────────────────


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_review_leads_applies_tiers_and_never_hides_silently(policy_dir: Path, tmp_path: Path,
                                                                   monkeypatch) -> None:
    from soken_review.pinning.store import PinnedSource

    monkeypatch.setitem(lcfg.config()["exploration"], "rate", 0.0)
    monkeypatch.setattr(read_mod._tiers, "resolve_version", lambda _v: "t1")
    root = tmp_path / "pins"
    ctx = MemoryJobContext(root)
    ctx.set_state(JOB, "ready")
    PinnedSource.from_files({"src/A.sol": b"contract A {}\n"}).persist(root, JOB)
    leads = [_lead(1, "incorrect-equality", "slither@0.11.6", "Medium"),
             _lead(2, "inconsistent-type-names", "aderyn@0.6.8", "Low"),
             _lead(3, "reentrancy-eth", "slither@0.11.6", "High")]
    (root / JOB / "leads.json").write_text(json.dumps(leads))
    read_mod.set_context(ctx)
    async with Client(SokenServer()) as client:
        text = (await client.call_tool("review_leads", {"job_id": JOB})).content[0].text
        full = (await client.call_tool("review_leads", {"job_id": JOB, "include_collapsed": True})).content[0].text
        by_rule = (await client.call_tool("review_leads", {"job_id": JOB, "detector": "inconsistent-type-names"})).content[0].text
    lines = text.splitlines()
    assert "rule tiers t1: 1 demoted, 1 collapsed" in lines[1] and "include_collapsed" in lines[1]
    assert "High and Medium open 1" in lines[0]                              # the demoted Medium is not counted
    assert "LEAD-0002" not in text and "LEAD-0002" in full and "LEAD-0002" in by_rule
    assert text.index("LEAD-0003") < text.index("LEAD-0001")
    assert "LEAD-0001 open other low" in text and "tier demoted, analyzer medium" in text


def test_report_schema_carries_the_lower_priority_counts() -> None:
    import jsonschema

    schema = json.loads((Path(lcfg.REPO_ROOT) / "contract" / "report.automated.schema.json").read_text())
    cov = {"$defs": schema["$defs"], **schema["$defs"]["review_coverage"]}
    doc = {"areas": [{"area_id": "evm.x", "area": "X", "code_returned": "No", "result": "Not covered"}],
           "leads": [{"analyzer": "slither", "version": "0.11.6", "leads": 9, "promoted": 1, "dismissed": 2,
                      "lower_priority": 4}],
           "withdrawn": [], "injection_flags": [], "rule_tiers": {"version": "t1", "lower_priority": 4}}
    jsonschema.Draft202012Validator(cov).validate(doc)
    texts = json.loads((Path(lcfg.REPO_ROOT) / "src/soken_review/report/kit/text/automated.json").read_text())
    assert "{n}" in texts["rule_tiers_note"] and "—" not in texts["rule_tiers_note"]
