"""Rubric-wide invariants over every shipped checklist item (contract/rubric/checklists/*.yaml, the
generic items, the basis items MB0-MB4) and the answer caps (tools.v1.json).

1. Given a semantic map in which the location sits inside a function, no item of any family
   resolves to `not_covered` with an empty range (blind run 2026-10-26, JUDGEMENT.md D10: the
   `ata_owner_reassign` items shipped empty scopes nobody could satisfy).
2. A scope the map cannot supply applies no cap: `scope_not_covered` never names K10, which is
   the no-contract-map cap only.
3. The ranges an item lists never exceed `SCOPE_RANGES_MAX`, which never exceeds the `refs`
   maxItems of review_answer_challenge answers and of invariant_walks rows (D17: 16 ranges
   against a 12-ref cap on the Solana run).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from soken_review.engine.severity import SeverityContext, compute_severity
from soken_review.tools import walks
from soken_review.tools.challenge import (
    ANSWER_REFS_MAX,
    SCOPE_RANGES_MAX,
    _checklist_items_for_category,
    compute_challenge_items,
)

ROOT = Path(__file__).resolve().parents[2]
RUBRIC = ROOT / "contract" / "rubric"
SCHEMA = json.loads((ROOT / "contract" / "mcp" / "tools.v1.json").read_text())
TOOLS = {t["name"]: t for t in SCHEMA["tools"]}
ENUMS = yaml.safe_load((RUBRIC / "enums.yaml").read_text())
FAMILIES = ("evm", "solana", "ton", "move", "cairo")
FILE_OF = {"evm": "src/Vault.sol", "solana": "src/lib.rs", "ton": "contracts/master.tact",
           "move": "sources/vault.move", "cairo": "src/vault.cairo"}

# Medium+ so the basis items MB0-MB4 are emitted too
MATRIX = {"impact_class": "theft_of_funds", "magnitude": "unbounded", "trigger": "anyone",
          "precondition": "none", "reversibility": "irreversible"}


def _categories(family: str) -> list[tuple[str, bool]]:
    """(category id, is_generic) for every category the family ships, checklist or generic."""
    data = yaml.safe_load((RUBRIC / "checklists" / f"{family}.yaml").read_text()) or {}
    listed = set((data.get("categories") or {}).keys())
    out: list[tuple[str, bool]] = []
    for c in ENUMS["categories"]:
        if c.get("family") != family or c.get("server_only"):
            continue
        out.append((c["id"], bool(c.get("generic")) and c["id"] not in listed))
    assert out, family
    assert listed <= {cid for cid, _ in out}, f"{family}: checklist names a category enums.yaml lacks"
    return out


def _fn(path: str, name: str, start: int, end: int, calls: list[str] = (), unit: str = "Vault") -> tuple[dict, dict]:
    sid = f"{path}:{name}"
    span = {"id": sid, "name": name, "kind": "function", "file": path, "start": start, "end": end, "unit": f"{path}:{unit}"}
    fn = {"span": sid, "visibility": "public", "is_entry": True, "modifiers": [], "guards": [],
          "calls": [{"kind": "internal", "target": t, "line": start + 1} for t in calls], "writes": [], "reads": []}
    return span, fn


def _map(family: str, *, callers: int = 0) -> dict[str, Any]:
    """One entry function holding the location (lines 10-20), plus `callers` entry functions that
    call it, each five lines long and ten lines apart."""
    path = FILE_OF[family]
    spans, fns = [], []
    sp, fn = _fn(path, "target", 10, 20)
    spans.append(sp)
    fns.append(fn)
    for i in range(callers):
        start = 40 + i * 15
        sp, fn = _fn(path, f"entry{i}", start, start + 4, calls=["target"])
        spans.append(sp)
        fns.append(fn)
    return {"version": 1, "spans": spans, "_status": "partial",
            "semantic": {"functions": fns, "units": [], "category_to_functions": {}}}


def _location(family: str) -> list[dict[str, Any]]:
    return [{"file": FILE_OF[family], "start": 12, "end": 13}]


@pytest.mark.parametrize("family", FAMILIES)
def test_every_scope_name_in_the_rubric_is_a_known_scope(family):
    names = set(ENUMS["challenge_scope"])
    data = yaml.safe_load((RUBRIC / "checklists" / f"{family}.yaml").read_text()) or {}
    for item in data.get("generic_items") or []:
        assert item.get("scope", "entry_function") in names, item
    for cat, body in (data.get("categories") or {}).items():
        for item in (body or {}).get("items") or []:
            assert item.get("scope", "entry_function") in names, (cat, item)


@pytest.mark.parametrize("family", FAMILIES)
def test_no_shipped_item_resolves_to_an_empty_not_covered_scope(family):
    doc = _map(family)
    for cat, is_generic in _categories(family):
        raw = _checklist_items_for_category(family, cat, is_generic)
        items, _ = compute_challenge_items(family, cat, MATRIX, doc, _location(family), is_generic)
        assert len(items) >= len(raw), (cat, [i["id"] for i in items])
        for item in items:
            scope = item["scope"]
            assert scope["ranges"], (family, cat, item["id"], scope)
            assert not scope.get("not_covered"), (family, cat, item["id"], scope)
            assert scope["source"] in ("semantic", "lexical"), scope


def test_a_scope_the_map_cannot_supply_applies_no_cap():
    """Items of a map with no function at the location are not_covered with no ranges; that state
    reaches the engine as scope_not_covered and names no rule. K10 is the no-map cap."""
    doc = _map("solana")
    items, _ = compute_challenge_items("solana", "solana.ata_owner_reassign", MATRIX, doc,
                                       [{"file": "src/lib.rs", "start": 2, "end": 2}], False)
    assert all(i["scope"].get("not_covered") and i["scope"]["ranges"] == [] for i in items)
    base = {"phase": "post_challenge", "evidence_level": "analyzer_and_reasoning", "has_attack_steps": True,
            "severity_before": "Critical"}
    r = compute_severity(MATRIX, "post_challenge", SeverityContext(**base, scope_not_covered=True))
    assert r.severity == "Critical" and r.caps_applied == [] and "K10" not in r.severity_rule
    r = compute_severity(MATRIX, "post_challenge", SeverityContext(**base, map_unavailable=True))
    assert r.severity == "Critical" and r.caps_applied == ["K10"] and r.calibration == "High"
    rules = yaml.safe_load((RUBRIC / "severity_rules.yaml").read_text())
    k10 = next(r for r in rules["rules"] if r["id"] == "K10")
    assert "no contract map" in k10["condition"] and "not covered" not in k10["condition"].split("applies no cap")[0]


@pytest.mark.parametrize("family", FAMILIES)
def test_ranges_never_exceed_the_answer_ref_caps(family):
    """A target reached by 20 entry functions lists 21 raw ranges; every item prints at most
    SCOPE_RANGES_MAX, and an absent answer can carry one ref per range."""
    doc = _map(family, callers=20)
    for cat, is_generic in _categories(family):
        items, _ = compute_challenge_items(family, cat, MATRIX, doc, _location(family), is_generic)
        for item in items:
            ranges = item["scope"]["ranges"]
            assert ranges and not item["scope"].get("not_covered"), (cat, item)
            assert len(ranges) <= SCOPE_RANGES_MAX, (cat, item["id"], len(ranges))


def test_answer_and_walk_ref_caps_hold_the_server_ranges():
    answer_refs = TOOLS["review_answer_challenge"]["inputSchema"]["properties"]["answers"]["items"]["properties"]["refs"]
    walk_refs = (TOOLS["review_set_section"]["inputSchema"]["properties"]["invariant_walks"]["properties"]
                 ["rows"]["items"]["properties"]["refs"])
    assert SCOPE_RANGES_MAX <= ANSWER_REFS_MAX
    assert answer_refs["maxItems"] == ANSWER_REFS_MAX >= SCOPE_RANGES_MAX
    assert walk_refs["maxItems"] == walks._REFS_MAX >= SCOPE_RANGES_MAX
