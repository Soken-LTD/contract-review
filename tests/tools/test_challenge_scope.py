"""entry_function scope resolution (scopes.yaml, 04 8.4): callers, modifiers, same-unit callees.

Pure: builds maps from the fixtures and calls `_resolve_scope` directly. Regression for the
2026-10-22 review where the scope of a finding inside an internal function was the function body
only, so every quote from the external caller that proves reachability (L1) was rejected with
E_CHALLENGE_SCOPE (65 rejections on one review).
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories
from soken_review.tools.challenge import _resolve_scope

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map"
CATS = list(family_categories("evm"))


def _mc_map() -> dict:
    crlf = (FIX / "masterchef_crlf" / "MasterChef.crlf.sol").read_bytes().decode("utf-8")
    with gzip.open(FIX / "masterchef_crlf" / "solc_output.sources.json.gz", "rt", encoding="utf-8") as fh:
        out = json.load(fh)
    doc = build_map({"MasterChef.sol": crlf.replace("\r\n", "\n")}, out, CATS,
                    compiled_texts={"MasterChef.sol": crlf}).doc
    doc["_status"] = "full"
    return doc


def _vault_map() -> dict:
    doc = build_map({"src/Vault.sol": (FIX / "Vault.sol").read_text()},
                    json.loads((FIX / "vault_solc_output.json").read_text()), CATS).doc
    doc["_status"] = "full"
    return doc


def _scope(doc: dict, file: str, start: int, end: int) -> tuple[list[str], bool, str]:
    return _resolve_scope("entry_function", "evm", doc, [{"file": file, "start": start, "end": end}])


def test_internal_function_scope_includes_the_entry_callers():
    """safeSushiTransfer (internal, 1602-1609) is reached from deposit and withdraw: both in scope."""
    ranges, not_covered, source = _scope(_mc_map(), "MasterChef.sol", 1602, 1609)
    assert not not_covered and source == "semantic"
    assert "MasterChef.sol:1602-1609" in ranges
    assert "MasterChef.sol:1578-1589" in ranges, ranges   # withdraw
    assert "MasterChef.sol:1563-1575" in ranges, ranges   # deposit


def test_entry_scope_includes_same_unit_callees_not_libraries():
    """withdraw calls updatePool and safeSushiTransfer (same unit) and SafeMath.sub (library)."""
    ranges, not_covered, _ = _scope(_mc_map(), "MasterChef.sol", 1578, 1589)
    assert not not_covered
    assert "MasterChef.sol:1544-1560" in ranges          # updatePool (depth 1)
    assert "MasterChef.sol:1602-1609" in ranges          # safeSushiTransfer (depth 1)
    assert "MasterChef.sol:1509-1519" in ranges          # getMultiplier via updatePool (depth 2)
    assert all(int(r.split(":")[1].split("-")[0]) >= 1448 for r in ranges), ranges   # no SafeMath / ERC20 helpers


def test_entry_scope_includes_inherited_modifier_body():
    """setFee is onlyOwner; the modifier lives in the base contract Owned."""
    ranges, not_covered, _ = _scope(_vault_map(), "src/Vault.sol", 36, 38)
    assert not not_covered
    assert ranges == ["src/Vault.sol:8-11", "src/Vault.sol:36-38"], ranges


def test_internal_helper_scope_includes_caller_and_stays_in_unit():
    """_chargeFee is called by deposit only."""
    ranges, not_covered, _ = _scope(_vault_map(), "src/Vault.sol", 55, 57)
    assert not not_covered
    assert ranges == ["src/Vault.sol:40-42", "src/Vault.sol:55-57"], ranges


def test_scope_without_semantic_layer_is_the_lexical_span_only():
    doc = _vault_map()
    doc.pop("semantic")
    ranges, not_covered, source = _scope(doc, "src/Vault.sol", 55, 57)
    assert ranges == ["src/Vault.sol:55-57"] and not not_covered and source == "lexical"


def test_location_outside_every_function_is_not_covered():
    ranges, not_covered, source = _scope(_vault_map(), "src/Vault.sol", 19, 20)   # constants
    assert ranges == [] and not_covered and source == "not_covered"


def test_mandatory_scope_over_the_line_cap_is_not_covered():
    doc = _vault_map()
    # inflate the caller `deposit` beyond the cap; the callee `_chargeFee` then cannot be covered
    for sp in doc["spans"]:
        if sp["id"] == "Vault.deposit()":
            sp["end"] = sp["start"] + 450
    ranges, not_covered, _ = _scope(doc, "src/Vault.sol", 55, 57)
    assert ranges == [] and not_covered


def test_shared_state_writers_scope_adds_admin_writer():
    """MB3 (r5 2026-10-31): "an admin function in the map can restore the affected state" had the
    entry_function scope, so quotes of the admin function were outside it. shared_state_writers
    adds every external function touching the state the location writes (or reads)."""
    doc = _vault_map()
    loc = [{"file": "src/Vault.sol", "start": 56, "end": 56}]      # _chargeFee reads feeBps
    base, _, _ = _resolve_scope("entry_function", "evm", doc, loc)
    ranges, nc, source = _resolve_scope("shared_state_writers", "evm", doc, loc)
    assert not nc and source == "semantic"
    assert set(base) <= set(ranges)
    assert "src/Vault.sol:36-38" in ranges and "src/Vault.sol:36-38" not in base   # setFee(uint256)


def test_mb3_uses_shared_state_writers_scope():
    from soken_review.tools.challenge import _basis_items
    items = _basis_items({"impact_class": "permanent_freeze", "magnitude": "bounded", "trigger": "anyone",
                          "precondition": "market_condition", "reversibility": "irreversible"})
    mb3 = [i for i in items if i["id"] == "MB3"]
    assert mb3 and mb3[0]["scope"] == "shared_state_writers"
