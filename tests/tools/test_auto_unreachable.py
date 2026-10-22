"""map.unreachable auto check (04 §8.5): proof of unreachability, fail closed.

Reproduces the 2026-10-22 false kill: the semantic map names functions `Contract.name(types)` while
call edges carry the bare `name`; the resolver only knew the lexical `path:Contract:name` shape, so
every internal edge was dropped, the BFS from the entry points reached nothing, and an internal
function called from two external functions was "proven" unreachable. The auto item then killed a
true finding in the blind study (c6, `_claim`).
"""

from __future__ import annotations

from soken_review.tools.challenge import _auto_unreachable, _callee_names

FILE = "src/PrelaunchPoints.sol"


def _span(sid: str, name: str, start: int, end: int, kind: str = "function") -> dict:
    return {"id": sid, "name": name, "file": FILE, "start": start, "end": end, "kind": kind, "unit": f"{FILE}:PrelaunchPoints"}


def _fn(sid: str, is_entry: bool, calls: list[tuple[str, str]]) -> dict:
    return {"span": sid, "is_entry": is_entry, "calls": [{"kind": k, "target": t, "line": f"{FILE}:1"} for t, k in calls]}


CLAIM = "PrelaunchPoints.claim(address,uint8,Exchange,bytes)"
CLAIM_STAKE = "PrelaunchPoints.claimAndStake(address,uint8,Exchange,bytes)"
_CLAIM = "PrelaunchPoints._claim(address,address,uint8,Exchange,bytes)"
_FILL = "PrelaunchPoints._fillQuote(IERC20,uint256,bytes)"
ORPHAN = "PrelaunchPoints._orphan()"


def _semantic_map(extra_fns: list[dict] | None = None, status: str = "full") -> dict:
    spans = [_span(CLAIM, "claim", 211, 216), _span(CLAIM_STAKE, "claimAndStake", 226, 235),
             _span(_CLAIM, "_claim", 240, 266), _span(_FILL, "_fillQuote", 491, 505), _span(ORPHAN, "_orphan", 600, 605)]
    fns = [_fn(CLAIM, True, [("_claim", "internal")]),
           _fn(CLAIM_STAKE, True, [("_claim", "internal"), ("ILpETHVault.stake", "external")]),
           _fn(_CLAIM, False, [("_fillQuote", "internal"), ("ILpETH.deposit", "external")]),
           _fn(_FILL, False, [("address.call", "external")]),
           _fn(ORPHAN, False, [])] + (extra_fns or [])
    return {"semantic": {"functions": fns}, "spans": spans, "_status": status}


def _loc(start: int, end: int) -> list[dict]:
    return [{"file": FILE, "start": start, "end": end, "role": "location"}]


def test_callee_names_cover_both_span_id_shapes():
    assert {"_claim", "PrelaunchPoints._claim"} <= _callee_names(_CLAIM, {"name": "_claim"})
    assert "withdraw" in _callee_names("src/V.sol:Vault:withdraw@Base", None)
    assert "mulDiv" in _callee_names("Math.mulDiv(uint256,uint256,uint256)", None)


def test_internal_function_called_from_entry_is_reachable():
    assert _auto_unreachable("evm.accounting_logic", _semantic_map(), _loc(256, 266)) == "absent"


def test_two_hops_internal_is_reachable():
    assert _auto_unreachable("evm.unchecked_call", _semantic_map(), _loc(495, 497)) == "absent"


def test_location_inside_entry_is_reachable():
    assert _auto_unreachable("evm.accounting_logic", _semantic_map(), _loc(212, 214)) == "absent"


def test_true_orphan_is_proven_unreachable_on_full_map():
    assert _auto_unreachable("evm.accounting_logic", _semantic_map(), _loc(601, 603)) == "present"


def test_orphan_on_partial_map_is_unknown():
    assert _auto_unreachable("evm.accounting_logic", _semantic_map(status="partial"), _loc(601, 603)) == "unknown"


def test_unresolved_internal_edge_never_proves_unreachability():
    # an entry calls an internal helper the map did not model: the edge may lead to the location
    extra = [_fn("PrelaunchPoints.rescue()", True, [("_unmodelledHelper", "internal")])]
    doc = _semantic_map(extra_fns=extra)
    doc["spans"].append(_span("PrelaunchPoints.rescue()", "rescue", 700, 702))
    assert _auto_unreachable("evm.accounting_logic", doc, _loc(601, 603)) == "unknown"
