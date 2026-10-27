"""Guards inherited from dependencies that are compiled but never pinned (04 2.1; Apyee blind run
2026-10-26: every `onlyOwner` function printed `guards: none` because the OpenZeppelin ASTs under
node_modules/ were not indexed).

Fixture: `src/Managed.sol` is the pinned file; `lib/oz/*` are minimal OpenZeppelin v5 replicas
(Ownable, Pausable, ReentrancyGuard) present in the solc output and in the compiled texts only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map" / "inherited"
PINNED = "src/Managed.sol"
DEPS = ("lib/oz/access/Ownable.sol", "lib/oz/utils/Context.sol", "lib/oz/utils/Pausable.sol",
        "lib/oz/utils/ReentrancyGuard.sol")


def _texts(paths) -> dict[str, str]:
    return {p: (FIX / p).read_text(encoding="utf-8") for p in paths}


@pytest.fixture(scope="module")
def doc() -> dict:
    out = json.loads((FIX / "solc_output.json").read_text(encoding="utf-8"))
    art = build_map(_texts([PINNED]), out, list(family_categories("evm")), build_ok=True,
                    compiled_texts=_texts([PINNED, *DEPS]))
    assert art.status == "full"
    return art.doc


def _fn(doc: dict, span: str) -> dict:
    return next(f for f in doc["semantic"]["functions"] if f["span"] == span)


def test_only_pinned_units_functions_and_spans(doc):
    assert [u["name"] for u in doc["semantic"]["units"]] == ["Managed"]
    assert {f["span"].split(".")[0] for f in doc["semantic"]["functions"]} == {"Managed"}
    assert all(sp["file"] == PINNED for sp in doc["spans"])
    assert {v["name"] for v in doc["semantic"]["state_vars"]} == {"keeper", "fee", "balances"}


def test_inherited_modifier_names_are_listed(doc):
    assert _fn(doc, "Managed.setFee(uint256)")["modifiers"] == ["onlyOwner"]
    assert _fn(doc, "Managed.deposit()")["modifiers"] == ["whenNotPaused", "nonReentrant"]


def test_only_owner_is_a_caller_check_on_the_reviewed_header_line_via_the_dependency(doc):
    # the check executes in Ownable._checkOwner (lib, never pinned); the map lists it on the
    # function header that applies the modifier, so fp_guarded can quote a pinned line
    assert _fn(doc, "Managed.setFee(uint256)")["guards"] == [
        {"class": "caller_check", "line": f"{PINNED}:23", "via": "lib/oz/access/Ownable.sol:32"}]
    assert _fn(doc, "Managed.setKeeper(address)")["guards"][0]["class"] == "caller_check"
    assert _fn(doc, "Managed.pause()")["guards"][0]["class"] == "caller_check"


def test_pause_and_reentrancy_guards_through_the_dependency(doc):
    guards = _fn(doc, "Managed.deposit()")["guards"]
    assert {"class": "pause_check", "line": f"{PINNED}:39", "via": "lib/oz/utils/Pausable.sol:31"} in guards
    assert {"class": "reentrancy_lock", "line": f"{PINNED}:39",
            "via": "lib/oz/utils/ReentrancyGuard.sol:24"} in guards


def test_inline_call_into_the_dependency_is_listed_at_the_call_site(doc):
    assert _fn(doc, "Managed.sweep(address)")["guards"] == [
        {"class": "caller_check", "line": f"{PINNED}:44", "via": "lib/oz/access/Ownable.sol:32"}]


def test_pinned_custom_modifier_keeps_the_executing_line_without_via(doc):
    assert _fn(doc, "Managed.harvest()")["guards"] == [{"class": "caller_check", "line": f"{PINNED}:17"}]


def test_unguarded_function_stays_unguarded(doc):
    assert _fn(doc, "Managed.open()")["guards"] == []


def test_roles_and_bases_see_the_dependency(doc):
    roles = {r["name"]: r["gated_functions"] for r in doc["semantic"]["roles"]}
    assert roles["onlyOwner"] == ["Managed.pause()", "Managed.setFee(uint256)", "Managed.setKeeper(address)"]
    assert roles["onlyKeeper"] == ["Managed.harvest()"]
    bases = doc["semantic"]["chain_extras"]["evm"]["units"][f"{PINNED}:Managed"]["bases"]
    assert {"Managed", "Ownable", "Pausable", "ReentrancyGuard", "Context"} <= set(bases)
    assert "Managed.setFee(uint256)" in doc["semantic"]["category_to_functions"]["evm.centralization"]


def test_dependency_without_text_still_resolves_and_names_the_path(doc):
    """No compiled text for the dependency (urls sources): the guard is still verified and the
    call site carries the dependency path as `via`."""
    out = json.loads((FIX / "solc_output.json").read_text(encoding="utf-8"))
    art = build_map(_texts([PINNED]), out, list(family_categories("evm")), build_ok=True)
    f = _fn(art.doc, "Managed.setFee(uint256)")
    assert f["guards"] == [{"class": "caller_check", "line": f"{PINNED}:23", "via": "lib/oz/access/Ownable.sol"}]
