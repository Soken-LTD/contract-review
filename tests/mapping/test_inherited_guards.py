"""Guards inherited from dependencies that are compiled but never pinned (04 2.1; Apyee blind run
2026-10-26: every `onlyOwner` function printed `guards: none` because the OpenZeppelin ASTs under
node_modules/ were not indexed).

Fixture: `src/Managed.sol` is the pinned file; `lib/oz/*` are minimal OpenZeppelin v5 replicas
(Ownable, Pausable, ReentrancyGuard) present in the solc output and in the compiled texts only.

Trust (security review of PR #84): a dependency guard is credited only when the dependency is
integrity-pinned in the run (`trusted_prefixes`); otherwise it is a `name_only` hint that
fp_guarded and `fixed` never accept. `doc` builds with `lib/oz/` trusted; `untrusted_doc` without.
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


def _build(**kw) -> dict:
    out = json.loads((FIX / "solc_output.json").read_text(encoding="utf-8"))
    art = build_map(_texts([PINNED]), out, list(family_categories("evm")), build_ok=True,
                    compiled_texts=_texts([PINNED, *DEPS]), **kw)
    assert art.status == "full"
    return art.doc


@pytest.fixture(scope="module")
def doc() -> dict:
    return _build(trusted_prefixes=("lib/oz/",))


@pytest.fixture(scope="module")
def untrusted_doc() -> dict:
    return _build()


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
    art = build_map(_texts([PINNED]), out, list(family_categories("evm")), build_ok=True,
                    trusted_prefixes=("lib/oz/",))
    f = _fn(art.doc, "Managed.setFee(uint256)")
    assert f["guards"] == [{"class": "caller_check", "line": f"{PINNED}:23", "via": "lib/oz/access/Ownable.sol"}]


# ---------------------------------------------------------------- untrusted dependency

def test_untrusted_dependency_guard_is_a_name_only_hint(untrusted_doc):
    """Without an integrity pin the OZ check is a hint: the class is kept as `hint`, the line and
    `via` still tell the reviewer where to look, and no caller_check exists for fp_guarded."""
    f = _fn(untrusted_doc, "Managed.setFee(uint256)")
    assert f["modifiers"] == ["onlyOwner"]
    assert f["guards"] == [{"class": "name_only", "hint": "caller_check", "line": f"{PINNED}:23",
                            "via": "lib/oz/access/Ownable.sol:32"}]
    dep = _fn(untrusted_doc, "Managed.deposit()")["guards"]
    assert {g["class"] for g in dep} == {"name_only"} and {g["hint"] for g in dep} == {"pause_check", "reentrancy_lock"}
    assert _fn(untrusted_doc, "Managed.sweep(address)")["guards"][0]["class"] == "name_only"


def test_untrusted_dependency_does_not_gate_roles_or_centralization(untrusted_doc):
    roles = {r["name"]: r["gated_functions"] for r in untrusted_doc["semantic"]["roles"]}
    assert "onlyOwner" not in roles and roles["onlyKeeper"] == ["Managed.harvest()"]
    assert "Managed.setFee(uint256)" not in untrusted_doc["semantic"]["category_to_functions"]["evm.centralization"]


def test_pinned_custom_modifier_is_credited_without_any_trust(untrusted_doc):
    assert _fn(untrusted_doc, "Managed.harvest()")["guards"] == [{"class": "caller_check", "line": f"{PINNED}:17"}]


def test_prefix_must_cover_the_executing_file():
    d = _build(trusted_prefixes=("lib/oz/utils/",))   # Pausable and ReentrancyGuard trusted, Ownable not
    assert _fn(d, "Managed.setFee(uint256)")["guards"][0]["class"] == "name_only"
    assert {g["class"] for g in _fn(d, "Managed.deposit()")["guards"]} == {"pause_check", "reentrancy_lock"}


def test_file_removed_by_the_scope_rules_is_never_credited():
    d = _build(trusted_prefixes=("lib/oz/",), untrusted_paths=frozenset({"lib/oz/access/Ownable.sol"}))
    assert _fn(d, "Managed.setFee(uint256)")["guards"][0]["class"] == "name_only"
    assert _fn(d, "Managed.sweep(address)")["guards"][0]["class"] == "name_only"
    assert _fn(d, "Managed.deposit()")["guards"][0]["class"] in {"pause_check", "reentrancy_lock"}


def test_hints_never_satisfy_fp_guarded(untrusted_doc):
    """The dismissal check matches `class == caller_check` on the guards list (tools/dismiss.py);
    a hint row has class `name_only`, so a quote of the header line cannot pass as fp_guarded."""
    f = _fn(untrusted_doc, "Managed.setFee(uint256)")
    assert not any(g["class"] == "caller_check" for g in f["guards"])
