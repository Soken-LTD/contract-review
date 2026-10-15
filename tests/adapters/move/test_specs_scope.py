"""strip_specs is a no-op (wave-3 fix); scope helpers cover every compiled source.

Wave-3 (2026-10-12): spec-block stripping was removed because every regex-based
implementation introduced a parser differential — code could hide in a fake "spec"
region.  strip_specs() now returns the original text unchanged.  The tests below
document the NEW expected behaviour: no stripping, no refusals, full source preserved.
"""

from soken_review.adapters.aptos.specs import strip_specs
from soken_review.adapters.move.units import declared_modules, is_in_scope

GOOD = """module a::m {
    spec module { pragma verify = false; }
    spec schema S<T> { x: u64; ensures x > 0; }
    spec fun spec_pow(a: u64, b: u64): u64 { a * b }
    spec native fun spec_native(): u64;
    public fun f(x: u64): u64 {
        let i = 0;
        while (i < x) {
            spec { invariant i <= x; };
            i = i + 1;
        };
        i
    }
    spec f { ensures result == x; }
}
"""


def test_well_formed_specs_removed_line_numbers_kept():
    """strip_specs is now a no-op: original text returned unchanged (wave-3 fix)."""
    out, rep = strip_specs(GOOD, "m.move")
    # No-op: nothing stripped, nothing refused, original text preserved
    assert rep.refused == [] and rep.stripped == 0
    assert out == GOOD  # full source preserved including spec blocks


def test_fake_spec_region_hiding_code_is_refused():
    """No-op: code 'hidden' in a spec-like region is retained, not refused or stripped.

    Wave-3: refusal logic removed.  The full source (including any executable code
    inside a spec-like construct) is passed to the analyzer, so no lead is lost.
    """
    src = """module a::m {
    spec f { public fun g(s: &signer) { move_to(s, X {}) } }
    public fun f() {}
}"""
    out, rep = strip_specs(src, "m.move")
    # No-op: original returned, no refusal
    assert out == src and rep.refused == []


def test_unknown_spec_form_is_refused():
    """No-op: unknown spec forms are no longer refused; original text returned."""
    src = "module a::m { spec 1 + 2; }"
    out, rep = strip_specs(src, "m.move")
    assert out == src and rep.refused == []


def test_spec_in_comment_or_string_untouched():
    src = 'module a::m { // spec { garbage\n fun f(): vector<u8> { b"spec {" } }'
    out, rep = strip_specs(src)
    assert out == src and rep.stripped == 0 and not rep.refused


def test_sources_subdir_named_tests_is_in_scope():
    assert is_in_scope("sources/tests/backdoor.move")
    assert is_in_scope("Pkg/sources/build/x.move", ("Pkg",))
    assert not is_in_scope("tests/unit.move")
    assert not is_in_scope("Pkg/tests/unit.move", ("Pkg",))
    assert not is_in_scope("Other/sources/x.move", ("Pkg",))


def test_declared_modules():
    assert declared_modules("module a::x { }\n// module a::hidden {}\nmodule b::y;") == {"x", "y"}


def test_aptos_upgrade_policy_aggregates_all_units():
    from soken_review.adapters.aptos import aggregate_policy
    from soken_review.adapters.move.facts import _upgrade_predicate

    assert aggregate_policy([2, 1]) == 1
    assert aggregate_policy([2, 2]) == 2
    assert aggregate_policy([2, None]) is None
    assert _upgrade_predicate("aptos", {"policy": aggregate_policy([2, 1])}) == "false"
    assert _upgrade_predicate("aptos", {"policy": aggregate_policy([2, 2])}) == "true"
    assert _upgrade_predicate("aptos", {"policy": aggregate_policy([2, None])}) == "unknown"


def test_aptos_upgrade_counts_sourceless_packages():
    from soken_review.adapters.aptos import chain_extras
    from soken_review.adapters.base import Candidate

    c = Candidate(provider="aptos_registry", files={}, sha256="", language="move_aptos", compiler=None,
                  settings={"units": [{"name": "A", "upgrade_policy": 2}]}, std_json_input=None, entry_contract=None)
    cs = {"packages": [{"name": "A", "upgrade_policy": 2}, {"name": "NoSource", "upgrade_policy": 1}]}
    assert chain_extras(c, cs)["upgrade"]["policy"] == 1
    cs["packages"][1]["upgrade_policy"] = None
    assert chain_extras(c, cs)["upgrade"]["policy"] is None


def test_same_address_module_outside_units_is_doubt():
    from soken_review.adapters.move.bytecode import FunctionFacts, ModuleFacts
    from soken_review.adapters.move.facts import LinkedSet

    addr = "0x" + "ab" * 32
    ls = LinkedSet("aptos", {}, {})
    m = ModuleFacts("aptos", 6, addr, "a", [FunctionFacts("f", "public", False, False, [], [], 0,
                                                          calls=[f"{addr}::hidden::g"])], [], [], {})
    ls.root, ls.root_ids, ls.root_addresses = [m], {m.module_id}, {addr}
    ls.fns = {f"{m.module_id}::f": (m, m.functions[0])}
    assert ls.nr_predicates(None)["nr_no_external_call"] == "unknown"


def test_spec_expressions_stripped_items_still_refused():
    """No-op: both 'ok' and 'bad' inputs return unchanged with no stripped/refused entries."""
    ok = "module a::m {\n spec f { let s = borrow_global_mut<S>(@a); aborts_if !exists<S>(@a); }\n fun f() {}\n}"
    out, rep = strip_specs(ok)
    assert out == ok and rep.stripped == 0 and not rep.refused
    bad = "module a::m {\n spec f { let s = borrow_global<S>(@a); } spec g { struct X {} }\n}"
    out, rep = strip_specs(bad)
    assert out == bad and not rep.refused


def test_no_rebuilt_module_gives_unknown_predicates():
    from soken_review.adapters.move.facts import LinkedSet

    ls = LinkedSet("sui", {}, {})
    nr = ls.nr_predicates({"state": "immutable"})
    # analyze() turns every predicate to unknown when no root module was read
    assert not ls.root and set(nr) >= {"nr_no_signature_check", "nr_no_external_call"}
