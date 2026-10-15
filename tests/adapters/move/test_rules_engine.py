"""Rule engine: text adds leads, never suppresses; guards are bytecode facts; ambiguity is kept."""

from pathlib import Path

import pytest
import yaml

from soken_review.adapters.move.bytecode import FunctionFacts, ModuleFacts
from soken_review.adapters.move.facts import LinkedSet
from soken_review.adapters.move.rules import FN_PREDICATES, Rule, _source_ok, load_rules, package_types
from soken_review.adapters.move.source import index_sources
from soken_review.adapters.move.units import normalize_address

ROOT = Path(__file__).resolve().parents[3] / "src" / "soken_review" / "adapters"


def test_all_rule_files_load_for_their_chain():
    assert len(load_rules(ROOT / "sui" / "rules", "sui")) >= 8
    assert len(load_rules(ROOT / "aptos" / "rules", "aptos")) >= 10


def test_text_negative_is_rejected_at_load(tmp_path):
    (tmp_path / "r.yaml").write_text(yaml.safe_dump([{
        "id": "X-1", "category": "move.missing_auth", "analyzer_severity_raw": "high",
        "facts": ["fn_public"], "source": {"negative": ["sender\\("]}}]))
    with pytest.raises(ValueError, match="text negatives"):
        load_rules(tmp_path, "sui")


def test_string_literal_cannot_satisfy_pattern():
    files = {"sources/a.move": 'module p::a {\n public fun f(): vector<u8> { b"x << 2" }\n}\n'}
    idx = index_sources(files, lambda p: True)
    span = idx.fns("a", "f")[0]
    rule = Rule(id="T", category="move.shift_overflow", raw="medium", chain="sui", scope="function", facts=[],
                pattern=__import__("re").compile("<<"), negative=[], fixtures={})
    assert not _source_ok(rule, span.signature + span.body)


def test_guard_is_a_bytecode_call_not_text():
    sui2 = normalize_address("0x2")
    m = ModuleFacts("sui", 7, normalize_address("0x0"), "a", [], [], [], {})
    with_call = FunctionFacts("f", "public", False, False, [], [], 0, calls=[f"{sui2}::tx_context::sender"])
    without = FunctionFacts("g", "public", False, False, [], [], 0, calls=[])
    pred = FN_PREDICATES["no_sender_call"]
    assert pred(None, m, with_call) is False
    assert pred(None, m, without) is True


def test_duplicate_function_spans_are_all_kept_and_file_partial():
    files = {"sources/a.move": "module p::a {\n public fun f() {}\n}\n",
             "sources/b.move": "module q::a {\n public fun f() { abort 1 }\n}\n"}
    idx = index_sources(files, lambda p: True)
    assert len(idx.fns("a", "f")) == 2
    assert idx.files["sources/a.move"] == "partial" and idx.files["sources/b.move"] == "partial"


def test_analyze_without_rebuilt_modules_is_unknown_and_not_ok(tmp_path):
    from soken_review.adapters.base import BuildResult, Candidate
    from soken_review.adapters.move.analyze import analyze

    (tmp_path / "host").mkdir()
    c = Candidate(provider="user", files={"sources/a.move": "module p::a { public fun f() {} }"}, sha256="",
                  language="move_sui", compiler=None, settings={}, std_json_input=None, entry_contract=None)
    _, sm, _ = analyze(BuildResult(candidate=c, status="ok", work_dir=str(tmp_path)), chain="sui", lint_runs=[],
                       lint_version="1", chain_extras={}, upgrade={"state": "immutable"},
                       in_scope=lambda p: True, rules_dir=ROOT / "sui" / "rules",
                       lint_map_path=ROOT / "sui" / "lint_map.yaml", dep_modules={})
    assert set(sm["nr"].values()) == {"unknown"}
    assert sm["status"] != "ok" and any(x["reason"] == "no_rebuilt_modules" for x in sm["not_run"])


# ---------------------------------------------------------------------------
# package_types: capability detection (wave-7) and suppression still removed (wave-6)
# ---------------------------------------------------------------------------

def _make_linked(chain: str, functions: list[FunctionFacts], errors: list[str] | None = None,
                 struct_abilities: list[str] | None = None) -> LinkedSet:
    """Build a LinkedSet with synthetic root module; bypasses bytecode parsing."""
    addr = normalize_address("0xabcd")
    struct_name = "AdminCap"
    abilities = struct_abilities if struct_abilities is not None else ["key"]
    m = ModuleFacts(chain, 7 if chain == "sui" else 8, addr, "mymod",
                    functions,
                    [{"name": struct_name, "abilities": abilities}],
                    [], {})
    ls = LinkedSet(chain, {}, {})
    ls.root = [m]
    ls.root_ids = {m.module_id}
    ls.root_addresses = {addr}
    ls.modules = {m.module_id: m}
    ls.fns = {f"{m.module_id}::{f.name}": (m, f) for f in functions}
    if errors is not None:
        ls.errors = errors
    return ls


def test_capability_detection_fires_for_key_struct_used_as_guard():
    """package_types phase-1 detects capability candidates (wave-7 fix).

    A root struct with ``key`` ability taken as ``&T`` (immutable ref) in a public/friend/entry
    function must appear in the returned capability set.  This makes the positive
    ``struct_is_capability`` predicate fire and the ``move.capability_leak`` rule (SUI, key+store)
    can detect the issue.

    Before the wave-7 fix: package_types always returned ``set()`` for capabilities (wave-6
    accidentally killed detection along with suppression).
    After the fix: the struct IS in the capability set.
    """
    addr = normalize_address("0xabcd")
    cap_qname = f"{addr}::mymod::AdminCap"

    guarded_fn = FunctionFacts(
        "do_admin", "public", False, False,
        [{"type": cap_qname, "ref": True, "mut": False, "abilities": ["key"]},
         {"type": "address", "ref": False, "mut": False, "abilities": []}],
        [], 0, calls=["something"],
    )
    ls = _make_linked("sui", [guarded_fn])
    _, caps = package_types(ls, "sui")
    assert cap_qname in caps, (
        f"key struct taken as &T in public fn must be in caps; got {caps}"
    )


def test_capability_struct_is_capability_predicate_fires():
    """struct_is_capability returns True when the struct name is in ctx.capabilities (wave-7).

    This exercises the full predicate path: package_types → ctx.capabilities →
    STRUCT_PREDICATES['struct_is_capability'].  Before the wave-7 fix, capabilities was always
    empty so the predicate always returned False — the move.capability_leak rule could never fire.
    """
    from soken_review.adapters.move.source import StructSpan
    addr = normalize_address("0xabcd")
    cap_qname = f"{addr}::mymod::AdminCap"

    guarded_fn = FunctionFacts(
        "do_admin", "public", False, False,
        [{"type": cap_qname, "ref": True, "mut": False, "abilities": ["key", "store"]}],
        [], 0,
    )
    ls = _make_linked("sui", [guarded_fn], struct_abilities=["key", "store"])
    _, caps = package_types(ls, "sui")

    # Build a minimal Ctx; only capabilities matters for struct_is_capability.
    from soken_review.adapters.move.rules import STRUCT_PREDICATES, Ctx
    from soken_review.adapters.move.source import SourceIndex
    ctx = Ctx(chain="sui", linked=ls, source=SourceIndex(),
              chain_extras={}, shared_types=set(), capabilities=caps)

    span = StructSpan(module="mymod", name="AdminCap", abilities=["key", "store"],
                      file="sources/a.move", start=1, end=5, body="")
    assert STRUCT_PREDICATES["struct_is_capability"](ctx, span), (
        "struct_is_capability must be True when struct is in ctx.capabilities"
    )


def test_function_with_cap_param_no_suppression_emits_lead():
    """A function taking &AdminCap still has no_capability_param suppression predicate
    removed: the predicate must NOT be in FN_PREDICATES (wave-6 permanent deletion).

    Suppression was removed because a suppressed lead is a silent gap; an extra lead
    costs one dismiss.  The reviewer (model + 04 validator) decides whether the guard
    is sufficient.
    """
    assert "no_capability_param" not in FN_PREDICATES, (
        "no_capability_param suppression must remain permanently deleted (wave-6)"
    )


# ---------------------------------------------------------------------------
# Friend visibility fail-open fix (wave-5)
# ---------------------------------------------------------------------------

def test_friend_function_is_included_by_public_or_entry_predicate():
    """`public(friend)` functions must fire rules that use `fn_public_or_entry`.

    Before the fix `_p_public_or_entry` only checked `visibility == "public"` and `.entry`,
    so friend-visibility functions silently passed through all rules that gate on that
    predicate — a fail-open on the callable surface.
    """
    addr = normalize_address("0xabcd")
    m = ModuleFacts("sui", 7, addr, "mymod", [], [], [], {})

    friend_fn = FunctionFacts("privileged_op", "friend", False, False, [], [], 0)
    public_fn = FunctionFacts("public_op", "public", False, False, [], [], 0)
    private_fn = FunctionFacts("internal_op", "private", False, False, [], [], 0)
    entry_fn = FunctionFacts("entry_op", "private", True, False, [], [], 0)

    pred = FN_PREDICATES["fn_public_or_entry"]
    # friend must pass — it is part of the callable surface
    assert pred(None, m, friend_fn) is True, "friend function must be included by fn_public_or_entry"
    assert pred(None, m, public_fn) is True
    assert pred(None, m, entry_fn) is True
    # private without entry must NOT pass (it is not on the callable surface)
    assert pred(None, m, private_fn) is False


