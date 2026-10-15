"""Compiler advisories and construct detectors (05 6.2 A1 to A5).

Fixtures in tests/fixtures/evm/compiler_bugs/<case>/ are real solc std-json inputs and the
`sources` (compact AST) of the sandboxed build's output, so detectors run on true solc ASTs.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from soken_review.adapters.evm import compiler_bugs as cb
from soken_review.adapters.evm.analyze import _LEAD_SCHEMA, _build_leads

_FX = Path(__file__).parents[2] / "fixtures" / "evm" / "compiler_bugs"


def _case(name: str) -> tuple[dict, dict, dict]:
    d = _FX / name
    return (json.loads((d / "input.json").read_text()), json.loads((d / "output.json").read_text()),
            json.loads((d / "compiler.json").read_text()))


def _report(name: str, pinned_by: str | None = None) -> cb.CompilerBugReport:
    inp, out, comp = _case(name)
    return cb.solc_report(comp["version"], pinned_by or comp["version_pinned_by"], inp, out)


def _rows(rep: cb.CompilerBugReport) -> dict[str, str]:
    return {r["bug"]: r["status"] for r in rep.advisories}


def _leads(rep: cb.CompilerBugReport) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for item in rep.raw_leads:
        out.setdefault(item["rule_id"], []).append(item["start"])
    return out


# --- pinned data --------------------------------------------------------------------------

def test_pinned_files_match_sha256_and_cover_releases():
    by_version = cb._load_pinned("solc_bugs_by_version.json")
    bugs = cb._load_pinned("solc_bugs.json")
    assert "0.8.37" in by_version and "0.4.24" in by_version
    names = {b["name"] for b in bugs}
    for row in by_version.values():
        assert set(row["bugs"]) <= names


def test_tampered_pinned_file_is_refused(tmp_path, monkeypatch):
    for f in (cb._COMPILERS).iterdir():
        (tmp_path / f.name).write_bytes(f.read_bytes())
    (tmp_path / "solc_bugs.json").write_text("[]")
    monkeypatch.setattr(cb, "_COMPILERS", tmp_path)
    with pytest.raises(cb.PinnedDataError):
        cb._load_pinned("solc_bugs.json")


def test_detector_map_names_real_bugs_and_real_detectors():
    names = {b["name"] for b in cb._load_pinned("solc_bugs.json")}
    dmap = cb.detector_map()
    assert set(dmap) == names
    assert {d for d in dmap.values() if d} <= set(cb.DETECTORS)


# --- A1 and version handling ----------------------------------------------------------

def test_pragma_guess_runs_nothing():
    rep = _report("v0_4_24_opt", pinned_by="pragma_guess")
    assert rep.status == "not_run" and rep.reason == "version_pinned_by_pragma"
    assert rep.raw_leads == [] and rep.advisories == []


def test_unknown_version_is_not_run():
    inp, out, _ = _case("v0_4_24_opt")
    rep = cb.solc_report("0.4.99+commit.deadbeef", "sourcify", inp, out)
    assert rep.status == "not_run" and rep.reason == "version_not_in_bug_list"


# --- A2: located leads on real ASTs ----------------------------------------------------

def test_v0_4_24_optimized_constructs_fire():
    rep = _report("v0_4_24_opt")
    leads = _leads(rep)
    # Bugs.sol: Leaf (line 8) has no constructor, Base has one; keccak256 in assembly (10);
    # new uint[](n) (14); uint8 ** uint8 (18)
    assert leads["compiler.ImplicitConstructorCallvalueCheck"] == [8]
    assert leads["compiler.KeccakCaching"] == [10]
    assert leads["compiler.MemoryArrayCreationOverflow"] == [14]
    assert leads["compiler.ExpExponentCleanup"] == [18]
    rows = _rows(rep)
    assert rows["KeccakCaching"] == "lead"
    assert rows["EventStructWrongData"] == "construct_not_found"           # A3
    assert rows["LostStorageArrayWriteOnSlotOverflow"] == "not_machine_checked"  # A4
    assert rows["ABIEncoderV2PackedStorage_0.4.x"] == "settings_not_affected"   # no ABIEncoderV2
    for item in rep.raw_leads:
        assert item["category"] == "evm.compiler_bug" and item["file"] == "Bugs.sol"


def test_clean_contract_no_leads_and_base_contracts_ignored():
    rep = _report("v0_4_24_clean")
    assert rep.raw_leads == []
    rows = _rows(rep)
    assert rows["KeccakCaching"] == "construct_not_found"
    assert rows["MemoryArrayCreationOverflow"] == "construct_not_found"  # literal length
    assert rows["ImplicitConstructorCallvalueCheck"] == "construct_not_found"  # own constructor


def test_keccak_caching_needs_optimizer():
    inp, out, comp = _case("v0_4_24_opt")
    inp["settings"]["optimizer"]["enabled"] = False
    rep = cb.solc_report(comp["version"], "sourcify", inp, out)
    assert _rows(rep)["KeccakCaching"] == "settings_not_affected"
    assert "compiler.KeccakCaching" not in _leads(rep)


def test_v0_8_26_via_ir_constructs_fire():
    rep = _report("v0_8_26_ir")
    leads = _leads(rep)
    assert leads["compiler.MisorderedNamedParametersInRequireWithCustomErrors"] == [8]
    assert sorted(leads["compiler.SpillSlotCollisionAcrossMutualRecursion"]) == [11, 15]
    assert sorted(leads["compiler.UnsoundSpillInMutualRecursion"]) == [11, 15]
    assert _rows(rep)["MemoryByteArrayElementDeleteClearsWholeWord"] == "settings_not_affected"  # viaIR


def test_v0_8_26_legacy_delete_memory_bytes_element():
    rep = _report("v0_8_26_legacy")
    assert _leads(rep) == {"compiler.MemoryByteArrayElementDeleteClearsWholeWord": [6]}
    assert _rows(rep)["MisorderedNamedParametersInRequireWithCustomErrors"] == "settings_not_affected"


def test_leads_validate_as_lead_v1_with_category_and_severity():
    rep = _report("v0_4_24_opt")
    leads = _build_leads(rep.raw_leads)
    assert len(leads) == len(rep.raw_leads)
    by_rule = {lead["rule_id"]: lead for lead in leads}
    for lead in leads:
        jsonschema.validate(lead, _LEAD_SCHEMA)
        assert lead["category"] == "evm.compiler_bug"
        assert lead["tools"] == [cb.solc_bugs_tool()]
    assert by_rule["compiler.KeccakCaching"]["severity_norm"] == "Medium"
    assert by_rule["compiler.ExpExponentCleanup"]["severity_norm"] == "High"         # medium/high
    assert by_rule["compiler.ImplicitConstructorCallvalueCheck"]["severity_norm"] == "Info"  # very low


# --- settings derivation ----------------------------------------------------------------

@pytest.mark.parametrize(
    ("version", "settings", "key", "want", "expected"),
    [
        ("0.8.28+commit.7893614a", {"viaIR": True}, "evmVersion", ">=cancun", True),    # default cancun
        ("0.8.24+commit.e11b9ed9", {}, "evmVersion", ">=cancun", False),                # default shanghai
        ("0.8.24+commit.e11b9ed9", {"evmVersion": "cancun"}, "evmVersion", ">=cancun", True),
        ("0.5.16+commit.9c3226ce", {"optimizer": {"enabled": True}}, "yulOptimizer", True, False),
        ("0.6.12+commit.27d51765", {"optimizer": {"enabled": True}}, "yulOptimizer", True, True),
        ("0.6.12+commit.27d51765", {"optimizer": {"enabled": True, "details": {"yul": False}}}, "yulOptimizer", True, False),
    ],
)
def test_conditions(version, settings, key, want, expected):
    st = cb.derive_settings(version, {"settings": settings, "sources": {}})
    assert cb._condition_holds(key, want, st) is expected


def _unit(*pragmas: list[str]) -> dict:
    return {"nodeType": "SourceUnit", "nodes": [{"nodeType": "PragmaDirective", "literals": p} for p in pragmas]}


def _ctx_of(*units: dict) -> cb.Ctx:
    return cb.Ctx(sources={}, asts={f"u{i}.sol": u for i, u in enumerate(units)}, file_index={})


@pytest.mark.parametrize(
    ("version", "units", "expected"),
    [
        ("0.7.6", [_unit(["solidity", "^", "0.7", ".0"])], False),
        ("0.7.6", [_unit(["abicoder", "v2"])], True),
        ("0.7.6", [_unit(["experimental", "ABIEncoderV2"])], True),
        ("0.8.0", [_unit()], True),                                    # default v2 from 0.8.0
        ("0.8.0", [_unit(["abicoder", "v1"])], False),
        # one v1 unit does not switch v2 off for the others: v2 if ANY unit uses it
        ("0.8.0", [_unit(["abicoder", "v1"]), _unit()], True),
        ("0.7.6", [_unit(["abicoder", "v1"]), _unit(["abicoder", "v2"])], True),
    ],
)
def test_abi_coder_from_ast_pragmas(version, units, expected):
    st = cb.derive_settings(version, {"settings": {}, "sources": {}}, _ctx_of(*units))
    assert st.abi_encoder_v2 is expected


def test_commented_pragma_does_not_turn_v2_off():
    """`// pragma abicoder v1` in a comment is not a PragmaDirective: v2 stays on for 0.8.x."""
    src = "// pragma abicoder v1\npragma solidity 0.8.0;\n"
    st = cb.derive_settings("0.8.0", {"settings": {}, "sources": {"a.sol": {"content": src}}},
                            _ctx_of(_unit(["solidity", "0.8", ".0"])))
    assert st.abi_encoder_v2 is True


def test_abi_coder_unknown_without_ast_keeps_bug_in_scope():
    st = cb.derive_settings("0.7.6", {"settings": {}, "sources": {}}, None)
    assert st.abi_encoder_v2 is None
    assert cb._condition_holds("ABIEncoderV2", True, st) is None
    inp, out, comp = _case("v0_4_24_opt")
    for src in out["sources"].values():
        src["ast"] = {"name": "SourceUnit"}  # no compact AST
    rows = {r["bug"]: r for r in cb.solc_report(comp["version"], "sourcify", inp, out).advisories}
    row = rows["ABIEncoderV2PackedStorage_0.4.x"]
    assert row["status"] != "settings_not_affected"
    assert row["conditions_unknown"] == ["ABIEncoderV2"]


def test_unknown_condition_key_keeps_bug_in_scope():
    st = cb.derive_settings("0.8.0", {"settings": {}, "sources": {}}, None)
    assert cb._condition_holds("someFutureSetting", True, st) is None


def test_pragma_on_real_ast_fixture():
    """The 0.4.24 fixture has no ABIEncoderV2 pragma: proven False from its AST."""
    inp, out, comp = _case("v0_4_24_opt")
    st = cb.derive_settings(comp["version"], inp, cb.build_ctx(inp, out))
    assert st.abi_encoder_v2 is False


# --- ReDoS: attacker-controlled source text and type strings ------------------------------

def _timed(fn, *args) -> float:
    import time

    t0 = time.perf_counter()
    fn(*args)
    return time.perf_counter() - t0


def test_scanners_are_linear_on_pathological_input():
    n = 200_000
    types = ["][" * n, "[" + "1" * n + "][" + "1" * n, "returns (" + "[1]" * n + "x", "uint8" + "[]" * n]
    for t in types:
        assert _timed(cb._has_two_dim_array, t, True) < 1.0
        assert _timed(cb._has_two_dim_array, t, False) < 1.0
        assert _timed(cb._small_dynamic_array_base_size, t) < 1.0


def test_two_dim_and_yul_helpers_still_match():
    assert cb._has_two_dim_array("function () returns (uint256[2][3] memory)", fixed=True)
    assert not cb._has_two_dim_array("uint256[][] memory", fixed=True)
    assert cb._has_two_dim_array("uint256[][] memory", fixed=False)
    assert not cb._has_two_dim_array("uint256[] memory", fixed=False)
    assert cb._small_dynamic_array_base_size("uint128[] storage ref") == 16
    assert cb._small_dynamic_array_base_size("address[] storage ref") is None


@pytest.mark.parametrize(("pinned_by", "fires"), [("sourcify", True), ("pragma_guess", False), ("pragma", False)])
def test_decision_point_reads_version_pinned_by_from_the_build(tmp_path, pinned_by, fires):
    """A1 at the decision point analyze() uses: the candidate's own version_pinned_by reaches it."""
    from soken_review.adapters.base import BuildResult, Candidate, Compiler
    from soken_review.adapters.evm.analyze import compiler_bug_report

    inp, out, comp = _case("v0_4_24_opt")
    from soken_review.adapters.evm.build import write_host_build_copy

    write_host_build_copy(tmp_path, inp, out)
    cand = Candidate(provider="user", files={}, sha256="", language="solidity",
                     compiler=Compiler(version=comp["version"], version_pinned_by=pinned_by),
                     settings={}, std_json_input=None, entry_contract=None)
    rep = compiler_bug_report(BuildResult(candidate=cand, status="ok", work_dir=str(tmp_path)))
    assert bool(rep.raw_leads) is fires
    assert rep.status == ("ok" if fires else "not_run")


def test_no_compact_ast_is_not_machine_checked():
    inp, out, comp = _case("v0_4_24_opt")
    for src in out["sources"].values():
        src["ast"] = {"name": "SourceUnit"}  # legacy-format AST
    rep = cb.solc_report(comp["version"], "sourcify", inp, out)
    assert rep.raw_leads == []
    assert {r["status"] for r in rep.advisories} <= {"not_machine_checked", "settings_not_affected"}


# --- Yul facts come from the compact AST; no Yul AST = hit -------------------------------

def _call(name: str) -> dict:
    return {"nodeType": "YulFunctionCall", "functionName": {"nodeType": "YulIdentifier", "name": name}, "arguments": []}


def _asm(ast: dict | None, refs: list | None = None) -> dict:
    node = {"nodeType": "InlineAssembly", "src": "0:10:0", "externalReferences": refs or []}
    if ast is not None:
        node["AST"] = ast
    return node


def _ctx_with(*nodes: dict) -> cb.Ctx:
    unit = {"nodeType": "SourceUnit", "nodes": list(nodes), "src": "0:10:0"}
    return cb.Ctx(sources={"a.sol": b"x" * 10}, asts={"a.sol": unit}, file_index={0: "a.sol"})


def test_yul_ast_drives_keccak_and_memory_detectors():
    block = {"nodeType": "YulBlock", "statements": [{"nodeType": "YulExpressionStatement", "expression": _call("sload")}]}
    ctx = _ctx_with(_asm(block))
    assert cb.d_keccak_in_assembly(ctx) == []           # "keccak256(" in a comment is not in the AST
    assert cb.d_assembly_memory_write_no_locals(ctx) == []
    block2 = {"nodeType": "YulBlock", "statements": [{"nodeType": "YulExpressionStatement", "expression": _call("keccak256")},
                                                     {"nodeType": "YulExpressionStatement", "expression": _call("mstore")}]}
    ctx2 = _ctx_with(_asm(block2))
    assert len(cb.d_keccak_in_assembly(ctx2)) == 1
    assert len(cb.d_assembly_memory_write_no_locals(ctx2)) == 1


def test_conditional_termination_inside_yul_function_only():
    inner = {"nodeType": "YulBlock", "statements": [{"nodeType": "YulExpressionStatement", "expression": _call("return")}]}
    fdef = {"nodeType": "YulFunctionDefinition", "name": "f", "body": inner}
    assert len(cb.d_yul_function_conditional_termination(_ctx_with(_asm({"nodeType": "YulBlock", "statements": [fdef]})))) == 1
    top = {"nodeType": "YulBlock", "statements": [
        {"nodeType": "YulFunctionDefinition", "name": "g", "body": {"nodeType": "YulBlock", "statements": []}},
        {"nodeType": "YulExpressionStatement", "expression": _call("return")},
    ]}
    assert cb.d_yul_function_conditional_termination(_ctx_with(_asm(top))) == []


def test_no_yul_ast_is_a_hit_for_every_yul_detector():
    ctx = _ctx_with(_asm(None))  # pre-0.6 output: `operations` text only
    assert len(cb.d_keccak_in_assembly(ctx)) == 1
    assert len(cb.d_assembly_memory_write_no_locals(ctx)) == 1
    assert len(cb.d_yul_function_conditional_termination(ctx)) == 1


def test_advisories_never_read_work_out(tmp_path):
    """Only the host-only copy counts: files under work/out (container-writable) are ignored."""
    from soken_review.adapters.evm.build import write_host_build_copy

    inp, out, comp = _case("v0_4_24_opt")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "input.json").write_text(json.dumps(inp))
    (tmp_path / "out" / "output.json").write_text(json.dumps(out))
    rep = cb.report_from_work_dir(tmp_path, comp["version"], "sourcify")
    assert rep.status == "not_run" and rep.reason == "build_output_missing" and not rep.raw_leads
    write_host_build_copy(tmp_path, inp, out)
    (tmp_path / "out" / "output.json").write_text("{}")  # a later container rewrites work/out
    assert cb.report_from_work_dir(tmp_path, comp["version"], "sourcify").raw_leads
