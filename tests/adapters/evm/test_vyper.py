"""Vyper plug-in inside the EVM gate (05 section 15): compiler cache, build input, advisories, dispatch."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.adapters.evm.build import InputSanitizationError
from soken_review.adapters.evm.compiler import CompilerCacheError
from soken_review.adapters.vyper import advisories as va
from soken_review.adapters.vyper import build as vb
from soken_review.adapters.vyper import compiler as vc


def _cand(version: str = "0.3.0+commit.8a23feb", files: dict | None = None, pinned_by: str = "sourcify",
          std: dict | None = None, settings: dict | None = None) -> Candidate:
    return Candidate(provider="sourcify", files=files or {"P.vy": "x: uint256\n"}, sha256="", language="vyper",
                     compiler=Compiler(version=version, version_pinned_by=pinned_by), settings=settings or {},
                     std_json_input=std, entry_contract="P.vy:P")


# --- compiler cache -----------------------------------------------------------------------

def test_release_rows_pinned_with_source():
    rows = vc._releases()
    pinned = [r for r in rows if r["sha256"]]
    assert {"0.2.4", "0.3.0", "0.3.10", "0.4.3"} <= {r["version"] for r in pinned}
    for r in pinned:
        assert r["sha256_source"] in ("github_asset_digest",) or r["sha256_source"].startswith("first_download")
        assert r["url"].startswith("https://github.com/vyperlang/vyper/releases/download/")


def test_find_release_exact_and_commit_mismatch():
    assert vc.find_release("0.2.4+commit.7949850")["version"] == "0.2.4"
    assert vc.find_release("0.2.4")["version"] == "0.2.4"
    assert vc.find_release("0.2.4+commit.deadbee") is None
    assert vc.find_release("9.9.9") is None


@pytest.mark.parametrize("version", ["0.4.0b1", "0.1.0-beta.17", "0.3.10rc2"])
def test_prerelease_refused(tmp_path, version):
    with pytest.raises(CompilerCacheError):
        vc.VyperCache(tmp_path).binary(version)


def test_unpinned_release_refused(tmp_path):
    unpinned = next(r for r in vc._releases() if not r["sha256"])
    with pytest.raises(CompilerCacheError):
        vc.VyperCache(tmp_path).binary(unpinned["long_version"])


def test_download_with_wrong_sha_refused_and_right_sha_cached(tmp_path, monkeypatch):
    row = vc.find_release("0.2.4")
    monkeypatch.setattr(vc, "_http_get", lambda url: b"not the binary")
    with pytest.raises(CompilerCacheError):
        vc.VyperCache(tmp_path).binary("0.2.4")
    assert not (tmp_path / vc.PLATFORM_DIR / f"vyper-{row['long_version']}").exists()
    payload = b"fake vyper"
    monkeypatch.setattr(vc, "find_release", lambda v: {**row, "sha256": hashlib.sha256(payload).hexdigest()})
    monkeypatch.setattr(vc, "_http_get", lambda url: payload)
    path = vc.VyperCache(tmp_path).binary("0.2.4")
    assert path.read_bytes() == payload
    path.write_bytes(b"tampered")  # a changed cache entry is refused on next use
    with pytest.raises(CompilerCacheError):
        vc.VyperCache(tmp_path).binary("0.2.4")


# --- build input --------------------------------------------------------------------------

def test_prepare_std_input_composes_and_selects_outputs():
    inp = vb.prepare_std_input(_cand(settings={"search_paths": ["."], "evmVersion": "istanbul"}))
    assert inp["language"] == "Vyper"
    assert inp["sources"] == {"P.vy": {"content": "x: uint256\n"}}
    assert inp["settings"]["outputSelection"] == {"*": ["abi", "evm.bytecode", "evm.deployedBytecode", "ast"]}
    assert inp["settings"]["evmVersion"] == "istanbul"


@pytest.mark.parametrize(
    "std",
    [
        {"sources": {"../x.vy": {"content": ""}}},
        {"sources": {"/abs.vy": {"content": ""}}},
        {"sources": {"a.vy": {"content": ""}}, "interfaces": {"../i.json": {}}},
        {"sources": {"a.vy": {"content": ""}}, "settings": {"search_paths": ["../.."]}},
        {"sources": {"a.vy": {"content": ""}}, "settings": {"search_paths": ["/etc"]}},
        {"sources": {"a.vy": {"content": ""}}, "settings": {"evmVersion": "--evil"}},
    ],
)
def test_unsafe_inputs_refused(std):
    with pytest.raises(InputSanitizationError):
        vb.prepare_std_input(_cand(std=std))


def test_urls_dropped():
    inp = vb.prepare_std_input(_cand(std={"sources": {"a.vy": {"content": "", "urls": ["/etc/passwd"]}}}))
    assert "urls" not in inp["sources"]["a.vy"]


def test_evm_build_dispatches_vyper(monkeypatch):
    from soken_review.adapters.evm import build as eb

    seen = {}

    def fake(candidate, cache_dir=None, work_dir=None):
        seen["c"] = candidate
        return BuildResult(candidate=candidate, status="failed", reason="x")

    monkeypatch.setattr(vb, "build", fake)
    cand = _cand()
    eb.build(cand)
    assert seen["c"] is cand


def test_vyper_build_unpinned_is_not_checkable(tmp_path):
    unpinned = next(r for r in vc._releases() if not r["sha256"])
    res = vb.build(_cand(version=unpinned["long_version"]), cache_dir=tmp_path, work_dir=tmp_path)
    assert res.status == "failed" and res.reason == "compiler_binary_missing"


# --- advisories ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("0.3.0+commit.8a23feb", ">= 0.2.15, < 0.3.1", True),
        ("0.3.1", ">= 0.2.15, < 0.3.1", False),
        ("0.2.14", ">= 0.2.15, < 0.3.1", False),
        ("0.4.3", ">= 0.4.1", True),
        ("0.2.4", ">= 0", True),
        ("0.1.0b14", "= 0.1.0b14", True),
        ("0.2.4", "garbage", None),
        ("0.2.4", None, None),
    ],
)
def test_in_range(version, spec, expected):
    assert va.in_range(version, spec) is expected


def test_strip_comments_keeps_strings_and_lines():
    src = 'a = "x # not a comment"  # raw_call(value=1, is_static_call=True)\nb = 1\n'
    out = va.strip_comments(src)
    assert "raw_call" not in out and '"x # not a comment"' in out and out.count("\n") == 2


_POOL = '''
@external
@nonreentrant('lock')
def exchange(i: int128):
    pass

@external
@nonreentrant('lock')
def remove_liquidity(a: uint256):
    pass

@external
@nonreentrant('other')
def solo():
    pass

@internal
def _f(a: uint256 = 1) -> uint256:
    return a

@external
def g(x: uint256):
    for i in range(x, x + 10):
        pass
    # concat(b"a", b"b") in a comment
    y: Bytes[64] = concat(b"a", b"b")
'''


def _report(version: str, src: str = _POOL, pinned_by: str = "sourcify"):
    return va.vyper_report(version, pinned_by, {"sources": {"Pool.vy": {"content": src}}})


def _leads(rep) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for item in rep.raw_leads:
        out.setdefault(item["rule_id"], []).append(item["start"])
    return out


def test_named_lock_advisory_fires_on_shared_key_only():
    """F30 GHSA-5824-cm3x-3c38: `lock` shared by two functions fires, `other` used once does not."""
    leads = _leads(_report("0.3.0+commit.8a23feb"))
    assert leads["compiler.GHSA-5824-cm3x-3c38"] == [3, 8]
    assert leads["compiler.GHSA-6r8q-pfpv-7cgj"] == [23]       # range(x, x + N) before 0.3.8
    assert leads["compiler.GHSA-ph9x-4vc9-m39g"] == [18]       # internal default argument
    assert leads["compiler.GHSA-2q8v-3gqq-4f8p"] == [26]       # concat in code, not the comment


def test_fixed_release_has_no_named_lock_row():
    rows = {r["bug"]: r["status"] for r in _report("0.3.1").advisories}
    assert "GHSA-5824-cm3x-3c38" not in rows
    rows = {r["bug"]: r["status"] for r in _report("0.3.0", src="x: uint256\n").advisories}
    assert rows["GHSA-5824-cm3x-3c38"] == "construct_not_found"


def test_vyper_leads_are_lead_v1():
    import jsonschema

    from soken_review.adapters.evm.analyze import _LEAD_SCHEMA, _build_leads

    leads = _build_leads(_report("0.3.0").raw_leads)
    assert leads
    for lead in leads:
        jsonschema.validate(lead, _LEAD_SCHEMA)
        assert lead["category"] == "evm.compiler_bug" and lead["tools"] == [va.tool_id()]
    assert {lead["severity_norm"] for lead in leads if lead["rule_id"] == "compiler.GHSA-5824-cm3x-3c38"} == {"High"}


@pytest.mark.parametrize(("pinned_by", "version", "reason"), [
    ("pragma_guess", "0.3.0", "version_pinned_by_pragma"),
])
def test_not_run(pinned_by, version, reason):
    rep = _report(version, pinned_by=pinned_by)
    assert rep.status == "not_run" and rep.reason == reason and not rep.raw_leads


@pytest.mark.parametrize(("pinned_by", "fires"), [("sourcify", True), ("pragma_guess", False)])
def test_decision_point_reads_pinned_by_from_build(tmp_path, pinned_by, fires):
    from soken_review.adapters.evm.build import write_host_build_copy
    from soken_review.adapters.vyper.analyze import advisory_report

    write_host_build_copy(tmp_path, {"sources": {"Pool.vy": {"content": _POOL}}}, {})
    cand = _cand(version="0.3.0+commit.8a23feb", pinned_by=pinned_by)
    rep = advisory_report(BuildResult(candidate=cand, status="ok", work_dir=str(tmp_path)))
    assert bool(rep.raw_leads) is fires


def test_evm_analyze_dispatches_vyper(monkeypatch, tmp_path):
    from soken_review.adapters.evm import analyze as ea
    from soken_review.adapters.vyper import analyze as vya

    monkeypatch.setattr(vya, "analyze", lambda r: (["sentinel"], {"status": "ok"}, {}))
    leads, _, _ = ea.analyze(BuildResult(candidate=_cand(), status="ok", work_dir=str(tmp_path)))
    assert leads == ["sentinel"]


def test_advisory_data_pinned():
    data = json.loads((Path(va.__file__).parent / "data" / "vyper_advisories.json").read_text())
    ids = {a["ghsa_id"] for a in data["advisories"]}
    assert "GHSA-5824-cm3x-3c38" in ids and data["checked_at"]
    assert set(va.DETECTORS) <= ids


def test_scanners_linear_on_pathological_source():
    n = 100_000
    for src in ["raw_call(" * n, "@nonreentrant(" * (n // 10), "range(" + "(" * n, "#" * n, '"' * n, "@internal\ndef f(" * (n // 20)]:
        t0 = time.perf_counter()
        va.source_view(src)  # tokenize + token lock scan
        raw_view = va.SourceView(text=src)  # detectors on the raw text too (bypassing tokenize)
        va._text_indexes(raw_view)
        for det in set(va.DETECTORS.values()):
            det(raw_view)
        assert time.perf_counter() - t0 < 3.0, src[:20]


# --- parse failures are hits, never absence ------------------------------------------------

def test_untokenisable_source_is_a_whole_file_hit():
    src = 'x: uint256\n"""unterminated docstring\n'
    rep = _report("0.3.0", src=src)
    rows = {r["bug"]: r for r in rep.advisories}
    assert rows["GHSA-5824-cm3x-3c38"]["status"] == "lead"
    assert rows["GHSA-5824-cm3x-3c38"]["unparsed_sources"] == ["Pool.vy"]
    assert all(item["start"] == 1 for item in rep.raw_leads)
    assert {r["status"] for r in rep.advisories} <= {"lead", "not_machine_checked"}


def test_triple_quoted_strings_do_not_hide_code():
    src = '"""it\'s a # docstring with a quote"""\n\n@external\ndef f():\n    y: Bytes[4] = concat(b"a", b"b")\n'
    assert _leads(_report("0.3.0", src=src))["compiler.GHSA-2q8v-3gqq-4f8p"] == [5]


def test_comment_hash_inside_triple_quotes_is_not_a_comment():
    src = '"""\n# not a comment, but a docstring line\n"""\nx: uint256 = 1  # real comment concat(\n'
    text = va.strip_comments(src)
    assert "# not a comment" in text and "concat(" not in text


def test_decorator_without_resolvable_function_is_a_hit():
    src = "@external\n@nonreentrant('lock')\n"  # no def follows: function unresolved
    assert _leads(_report("0.3.0", src=src))["compiler.GHSA-5824-cm3x-3c38"] == [2]
    src = "@external\n@nonreentrant(KEY)\ndef f():\n    pass\n"  # key not a literal: unresolved
    assert _leads(_report("0.3.0", src=src))["compiler.GHSA-5824-cm3x-3c38"] == [2]


def test_lock_facts_come_from_the_compiler_ast_when_present():
    """The AST says two functions share `lock`; the text alone shows one decorator."""
    src = "@external\n@nonreentrant('lock')\ndef a():\n    pass\n"
    dec = {"ast_type": "Call", "func": {"ast_type": "Name", "id": "nonreentrant"},
           "args": [{"ast_type": "Str", "value": "lock"}], "lineno": 2}
    ast = {"ast_type": "Module", "body": [
        {"ast_type": "FunctionDef", "name": "a", "lineno": 3, "decorator_list": [dec]},
        {"ast_type": "FunctionDef", "name": "b", "lineno": 9, "decorator_list": [{**dec, "lineno": 8}]},
    ]}
    rep = va.vyper_report("0.3.0", "sourcify", {"sources": {"Pool.vy": {"content": src}}},
                          {"sources": {"Pool.vy": {"ast": ast}}})
    assert sorted(_leads(rep)["compiler.GHSA-5824-cm3x-3c38"]) == [2, 8]
    rep_text_only = _report("0.3.0", src=src)
    assert "compiler.GHSA-5824-cm3x-3c38" not in _leads(rep_text_only)


def test_undelimited_calls_are_hits():
    # an unbalanced file: every text call detector is a whole-file hit
    view = va.SourceView(text="x = raw_call(a, b\n" + "y = range(i, \n")
    va._text_indexes(view)
    assert view.balanced is False
    assert va.DETECTORS["GHSA-w9g2-3w7p-72g9"](view) == [1]
    assert va.DETECTORS["GHSA-6r8q-pfpv-7cgj"](view) == [1]
    # balanced, but the first argument does not end within the window: a hit at the call
    long_arg = "y = 1\nz = range(" + "a" * 1000 + ", b)\n"
    view = va.SourceView(text=long_arg)
    va._text_indexes(view)
    assert va.DETECTORS["GHSA-6r8q-pfpv-7cgj"](view) == [2]



# --- algorithmic DoS: every detector linear in the file; AST depth capped ------------------

def _all_detectors(view):
    for det in set(va.DETECTORS.values()):
        va.run_detector(det, view)


def _megabyte(unit: str) -> str:
    return unit * (1_000_000 // len(unit))


@pytest.mark.parametrize("src", ids=["parens", "deep", "decorators", "internal", "raw_call", "range", "concat"], argvalues=[
    _megabyte("("),                                             # unbalanced, no tokens
    "x = " + "(" * 400_000 + "1" + ")" * 400_000 + "\n",       # deep balanced nesting
    _megabyte("@nonreentrant('k')\n"),                          # decorators, no def
    _megabyte("@internal\ndef f(a: uint256 = 1):\n    pass\n"),
    _megabyte("y = raw_call(a, b, value=1, is_static_call=True)\n"),
    _megabyte("z = range(x, x + 1)\n"),
    _megabyte("w = concat(concat(concat(b'a', b'b'), b'c'), b'd')\n"),
])
def test_one_megabyte_sources_finish_under_two_seconds(src):
    t0 = time.perf_counter()
    rep = va.vyper_report("0.3.0", "sourcify", {"sources": {"Big.vy": {"content": src}}})
    assert time.perf_counter() - t0 < 2.0
    assert rep.status == "ok"


def test_deep_ast_is_a_whole_file_hit_not_absence():
    node: dict = {"ast_type": "Int", "value": 1}
    for _ in range(va.MAX_AST_DEPTH + 50):
        node = {"ast_type": "BinOp", "op": {"ast_type": "Add"}, "left": node, "right": {"ast_type": "Int", "value": 1}}
    ast = {"ast_type": "Module", "body": [node]}
    t0 = time.perf_counter()
    rep = va.vyper_report("0.3.0", "sourcify", {"sources": {"Deep.vy": {"content": "x: uint256\n"}}},
                          {"sources": {"Deep.vy": {"ast": ast}}})
    assert time.perf_counter() - t0 < 2.0
    rows = {r["bug"]: r for r in rep.advisories}
    assert rows["GHSA-5824-cm3x-3c38"]["status"] == "lead"         # nothing proven absent
    assert rows["GHSA-5824-cm3x-3c38"]["unparsed_sources"] == ["Deep.vy"]


def test_wide_ast_with_many_calls_is_linear():
    calls = [{"ast_type": "Call", "func": {"ast_type": "Name", "id": "concat"}, "args": [], "keywords": [], "lineno": i}
             for i in range(1, 100_001)]
    ast = {"ast_type": "Module", "body": [{"ast_type": "IfExp", "lineno": 1, "body": calls}]}
    t0 = time.perf_counter()
    rep = va.vyper_report("0.3.0", "sourcify", {"sources": {"W.vy": {"content": ""}}}, {"sources": {"W.vy": {"ast": ast}}})
    assert time.perf_counter() - t0 < 2.0
    assert len([x for x in rep.raw_leads if x["rule_id"] == "compiler.GHSA-2q8v-3gqq-4f8p"]) == 100_000


# --- fail-closed: missing, unparsed or ambiguous input is a hit, never absence --------------

_UNKNOWN_AST = {"ast_type": "Module", "body": [{"ast_type": "SomeFutureNode", "lineno": 3, "value": {}}]}


@pytest.mark.parametrize("ghsa", sorted(va.DETECTORS))
def test_every_detector_hits_on_an_unknown_ast_node(ghsa):
    views = va.file_views("", _UNKNOWN_AST)
    assert va.run_detector(va.DETECTORS[ghsa], views) == [1]


@pytest.mark.parametrize("ghsa", sorted(va.DETECTORS))
def test_every_detector_hits_on_untokenisable_text_without_ast(ghsa):
    assert va.run_detector(va.DETECTORS[ghsa], va.file_views('"""never closed\n')) == [1]


@pytest.mark.parametrize("ghsa", sorted(va.DETECTORS))
def test_every_detector_hits_on_unreadable_ast(ghsa):
    assert va.run_detector(va.DETECTORS[ghsa], va.file_views("", ["not", "a", "module"])) == [1]


def test_unknown_node_reason_reaches_the_row():
    rep = va.vyper_report("0.3.0", "sourcify", {"sources": {"A.vy": {"content": ""}}},
                          {"sources": {"A.vy": {"ast": _UNKNOWN_AST}}})
    row = {r["bug"]: r for r in rep.advisories}["GHSA-5824-cm3x-3c38"]
    assert row["status"] == "lead"
    assert row["unparsed_reasons"]["A.vy"] == ["unknown_ast_node:SomeFutureNode"]


def test_parser_differential_takes_the_union():
    """The text sees a call the AST does not carry: the hit stands."""
    src = "@external\ndef f():\n    x: Bytes[2] = concat(b'a', b'b')\n"
    ast = {"ast_type": "Module", "body": [{"ast_type": "FunctionDef", "name": "f", "lineno": 2,
                                           "decorator_list": [{"ast_type": "Name", "id": "external"}],
                                           "args": {"ast_type": "arguments", "args": [], "defaults": []}, "body": []}]}
    rep = va.vyper_report("0.3.0", "sourcify", {"sources": {"A.vy": {"content": src}}}, {"sources": {"A.vy": {"ast": ast}}})
    assert _leads(rep)["compiler.GHSA-2q8v-3gqq-4f8p"] == [3]


@pytest.mark.parametrize("version", ["0.4.0b1", "banana", "0.3.10rc2"])
def test_unplaceable_version_keeps_every_advisory_in_scope(version):
    rep = _report(version)
    assert rep.status == "ok"
    rows = {r["bug"]: r for r in rep.advisories}
    assert len(rows) == len(va._load()["advisories"])
    assert all(r["conditions_unknown"] == ["version"] for r in rows.values())
    assert rows["GHSA-5824-cm3x-3c38"]["status"] == "lead"


def test_function_without_visibility_decorator_counts_as_internal():
    ast = {"ast_type": "Module", "body": [{"ast_type": "FunctionDef", "name": "g", "lineno": 4, "decorator_list": [],
                                           "args": {"ast_type": "arguments", "args": [],
                                                    "defaults": [{"ast_type": "Int", "value": 1}]},
                                           "body": []}]}
    assert va.run_detector(va.DETECTORS["GHSA-ph9x-4vc9-m39g"], va.file_views("", ast)) == [4]


def test_structural_compare_over_budget_is_a_match():
    a = {"ast_type": "List", "elts": [{"ast_type": "Int", "value": i} for i in range(20_000)]}
    b = {"ast_type": "List", "elts": [{"ast_type": "Int", "value": -1}] + a["elts"][1:]}  # differs at elts[0]
    assert va._same(a, b, budget=200_000) is False  # within budget: the difference is found
    assert va._same(a, b, budget=10) is True       # budget runs out before it: doubt = match (hit)


def test_multiline_ternary_with_msg_value_is_a_text_hit():
    src = "@external\n@payable\ndef f() -> uint256:\n    return (msg.value |\n        1) if True else 0\n"
    assert va.run_detector(va.DETECTORS["GHSA-6j9c-gvcw-74fj"], va.file_views(src)) == [4]


def test_text_range_one_argument_is_proven_not_x_plus_n():
    src = "@external\ndef f():\n    for i in range(255):\n        pass\n    for j in range(1, 256):\n        pass\n"
    assert va.run_detector(va.DETECTORS["GHSA-6r8q-pfpv-7cgj"], va.file_views(src)) == []
