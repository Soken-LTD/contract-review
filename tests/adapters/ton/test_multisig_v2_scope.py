"""TON multisig v2, blind round 5b (2026-10-31): library source in scope, stdlib without leads.

Job job_9G81X4WACSP4HZA0B0G7392QDS (EQBabkaz2T0_ZoRDzaMqZheJIDeRCJgwxMlsQ1GigwsjQlP-) matched at tier A,
but:

1. The order contract code is the masterchain library 0x6305a806...; its source (`order.func`) is
   verified on its own in the sources registry and was never fetched, so the reviewer could not
   read the half of the system that carries approvals. Now the library source is fetched, rebuilt,
   matched to the library hash read from the chain (own tier) and pinned under `_related/`.
2. 26 of the 27 leads sat on `imports/stdlib.fc` (asm prototypes, send-mode constants). The FunC
   standard library yields no leads and is pinned as a dependency.

Recorded fixtures (no network): tests/fixtures/ton/multisig_v2 (the multisig bundle, getLibraries
answer) and tests/fixtures/ton/multisig_v2_order (the order library's registry bundle and settings,
and its rebuild with func 0.4.4 in the locked ton-build image, hash 6305a806..., recorded 2026-10-31).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import Artifact, BuildResult, Candidate, Compiler
from soken_review.adapters.ton import analyze as analyze_mod
from soken_review.adapters.ton import fetch as fetch_mod
from soken_review.adapters.ton.cell import root_info
from soken_review.adapters.ton.provenance import MATCH_REBUILD, Attempt, Out, deployment_doc
from soken_review.adapters.ton.units import is_stdlib_file, stdlib_paths
from soken_review.pinning.store import PinnedSource
from soken_review.worker import ton_pipeline
from tests.worker.test_map_step_ton_starknet import _fake_sup, _FakeRepo, _write

FIX = Path(__file__).parent.parent.parent / "fixtures" / "ton"
MSIG = FIX / "multisig_v2"
ORDER = FIX / "multisig_v2_order"
DEPLOYED_HASH = "d3d14da9a627f0ec3533341829762af92b9540b21bf03665fac09c2b46eabbac"
ORDER_LIB = "6305a8061c856c2ccf05dcb0df5815c71475870567cab5f049e340bcf59251f3"
FRIENDLY = "EQBabkaz2T0_ZoRDzaMqZheJIDeRCJgwxMlsQ1GigwsjQlP-"
RAW = "0:5a6e46b3d93d3f668443cdca32a6178920dd1109098cc4c96cd4351a2830b235"
LIB_DIR = "_related/library_6305a8061c85"


def _tree(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob("*") if p.is_file()}


def _msig_cand(**settings) -> Candidate:
    return Candidate(provider="ton_verifier", files=_tree(MSIG / "src"), sha256="m" * 64, language="func",
                     compiler=Compiler(version="0.4.4", version_pinned_by="ton_verifier"),
                     settings={"stdlib_files": ["imports/stdlib.fc"], **settings}, std_json_input=None,
                     entry_contract=None)


def _order_cand() -> Candidate:
    meta = json.loads((ORDER / "library_candidate.json").read_text())
    return Candidate(provider="ton_verifier", files=_tree(ORDER / "src"), sha256="o" * 64, language="func",
                     compiler=Compiler(version=meta["compiler"], version_pinned_by="ton_verifier"),
                     settings=meta["settings"], std_json_input=None, entry_contract=None,
                     source_url=f"https://verifier.ton.org/{ORDER_LIB}")


def _libraries_result() -> dict:
    return json.loads((MSIG / "getLibraries.json").read_text())["result"]


# ── 1. fetch: the library's verified source comes with the referencing candidate ─────────────


@pytest.mark.asyncio
async def test_library_source_is_fetched_once_per_hash():
    a, b = _msig_cand(), _msig_cand()
    fetch_src = AsyncMock(return_value=_order_cand())
    cache: dict = {}
    with patch.object(fetch_mod, "_toncenter", AsyncMock(return_value=_libraries_result())), \
         patch.object(fetch_mod, "_registry_get_source_item_address", AsyncMock(return_value="EQitem")), \
         patch.object(fetch_mod, "fetch_source_from_registry", fetch_src):
        rows = await fetch_mod.resolve_library_refs(MagicMock(), a, sources=cache)
        await fetch_mod.resolve_library_refs(MagicMock(), b, sources=cache)
    assert rows[0]["status"] == "ok" and rows[0]["source_fetched"] is True
    fetch_src.assert_awaited_once()
    for cand in (a, b):
        lib = cand.settings["library_sources"][ORDER_LIB]
        assert "contracts/order.func" in lib["files"] and lib["compiler_version"] == "0.4.4"
        assert lib["settings"]["verifier"]["code_hash"] == ORDER_LIB
    # the JSON form round-trips (cands/<i>.json is how the build step gets it)
    back = fetch_mod.library_candidate_from_json(json.loads(json.dumps(a.settings["library_sources"][ORDER_LIB])))
    assert back.files == _order_cand().files and back.compiler.version == "0.4.4"


@pytest.mark.asyncio
async def test_no_library_source_without_a_body_or_a_registry_item():
    cand = _msig_cand()
    fetch_src = AsyncMock(return_value=_order_cand())
    with patch.object(fetch_mod, "_toncenter", AsyncMock(return_value=_libraries_result())), \
         patch.object(fetch_mod, "_registry_get_source_item_address", AsyncMock(return_value=None)), \
         patch.object(fetch_mod, "fetch_source_from_registry", fetch_src):
        await fetch_mod.resolve_library_refs(MagicMock(), cand)
    assert "library_sources" not in cand.settings
    fetch_src.assert_not_awaited()


@pytest.mark.asyncio
async def test_library_source_registry_failure_keeps_the_job():
    cand = _msig_cand()
    with patch.object(fetch_mod, "_toncenter", AsyncMock(return_value=_libraries_result())), \
         patch.object(fetch_mod, "_registry_get_source_item_address", AsyncMock(return_value="EQitem")), \
         patch.object(fetch_mod, "fetch_source_from_registry", AsyncMock(side_effect=RuntimeError("registry down"))):
        rows = await fetch_mod.resolve_library_refs(MagicMock(), cand)
    assert rows[0]["status"] == "ok" and rows[0]["source_fetched"] is False
    assert "library_sources" not in cand.settings


# ── 1. build: rebuilt, matched to the library hash, pinned with its own tier ───────────────────


def _fake_build(runtime_hash: str | None, reason: str = "compile_error"):
    def build(c, work_dir):
        if runtime_hash is None:
            return BuildResult(candidate=c, status="failed", reason=reason)
        art = Artifact(contract="contracts/order.func", creation="", runtime=runtime_hash, immutable_refs={},
                       link_refs={}, source_map="", storage_layout=None)
        return BuildResult(candidate=c, status="ok", artifacts=[art], work_dir=str(work_dir))
    return build


def _with_library() -> Candidate:
    order = _order_cand()
    return _msig_cand(library_refs=[{"hash": ORDER_LIB, "status": "ok",
                                     "verified_source": f"https://verifier.ton.org/{ORDER_LIB}"}],
                      library_sources={ORDER_LIB: fetch_mod.library_candidate_to_json(order)})


def test_library_rebuild_equal_to_the_hash_is_tier_a(tmp_path, monkeypatch):
    rebuilt = root_info((ORDER / "rebuilt_order_0.4.4.boc").read_bytes()).hash
    assert rebuilt == ORDER_LIB
    monkeypatch.setattr(ton_pipeline._build_mod, "build", _fake_build(rebuilt))
    cand = _with_library()
    _files, langs, in_scope, records = ton_pipeline._resolve_libraries(tmp_path, cand)
    assert records[0]["status"] == "pinned" and records[0]["tier"] == "A" and records[0]["match"] == "exact"
    assert records[0]["path"] == LIB_DIR and records[0]["hash"] == ORDER_LIB
    assert in_scope[f"{LIB_DIR}/contracts/order.func"] is True
    # its standard library and the files equal to the reviewed multisig files are readable, not reviewed
    for p in ("imports/stdlib.fc", "types.func", "messages.func", "errors.func", "op-codes.func"):
        assert in_scope[f"{LIB_DIR}/contracts/{p}"] is False, p
    assert records[0]["files_in_scope"] == 1 and set(langs.values()) == {"func"}
    row = cand.settings["library_refs"][0]
    assert (row["source_tier"], row["source_path"]) == ("A", LIB_DIR)


def test_library_rebuild_with_another_hash_is_not_pinned(tmp_path, monkeypatch):
    monkeypatch.setattr(ton_pipeline._build_mod, "build", _fake_build("00" * 32))
    files, _langs, _scope, records = ton_pipeline._resolve_libraries(tmp_path, _with_library())
    assert files == {} and records[0]["status"] == "source_not_matched" and records[0]["tier"] == "D"
    assert "not part of this review" in records[0]["note"]


def test_library_attested_but_compiler_missing_is_tier_b(tmp_path, monkeypatch):
    monkeypatch.setattr(ton_pipeline._build_mod, "build", _fake_build(None, "unsupported_toolchain"))
    _files, _langs, scope, records = ton_pipeline._resolve_libraries(tmp_path, _with_library())
    assert records[0]["tier"] == "B" and records[0]["match"] == "third_party_verified_only"
    assert scope[f"{LIB_DIR}/contracts/order.func"] is True


def test_library_body_not_read_is_never_pinned(tmp_path, monkeypatch):
    monkeypatch.setattr(ton_pipeline._build_mod, "build", _fake_build(ORDER_LIB))
    cand = _with_library()
    cand.settings["library_refs"][0]["status"] = "unavailable"
    assert ton_pipeline._resolve_libraries(tmp_path, cand) == ({}, {}, {}, [])


def test_report_row_names_the_library_tier_and_path():
    prov = {"reason": "MATCH_REBUILD", "tier": "A", "address": RAW, "dep_hash": DEPLOYED_HASH,
            "build_hash": DEPLOYED_HASH, "library_refs": [{"hash": ORDER_LIB, "status": "ok", "verified_source": "x",
                                                           "source_tier": "A", "source_path": LIB_DIR}]}
    doc = deployment_doc(prov, None, FRIENDLY)
    assert doc["library_refs"][0]["source_tier"] == "A" and doc["library_refs"][0]["source_path"] == LIB_DIR
    from soken_review.report.assemble import _build_verification_blocks

    rows = [r for b in _build_verification_blocks(doc, None, {"chain": "ton", "address": FRIENDLY})
            if "table" in b for r in b["table"]["rows"]]
    lib = next(r for r in rows if r[0] == "Library reference")
    assert "rebuilt to this hash" in lib[1] and LIB_DIR in lib[1]


# ── 1 + 3 end to end: build pins both, analyze yields no stdlib lead and reads order.func ─────


@pytest.mark.asyncio
async def test_build_and_analyze_pin_the_order_source_and_skip_stdlib(tmp_path, monkeypatch):
    repo = _FakeRepo()
    sup = _fake_sup(tmp_path, repo, monkeypatch, ton_pipeline)
    sup._after_build = AsyncMock()
    sup._after_analyze = AsyncMock()
    job = {"job_id": "job_TONMSIG2", "chain": "ton", "address": FRIENDLY,
           "source_args": {"kind": "deployed", "chain": "ton", "address": FRIENDLY}}
    out_dir = sup._job_dir(job["job_id"])
    _write(out_dir / "chain_state.json", {"mc_seqno": 102476117, "accounts": {
        RAW: {"status": "active", "code_hash": DEPLOYED_HASH, "dep_hash": DEPLOYED_HASH}}})
    cand = _with_library()
    _write(out_dir / "candidates.json", [{"provider": "ton_verifier", "sha256": cand.sha256, "language": "func",
                                          "compiler": {"version": "0.4.4", "version_pinned_by": "ton_verifier"},
                                          "entry_contract": None, "files": sorted(cand.files)}])
    _write(out_dir / "cands" / "0.json", ton_pipeline._cand_to_json(cand))

    def fake_resolve(_out_dir, _cs, cands):
        out = Out(0, "exact", MATCH_REBUILD, tried=[Attempt(0, "ton_verifier", "ok", {"multisig.func": DEPLOYED_HASH})],
                  matched_target="multisig.func", dep_hash=DEPLOYED_HASH, build_hash=DEPLOYED_HASH)
        return out, {0: BuildResult(candidate=cands[0], status="failed", reason="compile_error")}

    monkeypatch.setattr(ton_pipeline, "_resolve", fake_resolve)
    monkeypatch.setattr(ton_pipeline._build_mod, "build", _fake_build(ORDER_LIB))
    await ton_pipeline._build(sup, {"id": 7, "job_id": job["job_id"], "step": "build", "seq": 0}, job)

    pin = PinnedSource.load(sup._pin_root, job["job_id"])
    entries = pin.entries
    assert entries["multisig.func"].in_scope and entries["multisig.func"].role == "source"
    assert not entries["imports/stdlib.fc"].in_scope and entries["imports/stdlib.fc"].role == "dependency"
    order = entries[f"{LIB_DIR}/contracts/order.func"]
    assert order.in_scope and order.role == "source" and order.lang == "func"
    assert pin.read_text(f"{LIB_DIR}/contracts/order.func") == (ORDER / "src/contracts/order.func").read_text()
    build_prov = sup._mark_step.await_args.kwargs["provenance"]
    assert build_prov["related"][0]["tier"] == "A" and build_prov["related"][0]["path"] == LIB_DIR
    assert build_prov["stdlib"] == ["imports/stdlib.fc"]
    dep = json.loads((out_dir / "deployment.json").read_text())
    assert dep["library_refs"][0]["source_tier"] == "A"

    await ton_pipeline._analyze(sup, {"id": 8, "job_id": job["job_id"], "step": "analyze", "seq": 0}, job)
    leads = json.loads((sup._pin_root / job["job_id"] / "leads.json").read_text())
    files = {lead["file"] for lead in leads}
    assert not any(f.endswith("stdlib.fc") for f in files), files
    assert f"{LIB_DIR}/contracts/order.func" in files, files
    assert any(f == "multisig.func" for f in files), files
    static_map = json.loads((out_dir / "static_map.json").read_text())
    assert static_map["stdlib_excluded"] == ["imports/stdlib.fc"]


def test_review_status_lists_the_library_from_the_build_step():
    from soken_review.tools.start_status import _proxy_related_status

    rec = {"name": "library_6305a8061c85", "role": "library", "hash": ORDER_LIB, "status": "pinned",
           "provider": "ton_verifier", "match": "exact", "tier": "A", "path": LIB_DIR, "files": 6, "note": "n"}
    _proxy, rows = _proxy_related_status([{"step": "build", "status": "done", "provenance": {"related": [rec]}}])
    assert rows == [{k: v for k, v in rec.items()}]


# ── 3. stdlib detection ───────────────────────────────────────────────────


def test_multisig_stdlib_is_detected_by_name_and_content():
    files = _tree(MSIG / "src")
    assert stdlib_paths(files) == {"imports/stdlib.fc"}
    # the manifest flag alone also counts, with the same content check
    assert stdlib_paths({"lib/std.fc": files["imports/stdlib.fc"]}, ["lib/std.fc"]) == {"lib/std.fc"}


def test_project_code_named_stdlib_stays_in_scope():
    sends = ("() send_raw_message(cell msg, int mode) impure asm \"SENDRAWMSG\";\n"
             "() pay(slice to) inline { send_raw_message(begin_cell().end_cell(), 128); }\n")
    assert not is_stdlib_file("imports/stdlib.fc", sends)
    impure = "int f() asm \"NOW\";\n() g() impure inline { }\n"
    assert not is_stdlib_file("stdlib.fc", impure)
    assert not is_stdlib_file("contracts/helpers.fc", "int f() asm \"NOW\";\n")
    # a <{ }> block inside an asm string is not a function body
    assert is_stdlib_file("stdlib.fc", 'int f() asm "<{ NOW }> PUSHCONT EXECUTE";\n')
    assert not is_stdlib_file("stdlib.fc", "const int X = 1;\n")          # no asm: not the stdlib


def test_analyze_drops_stdlib_leads_only(tmp_path):
    cand = _msig_cand()
    br = BuildResult(candidate=cand, status="failed", reason="compile_error")
    leads, static_map, _ = analyze_mod.analyze(br, tmp_path / "source_only")
    files = {lead["file"] for lead in leads}
    assert "imports/stdlib.fc" not in files and "multisig.func" in files
    assert static_map["stdlib_excluded"] == ["imports/stdlib.fc"]
    # without the filter the rule pack fires on the stdlib (the round 5b noise)
    raw = analyze_mod._run_ton_rules(cand.files)
    assert sum(r["file"] == "imports/stdlib.fc" for r in raw) >= 10
