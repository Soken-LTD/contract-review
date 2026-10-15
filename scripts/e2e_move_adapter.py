"""Sui and Aptos live proof through the adapter code path only (plan v4 07 4, 6, 7; 09 5.2).

    uv run python scripts/e2e_move_adapter.py [name ...]

Per target: chain_state at a pinned checkpoint / ledger version (supervisor reads) -> fetch
(registry, MVR or repo; git in the sandbox) -> adapter build in the sandbox -> supervisor-side
comparison (host/provenance.json) -> adapter analyze in the sandbox -> case dir for
scripts/e2e_leads.py. Negative controls exercise the fail-closed paths on real data.
Needs SOKEN_IMAGE_SUI_BUILD, SOKEN_IMAGE_APTOS_BUILD, SOKEN_IMAGE_GIT_FETCH, SOKEN_SANDBOX_RUNTIME
and the SOKEN_MOVE_NETWORK docker network.
"""

from __future__ import annotations

import json
import shutil
import sys
import time
from dataclasses import asdict
from pathlib import Path

from soken_review.adapters.aptos import AptosAdapter
from soken_review.adapters.aptos.chain import read_chain_state as aptos_chain_state
from soken_review.adapters.base import ChainValue
from soken_review.adapters.sui import SuiAdapter
from soken_review.adapters.sui.chain import read_chain_state as sui_chain_state

ROOT = Path(__file__).resolve().parents[1] / ".sbx" / "move-e2e"

TARGETS = [
    {"name": "aptos-pancakeswap", "chain": "aptos",
     "address": "0xc7efb4076dbe143cbcd98cfaaa929ecfc8f299203dfff63b95ccb6bfe19850fa"},
    {"name": "aptos-liquidswap", "chain": "aptos",
     "address": "0x190d44266241744264b964a37b8f09863167a12d3e70cda39376cfb4e3561e12"},
    {"name": "sui-mvr-core", "chain": "sui",
     "address": "0xbb97fa5af2504cc944a8df78dcb5c8b72c3673ca4ba8e4969a98188bf745ee54"},
    {"name": "sui-deepbook-v1", "chain": "sui",
     "address": "0x2c8d603bc51326b8c13cef9dd07031a408a48dddb541963357661df5d3204809"},
    # negative controls
    {"name": "neg-aptos-no-package", "chain": "aptos", "control": "no_source",
     "address": "0x00000000000000000000000000000000000000000000000000000000000000ab"},
    {"name": "neg-aptos-untrusted", "chain": "aptos", "control": "untrusted",
     "address": "0xc7efb4076dbe143cbcd98cfaaa929ecfc8f299203dfff63b95ccb6bfe19850fa"},
    {"name": "neg-aptos-module-dropped", "chain": "aptos", "control": "drop_module",
     "address": "0xc7efb4076dbe143cbcd98cfaaa929ecfc8f299203dfff63b95ccb6bfe19850fa"},
    {"name": "neg-sui-no-image", "chain": "sui", "control": "no_image",
     "address": "0xbb97fa5af2504cc944a8df78dcb5c8b72c3673ca4ba8e4969a98188bf745ee54"},
]


def _case_dir(t: dict, cand, build, leads, static_map, read_plan, cs_file: Path) -> Path:
    case = ROOT / "cases" / t["name"]
    shutil.rmtree(case, ignore_errors=True)
    src = case / f"{cand.provider}_0"
    for path, text in cand.files.items():
        (src / path).parent.mkdir(parents=True, exist_ok=True)
        (src / path).write_text(text)
    meta = {k: v for k, v in asdict(cand).items() if k != "files"}
    (case / "candidates.json").write_text(json.dumps([meta], indent=1, default=str))
    cs = json.loads(cs_file.read_text())
    (case / "case.json").write_text(json.dumps({
        "chain": t["chain"], "chain_id": None, "address": t["address"],
        "checkpoint": cs.get("checkpoint"), "ledger_version": cs.get("ledger_version")}))
    (case / "build_result.json").write_text(json.dumps({"status": build.status, "reason": build.reason,
                                                         "nsloc": build.nsloc}))
    (case / "leads.json").write_text(json.dumps(leads, indent=1))
    (case / "static_map.json").write_text(json.dumps(static_map, indent=1))
    (case / "read_plan.json").write_text(json.dumps(read_plan, indent=1))
    return case


def run(t: dict) -> dict:
    t0 = time.time()
    work = ROOT / t["name"]
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    adapter = SuiAdapter() if t["chain"] == "sui" else AptosAdapter()
    cs = (sui_chain_state if t["chain"] == "sui" else aptos_chain_state)(t["address"])
    out: dict = {"name": t["name"], "chain": t["chain"]}
    if cs is None or (t["chain"] == "aptos" and not cs["packages"]):
        out |= {"stage": "chain_state", "result": "insufficient_source", "reason": "no_package_at_address"}
        return out
    cs_file = work / "chain_state.json"
    cs_file.write_text(json.dumps(cs))
    out["pin"] = cs.get("checkpoint") or cs.get("ledger_version")
    bundles = adapter.fetch_source({"address": t["address"], "chain_state_file": str(cs_file),
                                    "work_dir": str(work / "fetch")}, {t["chain"]: ChainValue(cs, "pinned")})
    cands = bundles[0].candidates
    if not cands:
        out |= {"stage": "fetch", "result": "insufficient_source"}
        return out
    cand = cands[0]
    out["provider"] = cand.provider
    out["files"] = len(cand.files)
    if t.get("control") == "untrusted":
        cand.files["PancakeSwap/build/PancakeSwap/bytecode_modules/swap.mv"] = "planted"
    if t.get("control") == "drop_module":
        from soken_review.adapters.move.units import normalize_address as _norm_addr
        _addr = _norm_addr(t["address"]) or t["address"]
        cand.files.pop(f"{_addr}/PancakeSwap/sources/u256.move")
    if t.get("control") == "no_image":
        import os
        os.environ["SOKEN_IMAGE_SUI_BUILD"] = ""
    build = adapter.build(cand, work / "build")
    out |= {"build": build.status, "build_reason": build.reason, "nsloc": build.nsloc,
            "untrusted": cand.untrusted_inputs}
    prov_file = work / "build" / "host" / "provenance.json"
    if prov_file.is_file():
        prov = json.loads(prov_file.read_text())
        units = prov.get("units") or {"package": prov}
        out["dep_match"] = {n: (p.get("dep_match"), p.get("reason")) for n, p in units.items()}
    if build.status != "ok":
        out["stderr"] = (build.stderr_head or "")[-600:]
        return out
    leads, static_map, read_plan = adapter.analyze(build)
    out |= {"analyze": static_map["status"], "not_run": static_map["not_run"], "leads": len(leads),
            "by_tool": {tool: sum(1 for ld in leads if any(x.startswith(tool) for x in ld["tools"]))
                        for tool in static_map["tools"]},
            "nr": static_map["nr"], "secs": round(time.time() - t0)}
    out["case"] = str(_case_dir(t, cand, build, leads, static_map, read_plan, cs_file))
    return out


def main(names: list[str]) -> int:
    rows = []
    for t in TARGETS:
        if names and t["name"] not in names:
            continue
        try:
            rows.append(run(t))
        except Exception as exc:  # noqa: BLE001 - one target failing must not hide the others
            rows.append({"name": t["name"], "error": f"{type(exc).__name__}: {exc}"[:600]})
        print(json.dumps(rows[-1], default=str), flush=True)
    ok = all("error" not in r for r in rows)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
