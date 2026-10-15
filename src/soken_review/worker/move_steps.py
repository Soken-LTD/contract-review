"""Supervisor steps for Sui and Aptos jobs (plan v4 07 section 4; 09 3.1, 3.4, 3.6).

Same step order and job states as the EVM path in supervisor.py:
  chain_state (supervisor, read-only provider reads, pinned checkpoint / ledger version)
  -> fetch (MVR / registry / repo / inline; git only in the sandbox) -> pin
  -> build (sandbox; the supervisor compares with chain_state and writes host/provenance.json)
  -> analyze (sandbox lints + rules) -> ready.
Every function here is synchronous and called through run_in_executor. Outputs are files in the
job dir so each step is restartable (09 3.4).
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..adapters.base import BuildResult, Candidate, ChainValue, Compiler
from ..pinning.store import PinnedSource

MOVE_CHAINS = {"sui", "aptos"}
LANG_CHAIN = {"move_sui": "sui", "move_aptos": "aptos"}


def job_chain(job: dict[str, Any]) -> str | None:
    chain = job.get("chain")
    if chain in MOVE_CHAINS:
        return chain
    args = _args(job)
    return LANG_CHAIN.get(args.get("language", "")) if job.get("source_kind") == "files" else None


def _args(job: dict[str, Any]) -> dict[str, Any]:
    a = job.get("source_args") or {}
    return json.loads(a) if isinstance(a, str) else a


def adapter(chain: str):
    if chain == "sui":
        from ..adapters.sui import SuiAdapter
        return SuiAdapter()
    from ..adapters.aptos import AptosAdapter
    return AptosAdapter()


def chain_state(job: dict[str, Any], out_dir: Path) -> str:
    """Write chain_state.json. Returns 'ok', 'no_address' (inline/repo without deployment) or
    'no_package' (terminal insufficient_source). Provider errors raise (step retried, then failed)."""
    chain = job_chain(job)
    address = job.get("address")
    if not address:
        return "no_address"
    if chain == "sui":
        from ..adapters.sui.chain import read_chain_state
        cs = read_chain_state(address)
        if cs is None:
            return "no_package"
    else:
        from ..adapters.aptos.chain import read_chain_state
        cs = read_chain_state(address)
        if not cs["packages"]:
            return "no_package"
    (out_dir / "chain_state.json").write_text(json.dumps(cs), encoding="utf-8")
    return "ok"


def fetch(job: dict[str, Any], out_dir: Path, pin_root: Path) -> dict[str, Any] | None:
    """Candidate -> pin + candidates.json. None = no source (insufficient_source)."""
    chain = job_chain(job)
    args = _args(job)
    cs_file = out_dir / "chain_state.json"
    cs = json.loads(cs_file.read_text()) if cs_file.exists() else None
    j: dict[str, Any] = {"address": job.get("address"), "chain_state_file": str(cs_file) if cs else None,
                         "work_dir": str(out_dir / "fetch")}
    if job.get("source_kind") == "repo":
        j |= {"repo_url": args["repo_url"], "commit": args.get("commit") or args.get("ref") or "HEAD",
              "package_dir": args.get("subdir") or "."}
    elif job.get("source_kind") == "files":
        j["files"] = {f["path"]: f["content"] for f in args.get("files", [])}
    bundles = adapter(chain).fetch_source(j, {chain: ChainValue(cs, "pinned")} if cs else {})
    if not bundles or not bundles[0].candidates:
        (out_dir / "candidates.json").write_text("[]", encoding="utf-8")
        return None
    cand = bundles[0].candidates[0]
    pin = PinnedSource.from_files({p: t.encode("utf-8") for p, t in cand.files.items()},
                                  langs={p: cand.language for p in cand.files})
    pin.persist(pin_root, job["job_id"])
    meta = {k: v for k, v in asdict(cand).items() if k != "files"}
    (out_dir / "candidates.json").write_text(json.dumps([meta], indent=1, default=str), encoding="utf-8")
    return {"source_pin": pin.source_pin, "provider": cand.provider, "sha256": cand.sha256}


def _candidate(out_dir: Path, pin_root: Path, job_id: str) -> Candidate:
    raw = json.loads((out_dir / "candidates.json").read_text())[0]
    pin = PinnedSource.load(pin_root, job_id)
    files = {p: "\n".join(pin.read_all(p)) for p in pin.entries}
    comp = raw.get("compiler")
    return Candidate(provider=raw["provider"], files=files, sha256=raw["sha256"], language=raw["language"],
                     compiler=Compiler(**comp) if comp else None, settings=raw.get("settings") or {},
                     std_json_input=None, entry_contract=raw.get("entry_contract"), source_url=raw.get("source_url"),
                     fetched_at=raw.get("fetched_at"))


def build(job: dict[str, Any], out_dir: Path, pin_root: Path) -> dict[str, Any]:
    cand = _candidate(out_dir, pin_root, job["job_id"])
    work = out_dir / "work"

    # Dep pre-fetch wiring for Sui non-inline packages (wave-4 design: build always offline).
    # Never rewrites Move.lock or Move.toml.  Instead, pre-populates the MOVE_HOME cache
    # (dirs["move"]) so the CLI can find the framework deps at the path it expects.
    # Non-framework git deps and wrong-commit framework deps → deps_unreachable (fail closed).
    chain = job_chain(job)
    if chain == "sui" and (cand.settings or {}).get("kind") != "inline":
        from soken_review.adapters.move import sandbox as _sbx
        from soken_review.adapters.sui.build import _check_move_lock, populate_move_home_deps
        pkg_dir = (cand.settings or {}).get("package_dir") or "."
        if _check_move_lock(cand.files, pkg_dir) is not None:
            # There are git deps; pre-populate MOVE_HOME before the offline build.
            try:
                dirs = _sbx.prepare_dirs(work)
            except PermissionError as exc:
                result: dict[str, Any] = {
                    "status": "failed", "reason": "sandbox_unavailable", "nsloc": 0,
                    "stderr_head": str(exc), "work_dir": None,
                    "untrusted_inputs": cand.untrusted_inputs, "provenance": None,
                }
                (out_dir / "build_result.json").write_text(json.dumps(result), encoding="utf-8")
                return result
            err = populate_move_home_deps(cand.files, pkg_dir, chain, dirs)
            if err is not None:
                result = {
                    "status": "failed", "reason": "deps_unreachable", "nsloc": 0,
                    "stderr_head": err, "work_dir": str(work),
                    "untrusted_inputs": cand.untrusted_inputs, "provenance": None,
                }
                (out_dir / "build_result.json").write_text(json.dumps(result), encoding="utf-8")
                return result

    r = adapter(job_chain(job)).build(cand, work)
    prov_file = work / "host" / "provenance.json"
    result = {"status": r.status, "reason": r.reason, "nsloc": r.nsloc, "stderr_head": r.stderr_head,
              "work_dir": r.work_dir, "untrusted_inputs": cand.untrusted_inputs,
              "provenance": json.loads(prov_file.read_text()) if prov_file.is_file() else None}
    (out_dir / "build_result.json").write_text(json.dumps(result), encoding="utf-8")
    if r.work_dir:
        (out_dir / "work_dir.txt").write_text(r.work_dir, encoding="utf-8")
    return result


def analyze(job: dict[str, Any], out_dir: Path, pin_root: Path) -> tuple[list[dict[str, Any]], bool]:
    """(leads, degraded). Build failure: no leads, degraded (09 3.6 non-terminal)."""
    res = json.loads((out_dir / "build_result.json").read_text())
    if res["status"] != "ok":
        return [], True
    cand = _candidate(out_dir, pin_root, job["job_id"])
    r = BuildResult(candidate=cand, status="ok", nsloc=res.get("nsloc", 0), work_dir=res["work_dir"])
    from ..adapters.move import sandbox as _move_sandbox
    # One step deadline for the whole analyze step (09 UV9-8): each container inside the adapter
    # gets min(per_container_wall_s, remaining); if deadline is exhausted the next analyzer is
    # skipped with reason "step_deadline".
    deadline = time.monotonic() + _move_sandbox.ANALYZE_STEP_WALL_S
    leads, static_map, read_plan = adapter(job_chain(job)).analyze(r, step_deadline=deadline)
    (out_dir / "static_map.json").write_text(json.dumps(static_map), encoding="utf-8")
    (out_dir / "read_plan.json").write_text(json.dumps(read_plan), encoding="utf-8")
    return leads, static_map.get("status") != "ok"
