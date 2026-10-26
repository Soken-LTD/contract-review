"""Supervisor step runners for Solana jobs (06; 09 3.1 to 3.6).

Same step rows and job states as the EVM and Move paths: chain_state -> fetch -> build -> analyze
-> map -> ready. Without this module a Solana job falls through the dispatcher to the EVM handlers
and orphans in `analyzing`; the dispatch branch in supervisor.py routes it here instead.

Two sub-flows are decided at chain_state from a single on-chain read (onchain.spl_mint):

  mint     - the deployed address is an SPL / Token-2022 mint, not a program. There is no custom
             code to audit; the reviewable surface is the mint account's authorities and extensions.
             We render that state as a line-stable source file (adapters/solana/mint.py), pin it,
             and emit deterministic leads from it. The facts are a supervisor RPC read, so the leads
             carry analyzer evidence (not reasoning only).
  program  - the address is owned by a BPF loader, or the job is a repo / inline source job. We
             drive the existing SolanaAdapter (verified-source fetch, build, clippy / cargo-audit).

Anything else (absent account, an account that is neither a program nor a mint) is a clean terminal
insufficient_source rather than an orphan.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..adapters.solana import onchain
from ..adapters.solana.mint import mint_safety_leads, mint_source
from ..db.job_repo import JobRepo
from ..db.leads_repo import persist_leads_from_pin
from ..mapping import step as _map_step
from ..pinning.store import PinnedSource

logger = logging.getLogger(__name__)

_KIND_FILE = "solana_kind.json"
# Repo tree around a subdir candidate (fetch.attach_build_workspace): host-only, never mounted, never
# pinned; the build step writes the pinned scope over it so the reviewed bytes are the built bytes.
_WORKSPACE_FILE = "build_workspace.json"
_RUNTIME_ONLY = frozenset({"files", "src_tree_dir", "_full_tree"})
_LOADERS = (onchain.BPF_LOADER_UPGRADEABLE, onchain.BPF_LOADER_V2, onchain.BPF_LOADER_V1)


def is_solana_job(job: dict[str, Any]) -> bool:
    return job.get("chain") == "solana"


def _args(job: dict[str, Any]) -> dict[str, Any]:
    a = job.get("source_args") or {}
    return json.loads(a) if isinstance(a, str) else a


async def _terminal(sup: Any, step: dict[str, Any], state: str, error_code: str | None = None) -> None:
    async with sup._pool.connection() as conn:
        repo = JobRepo(conn)
        async with conn.transaction():
            await repo.complete_step(step["id"], "done")
            await repo.transition(step["job_id"], state, error_code=error_code)


async def run_step(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    name = step["step"]
    if name == "chain_state" and step["seq"] == 0:
        await _chain_state(sup, step, job)
    elif name == "fetch":
        await _fetch(sup, step, job)
    elif name == "build":
        await _build(sup, step, job)
    elif name == "analyze":
        await _analyze(sup, step, job)
    elif name == "map":
        await _map(sup, step, job)
    else:
        # chain_state seq 1 and any other row: the mint and program flows finish at map; nothing
        # to do.  Family-agnostic steps (render, context) are intercepted by the supervisor
        # before this function; they should never arrive here.
        await sup._mark_step(step["id"], "done")


def _load_kind(out_dir: Path) -> dict[str, Any]:
    path = out_dir / _KIND_FILE
    return json.loads(path.read_text()) if path.exists() else {"kind": "program"}


# --------------------------------------------------------------------------------- chain_state (seq 0)

async def _chain_state(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    out_dir.mkdir(parents=True, exist_ok=True)
    kind_path = out_dir / _KIND_FILE

    if kind_path.exists():  # restartability (09 3.4)
        await sup._mark_step(step["id"], "done")
        await sup._after_chain_state(step, job)
        return

    address = job.get("address")
    # A repo or inline-source job has no deployed address: it is always the program-source flow.
    if not address or job.get("source_kind") in ("repo", "files"):
        kind_path.write_text(json.dumps({"kind": "program"}), encoding="utf-8")
        (out_dir / "chain_state.json").write_text(json.dumps({"kind": "program"}), encoding="utf-8")
        await sup._mark_step(step["id"], "done")
        await sup._after_chain_state(step, job)
        return

    loop = asyncio.get_event_loop()
    m = await loop.run_in_executor(None, lambda: onchain.spl_mint(address))

    if m.why is None:  # a real, initialized mint -> token-safety flow
        rec = {"kind": "mint", **asdict(m)}
        kind_path.write_text(json.dumps(rec), encoding="utf-8")
        (out_dir / "chain_state.json").write_text(
            json.dumps({"kind": "mint", "address": address, "slot": m.slot, "program": m.program}),
            encoding="utf-8")
        await sup._mark_step(step["id"], "done", provenance={"slot": m.slot, "program": m.program})
        await sup._after_chain_state(step, job)
        return

    if m.program in _LOADERS:  # a deployed program -> source flow via the SolanaAdapter
        kind_path.write_text(json.dumps({"kind": "program", "address": address, "slot": m.slot}),
                             encoding="utf-8")
        (out_dir / "chain_state.json").write_text(
            json.dumps({"kind": "program", "address": address, "slot": m.slot}), encoding="utf-8")
        await sup._mark_step(step["id"], "done", provenance={"slot": m.slot})
        await sup._after_chain_state(step, job)
        return

    if m.why.startswith("read_failed"):
        logger.error("solana chain_state read failed for %s: %s", job["job_id"][-8:], m.why)
        await sup._mark_step(step["id"], "failed", error_code="E_INTERNAL")
        return

    # absent account, or an account that is neither a program nor an initialized mint.
    logger.info("solana job %s: %s -> insufficient_source", job["job_id"][-8:], m.why)
    await _terminal(sup, step, "insufficient_source", error_code="E_SOURCE_NOT_FOUND")


# --------------------------------------------------------------------------------- fetch

async def _fetch(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    kind = _load_kind(out_dir)
    if kind.get("kind") == "mint":
        await _fetch_mint(sup, step, job, out_dir, kind)
    else:
        await _fetch_program(sup, step, job, out_dir)


async def _fetch_mint(sup: Any, step: dict[str, Any], job: dict[str, Any],
                      out_dir: Path, kind: dict[str, Any]) -> None:
    m = onchain.SplMint(**{k: v for k, v in kind.items() if k != "kind"})
    filename, text, _index = mint_source(m)
    pin = PinnedSource.from_files({filename: text.encode("utf-8")}, langs={filename: "text"})
    pin.persist(sup._pin_root, job["job_id"])
    nsloc = text.count("\n")
    (out_dir / "candidates.json").write_text(json.dumps([{
        "provider": "onchain", "sha256": pin.source_pin, "language": "text",
        "settings": {"kind": "mint"}, "entry_contract": None, "source_url": None,
        "nsloc": nsloc,
    }], indent=1), encoding="utf-8")
    async with sup._pool.connection() as conn:
        await JobRepo(conn).update_job_fields(job["job_id"], source_pin=pin.source_pin)
    await sup._mark_step(step["id"], "done", provenance={"provider": "onchain", "sha256": pin.source_pin})
    await sup._after_fetch(step, job)


async def _fetch_program(sup: Any, step: dict[str, Any], job: dict[str, Any], out_dir: Path) -> None:
    """Program-source flow: drive the SolanaAdapter fetch (verified source / repo / inline).

    Not exercised by the current job queue (all deployed addresses are mints); it reuses the
    SolanaAdapter's own tested fetch rather than reimplementing it. No source -> insufficient_source.
    """
    from ..adapters.solana import SolanaAdapter

    args = _args(job)
    cs_file = out_dir / "chain_state.json"
    cs = json.loads(cs_file.read_text()) if cs_file.exists() else {}
    # Build the job-dict that fetch_source expects: address (program ID) plus
    # repo_url/commit/subdir for repo jobs.  fetch_source normalises dict vs
    # object via isinstance check, so a plain dict is the canonical form here.
    j: dict[str, Any] = {"address": job.get("address"), "work_dir": str(out_dir / "fetch")}
    if job.get("source_kind") == "repo":
        j |= {
            "repo_url": args.get("repo_url"),
            "commit": job.get("resolved_commit") or args.get("commit") or args.get("ref"),
            "subdir": (args.get("subdir") or "").strip("/") or None,
        }
    elif job.get("source_kind") == "files":
        j["files"] = {f["path"]: f["content"] for f in args.get("files", [])}

    loop = asyncio.get_event_loop()
    # Pass the raw chain_state dict directly; fetch_source reads cs.get("upgrade_authority")
    # from it.  Wrapping in ChainValue here served no purpose and hid the upgrade_authority key.
    bundles = await loop.run_in_executor(
        None, lambda: SolanaAdapter().fetch_source(j, cs))
    if not bundles or not bundles[0].candidates:
        (out_dir / "candidates.json").write_text("[]", encoding="utf-8")
        await _terminal(sup, step, "insufficient_source", error_code="E_SOURCE_NOT_FOUND")
        return
    cand = bundles[0].candidates[0]
    pin = PinnedSource.from_files({p: t.encode("utf-8") for p, t in cand.files.items()},
                                  langs={p: cand.language for p in cand.files})
    pin.persist(sup._pin_root, job["job_id"])
    meta = {k: v for k, v in asdict(cand).items() if k not in _RUNTIME_ONLY}
    (out_dir / "candidates.json").write_text(json.dumps([meta], indent=1, default=str), encoding="utf-8")
    if cand._full_tree and (cand.settings or {}).get("subdir"):
        (out_dir / _WORKSPACE_FILE).write_text(json.dumps({"subdir": cand.settings["subdir"],
                                                           "files": cand._full_tree}), encoding="utf-8")
    async with sup._pool.connection() as conn:
        await JobRepo(conn).update_job_fields(job["job_id"], source_pin=pin.source_pin)
    await sup._mark_step(step["id"], "done", provenance={"provider": cand.provider, "sha256": cand.sha256})
    await sup._after_fetch(step, job)


# --------------------------------------------------------------------------------- build

async def _build(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    kind = _load_kind(out_dir)
    if kind.get("kind") == "mint":
        # No compilation: the pinned mint_state.txt is the reviewed artifact.
        cands = json.loads((out_dir / "candidates.json").read_text())
        nsloc = cands[0].get("nsloc", 0) if cands else 0
        result = {"status": "ok", "reason": None, "nsloc": nsloc, "work_dir": None,
                  "untrusted_inputs": False, "provenance": None}
        (out_dir / "build_result.json").write_text(json.dumps(result), encoding="utf-8")
        await sup._mark_step(step["id"], "done")
        await sup._after_build(step, result)
        return
    await _build_program(sup, step, job, out_dir)


async def _build_program(sup: Any, step: dict[str, Any], job: dict[str, Any], out_dir: Path) -> None:
    from ..adapters.base import Candidate, Compiler
    from ..adapters.solana import SolanaAdapter

    raw = json.loads((out_dir / "candidates.json").read_text())[0]
    pin = PinnedSource.load(sup._pin_root, job["job_id"])
    files = {p: "\n".join(pin.read_all(p)) for p in pin.entries}
    comp = raw.get("compiler")
    settings = dict(raw.get("settings") or {})
    cand = Candidate(provider=raw["provider"], files=build_files(files, out_dir / _WORKSPACE_FILE, settings),
                     sha256=raw["sha256"], language=raw["language"],
                     compiler=Compiler(**comp) if comp else None, settings=settings,
                     std_json_input=None, entry_contract=raw.get("entry_contract"),
                     source_url=raw.get("source_url"), fetched_at=raw.get("fetched_at"))
    # The SolanaAdapter.build wrapper manages its own sandbox work dir (adapters/solana/build.py).
    loop = asyncio.get_event_loop()
    r = await loop.run_in_executor(None, lambda: SolanaAdapter().build(cand))
    # nSLOC is the reviewed scope (the pin), not the workspace the build needed around it.
    result = {"status": r.status, "reason": r.reason, "nsloc": pin_nsloc(files), "work_dir": r.work_dir,
              "untrusted_inputs": getattr(cand, "untrusted_inputs", False), "provenance": None,
              "detail": build_detail(r.reason, r.stderr_head) if r.status != "ok" else None}
    (out_dir / "build_result.json").write_text(json.dumps(result), encoding="utf-8")
    await sup._mark_step(step["id"], "done")
    await sup._after_build(step, result)


def build_files(pinned: dict[str, str], workspace_path: Path, settings: dict[str, Any]) -> dict[str, str]:
    """Files the build gets: the pinned scope, inside its repo workspace when the fetch kept one.

    The workspace copy of the subdir is dropped and the pinned files are written under the subdir
    prefix, so what is built is exactly what is reviewed. Without a workspace file: the pin as is.
    """
    if not workspace_path.exists():
        return pinned
    data = json.loads(workspace_path.read_text(encoding="utf-8"))
    subdir = str(data.get("subdir") or settings.get("subdir") or "").strip("/")
    if not subdir:
        return pinned
    prefix = subdir + "/"
    out = {p: c for p, c in (data.get("files") or {}).items()
           if isinstance(c, str) and not p.startswith(prefix)}
    out.update({prefix + p: c for p, c in pinned.items()})
    return out


def pin_nsloc(files: dict[str, str]) -> int:
    from ..adapters.solana.units import count_nsloc_rust, is_in_scope_rust

    return sum(count_nsloc_rust(c) for p, c in files.items() if is_in_scope_rust(p) and isinstance(c, str))


def build_detail(reason: str | None, stderr_head: str | None) -> str:
    """`reason: last stderr lines`, kept in host status.json; clients only see map_view.build_error_summary."""
    tail = " | ".join(line.strip() for line in (stderr_head or "").splitlines()[-6:] if line.strip())
    return f"{reason or 'failed'}: {tail}"[:600] if tail else (reason or "failed")


# --------------------------------------------------------------------------------- analyze

async def _analyze(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    kind = _load_kind(out_dir)
    leads_out = sup._pin_root / job["job_id"] / "leads.json"
    leads_out.parent.mkdir(parents=True, exist_ok=True)

    if kind.get("kind") == "mint":
        m = onchain.SplMint(**{k: v for k, v in kind.items() if k != "kind"})
        leads = mint_safety_leads(m)
        leads_out.write_text(json.dumps(leads, indent=2), encoding="utf-8")
        (out_dir / "static_map.json").write_text(
            json.dumps({"status": "ok", "analyzer": "soken-spl-mint@1", "not_run": [],
                        "degraded_reasons": []}), encoding="utf-8")
        await sup._mark_step(step["id"], "done")
        await sup._after_analyze(step, degraded=False)
        return

    await _analyze_program(sup, step, job, out_dir, leads_out)


async def _analyze_program(sup: Any, step: dict[str, Any], job: dict[str, Any],
                           out_dir: Path, leads_out: Path) -> None:
    from ..adapters.base import BuildResult, Candidate, Compiler
    from ..adapters.solana import SolanaAdapter

    res = json.loads((out_dir / "build_result.json").read_text())
    raw = json.loads((out_dir / "candidates.json").read_text())[0]
    pin = PinnedSource.load(sup._pin_root, job["job_id"])
    files = {p: "\n".join(pin.read_all(p)) for p in pin.entries}
    if res["status"] != "ok" or not res.get("work_dir"):
        # No build: clippy and cargo-audit cannot run; the source rules still do (degraded, named).
        from ..adapters.solana.analyze import analyze_source_only

        loop = asyncio.get_event_loop()
        leads, static_map, _plan = await loop.run_in_executor(
            None, lambda: analyze_source_only(files, f"build_{res.get('reason') or 'failed'}"))
        leads_out.write_text(json.dumps(leads, indent=2), encoding="utf-8")
        (out_dir / "static_map.json").write_text(json.dumps(static_map), encoding="utf-8")
        await sup._mark_step(step["id"], "done")
        await sup._after_analyze(step, degraded=True)
        return
    comp = raw.get("compiler")
    cand = Candidate(provider=raw["provider"], files=files, sha256=raw["sha256"], language=raw["language"],
                     compiler=Compiler(**comp) if comp else None, settings=raw.get("settings") or {},
                     std_json_input=None, entry_contract=raw.get("entry_contract"),
                     source_url=raw.get("source_url"), fetched_at=raw.get("fetched_at"))
    # The analysis reads the built tree (work_dir/src) for clippy and cargo-audit; the source rules
    # read the candidate files, which must be the pinned scope (lead paths are pin paths).
    r = BuildResult(candidate=cand, status="ok", nsloc=res.get("nsloc", 0), work_dir=res["work_dir"])
    loop = asyncio.get_event_loop()
    leads, static_map, _read_plan = await loop.run_in_executor(None, lambda: SolanaAdapter().analyze(r))
    leads_out.write_text(json.dumps(leads, indent=2), encoding="utf-8")
    (out_dir / "static_map.json").write_text(json.dumps(static_map), encoding="utf-8")
    await sup._mark_step(step["id"], "done")
    await sup._after_analyze(step, degraded=static_map.get("status") != "ok")


# --------------------------------------------------------------------------------- map -> ready

async def _map(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    job_id = job["job_id"]
    out_dir = sup._job_dir(job_id)
    build_path = out_dir / "build_result.json"
    build = json.loads(build_path.read_text()) if build_path.exists() else {"status": "failed"}
    build_ok = build.get("status") == "ok"
    cs_path = out_dir / "chain_state.json"
    chain_state = json.loads(cs_path.read_text()) if cs_path.exists() else None
    cands_path = out_dir / "candidates.json"
    cands = json.loads(cands_path.read_text()) if cands_path.exists() else []
    loop = asyncio.get_event_loop()
    summary = await loop.run_in_executor(None, lambda: _map_step.run_map_step(
        sup._pin_root, job_id, family="solana", chain="solana",
        solc_output_path=None, build_ok=build_ok, job=job, chain_state=chain_state,
        candidate=cands[0] if cands else None,
        nsloc=int(build["nsloc"]) if build.get("nsloc") else None,
        analyzers={"spl_mint": "1"} if cands and
        (cands[0].get("settings") or {}).get("kind") == "mint" else {},
        build_detail=None if build_ok else (build.get("detail") or build.get("reason")),
        build_status="ok" if build_ok else "failed",
    ))
    async with sup._pool.connection() as conn:
        repo = JobRepo(conn)
        async with conn.transaction():
            await repo.update_job_fields(job_id, map_status=summary["map_status"])
            await repo.complete_step(step["id"], "done", provenance=summary)
            n_leads = await persist_leads_from_pin(conn, sup._pin_root, job_id)
            await repo.transition(job_id, "ready")
    logger.info("solana job %s map %s ready (%d leads persisted)", job_id[-8:], summary.get("map_status"), n_leads)
