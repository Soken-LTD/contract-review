"""TON job steps for the supervisor (plan v4 06 section 2, 4; 09 3.1 to 3.6).

Same step rows and states as the EVM path (chain_state 0 -> fetch -> build -> analyze -> ready);
the supervisor routes a job here when `is_ton_job` is true.

  chain_state 0  supervisor reads toncenter v2 at one mc seqno and hashes the code itself
  fetch          user source, then the verifier bundle for the deployed hash (06 4.2)
  build          one sandbox container per candidate; the supervisor hashes the BoC files and
                 runs `resolve_provenance` (06 2.4); only Out.src enters the pinned store
  analyze        soken-ton-rules (+ Misti for Tact) on Out.src -> leads.json (lead.v1)

Outcomes (06 2.1, 2.4, 2.5): account read failure -> failed E_INTERNAL; tier D after builds ->
insufficient_source; verifier unavailable and no exact match -> failed E_INTERNAL.

Files under the job dir:
  chain_state.json      06 2.2 TON document (supervisor-written)
  cands/<i>.json        candidate files and settings (supervisor-only, never mounted)
  candidates.json       candidate summaries
  attempts/<i>/         build container dirs (/work); attempts/<i>.host/ supervisor records
  provenance.json       Out (06 2.2) with mc_seqno and address
  build_result.json     the Out.src build, read by analyze
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..adapters.base import BuildResult, Candidate, Compiler
from ..adapters.ton import analyze as _analyze_mod
from ..adapters.ton import build as _build_mod
from ..adapters.ton.detect import parse_ton_address
from ..adapters.ton.fetch import TonReadError, fetch_ton_sources, read_ton_chain_state
from ..adapters.ton.provenance import Attempt, Dep, Out, deployment_doc, resolve_provenance
from ..adapters.ton.units import count_nsloc_ton
from ..db.job_repo import JobRepo
from ..db.leads_repo import persist_leads_from_pin
from ..mapping import step as _map_step
from ..pinning.store import PinnedSource

if TYPE_CHECKING:
    from .supervisor import Supervisor

logger = logging.getLogger(__name__)

TON_LANGUAGES = frozenset({"func", "tact", "tolk"})


def is_ton_job(job: dict[str, Any]) -> bool:
    if job.get("chain") == "ton":
        return True
    src = job.get("source_args") or {}
    return isinstance(src, dict) and src.get("language") in TON_LANGUAGES


async def run_step(sup: Supervisor, step: dict[str, Any], job: dict[str, Any]) -> None:
    name = step["step"]
    if name == "chain_state" and step["seq"] == 0:
        await _chain_state_0(sup, step, job)
    elif name == "fetch":
        await _fetch(sup, step, job)
    elif name == "build":
        await _build(sup, step, job)
    elif name == "analyze":
        await _analyze(sup, step, job)
    elif name == "map":
        await _map(sup, step, job)
    else:
        # Family-agnostic steps (render, context, purge, proof) are intercepted by the
        # supervisor BEFORE reaching this function.  Any step that arrives here without a
        # handler is unexpected; log and skip so the job does not stall.
        logger.warning("ton: unexpected step %s (should have been handled by supervisor); marking done", name)
        await sup._mark_step(step["id"], "done")


# ── helpers ───────────────────────────────────────────────────────────────


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    tmp.replace(path)


async def _terminal(sup: Supervisor, step: dict[str, Any], state: str, error_code: str, *,
                    tier: str | None = None, detail: dict[str, Any] | None = None) -> None:
    async with sup._pool.connection() as conn:
        repo = JobRepo(conn)
        async with conn.transaction():
            await repo.complete_step(step["id"], "done" if state == "insufficient_source" else "failed",
                                     error_code=None if state == "insufficient_source" else error_code)
            if tier is not None:
                await repo.update_job_fields(step["job_id"], tier=tier)
            await repo.transition(step["job_id"], state, error_code=error_code, error_detail=detail)
    logger.info("ton job %s: %s (%s)", step["job_id"][-8:], state, error_code)


def _raw_address(job: dict[str, Any]) -> str | None:
    address = job.get("address")
    if not address:
        return None
    raw, _ = parse_ton_address(str(address))
    return raw


def _user_inputs(job: dict[str, Any]) -> dict[str, Any]:
    src = job.get("source_args") or {}
    out: dict[str, Any] = {}
    if src.get("kind") == "files":
        out["user_files"] = {f["path"]: f["content"] for f in src.get("files", []) if f.get("role", "source") == "source"}
        out["language"] = src.get("language")
        out["compiler_version"] = src.get("compiler_version")
    elif src.get("kind") == "repo":
        out["repo_url"] = src.get("repo_url")
        out["repo_commit"] = src.get("commit") or src.get("ref")
        out["repo_subdir"] = src.get("subdir") or ""
    return out


_CANDIDATE_RUNTIME_ONLY_FIELDS = frozenset({"src_tree_dir", "_full_tree", "build_paths"})


def _cand_to_json(c: Candidate) -> dict[str, Any]:
    d = asdict(c)
    d["compiler"] = asdict(c.compiler) if c.compiler else None
    # Drop runtime-only fields that must never appear in persisted/public payloads.
    for f in _CANDIDATE_RUNTIME_ONLY_FIELDS:
        d.pop(f, None)
    return d


def _cand_from_json(d: dict[str, Any]) -> Candidate:
    comp = d.get("compiler")
    # Strip unknown / runtime-only keys so old serialised dicts work forward.
    known = set(Candidate.__dataclass_fields__)  # type: ignore[attr-defined]
    d = {k: v for k, v in d.items() if k in known}
    d["compiler"] = Compiler(**comp) if comp else None
    return Candidate(**d)


# ── chain_state 0 ─────────────────────────────────────────────────────────


async def _chain_state_0(sup: Supervisor, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    out_dir.mkdir(parents=True, exist_ok=True)
    cs_path = out_dir / "chain_state.json"
    if not cs_path.exists():
        raw = _raw_address(job)
        if job.get("address") and raw is None:
            await _fail_queued(sup, step, "E_INTERNAL", "unparseable TON address")
            return
        if raw is None:
            cs: dict[str, Any] = {"mc_seqno": None, "accounts": {}}
        else:
            try:
                cs = await read_ton_chain_state(raw)
            except (TonReadError, OSError) as exc:
                # 06 2.1: TON account state read failure -> job failed, E_INTERNAL
                logger.error("ton chain_state read failed for %s: %s", job["job_id"][-8:], exc)
                await _fail_queued(sup, step, "E_INTERNAL", str(exc)[:200])
                return
        _write_json(cs_path, cs)
    cs = json.loads(cs_path.read_text())
    acct = next(iter(cs["accounts"].values()), None)
    async with sup._pool.connection() as conn:
        repo = JobRepo(conn)
        if acct and acct.get("code_hash"):
            await repo.update_job_fields(job["job_id"], code_hash=acct["code_hash"])
    await sup._mark_step(step["id"], "done", provenance={"chain": "ton", "mc_seqno": cs.get("mc_seqno")})
    await sup._after_chain_state(step, job)


async def _fail_queued(sup: Supervisor, step: dict[str, Any], code: str, detail: str) -> None:
    async with sup._pool.connection() as conn:
        repo = JobRepo(conn)
        async with conn.transaction():
            await repo.complete_step(step["id"], "failed", error_code=code)
            await repo.transition(step["job_id"], "fetching")
            await repo.transition(step["job_id"], "failed", error_code=code, error_detail={"reason": detail})


# ── fetch ─────────────────────────────────────────────────────────────────


async def _fetch(sup: Supervisor, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    summary_path = out_dir / "candidates.json"
    if summary_path.exists():
        await sup._mark_step(step["id"], "done")
        await sup._after_fetch(step, job)
        return

    cs = json.loads((out_dir / "chain_state.json").read_text())
    acct = next(iter(cs["accounts"].values()), None)
    if acct is not None and acct["status"] != "active":
        _write_json(out_dir / "provenance.json", {"reason": "NO_DEPLOYED_CODE", "tier": "D", "why": acct["status"],
                                                  "mc_seqno": cs["mc_seqno"]})
        await _terminal(sup, step, "insufficient_source", "E_SOURCE_NOT_FOUND", tier="D",
                        detail={"reason": "NO_DEPLOYED_CODE", "status": acct["status"]})
        return

    read_status: dict[str, str] = {}
    inputs = _user_inputs(job)
    cands = await fetch_ton_sources(
        raw_address=next(iter(cs["accounts"]), None),
        code_hash=acct.get("dep_hash") if acct else None,
        read_status=read_status,
        **inputs,
    )
    for i, c in enumerate(cands):
        _write_json(out_dir / "cands" / f"{i}.json", _cand_to_json(c))
    _write_json(summary_path, [
        {
            "provider": c.provider, "sha256": c.sha256, "language": c.language,
            "compiler": asdict(c.compiler) if c.compiler else None,
            "entry_contract": c.entry_contract, "source_url": c.source_url,
            "files": sorted(c.files), "fetched_at": c.fetched_at,
            "explorer_verified": c.explorer_verified,
            "verifier": (c.settings or {}).get("verifier"),
        }
        for c in cands
    ])
    _write_json(out_dir / "fetch_status.json", read_status)

    if not cands:
        if read_status.get("ton_verifier") == "unavailable":
            await _terminal(sup, step, "failed", "E_INTERNAL", detail={"reason": "ton_verifier unavailable"})
            return
        _write_json(out_dir / "provenance.json", {"reason": "NO_SOURCE_FOUND", "tier": "D", "mc_seqno": cs["mc_seqno"]})
        await _terminal(sup, step, "insufficient_source", "E_SOURCE_NOT_FOUND", tier="D",
                        detail={"reason": "NO_SOURCE_FOUND"})
        return

    await sup._mark_step(step["id"], "done", provenance={"candidates": [c.provider for c in cands], **read_status})
    await sup._after_fetch(step, job)


# ── build + resolve_provenance ────────────────────────────────────────────


def _resolve(out_dir: Path, cs: dict[str, Any], cands: list[Candidate]) -> tuple[Out, dict[int, BuildResult]]:
    results: dict[int, BuildResult] = {}

    def attempt(i: int, c: Candidate) -> Attempt:
        br = _build_mod.build(c, work_dir=out_dir / "attempts" / str(i))
        results[i] = br
        status = "ok" if br.status == "ok" else (br.reason or "compile_error")
        # hashes: computed by this process from the BoC the container wrote (build.py)
        hashes = {a.contract: a.runtime for a in br.artifacts} if br.status == "ok" else {}
        return Attempt(i, c.provider, status, hashes, untrusted_inputs=c.untrusted_inputs,
                       build_config=(c.settings or {}).get("tact_build_config"))

    dep = None
    if cs["accounts"]:
        raw, acct = next(iter(cs["accounts"].items()))
        dep = Dep(address=raw, status=acct["status"], hash=acct.get("dep_hash"), why=acct.get("why"))
    return resolve_provenance(dep, cands, attempt), results


async def _build(sup: Supervisor, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    build_path = out_dir / "build_result.json"
    if build_path.exists():
        await sup._mark_step(step["id"], "done")
        await sup._after_build(step, json.loads(build_path.read_text()))
        return

    cs = json.loads((out_dir / "chain_state.json").read_text())
    summary = json.loads((out_dir / "candidates.json").read_text())
    cands = [_cand_from_json(json.loads((out_dir / "cands" / f"{i}.json").read_text())) for i in range(len(summary))]

    out, results = await asyncio.get_event_loop().run_in_executor(None, _resolve, out_dir, cs, cands)
    prov = {**out.to_json(), "mc_seqno": cs.get("mc_seqno"), "address": next(iter(cs["accounts"]), None)}
    _write_json(out_dir / "provenance.json", prov)
    # The report assembly reads deployment.json (never provenance.json): tier A renders from it
    cand_summary = summary[out.src] if out.src is not None and 0 <= out.src < len(summary) else None
    _write_json(out_dir / "deployment.json", deployment_doc(prov, cand_summary, job.get("address")))
    logger.info("ton job %s: provenance %s %s", job["job_id"][-8:], out.reason, out.tier)

    async with sup._pool.connection() as conn:
        await JobRepo(conn).update_job_fields(job["job_id"], tier=out.tier)
        if out.dep_hash is None and out.build_hash:
            await JobRepo(conn).update_job_fields(job["job_id"], code_hash=out.build_hash)

    if out.tier == "D":
        fetch_status = json.loads((out_dir / "fetch_status.json").read_text())
        if fetch_status.get("ton_verifier") == "unavailable":
            await _terminal(sup, step, "failed", "E_INTERNAL", detail={"reason": "ton_verifier unavailable"})
            return
        await _terminal(sup, step, "insufficient_source", "E_SOURCE_NOT_FOUND",
                        detail={"reason": out.reason, "why": out.why})
        return

    assert out.src is not None
    src = cands[out.src]
    br = results[out.src]
    pin = PinnedSource.from_files(
        {p: c.encode("utf-8") for p, c in src.files.items()},
        langs={p: src.language for p in src.files},
    )
    pin.persist(sup._pin_root, job["job_id"])
    # nsloc of the pinned sources whether or not the build ran (a refused build reported 0)
    nsloc = br.nsloc or sum(count_nsloc_ton(text, src.language) for text in src.files.values())
    result = {
        "status": br.status, "nsloc": nsloc, "reason": br.reason, "stderr_head": br.stderr_head,
        "work_dir": br.work_dir, "src": out.src,
    }
    _write_json(build_path, result)
    async with sup._pool.connection() as conn:
        await JobRepo(conn).update_job_fields(job["job_id"], source_pin=pin.source_pin)
    await sup._mark_step(step["id"], "done", provenance={"reason": out.reason, "tier": out.tier,
                                                         "dep_hash": out.dep_hash, "build_hash": out.build_hash})
    await sup._after_build(step, result)


# ── analyze ───────────────────────────────────────────────────────────────


async def _analyze(sup: Supervisor, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    leads_out = sup._pin_root / job["job_id"] / "leads.json"
    if leads_out.exists():
        await sup._mark_step(step["id"], "done")
        await sup._after_analyze(step)
        return

    result = json.loads((out_dir / "build_result.json").read_text())
    cand = _cand_from_json(json.loads((out_dir / "cands" / f"{result['src']}.json").read_text()))
    if result["status"] == "ok" and result.get("work_dir"):
        br = BuildResult(candidate=cand, status="ok", nsloc=result.get("nsloc", 0), work_dir=result["work_dir"])
        source_dir = None
    else:
        # The exact compiler is missing or the build failed (tier B/C): the rule pack and Misti
        # still read the pinned sources (matrix run 2026-10-25: Forton got 0 leads from a verified
        # Tact source because analyze required a successful build).
        br = BuildResult(candidate=cand, status="failed", reason=result.get("reason"))
        source_dir = out_dir / "attempts" / "source_only"
    leads, static_map, _ = await asyncio.get_event_loop().run_in_executor(
        None, _analyze_mod.analyze, br, source_dir)
    degraded = static_map.get("status") != "ok"
    _write_json(out_dir / "static_map.json", static_map)
    leads_out.parent.mkdir(parents=True, exist_ok=True)
    leads_out.write_text(json.dumps(leads, indent=2), encoding="utf-8")
    await sup._mark_step(step["id"], "done")
    await sup._after_analyze(step, degraded=degraded)


# ── map ───────────────────────────────────────────────────────────────────


async def _map(sup: Supervisor, step: dict[str, Any], job: dict[str, Any]) -> None:
    """Lexical map.v1, J1 to J5 flags and static facts from the pin (04 2.1, 12), family `ton`.

    Queued by _analyze through sup._after_analyze; the only step that moves a TON job to `ready`
    (03 3.1: map runs in `analyzing`). The semantic layer is parsed from the
    Tact/FunC/Tolk sources (mapping/semantic_ton.py; there is no compiler AST): `full` after a
    good build with a clean parse, `partial` when the build failed or the exact compiler is missing.
    """
    job_id = job["job_id"]
    out_dir = sup._job_dir(job_id)
    build_path = out_dir / "build_result.json"
    build = json.loads(build_path.read_text()) if build_path.exists() else {"status": "failed"}
    build_ok = build.get("status") == "ok"
    cs_path = out_dir / "chain_state.json"
    chain_state = json.loads(cs_path.read_text()) if cs_path.exists() else None
    cands_path = out_dir / "candidates.json"
    cands = json.loads(cands_path.read_text()) if cands_path.exists() else []
    src = build.get("src")
    candidate = cands[src] if isinstance(src, int) and 0 <= src < len(cands) else None
    detail = None if build_ok else (build.get("stderr_head") or build.get("reason"))
    sm_path = out_dir / "static_map.json"
    static_map = json.loads(sm_path.read_text()) if sm_path.exists() else {}
    analyzers: dict[str, str] = {}
    if static_map.get("status") in ("ok", "degraded"):
        analyzers["soken_ton_rules"] = str(static_map.get("rule_pack") or "").partition("@")[2] or "0"
        if str(static_map.get("analyzer") or "").startswith("misti@"):
            analyzers["misti"] = _analyze_mod._MISTI_VERSION
    summary = await asyncio.get_event_loop().run_in_executor(None, lambda: _map_step.run_map_step(
        sup._pin_root, job_id,
        family="ton", chain="ton",
        solc_output_path=None, build_ok=build_ok, job=job,
        chain_state=chain_state, candidate=candidate,
        nsloc=build.get("nsloc"), analyzers=analyzers, build_detail=detail,
        build_status="ok" if build_ok else "failed",
    ))
    async with sup._pool.connection() as conn:
        repo = JobRepo(conn)
        async with conn.transaction():
            await repo.update_job_fields(job_id, map_status=summary["map_status"])
            await repo.complete_step(step["id"], "done", provenance=summary)
            n_leads = await persist_leads_from_pin(conn, sup._pin_root, job_id)
            await repo.transition(job_id, "ready")
    logger.info("ton job %s map %s ready (%d leads persisted)", job_id[-8:], summary.get("map_status"), n_leads)
