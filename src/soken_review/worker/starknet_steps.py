"""Starknet step runners for the supervisor (07 4, 9; 09 3.1 to 3.6).

chain_state -> fetch -> build -> analyze -> ready, same step rows as the EVM path. Supervisor-only
files live in the job work dir (never mounted): chain_state.json, onchain_class.json,
provenance.json, map.json; containers only see work/build/{tree,scarb-cache,cargo-home,output}.

Provenance: dep.match is decided here from (a) the class read over RPC at the pinned block,
(b) class hashes this process computed from artifact bytes (build/host/artifacts.json) and
(c) the trust flag (build/host/trust_scan.json). Then 04 code_tier sets jobs.tier.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any

from ..adapters.base import BuildResult, Candidate, Compiler
from ..db.job_repo import JobRepo
from ..mapping import step as _map_step
from ..pinning.store import PinnedSource

logger = logging.getLogger(__name__)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_TIER_D_HINT = "Supply the repository and commit the class was declared from"   # 07 9.2 fixed hint


def _max_nsloc() -> int:
    import yaml

    limits = Path(__file__).resolve().parents[3] / "contract" / "ops" / "limits.yaml"
    return int(yaml.safe_load(limits.read_text())["surface"]["plugin"]["max_nsloc"])


async def _finish(sup: Any, step: dict[str, Any], *, step_status: str, to_state: str | None,
                  error_code: str | None = None, detail: dict[str, Any] | None = None,
                  next_step: dict[str, Any] | None = None, fields: dict[str, Any] | None = None,
                  provenance: dict[str, Any] | None = None) -> None:
    async with sup._pool.connection() as conn:
        repo = JobRepo(conn)
        async with conn.transaction():
            await repo.complete_step(step["id"], step_status, error_code=None if step_status == "done" else error_code,
                                     provenance=provenance)
            if fields:
                await repo.update_job_fields(step["job_id"], **fields)
            if to_state:
                await repo.transition(step["job_id"], to_state, error_code=error_code, error_detail=detail)
            if next_step:
                await repo.insert_step(job_id=step["job_id"], affinity=step.get("lease_owner"), **next_step)


async def run_step(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    name = step["step"]
    if name == "chain_state":
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
        await sup._mark_step(step["id"], "done")


# --------------------------------------------------------------------------------------------- chain_state

async def _chain_state(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    from ..adapters.starknet.fetch import read_chain_state

    out = sup._job_dir(job["job_id"])
    out.mkdir(parents=True, exist_ok=True)
    fetch_row = {"step": "fetch", "container": False, "units": 0, "ram_mb": 0, "max_attempts": 3}
    address = job.get("address")
    if not address:   # files or repo with no deployment: no chain read, 04 sets tier B
        await _finish(sup, step, step_status="done", to_state="fetching", next_step=fetch_row)
        return
    try:
        cs = await read_chain_state(address)
    except ValueError:
        await _finish(sup, step, step_status="failed", to_state="failed", error_code="E_ADDRESS_INVALID")
        return
    except LookupError:
        async with sup._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.complete_step(step["id"], "done")
                await repo.transition(job["job_id"], "fetching")
                await repo.transition(job["job_id"], "insufficient_source", error_code="E_SOURCE_NOT_FOUND",
                                      error_detail={"detail": "no_contract_at_address"})
        return
    contract_class = cs.pop("class")
    if contract_class is not None:          # only a body that hashed to the class hash is kept
        (out / "onchain_class.json").write_text(json.dumps(contract_class), encoding="utf-8")
    (out / "chain_state.json").write_text(json.dumps(cs, indent=1), encoding="utf-8")
    prov = {"block": cs["block"], "class_hash": cs["class_hash"], "cairo": cs["cairo_version"]}

    no_repo = job.get("source_kind") == "deployed"
    if cs["cairo0"] or no_repo:
        # 07 9.2 tier D response: what was read, the unlocking input, the fixed hint.
        detail = {
            "detail": "cairo0_class" if cs["cairo0"] else "source_not_on_chain",
            "read": {"class_hash": cs["class_hash"], "sierra": cs["sierra_version"], "cairo": cs["cairo_version"],
                     "cairo0": cs["cairo0"], "entry_point_counts": cs["entry_point_counts"]},
            "unlock": "repo and commit (Cairo 1 or later) building to the class hash",
            "hint": _TIER_D_HINT,
        }
        code = "E_INSUFFICIENT_SOURCE" if cs["cairo0"] else "E_SOURCE_NOT_FOUND"
        async with sup._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.complete_step(step["id"], "done", provenance=prov)
                await repo.update_job_fields(job["job_id"], tier="D", code_hash=cs["class_hash"])
                await repo.transition(job["job_id"], "fetching")
                await repo.transition(job["job_id"], "insufficient_source", error_code=code, error_detail=detail)
        return
    await _finish(sup, step, step_status="done", to_state="fetching", next_step=fetch_row,
                  fields={"code_hash": cs["class_hash"]}, provenance=prov)


# --------------------------------------------------------------------------------------------- fetch

async def _fetch(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    from ..adapters.starknet.fetch import clone_repo, make_candidate
    from ..adapters.starknet.units import count_nsloc_cairo, in_scope_paths

    job_id = job["job_id"]
    out = sup._job_dir(job_id)
    args = job.get("source_args") or {}
    if isinstance(args, str):
        args = json.loads(args)
    repo_url, commit, subdir = args.get("repo_url"), args.get("commit") or "", args.get("subdir") or ""
    if not repo_url:
        await _finish(sup, step, step_status="done", to_state="insufficient_source", error_code="E_SOURCE_NOT_FOUND",
                      detail={"detail": "starknet_needs_repo", "hint": _TIER_D_HINT})
        return
    if not _COMMIT_RE.match(commit):
        await _finish(sup, step, step_status="failed", to_state="failed", error_code="E_UNPINNED_REF",
                      detail={"detail": "full 40-hex commit required"})
        return
    files = await asyncio.get_running_loop().run_in_executor(None, lambda: clone_repo(repo_url, commit, out / "fetch"))
    if not files:
        await _finish(sup, step, step_status="failed", to_state="failed", error_code="E_COMMIT_NOT_FOUND")
        return
    cs = json.loads((out / "chain_state.json").read_text()) if (out / "chain_state.json").exists() else {}
    cand = make_candidate(files, provider="repo", repo_url=repo_url, commit=commit, subdir=subdir,
                          cairo_version=cs.get("cairo_version"))
    scope = in_scope_paths(files, cand.settings["package_dir"])
    nsloc = sum(count_nsloc_cairo(files[p]) for p in scope)
    if nsloc > _max_nsloc():
        await _finish(sup, step, step_status="failed", to_state="failed", error_code="E_SIZE_LIMIT",
                      detail={"measure": "nSLOC", "value": nsloc, "cap": _max_nsloc()})
        return
    pin = PinnedSource.from_files(
        {p: t.encode("utf-8") for p, t in files.items()},
        langs={p: ("cairo" if p.endswith(".cairo") else None) for p in files},
        in_scope={p: p in scope for p in files},
        roles={p: ("source" if p in scope else "dependency") for p in files},
    )
    pin.persist(sup._pin_root, job_id)
    (out / "candidates.json").write_text(json.dumps([{
        "provider": "repo", "sha256": cand.sha256, "language": "cairo",
        "compiler": {"version": cand.compiler.version, "version_pinned_by": cand.compiler.version_pinned_by}
        if cand.compiler else None,
        "settings": cand.settings, "source_url": repo_url, "commit": commit, "fetched_at": cand.fetched_at,
    }], indent=1), encoding="utf-8")
    async with sup._pool.connection() as conn:
        await JobRepo(conn).update_job_fields(job_id, source_pin=pin.source_pin)
    await _finish(sup, step, step_status="done", to_state="building",
                  next_step={"step": "build", "container": True, "units": 4, "ram_mb": 8192, "max_attempts": 1},
                  provenance={"provider": "repo", "sha256": cand.sha256, "commit": commit})


def _candidate(sup: Any, job_id: str) -> Candidate:
    out = sup._job_dir(job_id)
    raw = json.loads((out / "candidates.json").read_text())[0]
    pin = PinnedSource.load(sup._pin_root, job_id)
    comp = raw.get("compiler")
    return Candidate(
        provider="repo", files={p: pin.read_text(p) for p in pin.entries}, sha256=raw["sha256"], language="cairo",
        compiler=Compiler(comp["version"], comp["version_pinned_by"]) if comp else None,
        settings=raw.get("settings") or {}, std_json_input=None, entry_contract=None, source_url=raw.get("source_url"),
    )


# --------------------------------------------------------------------------------------------- build

def _refine_plugin_trust(host: Path, artifacts: list[dict[str, Any]], onchain_class_hash: str,
                         untrusted: bool, trust_reasons: list[str]) -> bool:
    """Refine the trust flag when cairo_plugin_in_tree is the only reason for untrusted.

    Reads host/scarb_metadata.json (written by the supervisor before the build; never
    mounted into containers, so it cannot be spoofed by the build step). Reads the
    package name from host/build_context.json and the pinned lock from host/Scarb.lock.pinned
    (both written by the supervisor; never mounted into containers).

    Calls plugin_allowed_for_unit() to check that every non-builtin plugin in the
    starknet-contract compilation unit is on the strict allow-list with a matching checksum
    from the pinned Scarb.lock. Clears the trust flag only when positive proof exists.
    Fails closed: any exception or missing data keeps untrusted.
    """
    from ..adapters.starknet.plugin_scope import plugin_allowed_for_unit

    if not untrusted:
        return False
    # Only refine when ALL reasons are cairo_plugin_in_tree hits (no other issues).
    if not trust_reasons or not all(r.startswith("cairo_plugin_in_tree:") for r in trust_reasons):
        return untrusted

    # Read supervisor-written metadata (never mounted into build containers).
    metadata_path = host / "scarb_metadata.json"
    try:
        meta = json.loads(metadata_path.read_text())
    except (OSError, ValueError):
        return True  # fail closed: no metadata

    # Read supervisor-written build context (package name).
    ctx_path = host / "build_context.json"
    try:
        ctx = json.loads(ctx_path.read_text())
        package_name: str = ctx["package_name"]
        if not package_name or not isinstance(package_name, str):
            return True
    except (OSError, ValueError, KeyError):
        return True  # fail closed: no build context

    # Read supervisor-pinned Scarb.lock for checksum verification.
    lock_path = host / "Scarb.lock.pinned"
    try:
        lock_text: str = lock_path.read_text()
    except OSError:
        return True  # fail closed: no pinned lock

    try:
        allowed = plugin_allowed_for_unit(meta, package_name, lock_text)
    except Exception:
        logger.warning("plugin_allowed_for_unit raised unexpectedly", exc_info=True)
        return True  # fail closed
    if allowed is False:  # noqa: SIM103 (explicit fail-closed branches)
        # Positive proof: every non-builtin plugin in the unit is allowlisted with
        # matching checksum.  Clear the cairo_plugin_in_tree trust hit.
        return False
    # allowed is True (non-allowlisted plugin found) or None (can't determine) -> keep untrusted.
    return True


def decide(out: Path, build_status: str, build_reason: str | None, has_deployment: bool) -> dict[str, Any]:
    """Supervisor provenance decision from supervisor-written files only (the decision point)."""
    from ..adapters.starknet.provenance import code_tier, decide_dep_match

    host = out / "build" / "host"
    trust = json.loads((host / "trust_scan.json").read_text()) if (host / "trust_scan.json").exists() else None
    # No trust record = not scanned = not trusted (fail closed).
    untrusted = True if trust is None else bool(trust.get("untrusted"))
    trust_reasons: list[str] = (trust or {}).get("reasons") or []
    if not has_deployment:
        return {"match": None, "reason": "no_deployment", "tier": code_tier(True, False, None),
                "untrusted_inputs": untrusted, "trust_reasons": trust_reasons}
    cs = json.loads((out / "chain_state.json").read_text())
    if not cs.get("class_verified"):
        return {"match": "not_checkable", "reason": "class_body_unverified", "tier": code_tier(True, True, "not_checkable"),
                "onchain_class_hash": cs.get("class_hash"), "untrusted_inputs": untrusted,
                "trust_reasons": trust_reasons, "artifact": None, "rebuilt_class_hash": None}
    artifacts = json.loads((host / "artifacts.json").read_text()) if (host / "artifacts.json").exists() else []

    # Refine trust: if the only reason for untrusted is an in-tree cairo-plugin crate that
    # scarb metadata confirms is NOT used by the matched compilation unit, clear the flag.
    untrusted = _refine_plugin_trust(host, artifacts, cs["class_hash"], untrusted, trust_reasons)

    dm = decide_dep_match(onchain_class_hash=cs["class_hash"], onchain_selectors=cs["selectors"], artifacts=artifacts,
                          build_status=build_status, build_reason=build_reason, untrusted_inputs=untrusted)
    dm["tier"] = code_tier(True, True, dm["match"])
    dm["onchain_class_hash"] = cs["class_hash"]
    dm["untrusted_inputs"] = untrusted
    dm["trust_reasons"] = trust_reasons
    dm["artifacts"] = [{"contract": a["contract"], "class_hash": a["class_hash"]} for a in artifacts]
    return dm


async def _build(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    from ..adapters.starknet.build import build

    job_id = job["job_id"]
    out = sup._job_dir(job_id)
    cand = _candidate(sup, job_id)
    cairo = cand.compiler.version if cand.compiler else None
    if not cairo and not job.get("address"):
        cairo = None   # no deployment: no decoded version; build needs a version (07 3.1) -> toolchain_unavailable
    result = await asyncio.get_running_loop().run_in_executor(None, lambda: build(cand, out / "build", cairo))
    (out / "build_result.json").write_text(json.dumps({
        "status": result.status, "reason": result.reason, "nsloc": result.nsloc, "stderr_head": result.stderr_head,
        "work_dir": result.work_dir}, indent=1), encoding="utf-8")
    prov = decide(out, result.status, result.reason, bool(job.get("address")))
    (out / "provenance.json").write_text(json.dumps(prov, indent=1), encoding="utf-8")
    fields: dict[str, Any] = {"tier": prov["tier"], "map_status": "none" if result.status == "ok" else "failed"}
    await _finish(sup, step, step_status="done", to_state="analyzing", fields=fields,
                  next_step={"step": "analyze", "tool": "scarb-lint", "container": True, "units": 2, "ram_mb": 4096,
                             "max_attempts": 1},
                  provenance={"dep_match": prov.get("match"), "reason": prov.get("reason"), "tier": prov["tier"]})


# --------------------------------------------------------------------------------------------- analyze

async def _analyze(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    from ..adapters.starknet.analyze import analyze
    from ..adapters.starknet.map import chain_extras
    from ..adapters.starknet.sierra import class_facts

    job_id = job["job_id"]
    out = sup._job_dir(job_id)
    cand = _candidate(sup, job_id)
    br_raw = json.loads((out / "build_result.json").read_text())
    br = BuildResult(candidate=cand, status=br_raw["status"], nsloc=br_raw.get("nsloc", 0), reason=br_raw.get("reason"),
                     work_dir=br_raw.get("work_dir"))
    prov = json.loads((out / "provenance.json").read_text())
    facts = None
    if (out / "onchain_class.json").exists():
        facts = class_facts(json.loads((out / "onchain_class.json").read_text()))
    elif prov.get("artifact"):
        art = out / "build" / "host" / "artifacts" / f"{prov['artifact']}.contract_class.json"
        facts = class_facts(json.loads(art.read_text())) if art.exists() else None
    cairo = cand.compiler.version if cand.compiler else None
    leads, static_map, _plan = await asyncio.get_running_loop().run_in_executor(
        None, lambda: analyze(br, facts, cairo, run_stock_lint=br.status == "ok",
                              run_caracal=br.status == "ok"))
    cs = json.loads((out / "chain_state.json").read_text()) if (out / "chain_state.json").exists() else None
    extras = chain_extras(cs, facts, static_map, prov)
    (out / "map.json").write_text(json.dumps({"chain_extras": {"starknet": extras}, "static": static_map}, indent=1),
                                  encoding="utf-8")
    leads_out = sup._pin_root / job_id / "leads.json"
    leads_out.parent.mkdir(parents=True, exist_ok=True)
    leads_out.write_text(json.dumps(leads, indent=2), encoding="utf-8")
    degraded = static_map.get("status") != "ok" or br.status != "ok"
    fields: dict[str, Any] = {"map_status": "full" if br.status == "ok" and extras["facts"] == "complete" else "partial"}
    if degraded:
        fields["analyzer_degraded"] = True
    # The map step (lexical map.v1, J1 to J5 flags, static facts) follows and moves the job to ready.
    await _finish(sup, step, step_status="done", to_state=None, fields=fields,
                  provenance={"leads": len(leads), "status": static_map.get("status")},
                  next_step={"step": "map", "container": False, "units": 0, "ram_mb": 0, "max_attempts": 2})


# --------------------------------------------------------------------------------------------- map

async def _map(sup: Any, step: dict[str, Any], job: dict[str, Any]) -> None:
    """Lexical map.v1, J1 to J5 flags and static facts from the pin (04 2.1, 12), family `cairo`.

    `map_status` stays as the analyze step set it from the Sierra and chain facts (07): the lexical
    layer never has a solc semantic layer and would only downgrade it. The step's provenance carries
    the lexical summary (files, spans, flags per rule, facts).
    """
    job_id = job["job_id"]
    out = sup._job_dir(job_id)
    br_path = out / "build_result.json"
    build = json.loads(br_path.read_text()) if br_path.exists() else {"status": "failed"}
    build_ok = build.get("status") == "ok"
    cs_path = out / "chain_state.json"
    chain_state = json.loads(cs_path.read_text()) if cs_path.exists() else None
    cands_path = out / "candidates.json"
    cands = json.loads(cands_path.read_text()) if cands_path.exists() else []
    detail = None if build_ok else (build.get("stderr_head") or build.get("reason"))
    summary = await asyncio.get_running_loop().run_in_executor(None, lambda: _map_step.run_map_step(
        sup._pin_root, job_id,
        family="cairo", chain="starknet",
        solc_output_path=None, build_ok=build_ok, job=job,
        chain_state=chain_state, candidate=cands[0] if cands else None,
        nsloc=build.get("nsloc"), analyzers={}, build_detail=detail,
    ))
    await _finish(sup, step, step_status="done", to_state="ready", provenance=summary)
