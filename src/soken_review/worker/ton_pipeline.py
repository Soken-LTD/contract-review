"""TON job steps for the supervisor (plan v4 06 section 2, 4; 09 3.1 to 3.6).

Same step rows and states as the EVM path (chain_state 0 -> fetch -> build -> analyze -> ready);
the supervisor routes a job here when `is_ton_job` is true.

  chain_state 0  supervisor reads toncenter v2 at one mc seqno and hashes the code itself
  fetch          user source, then the verifier bundle for the deployed hash (06 4.2)
  build          one sandbox container per candidate; the supervisor hashes the BoC files and
                 runs `resolve_provenance` (06 2.4); only Out.src enters the pinned store
  analyze        soken-ton-rules (+ Misti for Tact) on Out.src -> leads.json (lead.v1)

Outcomes (06 2.1, 2.4, 2.5): account read failure -> failed E_INTERNAL; tier D after builds ->
insufficient_source; verifier unavailable and no exact match -> failed E_INTERNAL. A repo or files
source the requester named is always reviewed: with a deployment it cannot be tied to, tier B
SOURCE_UNLINKED (provenance.py), never insufficient_source.

Repo-only TON jobs arrive here from the generic repo fetch (supervisor `_hand_repo_to_family`, family
detected from the tree or named by review_start `source.chain`) with the materialised tree in
`_repo_src_dir`; a repo job with a deployment fetches the commit archive itself.

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
from ..adapters.ton.fetch import (
    TonReadError,
    fetch_ton_sources,
    library_candidate_from_json,
    read_ton_chain_state,
)
from ..adapters.ton.provenance import (
    SOURCE_TOOLCHAIN_GAP,
    SOURCE_UNLINKED,
    Attempt,
    Dep,
    Out,
    deployment_doc,
    resolve_provenance,
    unlinked_reason,
)
from ..adapters.ton.units import count_nsloc_ton, stdlib_paths
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
        out["repo_commit"] = job.get("resolved_commit") or src.get("commit") or src.get("ref")
        out["repo_subdir"] = src.get("subdir") or ""
        tree = job.get("_repo_src_dir")
        if tree:
            from ..adapters.evm.repo_candidate import safe_read_repo_tree

            out["repo_files"], _refused = safe_read_repo_tree(tree)
    return out


async def _pin_repo_commit(sup: Supervisor, step: dict[str, Any], job: dict[str, Any]) -> dict[str, Any] | None:
    """The 40-hex commit of a repo job: the supervisor-resolved one, the requested one, or the ref
    (or the default branch) resolved with `ls-remote` here, so the pin and the report name a real
    commit. Returns the job with `resolved_commit` set, or None after ending the job on a bad ref."""
    src = job.get("source_args") or {}
    if src.get("kind") != "repo" or job.get("resolved_commit"):
        return job
    from ..errors import ReviewError
    from ..tools.git_probe import _SHA1_RE, ls_remote, resolve_ref, unpinned_ref_detail

    commit = str(src.get("commit") or "").lower()
    sha: str | None = commit if _SHA1_RE.match(commit) else None
    if sha is None and not commit:
        try:
            if src.get("ref"):
                sha = await resolve_ref(str(src.get("repo_url") or ""), str(src["ref"]))
            else:
                code, out = await ls_remote(str(src.get("repo_url") or ""), ["HEAD"])
                if code != 0:
                    raise ReviewError("E_REPO_UNREACHABLE", url=str(src.get("repo_url") or "")[:200])
                heads = [ln.split("\t", 1)[0].strip() for ln in out.splitlines() if ln.endswith("\tHEAD")]
                sha = heads[0] if heads and _SHA1_RE.match(heads[0]) else None
        except ReviewError as exc:
            await _terminal(sup, step, "failed", exc.code, detail=unpinned_ref_detail(exc, str(src.get("ref") or "HEAD")))
            return None
    if sha is None:
        return job          # a short commit: the archive fetch takes it as given
    async with sup._pool.connection() as conn:
        await JobRepo(conn).update_job_fields(job["job_id"], resolved_commit=sha)
    return {**job, "resolved_commit": sha}


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
    named_source = (job.get("source_args") or {}).get("kind") in ("repo", "files")
    if acct is not None and acct["status"] != "active" and not named_source:
        _write_json(out_dir / "provenance.json", {"reason": "NO_DEPLOYED_CODE", "tier": "D", "why": acct["status"],
                                                  "mc_seqno": cs["mc_seqno"]})
        await _terminal(sup, step, "insufficient_source", "E_SOURCE_NOT_FOUND", tier="D",
                        detail={"reason": "NO_DEPLOYED_CODE", "status": acct["status"]})
        return

    pinned = await _pin_repo_commit(sup, step, job)
    if pinned is None:
        return
    job = pinned
    read_status: dict[str, str] = {}
    inputs = _user_inputs(job)
    active = acct is not None and acct["status"] == "active"
    cands = await fetch_ton_sources(
        raw_address=next(iter(cs["accounts"]), None),
        code_hash=acct.get("dep_hash") if active else None,
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
        detail: dict[str, Any] = {"reason": "NO_SOURCE_FOUND"}
        if inputs.get("repo_url"):
            # the repository at this commit (and subdir) holds no FunC, Tact or Tolk file
            detail.update(reason="REPO_NO_TON_SOURCES", repo_family="no_ton_sources", chain="ton")
            if inputs.get("repo_subdir"):
                detail["subdir"] = str(inputs["repo_subdir"])[:200]
        await _terminal(sup, step, "insufficient_source", "E_SOURCE_NOT_FOUND", tier="D", detail=detail)
        return

    # `provider` is the source the review is of (review_status provenance.source): the requester's
    # repo or files when given, else the first automatic source.
    provider = next((c.provider for c in cands if c.provider in ("user", "repo")), cands[0].provider)
    await sup._mark_step(step["id"], "done", provenance={"provider": provider,
                                                         "candidates": [c.provider for c in cands], **read_status})
    await sup._after_fetch(step, job)


# ── build + resolve_provenance ────────────────────────────────────────────

# Library sources (masterchain libraries the reviewed code references by hash) are pinned beside the
# main source under _related/, the prefix the EVM related contracts use: readable, searchable and
# quotable in the same job, never compiled with the main code.
RELATED_PREFIX = "_related/"
MAX_LIBRARY_FILES = 200


def _library_name(lib_hash: str) -> str:
    return f"library_{lib_hash[:12]}"


def _resolve_libraries(out_dir: Path, cand: Candidate
                       ) -> tuple[dict[str, str], dict[str, str], dict[str, bool], list[dict[str, Any]]]:
    """Rebuild each library source fetched for `cand` (fetch.resolve_library_refs), compare its hash
    with the library body read from the chain, and return `(files, langs, in_scope, records)`.

    Blind round 5b (2026-10-31): the multisig v2 order contract is the library 0x6305a806..., whose
    source is verified on its own; the job pinned only the multisig bundle, so `order.func` could
    not be read. A library source enters the pin only at tier A (rebuild equals the library hash) or
    tier B (verifier-attested, compiler not installed); its standard library and the files equal to a
    reviewed main file are pinned out of scope (readable, no leads, not counted twice).
    """
    settings = cand.settings or {}
    sources = settings.get("library_sources") or {}
    refs = {r.get("hash"): r for r in (settings.get("library_refs") or []) if isinstance(r, dict)}
    main_texts = set(cand.files.values())
    files: dict[str, str] = {}
    langs: dict[str, str] = {}
    in_scope: dict[str, bool] = {}
    records: list[dict[str, Any]] = []
    for lib_hash, doc in list(sources.items())[:4]:
        row = refs.get(lib_hash)
        if not isinstance(doc, dict) or not isinstance(row, dict) or row.get("status") != "ok":
            continue                      # the library body must have been read and hashed here
        lc = library_candidate_from_json(doc)
        name = _library_name(lib_hash)
        work = out_dir / "attempts" / name

        def attempt(i: int, c: Candidate, work: Path = work) -> Attempt:
            br = _build_mod.build(c, work_dir=work)
            hashes = {a.contract: a.runtime for a in br.artifacts} if br.status == "ok" else {}
            return Attempt(i, c.provider, "ok" if br.status == "ok" else (br.reason or "compile_error"), hashes,
                           untrusted_inputs=c.untrusted_inputs)

        lo = resolve_provenance(Dep(address=f"library:{lib_hash}", status="active", hash=lib_hash), [lc], attempt)
        rec: dict[str, Any] = {"name": name, "role": "library", "hash": lib_hash, "provider": lc.provider,
                               "tier": lo.tier, "reason": lo.reason}
        if lo.tier not in ("A", "B"):
            rec.update(status="source_not_matched",
                       note=(f"The verified source of library {lib_hash[:12]} does not rebuild to the library "
                             f"code read from the chain ({lo.why or 'no match'}), so it is not part of this review."))
            row.update(source_tier=lo.tier, source_reason=lo.reason)
            records.append(rec)
            continue
        prefix = f"{RELATED_PREFIX}{name}/"
        std = stdlib_paths(lc.files, (lc.settings or {}).get("stdlib_files") or [])
        n_scope = 0
        for path, text in sorted(lc.files.items())[:MAX_LIBRARY_FILES]:
            pinned = prefix + path.lstrip("/")
            files[pinned] = text
            langs[pinned] = lc.language
            in_scope[pinned] = path not in std and text not in main_texts
            n_scope += in_scope[pinned]
        rec.update(status="pinned", match=lo.match or "third_party_verified_only", path=prefix.rstrip("/"),
                   files=min(len(lc.files), MAX_LIBRARY_FILES), files_in_scope=n_scope,
                   build_hash=lo.build_hash,
                   note=(f"Library {lib_hash[:12]} (code the reviewed contract deploys by hash): its verified "
                         f"source is pinned under {prefix.rstrip('/')}, tier {lo.tier}"
                         + (", rebuilt to the library hash read from the chain." if lo.tier == "A"
                            else ", attested by the verifier; the compiler is not installed, so it was not rebuilt.")))
        row.update(source_tier=lo.tier, source_reason=lo.reason, source_path=prefix.rstrip("/"))
        records.append(rec)
    return files, langs, in_scope, records



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
    lib_files: dict[str, str] = {}
    lib_langs: dict[str, str] = {}
    lib_scope: dict[str, bool] = {}
    lib_records: list[dict[str, Any]] = []
    if out.src is not None and 0 <= out.src < len(cands) and out.tier != "D":
        # the library sources, rebuilt and matched to the library hashes (written into library_refs)
        lib_files, lib_langs, lib_scope, lib_records = await asyncio.get_event_loop().run_in_executor(
            None, _resolve_libraries, out_dir, cands[out.src])
    if out.src is not None and 0 <= out.src < len(cands):
        # masterchain libraries the reviewed source references by hash (fetch.resolve_library_refs)
        libs = (cands[out.src].settings or {}).get("library_refs")
        if libs:
            prov["library_refs"] = libs
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
    # the FunC standard library is a dependency: readable, out of scope, no leads (units.stdlib_paths)
    std = stdlib_paths(src.files, (src.settings or {}).get("stdlib_files") or [])
    pin = PinnedSource.from_files(
        {p: c.encode("utf-8") for p, c in {**lib_files, **src.files}.items()},
        langs={**lib_langs, **{p: src.language for p in src.files}},
        in_scope={**lib_scope, **{p: False for p in std}},
        roles={**{p: ("source" if ok else "dependency") for p, ok in lib_scope.items()},
               **{p: "dependency" for p in std}},
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
    build_prov: dict[str, Any] = {"reason": out.reason, "tier": out.tier,
                                  "dep_hash": out.dep_hash, "build_hash": out.build_hash}
    if cs["accounts"]:
        # review_status build.deployment (start_status._deployment_status): the match outcome as
        # soon as it is known, in the dep_match vocabulary.
        if out.match == "exact":
            build_prov.update(dep_match="exact", dep_reason="match_rebuild")
        elif out.reason == SOURCE_TOOLCHAIN_GAP:
            build_prov.update(dep_match="third_party_verified_only", dep_reason="verifier_hash_attested")
        elif out.reason == SOURCE_UNLINKED:
            build_prov.update(dep_match="not_checkable", dep_reason=unlinked_reason(out.why))
    if lib_records:
        # review_status `related`: one line per library source, with its own match tier
        build_prov["related"] = lib_records
    if std:
        build_prov["stdlib"] = sorted(std)[:8]
    await sup._mark_step(step["id"], "done", provenance=build_prov)
    await sup._after_build(step, result)


# ── analyze ───────────────────────────────────────────────────────────────


def _pinned_related_sources(pin_root: Path, job_id: str) -> dict[str, str]:
    """In-scope source files of the pin under _related/ (library sources), path -> text."""
    try:
        pin = PinnedSource.load(pin_root, job_id)
    except (OSError, ValueError, KeyError):
        return {}
    return {p: pin.read_text(p) for p, e in pin.entries.items()
            if p.startswith(RELATED_PREFIX) and e.in_scope and e.role == "source"}


async def _analyze(sup: Supervisor, step: dict[str, Any], job: dict[str, Any]) -> None:
    out_dir = sup._job_dir(job["job_id"])
    leads_out = sup._pin_root / job["job_id"] / "leads.json"
    if leads_out.exists():
        await sup._mark_step(step["id"], "done")
        await sup._after_analyze(step)
        return

    result = json.loads((out_dir / "build_result.json").read_text())
    cand = _cand_from_json(json.loads((out_dir / "cands" / f"{result['src']}.json").read_text()))
    # the library sources pinned in scope (_resolve_libraries) are analysed with the main source
    cand.files = {**_pinned_related_sources(sup._pin_root, job["job_id"]), **cand.files}
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
