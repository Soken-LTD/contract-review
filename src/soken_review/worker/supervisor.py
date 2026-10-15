"""Supervisor loop: claim and run job steps for the EVM pipeline (plan-v4 09 3.1–3.6).

Step order for EVM deployed-address jobs (09 3.1, 03 3.1):
  chain_state (seq=0) -> fetch -> build -> analyze -> map -> chain_state (seq=1) -> ready;
  after finalize: render (08 3.2)

`map` builds map.v1 (lexical layer always, semantic layer when the build succeeded), the J1 to J5
flags and the static facts (04 2.1, 6.3, 12); `chain_state 1` reads the on-chain facts at the
pinned block; the transition to `ready` creates one server draft per J2 or J4 flag (04 12).

Non-terminal outcomes (09 3.6):
  - build failed/refused: ready with map_status=failed, analyzer_degraded=True
  - analyzer not_run:     ready with analyzer_degraded=True
  - insufficient_source (no bytecode or no source): terminal insufficient_source

Restartability (09 3.4): each runner checks for existing output and skips if already done.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import socket
import time
from pathlib import Path
from typing import Any

import psycopg_pool

from ..adapters.base import BuildResult, Candidate, Compiler
from ..adapters.evm import analyze as _analyze_mod
from ..adapters.evm import build as _build_mod
from ..adapters.evm import fetch as _fetch_mod
from ..adapters.evm import files as _files_mod
from ..adapters.evm.rpc import RpcClient
from ..db.job_repo import JobRepo
from ..engine.injection import server_draft_flags
from ..engine.provenance import DepResult, evm_deployment_check, resolve_provenance
from ..mapping import facts as _facts_mod
from ..mapping import step as _map_step
from ..pinning.store import PinnedSource
from ..report import render as _render_mod
from ..sandbox.output import UnsafeOutput, read_output_files
from . import ton_pipeline

logger = logging.getLogger(__name__)

def _rpc_url(chain_id: int) -> str | None:
    """`SOKEN_RPC_<chain_id>` (09 provider row, keyed endpoint) overrides the registry's first RPC (05 4.1)."""
    override = os.environ.get(f"SOKEN_RPC_{chain_id}")
    if override:
        return override
    from ..adapters.evm.registry import get_chain

    chain = get_chain(chain_id)
    return chain.rpc[0].url if chain and chain.rpc else None


class Supervisor:
    """Single-process supervisor: seed, claim, and run job steps (09 section 3.3).

    One instance per worker process. Call ``run()`` to start the event loop.
    """

    def __init__(
        self,
        pool: psycopg_pool.AsyncConnectionPool,
        pin_root: Path,
        *,
        host_name: str | None = None,
        poll_interval: float = 1.0,
        lease_secs: int = 360,
        total_units: int = 7,
        total_ram_mb: int = 14336,
    ) -> None:
        self._pool = pool
        self._pin_root = pin_root
        self._host = host_name or socket.gethostname()
        self._poll_interval = poll_interval
        self._lease_secs = lease_secs
        self._total_units = total_units
        self._total_ram_mb = total_ram_mb
        self._free_units = total_units
        self._free_ram_mb = total_ram_mb
        self._running: dict[int, asyncio.Task] = {}  # step_id -> task

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main loop: seed new jobs, claim and run steps, heartbeat (09 3.3)."""
        hb_task = asyncio.create_task(self._heartbeat_loop())
        try:
            while True:
                await self._seed_loop()
                step = await self._try_claim()
                if step:
                    task = asyncio.create_task(self._run_step(step))
                    self._running[step["id"]] = task
                    task.add_done_callback(lambda t, sid=step["id"]: self._running.pop(sid, None))
                else:
                    await asyncio.sleep(self._poll_interval)
        finally:
            hb_task.cancel()
            if self._running:
                await asyncio.gather(*self._running.values(), return_exceptions=True)

    # ------------------------------------------------------------------
    # Heartbeat (09 3.3: 15 s)
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                async with self._pool.connection() as conn:
                    await conn.execute(
                        """
                        insert into worker_hosts (name, units_total, ram_mb_total, last_seen)
                        values (%s, %s, %s, now())
                        on conflict (name) do update set last_seen = now()
                        """,
                        (self._host, self._total_units, self._total_ram_mb),
                    )
            except Exception:
                logger.exception("heartbeat failed")
            await asyncio.sleep(15)

    # ------------------------------------------------------------------
    # Seed loop (09 3.3): insert chain_state step for new queued jobs
    # ------------------------------------------------------------------

    async def _seed_loop(self) -> None:
        """Insert the initial chain_state step for queued jobs with no steps yet."""
        try:
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                jobs = await repo.find_unseeded_jobs()
                for job in jobs:
                    jid = job["job_id"]
                    async with conn.transaction():
                        await repo.insert_step(
                            job_id=jid,
                            step="chain_state",
                            seq=0,
                            container=False,
                            units=0,
                            ram_mb=0,
                            max_attempts=3,
                        )
                    logger.info("seeded chain_state step for job %s", jid[-8:])
        except Exception:
            logger.exception("seed_loop error")

    # ------------------------------------------------------------------
    # Claim
    # ------------------------------------------------------------------

    async def _try_claim(self) -> dict[str, Any] | None:
        """Claim the next eligible step row, respecting resource budgets (09 3.3)."""
        try:
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                step = None
                for render in (True, False):  # 09 3.3: render first
                    step = await repo.claim_step(
                        host=self._host,
                        free_units=self._free_units,
                        lease_secs=self._lease_secs,
                        free_ram_mb=self._free_ram_mb,
                        max_units_idle=self._total_units,
                        max_ram_idle=self._total_ram_mb,
                        render=render,
                    )
                    if step:
                        break
            return step
        except Exception:
            logger.exception("claim failed")
            return None

    # ------------------------------------------------------------------
    # Step dispatcher
    # ------------------------------------------------------------------

    async def _run_step(self, step: dict[str, Any]) -> None:
        """Dispatch one step to its runner; mark done or failed (09 3.6)."""
        step_name: str = step["step"]
        job_id: str = step["job_id"]
        step_id: int = step["id"]
        logger.info("running step %s/%s for job %s", step_name, step["seq"], job_id[-8:])

        # Allocate resources
        self._free_units = max(0, self._free_units - step["units"])
        self._free_ram_mb = max(0, self._free_ram_mb - step["ram_mb"])
        t0 = time.monotonic()

        try:
            job = await self._get_job(job_id)
            if job is not None and ton_pipeline.is_ton_job(job):
                await ton_pipeline.run_step(self, step, job)
            elif job is not None and job.get("chain") == "starknet" and (
                (step_name == "chain_state" and step["seq"] == 0) or step_name in ("fetch", "build", "analyze")
            ):
                # Starknet family (plan-v4 07): own runners for its steps; render etc. stay generic.
                from . import starknet_steps

                await starknet_steps.run_step(self, step, job)
            elif step_name == "chain_state" and step["seq"] == 0:
                await self._run_chain_state_0(step)
            elif step_name == "fetch":
                await self._run_fetch(step)
            elif step_name == "build":
                await self._run_build(step)
            elif step_name == "analyze":
                await self._run_analyze(step)
            elif step_name == "render":
                await _render_mod.run_render_step(self._pool, step, self._pin_root)
            elif step_name == "map":
                await self._run_map(step)
            elif step_name == "chain_state" and step["seq"] == 1:
                await self._run_chain_state_1(step)
            else:
                logger.warning("no handler for step %s; marking done", step_name)
                await self._mark_step(step_id, "done")
        except Exception:
            logger.exception("step %s/%s failed for job %s", step_name, step["seq"], job_id[-8:])
            await self._mark_step(step_id, "failed", error_code="E_INTERNAL")
        finally:
            self._free_units += step["units"]
            self._free_ram_mb += step["ram_mb"]
            elapsed = time.monotonic() - t0
            logger.info("step %s/%s finished in %.1fs", step_name, step["seq"], elapsed)

    # ------------------------------------------------------------------
    # chain_state 0: read bytecode, pin block (09 3.1)
    # ------------------------------------------------------------------

    async def _run_chain_state_0(self, step: dict[str, Any]) -> None:
        """Read on-chain bytecode to check source availability (09 3.1, 3.6)."""
        job_id = step["job_id"]
        step_id = step["id"]

        job = await self._get_job(job_id)
        if job is None:
            await self._mark_step(step_id, "failed", error_code="E_INTERNAL")
            return

        # Restartability: if output already exists, skip (09 3.4)
        out_dir = self._job_dir(job_id)
        out_dir.mkdir(parents=True, exist_ok=True)
        cs_path = out_dir / "chain_state.json"
        if cs_path.exists():
            logger.debug("chain_state output exists for %s; skipping", job_id[-8:])
            await self._mark_step(step_id, "done")
            await self._after_chain_state(step, job)
            return

        chain_id: int | None = job.get("chain_id")
        address: str | None = job.get("address")

        if not chain_id or not address:
            # Not a deployed-address job; transition directly to fetch
            await self._mark_step(step_id, "done")
            await self._after_chain_state(step, job)
            return

        rpc_url = _rpc_url(chain_id)
        if not rpc_url:
            # Fail closed: an address job without a pinned chain read would review unpinned code
            # with no deployment check (03 3.1: provider fault = failed, internal step error).
            logger.error("no RPC for chain_id %s; job %s failed", chain_id, job_id[-8:])
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.complete_step(step_id, "failed", error_code="E_INTERNAL")
                    await repo.transition(job_id, "failed", error_code="E_INTERNAL")
            return

        client = RpcClient(rpc_url)
        block_num = await client.block_number()
        # Use block_num - 1 for stability (avoid tip-race)
        pin_block = block_num - 1
        client_pinned = RpcClient(rpc_url, block=pin_block)

        addr_lower = address.lower()
        if not addr_lower.startswith("0x"):
            addr_lower = "0x" + addr_lower

        bytecode = await client_pinned.get_code(addr_lower)
        is_eoa = not bytecode or bytecode in ("0x", "0x0", "")

        cs_path.write_text(
            json.dumps({"chain_id": chain_id, "address": addr_lower, "bytecode": bytecode, "block": pin_block}),
            encoding="utf-8",
        )

        if is_eoa:
            # Terminal: no source possible for an EOA (09 3.6)
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.complete_step(step_id, "done")
                    await repo.transition(
                        job_id,
                        "insufficient_source",
                        error_code="E_SOURCE_NOT_FOUND",
                    )
            logger.info("job %s: no bytecode, terminal insufficient_source", job_id[-8:])
            return

        # Code present: proceed to fetch
        await self._mark_step(step_id, "done",
                              provenance={"block": pin_block, "chain_id": chain_id})
        await self._after_chain_state(step, job)

    async def _after_chain_state(self, step: dict[str, Any], job: dict[str, Any]) -> None:
        """Transition job to fetching and insert fetch step after chain_state done."""
        job_id = job["job_id"]
        affinity: str | None = step.get("lease_owner")
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.transition(job_id, "fetching")
                await repo.insert_step(
                    job_id=job_id,
                    step="fetch",
                    container=False,
                    units=0,
                    ram_mb=0,
                    max_attempts=3,
                    affinity=affinity,
                )

    # ------------------------------------------------------------------
    # fetch: retrieve source candidates, checkpoint (09 3.1, 3.4)
    # ------------------------------------------------------------------

    async def _run_fetch(self, step: dict[str, Any]) -> None:
        """Fetch source candidates and pin files (09 3.1)."""
        job_id = step["job_id"]
        step_id = step["id"]

        job = await self._get_job(job_id)
        if job is None:
            await self._mark_step(step_id, "failed", error_code="E_INTERNAL")
            return

        out_dir = self._job_dir(job_id)
        out_dir.mkdir(parents=True, exist_ok=True)
        candidates_path = out_dir / "candidates.json"

        # Restartability: if already fetched, skip (09 3.4)
        if candidates_path.exists():
            logger.debug("candidates.json exists for %s; skipping fetch", job_id[-8:])
            await self._mark_step(step_id, "done")
            await self._after_fetch(step, job)
            return

        # Read chain state
        cs_path = out_dir / "chain_state.json"
        chain_id: int | None = job.get("chain_id")
        address: str | None = job.get("address")
        bytecode: str | None = None

        if cs_path.exists():
            cs = json.loads(cs_path.read_text())
            chain_id = cs.get("chain_id") or chain_id
            address = cs.get("address") or address
            bytecode = cs.get("bytecode")

        source_args = job.get("source_args") or {}
        if isinstance(source_args, str):
            source_args = json.loads(source_args)
        if job.get("source_kind") == "files" and source_args.get("language") == "solidity":
            # Inline Solidity files (03 4.1): the requester's files are the only candidate,
            # compiler from the pragmas (adapters/evm/files.py).
            cand = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _files_mod.files_candidate(source_args.get("files") or [])
            )
            candidates = [cand] if cand is not None else []
        elif not chain_id or not address:
            # Not a deployed job; no candidates possible this way
            candidates_path.write_text("[]", encoding="utf-8")
            await self._mark_step(step_id, "done")
            await self._after_fetch(step, job)
            return
        else:
            candidates = await _fetch_mod.fetch_source(
                chain_id=chain_id,
                address=address,
                runtime_bytecode=bytecode or "",
            )

        if not candidates:
            # No source found: terminal insufficient_source (09 3.6)
            candidates_path.write_text("[]", encoding="utf-8")
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.complete_step(step_id, "done")
                    await repo.transition(
                        job_id,
                        "insufficient_source",
                        error_code="E_SOURCE_NOT_FOUND",
                    )
            logger.info("job %s: no source candidates, terminal insufficient_source", job_id[-8:])
            return

        # Pick the best candidate (first = highest priority per fetch order)
        best = candidates[0]

        # Pin source files (09 3.4 checkpoint)
        try:
            pin = PinnedSource.from_files(
                {path: content.encode("utf-8") for path, content in best.files.items()},
                langs={path: best.language for path in best.files},
            )
            pin.persist(self._pin_root, job_id)
        except Exception:
            logger.exception("pin failed for job %s", job_id[-8:])
            await self._mark_step(step_id, "failed", error_code="E_INTERNAL")
            return

        # Write candidates.json (RULES.md hand-off format)
        cands_out = [
            {
                "provider": c.provider,
                "sha256": c.sha256,
                "language": c.language,
                "compiler": {"version": c.compiler.version, "version_pinned_by": c.compiler.version_pinned_by}
                if c.compiler else None,
                "settings": c.settings,
                "entry_contract": c.entry_contract,
                "explorer_verified": c.explorer_verified,
                "sourcify_match": c.sourcify_match,
                "untrusted_inputs": c.untrusted_inputs,
                "fetched_at": c.fetched_at,
            }
            for c in candidates
        ]
        candidates_path.write_text(json.dumps(cands_out, indent=2), encoding="utf-8")
        # The reviewed candidate's Standard JSON input, byte for byte (the pin is LF-normalised);
        # build uses it only when its sources are the pinned files (_std_input_for_build).
        (out_dir / "std_input_0.json").write_text(
            json.dumps({"std_json_input": best.std_json_input,
                        "constructor_args_hex": best.constructor_args_hex}),
            encoding="utf-8",
        )

        # Update source_pin on the job row (03 checkpoint)
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            await repo.update_job_fields(job_id, source_pin=pin.source_pin)

        await self._mark_step(step_id, "done",
                              provenance={"provider": best.provider, "sha256": best.sha256})
        await self._after_fetch(step, job)

    async def _after_fetch(self, step: dict[str, Any], job: dict[str, Any]) -> None:
        """Transition job to building and insert build step after fetch done."""
        job_id = job["job_id"]
        affinity: str | None = step.get("lease_owner")
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.transition(job_id, "building")
                await repo.insert_step(
                    job_id=job_id,
                    step="build",
                    container=True,
                    units=2,
                    ram_mb=4096,
                    max_attempts=1,
                    affinity=affinity,
                )

    # ------------------------------------------------------------------
    # build: compile with solc inside sandbox (09 3.1, 4.1)
    # ------------------------------------------------------------------

    async def _run_build(self, step: dict[str, Any]) -> None:
        """Build candidate source with solc (09 3.1, 4.1)."""
        job_id = step["job_id"]
        step_id = step["id"]

        out_dir = self._job_dir(job_id)
        build_path = out_dir / "build_result.json"

        # Restartability (09 3.4)
        if build_path.exists():
            logger.debug("build_result.json exists for %s; skipping build", job_id[-8:])
            result = _load_build_result(build_path)
            prov = await self._resolve_provenance(job_id, out_dir, _build_result_from_disk(out_dir, result))
            await self._mark_step(step_id, "done", provenance=prov)
            await self._after_build(step, result)
            return

        candidates_path = out_dir / "candidates.json"
        if not candidates_path.exists():
            logger.error("no candidates.json for job %s", job_id[-8:])
            await self._mark_step(step_id, "failed", error_code="E_INTERNAL")
            return

        candidates_raw = json.loads(candidates_path.read_text())
        if not candidates_raw:
            # No candidates: write build_result with status=failed, map_status=failed
            result = {"status": "failed", "reason": "no_candidates", "nsloc": 0, "stderr_head": None}
            build_path.write_text(json.dumps(result), encoding="utf-8")
            await self._mark_step(step_id, "done")
            await self._after_build(step, result)
            return

        # Reconstruct the Candidate for build (from candidates.json + pin store)
        cand_raw = candidates_raw[0]

        try:
            pin = PinnedSource.load(self._pin_root, job_id)
            files_str = {path: "\n".join(pin.read_all(path)) for path in pin.entries}
        except Exception:
            logger.exception("failed to load pin for job %s", job_id[-8:])
            result = {"status": "failed", "reason": "pin_load_error", "nsloc": 0, "stderr_head": None}
            build_path.write_text(json.dumps(result), encoding="utf-8")
            await self._mark_step(step_id, "done")
            await self._after_build(step, result)
            return

        comp_raw = cand_raw.get("compiler")
        candidate = Candidate(
            provider=cand_raw["provider"],  # type: ignore[arg-type]
            files=files_str,
            sha256=cand_raw["sha256"],
            language=cand_raw["language"],
            compiler=Compiler(
                version=comp_raw["version"],
                version_pinned_by=comp_raw["version_pinned_by"],
            ) if comp_raw else None,
            settings=cand_raw.get("settings", {}),
            std_json_input=_std_input_for_build(out_dir, files_str),
            entry_contract=cand_raw.get("entry_contract"),
            explorer_verified=cand_raw.get("explorer_verified", False),
            sourcify_match=cand_raw.get("sourcify_match"),
            untrusted_inputs=cand_raw.get("untrusted_inputs", False),
        )

        # Run build (synchronous; offload to thread to avoid blocking the loop)
        work_dir = out_dir / "work"
        work_dir.mkdir(exist_ok=True)
        build_result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _build_mod.build(candidate, work_dir=work_dir)
        )

        result = {
            "status": build_result.status,
            "nsloc": build_result.nsloc,
            "reason": build_result.reason,
            "stderr_head": build_result.stderr_head,
            "work_dir": str(build_result.work_dir) if build_result.work_dir else None,
            "auxdata_ranges": {k: [list(r) for r in v] for k, v in build_result.auxdata_ranges.items()},
            "std_json": candidate.std_json_input is not None,
            # work/ is mounted read-write into build and analyze containers. Right after the
            # build, before any later container runs, the solc output is copied into the job dir
            # (never mounted) with its hash; the restart path and the map step read only the copy.
            "output_sha256": _snapshot_solc_output(out_dir, build_result.work_dir),
        }
        build_path.write_text(json.dumps(result), encoding="utf-8")

        # Store build_result.work_dir so analyze can find it
        if build_result.work_dir:
            (out_dir / "work_dir.txt").write_text(build_result.work_dir, encoding="utf-8")

        # The candidate is the one this supervisor reconstructed and built, never one a step returned
        prov = await self._resolve_provenance(job_id, out_dir, dataclasses.replace(build_result, candidate=candidate))
        await self._mark_step(step_id, "done", provenance=prov)
        await self._after_build(step, result)

    # ------------------------------------------------------------------
    # Provenance: 05 13.1 comparison and the 04 section 3 tier, computed here (05 3.1)
    # ------------------------------------------------------------------

    async def _resolve_provenance(self, job_id: str, out_dir: Path, build: BuildResult | None) -> dict[str, Any]:
        """Compare the rebuilt runtime with the pinned chain_state runtime, set the job tier.

        Inputs are the solc output parsed on the host and the runtime read in chain_state 0;
        no file a build container wrote is taken as a verdict. Writes deployment.json.
        """
        prov_path = out_dir / "deployment.json"
        if prov_path.exists():
            prov = json.loads(prov_path.read_text())
        else:
            cs_path = out_dir / "chain_state.json"
            cs = json.loads(cs_path.read_text()) if cs_path.exists() else {}
            address = cs.get("address")
            dep = None
            if build is not None and address:
                from ..adapters.evm.registry import get_chain

                chain = get_chain(cs.get("chain_id") or 0)
                if chain is None:
                    # No registry entry, no family rules (13.3): fail closed, never assume EVM.
                    dep = DepResult("not_checkable", "build_failed",
                                    notes=[f"chain {cs.get('chain_id')} not in the registry"])
                else:
                    dep = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: evm_deployment_check(family=chain.family, build=build,
                                                           onchain_runtime=cs.get("bytecode"),
                                                           address=address)
                    )
            prov = resolve_provenance(candidate=build.candidate if build else None, address=address, dep=dep)
            prov["block"] = cs.get("block")
            prov_path.write_text(json.dumps(prov, indent=2), encoding="utf-8")
        async with self._pool.connection() as conn:
            await JobRepo(conn).update_job_fields(job_id, tier=prov["tier"])
        logger.info("job %s: dep.match=%s tier=%s", job_id[-8:],
                    (prov.get("dep") or {}).get("match"), prov["tier"])
        return {"tier": prov["tier"], "dep_match": (prov.get("dep") or {}).get("match"),
                "dep_reason": (prov.get("dep") or {}).get("reason")}

    async def _after_build(self, step: dict[str, Any], build_result: dict[str, Any]) -> None:
        """Transition job to analyzing and insert analyze step after build (09 3.6)."""
        job_id = step["job_id"]
        affinity: str | None = step.get("lease_owner")
        map_status = "none" if build_result["status"] == "ok" else "failed"

        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.update_job_fields(job_id, map_status=map_status)
                await repo.transition(job_id, "analyzing")
                await repo.insert_step(
                    job_id=job_id,
                    step="analyze",
                    tool="slither",
                    container=True,
                    units=2,
                    ram_mb=6144,
                    max_attempts=1,
                    affinity=affinity,
                )

    # ------------------------------------------------------------------
    # analyze: run Slither/Aderyn, write leads.json (09 3.1, 3.6)
    # ------------------------------------------------------------------

    async def _run_analyze(self, step: dict[str, Any]) -> None:
        """Run static analyzers, write leads.json (09 3.1)."""
        job_id = step["job_id"]
        step_id = step["id"]

        out_dir = self._job_dir(job_id)
        leads_out = self._pin_root / job_id / "leads.json"

        # Restartability (09 3.4)
        if leads_out.exists():
            logger.debug("leads.json exists for %s; skipping analyze", job_id[-8:])
            await self._mark_step(step_id, "done")
            await self._after_analyze(step)
            return

        build_path = out_dir / "build_result.json"
        work_dir_file = out_dir / "work_dir.txt"

        if not build_path.exists():
            logger.error("no build_result.json for job %s", job_id[-8:])
            leads_out.parent.mkdir(parents=True, exist_ok=True)
            leads_out.write_text("[]", encoding="utf-8")
            await self._mark_step(step_id, "failed", error_code="E_INTERNAL")
            await self._after_analyze(step, degraded=True)
            return

        build_result_raw = json.loads(build_path.read_text())
        if build_result_raw["status"] != "ok" or not work_dir_file.exists():
            # Build failed: no analyze possible, write empty leads (09 3.6 non-terminal)
            leads_out.parent.mkdir(parents=True, exist_ok=True)
            leads_out.write_text("[]", encoding="utf-8")
            await self._mark_step(step_id, "done")
            await self._after_analyze(step, degraded=True)
            return

        # Reconstruct BuildResult for analyze
        work_dir = Path(work_dir_file.read_text().strip())

        cands_path = out_dir / "candidates.json"
        cands_raw = json.loads(cands_path.read_text()) if cands_path.exists() else []
        if not cands_raw:
            leads_out.parent.mkdir(parents=True, exist_ok=True)
            leads_out.write_text("[]", encoding="utf-8")
            await self._mark_step(step_id, "done")
            await self._after_analyze(step, degraded=True)
            return

        cand_raw = cands_raw[0]
        comp_raw = cand_raw.get("compiler")
        candidate = Candidate(
            provider=cand_raw["provider"],  # type: ignore[arg-type]
            files={},
            sha256=cand_raw["sha256"],
            language=cand_raw["language"],
            compiler=Compiler(
                version=comp_raw["version"],
                version_pinned_by=comp_raw["version_pinned_by"],
            ) if comp_raw else None,
            settings=cand_raw.get("settings", {}),
            std_json_input=None,
            entry_contract=cand_raw.get("entry_contract"),
            explorer_verified=cand_raw.get("explorer_verified", False),
        )

        br = BuildResult(
            candidate=candidate,
            status="ok",
            nsloc=build_result_raw.get("nsloc", 0),
            work_dir=str(work_dir),
        )

        try:
            leads, static_map, _read_plan = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _analyze_mod.analyze(br)
            )
            degraded = static_map.get("status") in ("not_run", "degraded")
        except Exception:
            logger.exception("analyze failed for job %s", job_id[-8:])
            leads = []
            static_map = {"status": "not_run", "reason": "analyzer_failed"}
            degraded = True
        (out_dir / "static_map.json").write_text(json.dumps(static_map), encoding="utf-8")

        leads_out.parent.mkdir(parents=True, exist_ok=True)
        leads_out.write_text(json.dumps(leads, indent=2), encoding="utf-8")

        await self._mark_step(step_id, "done")
        await self._after_analyze(step, degraded=degraded)

    async def _after_analyze(self, step: dict[str, Any], degraded: bool = False) -> None:
        """Queue the map step after the analyze step (03 3.1: map runs in `analyzing`)."""
        job_id = step["job_id"]
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                if degraded:
                    await repo.update_job_fields(job_id, analyzer_degraded=True)
                await repo.insert_step(
                    job_id=job_id, step="map", container=False, units=0, ram_mb=0, max_attempts=1,
                    affinity=step.get("lease_owner"),
                )

    # ------------------------------------------------------------------
    # map: map.v1, J1 to J5 flags, static facts (04 2.1, 12, 6.3)
    # ------------------------------------------------------------------

    async def _run_map(self, step: dict[str, Any]) -> None:
        """Build the contract map from the pin (lexical) and the solc output (semantic)."""
        job_id = step["job_id"]
        step_id = step["id"]
        job = await self._get_job(job_id)
        out_dir = self._job_dir(job_id)
        build_path = out_dir / "build_result.json"
        build = json.loads(build_path.read_text()) if build_path.exists() else {"status": "failed"}
        build_ok = build.get("status") == "ok"
        cs_path = out_dir / "chain_state.json"
        chain_state = json.loads(cs_path.read_text()) if cs_path.exists() else None
        cands_path = out_dir / "candidates.json"
        cands = json.loads(cands_path.read_text()) if cands_path.exists() else []
        sm_path = out_dir / "static_map.json"
        static_map = json.loads(sm_path.read_text()) if sm_path.exists() else {}
        analyzers = {}
        if static_map.get("status") == "ok":
            analyzers["slither"] = _analyze_mod._SLITHER_VERSION
            if static_map.get("aderyn", "not_run") != "not_run":
                analyzers["aderyn"] = _analyze_mod._ADERYN_VERSION
        detail = None if build_ok else (build.get("stderr_head") or build.get("reason"))
        summary = await asyncio.get_event_loop().run_in_executor(None, lambda: _map_step.run_map_step(
            self._pin_root, job_id,
            family="evm", chain=(job or {}).get("chain"),
            solc_output_path=_solc_output_copy(out_dir, build),
            build_ok=build_ok, job=job, chain_state=chain_state,
            candidate=cands[0] if cands else None, nsloc=build.get("nsloc"),
            analyzers=analyzers, build_detail=detail,
        ))
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.update_job_fields(job_id, map_status=summary["map_status"])
                await repo.complete_step(step_id, "done", provenance=summary)
                await repo.insert_step(
                    job_id=job_id, step="chain_state", seq=1, container=False, units=0, ram_mb=0,
                    max_attempts=3, affinity=step.get("lease_owner"),
                )
        logger.info("job %s map %s", job_id[-8:], summary)

    # ------------------------------------------------------------------
    # chain_state 1: on-chain facts at the pinned block (03 3.1, 04 6.3 A4)
    # ------------------------------------------------------------------

    async def _run_chain_state_1(self, step: dict[str, Any]) -> None:
        job_id = step["job_id"]
        step_id = step["id"]
        job = await self._get_job(job_id)
        out_dir = self._job_dir(job_id)
        cs_path = out_dir / "chain_state.json"
        facts = _facts_mod.load_facts(self._pin_root, job_id) or []
        added = 0
        if cs_path.exists() and job and job.get("chain_id") and not any(f["key"].startswith("onchain.") for f in facts):
            cs = json.loads(cs_path.read_text())
            rpc_url = _rpc_url(int(job["chain_id"]))
            if rpc_url and cs.get("block") is not None:
                from ..mapping.build import load_map

                doc, _ = load_map(self._pin_root, job_id)
                cands_path = out_dir / "candidates.json"
                cands = json.loads(cands_path.read_text()) if cands_path.exists() else []
                units = ((doc or {}).get("semantic") or {}).get("units") or []
                unit_id = _facts_mod.entry_unit_id((cands[0] if cands else {}).get("entry_contract"), units)
                onchain = await _facts_mod.onchain_facts(RpcClient(rpc_url), cs["address"], int(cs["block"]),
                                                         doc, unit_id)
                facts.extend(onchain)
                added = len(onchain)
                _facts_mod.write_facts(self._pin_root, job_id, facts)
        flags = _map_step.load_flags(self._pin_root, job_id) or []
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.complete_step(step_id, "done", provenance={"onchain_facts": added})
                await repo.transition(job_id, "ready")
                drafts = await repo.create_server_drafts(job_id, "evm", server_draft_flags(flags))
        logger.info("job %s ready (onchain facts %d, server drafts %d)", job_id[-8:], added, drafts)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _job_dir(self, job_id: str) -> Path:
        """Return the per-job working directory: <pin_root>/../work/<job_id>."""
        return self._pin_root.parent / "work" / job_id

    async def _get_job(self, job_id: str) -> dict[str, Any] | None:
        async with self._pool.connection() as conn:
            return await JobRepo(conn).get(job_id)

    async def _mark_step(
        self,
        step_id: int,
        status: str,
        *,
        error_code: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> None:
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            await repo.complete_step(step_id, status, error_code=error_code, provenance=provenance)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _load_build_result(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


_SOLC_OUTPUT_COPY = "solc_output.json"
_MAX_SOLC_OUTPUT_BYTES = 512 * 1024 * 1024


def _snapshot_solc_output(out_dir: Path, work_dir: str | None) -> str | None:
    """Copy work/out/output.json into the job dir (never mounted) and return its sha256.

    Read without following links (the container owned work/); a missing or unsafe output gives
    None, so later steps treat the build as having no solc output.
    """
    if not work_dir:
        return None
    try:
        files = read_output_files(Path(work_dir) / "out", "output.json", 1, _MAX_SOLC_OUTPUT_BYTES)
    except (FileNotFoundError, UnsafeOutput) as exc:
        logger.warning("solc output for %s not copied: %s", out_dir.name, exc)
        return None
    data = files.get("output.json")
    if data is None:
        return None
    (out_dir / _SOLC_OUTPUT_COPY).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _solc_output_copy(out_dir: Path, result: dict[str, Any]) -> Path | None:
    """The job-dir copy of the solc output, only when it still matches the recorded hash."""
    path = out_dir / _SOLC_OUTPUT_COPY
    expected = result.get("output_sha256")
    if result.get("status") != "ok" or not expected or not path.is_file():
        return None
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        logger.warning("solc output copy for %s does not match the recorded hash", out_dir.name)
        return None
    return path


def _std_input_for_build(out_dir: Path, pinned: dict[str, str]) -> dict[str, Any] | None:
    """The fetched Standard JSON input, only when its sources are exactly the pinned files.

    It keeps the original bytes (CRLF, trailing newline), so the rebuild can be `exact`; any
    other source set would build code that is not the code under review, so the pin wins.
    Allowed differences are CRLF for LF and trailing newlines only: solc ends a line comment at
    LF alone, so a lone CR would make the compiled code differ from the LF text the reviewer
    reads. Only `language: Solidity` with `content`-only sources (SolidityAST compiles `ast`).
    """
    from ..adapters.evm.build import InputSanitizationError, sanitize_std_input

    path = out_dir / "std_input_0.json"
    if not path.exists():
        return None
    std = json.loads(path.read_text()).get("std_json_input")
    try:
        sanitize_std_input(std or {})
    except (InputSanitizationError, AttributeError, TypeError):
        return None
    sources = (std or {}).get("sources") or {}
    if not sources or set(sources) != set(pinned):
        return None
    for key, src in sources.items():
        content = src.get("content")
        lf = content.replace("\r\n", "\n")
        if "\r" in lf or lf.rstrip("\n") != pinned[key].rstrip("\n"):
            return None
    return std


def _build_result_from_disk(out_dir: Path, result: dict[str, Any]) -> BuildResult | None:
    """Rebuild the BuildResult a restarted build step needs for the 13.1 comparison."""
    cands_path = out_dir / "candidates.json"
    cands = json.loads(cands_path.read_text()) if cands_path.exists() else []
    if not cands:
        return None
    raw = cands[0]
    comp = raw.get("compiler")
    candidate = Candidate(
        provider=raw["provider"],
        files={},
        sha256=raw["sha256"],
        language=raw["language"],
        compiler=Compiler(version=comp["version"], version_pinned_by=comp["version_pinned_by"]) if comp else None,
        settings=raw.get("settings", {}),
        std_json_input=_std_input_meta(out_dir) if result.get("std_json") else None,
        entry_contract=raw.get("entry_contract"),
        explorer_verified=raw.get("explorer_verified", False),
        sourcify_match=raw.get("sourcify_match"),
        untrusted_inputs=raw.get("untrusted_inputs", False),
    )
    artifacts = []
    work_dir = result.get("work_dir")
    copy = _solc_output_copy(out_dir, result)
    if copy is not None:
        artifacts = _build_mod._parse_artifacts(json.loads(copy.read_bytes()))
    return BuildResult(
        candidate=candidate,
        status="ok" if result.get("status") == "ok" and artifacts else "failed",
        artifacts=artifacts,
        auxdata_ranges={k: [tuple(r) for r in v] for k, v in (result.get("auxdata_ranges") or {}).items()},
        reason=result.get("reason") if result.get("status") != "ok" else (None if artifacts else "build_failed"),
        work_dir=work_dir,
    )


def _std_input_meta(out_dir: Path) -> dict[str, Any] | None:
    path = out_dir / "std_input_0.json"
    return json.loads(path.read_text()).get("std_json_input") if path.exists() else None
