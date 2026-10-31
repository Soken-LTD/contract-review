"""Supervisor loop: claim and run job steps for the EVM pipeline (plan-v4 09 3.1–3.6).

Step order for EVM deployed-address jobs (09 3.1, 03 3.1):
  chain_state (seq=0) -> fetch -> build -> analyze -> map -> chain_state (seq=1) -> ready;
  after finalize: render (08 3.2)

`map` builds map.v1 (lexical layer always, semantic layer when the build succeeded), the J1 to J5
flags and the static facts (04 2.1, 6.3, 12); `chain_state 1` reads the on-chain facts at the
pinned block; the transition to `ready` creates one server draft per J2 or J4 flag (04 12).

`context` (context ingestion spec 3) fetches the project's documents into the context store and
writes the context facts; it is queued when the job reaches `ready` (and by review_add_context
afterwards) so it never gates the interactive state.

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
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg_pool

from ..adapters.base import BuildResult, Candidate, Compiler
from ..adapters.evm import analyze as _analyze_mod
from ..adapters.evm import build as _build_mod
from ..adapters.evm import build_scope as _build_scope
from ..adapters.evm import fetch as _fetch_mod
from ..adapters.evm import files as _files_mod
from ..adapters.evm import solc_select as _solc_select
from ..adapters.evm.repo_candidate import repo_candidate_from_manifest, safe_read_repo_tree
from ..adapters.evm.rpc import RpcAllEndpointsFailed, RpcClientPool
from ..adapters.tron import analyze as _tron_analyze_mod
from ..adapters.tron import build as _tron_build_mod
from ..db.job_repo import JobRepo
from ..db.leads_repo import persist_leads_from_pin
from ..engine.injection import server_draft_flags
from ..engine.provenance import DepResult, evm_deployment_check, resolve_provenance
from ..errors import ReviewError
from ..mapping import facts as _facts_mod
from ..mapping import step as _map_step
from ..pinning.store import PinnedSource
from ..report import render as _render_mod
from ..sandbox.output import UnsafeOutput, read_output_files
from ..sandbox.profile import HostCapacityError, configure_host_capacity
from ..tools.git_probe import _SHA1_RE as _COMMIT_SHA1_RE
from ..tools.git_probe import resolve_ref as _resolve_ref
from . import move_steps as _move
from . import solana_steps as _solana_steps
from . import ton_pipeline

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# npm package name validation (security: prevent prompt injection via import paths)
# ---------------------------------------------------------------------------
# Strict subset of valid npm package names (npmjs.com/package/validate-npm-package-name).
# Scoped: @scope/name; unscoped: name.
# Chars: lowercase a-z, 0-9, hyphen, tilde, dot, underscore; max 214 chars total.
_NPM_PKG_RE = re.compile(
    r"^(?:@[a-z0-9~\-][a-z0-9._~\-]*/)?[a-z0-9~\-][a-z0-9._~\-]*$"
)
_NPM_PKG_MAX_LEN = 214
_MISSING_IMPORT_MAX_PKGS = 10

# Dependency-path first-segment validator: alphanumeric + safe punctuation, max 128 chars.
# Covers Foundry dir names (lib, test, src, forge-std, ...) and @scope-prefix segments.
# x-text-class: same invariant as npm names — user data from repo import strings.
_DEP_SEG_RE = re.compile(r"^[A-Za-z0-9._@~\-]{1,128}$")


def _dependency_error_detail(res: Any) -> dict[str, Any]:
    """error_detail for E_DEPENDENCY_UNRESOLVED. x-text-class: it reaches the client, so it holds
    only validated npm package names, enum reasons and the lockfile name from a fixed set; no
    version, range, URL or other lockfile / package.json text ever goes in."""
    rows = [f.as_dict() for f in res.fatal][:_MISSING_IMPORT_MAX_PKGS]
    rows = [r for r in rows if r["name"] != "<invalid>" and _validate_npm_pkg(r["name"])]
    lockfile = res.lockfile if res.lockfile in ("package-lock.json", "npm-shrinkwrap.json",
                                                 "yarn.lock", "pnpm-lock.yaml") else None
    return {
        "stage": "dependencies",
        "lockfile": lockfile,
        "missing": rows,
        "packages": ", ".join(r["name"] for r in rows) or "unnamed packages",
    }


def _validate_npm_pkg(name: str) -> bool:
    """Return True if *name* is a valid npm package name (strict subset)."""
    return len(name) <= _NPM_PKG_MAX_LEN and bool(_NPM_PKG_RE.match(name))


def _validate_dep_seg(seg: str) -> bool:
    """Return True if *seg* is a safe path-first-segment (x-text-class: user data)."""
    return bool(_DEP_SEG_RE.fullmatch(seg))


# ---------------------------------------------------------------------------
# Retry policy (plan 09 section 3.6)
# ---------------------------------------------------------------------------
# Backoff delays (seconds) before attempt N+1.  Index 0 = before attempt 2,
# index 1 = before attempt 3, etc.  Matches "3 (10 s, 40 s)" from the plan.
_TRANSIENT_BACKOFF: tuple[float, ...] = (10.0, 40.0)


def _transient_backoff(attempt: int) -> float:
    """Return the delay (s) to wait before the next attempt (09 3.6: 10 s, 40 s)."""
    idx = max(0, attempt - 1)
    if idx < len(_TRANSIENT_BACKOFF):
        return _TRANSIENT_BACKOFF[idx]
    return _TRANSIENT_BACKOFF[-1]


# Max size for supervisor-written JSON metadata files (chain_state.json, build_result.json,
# candidates.json).  These files are never container-mounted, but we use O_NOFOLLOW + a size cap
# for defense in depth (09 3.5 principle applied to all supervisor file reads).
_MAX_SUPERVISOR_JSON_BYTES = 1 * 1024 * 1024  # 1 MiB


def _read_json_nofollow(path: Path, max_bytes: int = _MAX_SUPERVISOR_JSON_BYTES) -> Any:
    """Read a supervisor-written JSON file with O_NOFOLLOW and a size cap.

    Raises OSError (including from a symlink) or ValueError (oversize); neither is silently
    swallowed — the caller's except chain marks the step failed.
    """
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_size > max_bytes:
            raise ValueError(f"{path.name}: {st.st_size} bytes over the {max_bytes}-byte cap")
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise ValueError(f"{path.name}: over the {max_bytes}-byte cap")
    return json.loads(data)


_TRON_CHAIN_ID = 728126428      # chains.json: the TRON mainnet record (family tron, address_format tron_base58)


async def _tron_chain_state(display_address: str, runtime_hex: str) -> dict[str, Any]:
    """chain_state.json of a TRON deployed-address job, written at fetch from the runtime the TRON
    fetcher read (05 4.2, F25/F26): the EVM comparison needs `chain_id` (registry family), the
    runtime and, for a library unit, the 20-byte self address. The block is the TronGrid head at the
    time of the read when it answers, else None (TronGrid reads are not block-pinned)."""
    from ..adapters.tron.address import TronAddressError, b58_to_hex
    from ..adapters.tron.rpc import TronGridClient

    self_address: str | None = None
    try:
        internal = b58_to_hex(display_address) if display_address.startswith("T") else display_address
        internal = internal.lower().removeprefix("0x")
        internal = internal[2:] if len(internal) == 42 and internal.startswith("41") else internal
        self_address = "0x" + internal if len(internal) == 40 else None
    except (TronAddressError, ValueError):
        self_address = None
    block: int | None = None
    try:
        block = int(await TronGridClient().eth_block_number())
    except Exception as exc:  # noqa: BLE001 - the block is a label, never a gate
        logger.info("tron chain_state: block number unavailable (%s)", type(exc).__name__)
    return {"chain_id": _TRON_CHAIN_ID, "address": display_address, "self_address": self_address,
            "bytecode": "0x" + runtime_hex.removeprefix("0x"), "block": block}


def _rpc_urls(chain_id: int) -> list[str]:
    """Return the ordered list of usable RPC URLs for *chain_id* (05 4.1, failover).

    A single ``SOKEN_RPC_<chain_id>`` env override always wins and is returned alone.
    Otherwise all non-disabled endpoints from chains.json are returned in registry order.
    """
    override = os.environ.get(f"SOKEN_RPC_{chain_id}")
    if override:
        return [override]
    from ..adapters.evm.registry import get_chain

    chain = get_chain(chain_id)
    if not chain or not chain.rpc:
        return []
    return [r.url for r in chain.rpc if not r.disabled]


def _rpc_url(chain_id: int) -> str | None:
    """Legacy single-URL helper; returns the first usable URL or None."""
    urls = _rpc_urls(chain_id)
    return urls[0] if urls else None


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
        # Physical memory, measured once here and recorded in worker_hosts.ram_mb_total; the
        # container admission (sandbox.profile) refuses a step above min(physical * 0.9, budget).
        # The claim budget stays `total_ram_mb`: a budget clamped to a small host would leave an
        # 8 GiB step queued forever with nothing recorded, the admission fails it with a reason.
        self._host_capacity = configure_host_capacity(total_ram_mb)
        self._running: dict[int, asyncio.Task] = {}  # step_id -> task
        # Dedicated executor for Move steps (Sui / Aptos): prevents them from exhausting the
        # default thread pool shared with lightweight steps (09 UV9-8).
        self._move_executor: ThreadPoolExecutor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="move-step"
        )

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main loop: seed new jobs, claim and run steps, heartbeat (09 3.3)."""
        hb_task = asyncio.create_task(self._heartbeat_loop())
        try:
            # Solana jobs built before the provenance step (2026-10-26) have no tier; set it once
            # from their job directories so finalize check F1 can close without a new job.
            await _solana_steps.backfill_tiers(self)
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
            self._move_executor.shutdown(wait=False)

    # ------------------------------------------------------------------
    # Heartbeat (09 3.3: 15 s)
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                async with self._pool.connection() as conn:
                    # ram_mb_total is the host's physical memory (measured at start), not the
                    # configured budget; a host that was resized reports the new value.
                    await conn.execute(
                        """
                        insert into worker_hosts (name, units_total, ram_mb_total, last_seen)
                        values (%s, %s, %s, now())
                        on conflict (name) do update set last_seen = now(),
                            units_total = excluded.units_total, ram_mb_total = excluded.ram_mb_total
                        """,
                        (self._host, self._total_units, self._host_capacity.recorded_mb),
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
            if job is not None and job.get("state") == "deleted":
                # review_delete_job cancelled the queued rows; a row claimed in the same instant
                # ends here, before any family runner writes to the job's directories.
                logger.info("step %s/%s job %s: job deleted, step cancelled", step_name, step["seq"], job_id[-8:])
                await self._mark_step(step_id, "cancelled")
                return
            if step_name == "context":
                # Project documents (context ingestion spec 3): family-independent, runs at `ready`
                # and never gates it; failures are per document.
                await self._run_context(step)
            elif step_name == "verify_fork":
                # review_verify_on_fork: family-independent, runs at `ready`, never gates the job; a
                # run failure is the run's result (fork_runs), the step itself ends done.
                from ..sandbox import fork_verify

                await fork_verify.run_step(self._pool, self._pin_root, step)
            elif step_name == "render":
                # Bug 1 fix (2026-10-25): render is family-agnostic and must run the generic handler
                # regardless of chain.  Previously this check appeared AFTER the family-dispatch
                # branches, so TON / Solana / Move / Starknet jobs logged "no handler for step
                # render; marking done" and stayed in render_queued forever.
                await _render_mod.run_render_step(self._pool, step, self._pin_root)
            elif job is not None and ton_pipeline.is_ton_job(job):
                await ton_pipeline.run_step(self, step, job)
            elif job is not None and job.get("chain") == "starknet" and (
                (step_name == "chain_state" and step["seq"] == 0) or step_name in ("fetch", "build", "analyze", "map")
            ):
                # Starknet family (plan-v4 07): own runners for its steps; render etc. stay generic.
                from . import starknet_steps

                await starknet_steps.run_step(self, step, job)
            elif job is not None and _move.job_chain(job) is not None:
                await self._run_move_step(step, job)
            elif job is not None and _solana_steps.is_solana_job(job):
                # Solana (06): own runners for every step. Without this branch a Solana job falls
                # through to the EVM handlers below and orphans in `analyzing`.
                await _solana_steps.run_step(self, step, job)
            elif step_name == "chain_state" and step["seq"] == 0:
                await self._run_chain_state_0(step)
            elif step_name == "fetch":
                await self._run_fetch(step)
            elif step_name == "build":
                await self._run_build(step)
            elif step_name == "analyze":
                await self._run_analyze(step)
            elif step_name == "map":
                await self._run_map(step)
            elif step_name == "chain_state" and step["seq"] == 1:
                await self._run_chain_state_1(step)
            else:
                logger.warning("no handler for step %s; marking done", step_name)
                await self._mark_step(step_id, "done")
            if step_name not in ("context", "verify_fork"):
                await self._maybe_queue_context(job_id)
        except RpcAllEndpointsFailed:
            # All RPC endpoints failed — transient; retry up to max_attempts (09 3.6).
            attempt = step.get("attempt", 1)
            max_attempts = step.get("max_attempts", 1)
            if attempt < max_attempts:
                backoff = _transient_backoff(attempt)
                logger.warning(
                    "step %s/%s job %s: all RPC endpoints failed (attempt %d/%d); retry in %.0fs",
                    step_name, step["seq"], job_id[-8:], attempt, max_attempts, backoff,
                )
                async with self._pool.connection() as conn:
                    await JobRepo(conn).retry_step(step_id, backoff)
            else:
                logger.error(
                    "step %s/%s job %s: all RPC endpoints failed, attempt %d/%d exhausted → terminal",
                    step_name, step["seq"], job_id[-8:], attempt, max_attempts,
                )
                async with self._pool.connection() as conn:
                    repo = JobRepo(conn)
                    async with conn.transaction():
                        await repo.complete_step(step_id, "done", error_code="E_INTERNAL")
                        await _fail_job(repo, job_id, "E_INTERNAL", {"stage": step_name, "reason": "rpc_all_endpoints_failed"})
        except HostCapacityError as exc:
            # The sandbox refused a container limit this host cannot honour (no OOM kill, nothing
            # ran). Not transient on this host: the job fails with the numbers, never E_INTERNAL.
            logger.error("step %s/%s job %s refused: %s", step_name, step["seq"], job_id[-8:], exc.reason)
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.complete_step(step_id, "failed", error_code="E_HOST_CAPACITY")
                    await _fail_job(repo, job_id, "E_HOST_CAPACITY", exc.detail())
        except Exception:
            logger.exception("step %s/%s failed for job %s", step_name, step["seq"], job_id[-8:])
            if step_name in ("render", "context", "verify_fork"):
                # Non-gating steps: mark the step failed but leave the job state unchanged.
                await self._mark_step(step_id, "failed", error_code="E_INTERNAL")
            else:
                # Any other step failure → fail the job so it never gets stuck in a
                # non-terminal state with no runnable steps (e.g. map raises FileNotFoundError
                # when TRON fetch wrote no pin; job_state stays `analyzing` forever).
                try:
                    async with self._pool.connection() as conn:
                        repo = JobRepo(conn)
                        async with conn.transaction():
                            await repo.complete_step(step_id, "failed", error_code="E_INTERNAL")
                            await _fail_job(
                                repo, job_id, "E_INTERNAL",
                                {"stage": step_name, "reason": "unexpected_exception"},
                            )
                except Exception:
                    logger.exception(
                        "double fault on job %s step %s; falling back to mark-only",
                        job_id[-8:], step_name,
                    )
        finally:
            self._free_units += step["units"]
            self._free_ram_mb += step["ram_mb"]
            elapsed = time.monotonic() - t0
            logger.info("step %s/%s finished in %.1fs", step_name, step["seq"], elapsed)

    # ------------------------------------------------------------------
    # Sui and Aptos (07 4): same states and step rows, Move runners in worker/move_steps.py
    # ------------------------------------------------------------------

    async def _run_move_step(self, step: dict[str, Any], job: dict[str, Any]) -> None:
        name, job_id, step_id = step["step"], step["job_id"], step["id"]
        out_dir = self._job_dir(job_id)
        out_dir.mkdir(parents=True, exist_ok=True)
        loop = asyncio.get_event_loop()

        async def terminal_no_source() -> None:
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.complete_step(step_id, "done")
                    current = await repo.get(job_id)
                    if current and current["state"] == "queued":
                        # 03 state machine: queued -> fetching -> insufficient_source
                        await repo.transition(job_id, "fetching")
                    await repo.transition(job_id, "insufficient_source", error_code="E_SOURCE_NOT_FOUND")

        if name == "chain_state":
            if not (out_dir / "chain_state.json").exists():
                state = await loop.run_in_executor(self._move_executor, lambda: _move.chain_state(job, out_dir))
                if state == "no_package":
                    await terminal_no_source()
                    return
            await self._mark_step(step_id, "done")
            await self._after_chain_state(step, job)
        elif name == "fetch":
            if not (out_dir / "candidates.json").exists():
                got = await loop.run_in_executor(self._move_executor, lambda: _move.fetch(job, out_dir, self._pin_root))
                if got is None:
                    await terminal_no_source()
                    return
                async with self._pool.connection() as conn:
                    await JobRepo(conn).update_job_fields(job_id, source_pin=got["source_pin"])
                await self._mark_step(step_id, "done", provenance={"provider": got["provider"], "sha256": got["sha256"]})
            else:
                await self._mark_step(step_id, "done")
            await self._after_fetch(step, job)
        elif name == "build":
            path = out_dir / "build_result.json"
            result = _load_build_result(path) if path.exists() else await loop.run_in_executor(
                self._move_executor, lambda: _move.build(job, out_dir, self._pin_root))
            # Supervisor-written provenance (dep.match per 07 9.1) is recorded on the step row.
            await self._mark_step(step_id, "done", provenance=result.get("provenance"))
            await self._after_build(step, result)
        elif name == "analyze":
            leads_out = self._pin_root / job_id / "leads.json"
            degraded = False
            if not leads_out.exists():
                # Timeout is enforced at sandbox level (sandbox.run kills the container via
                # docker rm -f on TimeoutExpired).  The step deadline is computed in
                # move_steps.analyze and passed down to each analyzer container.
                leads, degraded = await loop.run_in_executor(
                    self._move_executor, lambda: _move.analyze(job, out_dir, self._pin_root)
                )
                leads_out.parent.mkdir(parents=True, exist_ok=True)
                leads_out.write_text(json.dumps(leads, indent=2), encoding="utf-8")
            await self._mark_step(step_id, "done")
            await self._after_analyze(step, degraded=degraded)
        elif name == "map":
            # Build the lexical map.v1 layer for Move jobs (plan 04: map.v1 always present).
            # Files are supervisor-written and never container-mounted; read with O_NOFOLLOW +
            # size cap for defense in depth (09 3.5 principle applied to supervisor file reads).
            build_path = out_dir / "build_result.json"
            build = _read_json_nofollow(build_path) if build_path.exists() else {"status": "failed"}
            build_ok = build.get("status") == "ok"
            cs_path = out_dir / "chain_state.json"
            chain_state = _read_json_nofollow(cs_path) if cs_path.exists() else None
            cands_path = out_dir / "candidates.json"
            cands = _read_json_nofollow(cands_path) if cands_path.exists() else []
            detail = None if build_ok else (build.get("stderr_head") or build.get("reason"))
            summary = await loop.run_in_executor(self._move_executor, lambda: _map_step.run_map_step(
                self._pin_root, job_id,
                family="move", chain=_move.job_chain(job),
                solc_output_path=None, build_ok=build_ok, job=job,
                chain_state=chain_state, candidate=cands[0] if cands else None,
                nsloc=build.get("nsloc"), analyzers={}, build_detail=detail,
            ))
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.update_job_fields(job_id, map_status=summary["map_status"])
                    await repo.complete_step(step_id, "done", provenance=summary)
                    n_leads = await persist_leads_from_pin(conn, self._pin_root, job_id)
                    await repo.transition(job_id, "ready")
            logger.info("move job %s map %s ready (%d leads persisted)", job_id[-8:], summary.get("map_status"), n_leads)
        else:
            await self._mark_step(step_id, "done")

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

        rpc_urls = _rpc_urls(chain_id)
        if not rpc_urls:
            # Fail closed: an address job without a pinned chain read would review unpinned code
            # with no deployment check (03 3.1: provider fault = failed, internal step error).
            # review_start rejects chains without an RPC (E_CHAIN_DISABLED), so this is reached only
            # when the registry changed under a queued job.
            logger.error("no RPC for chain_id %s; job %s failed", chain_id, job_id[-8:])
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.complete_step(step_id, "done", error_code="E_INTERNAL")
                    await _fail_job(repo, job_id, "E_INTERNAL",
                                    {"stage": "chain_state", "reason": f"no RPC for chain_id {chain_id}"})
            return

        # RpcClientPool tries endpoints in order; raises RpcAllEndpointsFailed if all fail.
        # That exception is caught by _run_step and retried up to max_attempts (09 3.6).
        pool = RpcClientPool(rpc_urls)
        block_num = await pool.block_number()
        # Use block_num - 1 for stability (avoid tip-race)
        pin_block = block_num - 1
        pool_pinned = pool.with_block(pin_block)

        addr_lower = address.lower()
        if not addr_lower.startswith("0x"):
            addr_lower = "0x" + addr_lower

        bytecode = await pool_pinned.get_code(addr_lower)
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
                              provenance={"block": pin_block, "chain_id": chain_id,
                                          "rpc": pool_pinned.answered_by or pool.answered_by})
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
            # Inline Solidity files (03 4.1): the requester's files are the only candidate; the
            # compiler from compiler_version, a pasted config pin or the pragmas, and the
            # review_start remappings as solc settings (adapters/evm/files.py).
            cand = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _files_mod.files_candidate(
                    source_args.get("files") or [],
                    remappings=[r for r in (source_args.get("remappings") or []) if isinstance(r, str)],
                    compiler_version=source_args.get("compiler_version") or None)
            )
            candidates = [cand] if cand is not None else []
        elif job.get("source_kind") == "repo":
            # Repo source (05 4.2 step 6, 09 5.2): materialize via soken-fetch sandbox,
            # then build a repo Candidate from the manifest + files.
            candidates = await self._fetch_repo(step, job, out_dir, source_args,
                                                 chain_id, address, bytecode)
            if candidates is None:
                # Already handled terminal/transient outcome; return immediately.
                return
        elif job.get("chain") == "tron":
            # TRON deployed-address job: TronScan + Sourcify (05 4.2 TRON, UV5-02).
            # TRON addresses are base58check (T...) with no EVM chain RPC; the EVM fetch path
            # would write empty candidates and transition to building (via _after_fetch), leaving
            # the map step with no pin.  Always call the TRON-specific fetcher so a verified
            # source is pinned, or the job ends insufficient_source.
            from ..adapters.tron.fetch import fetch_source_tron

            tron_addr = address or ""
            if tron_addr:
                _tron_cands, _runtime_hex, _creation_hex = await fetch_source_tron(tron_addr)
                candidates = _tron_cands
                if _runtime_hex and not cs_path.exists():
                    # TRON jobs carry no EVM chain id, so chain_state 0 reads nothing and the build
                    # compared the rebuild with no runtime: every TRON job was tier B "not checked"
                    # (CRS Token, 2026-10-26). The runtime TronScan/TronGrid returned here is the
                    # pinned deployment; the registry id lets _resolve_provenance pick the family.
                    cs_path.write_text(json.dumps(await _tron_chain_state(tron_addr, _runtime_hex)), encoding="utf-8")
            else:
                candidates = []
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
            # Repo mode also pins the dependency files the scope imports (node_modules/, lib/), out
            # of scope with role `dependency`: readable and searchable with review_read_code and
            # review_search_code, never a location, never in the map or the nSLOC (1inch run
            # 2026-10-27: the ERC20Pods gas stipend behind L-003 could not be quoted).
            deps = _dependency_closure(best)
            pin = PinnedSource.from_files(
                {path: content.encode("utf-8") for path, content in {**deps, **best.files}.items()},
                langs={path: best.language for path in [*deps, *best.files]},
                in_scope={path: False for path in deps},
                roles={path: "dependency" for path in deps},
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
                # test and mock files the scope rules left out (report: out of scope, by server)
                "scope_excluded": list(c.scope_excluded or []),
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

        fetch_prov: dict[str, Any] = {"provider": best.provider, "sha256": best.sha256}
        if best.scope_excluded:
            # files the scope rules kept out of the review (review_status.scope_excluded)
            fetch_prov["scope_excluded"] = {"count": len(best.scope_excluded),
                                            "files": list(best.scope_excluded[:200])}
        deps_path = out_dir / "dependencies.json"
        if best.provider == "repo" and deps_path.is_file() and not deps_path.is_symlink():
            # Host-written summary of vendored npm packages (_resolve_npm_deps); review_status shows it.
            fetch_prov["dependencies"] = json.loads(deps_path.read_text(encoding="utf-8"))
        await self._mark_step(step_id, "done", provenance=fetch_prov)
        await self._after_fetch(step, job)

    async def _fetch_repo(
        self,
        step: dict[str, Any],
        job: dict[str, Any],
        out_dir: Path,
        source_args: dict[str, Any],
        chain_id: int | None,
        address: str | None,
        bytecode: str | None,
    ) -> list[Candidate] | None:
        """Materialise a repo source and return candidates (05 4.2 step 6, 09 5.2).

        Returns a list of candidates (possibly empty → insufficient_source), or None
        when this method has already written the terminal/error outcome to the DB and
        the caller should return immediately.
        """
        from ..sandbox.repo_fetch import materialize_repo

        job_id = job["job_id"]
        step_id = step["id"]
        repo_url: str = source_args.get("repo_url") or ""
        commit: str | None = source_args.get("commit")
        ref: str | None = source_args.get("ref")
        if not repo_url:
            logger.error("repo job %s has no repo_url", job_id[-8:])
            await self._mark_step(step_id, "failed", error_code="E_INTERNAL")
            return None

        # family for egress network: only known chains allowed (fail closed, not silent downgrade).
        # None/empty chain → "evm" default for plain repo-only reviews without an address.
        chain_name: str | None = job.get("chain")
        _KNOWN_REPO_FAMILIES = frozenset({"evm", "hyperevm", "tron"})
        if chain_name and chain_name not in _KNOWN_REPO_FAMILIES:
            await self._mark_step(step_id, "failed", error_code="E_CHAIN_DISABLED")
            logger.info("job %s: unknown chain %r → E_CHAIN_DISABLED", job_id[-8:], chain_name)
            return None
        family: str = chain_name or "evm"

        # Supervisor-side ref resolution (03 §4.1): the supervisor sets `expected_sha` BEFORE
        # calling the sandbox.  The sandbox must return exactly that sha; if it returns anything
        # else (or the manifest is missing/malformed), the job fails with a named error and
        # nothing is written to the DB.
        expected_sha: str | None = None
        if commit:
            if not _COMMIT_SHA1_RE.fullmatch(commit.lower()):
                await self._mark_step(step_id, "failed", error_code="E_COMMIT_NOT_FOUND")
                logger.info("job %s: commit %r is not a valid 40-hex sha", job_id[-8:], commit[:12])
                return None
            expected_sha = commit.lower()
        elif ref:
            try:
                expected_sha = await _resolve_ref(repo_url, ref)
            except ReviewError as exc:
                ec = exc.code if hasattr(exc, "code") else "E_COMMIT_NOT_FOUND"
                await self._mark_step(step_id, "failed", error_code=ec)
                logger.info("job %s: ref resolution failed for %r: %s", job_id[-8:], ref, exc)
                return None
        # If neither commit nor ref, expected_sha remains None (plain HEAD fetch).

        # Run soken-fetch in the sandbox (09 5.2).  This is a blocking operation;
        # offload to a thread so the event loop stays responsive.
        fetch_result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: materialize_repo(repo_url, out_dir / "repo_fetch", family,
                                     commit=expected_sha, ref=None if expected_sha else ref),
        )

        # Validate the manifest's resolved_commit against the supervisor-resolved sha.
        # Only write the SUPERVISOR's sha to the DB — never the sandbox's value directly.
        if fetch_result.ok:
            raw_resolved = fetch_result.manifest.get("resolved_commit") or ""
            manifest_sha = raw_resolved.lower() if isinstance(raw_resolved, str) else ""
            if expected_sha is not None:
                # Strict: manifest must echo back the exact sha we requested.
                if not _COMMIT_SHA1_RE.fullmatch(manifest_sha) or manifest_sha != expected_sha:
                    async with self._pool.connection() as conn:
                        repo = JobRepo(conn)
                        async with conn.transaction():
                            await repo.complete_step(step_id, "done",
                                                     error_code="E_COMMIT_NOT_FOUND")
                            await repo.transition(job_id, "failed",
                                                  error_code="E_COMMIT_NOT_FOUND")
                    logger.warning("job %s: manifest resolved_commit %r != expected %r",
                                   job_id[-8:], manifest_sha[:12], expected_sha[:12])
                    return None
                # Write only the validated supervisor-side sha.
                async with self._pool.connection() as conn:
                    await JobRepo(conn).update_job_fields(job_id, resolved_commit=expected_sha)
            elif _COMMIT_SHA1_RE.fullmatch(manifest_sha):
                # HEAD fetch: use the manifest sha only if it is a valid 40-hex.
                async with self._pool.connection() as conn:
                    await JobRepo(conn).update_job_fields(job_id, resolved_commit=manifest_sha)
                expected_sha = manifest_sha
            else:
                # Malformed manifest — refuse.
                async with self._pool.connection() as conn:
                    repo = JobRepo(conn)
                    async with conn.transaction():
                        await repo.complete_step(step_id, "done",
                                                 error_code="E_COMMIT_NOT_FOUND")
                        await repo.transition(job_id, "failed",
                                              error_code="E_COMMIT_NOT_FOUND")
                logger.warning("job %s: manifest missing valid resolved_commit", job_id[-8:])
                return None
            # Validate file-count (int) and sub-list before using.
            _manifest_files = fetch_result.manifest.get("files")
            _file_count = len(_manifest_files) if isinstance(_manifest_files, list) else 0
            logger.info("job %s: repo fetched, commit=%s, files=%d",
                        job_id[-8:], expected_sha[:12], _file_count)

        if not fetch_result.ok:
            # Map exit codes to job outcomes (09 3.6).
            # Transient (exit 20): retry up to max_attempts with backoff (10 s, 40 s).
            # Non-retryable (exit 21/22/23/24/25/26): terminal at once.
            attempt = step.get("attempt", 1)
            max_attempts = step.get("max_attempts", 3)
            if fetch_result.retryable and attempt < max_attempts:
                backoff = _transient_backoff(attempt)
                logger.warning(
                    "job %s: repo fetch transient (%s), attempt %d/%d; retry in %.0fs",
                    job_id[-8:], fetch_result.error_code, attempt, max_attempts, backoff,
                )
                async with self._pool.connection() as conn:
                    await JobRepo(conn).retry_step(step_id, backoff)
            else:
                # Non-retryable or exhausted retries: terminal failed
                async with self._pool.connection() as conn:
                    repo = JobRepo(conn)
                    async with conn.transaction():
                        await repo.complete_step(step_id, "done",
                                                 error_code=fetch_result.error_code)
                        # Persist WHY (exit code, kill reason, stderr tail) — a bare error code
                        # left a missing egress network undiagnosable (2026-10-22).
                        await repo.transition(job_id, "failed",
                                              error_code=fetch_result.error_code,
                                              error_detail={
                                                  "stage": "repo_fetch",
                                                  "exit_code": fetch_result.exit_code,
                                                  "killed_by": fetch_result.killed_by,
                                                  "stderr_tail": fetch_result.stderr_tail[:2048],
                                              })
                logger.warning("job %s: repo fetch failed (%s, exit %s, killed_by=%s): %s",
                               job_id[-8:], fetch_result.error_code, fetch_result.exit_code,
                               fetch_result.killed_by, fetch_result.stderr_tail[-400:] or "<no stderr>")
            return None

        # Get the explorer candidate for this address (if any) for compiler/settings (13.3)
        explorer_candidate: Candidate | None = None
        if chain_id and address and bytecode:
            try:
                cands = await _fetch_mod.fetch_source(chain_id=chain_id, address=address,
                                                      runtime_bytecode=bytecode)
                if cands and cands[0] is not None:
                    explorer_candidate = cands[0]
                    logger.debug("job %s: explorer candidate provider=%s", job_id[-8:],
                                 explorer_candidate.provider)
            except Exception:
                logger.debug("job %s: explorer lookup failed (non-fatal)", job_id[-8:],
                             exc_info=True)

        # review_start `source.chain` in repo mode (no deployment): a non-EVM chain skips the
        # Solidity candidate and hands this step to that family's runner (Hipo FunC repo, blind run
        # 2026-10-27: repo mode assumed Solidity and the start had no way to say otherwise).
        from ..adapters.repo_detect import FAMILY_OF_HINT

        hint = FAMILY_OF_HINT.get(str(source_args.get("chain") or "").lower())
        if hint and hint != "evm" and not chain_name and not address:
            detail = {"stage": "repo_candidate", "detail": "chain_hint", "chain": hint}
            if await self._hand_repo_to_family(step, job, source_args, fetch_result.src_dir,
                                               expected_sha, detail, family=hint):
                return None
            await self._repo_no_source(step_id, job_id, detail)
            return None

        # npm packages the sources import (Hardhat, Foundry with node_modules): vendored into the
        # tree, lockfile-pinned and sha512-checked, before the candidate is read (npm_deps).
        npm = await self._resolve_npm_deps(step, job, out_dir, fetch_result.src_dir)
        if npm is False:
            return None
        extra_remappings = list(npm.get("remappings") or []) if isinstance(npm, dict) else []

        # Build the repo Candidate from the manifest + files.
        # Pass repo_url@sha as source_url so provenance carries a real reference (not None).
        _source_url = f"{repo_url}@{expected_sha}" if expected_sha else repo_url
        cand, reason = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: repo_candidate_from_manifest(
                fetch_result.src_dir,
                fetch_result.manifest,
                explorer_candidate=explorer_candidate,
                source_url=_source_url,
                extra_remappings=extra_remappings,
            ),
        )

        if cand is None:
            detail: dict[str, Any] = {"stage": "repo_candidate", "detail": reason}
            if reason == "no_solidity_sources" and not chain_name and not address and hint != "evm":
                # A repo-only job reaches this path with no chain. A Scarb, Move, Solana or TON
                # tree is not an EVM failure: hand the same fetch step to its family runner
                # (adapters/repo_detect). Undetectable trees keep the reason in error_detail.
                handed = await self._hand_repo_to_family(step, job, source_args, fetch_result.src_dir,
                                                         expected_sha, detail)
                if handed:
                    return None
            # npm-only, no sources, etc. → insufficient_source (09 3.6)
            await self._repo_no_source(step_id, job_id, detail)
            return None

        candidates = [cand]

        # When an explorer candidate also exists, append it (R1/B4: reviewed=repo, settings=explorer)
        if explorer_candidate is not None and explorer_candidate.sha256 != cand.sha256:
            candidates.append(explorer_candidate)

        return candidates

    async def _resolve_npm_deps(self, step: dict[str, Any], job: dict[str, Any], out_dir: Path,
                                src_dir: Path) -> dict[str, Any] | None | bool:
        """Vendor the npm packages the repo imports (adapters/evm/npm_deps.py).

        Returns the dependency summary (also written to out_dir/dependencies.json for the fetch
        step provenance), None when the repo needs no npm package, or False when a dependency
        could not be resolved: the job is then already terminal (insufficient_source,
        E_DEPENDENCY_UNRESOLVED, detail names each package and why).
        """
        from ..adapters.evm import npm_deps as _npm
        from ..adapters.evm.repo_candidate import (
            _extract_settings,
            _read_foundry_toml,
            _read_remappings_txt,
            _select_scope_files,
        )
        from ..sandbox.npm_fetch import run_npm_fetch

        job_id = job["job_id"]
        npm_dir = out_dir / "npm_fetch"
        runs = [0]

        def fetch(requests: list[dict]) -> Any:
            runs[0] += 1
            return run_npm_fetch(requests, npm_dir / f"run{runs[0]}")

        def work() -> _npm.NpmResolution | None:
            tree, _refused = safe_read_repo_tree(src_dir)
            cfg = _read_foundry_toml(tree)
            remaps = list(_extract_settings(cfg, _read_remappings_txt(tree)).get("remappings") or [])
            scope = _select_scope_files(tree, cfg)
            return _npm.resolve_npm_deps(str(src_dir), tree, scope, remaps, fetch)

        res = await asyncio.get_event_loop().run_in_executor(None, work)
        if res is None:
            return None
        summary = res.summary()
        (out_dir / "dependencies.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        fatal = res.fatal
        logger.info("job %s: npm deps lockfile=%s vendored=%d unresolved=%d not_declared=%d",
                    job_id[-8:], res.lockfile, len(res.packages), len(fatal), len(res.not_declared))
        if not fatal:
            return summary
        detail = _dependency_error_detail(res)
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.complete_step(step["id"], "done", error_code="E_DEPENDENCY_UNRESOLVED")
                await repo.transition(job_id, "insufficient_source",
                                      error_code="E_DEPENDENCY_UNRESOLVED", error_detail=detail)
        return False

    async def _repo_no_source(self, step_id: int, job_id: str, detail: dict[str, Any]) -> None:
        """Repo mode found nothing it reviews: insufficient_source with the reason in error_detail
        (review_status turns it into a fix that names a different input: errors.yaml fix_repo)."""
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.complete_step(step_id, "done", error_code="E_SOURCE_NOT_FOUND")
                await repo.transition(job_id, "insufficient_source",
                                      error_code="E_SOURCE_NOT_FOUND", error_detail=detail)
        logger.info("job %s: repo insufficient_source reason=%s", job_id[-8:], detail)

    async def _hand_repo_to_family(self, step: dict[str, Any], job: dict[str, Any],
                                   source_args: dict[str, Any], src_dir: Path,
                                   resolved_sha: str | None, detail: dict[str, Any],
                                   family: str | None = None) -> bool:
        """Non-EVM repo mode (road-to-prod item 4): a Scarb.toml tree runs the Starknet fetch, a
        Move.toml tree the Sui/Aptos fetch, a Solana crate the Solana fetch and a FunC / Tact /
        Tolk tree the TON fetch, on this same step. `family` (review_start `source.chain`) runs
        that family's rule only. The chain is persisted first so every later step of the job
        routes to that family (`_run_step`). Returns False, with the reason added to `detail`, when
        the tree is not recognised; the caller then ends the job."""
        from ..adapters.repo_detect import RepoFamily, detect_repo_family

        job_id = job["job_id"]
        files, _refused = await asyncio.get_event_loop().run_in_executor(
            None, lambda: safe_read_repo_tree(src_dir))
        found = detect_repo_family(files, source_args.get("subdir"), family=family)
        if isinstance(found, RepoFamily) and found.chain == "evm":
            # Solidity or Vyper files the EVM candidate did not take (no compilable scope): the
            # family is known, the job still ends here with that reason.
            detail["repo_family"] = "evm"
            return False
        if not isinstance(found, RepoFamily):
            detail["repo_family"] = found.reason
            if found.manifests:
                detail["manifests"] = list(found.manifests[:10])
            return False
        from ..families import enabled_chains, family_disabled

        if family_disabled(chain=found.chain):
            # Launch switch (SOKEN_DISABLED_FAMILIES): the tree is a family this deployment does not
            # review; the job ends with the same code review_start gives a deployed source.
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.complete_step(step["id"], "done", error_code="E_CHAIN_DISABLED")
                    await repo.transition(job_id, "failed", error_code="E_CHAIN_DISABLED",
                                          error_detail={"stage": "repo_family", "repo_family": found.chain,
                                                        "enabled": enabled_chains()})
            logger.info("job %s: repo is %s, family disabled", job_id[-8:], found.chain)
            return True
        async with self._pool.connection() as conn:
            await JobRepo(conn).update_job_fields(job_id, chain=found.chain)
        args = dict(source_args)
        if not (args.get("subdir") or "").strip("/") and found.package_dir:
            args["subdir"] = found.package_dir
        if resolved_sha:
            args["commit"] = resolved_sha          # the family fetch pins what this fetch resolved
        handed = dict(job)
        handed.update(chain=found.chain, source_args=args, resolved_commit=resolved_sha or job.get("resolved_commit"))
        logger.info("job %s: repo is %s (%s), handing the fetch step to the %s runner",
                    job_id[-8:], found.chain, found.manifest, found.chain)
        if found.chain == "starknet":
            from . import starknet_steps

            await starknet_steps.run_step(self, step, handed)
        elif found.chain == "ton":
            # chain_state 0 ran on the EVM path and wrote nothing: a repo-only TON unit has no
            # account to read (ton_pipeline reads the empty document and reviews the repo, tier B).
            cs_path = self._job_dir(job_id) / "chain_state.json"
            if not cs_path.exists():
                cs_path.parent.mkdir(parents=True, exist_ok=True)
                cs_path.write_text(json.dumps({"mc_seqno": None, "accounts": {}}), encoding="utf-8")
            handed["_repo_src_dir"] = str(src_dir)     # the tree this fetch materialised (any host)
            await ton_pipeline.run_step(self, step, handed)
        elif found.chain == "solana":
            await _solana_steps.run_step(self, step, handed)
        else:
            await self._run_move_step(step, handed)
        return True

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
            # the reviewed sources only; pinned dependency files (out of scope) reach the build
            # through the import closure of the materialised tree, as before
            files_str = {path: "\n".join(pin.read_all(path)) for path, e in pin.entries.items() if e.in_scope}
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
            # B4 hint: path to the materialised source tree so build() can attempt
            # forge build --offline --build-info before falling back to B3.
            # Repo source is materialized to out_dir/repo_fetch/src by materialize_repo
            # (sandbox/repo_fetch.py: job_dir=out_dir/repo_fetch → src=job_dir/src).
            src_tree_dir=str(out_dir / "repo_fetch" / "src") if cand_raw.get("provider") == "repo" else None,
        )

        # B4 integrity: populate the full O_NOFOLLOW tree map from the materialised source so
        # _forge_sources_match_pin can verify EVERY forge source against the pinned tree, not
        # only scope files (candidate.files).  This re-read is done here in the supervisor,
        # never in build.py, to keep build() pure and the tree-read in one trusted location.
        # On failure to read (empty dir, permissions), _full_tree stays None and
        # _forge_sources_match_pin fails closed (returns "sources_differ").
        if candidate.src_tree_dir:
            try:
                full_tree, _refused = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: safe_read_repo_tree(candidate.src_tree_dir)
                )
                candidate._full_tree = full_tree  # type: ignore[attr-defined]
            except Exception:
                logger.warning("job %s: failed to read full tree for B4 integrity check",
                               job_id[-8:], exc_info=True)

        # Run build (synchronous; offload to thread to avoid blocking the loop). A TRON job
        # compiles with the TRON compiler choice (exact tron-solc, else upstream solc of the same
        # version); the evm build only knows binaries.soliditylang.org version strings and
        # failed every Tronscan field ("tron_0.6.2_Plato_v4.2": compiler_binary_missing).
        work_dir = out_dir / "work"
        work_dir.mkdir(exist_ok=True)
        is_tron = await self._is_tron_job(job_id)
        builder = _tron_build_mod.build_tron if is_tron else _build_mod.build
        build_result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: builder(candidate, work_dir=work_dir)
        )
        attempts = [_build_attempt_row(candidate, build_result)]

        # Parse-error retry (1inch farming 2026-10-27): a ParserError at the chosen version
        # (a stale config pin, an explorer version, or a floor) is tried once more with the
        # newest release that satisfies every pragma of the sources and their imports. Both
        # attempts are recorded; the successful one becomes the job's compiler.
        retry_version = None
        if build_result.status == "failed" and not is_tron and candidate.compiler \
                and _solc_select.is_parse_error(build_result.stderr_head):
            retry_version = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _parse_error_retry_version(candidate))
        if retry_version:
            retry_candidate = dataclasses.replace(
                candidate, compiler=Compiler(version=retry_version, version_pinned_by="pragma"))
            retry_dir = out_dir / "work_retry"
            retry_dir.mkdir(exist_ok=True)
            second = await asyncio.get_event_loop().run_in_executor(
                None, lambda: builder(retry_candidate, work_dir=retry_dir))
            attempts.append(_build_attempt_row(retry_candidate, second))
            logger.info("job %s: parse error at %s, retried with %s: %s", job_id[-8:],
                        candidate.compiler.version, retry_version, second.status)
            if second.status == "ok":
                build_result, candidate = second, retry_candidate
                candidates_raw[0]["compiler"] = {"version": retry_version, "version_pinned_by": "pragma"}
                candidates_raw[0]["compiler_retry"] = {"from": attempts[0]["version"], "reason": "parse_error"}
                candidates_path.write_text(json.dumps(candidates_raw, indent=2), encoding="utf-8")

        # Build scope retry (Lambo.win 2026-10-27): a repo build that still fails is tried with the
        # compilation closure of the deployable entry contracts, then without the files the
        # compiler fails on when nothing reviewed imports them. Every attempt is recorded; a file
        # left out is out of scope in the pin and the report (reason build_excluded).
        if build_result.status == "failed" and not is_tron and candidate.provider == "repo" \
                and _scope_retry_applies(build_result):
            narrowed = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _scope_retries(candidate, builder, out_dir, build_result))
            attempts.extend(narrowed.attempts)
            if narrowed.result is not None:
                build_result, candidate = narrowed.result, narrowed.candidate
                await self._apply_build_scope(job_id, out_dir, candidates_raw, candidates_path,
                                              candidate, narrowed.excluded, attempts[0]["version"])
                build_result = dataclasses.replace(
                    build_result, nsloc=_build_mod._count_nsloc(_reviewed_files(self._pin_root, job_id)))

        result = {
            "status": build_result.status,
            "nsloc": build_result.nsloc,
            "reason": build_result.reason,
            "stderr_head": build_result.stderr_head,
            "attempts": attempts,
            "work_dir": str(build_result.work_dir) if build_result.work_dir else None,
            "auxdata_ranges": {k: [list(r) for r in v] for k, v in build_result.auxdata_ranges.items()},
            "std_json": candidate.std_json_input is not None,
            # work/ is mounted read-write into build and analyze containers. Right after the
            # build, before any later container runs, the solc output is copied into the job dir
            # (never mounted) with its hash; the restart path and the map step read only the copy.
            "output_sha256": _snapshot_solc_output(out_dir, build_result.work_dir),
            # B4 decision provenance and its diagnostics — included only when present so the dict
            # stays sparse (forge_stderr_head is capped, printable, repo-influenced text; never fed
            # to detection).
            **{k: v for k, v in build_result.build_notes.items() if k in _BUILD_NOTE_KEYS},
        }
        build_path.write_text(json.dumps(result), encoding="utf-8")

        # Store build_result.work_dir so analyze can find it
        if build_result.work_dir:
            (out_dir / "work_dir.txt").write_text(build_result.work_dir, encoding="utf-8")

        # Missing-import / missing-dependency-path detection (plan 09 §5.2, 05 B4):
        # When solc reports "Source … not found" the repo cannot be built without the dep.
        # Both missing_import: (npm/bare-name) and missing_dependency_path: (lib/ paths)
        # transition to insufficient_source; never silently continue to analyze with 0 leads.
        #
        # Security (04/08 x-text-class): package names / dep-path first-segments come from
        # repo import strings — untrusted user data.  error_code is a server-side enum; it
        # MUST NOT carry repo text.  Validated names go into error_detail only (x-text-class).
        build_reason = result.get("reason") or ""
        if build_reason.startswith(("missing_import:", "missing_dependency_path:")):
            reason_kind, _, rest = build_reason.partition(":")
            if reason_kind == "missing_import":
                raw_names = (rest or "").split(",")
                valid_pkgs = [n for n in raw_names if n and _validate_npm_pkg(n)]
                invalid_count = len(raw_names) - len(valid_pkgs)
                valid_pkgs = valid_pkgs[:_MISSING_IMPORT_MAX_PKGS]
                detail: dict[str, Any] = {
                    "reason": "missing_import",
                    # x-text-class: user data from repo import strings; never use in
                    # tool descriptions, system prompts, or log lines
                    "packages": valid_pkgs,
                    "dropped_invalid": invalid_count,
                }
                # The status text differs by start mode: pasted files have no repository, commit
                # or lockfile to point at (errors.yaml what_files / fix_files).
                mode_job = await self._get_job(job_id)
                if (mode_job or {}).get("source_kind") == "files":
                    detail["mode"] = "files"
                logger.info("job %s: build insufficient_source missing_import pkgs=%d dropped=%d",
                            job_id[-8:], len(valid_pkgs), invalid_count)
            else:
                # missing_dependency_path: lib/ or src/ paths not in Standard JSON sources.
                # Validate each segment before storing (x-text-class: user data from repo).
                raw_segs = (rest or "").split(",")
                valid_segs = [s for s in raw_segs if s and _validate_dep_seg(s)]
                invalid_seg_count = len([s for s in raw_segs if s]) - len(valid_segs)
                valid_segs = valid_segs[:_MISSING_IMPORT_MAX_PKGS]
                detail = {
                    "reason": "missing_dependency_path",
                    # x-text-class: path first-segments from repo; user data
                    "path_prefixes": valid_segs,
                    "dropped_invalid": invalid_seg_count,
                }
                logger.info("job %s: build insufficient_source missing_dependency_path valid=%d dropped=%d",
                            job_id[-8:], len(valid_segs), invalid_seg_count)
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                async with conn.transaction():
                    await repo.complete_step(step_id, "done",
                                             provenance={"reason": reason_kind})
                    await repo.transition(job_id, "insufficient_source",
                                          error_code="E_DEPENDENCY_UNRESOLVED",
                                          error_detail=detail)
            return

        # The candidate is the one this supervisor reconstructed and built, never one a step returned
        prov = await self._resolve_provenance(job_id, out_dir, dataclasses.replace(build_result, candidate=candidate))
        if result.get("compiler_kind"):
            prov = {**prov, "compiler_kind": result["compiler_kind"], "compiler_used": result.get("compiler_used")}
        await self._mark_step(step_id, "done", provenance=prov)
        await self._after_build(step, result)

    async def _apply_build_scope(self, job_id: str, out_dir: Path, candidates_raw: list[dict[str, Any]],
                                 candidates_path: Path, candidate: Candidate, excluded: list[str],
                                 first_version: str | None) -> None:
        """Record a narrowed build that compiled: candidates.json follows its compiler and lists the
        excluded files (scope_excluded, reason build_excluded); the pin marks them out of scope
        (readable with review_read_code, never mapped, counted, located or the report subject)
        and the job's source_pin follows the new manifest. Runs before build_result.json is
        written, so a restart never sees a half-applied scope."""
        comp = candidate.compiler
        if comp is not None:
            candidates_raw[0]["compiler"] = {"version": comp.version, "version_pinned_by": comp.version_pinned_by}
            if (comp.version or "").split("+", 1)[0] != (first_version or ""):
                candidates_raw[0]["compiler_retry"] = {"from": first_version, "reason": "build_scope"}
        candidates_raw[0]["build_scope"] = {"files": len(candidate.files), "excluded": len(excluded)}
        if excluded:
            rows = list(candidates_raw[0].get("scope_excluded") or [])
            known = {r.get("path") for r in rows if isinstance(r, dict)}
            rows.extend({"path": p, "reason": _build_scope.BUILD_EXCLUDED} for p in excluded if p not in known)
            candidates_raw[0]["scope_excluded"] = rows
            pin = PinnedSource.load(self._pin_root, job_id)
            pin = pin.with_out_of_scope(set(excluded))
            pin.persist(self._pin_root, job_id)
            async with self._pool.connection() as conn:
                await JobRepo(conn).update_job_fields(job_id, source_pin=pin.source_pin)
        candidates_path.write_text(json.dumps(candidates_raw, indent=2), encoding="utf-8")
        logger.info("job %s: build scope narrowed to %d file(s), %d excluded", job_id[-8:],
                    len(candidate.files), len(excluded))

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
                    # self_address: the 20-byte form a library runtime pushes (TRON chain_state
                    # keeps the base58 address for display and the hex form for the comparison).
                    self_address = cs.get("self_address") or address
                    dep = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: evm_deployment_check(family=chain.family, build=build,
                                                           onchain_runtime=cs.get("bytecode"),
                                                           address=self_address)
                    )
            prov = resolve_provenance(candidate=build.candidate if build else None, address=address, dep=dep)
            prov["block"] = cs.get("block")
            prov_path.write_text(json.dumps(prov, indent=2), encoding="utf-8")
        async with self._pool.connection() as conn:
            await JobRepo(conn).update_job_fields(job_id, tier=prov["tier"])
        logger.info("job %s: dep.match=%s tier=%s", job_id[-8:],
                    (prov.get("dep") or {}).get("match"), prov["tier"])
        return {"tier": prov["tier"], "dep_match": (prov.get("dep") or {}).get("match"),
                "dep_reason": (prov.get("dep") or {}).get("reason"), "label_reason": prov.get("label_reason"),
                "block": prov.get("block")}

    async def _is_tron_job(self, job_id: str) -> bool:
        job = await self._get_job(job_id)
        return bool(job) and job.get("chain") == "tron"

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

        # Lead scoping (repo jobs): the pinned files are the review; vendored npm packages and the
        # repo files the scope selection excluded are known non-review files of this run.
        scope_files, excluded_files = await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._review_file_sets(job_id, out_dir, cand_raw.get("provider")))
        # TRON: Slither in the tron-analyze image (TRON shim) with the compiler the build used.
        is_tron = await self._is_tron_job(job_id)
        try:
            leads, static_map, _read_plan = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _tron_analyze_mod.analyze(br) if is_tron
                else _analyze_mod.analyze(br, scope_files=scope_files, excluded_files=excluded_files)
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

    def _review_file_sets(self, job_id: str, out_dir: Path,
                          provider: str | None) -> tuple[set[str] | None, set[str] | None]:
        """(pinned scope files, files known to be outside the review) for lead scoping.

        Excluded = every .sol of the materialized repo tree (vendored node_modules included) that
        is not pinned. (None, None) when the pin cannot be read: then no lead is dropped.
        """
        try:
            scope = {p for p, e in PinnedSource.load(self._pin_root, job_id).entries.items() if e.in_scope}
        except (OSError, ValueError, KeyError):
            logger.warning("job %s: pin unreadable for lead scoping; no lead filtered", job_id[-8:])
            return None, None
        if provider != "repo":
            return scope, None
        tree, _refused = safe_read_repo_tree(out_dir / "repo_fetch" / "src")
        return scope, {p for p in tree if p.endswith(".sol") and p not in scope}

    async def _after_analyze(self, step: dict[str, Any], degraded: bool = False) -> None:
        """Queue the map step after the analyze step (03 3.1: map runs in `analyzing`)."""
        job_id = step["job_id"]
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                if degraded:
                    await repo.update_job_fields(job_id, analyzer_degraded=True)
                await repo.insert_step(
                    job_id=job_id, step="map", container=False, units=0, ram_mb=0, max_attempts=2,
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
        # npm integrity record of this run: the only dependencies whose guards the map may credit
        deps_path = out_dir / "dependencies.json"
        dependencies = (json.loads(deps_path.read_text(encoding="utf-8"))
                        if deps_path.is_file() and not deps_path.is_symlink() else None)
        summary = await asyncio.get_event_loop().run_in_executor(None, lambda: _map_step.run_map_step(
            self._pin_root, job_id,
            family="evm", chain=(job or {}).get("chain"),
            solc_output_path=_solc_output_copy(out_dir, build),
            std_input_path=_compiled_input_path(out_dir, build),
            build_ok=build_ok, job=job, chain_state=chain_state,
            candidate=cands[0] if cands else None,
            dependencies=dependencies if isinstance(dependencies, dict) else None,
            nsloc=int(build["nsloc"]) if build.get("nsloc") is not None else None,
            analyzers=analyzers, build_detail=detail,
            # the real build outcome for review_status build.status (TRON compiles with a substitute
            # solc and still gets a `full` map; the map status is not the build status)
            build_status="ok" if build_ok else "failed",
        ))
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.update_job_fields(job_id, map_status=summary["map_status"])
                await repo.complete_step(step_id, "done", provenance=summary)
                await repo.insert_step(
                    job_id=job_id, step="chain_state", seq=1, container=False, units=0, ram_mb=0,
                    max_attempts=2, affinity=step.get("lease_owner"),
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
            rpc_urls = _rpc_urls(int(job["chain_id"]))
            if rpc_urls and cs.get("block") is not None:
                from ..mapping.build import load_map

                doc, _ = load_map(self._pin_root, job_id)
                cands_path = out_dir / "candidates.json"
                cands = json.loads(cands_path.read_text()) if cands_path.exists() else []
                units = ((doc or {}).get("semantic") or {}).get("units") or []
                unit_id = _facts_mod.entry_unit_id((cands[0] if cands else {}).get("entry_contract"), units)
                # Use RpcClientPool with failover; pin to the recorded block.
                rpc_pool_pinned = RpcClientPool(rpc_urls, block=int(cs["block"]))
                onchain = await _facts_mod.onchain_facts(rpc_pool_pinned, cs["address"], int(cs["block"]),
                                                         doc, unit_id)
                facts.extend(onchain)
                added = len(onchain)
                # State-parameter probes + related-contract classification
                # (feat/context-related-state): degrade gracefully on any error.
                try:
                    from ..mapping.related import (
                        classify_related_contracts,
                        state_parameter_facts,
                        write_related_contracts,
                    )
                    # Load verified ABI from the solc output copy so state facts
                    # are decoded by type (int256 sign-extends, bytes32 as hex,
                    # address without entropy guessing) and related contracts include
                    # all zero-arg address-returning public getters.
                    entry_contract = (cands[0] if cands else {}).get("entry_contract")
                    abi_list = _extract_abi_from_solc_output(out_dir, entry_contract)
                    state_fs = await state_parameter_facts(
                        rpc_pool_pinned, cs["address"], int(cs["block"]), doc, unit_id,
                        abi_list=abi_list,
                    )
                    if state_fs:
                        facts.extend(state_fs)
                    related = await classify_related_contracts(
                        rpc_pool_pinned, int(cs["block"]), onchain,
                        chain_id=int(job["chain_id"]),
                        abi_list=abi_list,
                        target_address=cs["address"],
                    )
                    # Expose related.<label>.verified facts
                    for entry in related:
                        label = entry.get("role") or "related"
                        verified = entry.get("verified")
                        if verified is not None:
                            facts.append({
                                "key": f"related.{label}.verified",
                                "value": str(verified).lower(),  # "true" / "false"
                                "source": "sourcify",
                                "unit_id": unit_id,
                            })
                    # Re-check deleted state before writing (security review 2026-10-24, Issue 8):
                    # review_delete_job may have run while the probe phase was executing.
                    async with self._pool.connection() as _del_conn:
                        _del_row = await (await _del_conn.execute(
                            "select state from jobs where job_id = %s", (job_id,)
                        )).fetchone()
                    if _del_row is None or _del_row[0] == "deleted":
                        logger.info("job %s: deleted during chain_state phase, discarding related/facts", job_id[-8:])
                        return
                    write_related_contracts(self._pin_root, job_id, related)
                except Exception:
                    logger.info("job %s: related/state facts skipped", job_id[-8:], exc_info=True)
                _facts_mod.write_facts(self._pin_root, job_id, facts)
        flags = _map_step.load_flags(self._pin_root, job_id) or []
        async with self._pool.connection() as conn:
            repo = JobRepo(conn)
            async with conn.transaction():
                await repo.complete_step(step_id, "done", provenance={"onchain_facts": added})
                n_leads = await persist_leads_from_pin(conn, self._pin_root, job_id)
                await repo.transition(job_id, "ready")
                drafts = await repo.create_server_drafts(job_id, "evm", server_draft_flags(flags))
        logger.info("job %s ready (onchain facts %d, server drafts %d, leads persisted %d)",
                    job_id[-8:], added, drafts, n_leads)

    # ------------------------------------------------------------------
    # context: project documents (context ingestion spec 2026-10-23, section 3)
    # ------------------------------------------------------------------

    async def _maybe_queue_context(self, job_id: str) -> None:
        """Queue the first `context` step once the job is `ready` and documents were requested.

        Steps of one job run one at a time in enqueue order (09 3.3 claim query), so a context
        round queued earlier would hold back build and analyze; queued at `ready` it never gates
        the interactive state. Later rounds come from review_add_context itself.
        """
        try:
            async with self._pool.connection() as conn:
                repo = JobRepo(conn)
                job = await repo.get(job_id)
                if job is None or job.get("state") != "ready" or not job.get("context_items"):
                    return
                steps = await repo.get_steps(job_id)
                if any(s["step"] == "context" for s in steps):
                    return
                async with conn.transaction():
                    await repo.insert_step(job_id=job_id, step="context", seq=0, container=True, units=1,
                                           ram_mb=1024, max_attempts=1)
            logger.info("job %s: context step queued (%d documents requested)", job_id[-8:],
                        len(job.get("context_items") or []))
        except Exception:
            logger.exception("job %s: queuing the context step failed", job_id[-8:])

    async def _run_context(self, step: dict[str, Any]) -> None:
        """Fetch every requested document not yet in the store, then rebuild the context facts."""
        from ..context.facts import context_facts, write_context_facts
        from ..context.items import find_entry, inline_document
        from ..context.store import ContextStore
        from ..sandbox.doc_fetch import fetch_document

        job_id, step_id = step["job_id"], step["id"]
        job = await self._get_job(job_id)
        items: list[dict[str, Any]] = list((job or {}).get("context_items") or [])
        store = ContextStore.load(self._pin_root, job_id)
        work = self._job_dir(job_id) / "context_fetch"
        work.mkdir(parents=True, exist_ok=True)
        loop = asyncio.get_event_loop()
        fetched = failed = 0
        for n, item in enumerate(items):
            existing = find_entry(store, item)
            if existing is not None and (existing.ok or existing.fetched_at >= str(item.get("requested_at") or "")):
                continue
            kind, url = str(item.get("kind") or "other"), item.get("url")
            if url:
                doc = await loop.run_in_executor(None, lambda k=kind, u=url, i=n: fetch_document(k, u, work, i))
            else:
                doc = inline_document(item)
            try:
                entry = store.add([doc])[0]
            except ValueError as exc:            # over the per-job cap or a bad kind: recorded, not fatal
                logger.warning("job %s: document %s not stored: %s", job_id[-8:], (url or item.get("path") or "")[:80], exc)
                failed += 1
                continue
            if entry.ok:
                fetched += 1
            else:
                failed += 1
                logger.info("job %s: document %s failed: %s (%s)", job_id[-8:], (url or item.get("path") or "")[:80],
                            entry.error, doc.get("error_detail", ""))
        facts = await loop.run_in_executor(None, lambda: context_facts(store, job or {}))
        write_context_facts(self._pin_root, job_id, facts)
        done = sum(1 for e in store.documents if e.ok)
        failed_total = sum(1 for e in store.documents if not e.ok)
        await self._mark_step(step_id, "done", provenance={"requested": len(items), "done": done,
                                                           "failed": failed_total, "fetched_now": fetched,
                                                           "facts": len(facts), "context_pin": store.context_pin})
        logger.info("job %s: context round done (requested %d, done %d, failed %d, facts %d)",
                    job_id[-8:], len(items), done, failed_total, len(facts))

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


# 03 3.1: `failed` is reachable only from fetching, building and analyzing. A job that dies while
# still `queued` (no RPC for its chain, a provider fault before fetch) walks queued -> fetching ->
# failed; a direct jump raised JobStateError and left the job `queued` forever (2026-10-22, Sepolia).
_FAIL_PATH: dict[str, list[str]] = {
    "awaiting_upload": ["queued", "fetching", "failed"],
    "queued": ["fetching", "failed"],
    "fetching": ["failed"],
    "building": ["failed"],
    "analyzing": ["failed"],
}


def fail_path(state: str) -> list[str]:
    """States to walk so that a job in `state` legally ends in `failed` ([] when it cannot)."""
    return list(_FAIL_PATH.get(state, []))


async def _fail_job(repo: JobRepo, job_id: str, error_code: str, error_detail: dict[str, Any] | None = None) -> bool:
    """Move the job to `failed` along the legal path; False when its state has no path there."""
    job = await repo.get(job_id)
    state = job.get("state") if isinstance(job, dict) else None
    # Unknown or already-advanced state: attempt the direct edge (the pre-fix behaviour); the
    # repo raises JobStateError if the graph forbids it, which the caller logs.
    path = fail_path(state) if state else []
    if not path:
        path = ["failed"]
    for to_state in path:
        if to_state == "failed":
            await repo.transition(job_id, "failed", error_code=error_code, error_detail=error_detail)
        else:
            await repo.transition(job_id, to_state)
    return True


def _load_build_result(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


_SOLC_OUTPUT_COPY = "solc_output.json"
# build_notes keys copied into build_result.json (B4 decision + why it fell back, 05 4.2).
_DEP_PIN_MAX_FILES = 80
_DEP_PIN_MAX_BYTES = 3 * 1024 * 1024


def _dependency_closure(candidate: Candidate) -> dict[str, str]:
    """Dependency .sol files the candidate's scope imports (repo mode: node_modules/ and lib/ of
    the materialised tree), capped, for the out-of-scope pin. Empty for other providers."""
    tree = getattr(candidate, "_full_tree", None)
    if candidate.provider != "repo" or not tree:
        return {}
    remaps = list((candidate.settings or {}).get("remappings") or [])
    closure = _solc_select.closure_sources(candidate.files, tree, remaps)
    out: dict[str, str] = {}
    total = 0
    for path in sorted(closure):
        if path in candidate.files or not path.endswith(".sol"):
            continue
        text = closure[path]
        if len(out) >= _DEP_PIN_MAX_FILES or total + len(text) > _DEP_PIN_MAX_BYTES:
            break
        out[path] = text
        total += len(text)
    return out


def _build_attempt_row(candidate: Candidate, result: BuildResult) -> dict[str, Any]:
    """One row of build_result.json `attempts` (review_status detailed build.attempts): the
    version tried, where it came from, and the failure class (enum token or error class names,
    never raw compiler text)."""
    from ..tools.map_view import build_error_summary

    comp = candidate.compiler
    return {
        "version": comp.version.split("+", 1)[0] if comp else None,
        "version_source": _solc_select.pinned_by_text(comp.version_pinned_by) if comp else None,
        "status": "ok" if result.status == "ok" else "failed",
        "reason": None if result.status == "ok" else build_error_summary(result.stderr_head or result.reason),
    }


# Build failures a narrower build may fix: compiler errors (parse, type, version) and imports
# that do not resolve; never a missing compiler binary, a sandbox fault or a sanitiser refusal.
_SCOPE_RETRY_REASONS = ("failed", "missing_import:", "missing_dependency_path:")
_SCOPE_EXCLUDE_ROUNDS = 3


@dataclasses.dataclass
class _Narrowed:
    attempts: list[dict[str, Any]]
    result: BuildResult | None = None        # the attempt that compiled, None when none did
    candidate: Candidate | None = None
    excluded: list[str] = dataclasses.field(default_factory=list)


def _scope_retry_applies(result: BuildResult) -> bool:
    reason = result.reason or ""
    return reason == "failed" or reason.startswith(_SCOPE_RETRY_REASONS[1:])


def _reviewed_files(pin_root: Path, job_id: str) -> dict[str, str]:
    pin = PinnedSource.load(pin_root, job_id)
    return {p: "\n".join(pin.read_all(p)) for p, e in pin.entries.items() if e.in_scope}


def _subset_compiler(candidate: Candidate, files: dict[str, str]) -> Compiler | None:
    """Compiler for a narrowed build: a project or explorer pin is kept; a pragma choice is made
    again over the narrowed files and what they import (the left-out files' pragmas no longer
    count)."""
    comp = candidate.compiler
    if comp is None or comp.version_pinned_by not in ("pragma", "pragma_partial", "pragma_guess"):
        return comp
    tree = getattr(candidate, "_full_tree", None)
    remaps = list((candidate.settings or {}).get("remappings") or [])
    exprs = _solc_select.pragma_exprs(_solc_select.closure_sources(files, tree, remaps))
    picked = _solc_select.choose_pragma_version(exprs, _solc_select.load_builds()) if exprs else None
    if picked is None:
        return comp
    return Compiler(version=picked[0], version_pinned_by=picked[1])


def _scope_retries(candidate: Candidate, builder: Any, out_dir: Path, first: BuildResult) -> _Narrowed:
    """Closure build, then up to three exclusion rounds (build_scope). Synchronous (executor)."""
    tree = getattr(candidate, "_full_tree", None)
    remaps = list((candidate.settings or {}).get("remappings") or [])
    out = _Narrowed(attempts=[])

    def attempt(files: dict[str, str], kind: str, work: str, dropped: list[str]) -> tuple[Candidate, BuildResult]:
        cand = dataclasses.replace(candidate, files=files, compiler=_subset_compiler(candidate, files),
                                   std_json_input=None, build_paths=sorted(files))
        work_dir = out_dir / work
        work_dir.mkdir(exist_ok=True)
        res = builder(cand, work_dir=work_dir)
        row = _build_attempt_row(cand, res)
        row["scope"] = kind
        row["files"] = len(files)
        if dropped:
            row["excluded"] = dropped[:50]
        out.attempts.append(row)
        return cand, res

    current, result = candidate, first
    closure = _build_scope.closure_files(candidate.files, tree, remaps)
    if closure and set(closure) != set(candidate.files):
        current, result = attempt(closure, "closure", "work_closure", [])
        if result.status == "ok":
            out.result, out.candidate = result, current
            return out
    excluded: list[str] = []
    for n in range(1, _SCOPE_EXCLUDE_ROUNDS + 1):
        version = current.compiler.version if current.compiler else None
        failing = _build_scope.failing_files(result.build_notes, current.files, version)
        plan = _build_scope.plan_exclusion(current.files, failing, tree, remaps)
        if plan is None:
            break
        kept, dropped = plan
        excluded.extend(dropped)
        current, result = attempt(kept, "exclude", f"work_exclude_{n}", dropped)
        if result.status == "ok":
            out.result, out.candidate, out.excluded = result, current, excluded
            return out
        if not _scope_retry_applies(result):
            break
    return out


def _parse_error_retry_version(candidate: Candidate) -> str | None:
    """The newest release satisfying every pragma of the candidate's files and the tree files
    they import, when it differs from the version just tried; None otherwise."""
    tree = getattr(candidate, "_full_tree", None)
    remaps = list((candidate.settings or {}).get("remappings") or [])
    exprs = _solc_select.pragma_exprs(_solc_select.closure_sources(candidate.files, tree, remaps))
    if not exprs:
        return None
    builds = _solc_select.load_builds()
    if not builds:
        return None
    newest = _solc_select.newest_satisfying(exprs, builds)
    tried = (candidate.compiler.version if candidate.compiler else "").split("+", 1)[0]
    if newest is None or newest.split("+", 1)[0] == tried:
        return None
    return newest


_BUILD_NOTE_KEYS = frozenset({
    "b4_source", "b4_rejected", "b4_detail", "libraries_unverified", "had_unknown_settings",
    "forge_version_mismatch", "forge_rc", "forge_stderr_head",
    "compiler_kind", "compiler_used",
})
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


def _compiled_input_path(out_dir: Path, result: dict[str, Any]) -> Path | None:
    """The Standard JSON input the build step actually compiled, for the map step.

    Every EVM solc build (std-json, forge-derived and synthetic alike) goes through `_run_build`,
    which writes the input it sent to solc into the host-only build dir (`<work>.host/build/
    input.json`, written from this process's memory, never container-mounted). That file is the
    byte stream the AST `src` offsets refer to. Fallback: the fetched `std_input_0.json` when the
    build recorded that it used it (`std_json`). None when neither exists (the pin text was
    compiled, and the map step then resolves offsets against the pin)."""
    if result.get("status") != "ok":
        return None
    work_dir = result.get("work_dir")
    if work_dir:
        host = _build_mod.host_build_dir(Path(work_dir)) / "input.json"
        if host.is_file():
            return host
    if result.get("std_json"):
        fetched = out_dir / "std_input_0.json"
        if fetched.is_file():
            return fetched
    return None


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


def _extract_abi_from_solc_output(
    out_dir: Path,
    entry_contract: str | None = None,
) -> list[dict[str, Any]] | None:
    """Extract the ABI for ``entry_contract`` from the job-dir solc output copy.

    The ABI lives in ``contracts[src][name]["metadata"]`` (JSON string) under
    ``output.abi``.  Sourcify always populates metadata; a bare solc output
    without metadata is tried as a fallback (``contracts[src][name]["abi"]``).

    Returns a non-empty list on success; None when the file is absent, the build
    failed, or no ABI can be found.  Reads at most ``_MAX_SOLC_OUTPUT_BYTES`` and
    never raises (degradation: chain_state continues without ABI-aware decoding).
    """
    path = out_dir / _SOLC_OUTPUT_COPY
    if not path.is_file():
        return None
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_SOLC_OUTPUT_BYTES:
            return None
        data = json.loads(raw)
    except (OSError, ValueError):
        return None
    contracts = data.get("contracts") or {}

    # Helper: extract ABI from a single contract data dict.
    def _abi_from_contract(c: dict[str, Any]) -> list | None:
        # Try metadata.output.abi first (Sourcify populates this).
        meta_raw = c.get("metadata")
        if meta_raw:
            try:
                meta = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
                abi = (meta.get("output") or {}).get("abi") or []
                if abi:
                    return abi
            except (ValueError, AttributeError):
                pass
        # Fallback: bare abi key (not always present).
        abi = c.get("abi") or []
        return abi if abi else None

    # First try: exact match on entry_contract ("src/Foo.sol:Foo").
    if entry_contract:
        src, _, name = entry_contract.rpartition(":")
        if src and name and src in contracts and name in contracts[src]:
            abi = _abi_from_contract(contracts[src][name])
            if abi:
                return abi

    # Fallback: return the first non-empty ABI we find.
    for ctrs in contracts.values():
        for c_data in ctrs.values():
            abi = _abi_from_contract(c_data)
            if abi:
                return abi
    return None
