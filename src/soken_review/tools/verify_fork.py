"""Handler of review_verify_on_fork (chain access design 1.7, P4 on EVM).

A reviewer sends one Foundry test with assertions about balances, state or reverts of the reviewed
contract; the worker runs it with `forge test` against a local, in-memory fork of the chain at the
job's pinned block (sandbox/fork_verify.py). Reads reach the chain only through the read-only proxy;
nothing is ever sent to a network.

Additive and optional: no step, finalize check or report gate depends on a run, and a failure is a
rejection or a run result (`error`, `timeout`), never a change of the job. A run bound to a draft
(`draft_key`) that passes raises that finding's evidence level to `test_verified` in the report, which
prints "Verified by a test on a local fork of <network> at block N" with the test name.

One call queues the run and waits up to `wait_seconds` for it; a run still queued or running is
answered with its `run_id`, and a call with `run_id` returns its current state.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from typing import Any

from ..chain.untrusted import GUIDE_NOTE
from ..errors import ReviewError
from ..server import handler
from . import chain as chain_tools
from .context import JobContext

logger = logging.getLogger(__name__)

_pool: Any | None = None
_ctx: JobContext | None = None
_POLL_S = 1.0
_DONE = frozenset({"passed", "failed", "error", "timeout"})


def set_pool(pool: Any) -> None:
    global _pool
    _pool = pool


def set_context(ctx: JobContext) -> None:
    global _ctx
    _ctx = ctx


def _get_pool() -> Any:
    if _pool is not None:
        return _pool
    return chain_tools._get_pool()


def _pin_root() -> Any:
    if _ctx is None:
        raise ReviewError("E_INTERNAL", incident="verify_on_fork not wired (ctx is None)")
    return _ctx.get_pin_root()


def report_line(network: str, block: int, tests: list[dict[str, Any]]) -> str:
    """The sentence the report prints under a finding verified by a passing run."""
    names = [t["name"] for t in tests if t.get("status") == "passed"][:3]
    return f"Verified by a test on a local fork of {network} at block {block:,}: {', '.join(names)}"


def run_view(row: dict[str, Any]) -> dict[str, Any]:
    """The tool result of one fork_runs row."""
    result = row.get("result") or {}
    if isinstance(result, str):
        result = json.loads(result)
    status = row["status"]
    out: dict[str, Any] = {
        "accepted": True, "job_id": row["job_id"], "run_id": row["run_id"], "status": status,
        "expect": row["expect"],
        "chain": {"family": "evm", "chain_id": int(row["chain_id"]), "network": row["network"], "block": int(row["block"])},
        "test": {"path": row["test_path"], "sha256": row["test_sha256"]},
    }
    if row.get("draft_key"):
        out["draft_key"] = row["draft_key"]
    if status in _DONE:
        out["matches_expectation"] = (status == "passed") == (row["expect"] == "pass")
        for k in ("tests", "rpc", "wall_s", "reason", "diagnostics", "engine"):
            if k in result:
                out[k] = result[k]
        if status == "passed" and row.get("draft_key"):
            out["evidence"] = {"draft_key": row["draft_key"], "level": "test_verified",
                               "report_line": report_line(row["network"], int(row["block"]), result.get("tests") or [])}
        elif row.get("draft_key"):
            out["evidence"] = {"draft_key": row["draft_key"], "level": "unchanged",
                               "why": "only a passing run raises the finding's evidence level"}
        out["untrusted_text_note"] = ("Assertion messages, console lines and compiler diagnostics are in untrusted_text: "
                                      + GUIDE_NOTE.replace("from the chain", "from the test run"))
    else:
        out["poll"] = {"run_id": row["run_id"], "after_s": 10,
                       "hint": "Call review_verify_on_fork again with run_id; the review goes on meanwhile."}
    return out


_COLS = ("run_id, job_id, draft_key, status, chain_id, network, block, test_path, test_sha256, expect, result")


async def _fetch_run(job_id: str, run_id: str) -> dict[str, Any] | None:
    from psycopg.rows import dict_row

    async with _get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(f"select {_COLS} from fork_runs where job_id = %s and run_id = %s", (job_id, run_id))
        return await cur.fetchone()


async def _wait(job_id: str, run_id: str, wait_s: float) -> dict[str, Any] | None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, wait_s)
    row = await _fetch_run(job_id, run_id)
    while row is not None and row["status"] not in _DONE and loop.time() < deadline:
        await asyncio.sleep(_POLL_S)
        row = await _fetch_run(job_id, run_id)
    return row


async def _resolve_block(cj: Any, requested: Any) -> int:
    """`pinned` (default when the job has one) or an integer is used as given; `latest` is frozen to
    the head at call time through the read-only proxy."""
    if isinstance(requested, int) and not isinstance(requested, bool):
        if cj.pinned_block is not None and requested > cj.pinned_block + 10_000_000:
            raise ReviewError("E_INVALID_ARGUMENT", field="block", rule="a block of the chain", value80=str(requested),
                              example=str(cj.pinned_block))
        return int(requested)
    if requested in (None, "pinned") and cj.pinned_block is not None:
        return int(cj.pinned_block)
    if requested == "pinned":
        raise ReviewError("E_INVALID_ARGUMENT", field="block", rule="pinned needs a job with a pinned block",
                          value80="pinned", example="latest")
    from ..chain.proxy import ChainProxy, ChainUnavailable, Meter, RpcFailure

    try:
        async with ChainProxy(meter=Meter(max_calls=8)) as px:
            head = await asyncio.wait_for(px.evm(int(cj.chain_id), "eth_blockNumber", []), timeout=20)
        return int(head, 16)
    except (ChainUnavailable, RpcFailure, TimeoutError, ValueError, TypeError) as exc:
        raise _Unavailable(ReviewError("E_CHAIN_UNAVAILABLE", reason=getattr(exc, "reason", "upstream"),
                                       hosts=", ".join(getattr(exc, "hosts", []) or [])[:200] or "free pool",
                                       retry_after_s=10)) from None


class _Unavailable(Exception):
    def __init__(self, err: ReviewError) -> None:
        super().__init__(err.code)
        self.err = err


@handler("review_verify_on_fork")
async def handle_verify_on_fork(args: dict[str, Any]) -> dict[str, Any]:
    from ..sandbox import fork_verify as fv
    from ..sandbox.profile import locked_image

    job_id = args["job_id"]
    wait_s = float(args.get("wait_seconds", fv.fork_limits().get("wait_s", 25)))
    if args.get("run_id"):
        row = await _fetch_run(job_id, str(args["run_id"]))
        if row is None:
            raise ReviewError("E_INVALID_ARGUMENT", field="run_id", rule="a run of this job", value80=str(args["run_id"]),
                              example="the run_id a previous call returned")
        row = await _wait(job_id, row["run_id"], wait_s)
        return run_view(row or {})
    try:
        job = await chain_tools._job_row(job_id)
        root = _pin_root()
        cj = chain_tools.chain_job(job, root, args.get("chain_id"))
    except chain_tools._Reject as rj:
        return {"accepted": False, "errors": [rj.err.envelope()]}
    if cj.family != "evm":
        return {"accepted": False, "errors": [ReviewError(
            "E_CHAIN_UNSUPPORTED", what=f"fork verification on {cj.network}",
            fix_hint="Fork verification runs on EVM chains today; cite review_chain_read facts instead.").envelope()]}
    if locked_image("evm-analyze") is None:
        return {"accepted": False, "errors": [ReviewError("E_FORK_UNAVAILABLE", reason="sandbox image not pinned").envelope()]}
    test = args.get("test")
    if not isinstance(test, dict) or not isinstance(test.get("content"), str):
        raise ReviewError("E_INVALID_ARGUMENT", field="test", rule="a test object with content (or run_id to poll)",
                          value80="missing", example='{"path": "test/Verify.t.sol", "content": "pragma solidity ..."}')
    try:
        path = fv.check_test_path(test.get("path"))
        from ..pinning.store import PinnedSource

        pin_paths = set(PinnedSource.load(root, job_id).entries)
        fv.check_test_source(test["content"], pin_paths)
    except fv.TestRejected as exc:
        raise ReviewError("E_INVALID_ARGUMENT", field=exc.field, rule=exc.rule, value80=exc.value, example=exc.example) from None
    try:
        block = await _resolve_block(cj, args.get("block"))
    except _Unavailable as un:
        return {"accepted": False, "errors": [un.err.envelope()]}
    lim = fv.fork_limits()
    draft_key = args.get("draft_key")
    run_id = f"fork-{secrets.token_hex(6)}"
    from ..db.job_repo import JobRepo

    async with _get_pool().connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        locked = await repo.get_and_lock(job_id)
        if locked is None or locked["state"] != "ready":
            return {"accepted": False, "errors": [ReviewError(
                "E_JOB_NOT_READY", state=(locked or {}).get("state", "deleted"), eta_s=0).envelope()]}
        async with conn.cursor() as cur:
            if draft_key:
                await cur.execute("select status from finding_drafts where job_id = %s and draft_key = %s",
                                  (job_id, draft_key))
                d = await cur.fetchone()
                if d is None or d[0] == "withdrawn":
                    return {"accepted": False, "errors": [ReviewError("E_FINDING_NOT_FOUND", draft=str(draft_key)[:40]).envelope()]}
            await cur.execute("select count(*), count(*) filter (where status in ('queued','running')) "
                              "from fork_runs where job_id = %s", (job_id,))
            total, pending = await cur.fetchone()
        if int(total) >= int(lim.get("runs_per_job", 6)):
            return {"accepted": False, "errors": [ReviewError(
                "E_FORK_LIMIT", what=f"{total} of {lim.get('runs_per_job', 6)} runs used for this job",
                fix_hint="Merge the assertions into one test file, or go on without another run.").envelope()]}
        if int(pending) >= int(lim.get("pending_per_job", 1)):
            return {"accepted": False, "errors": [ReviewError(
                "E_FORK_LIMIT", what="a run of this job is still queued or running",
                fix_hint="Poll it with run_id first.").envelope()]}
        step = await repo.insert_step(job_id=job_id, step="verify_fork", seq=min(int(total), 32000), container=True,
                                      units=1, ram_mb=1536, max_attempts=1)
        async with conn.cursor() as cur:
            await cur.execute(
                """insert into fork_runs (run_id, job_id, step_id, draft_key, chain_id, network, block, test_path,
                                          test_sha256, test_source, expect)
                   values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (run_id, job_id, step["id"], draft_key, int(cj.chain_id), cj.network, block, path,
                 fv.test_sha256(test["content"]), test["content"], args.get("expect") or "pass"))
    logger.info("job %s: fork run %s queued at block %d", job_id[-8:], run_id, block)
    row = await _wait(job_id, run_id, wait_s)
    return run_view(row or {})
