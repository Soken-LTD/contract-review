"""Handler for review_add_context (context ingestion spec 2026-10-23, section 2; tool 19).

Registered via @handler("review_add_context"). `{job_id, items}`: 1 to 8 `{kind, url}` or
`{kind, path, content}` items. Allowed while the job is in a non-terminal, non-frozen state
(awaiting_upload, queued, fetching, building, analyzing, ready). Idempotent per URL: a URL already
ingested returns the existing document (`exists`); a URL whose fetch failed is queued again and
carries the earlier `E_CONTEXT_FETCH` in its row. At most 12 documents per job (E_CONTEXT_LIMIT).

The request records land in `jobs.context_items`; the worker's `context` step fetches them. Before
`ready` the supervisor queues that step when the job reaches `ready`; after `ready` this handler
inserts a new `context` step itself, and `review_status` reports `context: {requested, done,
failed}` until the round completes.
"""

from __future__ import annotations

from typing import Any

import psycopg_pool

from ..context.items import check_cap, item_key, item_result, status_counts, validate_items
from ..context.store import ContextStore
from ..db.pool import get_pool
from ..errors import ReviewError
from ..server import handler
from .context import JobContext

_pool: psycopg_pool.AsyncConnectionPool | None = None
_ctx: JobContext | None = None

_OPEN_STATES = frozenset({"awaiting_upload", "queued", "fetching", "building", "analyzing", "ready"})
_FROZEN_STATES = frozenset({"finalized", "render_queued", "rendering", "rendered", "render_failed"})
_TERMINAL_STATES = frozenset({"insufficient_source", "failed"})
POLL_AFTER_S = 5


def set_pool(pool: psycopg_pool.AsyncConnectionPool) -> None:
    global _pool
    _pool = pool


def set_context(ctx: JobContext) -> None:
    global _ctx
    _ctx = ctx


def _get_pool() -> psycopg_pool.AsyncConnectionPool:
    return _pool if _pool is not None else get_pool()


def _get_ctx() -> JobContext:
    if _ctx is None:
        raise ReviewError("E_INTERNAL", incident="add_context not wired (ctx is None)")
    return _ctx


@handler("review_add_context")
async def handle_review_add_context(args: dict[str, Any]) -> dict[str, Any]:
    job_id: str = args["job_id"]
    try:
        items = validate_items(args["items"])
    except ReviewError as exc:
        if exc.channel == "rejection":
            return {"accepted": False, "errors": [exc.envelope()]}
        raise
    pool = _get_pool()
    from ..db.job_repo import JobRepo

    async with pool.connection() as conn:
        job = await JobRepo(conn).get(job_id)
    if job is None or job["state"] == "deleted":
        raise ReviewError("E_JOB_NOT_FOUND")
    state = job["state"]
    if state == "expired":
        raise ReviewError("E_JOB_EXPIRED", job=job_id, date=str(job.get("expires_at") or ""))
    if state in _FROZEN_STATES:
        return {"accepted": False, "errors": [ReviewError("E_JOB_FROZEN").envelope()]}
    if state in _TERMINAL_STATES:
        return {"accepted": False, "errors": [
            ReviewError("E_JOB_TERMINAL", state=state, exit_code=job.get("error_code") or "").envelope()]}
    if state not in _OPEN_STATES:
        return {"accepted": False, "errors": [ReviewError("E_JOB_NOT_READY", state=state, eta_s=0).envelope()]}

    existing: list[dict[str, Any]] = list(job.get("context_items") or [])
    try:
        check_cap(existing, items)
    except ReviewError as exc:
        return {"accepted": False, "errors": [exc.envelope()]}

    pin_root = _get_ctx().get_pin_root()
    store = ContextStore.load(pin_root, job_id)
    known = {item_key(r) for r in existing}

    async with pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        all_items = await repo.append_context_items(job_id, items)
        current = await repo.get(job_id)
        if current is not None and current["state"] == "ready":
            steps = await repo.get_steps(job_id)
            pending = any(s["step"] == "context" and s["status"] in ("queued", "running") for s in steps)
            if not pending:
                seq = sum(1 for s in steps if s["step"] == "context")
                await repo.insert_step(job_id=job_id, step="context", seq=seq, container=True, units=1,
                                       ram_mb=1024, max_attempts=1)

    rows = [item_result(store, it, already_requested=item_key(it) in known) for it in items]
    return {
        "accepted": True,
        "job_id": job_id,
        "items": rows,
        "context": status_counts(store, all_items),
        "poll_after_s": POLL_AFTER_S,
    }
