"""review_delete_job (03 section 4; 08 3.4; 09 retention): the requester removes a job.

The job id is the capability (as for every other tool of the authless surface). Deletion is one
transaction on the rows and then best-effort removal of the files:

  * open steps become `cancelled` so the worker claims nothing more for the job; a step already
    running finishes against a job that is gone and ends in its own error path;
  * the live report row goes (publish requests cascade from it) and one 09 tombstone per served
    PDF plus one for the job are appended (`report_tombstones`, hashes only, reason user_delete);
  * every row keyed by the job in any table with a `job_id` column goes (findings, leads, reads,
    sections, context documents, enrichment, uploads);
  * the job row itself stays as the terminal `deleted` state with its request data scrubbed, so a
    later call on the same id answers `deleted` (idempotent) and never an existence oracle;
  * on disk: the pin store and context documents (`<pin_root>/<job_id>`), the worker's work dir
    (`<pin_root>/../work/<job_id>`) and the report objects (`<store>/reports/<report_id>/`).

Only names the contract lists appear in `deleted`: source, artifacts, findings, reads, report, pdf.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import shutil
from pathlib import Path
from typing import Any

import psycopg
import psycopg_pool
from psycopg import sql
from psycopg.rows import dict_row

from ..db.job_repo import JobRepo
from ..db.pool import get_pool
from ..errors import ReviewError
from ..server import handler
from .context import JobContext

logger = logging.getLogger(__name__)

_pool: psycopg_pool.AsyncConnectionPool | None = None
_ctx: JobContext | None = None

# Tables whose rows count as the contract's "findings" and "reads" (the rest are removed too).
_FINDING_TABLES = frozenset({"finding_drafts", "leads", "lead_dismissals", "finding_leads", "challenge_answers"})
_READ_TABLES = frozenset({"job_reads"})


def set_pool(pool: psycopg_pool.AsyncConnectionPool) -> None:
    global _pool
    _pool = pool


def set_context(ctx: JobContext) -> None:
    global _ctx
    _ctx = ctx


def _get_pool() -> psycopg_pool.AsyncConnectionPool:
    return _pool if _pool is not None else get_pool()


def _ref_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def _child_tables(conn: psycopg.AsyncConnection) -> list[str]:
    """Every public table with a `job_id` column except `jobs` itself, `reports` first (its
    publish rows cascade from it, and it holds no cascade from jobs)."""
    async with conn.cursor() as cur:
        await cur.execute(
            """
            select table_name from information_schema.columns
            where table_schema = 'public' and column_name = 'job_id' and table_name <> 'jobs'
            order by (table_name = 'reports') desc, table_name
            """
        )
        return [row[0] for row in await cur.fetchall()]


async def _delete_rows(conn: psycopg.AsyncConnection, job_id: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in await _child_tables(conn):
        async with conn.cursor() as cur:
            await cur.execute(sql.SQL("delete from {} where job_id = %s").format(sql.Identifier(table)), (job_id,))
            counts[table] = cur.rowcount
    return counts


async def _tombstones(conn: psycopg.AsyncConnection, job_id: str, report: dict[str, Any] | None) -> None:
    rows: list[tuple[str, str, str | None]] = [("job", _ref_hash(job_id), None)]
    if report is not None:
        rows += [("report", _ref_hash(report["report_id"]), sha) for sha in (report["pdf_sha256s"] or [])]
    async with conn.cursor() as cur:
        await cur.executemany(
            "insert into report_tombstones (kind, ref_hash, pdf_sha256, reason) values (%s, %s, %s, 'user_delete')",
            rows,
        )


def _rmtree(path: Path) -> bool:
    """Remove a directory tree; True when something was there. Never follows a symlinked root."""
    if path.is_symlink() or not path.is_dir():
        return False
    shutil.rmtree(path, ignore_errors=True)
    return True


def _remove_files(pin_root: Path | None, job_id: str, report_prefix: str | None) -> set[str]:
    removed: set[str] = set()
    if pin_root is not None:
        pin_root = pin_root.resolve()
        if _rmtree(pin_root / job_id):
            removed.add("source")
        if _rmtree(pin_root.parent / "work" / job_id):
            removed.add("artifacts")
    if report_prefix:
        from ..report.render import store_root

        # object_prefix is reports/<report_id>/<render_no>/: remove the report's whole directory
        parts = Path(report_prefix).parts
        if len(parts) >= 2 and parts[0] == "reports" and _rmtree(store_root() / parts[0] / parts[1]):
            removed.update({"report", "pdf"})
    return removed


@handler("review_delete_job")
async def handle_review_delete_job(args: dict[str, Any]) -> dict[str, Any]:
    """Delete a job: rows in one transaction, files after it (best effort, logged)."""
    job_id: str = args["job_id"]
    pool = _get_pool()
    deleted: set[str] = set()
    report: dict[str, Any] | None = None

    async with pool.connection() as conn:
        repo = JobRepo(conn)
        async with conn.transaction():
            job = await repo.get_and_lock(job_id)
            if job is None:
                raise ReviewError("E_JOB_NOT_FOUND")
            if job["state"] == "deleted":
                return {"accepted": True, "job_id": job_id, "state": "deleted", "deleted": []}
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    "update job_steps set status = 'cancelled', cancel_reason = 'user_delete'"
                    " where job_id = %s and status in ('queued', 'running')",
                    (job_id,),
                )
                await cur.execute(
                    "select report_id, pdf_sha256s, object_prefix from reports where job_id = %s", (job_id,)
                )
                report = await cur.fetchone()
            await _tombstones(conn, job_id, report)
            counts = await _delete_rows(conn, job_id)
            if any(counts.get(t, 0) for t in _FINDING_TABLES):
                deleted.add("findings")
            if any(counts.get(t, 0) for t in _READ_TABLES):
                deleted.add("reads")
            if report is not None:
                deleted.update({"report", "pdf"})
            await repo.transition(job_id, "deleted", touch=True)
            await conn.execute(
                """
                update jobs set source_args = '{}'::jsonb, error_detail = null, previous_snapshot = null,
                       source_pin = null, resolved_commit = null, code_hash = null, upload_id = null,
                       upload_sha256 = null, address = null, report_id = null
                where job_id = %s
                """,
                (job_id,),
            )
            if job.get("source_pin") or job.get("upload_sha256"):
                deleted.add("source")

    pin_root = _ctx.get_pin_root() if _ctx is not None else None
    try:
        removed = await asyncio.get_event_loop().run_in_executor(
            None, _remove_files, pin_root, job_id, report["object_prefix"] if report else None)
        deleted.update(removed)
    except Exception:
        logger.exception("job %s: rows deleted, file removal failed (retention sweep will finish it)", job_id[-8:])
    logger.info("job %s deleted: %s", job_id[-8:], sorted(deleted))
    return {"accepted": True, "job_id": job_id, "state": "deleted",
            "deleted": [n for n in ("source", "artifacts", "findings", "reads", "report", "pdf") if n in deleted]}
