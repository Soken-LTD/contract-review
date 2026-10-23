"""Retention sweep (plan-v4 part 09 O1 to O7, M16; privacy policy rows): what the service keeps and
for how long, applied by one idempotent pass. Nothing expired before this module existed: jobs
only received `expires_at` at render time and no code moved a job to `expired`.

    python -m soken_review.worker.retention --dsn <dsn> --pin-root <dir> [--dry-run] [--json]

Rules (every one tombstoned with reason `expiry`, rows purged through `tools.delete.purge_job`,
files removed through `tools.delete._remove_files`):

  * terminal and stuck jobs (failed, insufficient_source, awaiting_upload, and any pipeline or
    render state) older than `failed_days` (7) by `created_at`  -> `deleted`
  * `ready` jobs idle longer than `job.ready_idle_ttl_h` (24 h) by `last_call_at` -> `expired`
  * `rendered` jobs whose report passed `reports.expires_at` (30 days at render) -> `expired`
  * `build_cache` rows past `expires_at`
  * orphan directories: `<pin_root>/job_*` and `<pin_root>/../work/job_*` without a live job row,
    `<store>/reports/<id>` without a reports row (what a container wrote in the last instant of a
    delete, or a crashed render)

The publication records and `report_tombstones` are never touched here (append-only; the 09
retention table assigns their pruning to the scheduler role).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

from ..db.job_repo import JobRepo
from ..report.render import store_root
from ..tools.delete import _remove_files, purge_job

logger = logging.getLogger(__name__)

FAILED_DAYS = 7
READY_IDLE_HOURS = 24
_JOB_DIR = "job_"
# A job keeps its directories until its row is purged (failed and refused jobs for 7 days): only
# deleted and expired rows, or no row at all, make a directory an orphan.
_LIVE_STATES = ("awaiting_upload", "queued", "fetching", "building", "analyzing", "ready", "finalized",
                "render_queued", "rendering", "rendered", "render_failed", "failed", "insufficient_source")
_SEVEN_DAY_STATES = ("awaiting_upload", "queued", "fetching", "building", "analyzing", "finalized",
                     "render_queued", "rendering", "render_failed", "failed", "insufficient_source")


@dataclass
class SweepReport:
    purged_terminal: list[str] = field(default_factory=list)
    expired_idle: list[str] = field(default_factory=list)
    expired_reports: list[str] = field(default_factory=list)
    build_cache_rows: int = 0
    orphan_dirs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def ready_idle_hours() -> int:
    """`job.ready_idle_ttl_h` from contract/ops/limits.yaml, else the launch default."""
    try:
        import yaml

        path = Path(__file__).resolve().parents[3] / "contract" / "ops" / "limits.yaml"
        value = (yaml.safe_load(path.read_text(encoding="utf-8")).get("job") or {}).get("ready_idle_ttl_h")
        return int(value) if value else READY_IDLE_HOURS
    except Exception:  # noqa: BLE001  # a broken limits file never stops the sweep
        return READY_IDLE_HOURS


async def _candidates(conn: psycopg.AsyncConnection, idle_hours: int, failed_days: int) -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            select j.job_id, j.state, 'terminal' as why from jobs j
             where j.state = any(%(seven)s) and j.created_at < now() - %(seven_days)s::interval
            union all
            select j.job_id, j.state, 'idle' from jobs j
             where j.state = 'ready' and j.last_call_at < now() - %(idle)s::interval
            union all
            select j.job_id, j.state, 'report' from jobs j join reports r on r.job_id = j.job_id
             where j.state = 'rendered' and r.expires_at < now()
            """,
            {"seven": list(_SEVEN_DAY_STATES), "seven_days": timedelta(days=failed_days),
             "idle": timedelta(hours=idle_hours)},
        )
        return list(await cur.fetchall())


async def _purge_one(conn: psycopg.AsyncConnection, pin_root: Path, job_id: str, to_state: str) -> None:
    async with conn.transaction():
        job = await JobRepo(conn).get_and_lock(job_id)
        if job is None or job["state"] in ("deleted", "expired"):
            return
        _deleted, report = await purge_job(conn, job_id, reason="expiry", to_state=to_state)
    await asyncio.get_event_loop().run_in_executor(
        None, _remove_files, pin_root, job_id, report["object_prefix"] if report else None)


async def _orphan_dirs(conn: psycopg.AsyncConnection, pin_root: Path, dry_run: bool) -> list[str]:
    """Directories no live row points at. A job dir whose job is deleted or expired, or missing;
    a report dir whose report row is gone."""
    removed: list[str] = []
    roots = [pin_root.resolve(), pin_root.resolve().parent / "work"]
    names: set[str] = set()
    for root in roots:
        if root.is_dir():
            names.update(p.name for p in root.iterdir() if p.name.startswith(_JOB_DIR) and p.is_dir() and not p.is_symlink())
    live: set[str] = set()
    if names:
        async with conn.cursor() as cur:
            await cur.execute("select job_id from jobs where job_id = any(%s) and state = any(%s)",
                              (sorted(names), list(_LIVE_STATES)))
            live = {row[0] for row in await cur.fetchall()}
    for root in roots:
        for name in sorted(names - live):
            path = root / name
            if path.is_dir() and not path.is_symlink():
                removed.append(str(path))
                if not dry_run:
                    shutil.rmtree(path, ignore_errors=True)
    reports_root = store_root() / "reports"
    if reports_root.is_dir():
        ids = sorted(p.name for p in reports_root.iterdir() if p.is_dir() and not p.is_symlink())
        kept: set[str] = set()
        if ids:
            async with conn.cursor() as cur:
                await cur.execute("select report_id from reports where report_id = any(%s)", (ids,))
                kept = {row[0] for row in await cur.fetchall()}
        for rid in ids:
            if rid not in kept:
                path = reports_root / rid
                removed.append(str(path))
                if not dry_run:
                    shutil.rmtree(path, ignore_errors=True)
    return removed


async def sweep(conn: psycopg.AsyncConnection, pin_root: Path, *, dry_run: bool = False,
                failed_days: int = FAILED_DAYS, idle_hours: int | None = None) -> SweepReport:
    """One pass. Each job is its own transaction, so one failure never blocks the rest."""
    out = SweepReport()
    idle = idle_hours if idle_hours is not None else ready_idle_hours()
    for row in await _candidates(conn, idle, failed_days):
        job_id, why = row["job_id"], row["why"]
        to_state = "deleted" if why == "terminal" else "expired"
        bucket = {"terminal": out.purged_terminal, "idle": out.expired_idle, "report": out.expired_reports}[why]
        if dry_run:
            bucket.append(job_id)
            continue
        try:
            await _purge_one(conn, pin_root, job_id, to_state)
            bucket.append(job_id)
        except Exception as exc:  # logged, the sweep goes on
            logger.exception("retention: job %s (%s) not purged", job_id[-8:], why)
            out.errors.append(f"{job_id}: {exc}"[:200])
    async with conn.cursor() as cur:
        if dry_run:
            await cur.execute("select count(*) from build_cache where expires_at < now()")
            out.build_cache_rows = int((await cur.fetchone())[0])
        else:
            await cur.execute("delete from build_cache where expires_at < now()")
            out.build_cache_rows = cur.rowcount
    out.orphan_dirs = await _orphan_dirs(conn, pin_root, dry_run)
    return out


async def run(dsn: str, pin_root: Path, *, dry_run: bool) -> SweepReport:
    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        return await sweep(conn, pin_root, dry_run=dry_run)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Soken contract-review retention sweep")
    ap.add_argument("--dsn", default=os.environ.get("SOKEN_DATABASE_URL", ""))
    ap.add_argument("--pin-root", default=os.environ.get("SOKEN_PIN_ROOT", "/srv/sbx"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not args.dsn:
        ap.error("--dsn or SOKEN_DATABASE_URL required")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    report = asyncio.run(run(args.dsn, Path(args.pin_root), dry_run=args.dry_run))
    summary = report.as_dict()
    if args.json:
        print(json.dumps(summary, separators=(",", ":")))
    else:
        print("retention sweep" + (" (dry run)" if args.dry_run else "") + ": " + ", ".join(
            f"{k}={len(v) if isinstance(v, list) else v}" for k, v in summary.items()))
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
