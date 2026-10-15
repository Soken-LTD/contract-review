#!/usr/bin/env python3
"""Dev driver for the render path (08 3, P0-RENDER): ready job -> finalized -> worker render.

Stand-ins, not product code: `review_submit_finding` and `review_finalize` (03 4.9, 4.14) are not
built yet, so `--seed` writes test findings straight into the finding tables (titles start with
"Test fixture") and `finalize` only assigns the report id and final ids, then queues the render.
The render itself runs through `Supervisor` exactly as in production (claim, render step, upload).

Usage:
  uv run python scripts/render_dev.py --dsn DSN --pin-root PIN [--copy-from SRC_DSN] [--seed JOB] JOB...
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import secrets
import sys
import time
from pathlib import Path

import psycopg
import psycopg_pool
from psycopg.types.json import Jsonb

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soken_review.db.migrate import run_migrations
from soken_review.report.kit.build import SEV_PREFIX, SEVS
from soken_review.report.render import queue_render
from soken_review.worker.supervisor import Supervisor

SEED = [
    {"key": "test-drift-clock", "severity": "High", "category": "evm.reentrancy", "family": "evm",
     "impact": "theft_of_funds", "rule": "S2", "level": "analyzer_and_reasoning", "lead": "LEAD-0013",
     "loc": ("src/GBLIN.sol", 714, 728), "ctx": ("src/GBLIN.sol", 700, 709),
     "title": "Test fixture HIGHSECRET drift clock write in the auction marker",
     "description": "Seeded test finding for the render proof; not a review result. The `_markDrift` function "
                    "writes `driftSince` after it reads the basket value.",
     "impact_text": "Seeded test text; it states no impact of the deployed code.",
     "recommendation": "Seeded test text; no change is recommended."},
    {"key": "test-drift-rounding", "severity": "Medium", "category": "evm.arithmetic_precision", "family": "evm",
     "impact": "incorrect_accounting_no_fund_effect", "rule": "M1", "level": "reasoning_challenged", "lead": None,
     "loc": ("src/GBLIN.sol", 718, 718), "ctx": None,
     "title": "Test fixture drift basis points rounded down in the auction marker",
     "description": "Seeded test finding for the render proof; not a review result. Line 718 divides by `tot` "
                    "after the multiplication by `BPS`.",
     "impact_text": "Seeded test text; it states no impact of the deployed code.",
     "recommendation": "Seeded test text; no change is recommended."},
    {"key": "test-pending-owner", "severity": "Low", "category": "evm.input_validation", "family": "evm",
     "impact": "spec_deviation_bounded", "rule": "L1", "level": "reasoning_only", "lead": None,
     "loc": ("src/GBLIN.sol", 1068, 1071), "ctx": None,
     "title": "Test fixture pending owner accepts the zero address",
     "description": "Seeded test finding for the render proof; not a review result. The `transferOwnership` "
                    "function stores `newOwner` in `pendingOwner` without a zero address check.",
     "impact_text": "Seeded test text; the two step transfer still needs the pending owner to accept.",
     "recommendation": "Seeded test text; no change is recommended."},
]

log = logging.getLogger("render_dev")


async def copy_jobs(src: str, dst: str, job_ids: list[str]) -> None:
    async with await psycopg.AsyncConnection.connect(src) as s, await psycopg.AsyncConnection.connect(dst) as d:
        for jid in job_ids:
            row = await (await s.execute("select row_to_json(j) from jobs j where job_id = %s", (jid,))).fetchone()
            if row is None:
                raise SystemExit(f"{jid} not in source db")
            await d.execute("delete from reports where job_id = %s", (jid,))
            await d.execute("delete from jobs where job_id = %s", (jid,))
            await d.execute("insert into jobs select * from jsonb_populate_record(null::jobs, %s)", (Jsonb(row[0]),))
            steps = await (await s.execute("select row_to_json(t) from job_steps t where job_id = %s order by id",
                                           (jid,))).fetchall()
            for (st,) in steps:
                st.pop("id", None)
                cols = ", ".join(st)
                await d.execute(f"insert into job_steps ({cols}) select {cols} from jsonb_populate_record(null::job_steps, %s)",
                                (Jsonb(st),))
        await d.commit()


async def seed(conn: psycopg.AsyncConnection, job_id: str) -> None:
    for no, f in enumerate(SEED, start=1):
        path, a, b = f["loc"]
        content = {"job_id": job_id, "draft_key": f["key"], "category": f["category"], "title": f["title"],
                   "quotes": [{"file": path, "start": a, "end": b, "text": "", "role": "location"}],
                   "matrix": {"impact_class": f["impact"], "magnitude": "bounded", "trigger": "anyone",
                              "precondition": "none", "reversibility": "irreversible"},
                   "body": {"description": [{"p": f["description"]}], "impact": [{"p": f["impact_text"]}],
                            "recommendation": [{"p": f["recommendation"]}]}}
        h = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
        await conn.execute(
            """insert into finding_drafts (job_id, draft_key, finding_no, origin, status, current_revision, severity,
                 evidence_level) values (%s, %s, %s, 'model', 'accepted', 1, %s, %s)""",
            (job_id, f["key"], no, f["severity"], f["level"]))
        await conn.execute(
            """insert into finding_revisions (job_id, draft_key, revision, content, content_hash, category,
                 category_family, impact_class, computed_severity, severity_rule)
               values (%s, %s, 1, %s, %s, %s, %s, %s, %s, %s)""",
            (job_id, f["key"], Jsonb(content), h, f["category"], f["family"], f["impact"], f["severity"], f["rule"]))
        quotes = [("location", f["loc"])] + ([("context", f["ctx"])] if f["ctx"] else [])
        for ord_, (role, (p, s, e)) in enumerate(quotes):
            await conn.execute(
                """insert into finding_quote_ranges (job_id, draft_key, revision, ord, role, path, start_line, end_line)
                   values (%s, %s, 1, %s, %s, %s, %s, %s)""", (job_id, f["key"], ord_, role, p, s, e))
        if f["lead"]:
            await conn.execute("insert into finding_leads values (%s, %s, 1, %s)", (job_id, f["key"], f["lead"]))
        if f["level"] != "reasoning_only":
            await conn.execute(
                """insert into challenge_answers (job_id, draft_key, revision, checklist_sha256, items, answers_hash,
                     answers, verdict, severity_before) values (%s, %s, 1, %s, %s, %s, %s, 'passed', %s)""",
                (job_id, f["key"], "0" * 64, Jsonb([{"id": "R1", "condition": "Every state variable the caller profits "
                                                     "from is written before the external call."}]), "0" * 64,
                 Jsonb([{"item_id": "R1", "answer": "No"}]), f["severity"]))


async def finalize(conn: psycopg.AsyncConnection, job_id: str) -> str:
    """Stand-in for review_finalize (03 4.14): report id, final ids, finalized, render queued."""
    rid = base64.b32encode(secrets.token_bytes(16)).decode().lower().rstrip("=")[:26]
    rows = await (await conn.execute("""select draft_key, severity from finding_drafts where job_id = %s
        and status = 'accepted' order by finding_no""", (job_id,))).fetchall()
    per: dict[str, int] = {}
    for key, sev in sorted(rows, key=lambda r: SEVS.index(r[1])):
        per[sev] = per.get(sev, 0) + 1
        await conn.execute("update finding_drafts set final_id = %s where job_id = %s and draft_key = %s",
                           (f"{SEV_PREFIX[sev]}-{per[sev]:03d}", job_id, key))
    await conn.execute("update jobs set state = 'ready', report_id = %s where job_id = %s", (rid, job_id))
    from soken_review.db.job_repo import JobRepo

    await JobRepo(conn).transition(job_id, "finalized")
    await queue_render(conn, job_id)
    return rid


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--pin-root", required=True, type=Path)
    ap.add_argument("--copy-from")
    ap.add_argument("--seed", action="append", default=[])
    ap.add_argument("jobs", nargs="+")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    await run_migrations(a.dsn)
    if a.copy_from:
        await copy_jobs(a.copy_from, a.dsn, a.jobs)
    async with await psycopg.AsyncConnection.connect(a.dsn) as conn:
        for jid in a.jobs:
            async with conn.transaction():
                for t in ("challenge_answers", "finding_leads", "finding_quote_ranges", "finding_revisions",
                          "finding_drafts"):
                    await conn.execute(f"delete from {t} where job_id = %s", (jid,))
                if jid in a.seed:
                    await seed(conn, jid)
                print(jid, "report_id", await finalize(conn, jid))
    pool = psycopg_pool.AsyncConnectionPool(a.dsn, min_size=1, max_size=4, open=False)
    await pool.open()
    sup = Supervisor(pool, a.pin_root, host_name="render-dev-1", poll_interval=0.5)
    task = asyncio.create_task(sup.run())
    t0 = time.monotonic()
    try:
        while time.monotonic() - t0 < 600:
            await asyncio.sleep(1)
            async with pool.connection() as conn:
                states = dict(await (await conn.execute("select job_id, state from jobs where job_id = any(%s)",
                                                        (a.jobs,))).fetchall())
            if all(s in ("rendered", "render_failed") for s in states.values()):
                break
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    async with pool.connection() as conn:
        for jid in a.jobs:
            row = await (await conn.execute("""select j.state, j.error_detail, r.report_id, r.object_prefix, r.out_name,
                r.pdf_sha256s, r.profile from jobs j left join reports r using (job_id) where j.job_id = %s""",
                                            (jid,))).fetchone()
            print(json.dumps({"job": jid, "state": row[0], "error": row[1], "report_id": row[2], "prefix": row[3],
                              "out_name": row[4], "pdf_sha256s": row[5], "profile": row[6]}))
    await pool.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
