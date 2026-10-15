#!/usr/bin/env python3
"""Call `review_report` through the MCP server (contract validation included) for live jobs.

Usage: uv run python scripts/report_call_dev.py --dsn DSN JOB [--page N]
Prints the structured result and checks it against the tool outputSchema.
"""

from __future__ import annotations

import argparse
import asyncio
import json

import psycopg_pool
from jsonschema import Draft202012Validator

from soken_review import tools  # noqa: F401  registers handlers
from soken_review.server import SokenServer
from soken_review.tools import report as report_tool


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--page", type=int, default=0)
    ap.add_argument("jobs", nargs="+")
    a = ap.parse_args()
    pool = psycopg_pool.AsyncConnectionPool(a.dsn, min_size=1, max_size=2, open=False)
    await pool.open()
    report_tool.set_pool(pool)
    server = SokenServer()
    schema = server.contract["review_report"]["outputSchema"]
    for jid in a.jobs:
        res = await server.call_tool("review_report", {"job_id": jid, "page": a.page})
        body = res.structured_content
        errors = [e.message for e in Draft202012Validator(schema).iter_errors(body)]
        print(json.dumps({"job": jid, "schema_errors": errors, "result": body}, indent=1))
    await pool.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
