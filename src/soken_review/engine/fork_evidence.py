"""Which fork runs raise a finding's printed evidence level to test_verified (review_verify_on_fork).

A run counts for a draft only when all of these hold (security review 2026-10-31):

- it is bound to the draft and to the revision that is current now (a revised finding loses the
  mark until a new run against the new revision passes);
- the reviewer claimed a pass (`expect` pass) and every test that ran passed;
- it finished before the job was finalized (the report evidence cannot change after finalize;
  finalize also refuses while a run of the job is queued or running);
- the test exercised the cited contract: the run read the job's deployment address through the
  proxy, or the test imports a pinned file the finding quotes.

The raise is printed only. The stored evidence level, the severity caps (K8) and finalize use the
base level; a run never changes a severity.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

_IMPORT_PREFIX = "pinned/"


def exercised(result: dict[str, Any], test_source: str, address: str | None, cited: set[str]) -> str | None:
    """`address` when the run read the deployment address, `import` when the test imports a cited
    pinned file, else None."""
    from ..sandbox.fork_verify import test_imports

    touched = {str(a).lower() for a in ((result.get("rpc") or {}).get("addresses") or [])}
    if address and address.lower() in touched:
        return "address"
    imported = {i[len(_IMPORT_PREFIX):] for i in test_imports(test_source or "") if i.startswith(_IMPORT_PREFIX)}
    if imported & cited:
        return "import"
    return None


def why_not(run: dict[str, Any], current_revision: int | None, address: str | None, cited: set[str],
            finalized_at: datetime | None = None) -> str | None:
    """None when the run raises the draft's evidence, else the reason it does not (tool output)."""
    if not run.get("draft_key"):
        return "the run is not bound to a finding (draft_key)"
    if run.get("status") != "passed":
        return "only a passing run raises the finding's evidence level"
    if run.get("expect") != "pass":
        return "the run was filed with expect fail"
    if current_revision is None or run.get("draft_revision") != current_revision:
        return "the finding was revised after the run; run the test again against the current revision"
    if finalized_at is not None and run.get("finished_at") is not None and run["finished_at"] > finalized_at:
        return "the run ended after finalize"
    result = run.get("result") or {}
    if isinstance(result, str):
        result = json.loads(result)
    if not any(t.get("status") == "passed" for t in result.get("tests") or []):
        return "no test passed"
    if exercised(result, run.get("test_source") or "", address, cited) is None:
        return ("the test neither read the deployment address on the fork nor imports a pinned file the "
                "finding quotes")
    return None


async def _rows(conn: Any, sql: str, params: tuple) -> list[dict[str, Any]]:
    from psycopg.rows import dict_row

    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        return list(await cur.fetchall())


async def context(conn: Any, job_id: str) -> tuple[str | None, datetime | None, dict[str, int], dict[str, set[str]]]:
    """(deployment address, finalized_at, current revision per draft, quoted paths per draft)."""
    job = (await _rows(conn, "select address, finalized_at, state from jobs where job_id = %s", (job_id,)) or [{}])[0]
    finalized_at = job.get("finalized_at") if job.get("state") not in (None, "ready") else None
    revs = {r["draft_key"]: int(r["current_revision"]) for r in await _rows(
        conn, "select draft_key, current_revision from finding_drafts where job_id = %s and status <> 'withdrawn'", (job_id,))}
    cited: dict[str, set[str]] = {}
    for q in await _rows(conn, """select q.draft_key, q.path from finding_quote_ranges q join finding_drafts d
            on d.job_id = q.job_id and d.draft_key = q.draft_key and d.current_revision = q.revision
            where q.job_id = %s""", (job_id,)):
        cited.setdefault(q["draft_key"], set()).add(q["path"])
    return job.get("address"), finalized_at, revs, cited


async def verified_runs(conn: Any, job_id: str) -> dict[str, dict[str, Any]]:
    """{draft_key: the latest run that raises it}."""
    address, finalized_at, revs, cited = await context(conn, job_id)
    runs = await _rows(conn, """select run_id, draft_key, draft_revision, status, expect, network, block, test_path,
               test_sha256, test_source, result, finished_at
        from fork_runs where job_id = %s and draft_key is not null and status = 'passed'
        order by finished_at desc nulls last""", (job_id,))
    out: dict[str, dict[str, Any]] = {}
    for r in runs:
        key = r["draft_key"]
        if key in out:
            continue
        if why_not(r, revs.get(key), address, cited.get(key, set()), finalized_at) is None:
            out[key] = r
    return out
