"""Which fork runs raise a finding's printed evidence level to test_verified (review_verify_on_fork).

A run counts for a draft only when all of these hold (security review 2026-10-31):

- it is bound to the draft and to the revision that is current now (a revised finding loses the
  mark until a new run against the new revision passes);
- the reviewer claimed a pass (`expect` pass), the run has at least one test and every test passed
  (a skipped or unreported test fails closed);
- it finished before the job was finalized (no end time after finalize fails closed) (the report evidence cannot change after finalize;
  finalize also refuses while a run of the job is queued or running);
- the cited contract executed: the EVM loaded the deployment's code or storage (or called it) through
  the proxy, or the test deploys or calls a contract of a pinned file the finding quotes. A run that
  meets everything else but this is printed as "Exercised by a test" and raises nothing.

The raise is printed only. The stored evidence level, the severity caps (K8) and finalize use the
base level; a run never changes a severity.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

_IMPORT_PREFIX = "pinned/"


def exercised(result: dict[str, Any], test_source: str, address: str | None, cited: set[str]) -> str | None:
    """How the run shows that the cited contract executed: `address` when the EVM loaded the deployment's
    code or storage (or called it) through the proxy, `import` when the test deploys or calls a contract
    declared in a pinned file the finding quotes; else None. A balance or nonce read alone, or an
    import the test never uses, is not execution."""
    executed = {str(a).lower() for a in ((result.get("rpc") or {}).get("executed") or [])}
    if address and address.lower() in executed:
        return "address"
    for imp in result.get("imports") or []:
        if isinstance(imp, dict) and imp.get("path") in cited and imp.get("used"):
            return "import"
    return None


NOT_EXERCISED = ("the test did not execute the cited contract (no code or storage load of the deployment, and"
                 " no deployment of or call into a contract of a pinned file the finding quotes)")


def why_not(run: dict[str, Any], current_revision: int | None, address: str | None, cited: set[str],
            finalized_at: datetime | None = None) -> str | None:
    """None when the run raises the draft's evidence, else the reason it does not (tool output).
    NOT_EXERCISED is the one reason that still prints the run, as exercised (`classify`)."""
    if not run.get("draft_key"):
        return "the run is not bound to a finding (draft_key)"
    if run.get("status") != "passed":
        return "only a passing run raises the finding's evidence level"
    if run.get("expect") != "pass":
        return "the run was filed with expect fail"
    if current_revision is None or run.get("draft_revision") != current_revision:
        return "the finding was revised after the run; run the test again against the current revision"
    if finalized_at is not None and (run.get("finished_at") is None or run["finished_at"] > finalized_at):
        return "the run had not ended when the job was finalized"
    result = run.get("result") or {}
    if isinstance(result, str):
        result = json.loads(result)
    tests = result.get("tests") or []
    if not tests or not all(isinstance(t, dict) and t.get("status") == "passed" for t in tests):
        return "every test of the run must pass (at least one test)"
    if exercised(result, run.get("test_source") or "", address, cited) is None:
        return NOT_EXERCISED
    return None


def classify(run: dict[str, Any], current_revision: int | None, address: str | None, cited: set[str],
             finalized_at: datetime | None = None) -> tuple[str | None, str | None]:
    """("verified", None): raises to test_verified; ("touched", why): printed as "Exercised by a
    test" without a raise; (None, why): not printed."""
    why = why_not(run, current_revision, address, cited, finalized_at)
    if why is None:
        return "verified", None
    if why == NOT_EXERCISED:
        return "touched", why
    return None, why


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
    """{draft_key: run} for the report: the latest verified run of each draft, else its latest touched
    run; each row carries `kind` (verified or touched)."""
    address, finalized_at, revs, cited = await context(conn, job_id)
    runs = await _rows(conn, """select run_id, draft_key, draft_revision, status, expect, network, block, test_path,
               test_sha256, test_source, result, finished_at
        from fork_runs where job_id = %s and draft_key is not null and status = 'passed'
        order by finished_at desc nulls last""", (job_id,))
    out: dict[str, dict[str, Any]] = {}
    for r in runs:
        key = r["draft_key"]
        if key in out and out[key]["kind"] == "verified":
            continue
        kind, _why = classify(r, revs.get(key), address, cited.get(key, set()), finalized_at)
        if kind == "verified" or (kind == "touched" and key not in out):
            out[key] = {**r, "kind": kind}
    return out
