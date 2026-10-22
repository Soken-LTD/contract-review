"""Lead rows: the lead.v1 documents the analyze step writes to ``<pin_root>/<job>/leads.json``
mirrored into the ``leads`` table (03 3.6 DDL).

Why both: `review_leads` pages the JSON file (03 4.7), while every write path that depends on a
lead (`review_submit_finding` lead linking, `review_dismiss_lead`, the finalize F2/F4 gates and the
E3 `analyzer_and_reasoning` evidence level) reads the table. Until 2026-10-22 nothing populated the
table on the product path, so every lead link failed with E_LEAD_NOT_FOUND, every finding stayed
`reasoning_only` and K4 printed real Highs as Low. `persist_leads` runs once, just before the job
enters `ready`; it is idempotent (primary key job_id, lead_id; existing rows keep their state).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import psycopg

logger = logging.getLogger(__name__)

_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_LOCATED = {"verbatim", "function", "moved"}
_MAX_LEADS = 5000


def load_leads_json(pin_root: Path, job_id: str) -> list[dict[str, Any]]:
    """Read leads.json (bare list or ``{"leads": [...]}``); missing or malformed gives []."""
    path = pin_root / job_id / "leads.json"
    if not path.is_file() or path.is_symlink():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    leads = raw.get("leads", []) if isinstance(raw, dict) else raw
    return [lead for lead in leads if isinstance(lead, dict)] if isinstance(leads, list) else []


def lead_row(job_id: str, lead: dict[str, Any]) -> tuple[Any, ...] | None:
    """Map one lead.v1 document to a ``leads`` row; None when the document cannot satisfy the DDL."""
    lead_id = str(lead.get("id") or "")
    path = str(lead.get("file") or lead.get("path") or "")
    category = str(lead.get("category") or "")
    rule_id = str(lead.get("rule_id") or "")
    if not (lead_id.startswith("LEAD-") and path and category and rule_id):
        return None
    origin = lead.get("origin") or "analyzer"
    if origin not in ("analyzer", "previous_report"):
        return None
    sev = str(lead.get("severity_norm") or "Info")
    if sev == "Informational":
        sev = "Info"
    if sev not in _SEVERITIES:
        sev = "Info"
    if sev == "Critical" and origin == "analyzer":
        sev = "High"                      # DDL: analyzer leads never carry Critical
    try:
        start, end = int(lead.get("start", 0)), int(lead.get("end", 0))
    except (TypeError, ValueError):
        return None
    tools = lead.get("tools") or ["analyzer"]
    if not isinstance(tools, list):
        tools = [str(tools)]
    located = lead.get("located") if origin == "previous_report" else None
    if origin == "previous_report" and located not in _LOCATED:
        located = "function"
    return (
        job_id, lead_id, origin, lead.get("prev_finding_id"), rule_id[:200], [str(t)[:80] for t in tools][:8],
        category[:60], category.split(".", 1)[0][:20], str(lead.get("analyzer_severity_raw") or sev)[:40],
        sev, located, path[:200], start, end,
    )


async def persist_leads(conn: psycopg.AsyncConnection, job_id: str, leads: list[dict[str, Any]]) -> int:
    """Insert the job's leads as ``open`` rows; rows already present are left untouched.

    Returns the number of rows the statement inserted. Must run inside the caller's transaction.
    """
    rows = [r for r in (lead_row(job_id, lead) for lead in leads[:_MAX_LEADS]) if r is not None]
    skipped = len(leads[:_MAX_LEADS]) - len(rows)
    if skipped:
        logger.warning("job %s: %d lead documents did not fit the leads DDL and were not persisted", job_id[-8:], skipped)
    if not rows:
        return 0
    inserted = 0
    async with conn.cursor() as cur:
        for row in rows:
            await cur.execute(
                """insert into leads (job_id, lead_id, origin, prev_finding_id, rule_id, tools, category,
                                      category_family, analyzer_severity_raw, severity_norm, located,
                                      path, start_line, end_line, state)
                   values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open')
                   on conflict (job_id, lead_id) do nothing""",
                row,
            )
            inserted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    return inserted


async def persist_leads_from_pin(conn: psycopg.AsyncConnection, pin_root: Path, job_id: str) -> int:
    """`persist_leads` over the job's leads.json; the hook every family calls before `ready`."""
    return await persist_leads(conn, job_id, load_leads_json(pin_root, job_id))


async def lead_states(conn: psycopg.AsyncConnection, job_id: str) -> dict[str, dict[str, Any]]:
    """``{lead_id: {state, reason, state_ref}}`` for the job (the table is the state of record)."""
    async with conn.cursor() as cur:
        await cur.execute("select lead_id, state, reason, state_ref from leads where job_id = %s", (job_id,))
        return {r[0]: {"state": r[1], "reason": r[2], "state_ref": r[3]} for r in await cur.fetchall()}
