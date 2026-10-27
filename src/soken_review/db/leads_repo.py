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
from functools import cache
from pathlib import Path
from typing import Any

import psycopg
import yaml

logger = logging.getLogger(__name__)

_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_LOCATED = {"verbatim", "function", "moved"}
_MAX_LEADS = 5000
_RUBRIC_DIR = Path(__file__).resolve().parents[3] / "contract" / "rubric"
_SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
_FINDING_TO_LEAD_SEV = {"Informational": "Info"}


@cache
def category_severity_caps() -> dict[str, str]:
    """category id -> `max_severity` of rubric/enums.yaml in the lead scale (Informational = Info)."""
    try:
        rows = yaml.safe_load((_RUBRIC_DIR / "enums.yaml").read_text(encoding="utf-8")).get("categories") or []
    except (OSError, ValueError, AttributeError):
        return {}
    out: dict[str, str] = {}
    for row in rows:
        cap = row.get("max_severity") if isinstance(row, dict) else None
        if cap:
            out[str(row["id"])] = _FINDING_TO_LEAD_SEV.get(str(cap), str(cap))
    return out


def clamp_lead_severity(lead: dict[str, Any]) -> dict[str, Any]:
    """Bound `severity_norm` by the category's `max_severity` (enums.yaml), in place.

    The analyzer scale is normalised per tool (analyzer_severity.yaml), the category cap per
    rubric: a `nativeThrowUnless` style hit mapped to `ton.best_practice` arrived as High while no
    finding of that category can print above Informational, so the list showed "best_practice
    high" 29 times and F2 demanded a quoted dismissal for each (BNB and TON blind runs 2026-10-26).
    The raw analyzer value stays in `analyzer_severity_raw`."""
    cap = category_severity_caps().get(str(lead.get("category") or ""))
    sev = str(lead.get("severity_norm") or "")
    if cap and sev in _SEV_RANK and _SEV_RANK[sev] > _SEV_RANK.get(cap, 5):
        lead.setdefault("analyzer_severity_raw", sev)
        lead["severity_norm"] = cap
    return lead


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
    return [clamp_lead_severity(lead) for lead in leads if isinstance(lead, dict)] if isinstance(leads, list) else []


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
    sev = str(clamp_lead_severity(dict(lead)).get("severity_norm") or "Info")
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
    for row in rows:
        # conn.execute (not a cursor context manager): the worker tests drive the supervisor with
        # an AsyncMock connection, and psycopg's AsyncConnection.execute returns the cursor.
        cur = await conn.execute(
            """insert into leads (job_id, lead_id, origin, prev_finding_id, rule_id, tools, category,
                                  category_family, analyzer_severity_raw, severity_norm, located,
                                  path, start_line, end_line, state)
               values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open')
               on conflict (job_id, lead_id) do nothing""",
            row,
        )
        rc = getattr(cur, "rowcount", 0)
        inserted += rc if isinstance(rc, int) and rc > 0 else 0
    return inserted


async def persist_leads_from_pin(conn: psycopg.AsyncConnection, pin_root: Path, job_id: str) -> int:
    """`persist_leads` over the job's leads.json; the hook every family calls before `ready`."""
    return await persist_leads(conn, job_id, load_leads_json(pin_root, job_id))


async def lead_states(conn: psycopg.AsyncConnection, job_id: str) -> dict[str, dict[str, Any]]:
    """``{lead_id: {state, reason, state_ref}}`` for the job (the table is the state of record)."""
    cur = await conn.execute("select lead_id, state, reason, state_ref from leads where job_id = %s", (job_id,))
    rows = await cur.fetchall()
    return {r[0]: {"state": r[1], "reason": r[2], "state_ref": r[3]} for r in rows}
