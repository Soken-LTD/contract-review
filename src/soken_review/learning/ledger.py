"""Learning ledger writers (learning-loop design 2026-10-27, section 2.1, phase P0).

A job's lead and finding outcomes are copied into `lead_outcomes` and `finding_outcomes` when it
is finalized (`review_finalize`) and again when its rows are purged (`review_delete_job` and the
retention sweep, both through `tools.delete.purge_job`), so the counts survive the cascade that
removes the job's own rows. Each write replaces the job's earlier rows (matched by the salted
`job_tag`), so a re-finalize after a render failure or a purge after finalize never double counts.

What is written is the closed set in migration 016: tool, rule, category, family and severity
tokens, outcomes, week, release and salted tags. `config.token()` rejects anything outside the
closed alphabets, so a free-text value (a path, an address, a message) can never reach a row.

Every writer is fail-soft: it runs in a savepoint and logs on error, so the ledger can never stop a
finalize, a delete or a submit.
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta
from typing import Any

from psycopg.rows import dict_row

from ..families import FAMILY_OF_CHAIN
from . import tiers
from .config import current_salt, job_tags, release, tag, token, token_or_none

logger = logging.getLogger(__name__)

_LEAD_SEV = {"Critical", "High", "Medium", "Low", "Info"}
_FINDING_SEV = {"Critical", "High", "Medium", "Low", "Informational"}
_OUTCOME = {"promoted": "promoted", "dismissed": "dismissed", "not_reviewed": "auto_closed",
            "open": "open", "merged": "merged"}
_RECORDED_BY = {"finalize", "purge", "backfill"}


def _week(ts: datetime | None) -> date:
    d = (ts or datetime.now(UTC)).date()
    return d - timedelta(days=d.weekday())


def consent_class(job: dict[str, Any]) -> str:
    """public_code for third-party public-code reviews; private otherwise (owner opt-in is P6)."""
    return "public_code" if job.get("requester_role") == "third_party_public_code" else "private"


def _target_value(job: dict[str, Any]) -> str:
    return str(job.get("target_key") or job.get("source_pin") or job.get("code_hash") or job["job_id"])


def chain_family(job: dict[str, Any], leads: list[dict[str, Any]]) -> str:
    fam = FAMILY_OF_CHAIN.get(str(job.get("chain") or ""))
    if fam:
        return fam
    fams = [str(r.get("category_family") or "") for r in leads if r.get("category_family")]
    return token("family", max(set(fams), key=fams.count) if fams else "", "unknown")


def _sev(value: Any, allowed: set[str]) -> str | None:
    return str(value) if value in allowed else None


async def _fetch(conn: Any, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(query, params)
        return list(await cur.fetchall())


async def _gather(conn: Any, job_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    leads = await _fetch(conn, """select lead_id, rule_id, tools, category, category_family, severity_norm,
                                         state, reason, state_ref
                                  from leads where job_id = %s and origin = 'analyzer'
                                  order by sev_rank desc, path, start_line, lead_id""", (job_id,))
    drafts = await _fetch(conn, """
        select d.draft_key, d.status, d.severity, d.severity_set_by, d.severity_rule, d.evidence_level,
               d.withdrawn_by, d.withdrawn_reason, d.rejected_count, d.current_revision,
               r.category, r.category_family, r.computed_severity, r.severity_rule as rev_rule,
               r.caps_applied, r.content->>'claimed_severity' as claimed,
               (select count(*) from finding_revisions x where x.job_id = d.job_id and x.draft_key = d.draft_key) as revisions,
               (select c.verdict from challenge_answers c where c.job_id = d.job_id and c.draft_key = d.draft_key
                 order by c.revision desc, c.created_at desc limit 1) as verdict,
               (select l.rule_id || chr(9) || coalesce(l.tools[1], '')
                  from finding_leads fl join leads l on l.job_id = fl.job_id and l.lead_id = fl.lead_id
                 where fl.job_id = d.job_id and fl.draft_key = d.draft_key and fl.revision = d.current_revision
                 order by fl.lead_id limit 1) as lead_ref
        from finding_drafts d
        left join finding_revisions r on r.job_id = d.job_id and r.draft_key = d.draft_key
                                     and r.revision = d.current_revision
        where d.job_id = %s order by d.finding_no""", (job_id,))
    return leads, drafts


def lead_rows(job: dict[str, Any], leads: list[dict[str, Any]], drafts: list[dict[str, Any]],
              recorded_by: str) -> list[tuple[Any, ...]]:
    """Ledger rows for the analyzer leads of one job (pure; the anonymisation tests call it)."""
    salt = current_salt()
    common = (_week(job.get("finalized_at")), salt.salt_id, tag("job", job["job_id"], salt),
              tag("target", _target_value(job), salt), tag("principal", str(job.get("principal_key") or ""), salt),
              consent_class(job), chain_family(job, leads))
    version = str(job.get("learning_policy_version") or tiers.baseline_version())
    known = tiers.load_policy(version) is not None
    docs = [{"id": r["lead_id"], "rule_id": r["rule_id"], "tools": r["tools"], "severity_norm": r["severity_norm"],
             "origin": "analyzer"} for r in leads]
    shown, _ = tiers.apply_tiers(docs, version, job["job_id"])
    shown_by_id = {d["id"]: d for d in shown}
    printed = {d["draft_key"]: d["severity"] for d in drafts if d["status"] == "accepted"}
    rel = release()
    out = []
    for r in leads:
        tools_list = r.get("tools") or []
        name, _, ver = str(tools_list[0] if tools_list else "").partition("@")
        view = shown_by_id.get(r["lead_id"], {})
        outcome = _OUTCOME.get(str(r["state"]), "open")
        reason = token("word", r.get("reason"), "other") if outcome == "dismissed" else None
        sev = _sev(r.get("severity_norm"), _LEAD_SEV) or "Info"
        out.append((*common,
                    token("tool", name or tiers.lead_tool(r), "unknown"), token("tool_version", ver, "unknown"),
                    token("rule_id", r.get("rule_id")), token("category", r.get("category"), "unknown"),
                    token("family", r.get("category_family"), "unknown"), sev,
                    _sev(view.get("severity_norm"), _LEAD_SEV) or sev,
                    version if known else "unknown", view.get("tier", "normal") if known else "unknown",
                    outcome, reason,
                    _sev(printed.get(r.get("state_ref") or ""), _FINDING_SEV) if outcome == "promoted" else None,
                    rel, token("word", job.get("state"), "other"), recorded_by))
    return out


def finding_rows(job: dict[str, Any], leads: list[dict[str, Any]], drafts: list[dict[str, Any]],
                 recorded_by: str) -> list[tuple[Any, ...]]:
    salt = current_salt()
    common = (_week(job.get("finalized_at")), salt.salt_id, tag("job", job["job_id"], salt),
              tag("target", _target_value(job), salt), tag("principal", str(job.get("principal_key") or ""), salt),
              consent_class(job), chain_family(job, leads))
    rel = release()
    out = []
    for d in drafts:
        lead_rule, lead_tool = None, None
        if d.get("lead_ref"):
            rule, _, tool = str(d["lead_ref"]).partition("\t")
            lead_rule = token("rule_id", rule)
            lead_tool = token("tool", tool.split("@", 1)[0] or rule.split(":", 1)[0], "unknown")
        caps = [c for c in (token_or_none("cap", x) for x in (d.get("caps_applied") or [])) if c][:12]
        out.append((*common,
                    token("category", d.get("category"), "unknown"), token("family", d.get("category_family"), "unknown"),
                    d["status"], token_or_none("word", d.get("withdrawn_by")), token_or_none("word", d.get("withdrawn_reason")),
                    _sev(d.get("claimed"), _FINDING_SEV), _sev(d.get("computed_severity"), _FINDING_SEV),
                    _sev(d.get("severity"), _FINDING_SEV) if d["status"] == "accepted" else None,
                    token_or_none("word", d.get("severity_set_by")),
                    token_or_none("severity_rule", d.get("severity_rule") or d.get("rev_rule")),
                    caps, token_or_none("word", d.get("evidence_level")), token_or_none("word", d.get("verdict")),
                    lead_rule is not None, lead_tool, lead_rule,
                    int(d.get("rejected_count") or 0), int(d.get("revisions") or 0),
                    rel, token("word", job.get("state"), "other"), recorded_by))
    return out


_GATE_INSERT = """insert into gate_events (week, salt_id, job_tag, principal_tag, draft_tag, chain_family, tool, kind,
                                           error_code, rule_id, warning_class, field, attempt, release)
  values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""


def warning_rows(job: dict[str, Any], stored: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    """Friction rows for the advisory warnings of accepted writes (gate_warnings, migration 017):
    code, rule id, class and field only; the matched text, message and suggestion are dropped."""
    salt = current_salt()
    common = (_week(job.get("finalized_at")), salt.salt_id, tag("job", job["job_id"], salt),
              tag("principal", str(job.get("principal_key") or ""), salt))
    fam = chain_family(job, [])
    rel = release()
    out = []
    for row in stored:
        draft = tag("draft", f"{job['job_id']}\t{row.get('owner_key') or ''}", salt)
        for w in (row.get("warnings") or [])[:200]:
            if not isinstance(w, dict):
                continue
            out.append((*common, draft, fam, token("tool", row.get("tool"), "unknown"), "warning",
                        token("code", w.get("code"), "UNCATALOGUED"), token_or_none("cap", w.get("rule")),
                        token_or_none("word", w.get("class")), token_or_none("field", w.get("field")),
                        int(row.get("revision") or 0), rel))
    return out


_LEAD_INSERT = """insert into lead_outcomes
  (week, salt_id, job_tag, target_tag, principal_tag, consent_class, chain_family, tool, tool_version, rule_id,
   category, category_family, severity_norm, severity_shown, policy_version, tier_shown, outcome, dismiss_reason,
   printed_severity, release, job_state, recorded_by)
  values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
_FINDING_INSERT = """insert into finding_outcomes
  (week, salt_id, job_tag, target_tag, principal_tag, consent_class, chain_family, category, category_family,
   status, withdrawn_by, withdrawn_reason, severity_proposed, severity_computed, severity_printed, severity_set_by,
   severity_rule, caps_applied, evidence_level, challenge_verdict, from_lead, lead_tool, lead_rule, rejected_count,
   revisions, release, job_state, recorded_by)
  values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
          %s, %s)"""


async def record_job(conn: Any, job_id: str, recorded_by: str) -> int:
    """Replace the job's ledger rows with its current outcomes; returns rows written. Runs inside
    the caller's transaction (finalize, purge) or its own (backfill). Raises on a database error;
    callers on the product path use `record_job_safe`."""
    if recorded_by not in _RECORDED_BY:
        raise ValueError(recorded_by)
    rows = await _fetch(conn, "select * from jobs where job_id = %s", (job_id,))
    if not rows:
        return 0
    job = rows[0]
    leads, drafts = await _gather(conn, job_id)
    tags = job_tags(job_id)
    async with conn.cursor() as cur:
        await cur.execute("delete from lead_outcomes where job_tag = any(%s)", (tags,))
        await cur.execute("delete from finding_outcomes where job_tag = any(%s)", (tags,))
        await cur.execute("delete from gate_events where job_tag = any(%s) and kind = 'warning'", (tags,))
        lrows = lead_rows(job, leads, drafts, recorded_by)
        frows = finding_rows(job, leads, drafts, recorded_by)
        wrows = warning_rows(job, await _fetch(conn, "select tool, owner_key, revision, warnings from gate_warnings"
                                                     " where job_id = %s order by id", (job_id,)))
        if lrows:
            await cur.executemany(_LEAD_INSERT, lrows)
        if frows:
            await cur.executemany(_FINDING_INSERT, frows)
        if wrows:
            await cur.executemany(_GATE_INSERT, wrows)
    return len(lrows) + len(frows) + len(wrows)


async def record_job_safe(conn: Any, job_id: str, recorded_by: str) -> int:
    """`record_job` in a savepoint; any error is logged and swallowed (never blocks the caller)."""
    try:
        async with conn.transaction():
            return await record_job(conn, job_id, recorded_by)
    except Exception:  # the ledger never stops finalize, delete or retention
        logger.exception("learning ledger: job %s not recorded (%s)", job_id[-8:], recorded_by)
        return 0


async def record_rejection(conn: Any, job: dict[str, Any], draft_key: str, tool: str,
                           violations: list[dict[str, Any]], attempt: int) -> None:
    """One `gate_events` row per rejected-submit violation: error code and field name only."""
    try:
        salt = current_salt()
        common = (_week(None), salt.salt_id, tag("job", job["job_id"], salt),
                  tag("principal", str(job.get("principal_key") or ""), salt),
                  tag("draft", f"{job['job_id']}\t{draft_key}", salt), chain_family(job, []),
                  token("tool", tool, "unknown"), "rejection")
        rows = [(*common, token("code", v.get("code"), "UNCATALOGUED"), None, None,
                 token_or_none("field", v.get("field")), int(attempt), release())
                for v in violations[:40] if isinstance(v, dict)]
        if not rows:
            return
        async with conn.transaction(), conn.cursor() as cur:
            await cur.executemany(_GATE_INSERT, rows)
    except Exception:  # friction logging never changes a submit result
        logger.exception("learning ledger: gate events not recorded")


async def backfill(conn: Any) -> dict[str, int]:
    """One-off: record every job that still has leads or drafts and no ledger rows yet, with the
    same anonymisation as the product path. Idempotent (a recorded job is skipped). `conn` must be
    in autocommit mode: each job is its own transaction."""
    jobs = await _fetch(conn, """select job_id from jobs j
                                 where (exists (select 1 from leads l where l.job_id = j.job_id)
                                        or exists (select 1 from finding_drafts d where d.job_id = j.job_id))
                                 order by created_at""", ())
    out = {"jobs": 0, "skipped": 0, "rows": 0}
    for row in jobs:
        job_id = row["job_id"]
        async with conn.transaction():
            cur = await conn.execute("select 1 from lead_outcomes where job_tag = any(%s) union all "
                                     "select 1 from finding_outcomes where job_tag = any(%s) limit 1",
                                     (job_tags(job_id), job_tags(job_id)))
            if await cur.fetchone():
                out["skipped"] += 1
                continue
            out["rows"] += await record_job(conn, job_id, "backfill")
            out["jobs"] += 1
    return out
