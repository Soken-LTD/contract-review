"""Handler for review_finalize (03 §4.14, 04 §13).

Registered via @handler("review_finalize").

Finalize checks F1-F6, F8 (03 §4.14 table, 04 §13 table).
On pass: run the full text-gate pre-freeze check (same function as render-time check_strings),
then auto-close Low/Info analyzer leads, recompute effective severity (phase finalize),
assign final ids per severity/finding_no order, set finalized, queue render.
Idempotent: returns stored result if already finalized.

render_failed recovery: calling review_finalize on a render_failed job resets the job to
ready (state machine: render_failed -> ready) and returns E_RENDER_FAILED with the stored
gate error so the model knows which text to fix.  report_at and report_id are cleared by
render.py when the failure is recorded, so the quota refund happens automatically and the
next finalize re-issues them under the advisory lock.

Also exports `compute_finalize_checks(conn, job_id)` used by review_status (03 §4.2
finalize_checks[]) so both share one implementation.

Ambiguities: docs/w0/submit-finalize-ambiguities.md.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import psycopg
import psycopg_pool
from psycopg.rows import dict_row

from .. import quota
from ..db.job_repo import JobRepo
from ..db.pool import get_pool
from ..engine.severity import SeverityContext, compute_severity
from ..engine.text_gate import check_model_field
from ..errors import ReviewError
from ..mapping.build import load_map
from ..mapping.semantic_evm import detect_token_review, units_holding
from ..report.render import queue_render
from ..server import handler
from .context import JobContext
from .coverage import EnumsLoadError, category_allowed_na_reasons, compute_coverage_rows
from .set_section import _check_na_predicate_for_section
from .submit import _category_info, _family_from_chain

_pool: psycopg_pool.AsyncConnectionPool | None = None
_ctx: JobContext | None = None


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
        raise ReviewError("E_INTERNAL", incident="finalize not wired (ctx is None)")
    return _ctx


# ── Severity helpers ──────────────────────────────────────────────────────────

_SEVS = ("Informational", "Low", "Medium", "High", "Critical")
_SEV_RANK: dict[str, int] = {s: i for i, s in enumerate(_SEVS)}
_FINAL_ID_PREFIX = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}


# ── report_id derivation (ambiguity SF-007) ────────────────────────────────────

_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def _derive_report_id(job_id: str) -> str:
    """Deterministic report_id from job_id: base32(sha256(job_id))[:26] (03 §4.15)."""
    digest = hashlib.sha256(job_id.encode()).hexdigest()
    return "".join(_B32[int(c, 16) * 2] for c in digest[:26])


# ── F-check queries ───────────────────────────────────────────────────────────

def _loc_quotes(draft_row: dict[str, Any]) -> list[dict[str, Any]]:
    """Location quotes of a draft row as the finalize query returns them (jsonb list or JSON text)."""
    raw = draft_row.get("location_quotes")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return []
    return [q for q in (raw or []) if isinstance(q, dict)]


async def compute_finalize_checks(
    conn: psycopg.AsyncConnection, job_id: str
) -> list[dict[str, Any]]:
    """Return list of {id, open, tool} for F1 to F6 and F8 (03 §4.2, §4.14).

    open=True means the check has not been satisfied; tool is the closing tool name.
    """
    checks: list[dict[str, Any]] = []

    # F1: jobs.tier null or D
    async with conn.cursor() as cur:
        await cur.execute("select tier from jobs where job_id = %s", (job_id,))
        row = await cur.fetchone()
        tier = row[0] if row else None
    f1_open = tier is None or tier == "D"
    # F1 has no closing tool (tier is set externally); omit key entirely (schema: string, not nullable)
    # open is integer per schema (1=open, 0=closed)
    checks.append({"id": "F1", "open": int(f1_open)})

    # F2: open High/Medium analyzer leads + broken duplicate chains
    async with conn.cursor() as cur:
        # Open High/Medium analyzer leads
        await cur.execute(
            """select count(*) from leads
               where job_id = %s and origin = 'analyzer'
                 and severity_norm in ('High','Medium') and state = 'open'""",
            (job_id,),
        )
        open_hm = (await cur.fetchone())[0]

        # Duplicate-chain integrity (recursive walk per 03 §4.14 SQL)
        # We run a simplified version: check chains that end at a non-qualified target
        await cur.execute(
            """with recursive walk (origin, origin_rank, cat, op, os, oe, ref, hops) as (
                 select l.lead_id, l.sev_rank, l.category, l.path, l.start_line, l.end_line, l.state_ref, 1
                 from leads l
                 where l.job_id = %(job)s and l.state = 'dismissed' and l.reason = 'duplicate_of'
                   and l.severity_norm in ('High','Medium')
                 union all
                 select w.origin, w.origin_rank, w.cat, w.op, w.os, w.oe, t.state_ref, w.hops + 1
                 from walk w join leads t on t.job_id = %(job)s and t.lead_id = w.ref
                 where w.hops < 8 and t.state_ref is not null
                   and (t.state = 'promoted' or (t.state = 'dismissed' and t.reason = 'duplicate_of'))
               ) cycle ref set is_cycle using path,
               terminal as (select distinct on (origin) origin, origin_rank, cat, op, os, oe, ref, hops, is_cycle
                            from walk order by origin, hops desc)
               select count(*) from terminal t
               where t.is_cycle or t.hops >= 8 or t.ref like 'LEAD-%%'
                  or not exists (
                       select 1 from finding_drafts d join finding_revisions r
                            on r.job_id = d.job_id and r.draft_key = d.draft_key and r.revision = d.current_revision
                         where d.job_id = %(job)s and d.draft_key = t.ref
                           and d.status in ('accepted','needs_challenge') and r.category = t.cat
                           and exists (select 1 from finding_quote_ranges q where q.job_id = %(job)s
                             and q.draft_key = d.draft_key and q.revision = d.current_revision and q.role = 'location'
                             and q.path = t.op and q.start_line <= t.oe and q.end_line >= t.os)
                           and (case d.severity when 'Critical' then 5 when 'High' then 4 when 'Medium' then 3
                                when 'Low' then 2 else 1 end) >= t.origin_rank)
               """,
            {"job": job_id},
        )
        chain_broken = (await cur.fetchone())[0]

    f2_open = bool(open_hm + chain_broken)
    checks.append({"id": "F2", "open": int(f2_open), **({"tool": "review_dismiss_lead"} if f2_open else {})})

    # F3: findings in needs_challenge
    async with conn.cursor() as cur:
        await cur.execute(
            "select count(*) from finding_drafts where job_id = %s and status = 'needs_challenge'",
            (job_id,),
        )
        f3_count = (await cur.fetchone())[0]
    f3_open = f3_count > 0
    checks.append({"id": "F3", "open": int(f3_open), **({"tool": "review_answer_challenge"} if f3_open else {})})

    # F4: promoted leads whose draft is withdrawn (invariant)
    async with conn.cursor() as cur:
        await cur.execute(
            """select count(*) from leads l
               join finding_drafts d on d.job_id = l.job_id and d.draft_key = l.state_ref
               where l.job_id = %s and l.state = 'promoted' and d.status = 'withdrawn'""",
            (job_id,),
        )
        f4_count = (await cur.fetchone())[0]
    f4_open = f4_count > 0
    checks.append({"id": "F4", "open": int(f4_open)})  # invariant: no closing tool; omit key (schema: string, not nullable)

    # F5: server-computed coverage (04 §13 / SF-003).
    # The server always produces one row per family category (read/partially_read/not_covered/
    # no_candidates) — not_covered does NOT block.  F5 is open only when an accepted N/A
    # override row's predicate is no longer true (04 E9).
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("select chain from jobs where job_id = %s", (job_id,))
        chain_row = await cur.fetchone()
    f5_family = _family_from_chain(chain_row["chain"] if chain_row else None)

    try:
        _pin_root = _get_ctx().get_pin_root()
        f5_map_doc, _ = load_map(_pin_root, job_id)
    except FileNotFoundError:
        f5_map_doc = None  # map worker not run yet; not_covered is spec-correct
    except (OSError, ValueError) as exc:
        raise ReviewError("E_INTERNAL", incident=f"map load failed (corrupt/unreadable): {exc}") from exc

    # Build job_reads_index for coverage computation
    f5_reads_index: dict[str, list[tuple[int, int]]] = {}
    async with conn.cursor() as cur:
        await cur.execute(
            "select path, start_line, end_line from job_reads where job_id = %s",
            (job_id,),
        )
        async for f_path, f_start, f_end in cur:
            f5_reads_index.setdefault(f_path, []).append((f_start, f_end))

    try:
        f5_coverage_rows = compute_coverage_rows(f5_family, f5_map_doc, f5_reads_index)
    except EnumsLoadError as exc:
        raise ReviewError("E_INTERNAL", incident=f"enums.yaml unavailable: {exc}") from exc

    # Check N/A override rows: if any accepted N/A predicate is no longer true → F5 re-opens
    # Also open F5 if coverage computation found a configuration error (zero categories).
    f5_open = any(r.get("status") == "configuration_error" for r in f5_coverage_rows)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select content from sections
               where job_id = %s and section = 'coverage'
               order by revision desc limit 1""",
            (job_id,),
        )
        f5_sec = await cur.fetchone()

    if f5_sec:
        for na_row in (f5_sec["content"] or []):
            na_reason = na_row.get("reason", "")
            na_area = na_row.get("area_id", "")
            if na_reason:
                # Re-check category binding: reason must still be allowed for this category
                if na_area and na_reason not in category_allowed_na_reasons(f5_family, na_area):
                    f5_open = True
                    break
                pred = _check_na_predicate_for_section(na_reason, f5_family, f5_map_doc)
                if pred != "true":
                    f5_open = True
                    break

    checks.append({"id": "F5", "open": int(f5_open), **({"tool": "review_set_section"} if f5_open else {})})

    # F6: placeholder resolution (fact/calc/finding placeholders unresolved)
    # W0: simplified check via placeholder_refs table
    async with conn.cursor() as cur:
        await cur.execute(
            """select count(*) from placeholder_refs
               where job_id = %s and resolved = false""",
            (job_id,),
        )
        unresolved_count = (await cur.fetchone())[0]
    f6_open = unresolved_count > 0
    checks.append({"id": "F6", "open": int(f6_open), **({"tool": "review_submit_finding"} if f6_open else {})})

    # F8: findings in needs_text
    async with conn.cursor() as cur:
        await cur.execute(
            "select count(*) from finding_drafts where job_id = %s and status = 'needs_text'",
            (job_id,),
        )
        f8_count = (await cur.fetchone())[0]
    f8_open = f8_count > 0
    checks.append({"id": "F8", "open": int(f8_open), **({"tool": "review_submit_finding"} if f8_open else {})})

    return checks


# ── Final-id assignment ───────────────────────────────────────────────────────

def _final_id(prefix: str, n: int) -> str:
    return f"{prefix}-{n:03d}"


async def _assign_final_ids(
    conn: psycopg.AsyncConnection, job_id: str
) -> tuple[dict[str, str], list[dict[str, Any]], int]:
    """Assign final ids per 03 §4.14 order and return (final_ids_map, open_carried_leads, leads_not_reviewed).

    Order: per severity (Critical->Informational), open finding_drafts by finding_no,
    then carried leads at that sev_rank (fixed, then not_reviewed), by lead_id.
    """
    # Recompute effective severity at finalize phase via the full K-cap chain.
    # K4 (reasoning_only → Low), K8 (Critical without E3+attack_steps+no open downgrade → High),
    # K10 (map_unavailable → High), K11 (generic + no analyzer lead → High).
    # W0 defaults: downgrade_items_present=0, open_downgrade_item=False, scope_not_covered=False.
    # Retail-token profile (04 §7.4): computed once from the persisted semantic map; applies to
    # every draft of this job. per-draft `has_location_quote` comes from finding_quote_ranges.
    f_map_doc, _ = load_map(_get_ctx().get_pin_root(), job_id)
    f_semantic = f_map_doc.get("semantic") if f_map_doc else None
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select d.draft_key, d.finding_no, d.severity, d.evidence_level,
                      d.current_revision,
                      r.category, r.category_family, r.impact_class,
                      r.content->>'matrix' as matrix_json,
                      d.matrix_effective,
                      r.map_unavailable,
                      jsonb_array_length(coalesce(r.content->'attack_steps', '[]'::jsonb)) > 0
                          as has_attack_steps,
                      exists (select 1 from finding_quote_ranges q
                              where q.job_id = d.job_id and q.draft_key = d.draft_key
                                and q.revision = d.current_revision and q.role = 'location')
                          as has_location_quote,
                      (select coalesce(jsonb_agg(jsonb_build_object('file', q.path, 'start', q.start_line, 'end', q.end_line)), '[]'::jsonb)
                         from finding_quote_ranges q
                        where q.job_id = d.job_id and q.draft_key = d.draft_key
                          and q.revision = d.current_revision and q.role = 'location') as location_quotes,
                      d.status
               from finding_drafts d
               join finding_revisions r on r.job_id = d.job_id and r.draft_key = d.draft_key
                 and r.revision = d.current_revision
               where d.job_id = %s and d.status in ('accepted', 'needs_challenge')
               order by d.finding_no""",
            (job_id,),
        )
        drafts = await cur.fetchall()

    # Build set of draft_keys that have an analyzer lead with same category (for K11).
    # IMPORTANT: restrict to current_revision AND lead currently promoted by this draft
    # (state='promoted', state_ref=draft_key). Old revisions that linked a lead which was
    # later unlinked (lead back to open/promoted by another draft) must NOT count —
    # otherwise K11 never fires after a model drops its analyzer lead in revision 2+.
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select distinct d.draft_key
               from finding_drafts d
               join finding_leads fl on fl.job_id = d.job_id
                 and fl.draft_key = d.draft_key and fl.revision = d.current_revision
               join leads l on l.job_id = d.job_id and l.lead_id = fl.lead_id
                 and l.state = 'promoted' and l.state_ref = d.draft_key
                 and l.origin = 'analyzer'
               join finding_revisions r on r.job_id = d.job_id
                 and r.draft_key = d.draft_key and r.revision = d.current_revision
               where d.job_id = %s and l.category = r.category""",
            (job_id,),
        )
        analyzer_lead_draft_keys: set[str] = {row["draft_key"] for row in await cur.fetchall()}

    # For each draft, recompute severity at finalize using compute_severity (one implementation)
    effective_severities: dict[str, str] = {}
    for d in drafts:
        stored_sev = d["severity"] or "Informational"
        ev_level = d.get("evidence_level") or "reasoning_only"
        map_unavail = bool(d.get("map_unavailable", False))
        has_attack_steps = bool(d.get("has_attack_steps", False))

        # The post-challenge matrix (basis fallbacks applied, 04 8.2) is the one the reviewer
        # defended; recomputing from the submitted matrix re-raised a challenge-downgraded
        # Critical->High back to Critical in the PDF (c2 re-run, 2026-10-23).
        matrix_raw = d.get("matrix_json")
        try:
            eff = d.get("matrix_effective")
            if isinstance(eff, str):
                eff = json.loads(eff)
            matrix = dict(eff) if isinstance(eff, dict) and eff else (json.loads(matrix_raw) if matrix_raw else {})
        except (ValueError, TypeError):
            # Corrupt stored JSON — cannot compute severity safely; block finalize
            raise ReviewError(
                "E_INTERNAL",
                incident=f"corrupt matrix_json for draft {d['draft_key']!s:.40}",
            )

        cat_info = _category_info(d["category"]) if d.get("category") else {}

        # Read challenge_answers for this draft to get real downgrade counts (04 §8.1).
        # At finalize F3 guarantees no needs_challenge findings exist, so open_downgrade_item
        # is always False.  scope_not_covered is derived from stored items (K10).
        async with conn.cursor(row_factory=dict_row) as cur2:
            await cur2.execute(
                """select items, answers from challenge_answers
                   where job_id = %s and draft_key = %s and revision = %s""",
                (job_id, d["draft_key"], d["current_revision"]),
            )
            ca_row = await cur2.fetchone()

        if ca_row is not None:
            ca_items = ca_row["items"] if isinstance(ca_row["items"], list) else []
            ca_answers = ca_row["answers"] if isinstance(ca_row["answers"], list) else []
            ca_by_id = {a["item_id"]: a for a in ca_answers if isinstance(a, dict)}
            downgrade_count = sum(
                1 for item in ca_items
                if isinstance(item, dict) and item.get("kind") == "downgrade"
                and ca_by_id.get(item.get("id", ""), {}).get("value") == "present"
            )
            scope_not_cov = any(
                isinstance(item, dict) and item.get("scope", {}).get("not_covered", False)
                for item in ca_items
            )
        else:
            # No challenge taken (Low/Info findings go directly to accepted)
            downgrade_count = 0
            scope_not_cov = False

        sev_ctx = SeverityContext(
            phase="finalize",
            evidence_level=ev_level,
            has_attack_steps=has_attack_steps,
            open_downgrade_item=False,          # F3 guarantees no needs_challenge
            downgrade_items_present=downgrade_count,
            scope_not_covered=scope_not_cov,    # from challenge_answers items
            map_unavailable=map_unavail,
            category_generic=bool(cat_info.get("generic", False)) if cat_info else False,
            category_max_severity=cat_info.get("max_severity") if cat_info else None,
            linked_lead_same_cat=d["draft_key"] in analyzer_lead_draft_keys,
            # per finding: the unit holding the location decides the retail-token profile
            token_review=detect_token_review(f_semantic, units_holding(f_semantic, _loc_quotes(d))),
            has_location_quote=bool(d["has_location_quote"]),
        )

        if matrix:
            # A KeyError/ValueError here means the stored matrix enum is invalid.
            # This is an internal consistency error — block finalize rather than accept
            # with uncapped severity (fail-closed: broken stored data must be investigated).
            sev_result = compute_severity(matrix, "finalize", sev_ctx)
            finalize_sev = sev_result.severity
            finalize_caps = sev_result.caps_applied
        else:
            finalize_sev = stored_sev
            finalize_caps = []

        effective_severities[d["draft_key"]] = finalize_sev
        # Update the draft with recomputed severity and caps
        if finalize_sev != stored_sev or finalize_caps:
            # caps_applied is text[] in the schema; pass as Python list (psycopg3 converts)
            await conn.execute(
                """update finding_drafts set severity = %s, caps_applied = %s
                   where job_id = %s and draft_key = %s""",
                (finalize_sev, finalize_caps, job_id, d["draft_key"]),
            )

    # Group drafts by effective severity
    by_sev: dict[str, list[dict[str, Any]]] = {s: [] for s in _SEVS}
    for d in drafts:
        sev = effective_severities.get(d["draft_key"], d["severity"] or "Informational")
        by_sev[sev].append(d)

    # Assign final ids: per severity, sorted by finding_no
    final_ids: dict[str, str] = {}
    counters: dict[str, int] = {s: 1 for s in _SEVS}

    # Process severities Critical -> Informational
    for sev in reversed(_SEVS):  # Informational, Low, Medium, High, Critical -> reversed = Critical first
        for d in sorted(by_sev[sev], key=lambda x: x["finding_no"]):
            prefix = _FINAL_ID_PREFIX[sev]
            fid = _final_id(prefix, counters[sev])
            counters[sev] += 1
            draft_key = d["draft_key"]
            final_ids[f"F-{d['finding_no']:02d}"] = fid
            await conn.execute(
                "update finding_drafts set final_id = %s where job_id = %s and draft_key = %s",
                (fid, job_id, draft_key),
            )

    # Auto-close Low and Info analyzer leads, open carried leads as not_reviewed
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select lead_id, origin, severity_norm, state from leads
               where job_id = %s and state in ('open', 'not_reviewed')""",
            (job_id,),
        )
        open_leads = await cur.fetchall()

    leads_not_reviewed = 0
    carried_lead_final_ids: list[dict[str, Any]] = []

    for lead in open_leads:
        if lead["origin"] == "analyzer" and lead["severity_norm"] in ("Low", "Info"):
            # Auto-close as not_reviewed
            await conn.execute(
                "update leads set state = 'not_reviewed' where job_id = %s and lead_id = %s",
                (job_id, lead["lead_id"]),
            )
            leads_not_reviewed += 1
        elif lead["origin"] == "previous_report":
            # Carried leads: open at finalize -> not_reviewed (printed "Not verified as fixed")
            await conn.execute(
                "update leads set state = 'not_reviewed' where job_id = %s and lead_id = %s",
                (job_id, lead["lead_id"]),
            )
            leads_not_reviewed += 1
            carried_lead_final_ids.append(lead)

    # Assign final ids to carried leads at their sev_rank
    # (Fixed first, then not_reviewed, by lead_id, within the same sev_rank as findings)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select lead_id, severity_norm, state, origin from leads
               where job_id = %s and origin = 'previous_report'
               order by sev_rank desc, lead_id""",
            (job_id,),
        )
        carried_leads = await cur.fetchall()

    for lead in carried_leads:
        sev = {"Critical": "Critical", "High": "High", "Medium": "Medium",
               "Low": "Low", "Info": "Informational"}.get(lead["severity_norm"], "Informational")
        # Assign next final id in this severity bucket
        prefix = _FINAL_ID_PREFIX[sev]
        fid = _final_id(prefix, counters[sev])
        counters[sev] += 1
        final_ids[lead["lead_id"]] = fid

    return final_ids, carried_leads, leads_not_reviewed


# ── Pre-freeze text gate ──────────────────────────────────────────────────────

async def _check_gate_violations(conn: psycopg.AsyncConnection, job_id: str, profile: str) -> list[dict[str, Any]]:
    """Run the FULL model-scope text gate on all report text before freezing (04 §11.4).

    Queries every accepted finding's prose fields and every section's text fields from the
    DB and calls ``check_model_field`` with NO rule-skipping so enforcement is never weaker
    than write-time.  ``absence_claims`` are extracted from the stored finding content to
    provide T24 its binding context.

    The render builder (``build.check_strings``) is the only place ``LATE_GATE_SKIP`` is
    applied; this pre-freeze gate is not the render builder.

    Returns a list of error envelope dicts (empty = clean).
    """
    errors: list[dict[str, Any]] = []

    # ── Finding text ──────────────────────────────────────────────────────────
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select d.draft_key, d.finding_no, r.content
               from finding_drafts d
               join finding_revisions r
                 on r.job_id = d.job_id and r.draft_key = d.draft_key
                    and r.revision = d.current_revision
               where d.job_id = %s and d.status in ('accepted', 'needs_challenge')""",
            (job_id,),
        )
        drafts = await cur.fetchall()

    for d in drafts:
        content = d["content"] or {}
        finding_ref = f"F-{d['finding_no']:02d}"
        # Extract absence_claims from stored content so T24 can bind them (04 §7.6).
        absence_claims: list[dict[str, str]] = content.get("absence_claims") or []
        # title
        if title := content.get("title"):
            for v in check_model_field(title, field="title", profile=profile,
                                       absence_claims=absence_claims):
                errors.append(ReviewError(
                    v.code, rule=v.rule_id, match=v.match[:80], cp=v.match[:5],
                    pos=v.span[0], token=v.match[:40],
                    hint=f"{finding_ref}.title: rule {v.rule_id} on {v.match!r:.40}",
                ).envelope())
        # body fields: description, impact, recommendation
        body = content.get("body") or {}
        for field_name in ("description", "impact", "recommendation"):
            for block in (body.get(field_name) or []):
                text = block.get("p") or ""
                if text:
                    for v in check_model_field(text, field=field_name, profile=profile,
                                               absence_claims=absence_claims):
                        errors.append(ReviewError(
                            v.code, rule=v.rule_id, match=v.match[:80], cp=v.match[:5],
                            pos=v.span[0], token=v.match[:40],
                            hint=f"{finding_ref}.{field_name}: rule {v.rule_id} on {v.match!r:.40}",
                        ).envelope())
                for item in block.get("ul") or []:
                    for v in check_model_field(str(item), field=field_name, profile=profile,
                                               is_list_item=True, absence_claims=absence_claims):
                        errors.append(ReviewError(
                            v.code, rule=v.rule_id, match=v.match[:80], cp=v.match[:5],
                            pos=v.span[0], token=v.match[:40],
                            hint=f"{finding_ref}.{field_name}[ul]: rule {v.rule_id} on {v.match!r:.40}",
                        ).envelope())
        # attack_steps
        for step in (content.get("attack_steps") or []):
            text = step.get("text") or ""
            if text:
                for v in check_model_field(text, field="attack_steps", profile=profile,
                                           absence_claims=absence_claims):
                    errors.append(ReviewError(
                        v.code, rule=v.rule_id, match=v.match[:80], cp=v.match[:5],
                        pos=v.span[0], token=v.match[:40],
                        hint=f"{finding_ref}.attack_steps: rule {v.rule_id} on {v.match!r:.40}",
                    ).envelope())
        # notes (top-level notes in body)
        for note in (body.get("notes") or []):
            text = note.get("p") or ""
            if text:
                for v in check_model_field(text, field="notes", profile=profile,
                                           absence_claims=absence_claims):
                    errors.append(ReviewError(
                        v.code, rule=v.rule_id, match=v.match[:80], cp=v.match[:5],
                        pos=v.span[0], token=v.match[:40],
                        hint=f"{finding_ref}.notes: rule {v.rule_id} on {v.match!r:.40}",
                    ).envelope())

    # ── Section text ──────────────────────────────────────────────────────────
    # sections: roles_notes and context_notes contain model prose; out_of_scope_reasons
    # is also model prose.  coverage content is structured (N/A rows), not prose.
    _SEC_FIELD: dict[str, str] = {
        "roles_notes": "notes",
        "context_notes": "notes",
        "out_of_scope_reasons": "notes",
    }
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select section, content from sections
               where job_id = %s and section = any(%s)
               order by revision desc""",
            (job_id, list(_SEC_FIELD.keys())),
        )
        all_sec = await cur.fetchall()

    seen_sections: set[str] = set()
    for sec in all_sec:
        sec_name = sec["section"]
        if sec_name in seen_sections:
            continue  # only the latest revision counts
        seen_sections.add(sec_name)
        field = _SEC_FIELD[sec_name]
        for block in (sec["content"] or []):
            text = block.get("p") or block.get("reason") or ""
            is_li = False
            if isinstance(block, dict) and "ul" in block:
                for item in block["ul"] or []:
                    for v in check_model_field(str(item), field=field, profile=profile, is_list_item=True):
                        errors.append(ReviewError(
                            v.code, rule=v.rule_id, match=v.match[:80], cp=v.match[:5],
                            pos=v.span[0], token=v.match[:40],
                            hint=f"{sec_name}[ul]: rule {v.rule_id} on {v.match!r:.40}",
                        ).envelope())
                continue
            if text:
                for v in check_model_field(text, field=field, profile=profile, is_list_item=is_li):
                    errors.append(ReviewError(
                        v.code, rule=v.rule_id, match=v.match[:80], cp=v.match[:5],
                        pos=v.span[0], token=v.match[:40],
                        hint=f"{sec_name}: rule {v.rule_id} on {v.match!r:.40}",
                    ).envelope())

    return errors


# ── Main handler ──────────────────────────────────────────────────────────────

@handler("review_finalize")
async def handle_review_finalize(args: dict[str, Any]) -> dict[str, Any]:
    """Finalize a job: run checks, assign ids, queue render (03 §4.14).

    Per 03 §7.1: open items return a rejection (accepted: false) with E_FINALIZE_OPEN.
    Idempotent: if already finalized (or beyond), returns the stored result.

    render_failed recovery: if called on a render_failed job, resets the job to ready
    and returns E_RENDER_FAILED with the stored gate error so the model can revise the
    text and call review_finalize again.
    """
    job_id: str = args["job_id"]
    pool = _get_pool()

    async with pool.connection() as conn, conn.transaction():
        # ── Lock job row ──────────────────────────────────────────────
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from jobs where job_id = %s for update", (job_id,))
            job = await cur.fetchone()

        if job is None:
            raise ReviewError("E_JOB_NOT_FOUND")

        state = job["state"]

        # ── render_failed recovery (03 §4.14 recovery path) ──────────
        # Calling review_finalize on a render_failed job resets it to ready so the
        # model can revise the flagged text and finalize again.  The stored gate error
        # is surfaced here; report_at and report_id were already cleared in render.py.
        if state == "render_failed":
            repo = JobRepo(conn)
            await repo.transition(job_id, "ready")
            await conn.execute("update jobs set last_call_at = now() where job_id = %s", (job_id,))
            stored_detail = job.get("error_detail") or {}
            return {
                "accepted": False,
                "state": "ready",
                "errors": [ReviewError("E_RENDER_FAILED",
                                       detail=json.dumps(stored_detail)[:300]).envelope()],
                "hint": (
                    "Job reset to ready; revise the flagged text (see 'detail') "
                    "and call review_finalize again."
                ),
            }

        # ── Idempotent replay (ambiguity SF-008) ──────────────────────
        if state in ("finalized", "render_queued", "rendering", "rendered"):
            return await _stored_finalize_result(conn, job_id, state)

        # ── State check ───────────────────────────────────────────────
        if state in ("insufficient_source", "failed", "expired", "deleted"):
            return {"accepted": False, "errors": [
                ReviewError("E_JOB_TERMINAL", state=state, exit_code=job.get("error_code", "")).envelope()
            ]}
        if state != "ready":
            return {"accepted": False, "errors": [
                ReviewError("E_JOB_NOT_READY", state=state, eta_s=0).envelope()
            ]}

        # ── Run finalize checks ────────────────────────────────────────
        checks = await compute_finalize_checks(conn, job_id)
        open_checks = [c for c in checks if c["open"]]

        if open_checks:
            items = [
                {"id": c["id"], "open": 1, **({"tool": c["tool"]} if c.get("tool") else {})}
                for c in open_checks[:40]
            ]
            return {
                "accepted": False,
                "errors": [ReviewError("E_FINALIZE_OPEN", items=str([c["id"] for c in open_checks[:40]])).envelope()],
                "items": items,
            }

        # ── Pre-freeze text gate (04 §11.4 render parity) ─────────────
        # Run the full model-scope text gate on all report prose before freezing so
        # a render-time late_gate failure can never happen on text that passed write
        # time (e.g. a T27 phrase added to the rule list after the finding was submitted).
        job_profile = "owner" if job.get("ownership_proven") else "public_review"
        gate_errors = await _check_gate_violations(conn, job_id, job_profile)
        if gate_errors:
            return {
                "accepted": False,
                "errors": [ReviewError("E_FINALIZE_OPEN",
                                       items="gate_violations").envelope()],
                "gate_violations": gate_errors[:40],
            }

        # ── All checks pass: finalize ──────────────────────────────────

        # Daily report quota (quota.py): this is where a report is issued, so the count is
        # taken under an advisory lock per key; a refusal leaves the job ready for tomorrow.
        try:
            await quota.check(conn, job.get("limit_key"), job_id=job_id, lock=True)
        except ReviewError as exc:
            return {"accepted": False, "errors": [exc.envelope()]}

        # Assign report_id (SF-007)
        report_id = _derive_report_id(job_id)
        await conn.execute(
            "update jobs set report_id = %s, report_at = now() where job_id = %s and report_id is null",
            (report_id, job_id),
        )

        # Assign final ids, close open leads
        final_ids, _carried, leads_not_reviewed = await _assign_final_ids(conn, job_id)

        # Transition: ready -> finalized
        repo = JobRepo(conn)
        await repo.transition(job_id, "finalized")

        # Queue render: finalized -> render_queued
        await queue_render(conn, job_id)

        await conn.execute("update jobs set last_call_at = now() where job_id = %s", (job_id,))

        return {
            "accepted": True,
            "state": "render_queued",
            "final_ids": final_ids,
            "leads_not_reviewed": leads_not_reviewed,
            "poll_after_s": 2,
        }


async def _stored_finalize_result(
    conn: psycopg.AsyncConnection, job_id: str, state: str
) -> dict[str, Any]:
    """Return the stored finalize result for idempotent replay."""
    # Reconstruct from DB: final ids from finding_drafts.final_id + carried leads
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select d.finding_no, d.final_id from finding_drafts d
               where d.job_id = %s and d.final_id is not null
               order by d.finding_no""",
            (job_id,),
        )
        draft_rows = await cur.fetchall()

    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select lead_id, severity_norm, state from leads
               where job_id = %s and origin = 'previous_report'
               order by sev_rank desc, lead_id""",
            (job_id,),
        )
        carried_rows = await cur.fetchall()

    async with conn.cursor() as cur:
        await cur.execute(
            "select count(*) from leads where job_id = %s and state = 'not_reviewed'",
            (job_id,),
        )
        not_reviewed = (await cur.fetchone())[0]

    final_ids: dict[str, str] = {}
    for row in draft_rows:
        final_ids[f"F-{row['finding_no']:02d}"] = row["final_id"]
    for row in carried_rows:
        # Carried leads assigned final ids during the original finalize pass
        # We don't store them separately; for idempotency return what we have
        pass

    return {
        "accepted": True,
        "state": state,
        "final_ids": final_ids,
        "leads_not_reviewed": not_reviewed,
        "poll_after_s": 2,
    }
