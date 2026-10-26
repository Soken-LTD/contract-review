"""Handler for review_set_section (03 §4.13).

Registered via @handler("review_set_section").

Four sections:
  roles_notes          – notes on protocol roles (owner, admin, pauser, …)
  out_of_scope_reasons – files/directories excluded from the audit scope
  coverage             – per-category area coverage rows
  context_notes        – reviewer prose on the project documents (context ingestion spec 6, 7):
                         1..8 model blocks ({p} | {ul} | {table}), text gate scope model and the
                         number check on every string; printed under "Project context"

For F5, a coverage section with at least one row closes the check.
Idempotent by content_hash: same content → return existing revision unchanged.

Sections schema (DB):
  (job_id, section, revision) primary key
  content: JSONB
  content_hash: SHA-256 of canonical JSON

Validation:
  V5/V6: text gate and number check on all text fields
  coverage not_applicable: predicate must be confirmable (else E_COVERAGE_NA_UNCONFIRMED)
  section content is JSON validated at schema level (V0) before this handler
"""

from __future__ import annotations

import hashlib
import json
from functools import cache
from pathlib import Path
from typing import Any

import psycopg_pool
import yaml
from psycopg.rows import dict_row

from ..db.pool import get_pool
from ..engine.numbers import lex_numbers
from ..engine.text_gate import check_model_field
from ..errors import ReviewError
from ..mapping.build import load_map
from ..mapping.lifecycle import load_lifecycle, rubric
from ..server import handler
from .context import JobContext
from .coverage import (
    EnumsLoadError,
    category_allowed_na_reasons,
    compute_coverage_rows,
    family_categories,
)
from .coverage import (
    rows_index as cov_rows_index,
)
from .submit import _family_from_chain
from .walks import latest_rows, load_drafts, load_reads, merge_rows, open_walks, validate_row, walk_index

RUBRIC_DIR = Path(__file__).resolve().parents[3] / "contract" / "rubric"

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
        from ..errors import ReviewError
        raise ReviewError("E_INTERNAL", incident="set_section not wired (ctx is None)")
    return _ctx


_FROZEN_STATES = frozenset({"finalized", "render_queued", "rendering", "rendered", "render_failed"})
_TERMINAL_STATES = frozenset({"insufficient_source", "failed", "expired", "deleted"})
_SECTIONS = ("roles_notes", "out_of_scope_reasons", "coverage", "context_notes", "invariant_walks")  # enums.yaml `section`
# context_notes block limits: finding.v1 `block` (the tools.v1 `context_notes.notes` items) and the
# report schema `context.notes` (max 8 model blocks).
_CTX_MAX_BLOCKS, _CTX_P_MAX, _CTX_UL_MAX, _CTX_UL_ITEM_MAX = 8, 900, 8, 300
_CTX_HEAD_MAX, _CTX_HEAD_CELL_MAX, _CTX_ROWS_MAX, _CTX_COLS_MAX, _CTX_CELL_MAX = 6, 60, 12, 6, 300


def _check_context_blocks(content: Any) -> str | None:
    """Shape check for context_notes blocks; returns the E_SECTION_INVALID detail or None."""
    if len(content) > _CTX_MAX_BLOCKS:
        return f"context_notes: at most {_CTX_MAX_BLOCKS} blocks (got {len(content)})"
    for i, b in enumerate(content):
        if not isinstance(b, dict) or len(b) != 1 or next(iter(b)) not in ("p", "ul", "table"):
            return f"context_notes[{i}]: block must be one of {{p}}, {{ul}}, {{table}}"
        if "p" in b:
            if not isinstance(b["p"], str) or not 1 <= len(b["p"]) <= _CTX_P_MAX:
                return f"context_notes[{i}].p: string of 1..{_CTX_P_MAX} characters"
        elif "ul" in b:
            ul = b["ul"]
            if not isinstance(ul, list) or not 1 <= len(ul) <= _CTX_UL_MAX or not all(
                    isinstance(s, str) and 1 <= len(s) <= _CTX_UL_ITEM_MAX for s in ul):
                return f"context_notes[{i}].ul: 1..{_CTX_UL_MAX} strings of 1..{_CTX_UL_ITEM_MAX} characters"
        else:
            tb = b["table"]
            if not isinstance(tb, dict) or set(tb) != {"head", "rows"}:
                return f"context_notes[{i}].table: {{head, rows}} only"
            head, rows = tb["head"], tb["rows"]
            if not isinstance(head, list) or not 1 <= len(head) <= _CTX_HEAD_MAX or not all(
                    isinstance(s, str) and 1 <= len(s) <= _CTX_HEAD_CELL_MAX for s in head):
                return f"context_notes[{i}].table.head: 1..{_CTX_HEAD_MAX} strings of 1..{_CTX_HEAD_CELL_MAX} characters"
            if not isinstance(rows, list) or not 1 <= len(rows) <= _CTX_ROWS_MAX or not all(
                    isinstance(r, list) and len(r) <= _CTX_COLS_MAX and all(isinstance(s, str) and len(s) <= _CTX_CELL_MAX for s in r)
                    for r in rows):
                return f"context_notes[{i}].table.rows: 1..{_CTX_ROWS_MAX} rows of up to {_CTX_COLS_MAX} strings of up to {_CTX_CELL_MAX} characters"
    return None


def _walk_example() -> str:
    return str(rubric()["guide"]["answer_example"])


@cache
def _load_na_predicates() -> dict[str, Any]:
    """Load na_predicates.yaml (cached)."""
    path = RUBRIC_DIR / "na_predicates.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _check_na_predicate_for_section(reason: str, family: str, map_doc: dict | None) -> str:
    """Check whether a not_applicable reason can be confirmed. Returns 'true'|'false'|'unknown'."""
    preds = _load_na_predicates()
    fam_preds = preds.get(family, {})
    if reason not in fam_preds:
        return "false"  # Unknown reason → reject
    if map_doc is None or map_doc.get("semantic") is None:
        return "unknown"  # Cannot confirm without map
    # Check the predicate via the map
    semantic = map_doc.get("semantic", {})
    if reason == "nr_no_external_call":
        for fn in semantic.get("functions", []):
            for call in fn.get("calls", []):
                if call.get("kind") in ("external", "delegatecall", "value_transfer"):
                    return "false"
        return "true"
    if reason == "nr_no_proxy":
        for unit in semantic.get("units", []):
            if unit.get("proxy_address") or unit.get("upgrade_surface"):
                return "false"
        return "true"
    if reason == "nr_no_upgrade_path":
        for unit in semantic.get("units", []):
            if unit.get("upgrade_surface"):
                return "false"
        return "true"
    # Default: unimplemented predicate — cannot confirm
    return "unknown"


def _collect_text_fields(section: str, content: Any) -> list[tuple[str, str]]:
    """Extract (field_path, text) pairs from section content for V5/V6 checks."""
    result: list[tuple[str, str]] = []
    if section == "context_notes":
        for i, b in enumerate(content):
            if "p" in b:
                result.append((f"context_notes[{i}].p", b["p"]))
            elif "ul" in b:
                result.extend((f"context_notes[{i}].ul[{j}]", s) for j, s in enumerate(b["ul"]))
            else:
                result.extend((f"context_notes[{i}].table.head[{j}]", s) for j, s in enumerate(b["table"]["head"]))
                result.extend((f"context_notes[{i}].table.rows[{j}][{k}]", s)
                              for j, row in enumerate(b["table"]["rows"]) for k, s in enumerate(row) if s)
    elif section == "roles_notes":
        if isinstance(content, list):
            for i, row in enumerate(content):
                # tools.v1 schema uses "role" (not "role_name"); "notes" is a legacy alias
                for field in ("role", "risk_note", "notes"):
                    val = row.get(field, "")
                    if val:
                        result.append((f"roles_notes[{i}].{field}", str(val)))
    elif section == "out_of_scope_reasons":
        if isinstance(content, list):
            for i, row in enumerate(content):
                for field in ("path_pattern", "reason"):
                    val = row.get(field, "")
                    if val:
                        result.append((f"out_of_scope_reasons[{i}].{field}", str(val)))
    elif section == "coverage" and isinstance(content, list):
        for i, row in enumerate(content):
            for field in ("area_id", "note", "reason"):
                val = row.get(field, "")
                if val:
                    result.append((f"coverage[{i}].{field}", str(val)))
    return result


_SECTION_KEYS = ("roles_notes", "out_of_scope_reasons", "coverage", "context_notes", "invariant_walks")


@handler("review_set_section")
async def handle_review_set_section(args: dict[str, Any]) -> dict[str, Any]:
    """One section, or every section whose object is in the call (03 §4.13).

    The 2026-10-25 Solana blind run spent 10 set_section calls; a review needs up to four sections. When
    the call carries the objects of several sections, each one goes through the same single-section path
    (same gates, own revision, own idempotency) in the order: `section` first, then the schema order.
    Sections are independent: one rejected section does not undo another. The result is the first
    section's result, `accepted` only when every section was accepted, every error, and `sections`.
    """
    named = args["section"]
    present = [k for k in _SECTION_KEYS if isinstance(args.get(k), dict)]
    others = [k for k in present if k != named]
    if not others:
        return await _set_one_section(args)
    order = ([named] if named in present else []) + others
    results: list[tuple[str, dict[str, Any]]] = []
    for name in order:
        res = await _set_one_section({"job_id": args["job_id"], "section": name, name: args[name]})
        results.append((name, res))
    out = dict(results[0][1])
    out["accepted"] = all(r.get("accepted") for _, r in results)
    errors = [e for _, r in results for e in (r.get("errors") or [])]
    if errors:
        out["errors"] = errors[:20]
        if len(errors) > 20:
            out["errors_more"] = len(errors) - 20
    rows = []
    for name, r in results:
        row: dict[str, Any] = {"section": name, "accepted": bool(r.get("accepted"))}
        if "revision" in r:
            row["revision"] = r["revision"]
        if r.get("errors"):
            row["errors"] = r["errors"][:20]
        rows.append(row)
    out["sections"] = rows
    # invariant walks: the open-walk list belongs to the whole call, whichever section came first
    walks = next((r for name, r in results if name == "invariant_walks" and "walks_open" in r), None)
    if walks is not None:
        out["walks_open"] = walks["walks_open"]
    return out


async def _set_one_section(args: dict[str, Any]) -> dict[str, Any]:
    """Submit or update a report section (03 §4.13).

    Idempotent: same content hash → return current revision without inserting.
    """
    job_id: str = args["job_id"]
    section: str = args["section"]
    content: Any = args.get("content")
    if content is None and section == "context_notes" and isinstance(args.get("context_notes"), dict):
        content = args["context_notes"].get("notes")  # tools.v1 shape: {section: "context_notes", context_notes: {notes: [...]}}
    # Bug 3 fix (2026-10-25): tools.v1 shape for roles_notes, coverage, out_of_scope_reasons
    # is {section: "...", <section>: {rows: [...]}}, not {section: "...", content: [...]}.
    # Previously these three sections always returned E_SECTION_INVALID "content must be an array"
    # because args.get("content") was always None.
    if content is None and section in ("roles_notes", "coverage", "out_of_scope_reasons", "invariant_walks"):
        section_arg = args.get(section)
        if isinstance(section_arg, dict):
            content = section_arg.get("rows")
    pool = _get_pool()

    # State check — quick unlocked read before we do any work (map, text-gate, etc.)
    async with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("select * from jobs where job_id = %s", (job_id,))
        job = await cur.fetchone()

    if job is None:
        raise ReviewError("E_JOB_NOT_FOUND")

    state = job["state"]
    if state in _FROZEN_STATES:
        return {"accepted": False, "errors": [ReviewError("E_JOB_FROZEN").envelope()]}
    if state in _TERMINAL_STATES:
        return {"accepted": False, "errors": [
            ReviewError("E_JOB_TERMINAL", state=state, exit_code=job.get("error_code", "")).envelope()
        ]}
    if state != "ready":
        return {"accepted": False, "errors": [
            ReviewError("E_JOB_NOT_READY", state=state, eta_s=0).envelope()
        ]}
    # Note: the write transaction below re-checks state with FOR UPDATE (TOCTOU guard).
    # Profile drives profile-specific text rules (T30) at write time.
    job_profile = "owner" if job.get("ownership_proven") else "public_review"

    # Validate section name
    if section not in _SECTIONS:
        return {"accepted": False, "errors": [
            ReviewError("E_SECTION_INVALID", detail=f"unknown section '{section}'").envelope()
        ]}

    # Content must be a non-empty list.
    # Bug 3 fix (2026-10-25): include a real section-specific example in the error so the model
    # can correct its call immediately rather than guessing the shape.
    _SECTION_EXAMPLES: dict[str, str] = {
        "roles_notes": '[{"role": "owner", "risk_note": "Can pause all transfers."}]',
        "coverage": '[{"area_id": "AC", "status": "partially_read"}]',
        "out_of_scope_reasons": '[{"item_id": "X-001", "reason": "Vendored dependency, not audited."}]',
        "context_notes": '[{"p": "The project is a token bridge."}]',
        "invariant_walks": _walk_example(),
    }
    if not isinstance(content, list):
        example = _SECTION_EXAMPLES.get(section, "[]")
        return {"accepted": False, "errors": [
            ReviewError("E_SECTION_INVALID", detail="content must be an array", example=example).envelope()
        ]}
    if not content:
        example = _SECTION_EXAMPLES.get(section, "[]")
        return {"accepted": False, "errors": [
            ReviewError("E_SECTION_INVALID", detail="content must have at least one row", example=example).envelope()
        ]}
    if section == "context_notes":
        detail = _check_context_blocks(content)
        if detail is not None:
            return {"accepted": False, "errors": [ReviewError("E_SECTION_INVALID", detail=detail).envelope()]}

    # ── V5/V6 on all text fields ──────────────────────────────────────────────
    violations: list[dict[str, Any]] = []
    for field_path, text in _collect_text_fields(section, content):
        # context_notes strings are report prose (field class `notes`, same rules as roles notes;
        # list items get the T30 list-actor check); the other sections keep their path as field.
        # Use check_model_field (canonical early-gate = render-time gate, 04 §11.4).
        if section == "context_notes":
            field_vs = check_model_field(text, field="notes", profile=job_profile,
                                         is_list_item=".ul[" in field_path)
        else:
            field_vs = check_model_field(text, field=field_path, profile=job_profile)
        for v in field_vs:
            violations.append(ReviewError(
                v.code, rule=v.rule_id,
                match=v.match[:80] if v.match else "",
                cp=(v.match[:5] if v.match else ""),
                pos=v.span[0],
                token=(v.match[:40] if v.match else ""),
            ).envelope())
        for v in lex_numbers(text):
            violations.append(ReviewError(
                v.code, rule=v.rule_id,
                match=v.match[:80] if v.match else "",
                token=v.match[:40] if v.match else "",
                field=field_path,
                cp=(v.match[:5] if v.match else ""),
                pos=v.span[0],
            ).envelope())

    if violations:
        return {"accepted": False, "errors": violations}

    # ── Coverage section: strict N/A-only schema (04 §13, 03 §4.13) ─────────
    if section == "coverage":
        try:
            pin_root = _get_ctx().get_pin_root()
            map_doc, _ = load_map(pin_root, job_id)
        except FileNotFoundError:
            map_doc = None  # map worker not run yet; not_covered is spec-correct
        except (OSError, ValueError) as exc:
            raise ReviewError("E_INTERNAL", incident=f"map load failed (corrupt/unreadable): {exc}") from exc

        family = _family_from_chain(job.get("chain"))
        try:
            valid_cats = set(family_categories(family))
        except EnumsLoadError as exc:
            raise ReviewError("E_INTERNAL", incident=f"enums.yaml unavailable: {exc}") from exc

        # Build job_reads_index for computed coverage status check
        pool_for_reads = _get_pool()
        reads_index: dict[str, list[tuple[int, int]]] = {}
        async with pool_for_reads.connection() as rc, rc.cursor() as rcur:
            await rcur.execute(
                "select path, start_line, end_line from job_reads where job_id = %s",
                (job_id,),
            )
            async for r_path, r_start, r_end in rcur:
                reads_index.setdefault(r_path, []).append((r_start, r_end))

        # Server-computed status per category
        try:
            computed_rows = compute_coverage_rows(family, map_doc, reads_index)
        except EnumsLoadError as exc:
            raise ReviewError("E_INTERNAL", incident=f"enums.yaml unavailable: {exc}") from exc
        computed_index = cov_rows_index(computed_rows)

        for i, row in enumerate(content):
            area_id = row.get("area_id") or f"row_{i}"
            reason = row.get("reason") or ""
            note = row.get("note") or ""

            # Reject any row that carries a 'state' field (old schema)
            if "state" in row:
                return {"accepted": False, "errors": [
                    ReviewError("E_SECTION_INVALID",
                                detail=f"coverage row {i}: 'state' field is not accepted; "
                                       "use {area_id, reason, note} only").envelope()
                ]}

            # area_id must be a valid family category
            if area_id not in valid_cats:
                return {"accepted": False, "errors": [
                    ReviewError("E_SECTION_INVALID",
                                detail=f"coverage row {i}: area_id '{area_id}' is not a "
                                       f"valid {family} category").envelope()
                ]}

            # reason must be allowed for this specific category (04 §13; derived from checklist na:[])
            cat_allowed = category_allowed_na_reasons(family, area_id)
            if not reason or reason not in cat_allowed:
                return {"accepted": False, "errors": [
                    ReviewError("E_COVERAGE_NA_UNCONFIRMED",
                                detail=f"coverage row {i}: reason '{reason}' is not allowed "
                                       f"for category '{area_id}' in family '{family}'").envelope()
                ]}

            # note must be 10..300 chars
            if len(note) < 10 or len(note) > 300:
                return {"accepted": False, "errors": [
                    ReviewError("E_SECTION_INVALID",
                                detail=f"coverage row {i}: note must be 10–300 characters "
                                       f"(got {len(note)})").envelope()
                ]}

            # N/A can only replace not_covered or no_candidates (not read/partially_read)
            computed_status = computed_index.get(area_id, "not_covered")
            if computed_status in ("read", "partially_read"):
                return {"accepted": False, "errors": [
                    ReviewError("E_COVERAGE_NA_UNCONFIRMED",
                                detail=f"{area_id}: computed status is '{computed_status}'; "
                                       "N/A cannot override a covered category").envelope()
                ]}

            # Predicate must be confirmable as true
            predicate_result = _check_na_predicate_for_section(reason, family, map_doc)
            if predicate_result != "true":
                return {"accepted": False, "errors": [
                    ReviewError("E_COVERAGE_NA_UNCONFIRMED",
                                detail=f"{area_id}: predicate {reason}={predicate_result}").envelope()
                ]}

    # ── Invariant walks: coverage-checked answers, merged by walk_id ──────────
    walks_open: list[str] = []
    if section == "invariant_walks":
        lc = load_lifecycle(_get_ctx().get_pin_root(), job_id)
        index = walk_index(lc)
        if not index:
            return {"accepted": False, "errors": [ReviewError(
                "E_SECTION_INVALID", detail="this job has no invariant walks (review_get_guide topic invariants)",
                example=_walk_example()).envelope()]}
        async with pool.connection() as wc:
            reads = await load_reads(wc, job_id)
            drafts = await load_drafts(wc, job_id)
            previous = await latest_rows(wc, job_id)
        errors = []
        for row in content:
            detail = validate_row(row, index.get(str((row or {}).get("walk_id"))) if isinstance(row, dict) else None,
                                  reads, drafts)
            if detail is not None:
                errors.append(ReviewError("E_SECTION_INVALID", detail=detail, example=_walk_example()).envelope())
        if errors:
            return {"accepted": False, "errors": errors[:20]}
        clean = [{k: row[k] for k in ("walk_id", "outcome", "refs", "note", "draft_key") if k in row} for row in content]
        content = merge_rows(previous, clean)
        walks_open = open_walks(lc, content, drafts)

    # ── Compute content hash and check idempotency ────────────────────────────
    content_hash = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()

    async with pool.connection() as conn, conn.transaction():
        # TOCTOU guard: lock job row and re-verify state inside the write transaction
        async with conn.cursor(row_factory=dict_row) as lcur:
            await lcur.execute(
                "select state from jobs where job_id = %s for update", (job_id,)
            )
            locked_job = await lcur.fetchone()
        if locked_job is None:
            raise ReviewError("E_JOB_NOT_FOUND")
        locked_state = locked_job["state"]
        if locked_state in _FROZEN_STATES:
            return {"accepted": False, "errors": [ReviewError("E_JOB_FROZEN").envelope()]}
        if locked_state not in ("ready",):
            return {"accepted": False, "errors": [
                ReviewError("E_JOB_NOT_READY", state=locked_state, eta_s=0).envelope()
            ]}

        # Check existing rows for this section
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """select revision, content_hash from sections
                   where job_id = %s and section = %s
                   order by revision desc limit 1""",
                (job_id, section),
            )
            existing = await cur.fetchone()

        if existing is not None:
            if existing["content_hash"] == content_hash:
                # Idempotent: same content → return without inserting
                return {
                    "accepted": True,
                    "section": section,
                    "revision": existing["revision"],
                    "idempotent": True,
                    **({"walks_open": walks_open} if section == "invariant_walks" else {}),
                }
            # New content: next revision
            next_revision = existing["revision"] + 1
        else:
            next_revision = 1

        # Insert new section revision
        await conn.execute(
            """insert into sections (job_id, section, revision, content, content_hash)
               values (%s, %s, %s, %s, %s)""",
            (job_id, section, next_revision,
             __import__("psycopg").types.json.Jsonb(content),
             content_hash),
        )
        await conn.execute(
            "update jobs set last_call_at = now() where job_id = %s", (job_id,)
        )

    return {
        "accepted": True,
        "section": section,
        "revision": next_revision,
        "idempotent": False,
        **({"walks_open": walks_open} if section == "invariant_walks" else {}),
    }
