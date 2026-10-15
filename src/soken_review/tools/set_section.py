"""Handler for review_set_section (03 §4.13).

Registered via @handler("review_set_section").

Three sections:
  roles_notes          – notes on protocol roles (owner, admin, pauser, …)
  out_of_scope_reasons – files/directories excluded from the audit scope
  coverage             – per-category area coverage rows

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
from ..engine.text_gate import CheckContext, check_text
from ..errors import ReviewError
from ..mapping.build import load_map
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
    if section == "roles_notes":
        if isinstance(content, list):
            for i, row in enumerate(content):
                for field in ("role_name", "risk_note", "notes"):
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


@handler("review_set_section")
async def handle_review_set_section(args: dict[str, Any]) -> dict[str, Any]:
    """Submit or update a report section (03 §4.13).

    Idempotent: same content hash → return current revision without inserting.
    """
    job_id: str = args["job_id"]
    section: str = args["section"]
    content: Any = args["content"]
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

    # Validate section name
    if section not in ("roles_notes", "out_of_scope_reasons", "coverage"):
        return {"accepted": False, "errors": [
            ReviewError("E_SECTION_INVALID", detail=f"unknown section '{section}'").envelope()
        ]}

    # Content must be a non-empty list
    if not isinstance(content, list):
        return {"accepted": False, "errors": [
            ReviewError("E_SECTION_INVALID", detail="content must be an array").envelope()
        ]}
    if not content:
        return {"accepted": False, "errors": [
            ReviewError("E_SECTION_INVALID", detail="content must have at least one row").envelope()
        ]}

    # ── V5/V6 on all text fields ──────────────────────────────────────────────
    violations: list[dict[str, Any]] = []
    for field_path, text in _collect_text_fields(section, content):
        for v in check_text(text, "model", CheckContext(field=field_path)):
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
    }
