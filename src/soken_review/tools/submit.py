"""Handler for review_submit_finding (03 §4.10, 04 §1.2).

Registered via @handler("review_submit_finding").

Pipeline (04 §1.2):
  V0 schema  -> E_INVALID_ARGUMENT (server.py)
  V1 tier D  -> E_TIER_D
  State check -> E_JOB_NOT_READY or E_JOB_FROZEN
  Server-draft rules -> E_FIELD_FIXED or E_SERVER_DRAFT
  expected_revision -> E_REVISION_CONFLICT
  Content-hash replay -> return current revision unchanged
  Retry budget -> E_RETRY_BUDGET (7th rejection)
  V2/V3 quote-match against pin store
  V4 injection echo check
  V5 text gate (model scope, all text fields)
  V6 number check (all text fields)
  V7.5 trigger check against map (map_unavailable when absent)
  V8 severity computation
  V9 duplicate check (W0: basic overlap only)
  V10 lead link validation and promotion
  On acceptance: insert revision, assign F-nn, set status, promote leads
  On rejection: store nothing, increment rejected_count

Ambiguities resolved: docs/w0/submit-finalize-ambiguities.md.
"""

from __future__ import annotations

import hashlib
import json
from functools import cache
from pathlib import Path
from typing import Any

import psycopg
import psycopg_pool
import yaml
from psycopg.rows import dict_row

from ..context.store import ContextStore, is_context_path
from ..db.pool import get_pool
from ..engine.injection import check_echo
from ..engine.numbers import lex_numbers
from ..engine.severity import SeverityContext, compute_severity
from ..engine.text_gate import check_model_field
from ..errors import ReviewError
from ..mapping.build import load_map
from ..mapping.semantic_evm import detect_token_review, units_holding
from ..mapping.step import load_flags
from ..pinning.quote_match import QuoteMatchError, quote_match
from ..pinning.store import PinnedSource
from ..server import handler
from .context import JobContext

RUBRIC_DIR = Path(__file__).resolve().parents[3] / "contract" / "rubric"

_pool: psycopg_pool.AsyncConnectionPool | None = None
_ctx: JobContext | None = None


def set_pool(pool: psycopg_pool.AsyncConnectionPool) -> None:
    global _pool
    _pool = pool


def set_context(ctx: JobContext) -> None:
    """Set the JobContext used by this handler (pin root, etc.)."""
    global _ctx
    _ctx = ctx


def _get_pool() -> psycopg_pool.AsyncConnectionPool:
    return _pool if _pool is not None else get_pool()


def _get_ctx() -> JobContext:
    if _ctx is None:
        from ..errors import ReviewError
        raise ReviewError("E_INTERNAL", incident="submit not wired (ctx is None)")
    return _ctx


# ── Text field helpers ─────────────────────────────────────────────────────────

def _iter_text_fields(args: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (field_name, text) pairs for all prose fields in a submission.

    Used by V4 echo check, V5 text gate, and V6 number check.
    """
    result: list[tuple[str, str]] = []
    if title := args.get("title"):
        result.append(("title", str(title)))
    body = args.get("body") or {}
    for section in ("description", "impact", "recommendation"):
        for block in (body.get(section) or []):
            if p := block.get("p"):
                result.append((section, str(p)))
    for step in (args.get("attack_steps") or []):
        if text := step.get("text"):
            result.append(("attack_steps", str(text)))
    if notes := args.get("notes"):
        result.append(("notes", str(notes)))
    return result


def _violation_to_error(v: Any) -> dict[str, Any]:
    """Convert a Violation (text_gate or numbers) to a ReviewError envelope dict."""
    return ReviewError(
        v.code,
        rule=v.rule_id,
        match=v.match[:80] if v.match else "",
        cp=(v.match[:5] if v.match else ""),
        pos=v.span[0],
        token=(v.match[:40] if v.match else ""),
    ).envelope()


# ── Enums cache ────────────────────────────────────────────────────────────────

@cache
def _categories() -> dict[str, dict[str, Any]]:
    """category id -> row from enums.yaml."""
    cats = yaml.safe_load((RUBRIC_DIR / "enums.yaml").read_text(encoding="utf-8"))["categories"]
    return {c["id"]: c for c in cats}


def _category_info(cat_id: str) -> dict[str, Any] | None:
    return _categories().get(cat_id)


def _family_categories(family: str) -> list[str]:
    return [c["id"] for c in _categories().values() if c["family"] == family and not c.get("server_only")]


# ── Content-hash helper ────────────────────────────────────────────────────────

def _content_hash(args: dict[str, Any]) -> str:
    """Stable content hash of submission fields (for replay detection, 03 §10)."""
    # Include all fields except job_id, draft_key, expected_revision (those are control fields)
    sig_keys = [k for k in sorted(args) if k not in ("job_id", "draft_key", "expected_revision")]
    sig = {k: args[k] for k in sig_keys}
    return hashlib.sha256(json.dumps(sig, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


# ── Server-draft field guard ───────────────────────────────────────────────────

_SERVER_DRAFT_ALLOWED = frozenset({"job_id", "draft_key", "expected_revision", "title", "body"})
_MODEL_DRAFT_REQUIRED = frozenset({"category", "quotes", "matrix"})


def _check_server_draft_fields(args: dict[str, Any]) -> list[dict[str, Any]]:
    """Return E_FIELD_FIXED errors for any extra fields on a server draft (04 §12, 03 §4.10)."""
    errors = []
    for key in args:
        if key not in _SERVER_DRAFT_ALLOWED:
            errors.append(ReviewError("E_FIELD_FIXED", field=key).envelope())
    return errors


# ── Category validator ─────────────────────────────────────────────────────────

def _validate_category(cat_id: str, family: str) -> list[dict[str, Any]]:
    """Return E_CATEGORY_UNKNOWN if the category id is unknown for this family."""
    info = _category_info(cat_id)
    if info is None or info["family"] != family:
        allowed = _family_categories(family)
        return [ReviewError("E_CATEGORY_UNKNOWN", value=cat_id, family=family,
                            list=", ".join(allowed[:20])).envelope()]
    if info.get("legacy") == "read only by corpus import" or info.get("server_only"):
        allowed = [c for c in _family_categories(family) if not _category_info(c).get("server_only")]
        return [ReviewError("E_CATEGORY_UNKNOWN", value=cat_id, family=family,
                            list=", ".join(allowed[:20])).envelope()]
    return []


# ── Lead validator ─────────────────────────────────────────────────────────────

async def _validate_leads(
    conn: psycopg.AsyncConnection,
    job_id: str,
    draft_key: str,
    lead_ids: list[str],
    category: str,
    location_quotes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool, set[str]]:
    """Validate leads and return (errors, linked_lead_same_cat, carried_lead_ids).

    Checks:
    - Lead exists and belongs to this job (E_LEAD_NOT_FOUND)
    - Lead is in a linkable state: open, or currently promoted by THIS draft (not another).
      Leads promoted by another draft cannot be re-linked (E_LEAD_NOT_FOUND used as guard).
    - Lead overlaps at least one location quote (E_LEAD_NO_OVERLAP)
    - Lead category matches finding category (E_CATEGORY_MISMATCH)

    linked_lead_same_cat: True ONLY for origin='analyzer' leads where the lead is open OR
    promoted by THIS draft. Previous_report leads do not grant analyzer_and_reasoning evidence
    (SF-002). Old revisions that dropped a lead must not count (per orchestrator: same rule as
    finalize — state='open' OR (state='promoted' AND state_ref=this draft)).

    carried_lead_ids: set of lead IDs with origin='previous_report' (03 §4.10 step 5).
    """
    if not lead_ids:
        return [], False, set()

    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "select lead_id, category, path, start_line, end_line, origin, state, state_ref "
            "from leads where job_id = %s and lead_id = any(%s)",
            (job_id, lead_ids),
        )
        rows = {r["lead_id"]: r for r in await cur.fetchall()}

    errors: list[dict[str, Any]] = []
    linked_same_cat = False
    carried_lead_ids: set[str] = set()

    # Build location ranges: {path: [(start, end), ...]}
    loc_ranges: dict[str, list[tuple[int, int]]] = {}
    for q in location_quotes:
        if q.get("role", "location") == "location":
            p = q["file"]
            loc_ranges.setdefault(p, []).append((q["start"], q["end"]))

    for lid in lead_ids:
        row = rows.get(lid)
        if row is None:
            errors.append(ReviewError("E_LEAD_NOT_FOUND", lead=lid).envelope())
            continue
        # Category mismatch
        if row["category"] != category:
            errors.append(ReviewError("E_CATEGORY_MISMATCH", lead=lid, category=row["category"]).envelope())
            continue
        # Overlap check: lead's (path, start_line, end_line) overlaps a location quote
        path = row["path"]
        ls, le = row["start_line"], row["end_line"]
        ranges = loc_ranges.get(path, [])
        overlaps = any(not (le < qs or ls > qe) for qs, qe in ranges)
        if not overlaps:
            errors.append(ReviewError("E_LEAD_NO_OVERLAP", lead=lid,
                                      range=f"{path}:{ls}-{le}").envelope())
            continue
        # Lead state check: only 'open' or previously-promoted-by-THIS-draft is linkable.
        # A dismissed lead or a lead promoted by ANOTHER draft must be rejected.
        # No spec code for "not linkable" — use E_LEAD_NOT_FOUND (closest per errors.yaml;
        # see note: spec 03 §4.10 / 04 §10 has no E_LEAD_NOT_LINKABLE; documented in ambiguities).
        lead_state = row.get("state", "")
        lead_state_ref = row.get("state_ref") or ""
        lead_linkable = lead_state == "open" or (
            lead_state == "promoted" and lead_state_ref == draft_key
        )
        if not lead_linkable:
            errors.append(ReviewError("E_LEAD_NOT_FOUND", lead=lid).envelope())
            continue

        # Security (04 §4.10): only analyzer-origin leads grant E3 evidence level.
        # previous_report leads are carried but do NOT elevate evidence (SF-002 fix).
        # K11 evidence rule (same as finalize): only count if lead is open OR promoted by
        # THIS draft (not by another draft). A lead promoted by another draft that revision N
        # linked but revision N+1 dropped must not grant E3 at submission.
        origin = row.get("origin", "")
        if origin == "analyzer":
            linked_same_cat = True
        if origin == "previous_report":
            carried_lead_ids.add(lid)

    return errors, linked_same_cat, carried_lead_ids


# ── Family from chain ─────────────────────────────────────────────────────────

def _family_from_chain(chain: str | None) -> str:
    """Map chain -> family for category validation."""
    if chain is None:
        return "evm"
    if chain in ("evm", "hyperevm", "tron"):
        return "evm"
    if chain == "solana":
        return "solana"
    if chain == "ton":
        return "ton"
    if chain in ("sui", "aptos"):
        return "move"
    if chain == "starknet":
        return "cairo"
    return "evm"


# ── DB: get or initialise draft row ──────────────────────────────────────────

async def _get_or_init_draft(
    conn: psycopg.AsyncConnection,
    job_id: str,
    draft_key: str,
) -> dict[str, Any] | None:
    """Return the finding_drafts row or None if not found."""
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "select * from finding_drafts where job_id = %s and draft_key = %s",
            (job_id, draft_key),
        )
        return await cur.fetchone()  # type: ignore[return-value]


async def _get_draft_content_hash(
    conn: psycopg.AsyncConnection,
    job_id: str,
    draft_key: str,
    revision: int,
) -> str | None:
    """Return the content_hash of a specific revision."""
    async with conn.cursor() as cur:
        await cur.execute(
            "select content_hash from finding_revisions where job_id = %s and draft_key = %s and revision = %s",
            (job_id, draft_key, revision),
        )
        row = await cur.fetchone()
        return row[0] if row else None


# ── Insert revision ──────────────────────────────────────────────────────────

async def _insert_revision(
    conn: psycopg.AsyncConnection,
    job_id: str,
    draft_key: str,
    revision: int,
    content: dict[str, Any],
    content_hash: str,
    category: str,
    family: str,
    impact_class: str,
    computed_severity: str,
    severity_rule: str,
    caps_applied: list[str],
    map_unavailable: bool,
) -> None:
    await conn.execute(
        """insert into finding_revisions
           (job_id, draft_key, revision, content, content_hash, category, category_family,
            impact_class, computed_severity, severity_rule, caps_applied, map_unavailable)
           values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (job_id, draft_key, revision,
         psycopg.types.json.Jsonb(content), content_hash,
         category, family, impact_class,
         computed_severity, severity_rule,
         caps_applied, map_unavailable),
    )


async def _insert_quote_ranges(
    conn: psycopg.AsyncConnection,
    job_id: str,
    draft_key: str,
    revision: int,
    quotes: list[dict[str, Any]],
) -> None:
    for ord_i, q in enumerate(quotes):
        role = q.get("role", "location")
        await conn.execute(
            """insert into finding_quote_ranges
               (job_id, draft_key, revision, ord, role, path, start_line, end_line)
               values (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (job_id, draft_key, revision, ord_i, role, q["file"], q["start"], q["end"]),
        )


async def _insert_lead_links(
    conn: psycopg.AsyncConnection,
    job_id: str,
    draft_key: str,
    revision: int,
    lead_ids: list[str],
) -> None:
    for lid in lead_ids:
        await conn.execute(
            "insert into finding_leads (job_id, draft_key, revision, lead_id) values (%s, %s, %s, %s)",
            (job_id, draft_key, revision, lid),
        )


# ── Leads: promote new, demote removed ───────────────────────────────────────

async def _get_prev_lead_ids(
    conn: psycopg.AsyncConnection,
    job_id: str,
    draft_key: str,
    revision: int,
) -> list[str]:
    """Lead ids linked in the given revision."""
    async with conn.cursor() as cur:
        await cur.execute(
            "select lead_id from finding_leads where job_id = %s and draft_key = %s and revision = %s",
            (job_id, draft_key, revision),
        )
        return [r[0] for r in await cur.fetchall()]


async def _promote_leads(
    conn: psycopg.AsyncConnection,
    job_id: str,
    draft_key: str,
    lead_ids: list[str],
    carried_lead_ids: set[str],
) -> None:
    """Set leads to promoted, state_ref = draft_key.

    Uses a constrained WHERE clause (state='open' OR (state='promoted' AND state_ref=this draft))
    to prevent concurrent submits from stealing a lead. Checks rowcount == len(lead_ids) and
    raises E_LEAD_NOT_FOUND if fewer rows were updated (TOCTOU guard).
    """
    if not lead_ids:
        return
    async with conn.cursor() as cur:
        await cur.execute(
            """update leads set state = 'promoted', state_ref = %s
               where job_id = %s and lead_id = any(%s)
                 and (state = 'open' or (state = 'promoted' and state_ref = %s))""",
            (draft_key, job_id, lead_ids, draft_key),
        )
        updated = cur.rowcount
    if updated != len(lead_ids):
        # A concurrent submit promoted one of these leads after our validation read.
        # Roll back by raising — the caller's transaction will be aborted.
        raise ReviewError("E_LEAD_NOT_FOUND", lead="concurrent_steal")


async def _demote_leads_to_open(
    conn: psycopg.AsyncConnection,
    job_id: str,
    lead_ids: list[str],
    draft_key: str | None = None,
) -> list[str]:
    """Return leads back to open (previously promoted by this draft).

    The state_ref = draft_key constraint ensures we only demote leads that were
    promoted by THIS specific draft, not leads that happen to share the same lead_id
    but were promoted by a concurrent submission.
    """
    if not lead_ids:
        return []
    async with conn.cursor() as cur:
        if draft_key is not None:
            await cur.execute(
                """update leads set state = 'open', state_ref = null
                   where job_id = %s and lead_id = any(%s)
                     and state = 'promoted' and state_ref = %s
                   returning lead_id""",
                (job_id, lead_ids, draft_key),
            )
        else:
            await cur.execute(
                """update leads set state = 'open', state_ref = null
                   where job_id = %s and lead_id = any(%s) and state = 'promoted'
                   returning lead_id""",
                (job_id, lead_ids),
            )
        return [r[0] for r in await cur.fetchall()]


# ── Main handler ──────────────────────────────────────────────────────────────

@handler("review_submit_finding")
async def handle_review_submit_finding(args: dict[str, Any]) -> dict[str, Any]:
    """Submit or revise a finding (03 §4.10).

    Per 03 §7.1: most errors are rejections (accepted: false); E_INVALID_ARGUMENT
    is an error (server.py catches schema violations before we get here).
    """
    job_id: str = args["job_id"]
    draft_key: str = args["draft_key"]
    expected_revision: int | None = args.get("expected_revision")
    is_server_draft = draft_key.startswith("srv-")

    # ── Server-draft field check ──────────────────────────────────────────
    if is_server_draft:
        field_errors = _check_server_draft_fields(args)
        if field_errors:
            return {"accepted": False, "errors": field_errors}

    pool = _get_pool()

    async with pool.connection() as conn, conn.transaction():
        # ── Lock job row ──────────────────────────────────────────────
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from jobs where job_id = %s for update", (job_id,))
            job = await cur.fetchone()

        if job is None:
            raise ReviewError("E_JOB_NOT_FOUND")

        state = job["state"]
        tier = job.get("tier")
        family = _family_from_chain(job.get("chain"))
        # Profile drives profile-specific text rules (T30 public_review) at write time
        # so the early gate and the render-time gate see the same set of violations.
        job_profile = "owner" if job.get("ownership_proven") else "public_review"

        # ── State matrix checks (03 §4.10 step 2) ────────────────────
        if state == "finalized":
            return {"accepted": False, "errors": [ReviewError("E_JOB_FROZEN").envelope()]}
        if state in ("render_queued", "rendering", "rendered", "render_failed", "finalized"):
            return {"accepted": False, "errors": [ReviewError("E_JOB_FROZEN").envelope()]}
        if state not in ("ready",):
            # Not ready yet
            return {"accepted": False, "errors": [
                ReviewError("E_JOB_NOT_READY", state=state, eta_s=0).envelope()
            ]}

        # ── Tier D check (V1) ─────────────────────────────────────────
        if tier == "D":
            return {"accepted": False, "errors": [ReviewError("E_TIER_D").envelope()]}

        # ── Get or expect draft row ───────────────────────────────────
        draft = await _get_or_init_draft(conn, job_id, draft_key)

        if draft is None and is_server_draft:
            # Server draft must already exist (created by the analyzer worker)
            raise ReviewError("E_INVALID_ARGUMENT", field="draft_key",
                              rule="server drafts must already exist", value80=draft_key[:80])

        if draft is None:
            # New model draft: will be created
            current_revision = -1  # will become 0 on first insert
            rejected_count = 0
        else:
            current_revision = draft["current_revision"]
            rejected_count = draft.get("rejected_count", 0)

        # ── Challenge-kill lock (03 §4.11 / 04 §8.6) ─────────────────
        # A finding killed by challenge can NEVER be resubmitted under the same key.
        # This check must precede content-hash replay, retry-budget, and all validation
        # so that not even an idempotent replay can resurrect a killed finding.
        if draft is not None and not is_server_draft and draft.get("withdrawn_by") == "challenge":
            return {"accepted": False, "errors": [
                ReviewError("E_DISPROVED_LOCKED", category=args.get("category", "")).envelope()
            ]}

        new_revision = current_revision + 1

        # ── expected_revision conflict (03 §4.10 step 3) ──────────────
        if expected_revision is not None and expected_revision != current_revision:
            return {"accepted": False, "errors": [
                ReviewError("E_REVISION_CONFLICT", revision=current_revision).envelope()
            ]}

        # ── Content-hash replay (03 §10) ─────────────────────────────
        content_hash = _content_hash(args)
        if current_revision >= 0:
            existing_hash = await _get_draft_content_hash(conn, job_id, draft_key, current_revision)
            if existing_hash == content_hash and draft:
                # Replay: return current state unchanged (idempotent)
                finding_no_str = f"F-{draft['finding_no']:02d}" if draft.get("finding_no") else None
                return {
                        "accepted": True,
                        "finding_no": finding_no_str,
                        "draft_key": draft_key,
                        "revision": current_revision,
                        "status": draft["status"],
                        "computed_severity": draft.get("severity"),
                        "severity_rule": "",
                        "caps_applied": [],
                        "evidence_level": draft.get("evidence_level", "reasoning_only"),
                        "leads_reopened": [],
                        "next_tools": _next_tools(draft["status"]),
                    }

        # ── Retry budget (7th rejection = E_RETRY_BUDGET) ─────────────
        # The budget check happens BEFORE running validation (spec: "the 7th rejected submission")
        # rejected_count is the count of rejections so far; if >= 6 the next would be the 7th
        max_rejections = 6  # limits.yaml job.rejected_per_draft default
        if rejected_count >= max_rejections and not is_server_draft:
            return {"accepted": False, "errors": [
                ReviewError("E_RETRY_BUDGET", draft=draft_key).envelope()
            ], "retries_left": 0}

        # ── Collect all validation errors (V2-V10) ────────────────────
        violations: list[dict[str, Any]] = []

        if is_server_draft:
            # Server drafts: only title+body, merged onto revision 0.
            # V5: use check_model_field (canonical early-gate, matches render-time check_strings).
            # The model cannot change category/quotes/matrix/lead links on server drafts
            # (_SERVER_DRAFT_ALLOWED guard already enforces this above).
            title: str = args.get("title", "")
            body_sd = args.get("body") or {}
            sd_text_args: dict[str, Any] = {"title": title, "body": body_sd}
            for field_name, field_text in _iter_text_fields(sd_text_args):
                for v in check_model_field(field_text, field=field_name, profile=job_profile):
                    violations.append(_violation_to_error(v))
        else:
            # Model draft: full field requirements
            category: str = args.get("category", "")
            quotes: list[dict[str, Any]] = args.get("quotes", [])
            matrix: dict[str, Any] = args.get("matrix", {})
            lead_ids: list[str] = args.get("lead_ids", [])
            title = args.get("title", "")

            # V7: category validation
            cat_errors = _validate_category(category, family)
            violations.extend(cat_errors)

            # V10: lead validation (category match, overlap)
            location_quotes = [q for q in quotes if q.get("role", "location") == "location"]
            lead_errors, linked_same_cat, carried_lead_ids = await _validate_leads(
                conn, job_id, draft_key, lead_ids, category, location_quotes
            )
            violations.extend(lead_errors)

            # V2/V3: quote-match against pin store (reject if pin missing — never skip)
            pin_root = _get_ctx().get_pin_root()
            try:
                pin = PinnedSource.load(pin_root, job_id)
            except (FileNotFoundError, OSError, ValueError):
                # ValueError catches json.JSONDecodeError (corrupt manifest) and
                # UnicodeDecodeError (non-UTF-8 content) — all map to pin_not_found
                raise ReviewError("E_JOB_NOT_READY", state="pin_not_found", eta_s=60)

            context_store = ContextStore.load(pin_root, job_id)   # context ingestion spec 4: context/ quotes
            for q in quotes:
                qt = q.get("text")
                if qt is None:
                    violations.append(
                        ReviewError(
                            "E_INVALID_ARGUMENT", field="quotes.text",
                            rule="required", value80="",
                        ).envelope()
                    )
                    continue
                # Security fix SF-010: reject location quotes that cite out-of-scope files.
                # quote_match only verifies text alignment — it does not enforce in_scope.
                # A model could fabricate findings against vendored dependencies (not audited).
                q_role = q.get("role", "location")
                if is_context_path(q["file"]) and q_role != "context":
                    # A project document never locates a finding (context ingestion spec 4).
                    violations.append(ReviewError(
                        "E_INVALID_ARGUMENT", field="quotes.role", rule="a context/ path takes role context",
                        value80=q["file"][:80], example='{"file": "context/whitepaper-1.md", "role": "context", ...}',
                    ).envelope())
                    continue
                entry = pin.get_entry(q["file"])
                if entry is not None and q_role == "location" and not entry.in_scope:
                    violations.append(
                        ReviewError("E_FILE_OUT_OF_SCOPE", path=q["file"]).envelope()
                    )
                    continue
                try:
                    quote_match(pin, q["file"], q["start"], q["end"], qt, context=context_store)
                except QuoteMatchError as e:
                    violations.append(ReviewError(e.code, **e.detail).envelope())

            # V4: injection echo check (j1_flags from flags.json).
            # FileNotFoundError = no map worker run yet; no J1 spans to check (documented W0
            # limitation per 04 §12 — map absence degrades V4 to no-op).
            # Any other error (OSError = permission/IO, ValueError = corrupt JSON) means the job's
            # infrastructure is broken — reject with E_INTERNAL rather than silently skip the check.
            try:
                _raw_flags = load_flags(pin_root, job_id) or []
            except FileNotFoundError:
                _raw_flags = []
            except (OSError, ValueError) as exc:
                raise ReviewError("E_INTERNAL", incident=f"flags.json unreadable: {exc!s:.80}") from exc
            j1_flags = [f for f in _raw_flags if f.get("rule") == "J1"]
            combined_text = "\n".join(t for _, t in _iter_text_fields(args))
            for v in check_echo(combined_text, j1_flags):
                violations.append(_violation_to_error(v))

            # V5: text gate (FULL model scope) on every prose field.  check_model_field
            # enforces all rules including T24/T29/T31 (no LATE_GATE_SKIP at write time,
            # 04 §11.4 write-time parity).  Pass absence_claims so T24 can bind them.
            finding_absence_claims: list[dict[str, str]] = args.get("absence_claims") or []
            for field_name, field_text in _iter_text_fields(args):
                for v in check_model_field(
                    field_text, field=field_name, profile=job_profile,
                    absence_claims=finding_absence_claims,
                ):
                    violations.append(_violation_to_error(v))

            # V6: number check on every prose field
            for field_name, field_text in _iter_text_fields(args):
                for v in lex_numbers(field_text):
                    violations.append(
                        ReviewError(
                            v.code, rule=v.rule_id,
                            match=v.match[:80] if v.match else "",
                            token=v.match[:40] if v.match else "",
                            field=field_name,
                            cp=(v.match[:5] if v.match else ""),
                            pos=v.span[0],
                        ).envelope()
                    )

            # V7.5: trigger check against semantic map.
            # FileNotFoundError = map worker not run; degrade to map_unavailable=True (K10
            # at finalize caps High — per 04 §7.5/E9: "absent map degrades via K10").
            # OSError (IO/permission) or ValueError (corrupt JSON) = infrastructure broken;
            # reject E_INTERNAL (cite: 04 §7.5/E9 specifies absent-or-unreadable both degrade,
            # but "unreadable" here means file-not-present, not corrupt — corrupt is server fault).
            try:
                map_doc, _ = load_map(pin_root, job_id)
            except FileNotFoundError:
                map_doc = None
            except (OSError, ValueError) as exc:
                raise ReviewError("E_INTERNAL", incident=f"map.json unreadable: {exc!s:.80}") from exc
            map_unavailable = map_doc is None or map_doc.get("semantic") is None

            # V8: severity computation
            cat_info = _category_info(category) if not cat_errors else None
            if matrix and cat_info is not None:
                sev_ctx = SeverityContext(
                    phase="submit",
                    category_generic=bool(cat_info.get("generic")),
                    category_max_severity=cat_info.get("max_severity"),
                    linked_lead_same_cat=linked_same_cat,
                    has_attack_steps=bool(args.get("attack_steps")),
                    map_unavailable=map_unavailable,
                    token_review=detect_token_review(
                        map_doc.get("semantic") if map_doc else None,
                        units_holding(map_doc.get("semantic") if map_doc else None, location_quotes)),
                    has_location_quote=bool(location_quotes),
                )
                try:
                    sev_result = compute_severity(matrix, "submit", sev_ctx)
                except (KeyError, ValueError) as e:
                    violations.append(
                        ReviewError(
                            "E_INVALID_ARGUMENT", field="matrix",
                            rule=str(e)[:80], value80="",
                        ).envelope()
                    )
                    sev_result = None
            else:
                sev_result = None
                if not matrix:
                    violations.append(
                        ReviewError(
                            "E_INVALID_ARGUMENT", field="matrix",
                            rule="required", value80="",
                        ).envelope()
                    )

            # V8.5: E_DISPROVED_LOCKED — a draft killed by challenge locks its location
            # ranges for its category (04 §8.6).  An overlapping new draft of the same
            # category is rejected.  Model-withdrawn drafts (withdrawn_by='model') do NOT lock.
            # Locked ranges are derived from challenge_answers.revision (the exact revision
            # that was challenged), NOT current_revision, so they remain stable even if the
            # draft row were later modified (challenge-kills are now permanently blocked above,
            # but belt-and-suspenders: use the immutable challenge_answers table as the anchor).
            if not is_server_draft and not cat_errors and location_quotes:
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """select fqr.path, fqr.start_line, fqr.end_line
                           from finding_drafts d
                           join challenge_answers ca
                             on ca.job_id = d.job_id
                             and ca.draft_key = d.draft_key
                             and ca.verdict = 'withdrawn'
                           join finding_revisions r
                             on r.job_id = d.job_id
                             and r.draft_key = d.draft_key
                             and r.revision = ca.revision
                           join finding_quote_ranges fqr
                             on fqr.job_id = d.job_id
                             and fqr.draft_key = d.draft_key
                             and fqr.revision = ca.revision
                             and fqr.role = 'location'
                           where d.job_id = %s
                             and d.status = 'withdrawn'
                             and d.withdrawn_by = 'challenge'
                             and d.kill_item is not null
                             and r.category = %s""",
                        (job_id, category),
                    )
                    locked_ranges = await cur.fetchall()

                # Check whether any locked range overlaps a new location quote
                new_loc_ranges = [
                    (q["file"], q["start"], q["end"])
                    for q in location_quotes
                ]
                for lr in locked_ranges:
                    for new_path, new_start, new_end in new_loc_ranges:
                        if (lr["path"] == new_path
                                and lr["start_line"] <= new_end
                                and lr["end_line"] >= new_start):
                            violations.append(
                                ReviewError("E_DISPROVED_LOCKED", category=category).envelope()
                            )
                            break
                    else:
                        continue
                    break  # stop at first overlapping locked range

            # V9: distinct_from draft_key cross-job authorization check.
            # The model may supply distinct_from=[draft_key, ...] to assert this finding
            # differs from others. Validate all supplied keys belong to THIS job to prevent
            # cross-job information leakage (incomplete-authorization-check, SF-013).
            if not is_server_draft:
                distinct_from: list[str] = args.get("distinct_from") or []
                if distinct_from:
                    async with conn.cursor() as cur:
                        await cur.execute(
                            "select draft_key from finding_drafts where job_id = %s and draft_key = any(%s)",
                            (job_id, distinct_from),
                        )
                        found_keys = {row[0] for row in await cur.fetchall()}
                    for dk in distinct_from:
                        if dk not in found_keys:
                            violations.append(
                                ReviewError(
                                    "E_INVALID_ARGUMENT",
                                    field="distinct_from",
                                    rule="draft_key must belong to this job",
                                    value80=dk[:80],
                                ).envelope()
                            )

        # ── On validation errors: increment rejected_count, return ────
        if violations:
            retries_left = max(0, max_rejections - rejected_count - 1)
            # Increment rejected_count
            if draft is None:
                # Create draft with rejected_count=1
                next_no = int(job["next_finding_no"])
                await conn.execute(
                    """insert into finding_drafts
                       (job_id, draft_key, finding_no, origin, status, current_revision, rejected_count, severity)
                       values (%s, %s, %s, 'model', 'needs_text', -1, 1, null)
                       on conflict (job_id, draft_key) do update set rejected_count = finding_drafts.rejected_count + 1""",
                    (job_id, draft_key, next_no),
                )
                await conn.execute(
                    "update jobs set next_finding_no = %s where job_id = %s",
                    (next_no + 1, job_id),
                )
            else:
                await conn.execute(
                    "update jobs set last_call_at = now() where job_id = %s",
                    (job_id,),
                )
                await conn.execute(
                    "update finding_drafts set rejected_count = rejected_count + 1 where job_id = %s and draft_key = %s",
                    (job_id, draft_key),
                )
            result: dict[str, Any] = {"accepted": False, "errors": violations[:20]}
            if len(violations) > 20:
                result["errors_more"] = len(violations) - 20
            result["retries_left"] = retries_left
            return result

        # ── Accept: insert revision and update draft ──────────────────
        if is_server_draft:
            # Server draft: update revision 0 with title+body
            # Category, matrix etc are already on revision 0
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    "select * from finding_revisions where job_id = %s and draft_key = %s and revision = 0",
                    (job_id, draft_key),
                )
                rev0 = await cur.fetchone()

            if rev0 is None:
                raise ReviewError("E_INTERNAL", incident="srv_draft_no_rev0")

            # Merge title+body onto the stored content
            stored_content = dict(rev0["content"])
            stored_content["title"] = args["title"]
            stored_content["body"] = args["body"]

            await conn.execute(
                "update finding_revisions set content = %s, content_hash = %s where job_id = %s and draft_key = %s and revision = 0",
                (psycopg.types.json.Jsonb(stored_content), content_hash, job_id, draft_key),
            )

            # Transition server draft from needs_text to accepted
            await conn.execute(
                """update finding_drafts set status = 'accepted', current_revision = 0
                   where job_id = %s and draft_key = %s""",
                (job_id, draft_key),
            )
            await conn.execute("update jobs set last_call_at = now() where job_id = %s", (job_id,))

            return {
                "accepted": True,
                "finding_no": f"F-{draft['finding_no']:02d}" if draft.get("finding_no") else "F-00",
                "draft_key": draft_key,
                "revision": 0,
                "status": "accepted",
                "computed_severity": "Informational",
                "severity_rule": "server_draft",
                "caps_applied": [],
                "evidence_level": "reasoning_only",
                "leads_reopened": [],
                "next_tools": [],
            }

        # ── Model draft acceptance ────────────────────────────────────
        # Issue 2: replace assert (vanishes under -O) with proper validation error.
        if sev_result is None:
            return {
                "accepted": False,
                "errors": [
                    ReviewError(
                        "E_INVALID_ARGUMENT", field="matrix",
                        rule="required for model drafts", value80="",
                    ).envelope()
                ],
            }

        computed_severity = sev_result.severity
        evidence_level = sev_result.evidence_level
        # Issue 4a: >= 2 so Medium also goes to needs_challenge (was >= 3, a severity-laundering bug)
        new_status = "needs_challenge" if _SEV_RANK[computed_severity] >= 2 else "accepted"

        # Assign F-nn on first acceptance (finding_no assigned from job counter)
        if draft is None:
            next_no = int(job["next_finding_no"])
            finding_no = next_no
            await conn.execute(
                """insert into finding_drafts
                   (job_id, draft_key, finding_no, origin, status, current_revision,
                    severity, evidence_level)
                   values (%s, %s, %s, 'model', %s, %s, %s, %s)""",
                (job_id, draft_key, finding_no, new_status, new_revision,
                 computed_severity, evidence_level),
            )
            await conn.execute(
                "update jobs set next_finding_no = %s where job_id = %s",
                (next_no + 1, job_id),
            )
        else:
            finding_no = draft["finding_no"]
            await conn.execute(
                # A new revision carries a new matrix: the post-challenge matrix of the previous
                # revision must not survive it (finalize and the report prefer matrix_effective).
                """update finding_drafts
                   set status = %s, current_revision = %s, severity = %s, evidence_level = %s,
                       matrix_effective = null
                   where job_id = %s and draft_key = %s""",
                (new_status, new_revision, computed_severity, evidence_level, job_id, draft_key),
            )

        # Insert revision
        content_for_revision: dict[str, Any] = {
            k: args[k] for k in args
            if k not in ("job_id", "draft_key", "expected_revision")
        }
        await _insert_revision(
            conn, job_id, draft_key, new_revision,
            content_for_revision, content_hash,
            category, family, matrix["impact_class"],
            computed_severity, sev_result.severity_rule,
            sev_result.caps_applied,
            map_unavailable,  # Issue 3 / V7.5: actual value from map load
        )
        await _insert_quote_ranges(conn, job_id, draft_key, new_revision, quotes)
        if lead_ids:
            await _insert_lead_links(conn, job_id, draft_key, new_revision, lead_ids)

        # Promote leads (Issue 3: carried_lead_ids now populated from _validate_leads)
        await _promote_leads(conn, job_id, draft_key, lead_ids, carried_lead_ids)

        # Demote leads no longer linked (return to open)
        leads_reopened: list[str] = []
        if draft is not None and current_revision >= 0:
            prev_leads = await _get_prev_lead_ids(conn, job_id, draft_key, current_revision)
            new_set = set(lead_ids)
            removed = [lid for lid in prev_leads if lid not in new_set]
            leads_reopened = await _demote_leads_to_open(conn, job_id, removed, draft_key=draft_key)

        # carried_from: set on first acceptance if any lead is origin=previous_report (03 §4.10 step 5)
        if carried_lead_ids and draft is None:
            prev_fid = None  # W0: no previous finding id from lead
            await conn.execute(
                "update finding_drafts set carried_from = %s where job_id = %s and draft_key = %s",
                (prev_fid, job_id, draft_key),
            )

        await conn.execute("update jobs set last_call_at = now() where job_id = %s", (job_id,))

        finding_no_str = f"F-{finding_no:02d}"
        result = {
            "accepted": True,
            "finding_no": finding_no_str,
            "draft_key": draft_key,
            "revision": new_revision,
            "status": new_status,
            "computed_severity": computed_severity,
            "severity_rule": sev_result.severity_rule,
            "caps_applied": sev_result.caps_applied,
            "evidence_level": evidence_level,
            "leads_reopened": leads_reopened,
            "next_tools": _next_tools(new_status),
        }
        return result


def _next_tools(status: str) -> list[str]:
    if status == "needs_challenge":
        return ["review_challenge"]
    if status == "needs_text":
        return ["review_submit_finding"]
    return ["review_finalize"]


# Severity rank for status decision
_SEV_RANK: dict[str, int] = {
    "Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4
}
