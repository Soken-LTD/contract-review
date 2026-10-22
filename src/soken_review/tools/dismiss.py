"""Handler for review_dismiss_lead (03 §4.9, 04 §10).

Registered via @handler("review_dismiss_lead").

Partial success: every item in the request is processed independently.
If a lead is already dismissed (or not found) it lands in `already[]`.
If a lead passes all checks, it goes to `dismissed[]`.
Rejected items go to `rejected[]` with their errors.

Reasons (04 §10):
  fp_guarded           – quoted code line guards against the attack; non-comment required
  fp_unreachable       – caller never reaches the location (requires semantic map)
  not_a_vulnerability  – the detector pattern matched but the code at the location has no such
                         weakness (analyzer leads only); a non-comment code quote inside the
                         lead's function plus a note of at least 40 characters stating why.
                         The server cannot prove a negative here, so this is the reviewer's
                         recorded triage call: quote, note and lead land in lead_dismissals.
  duplicate_of         – same category/family as a promoted or accepted draft (04 §10 D1-D4)
  fixed                – previous_report lead only; item_id confirms the fix

Design choices (fail-closed):
  - fp_unreachable without a map → E_DISMISS_UNCHECKABLE (cannot verify claim)
  - fp_guarded with comment-only quote → E_DISMISS_COMMENT_ONLY
  - not_a_vulnerability without a quote inside the lead's function or without a note →
    E_DISMISS_UNCHECKABLE / E_INVALID_ARGUMENT (a bare dismissal is not a triage record)
  - fixed for origin != previous_report → E_FIX_NOT_EVIDENT
  - duplicate_of: each rule failure is a separate check; fail on first
  - TOCTOU: per-lead UPDATE with rowcount check
"""

from __future__ import annotations

from typing import Any

import psycopg
import psycopg_pool
from psycopg.rows import dict_row

from ..db.pool import get_pool
from ..engine.text_gate import CheckContext, check_text
from ..errors import ReviewError
from ..pinning.quote_match import QuoteMatchError, normalize_lines, quote_match
from ..pinning.store import PinnedSource
from ..server import handler
from .challenge import _load_map_with_status, _parse_range_ref, _resolve_scope, _run_auto
from .context import JobContext
from .submit import _family_from_chain

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
        raise ReviewError("E_INTERNAL", incident="dismiss not wired (ctx is None)")
    return _ctx


_FROZEN_STATES = frozenset({"finalized", "render_queued", "rendering", "rendered", "render_failed"})
_TERMINAL_STATES = frozenset({"insufficient_source", "failed", "expired", "deleted"})


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith(("//", "#", "/*", "*/", " *", "(*", "*)"))


def _is_comment_only_text(text: str) -> bool:
    for line in normalize_lines(text):
        if not _is_comment_line(line):
            return False
    return True


def _check_note(note: str, lead_id: str) -> list[dict[str, Any]]:
    """Gate a dismissal note. Returns list of error envelopes.

    The note lands in `lead_dismissals` (audit log), never in the report, so only the `note`
    scope applies (control characters and scripts); the prose rules and the number provenance
    check are report-text rules and only burned attempts here."""
    errors: list[dict[str, Any]] = []
    for v in check_text(note, "note", CheckContext(field=f"dismiss.{lead_id}.note")):
        errors.append(ReviewError(
            v.code, rule=v.rule_id,
            match=v.match[:80] if v.match else "",
            cp=(v.match[:5] if v.match else ""),
            pos=v.span[0],
            token=(v.match[:40] if v.match else ""),
        ).envelope())
    return errors


_NAV_MIN_NOTE_CHARS = 40


def _lead_function_ranges(map_doc: dict | None, lead: dict[str, Any]) -> list[tuple[str, int, int]]:
    """Line ranges a `not_a_vulnerability` quote must touch: the lexical spans enclosing the
    lead location (function, modifier or contract-level span), else the lead's own lines."""
    path, start, end = lead["path"], int(lead["start_line"]), int(lead["end_line"])
    out: list[tuple[str, int, int]] = []
    for sp in (map_doc or {}).get("spans", []) or []:
        if sp.get("file") != path:
            continue
        s, e = int(sp.get("start", 0)), int(sp.get("end", 0))
        if s and e and not (e < start or s > end):
            out.append((path, s, e))
    return out or [(path, start, end)]


# ── Duplicate-of checks (04 §10 D1–D4) ───────────────────────────────────────

async def _check_duplicate_target(
    lead: dict[str, Any],
    target: str,
    conn: psycopg.AsyncConnection,
    job_id: str,
    family: str,
) -> list[dict[str, Any]]:
    """Validate duplicate_of target. Returns list of error envelopes on failure."""
    # Resolve: target is either a draft_key or a LEAD-XXXX id
    if target.startswith("LEAD-"):
        # Target is a lead - must be promoted and same category
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from leads where job_id = %s and lead_id = %s",
                (job_id, target),
            )
            target_lead = await cur.fetchone()
        if target_lead is None:
            return [ReviewError("E_DUPLICATE_TARGET", rule="target_not_found").envelope()]
        if target_lead["state"] != "promoted":
            return [ReviewError("E_DUPLICATE_TARGET", rule="D2_target_not_promoted").envelope()]
        # D1: same category
        if target_lead["category"] != lead["category"]:
            return [ReviewError("E_DUPLICATE_TARGET", rule="D1_category_mismatch").envelope()]
        # D4: target severity >= lead severity
        if target_lead["sev_rank"] < lead["sev_rank"]:
            return [ReviewError("E_DUPLICATE_TARGET", rule="D4_target_lower_severity").envelope()]
        # D3: location overlap
        if (target_lead["path"] != lead["path"] or
                target_lead["end_line"] < lead["start_line"] or
                target_lead["start_line"] > lead["end_line"]):
            return [ReviewError("E_DUPLICATE_TARGET", rule="D3_no_overlap").envelope()]
        return []

    # Target is a draft_key
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "select * from finding_drafts where job_id = %s and draft_key = %s",
            (job_id, target),
        )
        target_draft = await cur.fetchone()

    if target_draft is None:
        return [ReviewError("E_DUPLICATE_TARGET", rule="target_not_found").envelope()]

    # D2: target must be accepted or needs_challenge (live)
    if target_draft["status"] not in ("accepted", "needs_challenge"):
        return [ReviewError("E_DUPLICATE_TARGET", rule="D2_target_not_live").envelope()]

    # D1: category must match - check via finding_revisions
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select category, category_family from finding_revisions
               where job_id = %s and draft_key = %s and revision = %s""",
            (job_id, target, target_draft["current_revision"]),
        )
        target_rev = await cur.fetchone()

    if target_rev is None:
        return [ReviewError("E_DUPLICATE_TARGET", rule="target_rev_missing").envelope()]

    if target_rev["category"] != lead["category"]:
        return [ReviewError("E_DUPLICATE_TARGET", rule="D1_category_mismatch").envelope()]

    # D4: target severity >= lead severity (by rank)
    _SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Info": 1}
    target_sev_rank = _SEV_RANK.get(target_draft["severity"] or "Informational", 1)
    if target_sev_rank < lead["sev_rank"]:
        return [ReviewError("E_DUPLICATE_TARGET", rule="D4_target_lower_severity").envelope()]

    # D3: location overlap — check via quote ranges
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select path, start_line, end_line from finding_quote_ranges
               where job_id = %s and draft_key = %s and revision = %s and role = 'location'""",
            (job_id, target, target_draft["current_revision"]),
        )
        target_quotes = await cur.fetchall()

    lead_path = lead["path"]
    lead_start = lead["start_line"]
    lead_end = lead["end_line"]

    overlaps = any(
        q["path"] == lead_path and
        q["start_line"] <= lead_end and
        q["end_line"] >= lead_start
        for q in target_quotes
    )
    if not overlaps:
        return [ReviewError("E_DUPLICATE_TARGET", rule="D3_no_overlap").envelope()]

    return []


# ── Main handler ──────────────────────────────────────────────────────────────

@handler("review_dismiss_lead")
async def handle_review_dismiss_lead(args: dict[str, Any]) -> dict[str, Any]:
    """Dismiss one or more analyzer leads with stated reasons (03 §4.9, 04 §10).

    Partial success model: each item processed independently.
    Returns {dismissed[], already[], rejected[], high_medium_open: int}.
    """
    job_id: str = args["job_id"]
    items: list[dict[str, Any]] = args["items"]
    pool = _get_pool()

    # State check — read-only first pass
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

    # Load map and pin — pin_root must be resolved before both try blocks
    pin_root = _get_ctx().get_pin_root()

    try:
        map_doc = _load_map_with_status(pin_root, job_id)
    except FileNotFoundError:
        map_doc = None  # map worker not run yet; degrade gracefully
    except (OSError, ValueError) as exc:
        raise ReviewError("E_INTERNAL", incident=f"map load failed (corrupt/unreadable): {exc}") from exc

    try:
        pin = PinnedSource.load(pin_root, job_id)
    except (FileNotFoundError, OSError, ValueError):
        raise ReviewError("E_JOB_NOT_READY", state="pin_not_found", eta_s=60)

    family = _family_from_chain(job.get("chain"))

    dismissed: list[str] = []
    already: list[str] = []
    rejected: list[dict[str, Any]] = []

    for item in items:
        lead_id: str = item["lead_id"]
        reason: str = item["reason"]
        quotes: list[dict[str, Any]] = item.get("quotes") or []
        duplicate_of: str | None = item.get("duplicate_of")
        fix_item_id: str | None = item.get("item_id")
        note: str = item.get("note", "")

        # Load the lead
        async with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from leads where job_id = %s and lead_id = %s",
                (job_id, lead_id),
            )
            lead = await cur.fetchone()

        if lead is None:
            rejected.append({"lead_id": lead_id, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=lead_id).envelope()
            ]})
            continue

        if lead["state"] == "dismissed":
            already.append(lead_id)
            continue

        if lead["state"] != "open":
            rejected.append({"lead_id": lead_id, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=lead_id).envelope()
            ]})
            continue

        item_errors: list[dict[str, Any]] = []

        # V5/V6 on note
        item_errors.extend(_check_note(note, lead_id))

        # Reason-specific checks
        if reason == "fp_guarded":
            # fp_guarded is only valid for reentrancy and access_control categories (04 §10).
            # Without a semantic layer the guard class cannot be verified — reject with
            # E_DISMISS_UNCHECKABLE so the model must provide a different reason or more evidence.
            lead_category = lead.get("category", "")
            if lead_category in ("evm.reentrancy", "cairo.reentrancy"):
                required_guard_class: str | None = "reentrancy_lock"
            elif "access_control" in lead_category:
                required_guard_class = "caller_check"
            else:
                required_guard_class = None
                item_errors.append(ReviewError(
                    "E_DISMISS_UNCHECKABLE",
                    lead=lead_id,
                    reason="fp_guarded only valid for reentrancy/access_control categories",
                ).envelope())

            if required_guard_class is not None:
                if map_doc is None or map_doc.get("semantic") is None:
                    item_errors.append(ReviewError(
                        "E_DISMISS_UNCHECKABLE",
                        lead=lead_id,
                        reason="fp_guarded requires semantic map to verify guard class",
                    ).envelope())
                elif not quotes:
                    item_errors.append(ReviewError(
                        "E_DISMISS_UNCHECKABLE",
                        lead=lead_id, reason="no quotes provided",
                    ).envelope())
                else:
                    # Resolve entry function scope for the lead location (guards must be
                    # inside the entry function's scope, not anywhere in the codebase).
                    lead_loc = [{"file": lead["path"], "start": lead["start_line"],
                                 "end": lead["end_line"]}]
                    # _resolve_scope returns (ranges, not_covered, source); source is unused here
                    # because fp_guarded already guards against map_doc.semantic is None above.
                    scope_ranges, scope_nc, _scope_src = _resolve_scope(
                        "entry_function", family, map_doc, lead_loc
                    )

                    # Fail-closed: if scope cannot be resolved (not_covered or empty),
                    # we cannot verify that the guard covers the lead's entry function path.
                    if scope_nc or not scope_ranges:
                        item_errors.append(ReviewError(
                            "E_DISMISS_UNCHECKABLE",
                            lead=lead_id,
                            reason="fp_guarded: entry function scope unresolvable",
                        ).envelope())
                    else:
                        # Build lookup: spans of functions whose body overlaps the lead
                        # location (these are the functions whose guards are relevant).
                        functions = map_doc.get("semantic", {}).get("functions", [])  # type: ignore[union-attr]
                        spans_map = {sp["id"]: sp for sp in map_doc.get("spans", [])}  # type: ignore[union-attr]
                        lead_path = lead["path"]
                        lead_start = lead["start_line"]
                        lead_end = lead["end_line"]

                        for q in quotes[:3]:
                            qt = q.get("text")
                            # Missing fields are input errors — do NOT default to lead location
                            q_file = q.get("file")
                            q_start = q.get("start")
                            q_end = q.get("end")
                            if qt is None or q_file is None or q_start is None or q_end is None:
                                item_errors.append(ReviewError(
                                    "E_INVALID_ARGUMENT",
                                    field="dismiss.quotes",
                                    rule="file, start, end, text are required",
                                    value80="",
                                ).envelope())
                                break
                            if _is_comment_only_text(qt):
                                item_errors.append(ReviewError("E_DISMISS_COMMENT_ONLY").envelope())
                                break
                            try:
                                quote_match(pin, q_file, q_start, q_end, qt)
                            except QuoteMatchError as e:
                                item_errors.append(ReviewError(e.code, **e.detail).envelope())
                                continue
                            # Quote must lie within the resolved entry function scope (04 §10).
                            in_scope = any(
                                (parsed := _parse_range_ref(r)) is not None
                                and parsed[0] == q_file
                                and not (q_end < parsed[1] or q_start > parsed[2])
                                for r in scope_ranges
                            )
                            if not in_scope:
                                item_errors.append(ReviewError(
                                    "E_DISMISS_UNCHECKABLE",
                                    lead=lead_id,
                                    reason="quoted guard line is outside the lead's entry function scope",
                                ).envelope())
                                continue
                            # Verify guard class: quoted line must appear in the guards list of a
                            # function whose span encloses the lead location (04 §10).
                            # Parse guards[].line exactly: rpartition ":" → path + integer lineno.
                            guard_found = False
                            for fn in functions:
                                # Only consider functions whose span overlaps the lead location
                                fn_span = spans_map.get(fn.get("span", ""), {})
                                if (fn_span.get("file") != lead_path
                                        or fn_span.get("end", 0) < lead_start
                                        or fn_span.get("start", 0) > lead_end):
                                    continue
                                for g in fn.get("guards", []):
                                    if g.get("class") != required_guard_class:
                                        continue
                                    gline = g.get("line") or ""
                                    g_path, _, g_lineno_s = gline.rpartition(":")
                                    try:
                                        g_lineno = int(g_lineno_s)
                                    except ValueError:
                                        continue
                                    if g_path == q_file and q_start <= g_lineno <= q_end:
                                        guard_found = True
                                        break
                                if guard_found:
                                    break
                            if not guard_found:
                                item_errors.append(ReviewError(
                                    "E_DISMISS_UNCHECKABLE",
                                    lead=lead_id,
                                    reason=(
                                        f"quoted line not found as {required_guard_class} "
                                        "guard in the function enclosing the lead location"
                                    ),
                                ).envelope())

        elif reason == "fp_unreachable":
            # Delegate to _run_auto which uses BFS call-graph analysis (04 §10).
            # Dismiss only when _run_auto returns 'present' (proven unreachable via full map).
            # 'unknown' (partial map or no semantic layer) -> E_DISMISS_UNCHECKABLE (fail closed).
            location_quotes_for_auto = [{
                "file": lead["path"],
                "start": lead["start_line"],
                "end": lead["end_line"],
            }]
            auto_result = _run_auto(
                "map.unreachable", lead.get("category", ""), map_doc, location_quotes_for_auto
            )
            if auto_result != "present":
                item_errors.append(ReviewError(
                    "E_DISMISS_UNCHECKABLE",
                    lead=lead_id,
                    reason=(
                        f"map.unreachable={auto_result}; "
                        "proof of unreachability requires full map"
                    ),
                ).envelope())

        elif reason == "not_a_vulnerability":
            # The reviewer's triage call on analyzer noise (best-practice detectors rated High by
            # the analyzer, patterns that do not apply at this location). Not provable by the
            # server, so the record must carry evidence: a real code quote inside the lead's
            # function (quote-matched against the pin) and a stated reason. Carried leads keep
            # their own rule (`fixed`).
            if lead.get("origin") != "analyzer":
                item_errors.append(ReviewError(
                    "E_DISMISS_UNCHECKABLE", lead=lead_id,
                    reason="not_a_vulnerability applies to analyzer leads only; carried leads close as fixed",
                ).envelope())
            elif len(note.strip()) < _NAV_MIN_NOTE_CHARS:
                item_errors.append(ReviewError(
                    "E_INVALID_ARGUMENT", field=f"dismiss.{lead_id}.note",
                    rule=f"not_a_vulnerability needs a note of at least {_NAV_MIN_NOTE_CHARS} characters "
                         "stating why the detector pattern is not a weakness at this location",
                    value80=note[:80],
                ).envelope())
            elif not quotes:
                item_errors.append(ReviewError(
                    "E_DISMISS_UNCHECKABLE", lead=lead_id,
                    reason="not_a_vulnerability requires a code quote inside the lead's function",
                ).envelope())
            else:
                allowed = _lead_function_ranges(map_doc, lead)
                for q in quotes[:3]:
                    qt = q.get("text")
                    q_file, q_start, q_end = q.get("file"), q.get("start"), q.get("end")
                    if qt is None or q_file is None or q_start is None or q_end is None:
                        item_errors.append(ReviewError(
                            "E_INVALID_ARGUMENT", field="dismiss.quotes",
                            rule="file, start, end, text are required", value80="",
                        ).envelope())
                        break
                    if _is_comment_only_text(qt):
                        item_errors.append(ReviewError("E_DISMISS_COMMENT_ONLY").envelope())
                        break
                    try:
                        quote_match(pin, q_file, q_start, q_end, qt)
                    except QuoteMatchError as e:
                        item_errors.append(ReviewError(e.code, **e.detail).envelope())
                        continue
                    if not any(q_file == p and not (q_end < s or q_start > e) for p, s, e in allowed):
                        item_errors.append(ReviewError(
                            "E_DISMISS_UNCHECKABLE", lead=lead_id,
                            reason="quote lies outside the function that holds the lead location "
                                   + ", ".join(f"{p}:{s}-{e}" for p, s, e in allowed[:3]),
                        ).envelope())

        elif reason == "duplicate_of":
            if not duplicate_of:
                item_errors.append(ReviewError(
                    "E_DUPLICATE_TARGET", rule="target_required",
                ).envelope())
            else:
                async with pool.connection() as conn:
                    dup_errors = await _check_duplicate_target(lead, duplicate_of, conn, job_id, family)
                item_errors.extend(dup_errors)

        elif reason == "fixed":
            # Fixed only for previous_report leads (carried leads)
            if lead["origin"] != "previous_report":
                item_errors.append(ReviewError(
                    "E_FIX_NOT_EVIDENT", lead_id=lead_id,
                ).envelope())
            elif lead.get("located") == "moved":
                # located = moved means the code was moved, not fixed
                item_errors.append(ReviewError(
                    "E_FIX_NOT_EVIDENT", lead_id=lead_id,
                ).envelope())
            else:
                # Fixed: need to verify the fix exists via quotes or item_id
                # At W0: if no evidence provided → E_FIX_NOT_EVIDENT
                if not quotes and not fix_item_id:
                    item_errors.append(ReviewError(
                        "E_FIX_NOT_EVIDENT", lead_id=lead_id,
                    ).envelope())
                elif quotes:
                    # Verify quotes exist in pinned source; missing fields are input errors
                    for q in quotes[:3]:
                        qt = q.get("text") or ""
                        q_file = q.get("file")
                        q_start = q.get("start")
                        q_end = q.get("end")
                        if not qt or q_file is None or q_start is None or q_end is None:
                            item_errors.append(ReviewError(
                                "E_INVALID_ARGUMENT",
                                field="dismiss.quotes",
                                rule="file, start, end, text are required",
                                value80="",
                            ).envelope())
                            break
                        try:
                            quote_match(pin, q_file, q_start, q_end, qt)
                        except QuoteMatchError as e:
                            item_errors.append(ReviewError(e.code, **e.detail).envelope())

        else:
            item_errors.append(ReviewError(
                "E_INVALID_ARGUMENT",
                field="reason",
                rule="must be fp_guarded, fp_unreachable, not_a_vulnerability, duplicate_of, or fixed",
                value80=str(reason)[:80],
            ).envelope())

        if item_errors:
            rejected.append({"lead_id": lead_id, "errors": item_errors})
            continue

        # ── Commit the dismissal ─────────────────────────────────────────────
        async with pool.connection() as conn, conn.transaction():
            # TOCTOU guard: lock the job row and re-verify state inside the write transaction
            # (prevents state resurrection if concurrent finalize ran between our guard check
            # and this write — e.g. job transitions finalized → frozen mid-loop).
            async with conn.cursor(row_factory=dict_row) as cur2:
                await cur2.execute(
                    "select state from jobs where job_id = %s for update", (job_id,)
                )
                locked_job = await cur2.fetchone()
            if locked_job is None:
                raise ReviewError("E_JOB_NOT_FOUND")
            locked_state = locked_job["state"]
            if locked_state in _FROZEN_STATES:
                # Abort entire batch: job was finalized concurrently
                return {"accepted": False, "errors": [ReviewError("E_JOB_FROZEN").envelope()]}
            if locked_state not in ("ready",):
                return {"accepted": False, "errors": [
                    ReviewError("E_JOB_NOT_READY", state=locked_state, eta_s=0).envelope()
                ]}

            async with conn.cursor(row_factory=dict_row) as cur:
                if reason == "duplicate_of":
                    await cur.execute(
                        """update leads set state = 'dismissed', reason = %s, state_ref = %s
                           where job_id = %s and lead_id = %s and state = 'open'""",
                        (reason, duplicate_of, job_id, lead_id),
                    )
                else:
                    await cur.execute(
                        """update leads set state = 'dismissed', reason = %s
                           where job_id = %s and lead_id = %s and state = 'open'""",
                        (reason, job_id, lead_id),
                    )
                if cur.rowcount == 0:
                    # Concurrent steal (TOCTOU)
                    already.append(lead_id)
                    continue

            # Record dismissal audit log
            await conn.execute(
                """insert into lead_dismissals (job_id, lead_id, reason, target, quotes, note)
                   values (%s, %s, %s, %s, %s, %s)""",
                (job_id, lead_id, reason, duplicate_of,
                 __import__("psycopg").types.json.Jsonb(quotes) if quotes else None,
                 note),
            )
            await conn.execute(
                "update jobs set last_call_at = now() where job_id = %s", (job_id,)
            )

        dismissed.append(lead_id)

    # Count open High/Medium analyzer leads for caller awareness
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """select count(*) from leads
                   where job_id = %s and origin = 'analyzer'
                     and severity_norm in ('High','Medium') and state = 'open'""",
            (job_id,),
        )
        hm_open = (await cur.fetchone())[0]

    return {
        "accepted": True,
        "dismissed": dismissed,
        "already": already,
        "rejected": rejected,
        "high_medium_open": hm_open,
    }
