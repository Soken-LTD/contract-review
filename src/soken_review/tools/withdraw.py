"""Handler for review_withdraw_finding (03 §4.11, 04 §10).

Registered via @handler("review_withdraw_finding").

Model withdraws a finding it authored.  Effects (03 §4.11):
  - finding_drafts: status -> withdrawn, withdrawn_by='model',
    withdrawn_reason=reason, withdraw_evidence stored
  - Promoted leads: back to open (for origin=previous_report), or dismissed with
    reason=disproved_by_challenge for origin=analyzer (here: just return to open;
    disprove effect is only for challenge kills)
  - Leads in duplicate_of chain pointing at this draft -> back to open
  - Server drafts (origin='server_needs_text') -> E_SERVER_DRAFT
  - Already withdrawn -> idempotent return

Reasons (03 §4.11):
  disproved    – model found a counterexample; 1-3 quoted code lines required
  merged_into  – merged with another finding; target draft_key required and must be live
"""

from __future__ import annotations

from typing import Any

import psycopg_pool
from psycopg.rows import dict_row

from ..db.pool import get_pool
from ..engine.numbers import lex_numbers
from ..engine.text_gate import CheckContext, check_text
from ..errors import ReviewError
from ..pinning.quote_match import QuoteMatchError, normalize_lines, quote_match
from ..pinning.store import PinnedSource
from ..server import handler
from .context import JobContext

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
        raise ReviewError("E_INTERNAL", incident="withdraw not wired (ctx is None)")
    return _ctx


_FROZEN_STATES = frozenset({"finalized", "render_queued", "rendering", "rendered", "render_failed"})
_TERMINAL_STATES = frozenset({"insufficient_source", "failed", "expired", "deleted"})


def _is_comment_only(text: str) -> bool:
    lines = normalize_lines(text)
    if not lines:
        return True
    comment_starts = ("//", "#", "/*", "*/", " *", "(*", "*)")
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if not any(stripped.startswith(p) for p in comment_starts):
            return False
    return True


@handler("review_withdraw_finding")
async def handle_review_withdraw_finding(args: dict[str, Any]) -> dict[str, Any]:
    """Withdraw a model-authored finding (03 §4.11).

    Idempotent: already withdrawn → return current state unchanged.
    """
    job_id: str = args["job_id"]
    draft_key: str = args["draft_key"]
    reason: str = args["reason"]
    quotes: list[dict[str, Any]] = args.get("quotes") or []
    merged_into: str | None = args.get("merged_into")
    note: str = args.get("note", "")
    pool = _get_pool()

    async with pool.connection() as conn, conn.transaction():
        # Lock job row
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from jobs where job_id = %s for update", (job_id,))
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

        # Load draft
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from finding_drafts where job_id = %s and draft_key = %s for update",
                (job_id, draft_key),
            )
            draft = await cur.fetchone()

        if draft is None:
            return {"accepted": False, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=draft_key).envelope()
            ]}

        # Server drafts cannot be withdrawn by the model
        if draft["origin"] == "server_needs_text":
            return {"accepted": False, "errors": [
                ReviewError("E_SERVER_DRAFT").envelope()
            ]}

        # Idempotent: already withdrawn
        if draft["status"] == "withdrawn":
            leads_reopened: list[str] = []
            return {
                "accepted": True,
                "draft_key": draft_key,
                "withdrawn_by": draft.get("withdrawn_by", "model"),
                "leads_reopened": leads_reopened,
            }

        # Must be in a state that can be withdrawn
        if draft["status"] not in ("needs_challenge", "accepted", "needs_text"):
            return {"accepted": False, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=draft_key).envelope()
            ]}

        # ── Reason-specific validation ────────────────────────────────────────
        violations: list[dict[str, Any]] = []

        # V5/V6 on note
        for v in check_text(note, "model", CheckContext(field="withdraw.note")):
            violations.append(ReviewError(
                v.code, rule=v.rule_id,
                match=v.match[:80] if v.match else "",
                cp=(v.match[:5] if v.match else ""),
                pos=v.span[0],
                token=(v.match[:40] if v.match else ""),
            ).envelope())
        for v in lex_numbers(note):
            violations.append(ReviewError(
                v.code, rule=v.rule_id,
                match=v.match[:80] if v.match else "",
                token=v.match[:40] if v.match else "",
                field="withdraw.note",
                cp=(v.match[:5] if v.match else ""),
                pos=v.span[0],
            ).envelope())

        if violations:
            return {"accepted": False, "errors": violations}

        evidence: dict[str, Any] = {"reason": reason, "note": note}

        if reason == "disproved":
            # Need 1-3 quoted code lines
            if not quotes or len(quotes) < 1:
                return {"accepted": False, "errors": [
                    ReviewError("E_WITHDRAW_EVIDENCE").envelope()
                ]}
            if len(quotes) > 3:
                return {"accepted": False, "errors": [
                    ReviewError("E_WITHDRAW_EVIDENCE").envelope()
                ]}

            # Load pin for quote matching
            try:
                pin_root = _get_ctx().get_pin_root()
                pin = PinnedSource.load(pin_root, job_id)
            except (FileNotFoundError, OSError, ValueError):
                raise ReviewError("E_JOB_NOT_READY", state="pin_not_found", eta_s=60)

            for q in quotes:
                qt = q.get("text", "")
                # Comment-only check
                if _is_comment_only(qt):
                    return {"accepted": False, "errors": [
                        ReviewError("E_WITHDRAW_EVIDENCE").envelope()
                    ]}
                q_file = q.get("file", "")
                q_start = q.get("start", 0)
                q_end = q.get("end", 0)
                try:
                    quote_match(pin, q_file, q_start, q_end, qt)
                except QuoteMatchError as e:
                    return {"accepted": False, "errors": [
                        ReviewError(e.code, **e.detail).envelope()
                    ]}

            evidence["quotes"] = quotes

        elif reason == "merged_into":
            if not merged_into:
                return {"accepted": False, "errors": [
                    ReviewError("E_WITHDRAW_EVIDENCE").envelope()
                ]}
            # Target must be a live draft (accepted or needs_challenge) in same family
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    "select * from finding_drafts where job_id = %s and draft_key = %s",
                    (job_id, merged_into),
                )
                target_draft = await cur.fetchone()

            if target_draft is None:
                return {"accepted": False, "errors": [
                    ReviewError("E_WITHDRAW_EVIDENCE").envelope()
                ]}
            if target_draft["status"] not in ("accepted", "needs_challenge"):
                return {"accepted": False, "errors": [
                    ReviewError("E_WITHDRAW_EVIDENCE").envelope()
                ]}
            # Cannot merge into itself
            if merged_into == draft_key:
                return {"accepted": False, "errors": [
                    ReviewError("E_WITHDRAW_EVIDENCE").envelope()
                ]}

            evidence["merged_into"] = merged_into

        else:
            return {"accepted": False, "errors": [
                ReviewError("E_INVALID_ARGUMENT",
                            field="reason",
                            rule="must be disproved or merged_into",
                            value80=str(reason)[:80]).envelope()
            ]}

        # ── Commit withdrawal ─────────────────────────────────────────────────
        await conn.execute(
            """update finding_drafts
               set status = 'withdrawn', withdrawn_by = 'model',
                   withdrawn_reason = %s, withdraw_evidence = %s
               where job_id = %s and draft_key = %s""",
            (reason,
             __import__("psycopg").types.json.Jsonb(evidence),
             job_id, draft_key),
        )

        # Demote promoted leads back to open
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """select lead_id from leads
                   where job_id = %s and state = 'promoted' and state_ref = %s""",
                (job_id, draft_key),
            )
            promoted_leads = await cur.fetchall()

        reopened: list[str] = []
        for lead in promoted_leads:
            await conn.execute(
                "update leads set state = 'open', state_ref = null where job_id = %s and lead_id = %s",
                (job_id, lead["lead_id"]),
            )
            reopened.append(lead["lead_id"])

        # Return duplicate_of chains pointing at this draft back to open
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """select lead_id from leads
                   where job_id = %s and state = 'dismissed' and reason = 'duplicate_of'
                     and state_ref = %s""",
                (job_id, draft_key),
            )
            chain_leads = await cur.fetchall()

        for lead in chain_leads:
            await conn.execute(
                "update leads set state = 'open', reason = null, state_ref = null "
                "where job_id = %s and lead_id = %s",
                (job_id, lead["lead_id"]),
            )
            reopened.append(lead["lead_id"])

        await conn.execute(
            "update jobs set last_call_at = now() where job_id = %s", (job_id,)
        )

    return {
        "accepted": True,
        "draft_key": draft_key,
        "withdrawn_by": "model",
        "leads_reopened": reopened,
    }
