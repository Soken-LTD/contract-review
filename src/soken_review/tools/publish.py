"""`review_publish` (03 §4.16): status lookup for automatically published reports.

Since CEO decision 2026-10-24, every successfully rendered report is enqueued for
publication automatically by render.py in the same transaction as the `rendered`
transition.  This tool is now a status endpoint:

- No consent argument: returns the current publish status and public URL.
- Consent argument: records the explicit consent entry in publish_consent_log
  (for callers who want an explicit audit trail), then returns current status.
  If no publish_request exists yet (render not complete), validates the consent
  and creates the row respecting the hourly rate cap.

Ownership gate (IDOR prevention): the caller must supply the report's manage_key
(the #k= fragment of its manage_url) so only the job owner can query publish status.

## Security properties

1. report_id must exist in reports (our DB) — no arbitrary content accepted.
2. PDF bytes come from our object store (reports/<report_id>/<render_no>/report.pdf).
3. Title/filename derives from reports.out_name (server-side, validated column) and is
   additionally sanitized through sanitize_filename() (allowlist charset).
4. Idempotent by report_id (UNIQUE constraint in publish_requests).
5. Privileged git push executed by the worker process using fixed argv arrays; credentials
   never returned to the client in any response field.
6. Full consent audit log (party, name, statement, timestamp) in publish_consent_log.
7. No pricing / "free" information in any response.
8. Rate limit (SOKEN_PUBLISH_RATE_LIMIT_HOUR) applied in publish_worker per batch run
   so excess stays queued, not dropped.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Any

import psycopg_pool
from psycopg.rows import dict_row

from ..db.pool import get_pool
from ..errors import ReviewError
from ..quota import job_target
from ..server import handler
from ..worker.publish_worker import PUBLISH_LABEL, public_filename, public_url, read_subject
from .report import manage_key as _report_manage_key

# SOKEN_PUBLISH_RATE_LIMIT_HOUR: kept here for the fallback enqueue path (render auto-enqueue
# bypasses this; the worker uses it as a per-batch cap — see publish_worker.py).

logger = logging.getLogger(__name__)

_pool: psycopg_pool.AsyncConnectionPool | None = None

# Maximum new publish requests per hour (configurable; default 20).
_RATE_LIMIT_HOUR = int(os.environ.get("SOKEN_PUBLISH_RATE_LIMIT_HOUR", "20"))

# Consent field constraints (validated at this layer, not in JSON schema, so the
# error message is actionable for the caller).
_CONSENT_FIELDS = ("party", "name", "statement", "timestamp")
_CONSENT_MAX = {"party": 200, "name": 100, "statement": 500, "timestamp": 50}


def set_pool(pool: psycopg_pool.AsyncConnectionPool) -> None:
    global _pool
    _pool = pool


def _get_pool() -> psycopg_pool.AsyncConnectionPool:
    return _pool if _pool is not None else get_pool()


# ---------------------------------------------------------------------------
# Consent validation
# ---------------------------------------------------------------------------

def _validate_consent(consent: Any) -> None:
    """Raise ReviewError(E_INVALID_ARGUMENT) on invalid consent object."""
    if not isinstance(consent, dict):
        raise ReviewError("E_INVALID_ARGUMENT", field="consent", rule="type",
                          value80="(not an object)", example="consent must be an object")
    for field in _CONSENT_FIELDS:
        val = consent.get(field)
        if not val or not isinstance(val, str) or not val.strip():
            raise ReviewError(
                "E_INVALID_ARGUMENT",
                field=f"consent.{field}",
                rule="required",
                value80="(missing or empty)",
                example=f"consent.{field} must be a non-empty string",
            )
        max_len = _CONSENT_MAX[field]
        if len(val) > max_len:
            raise ReviewError(
                "E_INVALID_ARGUMENT",
                field=f"consent.{field}",
                rule="maxLength",
                value80=val[:80],
                example=f"consent.{field} must be at most {max_len} chars",
            )


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _load_job_by_id(job_id: str) -> dict[str, Any] | None:
    async with _get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("select * from jobs where job_id = %s", (job_id,))
        return await cur.fetchone()


async def _load_report(report_id: str) -> dict[str, Any] | None:
    async with _get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("select * from reports where report_id = %s", (report_id,))
        return await cur.fetchone()


async def _existing_request(report_id: str) -> dict[str, Any] | None:
    async with _get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "select * from publish_requests where report_id = %s", (report_id,)
        )
        return await cur.fetchone()


async def _rate_limit_count() -> int:
    async with _get_pool().connection() as conn, conn.cursor() as cur:
        await cur.execute(
            "select count(*) from publish_requests where queued_at > now() - interval '1 hour'"
        )
        row = await cur.fetchone()
        return row[0] if row else 0


async def _log_consent(report_id: str, consent: dict[str, Any]) -> None:
    """Append one consent entry to publish_consent_log (no publish_request side-effect).

    Used when the publish_request already exists (auto-enqueued by render.py) and the
    caller provides an explicit consent object as an additional audit record.
    """
    async with _get_pool().connection() as conn:
        await conn.execute(
            """insert into publish_consent_log (report_id, party, name, statement, client_ts)
               values (%s, %s, %s, %s, %s)""",
            (report_id, consent["party"], consent["name"], consent["statement"], consent["timestamp"]),
        )


async def _enqueue(report_id: str, job_id: str, consent: dict[str, Any]) -> None:
    """Log consent and insert the publish_request row in a single transaction.

    Used when no publish_request exists yet (edge case: caller provides consent before
    render completes, or auto-enqueue failed for some reason).
    """
    async with _get_pool().connection() as conn, conn.transaction():
        await conn.execute(
            """insert into publish_consent_log (report_id, party, name, statement, client_ts)
               values (%s, %s, %s, %s, %s)""",
            (
                report_id,
                consent["party"],
                consent["name"],
                consent["statement"],
                consent["timestamp"],
            ),
        )
        await conn.execute(
            """insert into publish_requests (report_id, job_id, status)
               values (%s, %s, 'queued')
               on conflict (report_id) do nothing""",
            (report_id, job_id),
        )


# ---------------------------------------------------------------------------
# Ownership gate
# ---------------------------------------------------------------------------

def _verify_owner(report_id: str, report: dict[str, Any], args: dict[str, Any]) -> None:
    """Prove the caller owns this report before anything is offered or enqueued.

    Requires the report's manage key (the ``#k=`` fragment of its manage_url, issued only to
    the owner at review time) and constant-time compares it against the server-derived key.
    Without this, any caller who learns a report_id or job_id could publish someone else's
    report to our public site (IDOR). Raises E_PUBLISH_NOT_OWNER on a missing or wrong key.
    """
    provided = args.get("manage_key")
    expected = _report_manage_key(report_id, report["key_version"])
    if not isinstance(provided, str) or not hmac.compare_digest(provided.encode(), expected.encode()):
        raise ReviewError("E_PUBLISH_NOT_OWNER", report_id=report_id)


# ---------------------------------------------------------------------------
# Offer helpers
# ---------------------------------------------------------------------------

def _offer_response(report: dict[str, Any], filename: str | None = None, replaces: bool = False) -> dict[str, Any]:
    """Build the Phase-1 offer payload. `filename`: the planned public name (default: from out_name)."""
    report_id: str = report["report_id"]
    safe_filename = filename or public_filename(report["out_name"].removesuffix(".pdf"))
    replaced = (" This target already has a published report; it will be replaced by this one, "
                "not listed twice.") if replaces else ""
    return {
        "accepted": True,
        "phase": "offer",
        "report_id": report_id,
        "sanitized_filename": safe_filename,
        "future_public_url": public_url(safe_filename),
        "disclaimer": (
            "This report will be published automatically, without review by SOKEN LTD, and stay "
            "public at the URL above and on soken.dev/audits, labelled " + PUBLISH_LABEL + "."
            + replaced + " Deleting the job later does not withdraw the published copy; removal is by "
            "takedown request (mcp.soken.dev/takedown.html). To proceed, call this tool again with a consent object containing: "
            "party (your organisation name), name (authorising person), "
            "statement (explicit consent text), and timestamp (ISO-8601)."
        ),
        "status": None,
        "public_url": None,
    }


async def _planned_filename(job: dict[str, Any], report: dict[str, Any]) -> tuple[str, bool]:
    """(name, replaces): the target's existing public file, else the labelled name for its subject.
    The worker makes the final choice (it may append the report id on a name clash)."""
    target = job_target(job)
    if target:
        async with _get_pool().connection() as conn, conn.cursor() as cur:
            await cur.execute("select safe_filename from published_targets where target_key = %s", (target,))
            row = await cur.fetchone()
        if row:
            return row[0], True
    subject = read_subject(report.get("object_prefix") or "", report["out_name"].removesuffix(".pdf"))
    return public_filename(subject), False


def _status_response(req: dict[str, Any]) -> dict[str, Any]:
    """Build a response from an existing publish_request row."""
    return {
        "accepted": True,
        "phase": req["status"],  # queued | publishing | published | failed
        "report_id": req["report_id"],
        "sanitized_filename": req.get("safe_filename"),
        "future_public_url": public_url(req["safe_filename"]) if req.get("safe_filename") else None,
        "disclaimer": None,
        "status": req["status"],
        "public_url": req.get("public_url"),
    }


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

@handler("review_publish")
async def handle_review_publish(args: dict[str, Any]) -> dict[str, Any]:
    """Return or record the publication status of a rendered report.

    Args:
        job_id     (required): job whose report to look up.
        manage_key (required): report owner's key (IDOR guard).
        consent    (optional): consent object {party, name, statement, timestamp};
                               recorded in the consent audit log when provided.

    Since CEO 2026-10-24, publication is automatic on render success.  This handler
    is now primarily a status endpoint.  When consent is provided it is always logged;
    if no publish_request exists yet (render not complete), one is created (rate-limited).

    Returns a structured result with accepted, phase, report_id, status, public_url.
    """
    job_id: str = args.get("job_id", "")
    consent_raw = args.get("consent")

    # ── Resolve report_id from job_id ────────────────────────────────────────
    job = await _load_job_by_id(job_id)
    if job is None:
        raise ReviewError("E_JOB_NOT_FOUND")

    report_id: str | None = job.get("report_id")
    state: str = job.get("state", "")

    if not report_id:
        # Job has not been finalized yet — no report_id assigned.
        return {
            "accepted": False,
            "errors": [ReviewError("E_REPORT_NOT_RENDERED", report_id="(none)", state=state).envelope()],
        }

    # ── Load report row ───────────────────────────────────────────────────────
    report = await _load_report(report_id)
    if report is None or state != "rendered":
        return {
            "accepted": False,
            "errors": [ReviewError("E_REPORT_NOT_RENDERED", report_id=report_id or "(none)", state=state).envelope()],
        }

    # ── Ownership gate: only the report owner (holder of the manage key) may query ──
    _verify_owner(report_id, report, args)

    # ── Consent recording (optional) ─────────────────────────────────────────
    if consent_raw is not None:
        # Validate consent fields (raises E_INVALID_ARGUMENT on failure).
        _validate_consent(consent_raw)

        existing = await _existing_request(report_id)
        if existing is not None:
            # Publish request already exists (auto-enqueued by render or a prior call):
            # just append the explicit consent record to the audit log.
            await _log_consent(report_id, consent_raw)
        else:
            # Publish request does not exist yet — create it with a rate-limit guard.
            count = await _rate_limit_count()
            if count >= _RATE_LIMIT_HOUR:
                return {
                    "accepted": False,
                    "errors": [ReviewError("E_PUBLISH_RATE_LIMITED", count=str(count)).envelope()],
                }
            await _enqueue(report_id, job_id, consent_raw)

    # ── Return current status ────────────────────────────────────────────────
    existing = await _existing_request(report_id)
    if existing is None:
        # Render just completed but the auto-enqueue transaction hasn't committed yet
        # (or was called with no consent before render finished and rate limit fired).
        return {
            "accepted": True,
            "phase": "not_queued",
            "report_id": report_id,
            "sanitized_filename": None,
            "future_public_url": None,
            "disclaimer": None,
            "status": None,
            "public_url": None,
        }
    return _status_response(existing)
