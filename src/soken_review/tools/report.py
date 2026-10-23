"""`review_report` (03 4.15, 08 4.1, 5.2): render state, signed links, counts, rows, `summary_text`.

`top`, `rows` and `summary_text` come from `project(report, profile)` (08 2.4), the only
projection. Links: page and PDF URLs signed for one hour under `public_review`; `manage_url`
carries the derived manage key in the fragment (08 4.1). `K_v` comes from
`SOKEN_REPORT_KEY_V<n>`; unset means a per-process random key (no constant default).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import UTC, datetime
from typing import Any

import psycopg_pool
from psycopg.rows import dict_row

from ..db.pool import get_pool
from ..errors import ReviewError
from ..report.kit.build import SEVS, counts, kit_texts, project
from ..report.render import KEY_VERSION, store_root
from ..server import handler

# Base URL for the signed report links. Production serves them at soken.dev/r/<id>; a test or
# staging deployment overrides this with SOKEN_REPORT_SITE so the links point at a host that
# actually serves the rendered reports.
SITE = os.environ.get("SOKEN_REPORT_SITE") or "https://soken.dev"
VIEW_TTL_S = 3600
ROWS_PER_PAGE = 20
_MAX_WAIT = 45
_PENDING = {"finalized", "render_queued", "rendering"}
_pool: psycopg_pool.AsyncConnectionPool | None = None
_random_keys: dict[int, bytes] = {}


def set_pool(pool: psycopg_pool.AsyncConnectionPool) -> None:
    global _pool
    _pool = pool


def _get_pool() -> psycopg_pool.AsyncConnectionPool:
    return _pool if _pool is not None else get_pool()


def key(version: int) -> bytes:
    raw = os.environ.get(f"SOKEN_REPORT_KEY_V{version}")
    if raw:
        return raw.encode()
    return _random_keys.setdefault(version, secrets.token_bytes(32))


def _b32(digest: bytes) -> str:
    return base64.b32encode(digest).decode().lower().rstrip("=")[:26]


def view_signature(report_id: str, expires: int, version: int = KEY_VERSION) -> str:
    """08 4.1: s = base32(HMAC-SHA256(K_v, report_id || "view" || e))[:26]."""
    return _b32(hmac.new(key(version), f"{report_id}view{expires}".encode(), hashlib.sha256).digest())


def manage_key(report_id: str, version: int = KEY_VERSION) -> str:
    return _b32(hmac.new(key(version), f"{report_id}manage".encode(), hashlib.sha256).digest())


def check_view(report_id: str, expires: int, sig: str, version: int = KEY_VERSION, now: float | None = None) -> bool:
    if (now or time.time()) >= expires:
        return False
    return hmac.compare_digest(view_signature(report_id, expires, version), sig)


def links(report_id: str, profile: str, version: int, now: float | None = None) -> dict[str, str]:
    query = ""
    if profile == "public_review":
        e = int(now or time.time()) + VIEW_TTL_S
        query = f"?e={e}&s={view_signature(report_id, e, version)}"
    return {"url": f"{SITE}/r/{report_id}{query}", "pdf_url": f"{SITE}/r/{report_id}.pdf{query}",
            "manage_url": f"{SITE}/r/{report_id}/manage#k={manage_key(report_id, version)}"}


def _loc(f: dict[str, Any]) -> str:
    loc = f["location"]
    return f'{loc["path"]}:{loc["start"]}' + (f'-{loc["end"]}' if loc["end"] != loc["start"] else "")


def finding_rows(projected: dict[str, Any]) -> list[dict[str, Any]]:
    """Projected rows: a withheld card gives category label as title and `withheld_line` as location."""
    t = kit_texts()
    out = []
    for f in projected["findings"]:
        if f.get("status") == "Fixed":
            continue
        if f.get("withheld"):
            out.append({"id": f["id"], "severity": f["severity"], "evidence_level": f["evidence_level"],
                        "title": f["category"], "location": t["withheld_line"]})
        else:
            out.append({"id": f["id"], "severity": f["severity"], "evidence_level": f["evidence_level"],
                        "title": f["title"], "location": _loc(f)})
    return out


def _cut_left(s: str, n: int) -> str:
    return s if len(s) <= n else "..." + s[-(n - 3):]


def _cut(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def summary_text(projected: dict[str, Any], c: dict[str, int], lk: dict[str, str] | None, expires: str) -> str:
    """08 5.2 template, under 2,000 characters."""
    t, m = kit_texts(), projected["meta"]
    rows = finding_rows(projected)
    lines = [f"Report ready: {m['subject']}, {m['network']}", f"Provenance: {m['provenance']['label']}",
             "Findings: " + ", ".join(f"{c[s]} {s}" for s in SEVS), t["authorship_box"]]
    if rows:
        lines.append("| Id | Severity | Title | Location |")
        for r in rows[:8]:
            loc = r["location"] if r["location"] == t["withheld_line"] else _cut_left(r["location"], 40)
            lines.append(f"| {r['id']} | {r['severity']} | {_cut(r['title'], 60)} | {loc} |")
        if len(rows) > 8:
            lines.append(f"and {len(rows) - 8} more in the report")
    if lk:
        lines += [f"Report: {lk['url']}", f"PDF: {lk['pdf_url']}",
                  f"Valid until: {expires}. Manage or delete: {lk['manage_url']}"]
    if m["profile"] == "public_review":
        lines += [t["links_valid_line"], t["responsible_disclosure"]]
    text = "\n".join(lines)
    return text[:2000]


def principal_of(job_id: str) -> str:
    """03 3.3: the job_id is the bearer capability (130 random bits) and there is no account layer;
    `principal_key` is the key review_start writes for it. The lookup is bound to it so a future
    authenticated principal replaces this one function, and a row owned by another principal reads
    exactly like a missing job (E_JOB_NOT_FOUND, no existence oracle)."""
    return hashlib.sha256(job_id.encode()).hexdigest()[:12]


async def _load(job_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    async with _get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("select * from jobs where job_id = %s and principal_key = %s", (job_id, principal_of(job_id)))
        job = await cur.fetchone()
        if job is None:
            return None, None, None
        await cur.execute("select * from reports where job_id = %s", (job_id,))
        rep = await cur.fetchone()
        await cur.execute("""select provenance from job_steps where job_id = %s and step = 'render' and status = 'done'
                                 order by id desc limit 1""", (job_id,))
        step = await cur.fetchone()
    return job, rep, step


def _status_only(status: str, job: dict[str, Any], code: str | None = None) -> dict[str, Any]:
    t = kit_texts()
    profile = "owner" if job["ownership_proven"] else "public_review"
    line = t["card_status"].get("render_pending" if status == "render_pending" else status, "")
    return {"accepted": True, "status": status, "code": code, "report_id": job.get("report_id"), "url": None,
            "pdf_url": None, "manage_url": None, "expires": None, "subject": None, "chain": None, "network": None,
            "provenance": None, "profile": profile, "counts": None, "top": None, "eta_s": None, "pages": None,
            "summary_text": line}


@handler("review_report")
async def handle_review_report(args: dict[str, Any]) -> dict[str, Any]:
    job_id: str = args["job_id"]
    wait = min(int(args.get("wait_seconds", 0)), _MAX_WAIT)
    page = int(args.get("page", 0))
    job, rep, step = await _load(job_id)
    if job is None:
        raise ReviewError("E_JOB_NOT_FOUND")
    deadline = time.monotonic() + wait
    while job["state"] in _PENDING and time.monotonic() < deadline:
        await asyncio.sleep(0.5)
        job, rep, step = await _load(job_id)
    state = job["state"]
    if state in ("failed", "insufficient_source"):
        raise ReviewError("E_JOB_TERMINAL")
    if state in ("awaiting_upload", "queued", "fetching", "building", "analyzing", "ready"):
        # The catalogued text is "Job is {state}, eta {eta_s} s." (contract/errors.yaml); the
        # report exists only after review_finalize, so there is no pipeline ETA to quote.
        raise ReviewError("E_JOB_NOT_READY", state=state, eta_s=0)
    if state in _PENDING:
        return _status_only("render_pending", job)
    if state == "render_failed":
        return _status_only("render_failed", job, (job.get("error_detail") or {}).get("detail"))
    if state in ("expired", "deleted"):
        return _status_only(state, job)
    if rep is None:
        raise ReviewError("E_INTERNAL")
    if rep["expires_at"] <= datetime.now(UTC):
        # Past its retention date the report is gone for the caller even before the sweep
        # (worker/retention) removes the row and the files.
        return _status_only("expired", job)
    report = json.loads((store_root() / rep["object_prefix"] / "report.json").read_text(encoding="utf-8"))
    profile = "owner" if job["ownership_proven"] else "public_review"
    projected = project(report, profile)
    c = counts(projected["findings"])
    rows = finding_rows(projected)
    top = None
    if rows:
        best = min(rows, key=lambda r: SEVS.index(r["severity"]))
        top = {"id": best["id"], "severity": best["severity"], "title": best["title"]}
    lk = links(rep["report_id"], profile, rep["key_version"])
    expires = rep["expires_at"].date().isoformat()
    m = projected["meta"]
    out: dict[str, Any] = {
        "accepted": True, "status": "ready", "code": None, "report_id": rep["report_id"], **lk, "expires": expires,
        "subject": m["subject"], "chain": m["chain"], "network": m["network"],
        "provenance": {"tier": m["provenance"]["tier"], "label": m["provenance"]["label"]}, "profile": profile,
        "counts": c, "top": top, "eta_s": None, "pages": (step or {}).get("provenance", {}).get("pages") if step else None,
        "summary_text": summary_text(projected, c, lk, expires),
    }
    if page >= 1:
        out["rows"] = rows[(page - 1) * ROWS_PER_PAGE: page * ROWS_PER_PAGE]
        out["rows_total"] = len(rows)
    return out
