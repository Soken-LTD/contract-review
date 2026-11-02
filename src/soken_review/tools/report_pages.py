"""The three report links review_report hands out (08 4.1), served by the app itself.

  GET  /r/<id>.pdf?e&s   the current render's PDF (reports.object_prefix), inline, never cached
  GET  /r/<id>?e&s       a small HTML page: subject, chain, network, counts, link to the signed PDF
  GET  /r/<id>/manage    a static page; it reads the manage key from the URL fragment (#k=, never
                         sent to the server on GET) and POSTs it back to the same path
  POST /r/<id>/manage    {"key": <manage key>, "action": "status" | "delete"}; delete runs the
                         review_delete_job path (tools/delete.delete_job: rows, tombstones, files)

Links of a `public_review` report carry `e` (expiry, unix seconds) and `s` (HMAC under the
report's key version); a missing, expired or wrong signature answers 403. An `owner` report's
links carry no signature (report.links), so none is required there; a signature that is present
must still verify. Unknown, deleted and expired reports answer 404.

Report text is untrusted (it quotes contract source and model prose): every value printed in
HTML goes through html.escape, the pages load no external asset, and a strict CSP allows only
the one inline script of the manage page (per-response nonce). The manage POST takes the key in
a JSON body (no cookies, no ambient authority), so a cross-site request gains nothing. nginx
rate-limits /r/ (deploy/nginx/report-routes.conf). The routes answer on any Host: the signature,
not the host name, is the capability, and both soken.dev and mcp.soken.dev proxy here.
"""

from __future__ import annotations

import asyncio
import hmac
import html
import json
import logging
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psycopg.rows import dict_row
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from ..report.render import store_root
from . import report as R

logger = logging.getLogger(__name__)

_PATH = re.compile(r"^/r/(?P<rid>[a-z2-7]{26})(?P<kind>\.pdf|/manage)?/?$")
_E = re.compile(r"^[0-9]{10}$")
_S = re.compile(r"^[a-z2-7]{26}$")
_PREFIX = re.compile(r"^reports/(?P<rid>[a-z2-7]{26})/[0-9]{1,6}/?$")
_OUT_NAME = re.compile(r"^[A-Za-z0-9_-]{1,76}\.pdf$")
_MAX_BODY = 4096

FORBIDDEN_TEXT = ("This report link has expired or its signature is not valid. "
                  "Call review_report again for new links.\n")
NOT_FOUND_TEXT = "No report at this address. It may have been deleted or expired.\n"

_BASE_HEADERS = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",       # the URL carries the signature
    "x-frame-options": "DENY",
}
_PAGE_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; "
             "form-action 'none'; frame-ancestors 'none'")


def _text(status: int, body: str, extra: dict[str, str] | None = None) -> Response:
    return Response(body, status_code=status, media_type="text/plain; charset=utf-8",
                    headers={**_BASE_HEADERS, **(extra or {})})


async def _row(report_id: str) -> dict[str, Any] | None:
    """The live report row with the job's ownership flag, or None (unknown, deleted, expired)."""
    async with R._get_pool().connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """select r.report_id, r.job_id, r.object_prefix, r.out_name, r.key_version, r.expires_at,
                      j.state, j.ownership_proven
                 from reports r join jobs j on j.job_id = r.job_id
                where r.report_id = %s""",
            (report_id,),
        )
        row = await cur.fetchone()
    if row is None or row["state"] in ("deleted", "expired") or row["expires_at"] <= datetime.now(UTC):
        return None
    return row


def _profile(row: dict[str, Any]) -> str:
    # the same rule report.handle_review_report signs the links with
    return "owner" if row["ownership_proven"] else "public_review"


def _signed(request: Request, row: dict[str, Any]) -> str | None:
    """The validated query string to reuse in links ("" for an unsigned owner link), or None when
    the request must be refused."""
    e, s = request.query_params.get("e"), request.query_params.get("s")
    if e is None and s is None and _profile(row) == "owner":
        return ""
    if not (e and s and _E.match(e) and _S.match(s)):
        return None
    if not R.check_view(row["report_id"], int(e), s, row["key_version"]):
        return None
    return f"?e={e}&s={s}"


def _object_dir(row: dict[str, Any]) -> Path | None:
    m = _PREFIX.match(row["object_prefix"] or "")
    if not m or m.group("rid") != row["report_id"]:
        return None
    return store_root() / row["object_prefix"]


async def _pdf(request: Request, rid: str) -> Response:
    row = await _row(rid)
    if row is None:
        return _text(404, NOT_FOUND_TEXT)
    if _signed(request, row) is None:
        return _text(403, FORBIDDEN_TEXT)
    base = _object_dir(row)
    path = base / "report.pdf" if base else None
    if path is None or path.is_symlink() or not path.is_file():
        return _text(404, NOT_FOUND_TEXT)
    data = await asyncio.get_running_loop().run_in_executor(None, path.read_bytes)
    name = row["out_name"] if _OUT_NAME.match(row["out_name"] or "") else "report.pdf"
    headers = {**_BASE_HEADERS, "content-disposition": f'inline; filename="{name}"',
               "content-security-policy": "default-src 'none'; frame-ancestors 'none'"}
    if request.method == "HEAD":
        return Response(b"", media_type="application/pdf", headers={**headers, "content-length": str(len(data))})
    return Response(data, media_type="application/pdf", headers=headers)


def _summary(row: dict[str, Any]) -> dict[str, Any]:
    """Cover fields and counts as review_report computes them; empty when report.json is absent."""
    base = _object_dir(row)
    try:
        report = json.loads((base / "report.json").read_text(encoding="utf-8")) if base else None
    except (OSError, ValueError):
        report = None
    if not isinstance(report, dict):
        return {}
    from ..report.kit.build import counts, project

    try:
        projected = project(report, _profile(row))
        meta = projected["meta"]
        return {"subject": meta.get("subject"), "chain": meta.get("chain"), "network": meta.get("network"),
                "counts": counts(projected["findings"])}
    except Exception:  # the page still offers the PDF
        logger.exception("report %s: summary projection failed", row["report_id"][-6:])
        return {}


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _page(title: str, body: str, nonce: str | None = None) -> Response:
    csp = _PAGE_CSP + (f"; script-src 'nonce-{nonce}'; connect-src 'self'" if nonce else "")
    doc = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
           "<meta name=\"robots\" content=\"noindex, nofollow\">"
           f"<title>{_esc(title)}</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:40rem;"
           "margin:2rem auto;padding:0 1rem;color:#111}table{border-collapse:collapse}td,th{border:1px solid #999;"
           "padding:.25rem .6rem;text-align:left}button{font-size:1rem;padding:.4rem 1rem}.muted{color:#555}"
           f"</style></head><body>{body}</body></html>")
    return Response(doc, media_type="text/html; charset=utf-8",
                    headers={**_BASE_HEADERS, "content-security-policy": csp})


async def _view(request: Request, rid: str) -> Response:
    row = await _row(rid)
    if row is None:
        return _text(404, NOT_FOUND_TEXT)
    query = _signed(request, row)
    if query is None:
        return _text(403, FORBIDDEN_TEXT)
    info = await asyncio.get_running_loop().run_in_executor(None, _summary, row)
    subject = info.get("subject") or "Contract review report"
    rows = "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>"
                   for k, v in (("Chain", info.get("chain")), ("Network", info.get("network")),
                                ("Valid until", row["expires_at"].date().isoformat())) if v)
    c = info.get("counts") or {}
    counts_html = ""
    if c:
        counts_html = ("<h2>Findings</h2><table><tr>" + "".join(f"<th>{_esc(k)}</th>" for k in c)
                       + "</tr><tr>" + "".join(f"<td>{_esc(v)}</td>" for v in c.values()) + "</tr></table>")
    body = (f"<h1>{_esc(subject)}</h1><table>{rows}</table>{counts_html}"
            f"<p><a href=\"/r/{_esc(rid)}.pdf{_esc(query)}\">Open the PDF report</a></p>"
            "<p class=\"muted\">This link expires. Call review_report again for new links.</p>")
    return _page(f"{subject} - report", body)


_MANAGE_JS = """
(function () {
  var k = (location.hash.match(/[#&]k=([a-z2-7]{26})/) || [])[1];
  var out = document.getElementById('out'), del = document.getElementById('del');
  function say(t) { out.textContent = t; }
  if (!k) { say('This page needs the full manage link from review_report (it ends with #k=...).'); return; }
  function post(action) {
    return fetch(location.pathname, {method: 'POST', credentials: 'omit', cache: 'no-store',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify({key: k, action: action})})
      .then(function (r) { return r.json().then(function (j) { j._status = r.status; return j; }); });
  }
  post('status').then(function (j) {
    if (j._status !== 200) { say(j.message || 'This report cannot be managed.'); return; }
    var lines = ['Report: ' + (j.subject || j.report_id), 'Valid until: ' + j.expires];
    if (j.public_url) { lines.push('Published copy: ' + j.public_url + ' (deleting here does not withdraw it; use the takedown request page)'); }
    say(lines.join('\\n'));
    del.hidden = false;
  }).catch(function () { say('The server could not be reached.'); });
  del.addEventListener('click', function () {
    if (!confirm('Delete this report and its review job? This cannot be undone.')) { return; }
    del.disabled = true;
    post('delete').then(function (j) {
      say(j._status === 200 ? 'Deleted. The report links no longer work.' : (j.message || 'Delete failed.'));
      if (j._status !== 200) { del.disabled = false; }
    }).catch(function () { say('The server could not be reached.'); del.disabled = false; });
  });
})();
"""


def _manage_page() -> Response:
    nonce = secrets.token_urlsafe(16)
    body = ("<h1>Manage report</h1><pre id=\"out\" style=\"white-space:pre-wrap\">Loading...</pre>"
            "<p><button id=\"del\" hidden>Delete report</button></p>"
            "<p class=\"muted\">Deleting removes the report, its PDF and the review job's data. "
            "A copy published on soken.dev/audits is removed by takedown request "
            "(mcp.soken.dev/takedown.html).</p>"
            f"<script nonce=\"{nonce}\">{_MANAGE_JS}</script>")
    return _page("Manage report", body, nonce=nonce)


def _json(status: int, payload: dict[str, Any]) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers=_BASE_HEADERS)


async def _read_body(request: Request) -> bytes | None:
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_BODY:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def _manage_post(request: Request, rid: str) -> Response:
    if (request.headers.get("content-type") or "").split(";")[0].strip().lower() != "application/json":
        return _json(415, {"error": "content_type", "message": "Send the key as JSON."})
    raw = await _read_body(request)
    if raw is None:
        return _json(413, {"error": "too_large", "message": "Request body too large."})
    try:
        args = json.loads(raw)
    except ValueError:
        args = None
    if not isinstance(args, dict) or not isinstance(args.get("key"), str) or args.get("action") not in ("status", "delete"):
        return _json(400, {"error": "bad_request", "message": "Expected {key, action: status|delete}."})
    row = await _row(rid)
    if row is None:
        return _json(404, {"error": "not_found", "message": NOT_FOUND_TEXT.strip()})
    expected = R.manage_key(rid, row["key_version"])
    if not hmac.compare_digest(args["key"].encode(), expected.encode()):
        return _json(403, {"error": "bad_key", "message": "The manage key does not match this report."})
    if args["action"] == "status":
        _pub_status, pub_url = await R._publish_info(rid)
        info = await asyncio.get_running_loop().run_in_executor(None, _summary, row)
        return _json(200, {"report_id": rid, "subject": info.get("subject"),
                           "expires": row["expires_at"].date().isoformat(),
                           "publish_status": _pub_status, "public_url": pub_url if _pub_status == "published" else None})
    from . import delete

    out = await delete.delete_job(row["job_id"])
    logger.info("report %s deleted from the manage page", rid[-6:])
    return _json(200, {"report_id": rid, "state": out["state"], "deleted": out["deleted"]})


async def handle(request: Request) -> Response:
    m = _PATH.match(request.url.path)
    if not m:
        return _text(404, NOT_FOUND_TEXT)
    rid, kind = m.group("rid"), m.group("kind")
    method = request.method
    if kind == "/manage":
        if method == "POST":
            return await _manage_post(request, rid)
        if method in ("GET", "HEAD"):
            return _manage_page()
        return _text(405, "Method not allowed.\n", {"allow": "GET, HEAD, POST"})
    if method not in ("GET", "HEAD"):
        return _text(405, "Method not allowed.\n", {"allow": "GET, HEAD"})
    return await (_pdf(request, rid) if kind == ".pdf" else _view(request, rid))


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    """ASGI entry for every /r/ path (context_pg._LifespanWrapper dispatches here)."""
    request = Request(scope, receive)
    try:
        response = await handle(request)
    except Exception:  # never a traceback page
        logger.exception("report route failed")
        response = _text(500, "Internal error.\n")
    await response(scope, receive, send)


def is_report_path(path: str) -> bool:
    return path.startswith("/r/")
