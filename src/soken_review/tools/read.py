"""Bulk read tool handlers (03 sections 4.4, 4.5, 4.6, 4.7, 4.8; plan parts 03 and 04).

All handlers are bulk read tools: text only, no outputSchema (03 section 1).
Registered into HANDLERS via @handler(name) from server.py.

RE2 via google-re2 (pip: google-re2); falls back to stdlib re with a compilation
guard.  Search hits are not reads (03 4.5) and are never logged to job_reads.

Cursor scheme (03 section 5):
  base64url(json{v,j,t,p,f}) . base64url(HMAC-SHA256(secret, payload)[:16])
where j = sha256(job_id)[:8], f = sha256(filters)[:8], p = page offset.
Invalid cursor -> E_CURSOR_INVALID (error channel, isError: true).
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
from typing import Any

# RE2 only: patterns are caller input, a backtracking engine would allow ReDoS (03 4.5).
import re2 as _re2  # type: ignore[import-untyped]

from ..context.store import ContextStore, is_context_path
from ..db.leads_repo import clamp_lead_severity, lead_states
from ..db.pool import get_pool
from ..engine.injection import escape_invisible
from ..errors import ReviewError
from ..learning import tiers as _tiers
from ..mapping.build import load_map, load_map_status
from ..mapping.facts import load_facts
from ..mapping.lifecycle import load_lifecycle, map_pointer
from ..mapping.step import load_flags
from ..pinning.store import PinnedSource
from ..server import handler
from . import map_view
from .context import JobContext

logger = logging.getLogger(__name__)

# ── module-level context (injected by orchestrator or tests) ─────────────────

_ctx: JobContext | None = None


def set_context(ctx: JobContext) -> None:
    """Bind a JobContext.  Called by tests and the production orchestrator."""
    global _ctx
    _ctx = ctx


def _get_ctx() -> JobContext:
    if _ctx is None:
        from ..errors import ReviewError
        raise ReviewError("E_INTERNAL", incident="read not wired (ctx is None)")
    return _ctx


# ── HMAC secret for cursor signing (03 section 5) ────────────────────────────

# Production sets one secret for every replica (stateless, 03 11); unset = per-process random key,
# so cursors never verify under a key that is public in the source.
_CURSOR_SECRET: bytes = os.environ.get("SOKEN_CURSOR_SECRET", "").encode() or secrets.token_bytes(32)

# ── size hard caps (03 section 6) ────────────────────────────────────────────

_CAP_READ_CODE = 30_000
_CAP_READ_BATCH = 60_000   # all ranges of one batched review_read_code call
_MIN_RANGE_BUDGET = 10_000  # a range starts only when one capped line (_LINE_CAP_BYTES) plus headers fits
_CAP_SEARCH = 20_000
_CAP_LEADS = 20_000
_CAP_FACTS = 20_000

# ── job state guards (03 section 3.5) ────────────────────────────────────────

_READABLE_STATES = frozenset({
    "ready",
    "finalized",
    "render_queued",
    "rendering",
    "rendered",
    "render_failed",
})
_TERMINAL_STATES = frozenset({"failed", "insufficient_source"})


def _check_job_readable(job_id: str) -> None:
    """Raise the correct ReviewError when the job is not in a readable state."""
    state = _get_ctx().get_job_state(job_id)
    if state is None or state == "deleted":
        raise ReviewError("E_JOB_NOT_FOUND")
    if state in _TERMINAL_STATES:
        raise ReviewError("E_JOB_TERMINAL", state=state, exit_code="")
    if state == "expired":
        raise ReviewError("E_JOB_EXPIRED", job=job_id, date="")
    if state not in _READABLE_STATES:
        raise ReviewError("E_JOB_NOT_READY", state=state, eta_s=0)


_MAP_SERVED_STATUSES = frozenset({"full", "partial"})


def _map_ready_early(job_id: str, root: Any) -> str | None:
    """Readable check for review_contract_map. The map is written before analysis finishes, and
    review_status shows `map_status full` from then on; the map is served in that window too (r5
    2026-10-31: E_JOB_NOT_READY while status already said full). Returns the in-progress state
    when served early, None when the job is readable as usual."""
    try:
        _check_job_readable(job_id)
        return None
    except ReviewError as err:
        if err.code != "E_JOB_NOT_READY":
            raise
        if load_map_status(root, job_id).get("map_status") not in _MAP_SERVED_STATUSES:
            raise
        if load_map(root, job_id)[0] is None:
            raise
        return _get_ctx().get_job_state(job_id)


def _load_pin(job_id: str) -> PinnedSource:
    root = _get_ctx().get_pin_root()
    pin_dir = root / job_id / "pin"
    if not pin_dir.exists():
        raise ReviewError("E_JOB_NOT_FOUND")
    return PinnedSource.load(root, job_id)


def _load_context(job_id: str) -> ContextStore:
    """The job's project documents (context ingestion spec 4); empty when none were ingested."""
    return ContextStore.load(_get_ctx().get_pin_root(), job_id)


def _all_paths(pin: PinnedSource, context: ContextStore) -> list[str]:
    """Code paths then readable context paths, each group sorted (search order, closest-path hints)."""
    return sorted(pin.entries.keys()) + sorted(p for p, e in context.entries.items() if e.ok)


# ── cursor helpers (03 section 5) ────────────────────────────────────────────


def _make_cursor(job_id: str, tool: str, position: int, filters: dict) -> str:
    j = hashlib.sha256(job_id.encode()).hexdigest()[:8]
    f = hashlib.sha256(json.dumps(filters, sort_keys=True).encode()).hexdigest()[:8]
    payload_bytes = json.dumps({"v": 1, "j": j, "t": tool, "p": position, "f": f}, separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    mac = _hmac.new(_CURSOR_SECRET, payload.encode(), hashlib.sha256).digest()[:16]
    sig = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
    return f"{payload}.{sig}"


def _parse_cursor(cursor: str, job_id: str, tool: str, filters: dict) -> int:
    """Validate and decode a cursor. Returns position or raises E_CURSOR_INVALID."""
    try:
        dot = cursor.rindex(".")
        payload = cursor[:dot]
        sig = cursor[dot + 1 :]
        expected_mac = _hmac.new(_CURSOR_SECRET, payload.encode(), hashlib.sha256).digest()[:16]
        expected_sig = base64.urlsafe_b64encode(expected_mac).rstrip(b"=").decode()
        if not _hmac.compare_digest(sig, expected_sig):
            raise ReviewError("E_CURSOR_INVALID")
        data = json.loads(base64.urlsafe_b64decode(payload + "=="))
        j_expected = hashlib.sha256(job_id.encode()).hexdigest()[:8]
        f_expected = hashlib.sha256(json.dumps(filters, sort_keys=True).encode()).hexdigest()[:8]
        if data.get("j") != j_expected or data.get("t") != tool or data.get("f") != f_expected:
            raise ReviewError("E_CURSOR_INVALID")
        return int(data["p"])
    except ReviewError:
        raise
    except Exception:  # noqa: BLE001  # any decode/parse error -> cursor invalid
        raise ReviewError("E_CURSOR_INVALID")


# ── review_read_code (03 4.4, 04 5.1) ────────────────────────────────────────


@handler("review_read_code")
async def _read_code(args: dict[str, Any]) -> str:
    """Read numbered pinned lines; logs range to job_reads (03 4.4).

    One range (path, start_line, end_line) or up to 8 `ranges` in one call. The 2026-10-25 blind runs
    spent 31 read calls on three reviews, most of them in bursts a few seconds apart; a batch returns the
    same per-range blocks joined by a blank line. Each range keeps the 400-line window and the per-call
    cap of a single read; the whole batch is capped at _CAP_READ_BATCH, and a range that no longer fits
    is listed as not read (nothing is logged for it), so a read is only ever recorded for printed lines.
    """
    job_id: str = args["job_id"]
    ranges = args.get("ranges")
    detailed = args.get("response_format") == "detailed"
    if not ranges:
        missing = [k for k in ("path", "start_line", "end_line") if args.get(k) is None]
        if missing:
            raise ReviewError("E_INVALID_ARGUMENT", field=missing[0], rule="required", value80="none",
                              example="path, start_line and end_line, or ranges [{path, start_line, end_line}]")
        _check_job_readable(job_id)
        return _read_range(job_id, args["path"], args["start_line"], args["end_line"], detailed, _CAP_READ_CODE)

    _check_job_readable(job_id)
    blocks: list[str] = []
    budget = _CAP_READ_BATCH
    for i, rng in enumerate(ranges):
        path, start, end = rng["path"], rng["start_line"], rng["end_line"]
        if budget < _MIN_RANGE_BUDGET:
            blocks.append(f"range {i + 1} not_read {path}:{start}-{end} (output cap; read it in a later call)")
            continue
        try:
            body = _read_range(job_id, path, start, end, detailed, min(_CAP_READ_CODE, budget))
        except ReviewError as err:
            if err.channel != "rejection":
                raise
            env = err.envelope()
            body = f"range {i + 1} rejected {env['code']}: {env['what']} {env['fix']}"
        budget -= len(body.encode("utf-8")) + 2
        blocks.append(body)
    return "\n\n".join(blocks)


def _read_range(job_id: str, path: str, start: int, end: int, detailed_fmt: bool, cap: int) -> str:
    """One numbered window of a pinned file or project document, logged to job_reads."""
    pin = _load_pin(job_id)
    context = _load_context(job_id)
    # A `context/` path reads from the document store with the same window, cap and job_reads log
    # (context ingestion spec 4); flags and map markers are code-only and print as none.
    source: Any = context if is_context_path(path) else pin
    entry = source.get_entry(path)
    if entry is None:
        closest = _closest_paths(path, _all_paths(pin, context))
        raise ReviewError("E_FILE_UNKNOWN", path=path, paths=", ".join(closest))

    total = entry.lines
    # Bug 5 fix (2026-10-25): when only end > total, clamp silently instead of raising
    # E_RANGE_INVALID.  Hard invalid cases (wrong types, start < 1, start > total,
    # end < start) still reject — only an overlong window is clamped.
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start \
            or start > total:
        raise ReviewError("E_RANGE_INVALID", path=path, lines=total)
    end_clamped = end > total
    end_original = end if end_clamped else None
    if end_clamped:
        end = total
    end = min(end, start + 399)  # at most 400 lines (03 4.4)

    lines = source.read_lines(path, start, end)
    sha_short = str(entry.sha256_lf)[:8]
    meta = f"{path} sha256:{sha_short} lines {start}-{end} of {total}"
    if end_clamped:
        meta += f" (end clamped from {end_original} to {total}: file has {total} lines)"
    root = _get_ctx().get_pin_root()
    job_flags = load_flags(root, job_id)
    if job_flags is None:
        # Flags are written at pin time with the map (04 12); a readable job without them is a fault.
        raise ReviewError("E_INTERNAL", incident=f"flags-missing-{job_id[-8:]}")
    detailed = detailed_fmt and not is_context_path(path)
    doc = load_map(root, job_id)[0] if detailed else None

    def _tail(a: int, b: int) -> str:
        hits = [f for f in job_flags if f["file"] == path and a <= f["line"] <= b]
        flag_text = "flags\n" + "\n".join(f"{path}:{f['line']} {f['rule']}" for f in hits) if hits else "flags none"
        if doc is not None and doc.get("semantic"):
            markers = map_view.render_markers(doc, path, a, b)
            flag_text += "\nmap markers\n" + ("\n".join(markers) if markers else "none")
        return flag_text

    def _body(n: int) -> str:
        last = start + n - 1
        label = "project document" if is_context_path(path) else "file"
        header = f"Untrusted source data, {label} {path}, lines {start}-{last}"
        numbered = "\n".join(rendered[:n])
        out = f"{header}\n{meta}\n```\n{numbered}\n```\n{_tail(start, last)}"
        return out if n == len(lines) else f"{out}\nnext_start_line {last + 1}"

    # Hard cap on the encoded output after escaping (03 6): lines are added while the UTF-8 body fits;
    # one line always fits because a rendered line is capped at _LINE_CAP_BYTES.
    rendered = [_render_line(start + i, line) for i, line in enumerate(lines)]
    n = len(rendered)
    body = _body(n)
    while len(body.encode("utf-8")) > cap and n > 1:
        over = len(body.encode("utf-8")) - cap
        drop = 1
        while drop < n - 1 and sum(len(r.encode("utf-8")) + 1 for r in rendered[n - drop : n]) < over:
            drop += 1
        n -= drop
        body = _body(n)
    if len(body.encode("utf-8")) > cap:
        raise ReviewError("E_INTERNAL", incident=f"read-cap-{job_id[-8:]}")

    _get_ctx().append_read(job_id, path, start, start + n - 1)
    return body


_SEGMENT = 400            # characters per printed segment (03 4.4)
_LINE_CAP_BYTES = 8_000   # bytes of one rendered line after escaping; the rest is reported, not printed


def _render_line(lineno: int, line: str) -> str:
    """One pinned line: escaped, split into 400-char segments over 400 chars, capped in bytes."""
    if len(line) <= _SEGMENT:
        out = f"{lineno}| {escape_invisible(line)}"
        if len(out.encode("utf-8")) <= _LINE_CAP_BYTES:
            return out
    parts: list[str] = []
    used = 0
    shown = 0
    for seg_i, j in enumerate(range(0, len(line), _SEGMENT), 1):
        part = f"{lineno}.{seg_i}| {escape_invisible(line[j : j + _SEGMENT])}"
        size = len(part.encode("utf-8")) + 1
        if used + size > _LINE_CAP_BYTES:
            break
        parts.append(part)
        used += size
        shown = j + _SEGMENT
    if shown < len(line):
        parts.append(f"{lineno}.cut| line continues, {len(line) - shown} more characters not shown")
    return "\n".join(parts)


def _closest_paths(path: str, candidates: list[str], n: int = 3) -> list[str]:
    """Return the n candidates with the longest common suffix with path."""

    def score(c: str) -> int:
        rp = path[::-1]
        rc = c[::-1]
        i = 0
        while i < len(rp) and i < len(rc) and rp[i] == rc[i]:
            i += 1
        return i

    return sorted(candidates, key=score, reverse=True)[:n]


# ── review_search_code (03 4.5) ───────────────────────────────────────────────


@handler("review_search_code")
async def _search_code(args: dict[str, Any]) -> str:
    """Literal or RE2 search; hits are not reads (03 4.5)."""
    job_id: str = args["job_id"]
    pattern: str = args["pattern"]
    mode: str = args.get("mode", "literal")
    path_glob: str | None = args.get("path_glob")
    context_lines: int = args.get("context_lines", 0)
    max_hits: int = args.get("max_hits", 40)
    cursor: str | None = args.get("cursor")

    _check_job_readable(job_id)
    pin = _load_pin(job_id)
    context = _load_context(job_id)

    def _source(p: str) -> Any:
        return context if is_context_path(p) else pin

    filters = {
        "pattern": pattern,
        "mode": mode,
        "path_glob": path_glob or "",
        "context_lines": context_lines,
    }
    offset = _parse_cursor(cursor, job_id, "review_search_code", filters) if cursor else 0

    compiled = _compile_pattern(pattern, mode)

    # Collect all hits in keyset order (sorted code paths, then sorted context paths, then line number)
    all_hits: list[tuple[str, int, str]] = []
    for path in _all_paths(pin, context):
        if path_glob and not fnmatch.fnmatch(path, path_glob):
            continue
        entry = _source(path).get_entry(path)
        if entry is None:
            continue
        file_lines = _source(path).read_all(path)
        for lineno, line in enumerate(file_lines, start=1):
            if _matches(line, pattern, mode, compiled):
                all_hits.append((path, lineno, line))

    page_hits = all_hits[offset : offset + max_hits]
    next_offset = offset + len(page_hits)

    out: list[str] = ["Untrusted source data, search results"]
    total_chars = len(out[0])
    budget_exceeded = False

    for page_idx, (hit_path, lineno, hit_text) in enumerate(page_hits):
        if context_lines > 0:
            entry = _source(hit_path).get_entry(hit_path)
            if entry:
                file_lines = _source(hit_path).read_all(hit_path)
                ctx_start = max(0, lineno - 1 - context_lines)
                ctx_end = min(len(file_lines), lineno + context_lines)
                for ci in range(ctx_start, ctx_end):
                    prefix = ">" if ci == lineno - 1 else " "
                    chunk = f"{prefix}{hit_path}:{ci + 1}| {escape_invisible(file_lines[ci][:_SEGMENT])}"
                    if total_chars + len(chunk.encode("utf-8")) + 1 > _CAP_SEARCH:
                        next_offset = offset + page_idx
                        budget_exceeded = True
                        break
                    out.append(chunk)
                    total_chars += len(chunk.encode("utf-8")) + 1
                if budget_exceeded:
                    break
        else:
            hit_line = f"{hit_path}:{lineno}| {escape_invisible(hit_text[:_SEGMENT])}"
            if total_chars + len(hit_line.encode("utf-8")) + 1 > _CAP_SEARCH:
                next_offset = offset + page_idx
                budget_exceeded = True
                break
            out.append(hit_line)
            total_chars += len(hit_line.encode("utf-8")) + 1

    if next_offset < len(all_hits):
        nc = _make_cursor(job_id, "review_search_code", next_offset, filters)
        out.append(f"next_cursor {nc}")
    else:
        out.append("end")

    return "\n".join(out)


def _compile_pattern(pattern: str, mode: str):
    """Compile RE2 or literal pattern. RE2 errors -> E_INVALID_ARGUMENT."""
    if mode != "regex":
        return None  # literal mode uses `in` operator
    try:
        return _re2.compile(pattern)
    except Exception as exc:  # google-re2 raises various exception types
        raise ReviewError("E_INVALID_ARGUMENT", field="pattern", rule="re2", value80=str(exc)[:80]) from exc


def _matches(line: str, pattern: str, mode: str, compiled) -> bool:
    if mode == "literal":
        return pattern in line
    return bool(compiled.search(line))


# ── review_leads (03 4.7) ─────────────────────────────────────────────────────


@handler("review_leads")
async def _leads(args: dict[str, Any]) -> str:
    """Paginated leads from leads.json in the job dir (03 4.7)."""
    job_id: str = args["job_id"]
    status_filter: str = args.get("status", "open")
    origin_filter: str = args.get("origin", "all")
    detector: str | None = args.get("detector")
    path_glob: str | None = args.get("path_glob")
    response_format: str = args.get("response_format", "concise")
    cursor: str | None = args.get("cursor")
    page_size: int = args.get("page_size", 25)
    include_collapsed: bool = bool(args.get("include_collapsed", False))

    _check_job_readable(job_id)

    filters: dict = {
        "status": status_filter,
        "origin": origin_filter,
        "detector": detector or "",
        "path_glob": path_glob or "",
    }
    if include_collapsed:
        filters["include_collapsed"] = True
    offset = _parse_cursor(cursor, job_id, "review_leads", filters) if cursor else 0

    leads = _load_leads(job_id)
    version = await _overlay_lead_states(job_id, leads)
    # Rule tiers (learning-loop design 2.2): order, shown severity and the collapsed set come from
    # the active policy file; the baseline returns the leads unchanged. Nothing is dropped: a
    # collapsed lead is counted in the header and listed with include_collapsed or a detector filter.
    leads, tier_summary = _tiers.apply_tiers(leads, version, job_id)

    # Stats over all leads (before filtering)
    all_open = [l for l in leads if l.get("state") == "open"]
    hm_open = sum(1 for l in all_open if l.get("severity_norm") in ("High", "Medium"))
    carried_open = sum(1 for l in all_open if l.get("origin") == "previous_report")

    # Apply filters
    filtered = [l for l in leads if _lead_matches(l, status_filter, origin_filter, detector, path_glob)]
    collapsed_hidden = not include_collapsed and not detector
    if collapsed_hidden:
        filtered = [l for l in filtered if _tiers.listed_by_default(l.get("tier", "normal"))]
    total = len(filtered)
    total_all = len(leads)

    # Paginate using keyset index: leads are sorted by sev_rank desc, path, start, id (03 DDL)
    page = filtered[offset : offset + page_size]
    next_offset = offset + len(page)
    page_num = offset // page_size + 1

    header = (
        f"leads {status_filter} {total} of {total_all} "
        f"(High and Medium open {hm_open}, carried open {carried_open}), page {page_num}"
    )
    out = [header]
    tier_line = _tiers.header_line(tier_summary, collapsed_hidden)
    if tier_line:
        out.append(tier_line)
    total_chars = sum(len(x) + 1 for x in out)

    for lead in page:
        line = _format_lead(lead, response_format)
        if total_chars + len(line) + 1 > _CAP_LEADS:
            break
        out.append(line)
        total_chars += len(line) + 1

    if next_offset < total:
        nc = _make_cursor(job_id, "review_leads", next_offset, filters)
        out.append(f"next_cursor {nc}")
    else:
        out.append("end")

    return "\n".join(out)


def _lead_matches(
    lead: dict,
    status_filter: str,
    origin_filter: str,
    detector: str | None,
    path_glob: str | None,
) -> bool:
    if status_filter != "all" and lead.get("state") != status_filter:
        return False
    if origin_filter != "all" and lead.get("origin", "analyzer") != origin_filter:
        return False
    if detector and not _detector_matches(lead, detector):
        return False
    return not (path_glob and not fnmatch.fnmatch(lead.get("file", ""), path_glob))


def _detector_matches(lead: dict, detector: str) -> bool:
    """`detector` names a rule id, a tool (with or without its version), the category or its last
    segment; case does not matter. Two blind runs filtered by the category name and got nothing."""
    want = detector.strip().lower()
    names = {str(lead.get("rule_id", "")), str(lead.get("category", "")),
             str(lead.get("category", "")).rsplit(".", 1)[-1]}
    for tool in lead.get("tools") or []:
        names.add(str(tool))
        names.add(str(tool).split("@", 1)[0])
    return want in {n.lower() for n in names if n}


_SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}


def _format_lead(lead: dict, fmt: str) -> str:
    """Single lead line per 03 4.7 compact format."""
    lid = lead.get("id", "?")
    state = lead.get("state", "?")
    category = lead.get("category", "")
    cat_short = category.split(".")[-1] if "." in category else category
    sev = lead.get("severity_norm", "?").lower()
    path = lead.get("file", "?")
    start = lead.get("start", "?")
    end = lead.get("end", "?")
    origin = lead.get("origin", "analyzer")

    location = f"{path}:{start}-{end}"
    line = f"{lid} {state} {cat_short} {sev} {location}"

    if origin == "previous_report":
        prev_id = lead.get("prev_finding_id", "")
        line += f" prev {prev_id}"

    # Every lead names its rule, the tool that raised it and the detector message in both formats
    # (blind run 2026-10-26: TON and "other" leads showed category, severity and line only, so the
    # reviewer could neither understand nor dismiss them). Concise keeps the message short.
    rule_id = str(lead.get("rule_id") or "unknown")
    tools = [str(t).split("@", 1)[0] for t in (lead.get("tools") or []) if t] or ["unknown"]
    msg = str(lead.get("message") or "")
    if not msg:
        msg = f"{tools[0]} rule {rule_id}; the detector gave no message"
    msg = msg[:400] if fmt == "detailed" else msg[:160]
    line += f' {rule_id} [{"+".join(tools)}] "{msg}"'
    suffix = _tiers.lead_suffix(lead)
    if suffix:
        line += f" ({suffix})"

    return line


async def _overlay_lead_states(job_id: str, leads: list[dict]) -> str:
    """Replace each lead's `state` with the ``leads`` table row when a database is configured,
    and return the rule tier policy version to apply (recorded on the job for the ledger).

    leads.json is written once by the analyze step and never updated; promotions and dismissals
    live in the table (03 3.6), so without this overlay a promoted lead kept showing as `open`.
    Without a pool (unit tests, MemoryJobContext) the file's own states are used unchanged and
    the configured default policy applies.
    """
    try:
        pool = get_pool()
    except RuntimeError:
        return _tiers.resolve_version(None)
    async with pool.connection() as conn:
        states = await lead_states(conn, job_id)
        version = await _tiers.active_version(conn)
        try:
            await conn.execute(
                "update jobs set learning_policy_version = %s"
                " where job_id = %s and learning_policy_version is distinct from %s",
                (version, job_id, version))
        except Exception as exc:  # noqa: BLE001  # recording the version never breaks listing
            logger.warning("job %s: learning policy version not recorded: %s", job_id[-8:], type(exc).__name__)
    for lead in leads:
        row = states.get(lead.get("id", ""))
        if row is not None:
            lead["state"] = row["state"]
            if row.get("reason"):
                lead["reason"] = row["reason"]
            if row.get("state_ref"):
                lead["state_ref"] = row["state_ref"]
    return version


def _load_leads(job_id: str) -> list[dict]:
    """Load lead.v1 documents from <job_dir>/leads.json.

    The analyze step always writes the file (empty list when degraded, 03 3.1), so a missing file
    is a server fault, never "no leads".
    """
    root = _get_ctx().get_pin_root()
    leads_path = root / job_id / "leads.json"
    if not leads_path.exists():
        raise ReviewError("E_INTERNAL", incident=f"leads-missing-{job_id[-8:]}")
    raw = json.loads(leads_path.read_text())
    # Accept both a bare list and an object with a "leads" key
    leads = raw if isinstance(raw, list) else raw.get("leads", [])
    # The label the reviewer reads never exceeds the category cap (same bound as the leads table).
    return [clamp_lead_severity(lead) if isinstance(lead, dict) else lead for lead in leads]


# ── review_contract_map (03 4.6) ──────────────────────────────────────────────


@handler("review_contract_map")
async def _contract_map(args: dict[str, Any]) -> str:
    """Units, entries, roles, external calls, writers, upgrade authority from map.v1 (03 4.6, 04 2.1)."""
    job_id: str = args["job_id"]
    contract: str | None = args.get("contract")
    detailed = args.get("response_format") == "detailed"
    cursor: str | None = args.get("cursor")
    page_size: int = max(1, min(int(args.get("page_size", 10)), 30))
    root = _get_ctx().get_pin_root()
    early_state = _map_ready_early(job_id, root)
    doc, status = load_map(root, job_id)
    if doc is None:
        raise ReviewError("E_INTERNAL", incident=f"map-missing-{job_id[-8:]}")
    pointer = map_pointer(load_lifecycle(root, job_id))
    if not doc.get("semantic"):
        lines = map_view.render_lexical(doc, status, load_map_status(root, job_id).get("build_detail"))
        if early_state:
            lines = [*lines, f"job still {early_state}, leads and facts arrive at ready"]
        return "\n".join([*lines, pointer] if pointer else lines)

    filters = {"contract": contract or "", "detailed": detailed, "page_size": page_size}
    offset = _parse_cursor(cursor, job_id, "review_contract_map", filters) if cursor else 0
    units = [u for u in doc["semantic"]["units"]
             if not contract or contract in (u["name"], u["id"])]
    facts = load_facts(root, job_id) or []
    page = units[offset : offset + page_size]
    out = [f"contract map {status}, units {len(units)}, page {offset // page_size + 1}"]
    if early_state:
        out[0] += f"; job still {early_state}, leads and facts arrive at ready"
    extras = doc["semantic"].get("chain_extras") or {}
    if any(isinstance(v, dict) and v.get("layer") == "parsed" for v in extras.values()):   # Solana, TON
        # Parsed from source (no compiler resolution); the build outcome is stated, never implied.
        build_status = load_map_status(root, job_id).get("build_status") or "unknown"
        out[0] += f"; layer parsed from source, build {build_status} (see review_status build)"
    if pointer and offset == 0:
        out.append(pointer)
    used = len(out[0])
    shown = 0
    for unit in page:
        block = "\n".join(map_view.render_unit(doc, unit, facts, detailed))
        if used + len(block) + 1 > _CAP_FACTS and shown:
            break
        out.append(block[: _CAP_FACTS - used - 40] if used + len(block) + 1 > _CAP_FACTS else block)
        used += len(out[-1]) + 1
        shown += 1
    nxt = offset + shown
    if nxt < len(units):
        out.append(f"next_cursor {_make_cursor(job_id, 'review_contract_map', nxt, filters)}")
    else:
        out.append("end")
    return "\n".join(out)


# ── review_facts (03 4.8) ─────────────────────────────────────────────────────


@handler("review_facts")
async def _facts(args: dict[str, Any]) -> str:
    """Fact records `key value unit source` (03 4.8; 04 6.3 A4)."""
    job_id: str = args["job_id"]
    prefix: str = args.get("filter") or ""
    cursor: str | None = args.get("cursor")
    page_size: int = max(1, min(int(args.get("page_size", 100)), 200))
    _check_job_readable(job_id)
    from . import chain as _chain

    await _chain.auto_snapshot(job_id, wait=True)   # chain.target.* for clients without the chain tools
    facts = load_facts(_get_ctx().get_pin_root(), job_id)
    if facts is None:
        raise ReviewError("E_INTERNAL", incident=f"facts-missing-{job_id[-8:]}")
    filters = {"filter": prefix, "page_size": page_size}
    offset = _parse_cursor(cursor, job_id, "review_facts", filters) if cursor else 0
    rows = [f for f in facts if f["key"].startswith(prefix)]
    page = rows[offset : offset + page_size]
    out = [f"facts {len(page)} of {len(rows)}"]
    used = len(out[0])
    shown = 0
    for f in page:
        line = map_view.render_fact(f)
        if used + len(line) + 1 > _CAP_FACTS:
            break
        out.append(line)
        used += len(line) + 1
        shown += 1
    nxt = offset + shown
    if nxt < len(rows):
        out.append(f"next_cursor {_make_cursor(job_id, 'review_facts', nxt, filters)}")
    else:
        out.append("end")
    return "\n".join(out)
