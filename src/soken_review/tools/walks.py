"""Invariant-walk answers: validation for review_set_section(section=invariant_walks) and the
finalize check F9 (feat/lifecycle-invariant-pass). Pure except the two small loaders at the end.

A walk (map/lifecycle.json, text in contract/rubric/invariants.yaml) is answered by one row:
  {walk_id, outcome: holds | violated | not_applicable, refs: [path:start-end], note, draft_key?}

Coverage rules, the point of the pass (a walk is traced through code, not asserted):
  - holds and violated need 1 to 8 refs, every ref read in full with review_read_code first;
  - the refs overlap at least min(2, n) of the walk's n focus function spans;
  - the refs contain every anchor line (the lifecycle leads the walk is bound to);
  - violated names a live draft (accepted, needs_challenge or needs_text) whose location quote
    overlaps a ref, so a broken invariant always lands in the report as a finding;
  - not_applicable is accepted only for a walk without anchors;
  - the note is 40 to 600 characters (audit-log text, not printed; no prose rules).
Rows merge by walk_id across calls, so a client can answer walk by walk.
"""

from __future__ import annotations

from typing import Any

from .challenge import _parse_range_ref

OUTCOMES = ("holds", "violated", "not_applicable")
LIVE_DRAFT = frozenset({"accepted", "needs_challenge", "needs_text"})
_NOTE_MIN, _NOTE_MAX, _REFS_MAX = 40, 600, 8


def _covered(path: str, start: int, end: int, reads: dict[str, list[tuple[int, int]]]) -> bool:
    """Every line of [start, end] lies in the union of the reads of `path`."""
    need = start
    for s, e in sorted(reads.get(path) or []):
        if s > need:
            break
        if e >= need:
            need = e + 1
        if need > end:
            return True
    return need > end


def _overlaps(a: tuple[str, int, int], b: tuple[str, int, int]) -> bool:
    return a[0] == b[0] and not (a[2] < b[1] or a[1] > b[2])


def walk_index(lc: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    return {w["id"]: w for w in (lc or {}).get("walks") or []}


def validate_row(row: Any, walk: dict[str, Any] | None, reads: dict[str, list[tuple[int, int]]],
                 drafts: dict[str, dict[str, Any]]) -> str | None:
    """The E_SECTION_INVALID detail for one answer row, or None when it is accepted."""
    if not isinstance(row, dict):
        return "row must be an object {walk_id, outcome, refs, note, draft_key}"
    wid = row.get("walk_id")
    if walk is None:
        return f"walk_id {str(wid)[:40]!r} is not a walk of this job (review_get_guide topic invariants)"
    outcome = row.get("outcome")
    if outcome not in OUTCOMES:
        return f"{wid}: outcome must be one of {', '.join(OUTCOMES)}"
    note = row.get("note")
    if not isinstance(note, str) or not _NOTE_MIN <= len(note.strip()) <= _NOTE_MAX:
        return f"{wid}: note must be {_NOTE_MIN} to {_NOTE_MAX} characters stating the invariant and the result"
    anchors = walk.get("anchors") or []
    if outcome == "not_applicable":
        if anchors:
            return f"{wid}: not_applicable is not accepted for a walk with anchors ({anchors[0]['lead_id']}); trace it"
        return None
    refs = row.get("refs")
    if not isinstance(refs, list) or not 1 <= len(refs) <= _REFS_MAX:
        return f"{wid}: refs must list 1 to {_REFS_MAX} ranges path:start-end"
    parsed: list[tuple[str, int, int]] = []
    for ref in refs:
        p = _parse_range_ref(ref) if isinstance(ref, str) else None
        if p is None:
            return f"{wid}: ref {str(ref)[:80]!r} is not path:start-end"
        if not _covered(*p, reads):
            return f"{wid}: ref {ref} was not read in full; read it with review_read_code first"
        parsed.append(p)
    focus = [_parse_range_ref(f["range"]) for f in walk.get("focus") or []]
    focus = [f for f in focus if f is not None]
    if focus:
        need = min(2, len(focus))
        hit = sum(1 for f in focus if any(_overlaps(f, r) for r in parsed))
        if hit < need:
            names = ", ".join(f"{x['name']} {x['range']}" for x in (walk.get("focus") or [])[:4])
            return f"{wid}: refs overlap {hit} focus functions, at least {need} needed ({names})"
    for a in anchors:
        path, _, line = str(a.get("ref", "")).rpartition(":")
        if not line.isdigit() or not any(_overlaps((path, int(line), int(line)), r) for r in parsed):
            return f"{wid}: refs do not contain anchor {a.get('lead_id')} at {a.get('ref')}"
    if outcome == "violated":
        key = row.get("draft_key")
        d = drafts.get(str(key)) if key else None
        if d is None or d.get("status") not in LIVE_DRAFT:
            return f"{wid}: violated needs draft_key of a live finding that reports the break"
        if not any(_overlaps(tuple(q), r) for q in d.get("locations") or [] for r in parsed):  # type: ignore[arg-type]
            return f"{wid}: the finding {key} has no location quote inside the refs"
    return None


def merge_rows(previous: list[dict[str, Any]] | None, new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Previous answers updated by the new rows, keyed by walk_id, in walk order of arrival."""
    out: dict[str, dict[str, Any]] = {}
    for row in previous or []:
        if isinstance(row, dict) and row.get("walk_id"):
            out[str(row["walk_id"])] = row
    for row in new:
        out[str(row["walk_id"])] = row
    return list(out.values())


def open_walks(lc: dict[str, Any] | None, rows: list[dict[str, Any]] | None,
               drafts: dict[str, dict[str, Any]]) -> list[str]:
    """Walk ids without an accepted answer (F9). A violated answer re-opens when its finding is
    withdrawn later."""
    answered: dict[str, dict[str, Any]] = {str(r.get("walk_id")): r for r in rows or [] if isinstance(r, dict)}
    out = []
    for wid in walk_index(lc):
        row = answered.get(wid)
        if row is None or row.get("outcome") not in OUTCOMES or row["outcome"] == "violated" and (drafts.get(str(row.get("draft_key"))) or {}).get("status") not in LIVE_DRAFT:
            out.append(wid)
    return out


async def load_drafts(conn: Any, job_id: str) -> dict[str, dict[str, Any]]:
    """{draft_key: {status, locations: [(path, start, end)]}} for the job's current revisions."""
    cur = await conn.execute(
        """select d.draft_key, d.status, q.path, q.start_line, q.end_line
             from finding_drafts d
             left join finding_quote_ranges q
               on q.job_id = d.job_id and q.draft_key = d.draft_key and q.revision = d.current_revision
              and q.role = 'location'
            where d.job_id = %s""",
        (job_id,),
    )
    out: dict[str, dict[str, Any]] = {}
    for key, status, path, start, end in await cur.fetchall():
        d = out.setdefault(key, {"status": status, "locations": []})
        if path is not None:
            d["locations"].append((path, int(start), int(end)))
    return out


async def load_reads(conn: Any, job_id: str) -> dict[str, list[tuple[int, int]]]:
    cur = await conn.execute("select path, start_line, end_line from job_reads where job_id = %s", (job_id,))
    reads: dict[str, list[tuple[int, int]]] = {}
    for path, start, end in await cur.fetchall():
        reads.setdefault(path, []).append((int(start), int(end)))
    return reads


async def latest_rows(conn: Any, job_id: str) -> list[dict[str, Any]]:
    cur = await conn.execute(
        """select content from sections where job_id = %s and section = 'invariant_walks'
            order by revision desc limit 1""",
        (job_id,),
    )
    row = await cur.fetchone()
    content = row[0] if row else None
    return [r for r in content if isinstance(r, dict)] if isinstance(content, list) else []
