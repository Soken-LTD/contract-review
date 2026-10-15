"""Server-computed coverage rows (04 §13, 03 §4.13).

compute_coverage_rows() is the ONE implementation that determines per-category
coverage status from the semantic map and job_reads.  F5 at finalize and
review_set_section validation both call this function.

Coverage status per category:
  read           - all functions in category_to_functions are fully covered by job_reads
  partially_read - at least one but not all functions are fully covered
  not_covered    - no function is fully covered (or no semantic layer)
  no_candidates  - no functions mapped to this category in category_to_functions

Determination rules:
- No semantic layer in map_doc → all categories: not_covered
- Category absent from category_to_functions → no_candidates
- A function span is "fully covered" when every line in [fn_start, fn_end] is contained
  in the union of overlapping job_reads entries for that file.
- read: every span fully covered
- partially_read: at least one span fully covered but not all
- not_covered: zero spans fully covered

Uses _parse_range_ref from challenge.py (same span normaliser, same path comparison).
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml

RUBRIC_DIR = Path(__file__).resolve().parents[3] / "contract" / "rubric"
CHECKLIST_DIR = RUBRIC_DIR / "checklists"

# Status ordering from best to worst coverage
COVERAGE_STATUSES = ("read", "partially_read", "not_covered", "no_candidates")


class EnumsLoadError(RuntimeError):
    """Raised when enums.yaml is missing or cannot be parsed (fail-closed)."""


@cache
def _load_enums() -> list[dict[str, Any]]:
    path = RUBRIC_DIR / "enums.yaml"
    if not path.exists():
        raise EnumsLoadError(f"enums.yaml not found at {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise EnumsLoadError(f"enums.yaml parse error: {exc}") from exc
    cats = data.get("categories", [])
    if not isinstance(cats, list):
        raise EnumsLoadError("enums.yaml 'categories' is not a list")
    return cats


def family_categories(family: str) -> list[str]:
    """Return all non-server-only category IDs for the given family.

    Propagates EnumsLoadError if enums.yaml is missing or unparsable.
    """
    return [
        c["id"] for c in _load_enums()
        if c.get("family") == family and not c.get("server_only")
    ]


def _span_fully_covered(
    fn_start: int, fn_end: int, file_reads: list[tuple[int, int]]
) -> bool:
    """Return True when every line in [fn_start, fn_end] is in the union of file_reads.

    We do a sweep: sort reads, merge overlapping intervals, then verify coverage.
    A single job_reads row covering [rs, re] covers any line in [rs, re].
    """
    if not file_reads:
        return False
    # Sort and merge overlapping read intervals
    intervals = sorted(file_reads)
    current = fn_start
    for rs, re in intervals:
        if rs > current:
            # Gap: [current, rs-1] not covered
            return False
        if re >= current:
            current = re + 1
        if current > fn_end:
            return True
    return current > fn_end


def compute_coverage_rows(
    family: str,
    map_doc: dict[str, Any] | None,
    job_reads_index: dict[str, list[tuple[int, int]]],
) -> list[dict[str, Any]]:
    """Return one row per family category: {area_id, status}.

    Callers build job_reads_index as path -> [(start_line, end_line)] from job_reads table.
    Uses category_to_functions from map_doc["semantic"] for span lookup; joins through
    spans[] (same normaliser as challenge.py) to get file/start/end.
    """
    cats = family_categories(family)
    rows: list[dict[str, Any]] = []

    if not cats:
        # No categories configured for this family: treat as F5-open so the
        # operator notices the configuration gap (not silently pass).
        rows.append({
            "area_id": "_no_categories",
            "status": "configuration_error",
            "note": f"no categories configured for family {family!r} in enums.yaml",
        })
        return rows

    semantic = None
    span_meta: dict[str, dict[str, Any]] = {}

    if map_doc is not None:
        semantic = map_doc.get("semantic")
        for sp in map_doc.get("spans", []):
            sid = sp.get("id", "")
            if sid:
                span_meta[sid] = sp

    for cat_id in cats:
        if semantic is None:
            rows.append({"area_id": cat_id, "status": "not_covered"})
            continue

        cat_to_fns: dict[str, list[str]] = semantic.get("category_to_functions", {})
        fn_span_ids: list[str] = cat_to_fns.get(cat_id, [])

        if not fn_span_ids:
            rows.append({"area_id": cat_id, "status": "no_candidates"})
            continue

        fully_covered = 0
        for sid in fn_span_ids:
            sp = span_meta.get(sid)
            if sp is None:
                continue
            fn_file = sp.get("file", "")
            fn_start = sp.get("start", 0)
            fn_end = sp.get("end", 0)
            if not fn_file or fn_end < fn_start:
                continue
            file_reads = job_reads_index.get(fn_file, [])
            if _span_fully_covered(fn_start, fn_end, file_reads):
                fully_covered += 1

        total = len(fn_span_ids)
        if fully_covered == total and total > 0:
            status = "read"
        elif fully_covered > 0:
            status = "partially_read"
        else:
            status = "not_covered"

        rows.append({"area_id": cat_id, "status": status})

    return rows


def rows_index(rows: list[dict[str, Any]]) -> dict[str, str]:
    """Return {area_id: status} dict for quick lookup."""
    return {r["area_id"]: r["status"] for r in rows}


@cache
def _load_checklist(family: str) -> dict[str, Any]:
    """Load and cache the checklist YAML for a family."""
    path = CHECKLIST_DIR / f"{family}.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def category_allowed_na_reasons(family: str, category_id: str) -> frozenset[str]:
    """Return the set of nr_* reason codes allowed for a specific category.

    Derived from the union of all ``na: [...]`` lists on checklist items for that
    category (04 §13, evm.yaml).  A category with no ``na`` entries allows no N/A
    reasons (fail-closed).  Generic items are NOT included (they carry no ``na``).
    """
    checklist = _load_checklist(family)
    categories = checklist.get("categories", {})
    cat_def = categories.get(category_id, {})
    items = cat_def.get("items", [])
    reasons: set[str] = set()
    for item in items:
        for reason in (item.get("na") or []):
            reasons.add(reason)
    return frozenset(reasons)
