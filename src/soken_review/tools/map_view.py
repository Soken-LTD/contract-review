"""Text rendering of `map.v1` and facts for the bulk read tools (03 sections 4.4, 4.6, 4.8). Pure.

Compact line format, no outputSchema (03 1). Every value printed comes from the map or the fact
records (server data); identifiers in the map passed the identifier grammar (04 2.1).
"""

from __future__ import annotations

import re
from typing import Any

# Compiler output quotes source lines; only its error class names are printed (no source text).
_ERROR_CLASS_RE = re.compile(r"\b([A-Z][A-Za-z]{2,40}Error|not_checkable|failed|no_candidates|"
                             r"compiler_version_unknown|sandbox_unavailable|pin_load_error)\b")

_CAP = 20_000
_REASON_RE = re.compile(r"[a-z][a-z0-9_]{1,40}")


def build_error_summary(build_detail: str | None) -> str | None:
    """Server-safe form of a build failure: the leading reason token plus error class names.

    Raw compiler or build stderr can quote repo text, so it stays in host files only."""
    if not build_detail:
        return None
    head = str(build_detail).split(":", 1)[0].strip()
    parts = [head] if _REASON_RE.fullmatch(head) else []
    parts += [c for c in sorted(set(_ERROR_CLASS_RE.findall(str(build_detail)))) if c not in parts][:5]
    return ", ".join(parts) or "failed"


def _spans(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["id"]: s for s in doc.get("spans") or []}


def _range(span: dict[str, Any] | None) -> str:
    if not span:
        return "?"
    return f"{span['file']}:{span['start']}-{span['end']}"


def unit_entries(doc: dict[str, Any], unit: dict[str, Any]) -> list[dict[str, Any]]:
    """Entry functions callable on a unit: own and inherited, most-derived definition first."""
    sem = doc.get("semantic") or {}
    extras = ((sem.get("chain_extras") or {}).get("evm") or {}).get("units") or {}
    bases = (extras.get(unit["id"]) or {}).get("bases") or [unit["name"]]
    order = {name: i for i, name in enumerate(bases)}
    picked: dict[str, dict[str, Any]] = {}
    funcs = sorted((f for f in sem.get("functions") or [] if f.get("is_entry")),
                   key=lambda f: order.get(f["span"].split(".", 1)[0], len(order)))
    for f in funcs:
        owner, _, sig = f["span"].partition(".")
        if owner not in order:
            continue
        picked.setdefault(sig, f)
    return sorted(picked.values(), key=lambda f: f["span"].partition(".")[2])


def _callees(sem: dict[str, Any], doc: dict[str, Any], span_id: str, depth: int = 3) -> list[dict[str, Any]]:
    funcs = {f["span"]: f for f in sem.get("functions") or []}
    by_name: dict[str, list[str]] = {}
    for s in doc.get("spans") or []:
        by_name.setdefault(s["name"], []).append(s["id"])
    seen = {span_id}
    frontier = [span_id]
    out = []
    for _ in range(depth):
        nxt = []
        for sid in frontier:
            for c in (funcs.get(sid) or {}).get("calls") or []:
                if c.get("kind") != "internal":
                    continue
                for cand in by_name.get(c["target"], []):
                    if cand not in seen and cand in funcs:
                        seen.add(cand)
                        nxt.append(cand)
                        out.append(funcs[cand])
        frontier = nxt
    return out


def render_unit(doc: dict[str, Any], unit: dict[str, Any], facts: list[dict[str, Any]], detailed: bool) -> list[str]:
    sem = doc.get("semantic") or {}
    spans = _spans(doc)
    entries = unit_entries(doc, unit)
    lines = [f"unit {unit['id']} {unit['kind']} {unit['file']}:{unit['start']}-{unit['end']}"]
    names = [f["span"].partition(".")[2] for f in entries]
    lines.append(f"  entries {len(entries)}: " + (", ".join(names) if names else "none"))
    entry_ids = {f["span"] for f in entries}
    roles = [r for r in sem.get("roles") or [] if entry_ids & set(r.get("gated_functions") or [])]
    if roles:
        lines.append("  roles: " + "; ".join(
            f"{r['name']} holder {r['holder_kind']} gates {len(entry_ids & set(r['gated_functions']))}" for r in roles))
    else:
        lines.append("  roles: none found in code")
    ext: dict[str, list[str]] = {}
    writers: dict[str, set[str]] = {}
    for f in entries:
        reach = [f, *_callees(sem, doc, f["span"])]
        short = f["span"].partition(".")[2].split("(")[0]
        for g in reach:
            for c in g.get("calls") or []:
                if c["kind"] != "internal":
                    ext.setdefault(f"{c['kind']} {c['target']}", []).append(c["line"])
            for w in g.get("writes") or []:
                writers.setdefault(w["var"], set()).add(short)
    if ext:
        lines.append("  external calls: " + "; ".join(
            f"{k} at {', '.join(sorted(set(v))[:3])}{' +' + str(len(set(v)) - 3) if len(set(v)) > 3 else ''}"
            for k, v in sorted(ext.items())))
    else:
        lines.append("  external calls: none")
    if writers:
        lines.append("  writers: " + "; ".join(f"{var} by {', '.join(sorted(fs))}" for var, fs in sorted(writers.items())))
    else:
        lines.append("  writers: none")
    lines.append("  upgrade authority: " + _upgrade_authority(sem, unit, facts))
    if detailed:
        for f in entries:
            sp = spans.get(f["span"])
            guards = ", ".join(f"{g['class']}{'(' + g['hint'] + ')' if g.get('hint') else ''} {g['line']}"
                               for g in f.get("guards") or []) or "none"
            calls = ", ".join(f"{c['kind']} {c['target']} {c['line']}" for c in f.get("calls") or []) or "none"
            writes = ", ".join(f"{w['var']} {w['line']}" for w in f.get("writes") or []) or "none"
            lines.append(f"  entry {f['span']} {f['visibility']} {_range(sp)}")
            lines.append(f"    guards: {guards}")
            lines.append(f"    writes: {writes}")
            lines.append(f"    calls: {calls}")
    return lines


def _upgrade_authority(sem: dict[str, Any], unit: dict[str, Any], facts: list[dict[str, Any]]) -> str:
    rows = [u for u in sem.get("upgrade_surface") or [] if u.get("unit") == unit["id"]]
    by_key = {f["key"]: f for f in facts}
    if not rows:
        admin = by_key.get("onchain.eip1967.admin") or by_key.get("onchain.eip1967.implementation")
        if admin:
            return f"none in code; EIP-1967 slot set ({{{{fact:{admin['key']}}}}} = {admin['value']})"
        return "none in code"
    parts = []
    for r in rows:
        f = by_key.get(r["authority_fact_key"])
        val = f" = {f['value']}" if f else " (not read)"
        parts.append(f"{r['mechanism']}, authority {{{{fact:{r['authority_fact_key']}}}}}{val}")
    return "; ".join(parts)


def render_lexical(doc: dict[str, Any], status: str | None, build_detail: str | None) -> list[str]:
    """Map without a semantic layer (04 1.3): fixed line, build detail, lexical spans per file."""
    lines = ["Contract map unavailable"]
    if build_detail:
        classes = sorted(set(_ERROR_CLASS_RE.findall(build_detail)))[:5]
        lines.append("build failed: " + (", ".join(classes) if classes else "see review_status build"))
    lines.append(f"map_status {status or 'failed'}; lexical layer only")
    per_file: dict[str, list[str]] = {}
    for s in doc.get("spans") or []:
        per_file.setdefault(s["file"], []).append(f"{s['name']} {s['start']}-{s['end']}")
    for path, items in sorted(per_file.items()):
        lines.append(f"{path}: " + ", ".join(items))
    return lines


def render_markers(doc: dict[str, Any], path: str, start: int, end: int) -> list[str]:
    """`detailed` read markers: state writes and external calls on the returned lines (03 4.4)."""
    out: list[tuple[int, str]] = []
    for f in (doc.get("semantic") or {}).get("functions") or []:
        for w in f.get("writes") or []:
            p, _, ln = w["line"].rpartition(":")
            if p == path and start <= int(ln) <= end:
                out.append((int(ln), f"{w['line']} write {w['var']}"))
        for c in f.get("calls") or []:
            if c["kind"] == "internal":
                continue
            p, _, ln = c["line"].rpartition(":")
            if p == path and start <= int(ln) <= end:
                out.append((int(ln), f"{c['line']} call {c['kind']} {c['target']}"))
    return [t for _, t in sorted(set(out))]


def render_fact(f: dict[str, Any]) -> str:
    return f"{f['key']} {f['value']} {f.get('unit') or '-'} {f['source']}"
