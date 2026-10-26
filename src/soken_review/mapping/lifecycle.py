"""Lifecycle and invariant pass: server side (feat/lifecycle-invariant-pass, 2026-10-26).

Runs in the `map` step of every family (`run_map_step`), after the analyze step wrote
`leads.json`. It does three things, all deterministic:

1. Lifecycle signals: `lifecycle_evm` (solc AST) and `lifecycle_solana` (Anchor source text) find
   the anchors of state-lifecycle bugs. Each signal becomes an analyzer lead of tool
   `soken-lifecycle` with a message rendered from `contract/rubric/invariants.yaml`, so it rides
   the existing lead machinery: F2 forces a decision on Medium leads, a promoted lead gives E3
   evidence (a Critical can print), a dismissal needs a quote and a note.
2. Protocol types: name patterns from the rubric over in-scope function, state variable and
   account names (vault, staking, lending or escrow, token, AMM, governance).
3. Invariant walks: per detected type, the rubric's walks with the code they must cover: focus
   function spans resolved from the map and anchor lines from the lifecycle leads. The client
   answers them with `review_set_section(section=invariant_walks)`; finalize check F9 stays open
   until every walk has an accepted answer.

Everything is stored in `<pin_root>/<job_id>/map/lifecycle.json` (outside `map.v1`, whose schema
is closed). Every client-facing sentence comes from the rubric file; this module substitutes
identifiers only.
"""

from __future__ import annotations

import json
import logging
import re
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from .lifecycle_evm import evm_signals
from .lifecycle_solana import account_names, solana_signals

logger = logging.getLogger(__name__)

_RUBRIC = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "invariants.yaml"
_SEVERITY = {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}
_SEV_RANK = {"High": 4, "Medium": 3, "Low": 2, "Info": 1}
_LEAD_RE = re.compile(r"^LEAD-(\d{4})$")
_FOCUS_CAP = 12
_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")


@cache
def rubric() -> dict[str, Any]:
    return yaml.safe_load(_RUBRIC.read_text(encoding="utf-8"))


def _tool_tag() -> str:
    r = rubric()
    return f"{r['tool']}@{r['version']}"


def _render(template: str, params: dict[str, Any]) -> str:
    """Identifier substitution only; a missing parameter renders as `-` (never a crash)."""
    text = _PLACEHOLDER_RE.sub(lambda m: str(params.get(m.group(1)) or "-"), template)
    return " ".join(text.split())[:600]


def _dep_re(family: str) -> re.Pattern[str]:
    r = rubric()
    return re.compile((r.get(family) or r["evm"])["dependency_paths"])


# ── signals -> leads ──────────────────────────────────────────────────────────


def rank_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order, cap and grade the signals: at most `max_leads`, at most `max_medium` warnings."""
    r = rubric()
    lim = r["limits"]
    defs = r["lifecycle_signals"]
    ordered = sorted(signals, key=lambda s: (-int(s.get("score", 0)), s["file"], int(s["start"]), s["signal"]))
    seen: set[tuple[str, str, int]] = set()
    out: list[dict[str, Any]] = []
    medium = 0
    for s in ordered:
        key = (s["signal"], s["file"], int(s["start"]))
        if key in seen or s["signal"] not in defs:
            continue
        seen.add(key)
        raw = defs[s["signal"]]["severity"]
        if raw == "warning" and (not s.get("strong") or medium >= lim["max_medium"]):
            raw = "note"
        if raw == "warning":
            medium += 1
        out.append({**s, "severity_raw": raw})
        if len(out) >= lim["max_leads"]:
            break
    return out


def leads_from_signals(signals: list[dict[str, Any]], first_no: int) -> list[dict[str, Any]]:
    """lead.v1 documents for ranked signals, numbered from `first_no`; sets `lead_id` on each signal."""
    defs = rubric()["lifecycle_signals"]
    tag = _tool_tag()
    leads = []
    for i, s in enumerate(signals):
        d = defs[s["signal"]]
        lead_id = f"LEAD-{first_no + i:04d}"
        s["lead_id"] = lead_id
        lead: dict[str, Any] = {
            "id": lead_id,
            "rule_id": f"{rubric()['tool']}:{s['signal']}",
            "tools": [tag],
            "category": d["category"],
            "analyzer_severity_raw": s["severity_raw"],
            "severity_norm": _SEVERITY[s["severity_raw"]],
            "file": s["file"],
            "start": max(1, int(s["start"])),
            "end": max(int(s["start"]), int(s["end"])),
            "state": "open",
            "origin": "analyzer",
            "message": _render(d["message"], s.get("params") or {}),
        }
        if s.get("unit"):
            lead["unit"] = s["unit"][:200]
        leads.append(lead)
    return leads


# ── protocol types and walks ──────────────────────────────────────────────────


def _deployable_contracts(doc: dict[str, Any]) -> set[str] | None:
    """Contract names that expose at least one entry function (semantic layer); None without one.
    Interfaces, libraries and abstract helpers then do not drive type detection or focus spans."""
    funcs = (doc.get("semantic") or {}).get("functions")
    if not funcs:
        return None
    return {f["span"].split(".", 1)[0] for f in funcs if f.get("is_entry")}


def _in_scope_functions(doc: dict[str, Any], family: str) -> list[dict[str, Any]]:
    dep = _dep_re(family)
    spans = [sp for sp in doc.get("spans") or [] if sp.get("kind") in ("function", "modifier")
             and not dep.search(sp.get("file", ""))]
    contracts = _deployable_contracts(doc)
    if contracts:
        spans = [sp for sp in spans if str(sp.get("id", "")).split(".", 1)[0] in contracts]
    return spans


def detect_protocol_types(names: set[str], signal_ids: set[str] | None = None) -> list[dict[str, Any]]:
    """Name-detected types (at most limits.max_types, most hits first), then signal-driven types
    whose signals are present and not already walked by a detected type."""
    r = rubric()
    lowered = [n.lower() for n in names if n]
    found = []
    for tid, t in r["protocol_types"].items():
        if "detect" not in t:
            continue
        hits = [p for p in t["detect"] if any(re.search(p, n) for n in lowered)]
        if len(hits) >= int(t.get("min_hits", 2)):
            found.append({"id": tid, "label": t["label"], "hits": len(hits)})
    found.sort(key=lambda t: (-t["hits"], t["id"]))
    found = found[: int(r["limits"]["max_types"])]
    walked = {sig for t in found for w in r["protocol_types"][t["id"]]["walks"] for sig in w.get("signals") or []}
    for tid, t in r["protocol_types"].items():
        wanted = set(t.get("detect_signals") or [])
        if wanted and wanted & (signal_ids or set()) and not wanted & walked:
            found.append({"id": tid, "label": t["label"], "hits": 0})
    return found


def build_walks(types: list[dict[str, Any]], fn_spans: list[dict[str, Any]],
                signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    r = rubric()
    lim = r["limits"]
    walks: list[dict[str, Any]] = []
    for t in types:
        for w in r["protocol_types"][t["id"]]["walks"]:
            focus_re = re.compile(w["focus"], re.IGNORECASE)
            focus = sorted({f"{sp['file']}:{sp['start']}-{sp['end']}|{sp['name']}" for sp in fn_spans
                            if focus_re.search(sp.get("name") or "")},
                           key=lambda s: (s.split(":")[0], int(s.split(":")[1].split("-")[0])))[:_FOCUS_CAP]
            anchors = [s for s in signals if s["signal"] in (w.get("signals") or []) and s.get("lead_id")]
            anchors = sorted(anchors, key=lambda s: -int(s.get("score", 0)))[: int(lim["max_walk_anchors"])]
            walks.append({
                "id": w["id"], "type": t["id"], "title": w["title"],
                "focus": [{"range": f.split("|")[0], "name": f.split("|")[1]} for f in focus],
                "anchors": [{"lead_id": s["lead_id"], "ref": f"{s['file']}:{s['start']}"} for s in anchors],
            })
            if len(walks) >= int(lim["max_walks"]):
                return walks
    return walks


def build_lifecycle(family: str, files: dict[str, str], doc: dict[str, Any], solc_output: dict | None,
                    compiled_texts: dict[str, str] | None) -> dict[str, Any]:
    """Signals, protocol types and walks of one job (pure)."""
    r = rubric()
    sem = doc.get("semantic")
    signals: list[dict[str, Any]] = []
    try:
        if family == "evm":
            signals = evm_signals(solc_output, files, compiled_texts, sem, r["evm"])
        elif family == "solana":
            signals = solana_signals(files, r["solana"])
    except Exception:
        logger.exception("lifecycle signals failed (family %s)", family)
        signals = []
    fn_spans = _in_scope_functions(doc, family)
    names = {sp.get("name") or "" for sp in fn_spans}
    dep = _dep_re(family)
    contracts = _deployable_contracts(doc)
    for sv in (sem or {}).get("state_vars") or []:
        unit = str(sv.get("unit", ""))
        if not dep.search(unit.rsplit(":", 1)[0]) and (contracts is None or unit.rsplit(":", 1)[-1] in contracts):
            names.add(sv.get("name") or "")
    if family == "solana":
        names |= account_names(files, r["solana"])
    for s in signals:
        names.update(s.get("names") or [])
    ranked = rank_signals(signals)
    return {
        "version": r["version"],
        "family": family,
        "signals": ranked,
        "protocol_types": detect_protocol_types(names, {s["signal"] for s in ranked}),
    }


# ── storage ───────────────────────────────────────────────────────────────────


def _path(pin_root: Path, job_id: str) -> Path:
    return pin_root / job_id / "map" / "lifecycle.json"


def load_lifecycle(pin_root: Path, job_id: str) -> dict[str, Any] | None:
    p = _path(pin_root, job_id)
    if not p.is_file() or p.is_symlink():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _read_leads(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    leads = raw.get("leads", []) if isinstance(raw, dict) else raw
    return [x for x in leads if isinstance(x, dict)] if isinstance(leads, list) else []


def apply_lifecycle(pin_root: Path, job_id: str, family: str, files: dict[str, str], doc: dict[str, Any],
                    solc_output: dict | None, compiled_texts: dict[str, str] | None) -> dict[str, Any]:
    """Build the pass, merge its leads into leads.json (idempotent: earlier lifecycle leads are
    replaced) and write lifecycle.json. Returns a summary for the map step provenance."""
    lc = build_lifecycle(family, files, doc, solc_output, compiled_texts)
    leads_path = pin_root / job_id / "leads.json"
    tool = rubric()["tool"]
    existing = [x for x in _read_leads(leads_path)
                if not any(str(t).startswith(f"{tool}@") for t in x.get("tools") or [])]
    numbers = [int(m.group(1)) for x in existing if (m := _LEAD_RE.match(str(x.get("id", ""))))]
    new_leads = leads_from_signals(lc["signals"], (max(numbers) if numbers else 0) + 1)
    if new_leads or leads_path.is_file():
        merged = existing + new_leads
        merged.sort(key=lambda x: (-_SEV_RANK.get(str(x.get("severity_norm")), 0), str(x.get("file", "")),
                                   int(x.get("start", 0) or 0), str(x.get("id", ""))))
        leads_path.parent.mkdir(parents=True, exist_ok=True)
        leads_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    lc["walks"] = build_walks(lc["protocol_types"], _in_scope_functions(doc, family), lc["signals"])
    p = _path(pin_root, job_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(lc, sort_keys=True, indent=1), encoding="utf-8")
    return {"leads": len(new_leads), "types": [t["id"] for t in lc["protocol_types"]], "walks": len(lc["walks"])}


# ── client-facing renderings (text from the rubric) ───────────────────────────


def walk_text(walk_id: str) -> dict[str, Any] | None:
    for t in rubric()["protocol_types"].values():
        for w in t["walks"]:
            if w["id"] == walk_id:
                return w
    return None


def render_guide(lc: dict[str, Any] | None, family: str) -> list[str]:
    """Lines of review_get_guide topic invariants: the method, then the job's walks."""
    g = rubric()["guide"]
    out = [" ".join(g["intro"].split())]
    out += [f"{i}. {' '.join(s.split())}" for i, s in enumerate(g["steps"], 1)]
    out.append(f"Example: {g['answer_example']}")
    if lc is None:
        out.append("Walk catalogue (detected per job from function, state and account names):")
        for tid, t in rubric()["protocol_types"].items():
            out.append(f"{tid} ({t['label']}): " + ", ".join(f"{w['id']} {w['title']}" for w in t["walks"]))
        return out
    leads = [s for s in lc.get("signals") or [] if s.get("lead_id")]
    if leads:
        out.append("Lifecycle leads: " + "; ".join(
            f"{s['lead_id']} {s['signal']} {s['file']}:{s['start']}" for s in leads))
    types = lc.get("protocol_types") or []
    if types:
        out.append("Protocol types: " + ", ".join(f"{t['id']} ({t['label']})" for t in types))
    walks = lc.get("walks") or []
    if not walks:
        out.append(" ".join(g["no_walks"].split()))
        return out
    out.append(f"Invariant walks ({len(walks)}):")
    for w in walks:
        spec = walk_text(w["id"]) or {}
        out.append(f"{w['id']} {w['title']}: {' '.join(str(spec.get('text', '')).split())}")
        if w.get("focus"):
            out.append("  focus: " + ", ".join(f"{f['name']} {f['range']}" for f in w["focus"]))
        if w.get("anchors"):
            out.append("  anchors: " + ", ".join(f"{a['lead_id']} {a['ref']}" for a in w["anchors"]))
    return out


def map_pointer(lc: dict[str, Any] | None) -> str | None:
    if not lc or not (lc.get("walks") or lc.get("signals")):
        return None
    return _render(rubric()["map_pointer"], {
        "leads": str(sum(1 for s in lc.get("signals") or [] if s.get("lead_id"))) or "0",
        "types": ", ".join(t["id"] for t in lc.get("protocol_types") or []) or "none",
        "walks": str(len(lc.get("walks") or [])),
    })
