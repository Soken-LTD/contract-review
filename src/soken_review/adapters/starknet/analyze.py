"""Starknet analyze step (07 5.3, 8.3): `scarb lint` in the sandbox plus soken-cairo-rules.

Leads are lead.v1 exactly. The lint runs offline in the build tree; its text output is untrusted:
only diagnostics whose path is a pinned in-scope file and whose line exists in it become leads.
Own rules run in the supervisor over the pinned text and the class facts decoded from the hashed
program (sierra.class_facts), never over the container tree.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from soken_review.adapters.base import BuildResult, Lead
from soken_review.adapters.starknet.rules import TOOL as RULES_TOOL
from soken_review.adapters.starknet.rules import load_rules, run_rules
from soken_review.adapters.starknet.sierra import ClassFacts
from soken_review.adapters.starknet.source import extract_components, parse
from soken_review.adapters.starknet.units import in_scope_paths

logger = logging.getLogger(__name__)

_RUBRIC = Path(__file__).resolve().parents[4] / "contract" / "rubric"
_LINT_MAP = Path(__file__).parent / "lint_map.yaml"
LINT_TOOL = "scarb-lint"
_DIAG_RE = re.compile(r"^(warn|warning|error): Plugin diagnostic: (.*)$")
_LOC_RE = re.compile(r"^\s*--> /work/tree/([A-Za-z0-9_./-]{1,200}):(\d+):(\d+)\s*$")
_SEV_RANK = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def parse_lint_output(text: str) -> list[dict[str, Any]]:
    """`warn: Plugin diagnostic: <message>` then ` --> /work/tree/<path>:<line>:<col>`."""
    out: list[dict[str, Any]] = []
    pending: str | None = None
    for line in text.splitlines():
        m = _DIAG_RE.match(line.strip())
        if m:
            pending = m.group(2).strip()
            continue
        loc = _LOC_RE.match(line)
        if loc and pending is not None:
            out.append({"message": pending, "file": loc.group(1), "line": int(loc.group(2))})
            pending = None
    return out


def lint_to_hits(diags: list[dict[str, Any]], files: dict[str, str], package_dir: str) -> list[dict[str, Any]]:
    lint_map = yaml.safe_load(_LINT_MAP.read_text())
    default = lint_map["default"]
    rows: list[dict[str, Any]] = []
    scope = in_scope_paths(files, package_dir)
    for d in diags:
        path = d["file"]
        if path not in scope:
            continue
        n_lines = files[path].count("\n") + 1
        if not 1 <= d["line"] <= n_lines:
            continue
        name, spec = next(((k, v) for k, v in lint_map["lints"].items() if d["message"].startswith(v["message"])),
                          ("unmapped", default))
        rows.append({"tool": LINT_TOOL, "rule_id": f"{LINT_TOOL}:{name}", "category": spec["category"],
                     "raw": spec["raw"], "file": path, "start": d["line"], "end": d["line"], "unit": None})
    return rows


def _normalize(tool: str, raw: str) -> str:
    data = yaml.safe_load((_RUBRIC / "analyzer_severity.yaml").read_text())
    return (data["analyzers"].get(tool) or {}).get(raw, data.get("default", "High"))


def build_leads(rows: list[dict[str, Any]], versions: dict[str, str]) -> list[Lead]:
    """Merge rows with the same category, file and overlapping lines (07 5.3), number LEAD-0001.."""
    groups: list[list[dict[str, Any]]] = []
    for r in sorted(rows, key=lambda x: (x["category"], x["file"], x["start"])):
        for g in groups:
            if g[0]["category"] == r["category"] and g[0]["file"] == r["file"] and any(
                    r["start"] <= x["end"] and x["start"] <= r["end"] for x in g):
                g.append(r)
                break
        else:
            groups.append([r])
    leads: list[Lead] = []
    for g in groups:
        sevs = [(_normalize(x["tool"], x["raw"]), x) for x in g]
        best_sev, best = min(sevs, key=lambda t: _SEV_RANK[t[0]])
        lead: Lead = {
            "id": "",
            "rule_id": " + ".join(sorted({x["rule_id"] for x in g}))[:120],
            "tools": sorted({f"{x['tool']}@{versions[x['tool']]}" for x in g}),
            "category": g[0]["category"],
            "analyzer_severity_raw": best["raw"],
            "severity_norm": best_sev,
            "file": g[0]["file"],
            "start": min(x["start"] for x in g),
            "end": max(x["end"] for x in g),
            "state": "open",
        }
        unit = next((x["unit"] for x in g if x.get("unit")), None)
        if unit:
            lead["unit"] = unit[:200]
        leads.append(lead)
    leads.sort(key=lambda lead: (_SEV_RANK[lead["severity_norm"]], lead["file"], lead["start"], lead["rule_id"]))
    for i, lead in enumerate(leads, 1):
        lead["id"] = f"LEAD-{i:04d}"
    return leads


def run_lint(result: BuildResult, cairo_version: str) -> tuple[str, list[dict[str, Any]], str | None]:
    """(status, diagnostics, reason): `scarb --offline lint` inside the build image, no network."""
    from soken_review.adapters.starknet.build import _container_workdir, image_for, run_offline
    from soken_review.adapters.starknet.trust_scan import package_name

    if result.status != "ok" or not result.work_dir:
        return "not_run", [], "build_not_ok"
    image = image_for(cairo_version)
    if image is None:
        return "not_run", [], "toolchain_unavailable"
    settings = result.candidate.settings or {}
    package_dir = str(settings.get("package_dir") or "")
    workdir = _container_workdir(package_dir)
    if workdir is None:
        return "not_run", [], "unsafe_package_dir"
    pkg = package_name(result.candidate.files, package_dir)
    cmd = ["scarb", "--offline", "lint"] + (["--package", pkg] if pkg else [])
    rc, log = run_offline(image, Path(result.work_dir), workdir, cmd, 900)
    if rc != 0:
        return "not_run", [], "\n".join([f"exit {rc}", *log.splitlines()[-10:]])
    return "ok", parse_lint_output(log), None


def analyze(result: BuildResult, facts: ClassFacts | None, cairo_version: str | None,
            run_stock_lint: bool = True) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
    files = result.candidate.files
    package_dir = str((result.candidate.settings or {}).get("package_dir") or "")
    in_scope = {p: files[p] for p in in_scope_paths(files, package_dir)}
    parsed = [parse(p, t) for p, t in sorted(in_scope.items())]
    rules = load_rules()
    rows: list[dict[str, Any]] = [
        {"tool": RULES_TOOL, "rule_id": f"soken:{h.rule_id}", "category": h.category, "raw": h.raw,
         "file": h.file, "start": h.start, "end": h.end, "unit": h.unit}
        for h in run_rules(parsed, facts, rules)
    ]
    tools: dict[str, Any] = {RULES_TOOL: {"status": "ok", "version": rules["version"]}}
    not_run: list[str] = []
    if run_stock_lint and cairo_version:
        status, diags, reason = run_lint(result, cairo_version)
        tools[LINT_TOOL] = {"status": status, "reason": reason, "version": cairo_version, "diagnostics": len(diags)}
        if status == "ok":
            rows += lint_to_hits(diags, files, package_dir)
        else:
            not_run.append(LINT_TOOL)
    else:
        tools[LINT_TOOL] = {"status": "not_run", "reason": "no_toolchain"}
        not_run.append(LINT_TOOL)
    versions = {RULES_TOOL: rules["version"], LINT_TOOL: cairo_version or "unknown"}
    leads = build_leads(rows, versions)
    static_map = {
        "status": "degraded" if not_run else "ok",
        "not_run": not_run,
        "tools": tools,
        "facts": "unknown" if facts is None or not facts.complete else "complete",
        "facts_error": None if facts is None else facts.error,
        "functions": [{"file": cf.path, "name": fn.name, "kind": fn.kind, "start": fn.start, "end": fn.end}
                      for cf in parsed for fn in cf.functions],
        "components": extract_components(parsed),
        "account": any(fn.name in ("__validate__", "__execute__") for cf in parsed for fn in cf.functions),
    }
    read_plan = {"files": sorted(in_scope), "nsloc": result.nsloc}
    return leads, static_map, read_plan
