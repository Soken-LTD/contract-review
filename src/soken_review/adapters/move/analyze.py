"""Move analyze step, shared by Sui and Aptos (plan v4 07 sections 5, 6.3, 7.3, 10).

  1. Stock lints in the sandbox (no network): Sui `sui move build --lint`, Aptos `aptos move lint`.
  2. Facts from the rebuilt modules the build copied to `host/` (root + linked dependencies).
  3. soken-move-rules (facts and source layers must agree).
  4. Leads: lead.v1 exactly; a stock lint and an own rule on the same category and overlapping lines
     merge into one lead listing both (07 5.3). Normalization only via rubric/analyzer_severity.yaml.

static_map.status: ok (every tool ran) | degraded (some did not; `not_run` lists tool and reason) |
not_run (none ran). A lead that fails lead.v1 raises: it is never silently dropped.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema
import yaml

from soken_review.adapters.base import BuildResult, Lead
from soken_review.adapters.move import lints, rules, sandbox
from soken_review.adapters.move.facts import LinkedSet
from soken_review.adapters.move.source import index_sources

_RUBRIC = Path(__file__).resolve().parents[4] / "contract" / "rubric"
_SCHEMA = json.loads((_RUBRIC / "schemas" / "lead.v1.json").read_text())
_SEVERITY = yaml.safe_load((_RUBRIC / "analyzer_severity.yaml").read_text())
_RANK = {"High": 4, "Medium": 3, "Low": 2, "Info": 1}


def normalize(tool: str, raw: str) -> str:
    """rubric/analyzer_severity.yaml; an unlisted raw value is the file default (fail closed)."""
    return (_SEVERITY["analyzers"].get(tool.split("@")[0]) or {}).get(raw) or _SEVERITY["default"]


def build_leads(items: list[dict[str, Any]]) -> list[Lead]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for it in items:
        groups.setdefault((it["category"], it["file"]), []).append(it)
    leads: list[Lead] = []
    for (category, file), group in sorted(groups.items()):
        group.sort(key=lambda x: (x["start"], x["end"]))
        clusters: list[list[dict[str, Any]]] = []
        for it in group:
            if clusters and it["start"] <= max(x["end"] for x in clusters[-1]):
                clusters[-1].append(it)
            else:
                clusters.append([it])
        for cl in clusters:
            best = max(cl, key=lambda x: _RANK[normalize(x["tool"], x["severity_raw"])])
            tools = list(dict.fromkeys(x["tool"] for x in cl))
            lead: Lead = {
                "id": f"LEAD-{len(leads) + 1:04d}",
                "rule_id": best["rule_id"],
                "tools": tools,
                "category": category,
                "analyzer_severity_raw": best["severity_raw"],
                "severity_norm": normalize(best["tool"], best["severity_raw"]),
                "file": file,
                "start": min(x["start"] for x in cl),
                "end": max(x["end"] for x in cl),
                "state": "open",
            }
            jsonschema.validate(lead, _SCHEMA)
            leads.append(lead)
    return leads


def load_host_modules(work: Path) -> dict[str, bytes]:
    """Rebuilt root package modules the build copied into host/ (the reviewed source's bytecode).

    Dependency modules are never taken from the build: the facts layer links the on-chain
    dependency bytecode read in chain_state at the pinned version (passed by the adapter); a
    dependency that was not read stays unresolved, so `nr_*` answers `unknown`."""
    return sandbox.read_artifacts(work / "host" / "artifacts")


def analyze(
    r: BuildResult,
    *,
    chain: str,
    lint_runs: list[tuple[list[str], Callable[[str], str | None]]],
    lint_version: str,
    chain_extras: dict[str, Any],
    upgrade: dict[str, Any] | None,
    in_scope: Callable[[str], bool],
    rules_dir: Path,
    lint_map_path: Path,
    dep_modules: dict[str, bytes],
    step_deadline: float | None = None,
) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
    """lint_runs: (argv, printed-path -> pin path) per unit package."""
    if r.status != "ok" or not r.work_dir:
        return [], {"status": "not_run", "reason": "build_failed", "not_run": [
            {"tool": f"{chain}-lint", "reason": "build_failed"}, {"tool": rules.TOOL, "reason": "build_failed"}]}, {}
    work = Path(r.work_dir)
    dirs = {"src": work / "src", "out": work / "out", "move": work / "move", "host": work / "host"}
    items: list[dict[str, Any]] = []
    not_run: list[dict[str, str]] = []
    degraded: list[dict[str, str]] = []
    tools: dict[str, Any] = {}

    # 1. stock lints
    lint_tool = f"{chain}-lint@{lint_version}"
    lint_map = lints.load_lint_map(lint_map_path)
    unmapped: set[str] = set()
    lint_ok = True
    for argv, path_map in lint_runs:
        # Step deadline: if the budget for this step is exhausted, skip remaining containers.
        if step_deadline is not None:
            remaining = step_deadline - time.monotonic()
            if remaining <= 0:
                not_run.append({"tool": lint_tool, "reason": "step_deadline", "detail": "step wall exceeded"})
                lint_ok = False
                break
            container_timeout = min(sandbox.ANALYZE_WALL_S, int(remaining) + 1)
        else:
            container_timeout = sandbox.ANALYZE_WALL_S
        try:
            # The CLIs write next to the package; lint runs on a scratch copy, the pin stays read-only.
            argv = [a.replace("/work/src", "/work/scratch/src", 1) if a.startswith("/work/src") else a for a in argv]
            run = sandbox.run(chain, "analyze", sandbox.scratch_copy(dirs, "lint"), argv,
                              timeout=container_timeout, workdir="/work/scratch/src")
        except sandbox.SandboxUnavailable as exc:
            not_run.append({"tool": lint_tool, "reason": "sandbox_unavailable", "detail": str(exc)})
            lint_ok = False
            break
        sandbox.write_host(dirs["host"] / f"lint-{len(tools)}.log", run.stdout + "\n" + run.stderr)
        if run.timed_out:
            # Container was killed by sandbox.run on timeout (docker rm -f); named reason.
            not_run.append({"tool": lint_tool, "reason": "analyze_timeout", "detail": "container killed"})
            lint_ok = False
            continue
        if run.returncode != 0:
            not_run.append({"tool": lint_tool, "reason": "analyzer_failed",
                            "detail": "killed" if run.returncode in (137, -9) else f"exit {run.returncode}"})
            lint_ok = False
            continue
        diags = lints.parse(chain, run.stdout + "\n" + run.stderr)
        got, miss, unlocated = lints.to_raw(chain, diags, lint_map, lint_tool, path_map)
        items += got
        unmapped.update(miss)
        if unlocated:
            degraded.append({"tool": lint_tool, "reason": "diagnostic_without_location", "detail": str(unlocated)})
    tools[lint_tool] = {"status": "ok" if lint_ok else "not_run", "unmapped_lints": sorted(unmapped)}

    # 2. facts
    linked = LinkedSet(chain, load_host_modules(work), dep_modules)
    source = index_sources(r.candidate.files, in_scope)
    shared, caps = rules.package_types(linked, chain)
    nr = linked.nr_predicates(upgrade)
    if not linked.root:
        nr = dict.fromkeys(nr, "unknown")        # no rebuilt module read: nothing is proven absent
    if chain == "aptos" and any("randomness" in a for f in source.functions for a in f.attributes):
        nr["nr_no_randomness_source"] = "false"

    # 3. own rules
    rule_tool = f"{rules.TOOL}@{rules.TOOL_VERSION}"
    if not linked.root:
        not_run.append({"tool": rule_tool, "reason": "no_rebuilt_modules"})
        tools[rule_tool] = {"status": "not_run"}
    else:
        ctx = rules.Ctx(chain=chain, linked=linked, source=source, chain_extras=chain_extras,
                        shared_types=shared, capabilities=caps)
        items += rules.run_rules(rules.load_rules(rules_dir, chain), ctx)
        tools[rule_tool] = {"status": "ok", "facts_errors": linked.errors, "unplaced": ctx.unplaced}
        if ctx.unplaced:
            degraded.append({"tool": rule_tool, "reason": "source_span_missing", "detail": ", ".join(ctx.unplaced)})
        if linked.errors:
            degraded.append({"tool": rule_tool, "reason": "module_unreadable", "detail": "; ".join(linked.errors)})
    if any(st == "partial" for st in source.files.values()):
        degraded.append({"tool": rule_tool, "reason": "source_layer_partial",
                         "detail": ", ".join(p for p, st in source.files.items() if st == "partial")})

    leads = build_leads([i for i in items if in_scope(i["file"])])
    ran = [t for t, v in tools.items() if v.get("status") == "ok"]
    status = "not_run" if not ran else ("degraded" if not_run or degraded else "ok")
    extras = chain_extras | {"shared_types": sorted(shared), "capability_types": sorted(caps)}
    static_map: dict[str, Any] = {
        "status": status, "chain": chain, "tools": tools, "not_run": not_run, "degraded": degraded, "nr": nr,
        "unreachable": linked.unreachable(), "chain_extras": extras,
        "linked_dependencies": {"source": "chain_state", "modules": len(dep_modules)},
        "files": [{"path": p, "status": s, "lexer": "fallback"} for p, s in sorted(source.files.items())],
        "spans": [{"id": f"{f.module}::{f.name}", "name": f.name, "kind": "function", "file": f.file,
                   "start": f.start, "end": f.end} for f in source.functions],
    }
    sandbox.write_host(dirs["host"] / "facts.json", json.dumps(linked.facts_json(), indent=1, default=list))
    sandbox.write_host(dirs["host"] / "static_map.json", json.dumps(static_map, indent=1))
    read_plan = {"version": "1", "entries": [{"file": ld["file"], "start": ld["start"], "end": ld["end"],
                                              "lead": ld["id"]} for ld in leads]}
    return leads, static_map, read_plan


def printed_to_pin(files: dict[str, str], base: str) -> Callable[[str], str | None]:
    """Map a diagnostic path to a pin path: relative to the CLI cwd (/work/src), to the package
    dir, or absolute under /work/src. Anything else (framework, deps) maps to None."""
    def norm(p: str) -> str | None:
        parts: list[str] = []
        for part in PurePosixPath(p).parts:
            if part in ("", ".", "/"):
                continue
            if part == "..":
                if not parts:
                    return None
                parts.pop()
            else:
                parts.append(part)
        return os.path.join(*parts) if parts else None

    def mapper(printed: str) -> str | None:
        if printed.startswith("/"):
            if not printed.startswith("/work/src/"):
                return None
            options = [printed.removeprefix("/work/src/")]
        else:
            options = [printed, f"{base}/{printed}" if base not in ("", ".") else printed]
        for o in options:
            path = norm(o)
            if path and path in files:
                return path
        return None
    return mapper
