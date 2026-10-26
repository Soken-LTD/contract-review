"""TON analyze step: Misti + soken-ton-rules -> lead.v1 list (plan v4 06 4.4).

analyze(build_result) -> (leads, static_map, read_plan)

Analyzer dispatch (plan 06 4.4):
  Tact:  Misti 0.9.0 built-ins via sandbox; soken-ton-rules
  Tolk:  acton linter (not yet implemented, U-T2); soken-ton-rules
  FunC:  soken-ton-rules only

Misti is run inside the sandbox (docker_argv step="analyze").
soken-ton-rules is Python-only and runs in-process (no sandbox needed for Python).
An analyzer that did not run is reported as static_map.status = not_run with a reason.

Severity normalization: analyzer_severity.yaml rows 'misti' and 'soken-ton-rules'.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from soken_review.adapters.base import BuildResult, Lead
from soken_review.adapters.ton.rules import _TOOL_NAME as _TON_RULES_TOOL_NAME
from soken_review.adapters.ton.rules import run_all_rules
from soken_review.adapters.ton.units import safe_store_path
from soken_review.sandbox.output import UnsafeOutput, read_output_files
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_RUBRIC = _REPO_ROOT / "contract" / "rubric"
_SCHEMA_PATH = _RUBRIC / "schemas" / "lead.v1.json"
_SEVERITY_PATH = _RUBRIC / "analyzer_severity.yaml"
_RULE_MAP_PATH = Path(__file__).parent / "data" / "rule_map.json"

_MISTI_VERSION = "0.9.0"
_MISTI_SARIF = "warnings.sarif"      # Misti writes <output-path dir>/warnings.sarif
# Gas and import-style results are not security leads (same role as evm _NOISE_DETECTORS): on
# Forton they were 49 of 81 Misti results, each one a lead a reviewer must triage.
_MISTI_NOISE_CATEGORIES = frozenset({"Optimization"})
_MISTI_NOISE = frozenset({"TransitiveImport"})
_MAX_SARIF_BYTES = 16 * 1024 * 1024
_ANALYZE_IMAGE = locked_image("ton-build")

_ANALYZE_LIMITS = StepLimits(cpus=2, memory="4g", pids=256, max_file=128 * 1024 * 1024)

# Dev-only bypass
_DIRECT = os.environ.get("SOKEN_TON_BUILD_DIRECT", "0") == "1"


def _load_json(p: Path) -> Any:
    return json.loads(p.read_text())


def _load_yaml(p: Path) -> Any:
    with p.open() as fh:
        return yaml.safe_load(fh)


try:
    _LEAD_SCHEMA: dict = _load_json(_SCHEMA_PATH)
    _SEVERITY_MAP: dict = _load_yaml(_SEVERITY_PATH)
    _RULE_MAP: dict = _load_json(_RULE_MAP_PATH)
    _TON_CATEGORIES: frozenset[str] = frozenset(
        c["id"] for c in _load_yaml(_RUBRIC / "enums.yaml")["categories"] if c.get("family") == "ton"
    )
except Exception as _exc:
    raise ImportError(f"Failed to load rubric data for ton/analyze: {_exc}") from _exc


# ── Public API ─────────────────────────────────────────────────────────────

def analyze(result: BuildResult, source_dir: Path | None = None) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
    """Run soken-ton-rules (+ Misti for Tact) and return (leads, static_map, read_plan).

    Both analyzers read the sources, not the build output: soken-ton-rules runs on the file texts
    and Misti compiles the Tact project itself. So a failed or refused build (exact compiler not in
    the image: matrix run 2026-10-25, Forton, tier B) still runs them when the caller passes
    `source_dir`, a fresh dir for the analyzer's own files; static_map.build records the build state.
    """
    if result.status == "ok" and result.work_dir:
        work_dir = Path(result.work_dir)
    elif source_dir is not None and result.candidate.files:
        work_dir = Path(source_dir)
        work_dir.parent.mkdir(parents=True, exist_ok=True)
    else:
        return [], {"status": "not_run", "reason": "build_failed"}, {}
    language = _get_language(result)
    files = result.candidate.files  # already path-safe (filter_candidate_files applied at fetch)

    all_raw: list[dict[str, Any]] = []

    # 1. soken-ton-rules (Python, all languages)
    ton_rules_raw = _run_ton_rules(files)
    all_raw.extend(ton_rules_raw)

    # 2. Misti for Tact (plan 06 4.4)
    misti_ran = False
    if language == "tact":
        misti_raw = _run_misti(work_dir, files, result.candidate.entry_contract
                               or (result.candidate.settings or {}).get("entry"))
        if misti_raw is not None:
            all_raw.extend(misti_raw)
            misti_ran = True
        else:
            logger.debug("Misti did not run; analyzer_degraded for Tact")

    leads = _build_leads(all_raw)
    static_map = _build_static_map(language, misti_ran)
    static_map["build"] = "ok" if result.status == "ok" else "failed"
    if language == "tact" and not misti_ran:
        static_map["status"] = "degraded"
        static_map["not_run"] = [f"misti@{_MISTI_VERSION}"]
    read_plan: dict[str, Any] = {"entries": [], "version": "1"}

    # Records go to the supervisor-only dir next to the attempt dir, never into a dir a
    # container has written (a planted symlink there would redirect the write).
    out_dir = work_dir.parent / f"{work_dir.name}.host" / "analyze"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "leads.json").write_text(json.dumps(leads, indent=2), encoding="utf-8")
    (out_dir / "static_map.json").write_text(json.dumps(static_map, indent=2), encoding="utf-8")
    (out_dir / "read_plan.json").write_text(json.dumps(read_plan, indent=2), encoding="utf-8")

    return leads, static_map, read_plan


def _get_language(result: BuildResult) -> str:
    lang = result.candidate.language.lower()
    if lang in ("func", "fift"):
        return "func"
    if lang == "tact":
        return "tact"
    if lang == "tolk":
        return "tolk"
    return "func"


# ── soken-ton-rules (Python-based, in-process) ────────────────────────────

def _run_ton_rules(files: dict[str, str]) -> list[dict[str, Any]]:
    """Run the soken-ton-rules rule pack in-process."""
    try:
        return run_all_rules(files)
    except Exception as exc:  # noqa: BLE001
        logger.warning("soken-ton-rules failed: %s", exc)
        return []


# ── Misti (Tact, sandbox) ─────────────────────────────────────────────────

def _tact_entry(candidate_entry: str | None, tact_files: list[str]) -> str:
    """The declared entry when it is one of the Tact files, else the first file in path order."""
    if candidate_entry:
        path = candidate_entry.split(":", 1)[0]
        if path in tact_files:
            return path
    return tact_files[0]


def _run_misti(work_dir: Path, files: dict[str, str], candidate_entry: str | None = None) -> list[dict[str, Any]] | None:
    """Run Misti 0.9.0 on Tact source and return raw leads or None (plan 06 4.4, F19).

    Misti runs in its own fresh dir next to the attempt dir (`<attempt>.misti`): sources and
    config are written before the container starts, /work/src is mounted read-only, and the
    SARIF is read back from /work/out through `sandbox.output` (no symlink, regular file).
    Returns None if Misti did not run (a None means not_run, not zero findings).
    """
    if not _DIRECT and _ANALYZE_IMAGE is None:
        return None
    tact_files = sorted(f for f in files if f.endswith(".tact"))
    if not tact_files:
        return []

    mdir = work_dir.parent / f"{work_dir.name}.misti"
    if mdir.exists():
        shutil.rmtree(mdir)
    if _DIRECT:
        mdir.mkdir()
        (mdir / "out").mkdir()
    else:
        sandbox_writable_dir(mdir)
        sandbox_writable_dir(mdir / "out")
    src_dir = mdir / "src"
    src_dir.mkdir()
    for path in tact_files:
        safe = safe_store_path(path)
        if safe is None:
            continue
        dest = src_dir / safe
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(files[path], encoding="utf-8")
    # The project root is the entry contract (it imports the rest); the first file in path order
    # only analysed what that file imported (Forton: ft_base_program_main, not ft_master).
    entry = _tact_entry(candidate_entry, tact_files)
    cfg = {"projects": [{"name": "analysis", "path": safe_store_path(entry), "output": "/tmp/tact_out",
                         "options": {}}]}
    (src_dir / "tact.config.json").write_text(json.dumps(cfg), encoding="utf-8")

    if _DIRECT:
        misti_bin = shutil.which("misti")
        if not misti_bin:
            return None
        cmd = [misti_bin, str(src_dir / "tact.config.json"), "--output-format", "sarif",
               "--output-path", str(mdir / "out")]
        try:
            subprocess.run(cmd, capture_output=True, timeout=180, check=False, cwd=str(src_dir))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
    else:
        if not shutil.which("docker"):
            return None
        argv = docker_argv(
            step="analyze",
            image=_ANALYZE_IMAGE,
            work_dir=mdir,
            cache_dir=None,
            limits=_ANALYZE_LIMITS,
            env={"HOME": "/tmp"},
            # --output-path is a directory: Misti 0.9.0 writes <dir>/warnings.sarif. A file path here
            # made it create a directory of that name, so no SARIF was ever read (Misti always not_run).
            command=["misti", "/work/src/tact.config.json", "--output-format", "sarif",
                     "--output-path", "/work/out"],
            runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
            mounts=[(mdir, "/work", False), (src_dir, "/work/src", True)],
        )
        try:
            subprocess.run(argv, capture_output=True, timeout=180, check=False)
        except subprocess.TimeoutExpired:
            return None

    try:
        found = read_output_files(mdir / "out", _MISTI_SARIF, 1, _MAX_SARIF_BYTES)
    except (FileNotFoundError, UnsafeOutput) as exc:
        logger.warning("misti output not read: %s", exc)
        return None
    if _MISTI_SARIF not in found:
        return None
    return _parse_misti_sarif(found[_MISTI_SARIF])


def _parse_misti_sarif(data: bytes) -> list[dict[str, Any]] | None:
    """Parse Misti SARIF output (container-written bytes) to raw lead dicts (plan 06 4.4, F19)."""
    try:
        sarif = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    raw: list[dict[str, Any]] = []
    for run in sarif.get("runs", []):
        tool_name = f"misti@{_MISTI_VERSION}"
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            if rule_id in _MISTI_NOISE or (result.get("properties") or {}).get("category") in _MISTI_NOISE_CATEGORIES:
                continue
            level = result.get("level", "warning")  # SARIF level: error/warning/note/none
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                file_path = (phys.get("artifactLocation", {}).get("uri") or "").removeprefix("file://").removeprefix("/work/src/")
                region = phys.get("region", {})
                start_line = region.get("startLine", 1)
                end_line = region.get("endLine", start_line)
                raw.append({
                    "tool": tool_name,
                    "rule_id": rule_id,
                    "severity_raw": level,
                    "file": file_path,
                    "start": start_line,
                    "end": end_line,
                })
    return raw


# ── Lead normalization and validation ─────────────────────────────────────

def _normalize_severity(tool_name: str, raw: str) -> str:
    base_tool = tool_name.split("@")[0]
    tool_map = _SEVERITY_MAP.get("analyzers", {}).get(base_tool, {})
    return tool_map.get(raw) or _SEVERITY_MAP.get("default", "High")


def _category_for(tool_name: str, rule_id: str) -> str:
    """rule_map.json category; an unmapped or unknown id becomes the generic `ton.best_practice` (enums.yaml)."""
    base_tool = tool_name.split("@")[0]
    cat = _RULE_MAP.get(base_tool, {}).get(rule_id)
    if cat not in _TON_CATEGORIES:
        logger.info("ton analyze: %s %s has no enums.yaml category; ton.best_practice", base_tool, rule_id)
        return "ton.best_practice"
    return cat


def _overlaps(a_s: int, a_e: int, b_s: int, b_e: int) -> bool:
    return a_s <= b_e and b_s <= a_e


def _merge_overlapping(items: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    if not items:
        return []
    sorted_items = sorted(items, key=lambda x: x["start"])
    clusters: list[list[dict[str, Any]]] = [[sorted_items[0]]]
    for item in sorted_items[1:]:
        last = clusters[-1]
        cluster_end = max(i["end"] for i in last)
        if _overlaps(last[0]["start"], cluster_end, item["start"], item["end"]):
            last.append(item)
        else:
            clusters.append([item])
    return clusters


def _build_leads(raw_items: list[dict[str, Any]]) -> list[Lead]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in raw_items:
        if not item.get("file") or not item.get("start"):
            continue
        cat = _category_for(item["tool"], item["rule_id"])
        groups.setdefault((cat, item["file"]), []).append(item)

    leads: list[Lead] = []
    sev_rank = {"High": 4, "Medium": 3, "Low": 2, "Info": 1}
    lead_idx = 1

    for (cat, file_path), items in groups.items():
        for group_items in _merge_overlapping(items):
            best_sev = "Info"
            tools_seen: list[str] = []
            rule_ids: list[str] = []
            for item in group_items:
                norm = _normalize_severity(item["tool"], item["severity_raw"])
                if sev_rank.get(norm, 0) > sev_rank.get(best_sev, 0):
                    best_sev = norm
                if item["tool"] not in tools_seen:
                    tools_seen.append(item["tool"])
                if item["rule_id"] not in rule_ids:
                    rule_ids.append(item["rule_id"])

            lead: Lead = {
                "id": f"LEAD-{lead_idx:04d}",
                "rule_id": rule_ids[0] if rule_ids else "unknown",
                "tools": tools_seen,
                "category": cat,
                "analyzer_severity_raw": group_items[0]["severity_raw"],
                "severity_norm": best_sev,
                "file": file_path,
                "start": min(i["start"] for i in group_items),
                "end": max(i["end"] for i in group_items),
                "state": "open",
            }
            try:
                jsonschema.validate(lead, _LEAD_SCHEMA)
            except jsonschema.ValidationError as exc:
                logger.warning("ton analyze: lead dropped, not lead.v1: %s", exc.message)
                continue
            leads.append(lead)
            lead_idx += 1

    return leads


def _build_static_map(language: str, misti_ran: bool) -> dict[str, Any]:
    return {
        "status": "ok",
        "language": language,
        "analyzer": f"misti@{_MISTI_VERSION}" if misti_ran else "not_run",
        "rule_pack": _TON_RULES_TOOL_NAME,
    }
