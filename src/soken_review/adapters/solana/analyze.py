"""Solana analyze step: clippy + cargo-audit + soken-solana-rules -> lead.v1 (06 section 3.4).

analyze(build_result) -> (leads, static_map, read_plan)

Tools (06 3.4):
  - clippy: runs in the candidate's build image (images.build_image of its version line), at the
    build's paths with the crates the deps step fetched, via docker_argv(step="analyze"); no network.
    ok only when cargo exits 0 and reports build-finished; otherwise status=error with the reason.
  - cargo-audit: runs INSIDE the solana-analyze image via docker_argv(step="analyze"); no network.
    RustSec advisory-db: the snapshot pinned in data/rustsec_db.json (rustsec.py), fetched beforehand
    and mounted read-only at /work/rustsec_db; commit, date and age are recorded with the result.
    When neither Docker nor the image is available, both tools record status=not_run.
  - soken-solana-rules: Python matcher over source files (rules/matcher.py)

Integrity rule (plan 09 3.5): no value that contributes to tier/hash decisions is read
from a container-written file. Clippy/audit JSON output comes from a host-side output dir
that is never the same mount as src. Host reads it through _safe_read_output_file().

Severity normalization: analyzer_severity.yaml rows soken-solana-rules, clippy, cargo-audit.
One lead per (category, file, overlapping range) per 04 E7.
Leads validated against contract/rubric/schemas/lead.v1.json.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema
import yaml

from soken_review.adapters.base import BuildResult, Lead
from soken_review.adapters.solana.detect import detect_framework_from_files
from soken_review.adapters.solana.rules.matcher import run_rules
from soken_review.adapters.solana.rules.matcher import version as rules_version
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_RUBRIC = _REPO_ROOT / "contract" / "rubric"
_SCHEMA_PATH = _RUBRIC / "schemas" / "lead.v1.json"
_SEVERITY_PATH = _RUBRIC / "analyzer_severity.yaml"

_DIRECT_TOOLS = os.environ.get("SOKEN_SOLANA_DIRECT", "0") == "1"
_SOKEN_RULES_VERSION = rules_version()
_CARGO_AUDIT_VERSION = "0.22.2"   # docker/solana-build/Dockerfile ARG, images.lock.json solana-analyze

# Docker limits for analysis step (offline, no network)
_ANALYZE_LIMITS = StepLimits(cpus=2.0, memory="4g", pids=256, max_file=64 * 1024 * 1024)

# Allowlisted clippy lints (06 3.4 U-S10)
_CLIPPY_LINTS = [
    "arithmetic_side_effects",
    "cast_possible_truncation",
    "unwrap_used",
    "indexing_slicing",
]

try:
    _LEAD_SCHEMA: dict = json.loads(_SCHEMA_PATH.read_text())
    _SEVERITY_MAP: dict = yaml.safe_load(_SEVERITY_PATH.read_text())
except Exception as exc:
    raise ImportError(f"Failed to load rubric data for solana/analyze: {exc}") from exc


# ---------------------------------------------------------------------------
# Host-safe output file reader (integrity: plan 09 3.5)
# ---------------------------------------------------------------------------

def _safe_read_output_file(output_dir: Path, filename: str) -> bytes | None:
    """Read a file from the container output dir safely (no symlink follow, path confined).

    Returns raw bytes on success, None if the file is absent or unsafe.
    This mirrors _safe_read_so semantics for text output files.
    """
    candidate = output_dir / filename
    try:
        st = os.lstat(candidate)
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode):
        logger.warning("symlink in analyze output rejected: %s", candidate)
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    # Verify path is actually under output_dir (no traversal)
    try:
        resolved = candidate.resolve()
        if not resolved.is_relative_to(output_dir.resolve()):
            logger.warning("path escape in analyze output: %s", candidate)
            return None
    except (OSError, ValueError):
        return None
    try:
        return candidate.read_bytes()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(result: BuildResult) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
    """Run Solana analyzers and return (leads, static_map, read_plan).

    Without a build (failed, or no work dir) clippy and cargo-audit cannot run, but the
    soken-solana-rules matcher reads source only: it still runs and its leads are kept, and the
    static map is `degraded` with both build tools named in `not_run` (never an "ok" with fewer leads).
    """
    if result.status != "ok" or not result.work_dir:
        return analyze_source_only(result.candidate.files, f"build_{result.reason or 'failed'}")

    work_dir = Path(result.work_dir)
    analyze_dir = work_dir / "analyze"
    analyze_dir.mkdir(exist_ok=True)

    files = result.candidate.files
    framework = detect_framework_from_files(files)

    # Read overflow checks from host-only supervisor dir (written by build.py, never by container)
    host_dir = work_dir / "host"
    overflow_checks_path = host_dir / "overflow_checks.txt"
    if not overflow_checks_path.exists():
        # Fallback: pre-host-dir layout (older builds)
        overflow_checks_path = work_dir / "overflow_checks.txt"
    overflow_checks = overflow_checks_path.read_text().strip() if overflow_checks_path.exists() else "unknown"

    all_raw: list[dict] = []
    tool_statuses: dict[str, Any] = {}

    # --- clippy (runs INSIDE Docker; no network) ---
    subdir = str((result.candidate.settings or {}).get("subdir") or "").strip("/")
    clippy_result = _run_clippy_docker(work_dir, analyze_dir)
    if clippy_result["status"] == "ok":
        all_raw.extend(scope_items(clippy_result.get("items", []), files, subdir))
    tool_statuses["clippy"] = clippy_result

    # --- cargo-audit (runs INSIDE Docker; no network; RustSec DB from cache mount) ---
    cargo_lock = _find_cargo_lock(work_dir)
    audit_result = _run_cargo_audit_docker(work_dir, analyze_dir) if cargo_lock else {
        "status": "not_run", "reason": "no_cargo_lock",
    }
    if audit_result["status"] == "ok":
        all_raw.extend(scope_items(audit_result.get("items", []), files, subdir))
    tool_statuses["cargo_audit"] = audit_result

    # --- soken-solana-rules (Python, always runs) ---
    rules_raw = _run_solana_rules(files, framework, overflow_checks)
    all_raw.extend(rules_raw)
    tool_statuses["soken_solana_rules"] = f"ran@{_SOKEN_RULES_VERSION}"

    # Build leads
    leads = _build_leads(all_raw)

    # Read plan: mint constants
    read_plan = _build_read_plan(files)

    # A tool that did not run is visible at the top (03 3.1 analyzer_degraded), never hidden
    # under an "ok" with fewer leads.
    not_run = sorted(name for name, st in tool_statuses.items() if isinstance(st, dict) and st.get("status") != "ok")
    degraded_reasons = [f"{name}:{st.get('reason')}" for name, st in sorted(tool_statuses.items())
                        if isinstance(st, dict) and st.get("status") != "ok"]
    if (audit_result.get("db") or {}).get("stale"):
        degraded_reasons.append("cargo_audit:rustsec_db_stale")
    static_map = {
        "status": "degraded" if degraded_reasons else "ok",
        "not_run": not_run,
        "degraded_reasons": degraded_reasons,
        "framework": framework,
        "overflow_checks": overflow_checks,
        "tools": tool_statuses,
    }

    # Persist for downstream
    (analyze_dir / "leads.json").write_text(json.dumps(leads, indent=2), encoding="utf-8")
    (analyze_dir / "static_map.json").write_text(json.dumps(static_map, indent=2), encoding="utf-8")
    (analyze_dir / "read_plan.json").write_text(json.dumps(read_plan, indent=2), encoding="utf-8")

    return leads, static_map, read_plan


def scope_items(items: list[dict], files: dict[str, str], subdir: str = "") -> list[dict]:
    """Tool items on reviewed (pinned) paths only.

    A subdir job builds inside its repo workspace, so rustc names files from the workspace root
    (`<subdir>/src/lib.rs`): the prefix is stripped. Items on other workspace members or registry
    crates are not in the review scope and are dropped. A dependency advisory on a workspace
    Cargo.lock outside the pin lands on the crate's Cargo.toml (where the dependency is declared).
    """
    out = []
    prefix = f"{subdir}/" if subdir else ""
    for item in items:
        path = str(item.get("file") or "")
        if prefix and path.startswith(prefix):
            path = path[len(prefix):]
        if path not in files and PurePosixPath(path).name == "Cargo.lock" and "Cargo.toml" in files:
            path = "Cargo.toml"
        if path in files:
            out.append({**item, "file": path})
    return out


def analyze_source_only(files: dict[str, str], reason: str,
                        overflow_checks: str = "unknown") -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
    """soken-solana-rules over the pinned source when no build exists (reason names why)."""
    framework = detect_framework_from_files(files)
    leads = _build_leads(_run_solana_rules(files, framework, overflow_checks))
    static_map = {
        "status": "degraded",
        "not_run": ["cargo_audit", "clippy"],
        "degraded_reasons": [f"cargo_audit:{reason}", f"clippy:{reason}"],
        "framework": framework,
        "overflow_checks": overflow_checks,
        "tools": {"clippy": {"status": "not_run", "reason": reason},
                  "cargo_audit": {"status": "not_run", "reason": reason},
                  "soken_solana_rules": f"ran@{_SOKEN_RULES_VERSION}"},
    }
    return leads, static_map, _build_read_plan(files)


# ---------------------------------------------------------------------------
# clippy (INSIDE Docker, step=analyze, no network)
# ---------------------------------------------------------------------------

def _find_cargo_lock(work_dir: Path) -> Path | None:
    src_dir = work_dir / "src"
    for lock in sorted(src_dir.rglob("Cargo.lock")):
        if not lock.is_symlink():
            return lock
    return None


def _write_pipe_output(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _run_clippy_docker(work_dir: Path, analyze_dir: Path) -> dict[str, Any]:
    """Run cargo clippy in the candidate's build image, at the build's paths (06 3.4: clippy runs in
    the build image), offline, with the crates the deps step fetched.

    Layout from host/build_meta.json (supervisor-written): source read-only at W, the candidate's
    CARGO_HOME read-write at CH, a fresh target dir. Status ok only when cargo exits 0: a clippy that
    could not compile is an error with its stderr tail, never "ok, no findings".

    Returns a result dict: {"status": "ok"|"not_run"|"error", "items": [...], "reason": "..."}
    """
    if _DIRECT_TOOLS:
        return _run_clippy_direct(work_dir, analyze_dir)

    from soken_review.adapters.solana.build import _safe_container_workdir, sandbox_layout

    layout = sandbox_layout(work_dir)
    if layout is None:
        return {"status": "not_run", "reason": "no_build_layout"}
    w, ch = layout["working_dir"], layout["cargo_home"]
    src_dir = work_dir / "src"
    src_root = src_dir / layout["mount"] if layout["mount"] else src_dir
    crate_rel, ws_rel = layout["crate_rel"], layout["ws_rel"]
    workdir = _safe_container_workdir(src_root, src_root / crate_rel if crate_rel else src_root, root=w)
    target = _safe_container_workdir(src_root, src_root / ws_rel if ws_rel else src_root, root=w)
    cargo_home = work_dir / "cargo-home"
    if workdir is None or target is None or not cargo_home.is_dir():
        return {"status": "not_run", "reason": "no_crate_dir_in_src"}
    clippy_target = sandbox_writable_dir(analyze_dir / "clippy_target")

    lint_args: list[str] = []
    for lint in _CLIPPY_LINTS:
        lint_args += ["-W", f"clippy::{lint}"]
    manifest = ["--manifest-path", f"{workdir}/Cargo.toml"] if layout.get("library_name") else []
    command = ["cargo", "clippy", "--locked", "--offline", "--ignore-rust-version", "--message-format=json", *manifest,
               *layout.get("cargo_args", []), "--", *lint_args]

    argv = docker_argv(
        step="analyze",
        image=layout["image"],
        work_dir=work_dir,
        cache_dir=None,
        limits=_ANALYZE_LIMITS,
        env={"HOME": layout["home"], "CARGO_HOME": ch, "RUSTUP_TOOLCHAIN": layout["active_toolchain"]},
        command=command,
        workdir=workdir,
        mounts=[
            (src_root, w, True),                         # source: read-only
            (clippy_target, f"{target}/target", False),  # clippy build dir: read-write, empty
            (cargo_home, ch, False),                     # crates fetched by deps; no network now
        ],
        image_paths=(w, ch),
    )

    # Container writes to stdout; captured via the subprocess pipe, never a container-written file.
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=900, check=False)
    except (subprocess.TimeoutExpired, Exception) as exc:  # noqa: BLE001
        return {"status": "not_run", "reason": f"docker_run_failed: {exc}"}

    _write_pipe_output(analyze_dir / "clippy_out.json", proc.stdout)
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.decode(errors="replace").splitlines()[-12:])
        return {"status": "error", "reason": f"clippy_exit_{proc.returncode}", "stderr_tail": tail}
    parsed = _parse_clippy_output(proc.stdout.decode(errors="replace"), layout["active_toolchain"])
    if not parsed.pop("build_finished", False):
        return {"status": "error", "reason": "clippy_no_build_finished"}
    return parsed


def _run_clippy_direct(work_dir: Path, analyze_dir: Path) -> dict[str, Any]:
    """Dev-only: run clippy on the host when SOKEN_SOLANA_DIRECT=1."""
    src_dir = work_dir / "src"
    if not src_dir.is_dir():
        return {"status": "not_run", "reason": "no_src_dir"}
    if not shutil.which("cargo"):
        return {"status": "not_run", "reason": "cargo_not_in_path"}

    cargo_tomls = sorted(src_dir.rglob("Cargo.toml"), key=lambda p: len(p.parts))
    if not cargo_tomls:
        return {"status": "not_run", "reason": "no_cargo_toml"}
    crate_dir = cargo_tomls[0].parent

    lint_args: list[str] = []
    for lint in _CLIPPY_LINTS:
        lint_args += ["-W", f"clippy::{lint}"]

    cmd = ["cargo", "clippy", "--locked", "--offline", "--message-format=json", "--"] + lint_args
    try:
        proc = subprocess.run(
            cmd, cwd=str(crate_dir), capture_output=True, timeout=300, check=False,
        )
    except (subprocess.TimeoutExpired, Exception):  # noqa: BLE001
        return {"status": "not_run", "reason": "cargo_clippy_failed"}

    parsed = _parse_clippy_output(proc.stdout.decode(errors="replace"))
    parsed.pop("build_finished", None)
    return parsed


def _parse_clippy_output(stdout: str, toolchain: str = "unknown") -> dict[str, Any]:
    items: list[dict] = []
    build_finished = False
    for line in stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") == "build-finished":
            build_finished = bool(msg.get("success"))
            continue
        if msg.get("reason") != "compiler-message":
            continue
        msg_inner = msg.get("message", {})
        level = msg_inner.get("level", "")
        if level not in ("warning", "error"):
            continue
        spans = msg_inner.get("spans", [])
        primary = next((s for s in spans if s.get("is_primary")), spans[0] if spans else {})
        file_name = primary.get("file_name", "")
        line_start = primary.get("line_start", 1)
        line_end = primary.get("line_end", line_start)
        code = msg_inner.get("code", {}) or {}
        rule_id = code.get("code", "") or ""
        if not rule_id:
            continue
        items.append({
            "tool": f"clippy@{toolchain.split('-')[0]}",
            "rule_id": f"clippy:{rule_id}",
            "severity_raw": level,
            "file": file_name,
            "start": max(1, int(line_start)),
            "end": max(1, int(line_end)),
            "category": "solana.arithmetic" if "arithmetic" in rule_id else "solana.other",
        })
    if not items:
        return {"status": "ok", "items": [], "note": "no_clippy_findings", "build_finished": build_finished}
    return {"status": "ok", "items": items, "build_finished": build_finished}


# ---------------------------------------------------------------------------
# cargo-audit (INSIDE Docker, step=analyze, no network)
# ---------------------------------------------------------------------------

def _run_cargo_audit_docker(work_dir: Path, analyze_dir: Path) -> dict[str, Any]:
    """Run cargo-audit inside the solana-analyze image (offline, pinned RustSec snapshot read-only).

    Returns {"status": "ok"|"not_run"|"error", "items": [...], "reason": "...", "db": {...}}

    The snapshot is the commit pinned in data/rustsec_db.json, fetched beforehand by
    `python -m soken_review.adapters.solana.rustsec fetch`; its commit, date and age go into the
    result. Not fetched: not_run rustsec_db_not_found.
    """
    if _DIRECT_TOOLS:
        return _run_cargo_audit_direct(work_dir, analyze_dir)

    image = locked_image("solana-analyze")
    if image is None:
        return {"status": "not_run", "reason": "image_digest_placeholder"}

    from soken_review.adapters.solana import rustsec

    db = rustsec.status()
    if db is None:
        return {"status": "not_run", "reason": f"rustsec_db_not_found:{rustsec.db_dir()}"}

    from soken_review.adapters.solana.build import sandbox_layout

    src_dir = work_dir / "src"
    layout = sandbox_layout(work_dir) or {}
    lock_rel = "/".join(p for p in (layout.get("mount"), layout.get("ws_rel"), "Cargo.lock") if p)
    lock = src_dir / lock_rel
    if not lock.is_file() or lock.is_symlink():
        found = _find_cargo_lock(work_dir)
        if found is None:
            return {"status": "not_run", "reason": "no_cargo_lock"}
        lock_rel = found.relative_to(src_dir).as_posix()

    command = [
        "cargo-audit", "audit", "--json", "--no-fetch",
        "--db", "/work/rustsec_db",
        "--file", f"/work/src/{lock_rel}",
    ]
    argv = docker_argv(
        step="analyze",
        image=image,
        work_dir=work_dir,
        cache_dir=None,
        limits=_ANALYZE_LIMITS,
        env={"HOME": "/tmp", "CARGO_HOME": "/tmp/cargo"},
        command=command,
        mounts=[
            (src_dir, "/work/src", True),                  # source: read-only
            (Path(db["path"]), "/work/rustsec_db", True),  # RustSec snapshot: read-only
        ],
    )

    try:
        proc = subprocess.run(argv, capture_output=True, timeout=300, check=False)
    except (subprocess.TimeoutExpired, Exception) as exc:  # noqa: BLE001
        return {"status": "not_run", "reason": f"docker_run_failed: {exc}", "db": db}

    _write_pipe_output(analyze_dir / "cargo_audit_out.json", proc.stdout)  # pipe, never a container file
    # cargo-audit exits 1 when it found vulnerabilities; anything else, or no JSON, is an error.
    if proc.returncode not in (0, 1):
        tail = "\n".join(proc.stderr.decode(errors="replace").splitlines()[-12:])
        return {"status": "error", "reason": f"cargo_audit_exit_{proc.returncode}", "stderr_tail": tail, "db": db}
    result = _parse_audit_output(proc.stdout.decode(errors="replace"))
    if result["status"] != "ok":
        result["status"] = "error"
        result["stderr_tail"] = "\n".join(proc.stderr.decode(errors="replace").splitlines()[-12:])
    result["db"] = db
    return result


def _run_cargo_audit_direct(work_dir: Path, analyze_dir: Path) -> dict[str, Any]:
    """Dev-only: run cargo-audit on the host when SOKEN_SOLANA_DIRECT=1."""
    cargo_lock = _find_cargo_lock(work_dir)
    if not cargo_lock:
        return {"status": "not_run", "reason": "no_cargo_lock"}

    bin_name = "cargo-audit" if shutil.which("cargo-audit") else None
    if bin_name is None:
        if shutil.which("cargo"):
            bin_name = "cargo"
        else:
            return {"status": "not_run", "reason": "cargo_audit_not_in_path"}

    cmd = (
        ["cargo-audit", "audit", "--json", "--file", str(cargo_lock), "--no-fetch"]
        if bin_name == "cargo-audit"
        else ["cargo", "audit", "--json", "--file", str(cargo_lock), "--no-fetch"]
    )
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=60, check=False,
        )
    except (subprocess.TimeoutExpired, Exception):  # noqa: BLE001
        return {"status": "not_run", "reason": "cargo_audit_failed"}

    return _parse_audit_output(proc.stdout.decode(errors="replace"))


def _parse_audit_output(stdout: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {"status": "not_run", "reason": "invalid_json_from_cargo_audit"}

    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), dict):
        return {"status": "not_run", "reason": "unexpected_json_from_cargo_audit"}
    database = data.get("database") if isinstance(data.get("database"), dict) else {}
    if not database.get("advisory-count"):
        return {"status": "not_run", "reason": "rustsec_db_empty"}
    items: list[dict] = []
    vulns = data.get("vulnerabilities", {}).get("list", [])
    for vuln in vulns:
        advisory = vuln.get("advisory", {})
        adv_id = advisory.get("id", "UNKNOWN")
        cvss = advisory.get("cvss", "")
        severity_band = _cvss_to_band(cvss)
        items.append({
            "tool": f"cargo-audit@{_CARGO_AUDIT_VERSION}",
            "rule_id": f"cargo-audit:{adv_id}",
            "severity_raw": severity_band,
            "file": "Cargo.lock",
            "start": 1,
            "end": 1,
            "category": "solana.dependency_advisory",
        })
    return {"status": "ok", "items": items, "advisory_count": database.get("advisory-count"),
            "vulnerabilities": len(items)}


def _cvss_to_band(cvss: str | None) -> str:
    """Map CVSS score string to cargo-audit severity band."""
    if not cvss:
        return "none"
    try:
        score = float(cvss.split("/")[0]) if "/" in cvss else float(cvss)
    except (ValueError, AttributeError):
        return "none"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# soken-solana-rules
# ---------------------------------------------------------------------------

def _run_solana_rules(
    files: dict[str, str],
    framework: str,
    overflow_checks: str,
) -> list[dict]:
    """Run soken-solana-rules matcher (06 3.5)."""
    try:
        return run_rules(files, framework, overflow_checks)
    except Exception as exc:  # noqa: BLE001
        logger.warning("soken-solana-rules failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Lead normalization, merging, validation (04 E7, 06 2.7)
# ---------------------------------------------------------------------------

def _normalize_severity(tool_name: str, raw: str) -> str:
    base_tool = tool_name.split("@")[0]
    tool_map = _SEVERITY_MAP.get("analyzers", {}).get(base_tool, {})
    norm = tool_map.get(raw) or tool_map.get(raw.lower())
    return norm or _SEVERITY_MAP.get("default", "High")


def _category_for(tool_name: str, rule_id: str, raw_category: str | None) -> str:
    if raw_category:
        return raw_category
    base_tool = tool_name.split("@")[0]
    if base_tool == "soken-solana-rules":
        return "solana.other"
    if base_tool == "clippy":
        return "solana.arithmetic"
    return "solana.other"


def _overlaps(a_s: int, a_e: int, b_s: int, b_e: int) -> bool:
    return a_s <= b_e and b_s <= a_e


def _merge_overlapping(items: list[dict]) -> list[list[dict]]:
    if not items:
        return []
    sorted_items = sorted(items, key=lambda x: x["start"])
    clusters: list[list[dict]] = [[sorted_items[0]]]
    for item in sorted_items[1:]:
        last = clusters[-1]
        cluster_end = max(i["end"] for i in last)
        if _overlaps(last[0]["start"], cluster_end, item["start"], item["end"]):
            last.append(item)
        else:
            clusters.append([item])
    return clusters


def _build_leads(raw_items: list[dict]) -> list[Lead]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for item in raw_items:
        cat = _category_for(item.get("tool", ""), item.get("rule_id", ""), item.get("category"))
        groups.setdefault((cat, item.get("file", "")), []).append(item)

    leads: list[Lead] = []
    sev_rank = {"High": 4, "Medium": 3, "Low": 2, "Info": 1}
    lead_idx = 1

    for (cat, file_path), items in groups.items():
        for group_items in _merge_overlapping(items):
            best_sev = "Info"
            tools_seen: list[str] = []
            rule_ids: list[str] = []
            for item in group_items:
                norm = _normalize_severity(item.get("tool", ""), item.get("severity_raw", ""))
                if sev_rank.get(norm, 0) > sev_rank.get(best_sev, 0):
                    best_sev = norm
                t = item.get("tool", "unknown@unknown")
                if t not in tools_seen:
                    tools_seen.append(t)
                r = item.get("rule_id", "unknown")
                if r not in rule_ids:
                    rule_ids.append(r)

            lead: Lead = {
                "id": f"LEAD-{lead_idx:04d}",
                "rule_id": rule_ids[0] if rule_ids else "unknown",
                "tools": tools_seen,
                "category": cat,
                "analyzer_severity_raw": group_items[0].get("severity_raw", "none"),
                "severity_norm": best_sev,
                "file": file_path,
                "start": max(1, min(i["start"] for i in group_items)),
                "end": max(1, max(i["end"] for i in group_items)),
                "state": "open",
            }

            try:
                jsonschema.validate(lead, _LEAD_SCHEMA)
                leads.append(lead)
                lead_idx += 1
            except jsonschema.ValidationError as exc:
                logger.debug("Lead validation failed: %s", exc.message)

    return leads


# ---------------------------------------------------------------------------
# Read plan (06 3.4 soken-solana-extract stub)
# ---------------------------------------------------------------------------

def _build_read_plan(files: dict[str, str]) -> dict[str, Any]:
    """Build a read plan stub from mint constants in source files (06 3.4, chain_state 1)."""
    import re
    mint_re = re.compile(
        r'(?:declare_id|Pubkey::from_str)\s*\(\s*"([A-Za-z0-9]{32,44})"\s*\)',
        re.MULTILINE,
    )
    mints: list[str] = []
    for content in files.values():
        if not isinstance(content, str):
            continue
        for m in mint_re.finditer(content):
            addr = m.group(1)
            from soken_review.adapters.solana.units import is_solana_address
            if is_solana_address(addr) and addr not in mints:
                mints.append(addr)

    return {
        "version": "1",
        "entries": [{"kind": "mint", "address": addr} for addr in mints],
        "note": "stub; full extraction requires soken-solana-extract",
    }
