"""EVM analyze step: Slither + Aderyn -> lead.v1 list (05 sections 8.1, 8.3, plan v4).

analyze(build_result) -> (leads, static_map, read_plan)

Security rules (09 4.1, reviewer notes 2026-10-09):
  - All tool invocations go through docker_argv(step="analyze").
  - Fail closed when docker is absent and SOKEN_ANALYZE_DIRECT != "1".
  - Sources written only into <proj>/src/ with is_relative_to(proj/src) check.
  - No config files (foundry.toml, hardhat configs, .env) are written to the
    project tree: Slither is driven with --compile-force-framework solc so it
    does not parse any build-system config (09 4.1 allows crytic-compile only
    with solc or foundry; we use the explicit solc path, not foundry here).
  - Remappings are passed as sanitized CLI flags; no untrusted string reaches
    a TOML or JSON config file.

Analyzer rules (05 8.1, 8.3):
  - Slither on every EVM build with --compile-force-framework solc.
  - Aderyn optional; absence reported in static_map.
  - Noise detectors -> coverage rows, not leads.
  - rule_id -> category via data/rule_map.json; unmapped -> evm.other.
  - severity normalized via contract/rubric/analyzer_severity.yaml.
  - One lead per (category, file, overlapping_range) (04 E7).
  - All leads validated against contract/rubric/schemas/lead.v1.json.
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
from soken_review.adapters.evm.build import _safe_relative_path, sanitize_remapping
from soken_review.adapters.evm.compiler_bugs import CompilerBugReport, report_from_work_dir
from soken_review.sandbox.output import UnsafeOutput, read_output_files
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rubric paths
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[4]
_RUBRIC = _REPO_ROOT / "contract" / "rubric"
_SCHEMA_PATH = _RUBRIC / "schemas" / "lead.v1.json"
_SEVERITY_PATH = _RUBRIC / "analyzer_severity.yaml"
_RULE_MAP_PATH = Path(__file__).parent / "data" / "rule_map.json"

# A Slither detector lists a wide scope element (the enclosing function/contract) alongside
# the specific node/variable/expression at fault. The lead points at the specific one so
# review_leads locates the suspicious line, not a whole function (eval: recall_narrow).
_SCOPE_ELEMENT_TYPES = frozenset({"contract", "function"})


def _detector_location(elements: list[dict]) -> tuple[int, int]:
    """Line span for one detector: its specific elements if any, else its scope element."""
    def _span(els: list[dict]) -> tuple[int, int] | None:
        lines = [n for el in els for n in (el.get("source_mapping", {}).get("lines") or [])]
        return (min(lines), max(lines)) if lines else None

    specific = [el for el in elements if el.get("type") not in _SCOPE_ELEMENT_TYPES]
    functions = [el for el in elements if el.get("type") == "function"]
    return _span(specific) or _span(functions) or _span(elements) or (1, 1)


# Noise detectors: coverage rows only, never leads (05 8.3)
_NOISE_DETECTORS = frozenset({
    "solc-version", "pragma", "naming-convention", "similar-names",
    "too-many-digits", "dead-code", "immutable-states", "constable-states",
})

_SLITHER_VERSION = "0.11.6"
_ADERYN_VERSION = "0.6.8"

_ANALYZE_IMAGE = locked_image("evm-analyze")  # digest-pinned (09 4.4); None = fail closed
_ANALYZE_LIMITS = StepLimits(cpus=2, memory="6g", pids=256, max_file=256 * 1024 * 1024)

# Dev-only bypass: never set in CI or tests touching fetched sources
_DIRECT_TOOLS = os.environ.get("SOKEN_ANALYZE_DIRECT", "0") == "1"

# Caps for files a container wrote (09 3.5): build std-json and tool reports
_MAX_BUILD_JSON = 256 * 1024 * 1024
_MAX_REPORT_JSON = 64 * 1024 * 1024

# Host-owned, read-only tool config mounted into the analyze sandbox: Slither never reads a
# config from the (attacker-controlled) source tree.
TOOL_CONFIG_MOUNT = "/work/.soken-config"
_SLITHER_CONFIG = "slither.config.json"

# Whitelisted evmVersion values (05 plan section 6.4 + solc docs)
_ALLOWED_EVM_VERSIONS = frozenset({
    "homestead", "tangerineWhistle", "spuriousDragon", "byzantium",
    "constantinople", "petersburg", "istanbul", "berlin", "london",
    "paris", "shanghai", "cancun", "prague",
})

# Only Solidity and Vyper source files are written to proj/src (09 4.1).
# .json is excluded to prevent package.json / slither.config.json / waffle.json
# from steering crytic-compile framework detection.
_ALLOWED_SOURCE_EXTS = frozenset({".sol", ".vy"})

# Config basenames that must never appear anywhere in the project tree.
_FORBIDDEN_BASENAMES = frozenset({
    "package.json", "package-lock.json", "yarn.lock",
    "foundry.toml", "hardhat.config.js", "hardhat.config.ts",
    "truffle-config.js", "truffle.js",
    "brownie-config.yaml", "brownie-config.yml",
    "slither.config.json", "ape-config.yaml",
    "remappings.txt", "makefile", "makefile.toml",
    ".env", ".env.local",
    "embark.json", "waffle.json",
    "crytic_compile.config.json", "aderyn.toml",
})


def _load_json(path: Path) -> Any:
    with path.open() as fh:
        return json.load(fh)


def _load_yaml(path: Path) -> Any:
    with path.open() as fh:
        return yaml.safe_load(fh)


try:
    _LEAD_SCHEMA: dict = _load_json(_SCHEMA_PATH)
    _SEVERITY_MAP: dict = _load_yaml(_SEVERITY_PATH)
    _RULE_MAP: dict = _load_json(_RULE_MAP_PATH)
except Exception as _exc:
    raise ImportError(f"Failed to load rubric data for evm/analyze: {_exc}") from _exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(result: BuildResult) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
    """Run Slither (+ Aderyn if available) inside the sandbox, return (leads, static_map, read_plan)."""
    if result.status != "ok" or not result.work_dir:
        return [], {"status": "not_run", "reason": "build_failed"}, {}
    if (result.candidate.language or "").lower() == "vyper":  # 05 15: Vyper plug-in
        from soken_review.adapters.vyper.analyze import analyze as vyper_analyze

        return vyper_analyze(result)

    work_dir = Path(result.work_dir)
    out_dir = prepare_analyze_dir(work_dir)

    proj_dir = out_dir / "proj"
    settings = _extract_settings(work_dir)
    if not _materialize_sources(work_dir, proj_dir):
        return [], {"status": "not_run", "reason": "project_materialization_failed"}, {}

    solc_path = _solc_path(result)
    if solc_path is None:
        return [], {"status": "not_run", "reason": "compiler_binary_missing"}, {}
    all_raw: list[dict] = []

    entry = (result.candidate.entry_contract or "").rpartition(":")[0] or None
    slither_raw = _run_slither(proj_dir, out_dir, solc_path, settings, entry)
    if slither_raw is None:
        reason = "sandbox_unavailable" if _ANALYZE_IMAGE is None and not _DIRECT_TOOLS else "analyzer_failed"
        return [], {"status": "not_run", "reason": reason}, {}
    all_raw.extend(slither_raw)

    solc_version = result.candidate.compiler.version if result.candidate.compiler else None
    aderyn_raw = _run_aderyn(proj_dir, out_dir, solc_version, solc_path, settings.get("remappings"))
    if aderyn_raw is not None:
        all_raw.extend(aderyn_raw)

    # Compiler advisories (05 6.2): construct matches are located leads (A2), the rest are rows
    bug_report = compiler_bug_report(result)
    all_raw.extend(bug_report.raw_leads)

    leads = _build_leads(all_raw)
    static_map = _build_static_map(out_dir, aderyn_available=aderyn_raw is not None)
    static_map["compiler_advisories"] = {
        "status": bug_report.status,
        "reason": bug_report.reason,
        "version": bug_report.version,
        "rows": bug_report.advisories,
    }
    read_plan: dict[str, Any] = {"entries": [], "version": "1"}

    write_records(work_dir, leads, static_map, read_plan)
    return leads, static_map, read_plan


# ---------------------------------------------------------------------------
# Container-written files and host-only records (09 3.5)
# ---------------------------------------------------------------------------

def host_dir(work_dir: Path) -> Path:
    """Supervisor-only dir next to the attempt dir; no container mounts it (TON: `<attempt>.host`)."""
    d = work_dir.parent / f"{work_dir.name}.host"
    d.mkdir(exist_ok=True)
    return d


def write_records(work_dir: Path, leads: list, static_map: dict, read_plan: dict) -> Path:
    """leads.json, static_map.json, read_plan.json into the host-only dir, never into a dir a
    container has written (a planted symlink there would redirect the write)."""
    out = host_dir(work_dir) / "analyze"
    out.mkdir(exist_ok=True)
    (out / "leads.json").write_text(json.dumps(leads, indent=2), encoding="utf-8")
    (out / "static_map.json").write_text(json.dumps(static_map, indent=2), encoding="utf-8")
    (out / "read_plan.json").write_text(json.dumps(read_plan, indent=2), encoding="utf-8")
    return out


def read_sandbox_json(directory: Path, name: str, cap: int = _MAX_REPORT_JSON) -> Any | None:
    """One JSON file a container may have written: no symlinks, regular file, size cap.
    None when missing, unsafe or not JSON (callers treat it as "no result")."""
    try:
        found = read_output_files(directory, name, 1, cap)
    except (FileNotFoundError, UnsafeOutput, OSError):
        return None
    data = found.get(name)
    if data is None:
        return None
    try:
        return json.loads(data)
    except ValueError:
        return None


def _host_build_json(work_dir: Path, name: str) -> dict | None:
    from soken_review.adapters.evm.build import host_build_dir

    path = host_build_dir(work_dir) / name
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_BUILD_JSON:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def build_input(work_dir: Path) -> dict | None:
    """The build's std-json input: the host-only copy the build step wrote from memory.
    Nothing under work/ is read after the build returns (a container may have changed it)."""
    return _host_build_json(work_dir, "input.json")


def build_output(work_dir: Path) -> dict | None:
    """The build's compiler output, host-only copy (see build_input)."""
    return _host_build_json(work_dir, "output.json")


def prepare_analyze_dir(work_dir: Path, name: str = "analyze") -> Path:
    """A fresh work/<name> dir. Whatever a previous container left there (a dir, a file, a
    symlink to a host path) is removed without following links, then the dir is created."""
    d = work_dir / name
    if d.is_symlink() or d.is_file():
        d.unlink()
    elif d.exists():
        shutil.rmtree(d)  # rmtree does not follow symlinks inside the tree
    d.mkdir()
    return d


SBX_MOUNT = "/work/analyze/sbx"


def sbx_dir(work_dir: Path) -> Path:
    """work/analyze/sbx: the only dir an analyze container may write (tool JSON reports)."""
    return work_dir / "analyze" / "sbx"


def tool_config_mounts(work_dir: Path) -> list[tuple[Path, str, bool]]:
    """Mounts for an analyze container (09 3.5):
      /work                read-only (sources the host materialized, the build tree)
      /work/analyze/sbx    read-write, the container's only writable dir; read back only
                           through sandbox/output.py
      /work/.soken-config  read-only, host-owned: empty slither.config.json (+ Vyper bin)
    Host records never go under work/ (write_records uses `<attempt>.host`)."""
    from soken_review.sandbox.profile import sandbox_writable_dir

    cfg = host_dir(work_dir) / "tool-config"
    cfg.mkdir(exist_ok=True)
    (cfg / _SLITHER_CONFIG).write_text("{}\n", encoding="utf-8")
    prepare_analyze_dir(work_dir, ".soken-config")  # mount point, never a planted link
    analyze = work_dir / "analyze"
    if not analyze.is_dir() or analyze.is_symlink():
        prepare_analyze_dir(work_dir)
    sbx = sbx_dir(work_dir)
    # Kept across the tools of one analyze run (Slither, then Aderyn); prepare_analyze_dir already
    # gave this run a fresh analyze/. Only a link or a non-dir is replaced.
    if sbx.is_symlink() or (sbx.exists() and not sbx.is_dir()):
        prepare_analyze_dir(analyze, "sbx")
    sandbox_writable_dir(sbx)
    return [
        (work_dir.resolve(), "/work", True),
        (sbx.resolve(), SBX_MOUNT, False),
        (cfg.resolve(), TOOL_CONFIG_MOUNT, True),
    ]


# ---------------------------------------------------------------------------
# Settings extraction (sanitized; no untrusted value reaches config files)
# ---------------------------------------------------------------------------

def _extract_settings(work_dir: Path) -> dict:
    """Load and sanitize settings from the build input.json."""
    raw = build_input(work_dir)
    if raw is None:
        return {}
    raw_settings = raw.get("settings", {})
    result: dict = {}

    # Remappings: use the shared sanitize_remapping validator (build.py)
    # Prefer embedding remappings in std-json settings rather than argv;
    # _run_slither passes them via --solc-remaps only as a fallback.
    clean_remaps: list[str] = []
    for r in raw_settings.get("remappings", []):
        safe = sanitize_remapping(r)
        if safe is not None:
            clean_remaps.append(safe)
    result["remappings"] = clean_remaps

    # optimizer: validate types strictly - never let untrusted string reach a config file
    optimizer = raw_settings.get("optimizer", {})
    runs = optimizer.get("runs", 200)
    if not isinstance(runs, int) or not (0 <= runs <= 0xFFFFFFFF):
        runs = 200  # reject; use safe default
    result["optimizer_runs"] = runs
    result["optimizer_enabled"] = optimizer.get("enabled") is True
    result["via_ir"] = raw_settings.get("viaIR") is True

    # evmVersion: must be in the fixed allowlist
    evm_version = raw_settings.get("evmVersion", "")
    if evm_version in _ALLOWED_EVM_VERSIONS:
        result["evm_version"] = evm_version
    # else omit (Slither will use its default)

    return result


def compiler_bug_report(result: BuildResult) -> CompilerBugReport:
    """05 6.2 advisories for the exact recorded compiler of this build."""
    compiler = result.candidate.compiler
    if compiler is None or not result.work_dir:
        return CompilerBugReport("not_run", "compiler_version_unknown")
    return report_from_work_dir(Path(result.work_dir), compiler.version, compiler.version_pinned_by)


def _solc_path(result: BuildResult) -> str | None:
    """The exact solc release the build used (05 6.1); never another cached release."""
    compiler = result.candidate.compiler
    if compiler is None:
        return None
    from soken_review.adapters.evm.compiler import CompilerCacheError, get_cache

    try:
        return str(get_cache().binary(compiler.version))
    except CompilerCacheError:
        return None


# ---------------------------------------------------------------------------
# Source tree materialization
# ---------------------------------------------------------------------------

def _materialize_sources(work_dir: Path, proj_dir: Path) -> bool:
    """Write only .sol/.vy files under proj_dir/src/, checked with is_relative_to.

    No config files are written (no foundry.toml, no hardhat configs).
    Returns False if any source key fails validation.
    """
    inp = build_input(work_dir)
    if inp is None:
        return False

    src_dir = proj_dir / "src"
    # The analyze copy (not the pin): crytic-compile writes crytic-export into its cwd here as uid 10001.
    sandbox_writable_dir(src_dir)
    src_base = src_dir.resolve()

    for raw_key, src_data in inp.get("sources", {}).items():
        if not _safe_relative_path(raw_key):
            return False  # fail closed on unsafe path key

        ext = Path(raw_key).suffix.lower()
        if ext not in _ALLOWED_SOURCE_EXTS:
            continue  # skip non-source files (.json, .ts, etc.)

        # Reject any component matching a forbidden config basename
        key_parts = Path(raw_key).parts
        if any(part.lower() in _FORBIDDEN_BASENAMES for part in key_parts):
            return False  # e.g. "lib/slither.config.json" or just "foundry.toml"

        dest = (src_dir / raw_key).resolve()
        if not dest.is_relative_to(src_base):
            return False  # traversal after normalization

        content = src_data.get("content", "")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

    return True


# ---------------------------------------------------------------------------
# Sandbox invocation helper
# ---------------------------------------------------------------------------

def _solc_cache_root() -> Path:
    from soken_review.adapters.evm.compiler import get_cache

    return get_cache()._root


def _run_sandboxed(
    work_dir: Path, command: list[str], timeout: int = 180, workdir: str | None = None,
    image: str | None = None, extra_env: dict[str, str] | None = None,
) -> bool:
    """Run *command* in the analyze sandbox.  Returns True if completed."""
    if _DIRECT_TOOLS:
        try:
            env = {**os.environ, **extra_env} if extra_env else None
            subprocess.run(command, capture_output=True, timeout=timeout, check=False, env=env)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    image = image or _ANALYZE_IMAGE
    if not shutil.which("docker") or image is None:
        raise RuntimeError("sandbox_unavailable")

    env = {"HOME": "/tmp"}  # solc-select writes ~/.solc-select; root fs is read-only (09 4.2)
    if extra_env:
        env.update(extra_env)
    argv = docker_argv(
        step="analyze",
        image=image,
        work_dir=work_dir,
        cache_dir=_solc_cache_root(),  # Slither calls the exact solc from /cache (read-only)
        limits=_ANALYZE_LIMITS,
        env=env,
        command=command,
        runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
        workdir=workdir,
        mounts=tool_config_mounts(work_dir),
    )
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return False
    if proc.returncode != 0:
        lines = proc.stderr.decode(errors="replace").strip().splitlines()
        tail = [ln for ln in lines if "rror" in ln][:3] + lines[-2:]
        logger.warning("analyzer exit %d: %s", proc.returncode, " | ".join(tail)[:600])
    return True


# ---------------------------------------------------------------------------
# Slither
# ---------------------------------------------------------------------------

def _run_slither(
    proj_dir: Path,
    out_dir: Path,
    solc_path: str,
    settings: dict,
    entry_file: str | None,
    image: str | None = None,
) -> list[dict] | None:
    """Run Slither on the entry file with the exact solc and settings (05 8.1) inside the sandbox.

    Returns raw detector rows, or None when Slither did not produce a result: an analyzer that
    did not run is never reported as "no leads" (03 3.1 analyzer_degraded).
    """
    out_json = out_dir / "sbx" / "slither_out.json"
    src_dir = proj_dir / "src"
    work_dir = out_dir.parent
    # entry_file comes from fetched metadata (Sourcify fullyQualifiedName): validate like a source
    # key, confine it to the tree, and pass it as ./<path> so it can never parse as an option.
    if (
        not entry_file
        or entry_file.startswith("-")
        or not _safe_relative_path(entry_file)
        or Path(entry_file).suffix.lower() not in _ALLOWED_SOURCE_EXTS
    ):
        return None
    target = (src_dir / entry_file).resolve()
    if not target.is_relative_to(src_dir.resolve()) or not target.is_file():
        return None

    solc_args = []
    if settings.get("via_ir"):
        solc_args.append("--via-ir")
    if settings.get("optimizer_enabled"):
        solc_args += ["--optimize", "--optimize-runs", str(settings["optimizer_runs"])]
    if settings.get("evm_version"):
        solc_args += ["--evm-version", settings["evm_version"]]

    if _DIRECT_TOOLS:
        tool_config_mounts(work_dir)
        cwd, out_arg, solc_arg = str(src_dir), str(out_json), solc_path
        config_arg = str(host_dir(work_dir) / "tool-config" / _SLITHER_CONFIG)
    else:
        cwd = "/work/" + src_dir.relative_to(work_dir).as_posix()
        out_arg = f"{SBX_MOUNT}/{out_json.name}"
        solc_arg = "/cache/" + Path(solc_path).relative_to(_solc_cache_root()).as_posix()
        config_arg = f"{TOOL_CONFIG_MOUNT}/{_SLITHER_CONFIG}"

    # --config-file: a host-owned empty config, so no slither.config.json in the tree applies
    cmd = ["slither", "./" + entry_file, "--solc", solc_arg, "--json", out_arg, "--disable-color",
           "--compile-force-framework", "solc", "--config-file", config_arg]
    if settings.get("remappings"):
        cmd += ["--solc-remaps", " ".join(settings["remappings"])]
    if solc_args:
        cmd += ["--solc-args", " ".join(solc_args)]

    try:
        if _DIRECT_TOOLS:
            subprocess.run(cmd, capture_output=True, timeout=600, check=False, cwd=cwd)
        elif not _run_sandboxed(work_dir, cmd, timeout=600, workdir=cwd, image=image):
            return None
    except RuntimeError:
        return None  # sandbox_unavailable

    data = read_sandbox_json(out_dir / "sbx", out_json.name)
    if not isinstance(data, dict) or not data.get("success"):
        return None

    raw: list[dict] = []
    for det in data.get("results", {}).get("detectors", []):
        check = det.get("check", "")
        if check in _NOISE_DETECTORS:
            continue
        elements = det.get("elements", [])
        start, end = _detector_location(elements)
        # File from the first element that has one (the scope element names the file too).
        file_rel = ""
        for element in elements:
            file_rel = element.get("source_mapping", {}).get("filename_relative") or ""
            if file_rel:
                break
        raw.append({
            "tool": f"slither@{_SLITHER_VERSION}",
            "rule_id": check,
            "severity_raw": det.get("impact", ""),
            "file": file_rel,
            "start": start,
            "end": end,
        })
    return raw


# ---------------------------------------------------------------------------
# Aderyn
# ---------------------------------------------------------------------------

def _aderyn_offline_sandbox(
    container_src: str, container_out: str, version: str, solc_path: str, remaps: list[str]
) -> tuple[list[str], dict[str, str]]:
    """Command + env that make Aderyn compile offline inside the analyze container.

    Pin FOUNDRY_SOLC_VERSION to the exact build solc so Aderyn/svm-rs skip the online release-list
    lookup, and copy that cached solc (already mounted read-only at /cache) to where svm-rs reads an
    installed release (XDG data dir -> `<data>/svm/<version>/solc-<version>`); svm then finds it
    installed and never reaches the network. The store and a copy of the materialized repo root must
    live in the writable, EXECUTABLE sbx bind mount: /tmp is mounted noexec (svm could not exec the
    solc there) and /work is read-only (foundry-compilers writes build artifacts next to the sources).
    Aderyn's root is the repo root (`container_src`, which holds `src/` and `lib/`), so it auto-detects
    `src`, auto-excludes `lib`, and emits `src/<file>` lead paths matching Slither's filename_relative;
    a remappings.txt written at the root (the same remappings Slither gets) resolves dependency imports.
    All variable data flows through the environment, so the script text is fixed."""
    # svm-rs keys its store by the bare semver and FOUNDRY_SOLC_VERSION must parse as one, so drop the
    # `+commit.<hash>` build metadata the cache carries (e.g. 0.8.37+commit.f401782d -> 0.8.37).
    short = version.split("+", 1)[0]
    rel = Path(solc_path).relative_to(_solc_cache_root()).as_posix()
    scratch = f"{SBX_MOUNT}/aderyn"
    xdg = f"{scratch}/xdg"
    env = {
        "HOME": "/tmp",
        "XDG_DATA_HOME": xdg,
        "FOUNDRY_SOLC_VERSION": short,
        "ADERYN_SOLC_SRC": f"/cache/{rel}",
        "ADERYN_SOLC_DST": f"{xdg}/svm/{short}/solc-{short}",
        "ADERYN_SRC_RO": container_src,
        "ADERYN_ROOT": f"{scratch}/repo",
        "ADERYN_REMAPS": "\n".join(remaps),
        "ADERYN_OUT": container_out,
    }
    script = (
        'mkdir -p "$(dirname "$ADERYN_SOLC_DST")" "$ADERYN_ROOT" '
        '&& cp "$ADERYN_SOLC_SRC" "$ADERYN_SOLC_DST" && chmod 0755 "$ADERYN_SOLC_DST" '
        '&& cp -R "$ADERYN_SRC_RO/." "$ADERYN_ROOT/" '
        '&& if [ -n "$ADERYN_REMAPS" ]; then printf "%s\\n" "$ADERYN_REMAPS" > "$ADERYN_ROOT/remappings.txt"; fi '
        '&& cd "$ADERYN_ROOT" && exec aderyn "$ADERYN_ROOT" -o "$ADERYN_OUT"'
    )
    return ["sh", "-c", script], env


def _aderyn_offline_direct(out_dir: Path, version: str, solc_path: str) -> dict[str, str]:
    """Seed a private svm store with the cached solc and pin the version, for _DIRECT_TOOLS runs.

    Mirrors the sandbox path without a container: svm-rs reads an installed release from the OS data
    dir (`dirs::data_dir()`), so seed the platform-correct subpath under a throwaway HOME and point
    HOME/XDG_DATA_HOME at it. Keeps Aderyn hermetic and offline on the dev host too."""
    import sys

    short = version.split("+", 1)[0]  # svm keys by bare semver; drop `+commit.<hash>` (see sandbox helper)
    store = (out_dir / "sbx" / "svm-home").resolve()
    sub = "Library/Application Support/svm" if sys.platform == "darwin" else ".local/share/svm"
    bindir = store / sub / short
    bindir.mkdir(parents=True, exist_ok=True)
    dst = bindir / f"solc-{short}"
    shutil.copy2(solc_path, dst)
    dst.chmod(0o755)
    return {"HOME": str(store), "XDG_DATA_HOME": str(store / ".local" / "share"),
            "FOUNDRY_SOLC_VERSION": short}


def _run_aderyn(
    proj_dir: Path, out_dir: Path, solc_version: str | None = None, solc_path: str | None = None,
    remappings: list[str] | None = None,
) -> list[dict] | None:
    """Run Aderyn (optional).  Returns raw list or None when absent/failed.

    Aderyn (0.6.8, via foundry-compilers/svm-rs) resolves solc online by default and downloads it;
    the no-network analyze sandbox blocks both, so it fails on every contract (Slither, primary,
    still carries the full lead set). When the exact build solc is known we run it offline via the
    seed+pin recipe in `_aderyn_offline_sandbox`/`_aderyn_offline_direct`; otherwise unchanged. Aderyn
    runs with the materialized repo root (`src_dir`, which holds `src/` and `lib/`) as its root, so its
    lead paths are `src/<file>` like Slither's; the build remappings are written as remappings.txt so
    dependency imports resolve."""
    out_json = out_dir / "sbx" / "aderyn_out.json"
    src_dir = proj_dir / "src"  # the materialized repo root (contains src/ and lib/)
    work_dir = out_dir.parent

    rel_src = src_dir.relative_to(work_dir)
    rel_out = out_json.relative_to(work_dir)
    container_src = "/work/" + "/".join(rel_src.parts)
    container_out = "/work/" + "/".join(rel_out.parts)
    remaps = remappings or []

    have_solc = bool(solc_version and solc_path)
    if _DIRECT_TOOLS:
        aderyn_bin = shutil.which("aderyn")
        if not aderyn_bin:
            return None
        if remaps:
            (src_dir / "remappings.txt").write_text("\n".join(remaps) + "\n", encoding="utf-8")
        cmd = [aderyn_bin, str(src_dir), "-o", str(out_json)]
        extra_env = _aderyn_offline_direct(out_dir, solc_version, solc_path) if have_solc else None
    elif have_solc:
        cmd, extra_env = _aderyn_offline_sandbox(container_src, container_out, solc_version, solc_path, remaps)
    else:
        cmd, extra_env = ["aderyn", container_src, "-o", container_out], None

    try:
        ok = _run_sandboxed(work_dir, cmd, extra_env=extra_env)
    except RuntimeError:
        return None

    if not ok:
        return None
    data = read_sandbox_json(out_dir / "sbx", out_json.name)
    if not isinstance(data, dict):
        return None

    raw: list[dict] = []

    def _parse_issues(issues: list[dict], default_sev: str) -> None:
        for issue in issues:
            detector_name = issue.get("detector_name") or issue.get("name") or ""
            for inst in issue.get("instances", [issue]):
                file_path = inst.get("contract_path") or inst.get("file") or ""
                line = inst.get("line") or 1
                raw.append({
                    "tool": f"aderyn@{_ADERYN_VERSION}",
                    "rule_id": detector_name,
                    "severity_raw": default_sev,
                    "file": file_path,
                    "start": int(line),
                    "end": int(line),
                })

    _parse_issues(data.get("high_issues", {}).get("issues", []), "High")
    _parse_issues(data.get("low_issues", {}).get("issues", []), "Low")
    return raw


# ---------------------------------------------------------------------------
# Lead normalization, merging, validation (04 E7)
# ---------------------------------------------------------------------------

def _normalize_severity(tool_name: str, raw: str) -> str:
    base_tool = tool_name.split("@")[0]
    tool_map = _SEVERITY_MAP.get("analyzers", {}).get(base_tool, {})
    return tool_map.get(raw) or _SEVERITY_MAP.get("default", "High")


def _category_for(tool_name: str, rule_id: str) -> str:
    base_tool = tool_name.split("@")[0]
    return _RULE_MAP.get(base_tool, {}).get(rule_id, "evm.other")


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
        # a producer that owns its category (compiler advisories: evm.compiler_bug) sets it
        cat = item.get("category") or _category_for(item["tool"], item["rule_id"])
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
                leads.append(lead)
                lead_idx += 1
            except jsonschema.ValidationError:
                pass

    return leads


# ---------------------------------------------------------------------------
# Static map (minimal, from Slither IR)
# ---------------------------------------------------------------------------

def _build_static_map(out_dir: Path, aderyn_available: bool = False) -> dict[str, Any]:
    data = read_sandbox_json(out_dir / "sbx", "slither_out.json")
    if not isinstance(data, dict):
        return {"status": "not_run"}

    seen: dict[str, set[str]] = {}
    for det in data.get("results", {}).get("detectors", []):
        for el in det.get("elements", []):
            if el.get("type") == "function":
                parent = (el.get("type_specific_fields") or {}).get("parent") or {}
                contract = parent.get("name", "")
                fname = el.get("name", "")
                if contract and fname:
                    seen.setdefault(contract, set()).add(fname)

    return {
        "status": "ok",
        "contracts": [{"contract": c, "functions": sorted(fns)} for c, fns in seen.items()],
        "tool": f"slither@{_SLITHER_VERSION}",
        "aderyn": f"@{_ADERYN_VERSION}" if aderyn_available else "not_run",
    }
