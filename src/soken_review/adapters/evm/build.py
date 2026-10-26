"""EVM build step: solc --standard-json inside the sandbox (05 sections 7, 13.2; 09 4.1).

build(candidate) -> BuildResult

Security rules (09 4.1, reviewer note 2026-10-09):
  - Every solc invocation runs inside docker via docker_argv(step="build", ...)
  - Fail closed when docker is unavailable: status='failed', reason='sandbox_unavailable'
  - Host execution only behind SOKEN_SOLC_DIRECT=1 (dev only, never default)
  - std-json input sanitized before reaching solc:
      - `urls` keys dropped from sources (solc must not read by path/URL)
      - source keys, remappings and settings.libraries must be relative, no `..`, no `\\`
      - settings keys `--allow-paths`, `--base-path` rejected
  - Auxdata second compile (_add_trailing_newlines) also sandboxed via same binary path

Compiler rules (05 6.1, 09 4.4):
  B2  explorer/user std_json candidate: solc --standard-json
  B3  synthetic project fallback when no std_json
  B4  forge --offline --build-info (repo candidates): forge resolves remappings/sources,
      returns only the Standard JSON `input`; our sandboxed solc recompiles it.
      Settings from forge's build-info are rebuilt from an allow-list (finding 1);
      build-info is read via sandbox.output.read_output_files (finding 2);
      sources verified by sha256 exact-bytes comparison (finding 3);
      forge runs in a named container; docker rm -f kills it on timeout (finding 4).
  X1  Sourcify cborAuxdata -> auxdata_ranges
  X2  recompile with trailing newlines to find differing ranges
  X3  appendCBOR=false or solc < 0.4.7 -> no auxdata ranges
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, NamedTuple

from soken_review.adapters.base import Artifact, BuildResult, Candidate
from soken_review.adapters.evm.compiler import CompilerCacheError, SolcCache, get_cache
from soken_review.sandbox.output import UnsafeOutput, read_output_files
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

# Repo-relative .sbx dir (colima only shares $HOME)
_REPO_ROOT = Path(__file__).resolve().parents[4]
_SBX_ROOT = _REPO_ROOT / ".sbx"
_LIMITS_YAML = _REPO_ROOT / "contract" / "ops" / "limits.yaml"

_BUILD_LIMITS = StepLimits(cpus=2, memory="4g", pids=256, max_file=256 * 1024 * 1024)

# Image for build sandbox. In production comes from images.lock.json.
_BUILD_IMAGE = locked_image("evm-analyze")  # digest-pinned (09 4.4); None = fail closed

# SOKEN_SOLC_DIRECT=1: dev-only bypass, never set in production or tests
_DIRECT_SOLC = os.environ.get("SOKEN_SOLC_DIRECT", "0") == "1"

# Minimum solc version that supports appendCBOR output (X3)
_MIN_CBOR_VERSION = (0, 4, 7)

# ---------------------------------------------------------------------------
# B4 forge settings allowlist (finding 1: attacker-controlled compile settings)
# Only these keys are accepted from forge's build-info `input.settings`.
# Any unknown key → had_unknown_settings=True → untrusted_inputs on the candidate.
# ---------------------------------------------------------------------------

# Valid EVM version names solc accepts (canonical lower-case; solc is case-sensitive).
_VALID_EVM_VERSIONS: frozenset[str] = frozenset({
    "homestead", "tangerineWhistle", "spuriousDragon", "byzantium", "constantinople",
    "petersburg", "istanbul", "berlin", "london", "paris", "shanghai", "cancun",
    "prague", "osaka",
})

# Valid metadata.bytecodeHash values.
_VALID_BYTECODE_HASH: frozenset[str] = frozenset({"ipfs", "bzzr1", "none"})

# Optimizer.runs must be a positive int in [1, 2**32-1]; runs=0 is a valid solc value too.
_OPT_RUNS_MAX: int = 2**32 - 1

# forge build-info max size (single file)
_FORGE_BUILD_INFO_MAX_BYTES: int = 50 * 1024 * 1024   # 50 MiB


_FORGE_STDERR_HEAD_CHARS = 1500   # forge stderr kept in build_notes when B4 fails (diagnostic only)


def _printable_head(data: bytes, limit: int = _FORGE_STDERR_HEAD_CHARS) -> str:
    """Capped, printable text from a sandbox tool's stderr: ANSI escapes and control bytes dropped.
    The text is repo-influenced and diagnostic only; it is never fed to detection."""
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", data.decode("utf-8", errors="replace"))
    text = "".join(ch for ch in text if ch == "\n" or ch.isprintable())
    return text.strip()[:limit]


def _forge_build_timeout() -> int:
    """Read build.evm.timeout_s from contract/ops/limits.yaml; default 300.

    Loading is lazy and cached on first call. Falls back to 300 on any error so a
    missing or malformed config never blocks the build path.
    """
    try:
        import yaml
        data = yaml.safe_load(_LIMITS_YAML.read_text())
        t = data.get("build", {}).get("evm", {}).get("timeout_s", 300)
        return int(t) if isinstance(t, (int, float)) and t > 0 else 300
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return 300


class ForgeStdInput(NamedTuple):
    """B4 forge build result: sanitized Standard JSON input plus trust flags."""
    std_input: dict       # settings rebuilt from allow-list; our outputSelection replaces forge's
    libraries_unverified: bool  # forge's settings had a 'libraries' key → tier B ceiling
    had_unknown_settings: bool  # settings had unknown/forbidden keys → tier B ceiling
    forge_version_mismatch: bool = False  # build-info version mismatches pinned compiler


# ---------------------------------------------------------------------------
# Input sanitizer
# ---------------------------------------------------------------------------

# Solc Standard JSON spec only accepts these three top-level keys.
# Forge may inject allowPaths, basePath, etc. at the input top-level — strip them.
_SOLC_STD_JSON_KEYS = frozenset({"language", "sources", "settings"})

# Forge-specific top-level keys that are filesystem hints: they become irrelevant once
# sources are inline in the Standard JSON.  Drop silently without flagging
# had_unknown_settings — they carry no compilation-affecting information.
# Any other extra top-level key (not in _SOLC_STD_JSON_KEYS and not here) still flags.
# NOTE: "version" is NOT here — it is handled separately in forge_build_repo by
# comparing it to the pinned compiler (see _check_forge_version).
_FORGE_TOP_SILENT_DROP = frozenset({
    "allowPaths",   # filesystem search paths; sources are inline
    "basePath",     # project root on the build host; irrelevant in std-json
    "includePaths", # additional include directories; irrelevant once inline
})

# Regex for parsing a semver triple and optional commit hash from a solc version string.
# Matches "0.8.26+commit.8a97fa7e.Linux.g++" or "solc-0.8.26+commit.8a97fa7e".
_FORGE_VERSION_RE = re.compile(r'(\d+\.\d+\.\d+)(?:\+commit\.([0-9a-f]+))?')

_BAD_PATH_RE = re.compile(r"(^/|\\|\.\.(/|$))")

# Remapping character allowlist: letters, digits, @_./:- only; no spaces, shell chars.
# Pattern: [optional-context:]<prefix>=<target>
# Both prefix and target: ^[A-Za-z0-9@_./-]{0,200}$, no leading '-'.
_REMAP_SAFE_RE = re.compile(r"^[A-Za-z0-9@_./ -]{0,200}$")
_REMAP_FULL_RE = re.compile(r"^(?:[A-Za-z0-9@_./-]*:)?([A-Za-z0-9@_./-]*)=([A-Za-z0-9@_./-]{0,200})$")


def _safe_relative_path(value: str) -> bool:
    """Return True if value is a safe relative path (no absolute, no .., no backslash)."""
    if not value:
        return False
    return not _BAD_PATH_RE.search(value)


def sanitize_remapping(remap: str) -> str | None:
    """Validate and return a single remapping string, or None if it should be dropped.

    Valid form: ``[context:]prefix=target`` where prefix and target contain only
    ``[A-Za-z0-9@_./-]`` characters, neither side starts with ``-``, and the
    target passes _safe_relative_path.

    A dropped entry is silently omitted (not an error); the caller may log it.
    """
    if not isinstance(remap, str):
        return None
    m = _REMAP_FULL_RE.match(remap)
    if not m:
        return None  # bad format
    prefix, target = m.group(1), m.group(2)
    # Leading dash on either side could smuggle CLI options
    if prefix.startswith("-") or target.startswith("-"):
        return None
    # Target must be a safe relative path or empty (empty prefix means global)
    if target and not _safe_relative_path(target):
        return None
    return remap


_SOURCE_KEYS = {"content", "keccak256"}


class InputSanitizationError(ValueError):
    """Raised when std-json input fails the path/key safety checks."""


def sanitize_std_input(inp: dict) -> dict:
    """Return a sanitized copy of a solc standard-json input dict.

    Actions taken:
      - Drop ``urls`` from every source entry (09 4.1: solc must not read
        by filesystem path or URL from inside the sandbox).
      - Reject source file keys that are absolute, contain ``..`` or ``\\``.
      - Reject ``settings.remappings`` entries whose target side contains
        absolute paths, ``..`` or ``\\``.
      - Reject ``settings.libraries`` keys that are absolute / unsafe.
      - Reject any top-level settings key named ``--allow-paths`` or
        ``--base-path`` (the JSON form of CLI flags).
    """
    import copy
    out = copy.deepcopy(inp)

    # Only Solidity text is compiled: with SolidityAST or EVMAssembly solc ignores `content`
    # and compiles `ast` / `assemblyJson`, which is not the text that is pinned and reviewed.
    if out.get("language", "Solidity") != "Solidity":
        raise InputSanitizationError(f"unsupported language: {out.get('language')!r}")

    # Sanitize sources
    sources = out.get("sources", {})
    for key in list(sources.keys()):
        if not _safe_relative_path(key):
            raise InputSanitizationError(f"unsafe source key: {key!r}")
        src = sources[key]
        if isinstance(src, dict):
            src.pop("urls", None)  # drop filesystem/IPFS URL references
            extra = set(src) - _SOURCE_KEYS
            if extra or not isinstance(src.get("content"), str):
                raise InputSanitizationError(f"source {key!r}: only content allowed, got {sorted(src)}")
        else:
            raise InputSanitizationError(f"source {key!r} is not an object")

    # Sanitize settings
    settings = out.get("settings", {})
    for forbidden in ("--allow-paths", "--base-path"):
        if forbidden in settings:
            raise InputSanitizationError(f"forbidden settings key: {forbidden!r}")

    # Sanitize remappings: drop invalid entries (don't reject the whole input)
    clean_remaps: list[str] = []
    for remap in settings.get("remappings", []):
        safe = sanitize_remapping(remap)
        if safe is not None:
            clean_remaps.append(safe)
    settings["remappings"] = clean_remaps

    # Libraries stay unlinked: solc would embed `settings.libraries` addresses with no
    # linkReferences, hiding code outside the reviewed source from 13.1. Unlinked, they show up
    # as link references and the provenance decision lists them (the candidate keeps the
    # original entries for checks[]).
    for lib_file in list((settings.get("libraries") or {}).keys()):
        if lib_file and not _safe_relative_path(lib_file):
            raise InputSanitizationError(f"unsafe library path: {lib_file!r}")
    settings.pop("libraries", None)

    return out


# ---------------------------------------------------------------------------
# B4 forge settings allowlist (finding 1)
# ---------------------------------------------------------------------------


def _sanitize_forge_settings(raw_settings: dict) -> tuple[dict, bool, bool]:
    """Rebuild settings from forge's build-info using an allow-list.

    Returns (clean_settings, libraries_unverified, had_unknown_settings).

    Only the following keys are accepted:
      optimizer.enabled (bool), optimizer.runs (int, 0..2^32-1),
      optimizer.details.yul (bool, the only plan-05-recorded detail),
      evmVersion (enum: _VALID_EVM_VERSIONS),
      viaIR (bool),
      metadata.bytecodeHash (enum: _VALID_BYTECODE_HASH),
      metadata.appendCBOR (bool),
      remappings (list[str], each sanitized by sanitize_remapping).

    'libraries' → libraries_unverified=True, dropped from clean_settings (05 rule).
    'outputSelection' → always dropped (our _OUTPUT_SELECTION replaces it).
    Any other key → had_unknown_settings=True, dropped.

    The returned clean_settings does NOT include outputSelection; callers must add it.
    """
    import copy
    clean: dict[str, Any] = {}
    libraries_unverified = False
    had_unknown = False

    for key, val in raw_settings.items():
        if key == "outputSelection":
            continue  # always replaced by caller
        if key == "libraries":
            if val:
                libraries_unverified = True
            continue  # dropped from clean settings
        if key == "optimizer":
            opt = val
            if isinstance(opt, dict):
                clean_opt: dict[str, Any] = {}
                if isinstance(opt.get("enabled"), bool):
                    clean_opt["enabled"] = opt["enabled"]
                runs = opt.get("runs")
                if isinstance(runs, int) and 0 <= runs <= _OPT_RUNS_MAX:
                    clean_opt["runs"] = runs
                elif runs is not None:
                    had_unknown = True  # invalid runs value
                # optimizer.details: only yul (bool) is recorded by plan 05
                details = opt.get("details")
                if isinstance(details, dict):
                    clean_details: dict[str, Any] = {}
                    if isinstance(details.get("yul"), bool):
                        clean_details["yul"] = details["yul"]
                    if len(details) > (1 if "yul" in details else 0):
                        had_unknown = True  # unknown detail keys
                    if clean_details:
                        clean_opt["details"] = clean_details
                elif details is not None:
                    had_unknown = True
                if clean_opt:
                    clean["optimizer"] = clean_opt
            else:
                had_unknown = True
        elif key == "evmVersion":
            if isinstance(val, str) and val in _VALID_EVM_VERSIONS:
                clean["evmVersion"] = val
            else:
                had_unknown = True
        elif key == "viaIR":
            if isinstance(val, bool):
                clean["viaIR"] = val
            else:
                had_unknown = True
        elif key == "metadata":
            meta = val
            if isinstance(meta, dict):
                clean_meta: dict[str, Any] = {}
                bch = meta.get("bytecodeHash")
                if bch is not None:
                    if isinstance(bch, str) and bch in _VALID_BYTECODE_HASH:
                        clean_meta["bytecodeHash"] = bch
                    else:
                        had_unknown = True
                acbor = meta.get("appendCBOR")
                if acbor is not None:
                    if isinstance(acbor, bool):
                        clean_meta["appendCBOR"] = acbor
                    else:
                        had_unknown = True
                # useLiteralContent: bool only; affects the CBOR metadata hash so must be
                # kept exactly as forge emits it.
                ulc = meta.get("useLiteralContent")
                if ulc is not None:
                    if isinstance(ulc, bool):
                        clean_meta["useLiteralContent"] = ulc
                    else:
                        had_unknown = True
                for mk in meta:
                    if mk not in ("bytecodeHash", "appendCBOR", "useLiteralContent"):
                        had_unknown = True
                if clean_meta:
                    clean["metadata"] = clean_meta
            else:
                had_unknown = True
        elif key == "remappings":
            raw_remaps = val
            if isinstance(raw_remaps, list):
                safe_remaps = []
                for r in raw_remaps:
                    validated = sanitize_remapping(r)
                    if validated is not None:
                        safe_remaps.append(validated)
                    else:
                        had_unknown = True  # unsafe remapping dropped
                if safe_remaps:
                    clean["remappings"] = safe_remaps
            else:
                had_unknown = True
        else:
            # Unknown key (stopAfter, modelChecker, debug, compilationTarget, etc.)
            had_unknown = True

    # Make a fresh copy to avoid mutating the input
    return copy.deepcopy(clean), libraries_unverified, had_unknown


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build(candidate: Candidate, cache_dir: Path | None = None, work_dir: Path | None = None) -> BuildResult:
    """Compile *candidate* and return a BuildResult.

    All solc invocations run inside the sandbox (docker_argv step='build').
    Fail closed when docker is unavailable unless SOKEN_SOLC_DIRECT=1.
    """
    if (candidate.language or "").lower() == "vyper":  # 05 15: Vyper plug-in, same step contract
        from soken_review.adapters.vyper.build import build as vyper_build

        return vyper_build(candidate, cache_dir=cache_dir, work_dir=work_dir)

    version = candidate.compiler.version if candidate.compiler else None
    if not version:
        return _fail(candidate, "not_checkable", "compiler_version_unknown")

    cache = get_cache(cache_dir)
    try:
        solc_bin = cache.binary(version)
    except CompilerCacheError as exc:
        return _fail(candidate, "not_checkable", exc.reason_detail)

    _SBX_ROOT.mkdir(exist_ok=True)

    # B4: for repo candidates, try forge to resolve sources+remappings into a Standard JSON
    # input; then compile that input with OUR sandboxed solc (same as B2/B3).
    # Forge's compiled output is discarded; only the `input` key from build-info is used.
    # Security: source tree is read-only; forge uses our pinned solc via --use flag;
    # settings rebuilt from allow-list (finding 1); sources verified by sha256 (finding 3);
    # named container killed on timeout (finding 4).
    b4_notes: dict = {}
    if candidate.src_tree_dir:
        _wdir = Path(work_dir) if work_dir is not None else Path(tempfile.mkdtemp(dir=_SBX_ROOT))
        forge_diag: dict = {}
        forge_result, forge_fail_reason = forge_build_repo(candidate.src_tree_dir, _wdir, solc_bin, cache,
                                                           diag=forge_diag,
                                                           extra_remappings=_npm_remappings(candidate))
        if forge_result is not None:
            gate_diag: dict = {}
            match_ok, reject_reason = _forge_sources_match_pin(
                forge_result.std_input, candidate.files,
                getattr(candidate, "_full_tree", None), diag=gate_diag,
            )
            if match_ok:
                try:
                    sanitized_b4_input = sanitize_std_input(forge_result.std_input)
                except InputSanitizationError:
                    b4_notes["b4_rejected"] = "sanitize_error"
                else:
                    # Apply trust flags from forge settings before building
                    if forge_result.libraries_unverified or forge_result.had_unknown_settings:
                        candidate.untrusted_inputs = True
                    b4_notes["b4_source"] = "forge_b4"
                    if forge_result.libraries_unverified:
                        b4_notes["libraries_unverified"] = True
                    if forge_result.had_unknown_settings:
                        b4_notes["had_unknown_settings"] = True
                    if forge_result.forge_version_mismatch:
                        b4_notes["forge_version_mismatch"] = True
                    br = _run_build(candidate, sanitized_b4_input, solc_bin, _wdir, cache)
                    br.build_notes.update(b4_notes)
                    return br
            else:
                b4_notes["b4_rejected"] = reject_reason
                b4_notes.update(gate_diag)          # which source and why (diagnostic only)
                # sources differ → mark untrusted (finding 3)
                candidate.untrusted_inputs = True
        elif forge_fail_reason:
            # forge_build_repo returned None: record why (and forge's rc / stderr head when it ran)
            # so the fallback to B3 is visible in build_result.json.
            b4_notes["b4_rejected"] = forge_fail_reason
            b4_notes.update(forge_diag)

    # Build and sanitize std-json input (B2/B3 path)
    try:
        std_input = sanitize_std_input(_prepare_std_input(candidate))
    except InputSanitizationError as exc:
        return _fail(candidate, "not_checkable", f"input_sanitization_error: {exc}")

    if work_dir is not None:
        br = _run_build(candidate, std_input, solc_bin, Path(work_dir), cache)
        if b4_notes:
            br.build_notes.update(b4_notes)
        return br

    with tempfile.TemporaryDirectory(dir=_SBX_ROOT) as tmp:
        br = _run_build(candidate, std_input, solc_bin, Path(tmp), cache)
        if b4_notes:
            br.build_notes.update(b4_notes)
        return br


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# 13.1 needs these outputs whatever the candidate's own outputSelection says; outputSelection
# does not change the emitted bytecode.
_OUTPUT_SELECTION = {
    "*": {
        "*": [
            "evm.bytecode", "evm.deployedBytecode",
            "evm.deployedBytecode.immutableReferences",
            "evm.bytecode.linkReferences",
            "evm.deployedBytecode.linkReferences",
            "evm.deployedBytecode.sourceMap",
            "storageLayout",
            "metadata",
        ],
        "": ["ast"],
    }
}


def _prepare_std_input(candidate: Candidate) -> dict:
    if candidate.std_json_input:
        out = dict(candidate.std_json_input)
        out["settings"] = {**(out.get("settings") or {}), "outputSelection": _OUTPUT_SELECTION}
        return out
    sources: dict[str, Any] = {}
    for path, content in candidate.files.items():
        sources[path] = {"content": content}
    settings: dict[str, Any] = dict(candidate.settings) if candidate.settings else {}
    # Repo candidates: the files the scope imports (lib/, node_modules/, shared local files) are
    # in the pinned tree but not in the scope pin; add exactly the import closure, resolved the
    # way solc resolves it (remappings, then the path as written), so B3 can compile a repo whose
    # sources import dependencies when forge (B4) is unavailable or rejected.
    full_tree = getattr(candidate, "_full_tree", None)
    if candidate.provider == "repo" and full_tree:
        from soken_review.adapters.evm.npm_deps import import_closure

        visited, _missing = import_closure(candidate.files, full_tree, list(settings.get("remappings") or []),
                                           node_modules=False)
        for path in sorted(visited - set(sources)):
            sources[path] = {"content": full_tree[path]}
    settings["outputSelection"] = _OUTPUT_SELECTION
    return {"language": "Solidity", "sources": sources, "settings": settings}


def _npm_remappings(candidate: Candidate) -> list[str]:
    """Remappings into vendored node_modules/ (npm_deps), passed to forge explicitly: forge maps
    node_modules by itself only when the repo has no lib/ dir."""
    out: list[str] = []
    for remap in (candidate.settings or {}).get("remappings") or []:
        safe = sanitize_remapping(remap)
        if safe is not None and safe.partition("=")[2].startswith("node_modules/"):
            out.append(safe)
    return out


def _invoke_solc(solc_bin: Path, stdin_data: bytes, work_dir: Path, cache: SolcCache) -> tuple[bytes, str]:
    """Invoke solc inside the sandbox. Returns (stdout, stderr_head).

    Falls back to direct invocation only when SOKEN_SOLC_DIRECT=1.
    Raises RuntimeError('sandbox_unavailable') when docker is absent and
    direct mode is not enabled.
    """
    if _DIRECT_SOLC:
        proc = subprocess.run(
            [str(solc_bin), "--standard-json"],
            input=stdin_data,
            capture_output=True,
            timeout=300,
            check=False,
        )
        stderr = proc.stderr.decode(errors="replace")
        return proc.stdout, "\n".join(stderr.splitlines()[:20])

    # Sandbox path
    import shutil
    if not shutil.which("docker"):
        raise RuntimeError("sandbox_unavailable")

    src_dir = work_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    # Write stdin to a file inside work/src so it's accessible read-only inside sandbox
    input_file = src_dir / "input.json"
    input_file.write_bytes(stdin_data)
    input_file.chmod(0o444)

    # The cache is mounted at /cache inside the container (read-only)
    # solc binary inside the container is at /cache/<platform>/solc-<version>
    # We use the version from the binary path's filename
    solc_filename = solc_bin.name  # e.g. solc-0.8.24+commit.e11b9ed9
    platform_name = solc_bin.parent.name  # e.g. linux-amd64

    if _BUILD_IMAGE is None:
        raise RuntimeError("sandbox_unavailable")
    argv = docker_argv(
        step="build",
        image=_BUILD_IMAGE,
        work_dir=work_dir,
        cache_dir=cache._root,
        limits=_BUILD_LIMITS,
        env={},
        # Input on stdin: solc before 0.6 reads --standard-json only from stdin.
        command=[f"/cache/{platform_name}/{solc_filename}", "--standard-json"],
        runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
        stdin=True,
    )

    try:
        proc = subprocess.run(argv, input=stdin_data, capture_output=True, timeout=300, check=False)
        stderr = proc.stderr.decode(errors="replace")
        return proc.stdout, "\n".join(stderr.splitlines()[:20])
    except subprocess.TimeoutExpired:
        raise RuntimeError("sandbox_unavailable")



# Well-known Foundry project-root directories.  A multi-segment missing-source path
# whose first segment is in this set is classified as a project-relative dependency
# (missing gitlink submodule, un-fetched lib, etc.).  Anything else is treated as an
# npm/bare package name — npm packages can appear as "pkg/file.sol" (2-segment) but
# their first segment does NOT match a typical project directory.
_PROJECT_ROOT_DIRS = frozenset({
    "lib", "src", "test", "tests", "script", "scripts",
    "contracts", "interfaces", "dependencies", "node_modules",
})


def _missing_import_reason(fatal_errors: list[dict]) -> str | None:
    """Classify solc 'Source ... not found' build failures (05 B4, 09 5.2).

    When solc cannot resolve an import it emits either:
      ParserError  — message: 'Source "@pkg/..." not found: File not found.'
      IOError      — message: '@pkg/...: File not found.' (Standard JSON mode)

    Classification (returned as prefix:value):
      missing_import:{pkg,...}           — npm-style: @scope/pkg, bare single-segment name,
                                           OR multi-segment where the first segment is NOT a
                                           known project directory (e.g. "ds-test/test.sol").
      missing_dependency_path:{first,..} — project-relative multi-segment path whose first
                                           segment IS a known Foundry directory (lib/, test/,
                                           src/, script/, …); a gitlink submodule that was NOT
                                           fetched, or a scope file that imports a lib/ dep not
                                           in the Standard JSON sources (B3 gap).

    Both prefixes must trigger `insufficient_source` at the supervisor; neither is silently
    swallowed.  Returns None when there are no not-found errors.

    Note: does NOT parse Solidity source code — only the structured solc JSON output.
    """
    npm_pkgs: set[str] = set()
    dep_paths: set[str] = set()

    for err in fatal_errors:
        if err.get("severity") not in ("error", "fatal", None, ""):
            continue
        msg = err.get("message", "")
        # 'Source "@pkg/Foo.sol" not found' or '"@pkg/Foo.sol" not found'
        # Also handles bare 'pkg/Foo.sol: File not found.' (IOError form)
        for candidate_path in _extract_not_found_paths(msg):
            if candidate_path.startswith(("./", "../", "/")):
                continue
            parts = candidate_path.split("/")
            first = parts[0] if parts else ""
            if not first:
                continue
            if candidate_path.startswith("@") and len(parts) >= 2:
                # @scope/pkg — npm scoped package
                npm_pkgs.add(parts[0] + "/" + parts[1])
            elif len(parts) == 1:
                # bare single-segment name (e.g. "ds-test") — npm or bare gitlink alias
                npm_pkgs.add(first)
            elif first in _PROJECT_ROOT_DIRS:
                # multi-segment path starting with a known Foundry project dir (lib/xxx,
                # test/utils/...) — project-relative dep, likely a missing gitlink submodule.
                dep_paths.add(first)
            else:
                # multi-segment but first segment is NOT a project dir — treat as npm package
                # (e.g. "ds-test/test.sol" where ds-test is an npm/gitlink alias).
                npm_pkgs.add(first)

    # npm packages take precedence when mixed; dep paths are separate signal.
    if npm_pkgs:
        return "missing_import:" + ",".join(sorted(npm_pkgs)[:5])
    if dep_paths:
        return "missing_dependency_path:" + ",".join(sorted(dep_paths)[:5])
    return None


def _extract_not_found_paths(message: str) -> list[str]:
    """Extract import paths from a solc 'not found' error message."""
    paths: list[str] = []
    # Pattern: Source "path" not found
    start = 0
    while True:
        idx = message.find('"', start)
        if idx == -1:
            break
        end = message.find('"', idx + 1)
        if end == -1:
            break
        fragment = message[idx + 1:end]
        if "not found" in message[end:end + 30]:
            paths.append(fragment)
        start = end + 1
    # Pattern: "path: File not found." (IOError — no surrounding quotes for path)
    if not paths and ": File not found" in message:
        path_part = message.split(": File not found")[0].strip()
        if path_part:
            paths.append(path_part)
    return paths


def _forge_sources_match_pin(
    forge_input: dict,
    pinned_files: dict[str, str],
    full_tree: dict[str, str] | None,
    diag: dict | None = None,
) -> tuple[bool, str]:
    """Verify ALL forge sources are in the pinned full tree and match byte-for-byte.

    Returns (True, "") on success, or (False, reason_code) on mismatch.

    Rules (finding 3 + integrity gap fix):
    - full_tree is the complete O_NOFOLLOW read of the repo (safe_files from
      repo_candidate_from_manifest) — all files, including lib/ deps, not just scope.
    - Every entry in forge_input["sources"] must:
        (a) have a "content" key (not "urls" — symlink or network fetch attempt);
        (b) exist in full_tree by exact path;
        (c) match full_tree[path] by exact sha256 of UTF-8-encoded bytes.
      Any violation → (False, "sources_differ").
    - If full_tree is None (non-repo candidate, or tree read was unavailable) →
      (False, "sources_differ") — fail closed.
    - Forward check: every pinned scope file must appear in forge's sources.
    - Comparison uses sha256 of UTF-8 encoded bytes; no LF-normalisation (parser
      differentials can exploit normalisation to produce a different AST).
    - On success the caller records b4_source="forge_b4" in build_notes.
    """
    # Fail closed when the full tree is not available (non-repo candidate or
    # a path that our O_NOFOLLOW reader refused).
    def reject(kind: str, path: str = "") -> tuple[bool, str]:
        # `diag` gets "<kind>:<path>" for the first violation (missing_in_tree, content_differs,
        # not_inline_content, scope_file_absent, no_tree); the reason code stays the single
        # "sources_differ" the trust logic keys on.
        if diag is not None:
            diag["b4_detail"] = f"{kind}:{path}" if path else kind
        return False, "sources_differ"

    if full_tree is None:
        return reject("no_tree")

    sources = (forge_input.get("sources") or {})

    # Check EVERY entry forge provides — lib/ deps included — against the pinned tree.
    for path, src_entry in sources.items():
        if not isinstance(src_entry, dict):
            return reject("not_inline_content", path)
        # Reject entries that use "urls" instead of inline "content": forge may have
        # followed a symlink or resolved a network URL that the O_NOFOLLOW reader
        # refused.  Only "content" is the pinned text we can verify.
        if "urls" in src_entry or "content" not in src_entry:
            return reject("not_inline_content", path)
        # Every path forge includes must be present in the full pinned tree.
        tree_content = full_tree.get(path)
        if tree_content is None:
            return reject("missing_in_tree", path)
        forge_content = src_entry["content"]
        if not isinstance(forge_content, str):
            return reject("not_inline_content", path)
        # Exact-bytes sha256: encode both as UTF-8, no normalisation.
        if (hashlib.sha256(forge_content.encode()).hexdigest()
                != hashlib.sha256(tree_content.encode()).hexdigest()):
            return reject("content_differs", path)

    # Forward check: every scope-pinned file must appear in forge's sources.
    for path in pinned_files:
        if path not in sources:
            return reject("scope_file_absent", path)

    return True, ""


def _check_forge_version(forge_version: Any, solc_bin: Path) -> bool:
    """Return True when forge's reported solc version doesn't match the pinned compiler.

    Comparison rules:
      - Absent version (None)  → False (no flag; version key was not emitted).
      - Non-string value       → True  (fail closed; unexpected type).
      - Unparsable string      → True  (fail closed; cannot verify).
      - Semver mismatch        → True  (different release).
      - Commit hash mismatch   → True  (both sides carry a commit hash and they differ).
      - Match or one side has  → False (semver equals; commit hashes absent or equal).
        no commit hash

    Both the forge string ("0.8.26+commit.8a97fa7e.Linux.g++") and the solc_bin name
    ("solc-0.8.26+commit.8a97fa7e") are parsed by _FORGE_VERSION_RE; the match on
    the solc_bin name tolerates the leading "solc-" prefix.
    """
    if forge_version is None:
        return False
    if not isinstance(forge_version, str):
        return True
    m_forge = _FORGE_VERSION_RE.search(forge_version)
    m_pinned = _FORGE_VERSION_RE.search(solc_bin.name)
    if m_forge is None or m_pinned is None:
        return True  # unparsable
    if m_forge.group(1) != m_pinned.group(1):
        return True  # semver mismatch
    # Both carry a commit hash: compare them
    if m_forge.group(2) is not None and m_pinned.group(2) is not None:
        return m_forge.group(2) != m_pinned.group(2)
    return False  # semver matches; commit hash absent on at least one side


def forge_build_repo(
    src_tree_dir: str,
    out_dir: Path,
    solc_bin: Path,
    cache: SolcCache,
    diag: dict | None = None,
    extra_remappings: list[str] | None = None,
) -> tuple[ForgeStdInput | None, str]:
    """B4: run forge to resolve sources+remappings into a Standard JSON input only.

    Forge's compiled output is DISCARDED.  The returned ForgeStdInput is recompiled
    by OUR sandboxed solc (_run_build) to prevent the repo from influencing compilation.

    Returns (result, reason) where reason is "" on success, or a rejection code when
    result is None:
      "forge_unavailable"  – image not set, docker absent, or dev bypass active
      "forge_timeout"      – forge container exceeded the configured timeout
      "forge_failed"       – forge exited non-zero, no build-info, parse error, etc.

    Security invariants (finding fixes 2026-10-13):
    - Finding 1: settings rebuilt from allow-list (_sanitize_forge_settings).
    - Finding 2: build-info read via sandbox.output.read_output_files (no-follow, capped).
    - Finding 4: forge runs in a named container; docker rm -f kills it on timeout.
      timeout taken from limits.yaml build.evm.timeout_s.
    - Source tree mounted READ-ONLY at /work/src; forge cannot modify it.
    - Forge writes to /work/out (fresh dir, separate from the source tree).
    - Forge uses ONLY the solc binary at /cache/<platform>/<solc_filename> (--use).
    - FOUNDRY_ env vars and .env loading are suppressed (clean env, --no-dotenv).
    - rc != 0 → None/forge_failed (no build-info search on failure).
    - Exactly one build-info file required; 0 or >1 → None/forge_failed.
    - Forge output field is never used; only `input` key is returned.
    """
    if _BUILD_IMAGE is None:
        return None, "forge_unavailable"
    if _DIRECT_SOLC:
        return None, "forge_unavailable"  # dev bypass: skip forge

    import shutil
    if not shutil.which("docker"):
        return None, "forge_unavailable"

    src = Path(src_tree_dir)
    if not src.is_dir() or src.is_symlink():
        return None, "forge_failed"

    # forge runs as the sandbox user: the out dir must be writable for it (a 0755 dir owned by the
    # supervisor user makes forge fail on build-info with no other symptom).
    forge_out = sandbox_writable_dir(out_dir / "forge_out")

    # Solc inside container: /cache/<platform>/<filename>
    solc_container_path = f"/cache/{solc_bin.parent.name}/{solc_bin.name}"

    # Named container so we can docker rm -f on timeout (finding 4)
    container_name = f"soken-forge-{uuid.uuid4().hex[:12]}"

    command = [
        "forge", "build",
        "--offline",          # no network
        "--build-info",       # emit out/build-info/<hash>.json with Standard JSON input
        "--skip", "test", "script",
        "--out", "/work/out",
        # The cache lives on the container's fresh tmpfs, never in the repo's cache/ (read-only
        # /work/src), so no cached state from the repo can enter. forge rejects --no-cache together
        # with --no-dynamic-test-linking, so the empty cache path is the isolation.
        "--cache-path", "/tmp/forge-cache",
        "--use", solc_container_path,  # our exact pinned solc; never repo-specified
        "--no-auto-detect",   # do not try to resolve solc from PATH; we supply --use
        # forge >= 1.x preprocesses test helpers (dynamic test linking: rewritten test/*.sol plus
        # synthetic foundry-pp/*.sol) into build-info; those are not repo files, so the source gate
        # would reject the whole B4 input. We only want forge's import resolution of the real tree.
        "--no-dynamic-test-linking",
        # Note: --no-dotenv does not exist in forge v1.8.5.  .env loading is suppressed
        # by HOME=/tmp (no user-level foundry config) and the lack of FOUNDRY_* in the
        # container env.  CLI --use overrides any FOUNDRY_SOLC from a repo .env file.
    ]
    # Vendored npm packages (npm_deps): each remapping was validated by sanitize_remapping (no
    # leading dash, relative target inside the tree), so it cannot become a forge option.
    for remap in extra_remappings or []:
        safe = sanitize_remapping(remap)
        if safe is not None:
            command += ["--remappings", safe]

    try:
        argv = docker_argv(
            step="build",
            image=_BUILD_IMAGE,
            work_dir=src,            # unused when mounts= is given
            cache_dir=cache._root,   # /cache: read-only, contains our pinned solc
            limits=_BUILD_LIMITS,
            # Clean env: no FOUNDRY_* passed in; HOME=/tmp keeps foundry away from /root
            env={"HOME": "/tmp"},
            command=command,
            workdir="/work/src",
            runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
            mounts=[
                (src.resolve(), "/work/src", True),        # source: READ-ONLY
                (forge_out.resolve(), "/work/out", False),  # output: writable
            ],
            name=container_name,
        )
    except (ValueError, TypeError):
        return None, "forge_failed"

    timeout_s = _forge_build_timeout()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _stdout, _stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        # Finding 4: kill the named container, then clean up the process
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        proc.kill()
        proc.communicate()
        return None, "forge_timeout"
    except OSError:
        return None, "forge_failed"

    if diag is not None:
        diag["forge_rc"] = proc.returncode
        head = _printable_head(_stderr or b"")
        if head:
            diag["forge_stderr_head"] = head
    if proc.returncode != 0:
        return None, "forge_failed"

    build_info_dir = forge_out / "build-info"
    if not build_info_dir.is_dir() or build_info_dir.is_symlink():
        return None, "forge_failed"

    # Finding 2: use the sandbox-safe reader (O_NOFOLLOW, size-capped, no direct open())
    try:
        files_map = read_output_files(
            build_info_dir, "*.json",
            max_files=1,
            max_bytes=_FORGE_BUILD_INFO_MAX_BYTES,
        )
    except (UnsafeOutput, FileNotFoundError, OSError):
        return None, "forge_failed"

    if len(files_map) != 1:
        return None, "forge_failed"

    data = next(iter(files_map.values()))
    try:
        info = json.loads(data)
    except (ValueError, RecursionError):
        return None, "forge_failed"

    # Return ONLY the input (Standard JSON that forge constructed from the source tree).
    # Forge's output field is discarded; OUR solc recompiles the input.
    raw_input = info.get("input")
    if not raw_input or not isinstance(raw_input, dict):
        return None, "forge_failed"

    # Finding 1: rebuild settings from allow-list; drop unknown keys; record trust flags.
    raw_settings = raw_input.get("settings") or {}
    clean_settings, libraries_unverified, had_unknown = _sanitize_forge_settings(raw_settings)
    # Always replace outputSelection with our own
    clean_settings["outputSelection"] = _OUTPUT_SELECTION

    # Version check: compare forge's reported solc version to the pinned compiler.
    # "version" is excluded from _FORGE_TOP_SILENT_DROP so it must be consumed here.
    # Absent → no flag.  Mismatch or unparsable → had_unknown=True + forge_version_mismatch.
    version_mismatch = _check_forge_version(raw_input.get("version"), solc_bin)
    if version_mismatch:
        had_unknown = True

    # Whitelist only the keys solc Standard JSON accepts (language, sources, settings).
    # Forge injects top-level keys that fall into two categories:
    #   (a) filesystem hints: allowPaths, basePath, includePaths — dropped silently via
    #       _FORGE_TOP_SILENT_DROP; irrelevant once sources are inline, no compile effect.
    #   (b) version — handled above by _check_forge_version; excluded from this check.
    #   (c) anything else not in _SOLC_STD_JSON_KEYS — unknown, flag had_unknown.
    extra_top_keys = set(raw_input) - _SOLC_STD_JSON_KEYS - {"version"}
    unknown_top_keys = extra_top_keys - _FORGE_TOP_SILENT_DROP
    if unknown_top_keys:
        had_unknown = True  # unexpected non-standard top-level key
    std_input = {k: v for k, v in raw_input.items() if k in _SOLC_STD_JSON_KEYS}
    std_input["settings"] = clean_settings

    return ForgeStdInput(
        std_input=std_input,
        libraries_unverified=libraries_unverified,
        had_unknown_settings=had_unknown,
        forge_version_mismatch=version_mismatch,
    ), ""


def _run_build(
    candidate: Candidate,
    std_input: dict,
    solc_bin: Path,
    work_dir: Path,
    cache: SolcCache,
) -> BuildResult:
    src_dir = work_dir / "src"
    out_dir = work_dir / "out"
    src_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    stdin_data = json.dumps(std_input).encode()

    try:
        stdout_data, stderr_head = _invoke_solc(solc_bin, stdin_data, work_dir, cache)
    except RuntimeError as exc:
        return _fail(candidate, "not_checkable", str(exc))
    except (OSError, ValueError) as exc:
        return _fail(candidate, "failed", str(exc)[:200])

    if not stdout_data:
        return BuildResult(candidate=candidate, status="failed", reason="failed",
                           stderr_head=stderr_head or "no output")

    try:
        output = json.loads(stdout_data)
    except (json.JSONDecodeError, RecursionError) as exc:  # deeply nested output: a failed build
        return BuildResult(candidate=candidate, status="failed", reason="failed",
                           stderr_head=f"json decode: {exc}\n{stderr_head}")

    errors = output.get("errors", [])
    fatal = [e for e in errors if e.get("severity") == "error"]
    if fatal:
        msg = "; ".join(e.get("formattedMessage", e.get("message", ""))[:200] for e in fatal[:5])
        reason = _missing_import_reason(fatal) or "failed"
        return BuildResult(candidate=candidate, status="failed", reason=reason,
                           stderr_head=(msg + "\n" + stderr_head)[:2000])

    advisories = [e.get("message", "")[:200] for e in errors if e.get("severity") != "error"]
    artifacts = _parse_artifacts(output)
    nsloc = _count_nsloc(candidate.files)

    # Persist for analyzers. The container had /work mounted: write without following links.
    try:
        write_no_follow(out_dir, "output.json", json.dumps(output).encode())
        write_no_follow(out_dir, "input.json", json.dumps(std_input).encode())
        write_host_build_copy(work_dir, std_input, output)
    except OSError as exc:
        return _fail(candidate, "failed", f"unsafe_build_output: {exc}"[:200])

    auxdata_ranges = _compute_auxdata_ranges(candidate, std_input, solc_bin, output, cache, work_dir)

    return BuildResult(
        candidate=candidate,
        status="ok",
        artifacts=artifacts,
        auxdata_ranges=auxdata_ranges,
        compiler_advisories=advisories,
        nsloc=nsloc,
        work_dir=str(work_dir),
        stderr_head=stderr_head or None,
    )


def _parse_artifacts(output: dict) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for file_path, file_contracts in output.get("contracts", {}).items():
        for contract_name, data in file_contracts.items():
            evm = data.get("evm", {})
            bytecode = evm.get("bytecode", {})
            deployed = evm.get("deployedBytecode", {})
            artifacts.append(Artifact(
                contract=f"{file_path}:{contract_name}",
                creation=bytecode.get("object", ""),
                runtime=deployed.get("object", ""),
                immutable_refs=deployed.get("immutableReferences", {}),
                link_refs={
                    **bytecode.get("linkReferences", {}),
                    **deployed.get("linkReferences", {}),
                },
                source_map=deployed.get("sourceMap", ""),
                storage_layout=data.get("storageLayout"),
            ))
    return artifacts


def _count_nsloc(files: dict[str, str]) -> int:
    total = 0
    for content in files.values():
        in_block = False
        for line in content.splitlines():
            stripped = line.strip()
            if "/*" in stripped:
                in_block = True
            if in_block:
                if "*/" in stripped:
                    in_block = False
                continue
            if not stripped or stripped.startswith("//"):
                continue
            total += 1
    return total


def _version_tuple(version_str: str) -> tuple[int, ...]:
    # Also tron-solc tags (tv_0.8.23, tron_v0.8.18+commit...) and "v0.8.24+commit..."
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str.split("+")[0])
    return tuple(int(p) for p in m.groups()) if m else (0, 0, 0)


def auxdata_x3(version: str, std_input: dict | None, settings: dict | None) -> bool:
    """13.2 X3: no auxdata (appendCBOR false, or solc before 0.4.7)."""
    if _version_tuple(version) < _MIN_CBOR_VERSION:
        return True
    s = std_input.get("settings") if std_input else settings
    return (s or {}).get("metadata", {}).get("appendCBOR", True) is False


def _compute_auxdata_ranges(
    candidate: Candidate,
    std_input: dict,
    solc_bin: Path,
    first_output: dict,
    cache: SolcCache,
    work_dir: Path,
) -> dict[str, list[tuple[int, int]]]:
    """Compute auxdata byte ranges (13.2 X1/X2/X3)."""
    if auxdata_x3(candidate.compiler.version if candidate.compiler else "", std_input, None):
        return {}

    result: dict[str, list[tuple[int, int]]] = {}
    contracts_out = first_output.get("contracts", {})
    second: dict | None = None  # X2 output, compiled once for all contracts

    def x2_output() -> dict:
        nonlocal second
        if second is None:
            second = {}
            import copy
            modified = copy.deepcopy(std_input)
            for src_data in modified.get("sources", {}).values():
                if "content" in src_data:
                    src_data["content"] += "\n"
            # Recompile via sandbox (or direct if enabled); a fresh dir, since the first
            # compile leaves a read-only input.json behind
            aux_work = work_dir / "auxdata_tmp"
            aux_work.mkdir(exist_ok=True)
            try:
                stdout2, _ = _invoke_solc(solc_bin, json.dumps(modified).encode(), aux_work, cache)
                second = json.loads(stdout2) if stdout2 else {}
            except (OSError, ValueError, RuntimeError):
                second = {}  # auxdata failure is non-fatal; leads to not_checkable at comparison
        return second

    for file_path, file_contracts in contracts_out.items():
        for contract_name, data in file_contracts.items():
            key = f"{file_path}:{contract_name}"
            deployed = data.get("evm", {}).get("deployedBytecode", {})

            # X1: Sourcify cborAuxdata
            cbor_auxdata = deployed.get("cborAuxdata")
            if cbor_auxdata:
                ranges: list[tuple[int, int]] = []
                entries = cbor_auxdata.values() if isinstance(cbor_auxdata, dict) else cbor_auxdata
                for entry in entries:
                    if isinstance(entry, dict):
                        offset = entry.get("offset", 0)
                        length = entry.get("length", 0)
                        if length > 0:
                            ranges.append((offset, offset + length))
                if ranges:
                    result[key] = ranges
                    continue

            # X2: recompile with trailing newlines (sandboxed). An empty list records that X2
            # ran and nothing varied (e.g. bytecodeHash none); a missing key means unknown.
            runtime1 = deployed.get("object", "")
            if not runtime1:
                continue
            runtime2 = (x2_output().get("contracts", {})
                        .get(file_path, {})
                        .get(contract_name, {})
                        .get("evm", {})
                        .get("deployedBytecode", {})
                        .get("object", ""))
            if not runtime2 or len(runtime1) != len(runtime2):
                continue
            result[key] = _diff_hex_ranges(runtime1, runtime2)

    return result


def _diff_hex_ranges(hex1: str, hex2: str) -> list[tuple[int, int]]:
    if len(hex1) != len(hex2):
        return []
    ranges: list[tuple[int, int]] = []
    i, n = 0, len(hex1) // 2
    while i < n:
        if hex1[i * 2: i * 2 + 2] != hex2[i * 2: i * 2 + 2]:
            start = i
            while i < n and hex1[i * 2: i * 2 + 2] != hex2[i * 2: i * 2 + 2]:
                i += 1
            ranges.append((start, i))
        else:
            i += 1
    return ranges


def host_build_dir(work_dir: Path) -> Path:
    """`<attempt>.host/build`: never mounted into a container (TON uses the same `.host` dir)."""
    return Path(work_dir).parent / f"{Path(work_dir).name}.host" / "build"


def write_host_build_copy(work_dir: Path, std_input: dict, output: dict) -> None:
    """The std-json input and compiler output, written from this process's memory into the
    host-only dir. Analyzers and advisories read only these copies: nothing under work/ is read
    after the build step returns (a later container may have changed it)."""
    d = host_build_dir(work_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "input.json").write_text(json.dumps(std_input), encoding="utf-8")
    (d / "output.json").write_text(json.dumps(output), encoding="utf-8")


def write_no_follow(directory: Path, name: str, data: bytes) -> None:
    """Write directory/name in a dir a container could write: the dir is opened with O_NOFOLLOW,
    an existing entry (file or planted symlink) is unlinked, the file is created O_EXCL|O_NOFOLLOW.
    Raises OSError when the dir itself is a link or not a dir."""
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.unlink(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    finally:
        os.close(dfd)


def _fail(candidate: Candidate, reason: str, detail: str = "") -> BuildResult:
    return BuildResult(candidate=candidate, status="failed", reason=detail or reason)
