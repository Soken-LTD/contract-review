"""EVM repo source candidate (05 section 4.2 step 6, section 7 rule B4).

After `soken-fetch` materializes a git tree into `src_dir`, this module:
  - Reads the materialized tree ONLY through an O_NOFOLLOW-at-every-level reader
    (same technique as `soken_review.sandbox.output`).  Every symlink, special file
    or path-component that is a symlink is refused and recorded; nothing is read
    through a link.
  - Reads `foundry.toml` (TOML) and `remappings.txt` for compiler settings.
  - Validates every remapping: the target side must stay inside the pinned tree
    (no absolute path, no `..`, no backslash).
  - Flags `ffi = true` or any script/build hook → `untrusted_inputs = True` (tier B).
  - npm packages (`node_modules/`) are vendored before this runs by the supervisor
    (adapters/evm/npm_deps.py, lockfile pinned, sha512 checked); their remappings arrive as
    `extra_remappings`. An import that still does not resolve is caught by the build gate
    (`missing_import`), never guessed here.
  - Returns a `Candidate(provider="repo", ...)` ready for `build()`.

The entry selection rule (plan 05/04): all non-test, non-script, non-dependency
Solidity sources the compile actually builds (from forge/solc output, not directory
names).  When no forge project is found, falls back to all *.sol files in the tree
that are not under `test/`, `tests/`, `script/`, `scripts/`, `lib/`, `node_modules/`.

All paths are re-checked by `filter_candidate_files` inside `make_candidate`.

Security model (09 3.5, 5.1):
  The src_dir contains output from an untrusted sandbox.  NEVER call `open()`,
  `read_text()`, `Path.stat()` etc. on paths derived by string concatenation of a
  user-supplied relative path and a host directory.  `_safe_read_tree` uses
  `os.open(..., O_NOFOLLOW)` at every directory level (via `dir_fd=`) so that a
  symlink in ANY path component is caught, not only the last one.  Symlinks are
  skipped (not raised), because git_materializer already converts them to refused
  entries; a symlink in the host dir means a TOCTOU or a malicious tree — both are
  refused silently and recorded.
"""

from __future__ import annotations

import logging
import os
import re
import stat
import tomllib
from pathlib import PurePosixPath
from typing import Any

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.evm.build import sanitize_remapping
from soken_review.adapters.evm.fetch import _now_iso, make_candidate

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Caps for reading the materialized tree (09 3.2 / 5.2)
# ---------------------------------------------------------------------------
_MAX_FILES = 20_000          # matches git_materializer MAX_FILES
_MAX_BYTES_TOTAL = 200 * 1024 * 1024
_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_DEPTH = 32

# O_NONBLOCK prevents blocking on FIFOs/devices; O_NOFOLLOW refuses symlinks.
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)

# ---------------------------------------------------------------------------
# Paths considered non-source (05 section 3.4 / 7 rule B4)
# ---------------------------------------------------------------------------

_NON_SOURCE_DIRS = frozenset({
    "test", "tests", "script", "scripts", "lib", "node_modules",
    ".git", ".github",
})

# ---------------------------------------------------------------------------
# Constants for trust checks
# ---------------------------------------------------------------------------

# foundry.toml keys that, when true, mean code can run arbitrary commands.
# Checked by `_has_ffi_or_hooks` on every profile.
_FFI_KEYS = ("ffi",)
# profile sub-keys for compile hooks — presence means arbitrary execution risk.
_HOOK_KEYS = ("build_command", "pre_build_hooks", "post_build_hooks", "script_dir")


# ---------------------------------------------------------------------------
# Safe tree reader (O_NOFOLLOW at every directory level)
# ---------------------------------------------------------------------------


def _safe_read_tree(
    root_fd: int,
    prefix: str,
    out: dict[str, bytes],
    refused: list[str],
    depth: int,
    total_ref: list[int],
) -> None:
    """Recursively read files from an open directory fd, never following links.

    Symlinks (at any level) are skipped and recorded in ``refused``; special
    files are also refused.  Byte and file-count caps are enforced.
    """
    if depth > _MAX_DEPTH:
        refused.append(f"{prefix}<depth_limit>")
        return
    try:
        entries = sorted(os.scandir(root_fd), key=lambda e: e.name)
    except OSError as exc:
        refused.append(f"{prefix}<scandir_error: {exc}>")
        return

    for e in entries:
        rel = f"{prefix}{e.name}"
        # is_symlink checks the final component via lstat; since we have a dir_fd,
        # the e.stat(follow_symlinks=False) call is relative to the open dir fd.
        st = e.stat(follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            refused.append(f"{rel}: symlink")
            continue
        if stat.S_ISDIR(st.st_mode):
            try:
                sub_fd = os.open(e.name, _DIR_FLAGS, dir_fd=root_fd)
            except OSError as exc:
                refused.append(f"{rel}: {exc}")
                continue
            try:
                _safe_read_tree(sub_fd, rel + "/", out, refused, depth + 1, total_ref)
            finally:
                os.close(sub_fd)
            continue
        if not stat.S_ISREG(st.st_mode):
            refused.append(f"{rel}: not_regular")
            continue
        # Size checks before reading
        if st.st_size > _MAX_FILE_BYTES:
            refused.append(f"{rel}: too_large")
            continue
        if total_ref[0] + st.st_size > _MAX_BYTES_TOTAL:
            refused.append(f"{rel}: total_cap")
            continue
        if len(out) >= _MAX_FILES:
            refused.append(f"{rel}: file_count_cap")
            continue
        try:
            fd = os.open(e.name, _FILE_FLAGS, dir_fd=root_fd)
        except OSError as exc:
            refused.append(f"{rel}: {exc}")
            continue
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                refused.append(f"{rel}: not_regular_after_open")
                continue
            data = os.read(fd, _MAX_FILE_BYTES + 1)
        except OSError as exc:
            refused.append(f"{rel}: read_error: {exc}")
            continue
        finally:
            os.close(fd)
        if len(data) > _MAX_FILE_BYTES:
            refused.append(f"{rel}: too_large_after_read")
            continue
        total_ref[0] += len(data)
        out[rel] = data


def safe_read_repo_tree(src_dir_str: str | os.PathLike[str]) -> tuple[dict[str, str], list[str]]:
    """Read the materialized git tree from ``src_dir_str`` with O_NOFOLLOW at every level.

    Returns (files, refused_paths):
    - files: {relative_path: utf-8_text} for every regular file
    - refused_paths: list of reasons for skipped paths (symlinks, specials, caps)
    """
    raw: dict[str, bytes] = {}
    refused: list[str] = []
    total_ref = [0]
    try:
        root_fd = os.open(src_dir_str, _DIR_FLAGS)
    except OSError as exc:
        logger.warning("safe_read_repo_tree: cannot open root %s: %s", src_dir_str, exc)
        return {}, [f"<root_open_error: {exc}>"]
    try:
        _safe_read_tree(root_fd, "", raw, refused, depth=0, total_ref=total_ref)
    finally:
        os.close(root_fd)
    # Decode to text (UTF-8 with replacement; non-text files like binaries are included
    # but will be filtered by scope selection).
    files = {k: v.decode("utf-8", errors="replace") for k, v in raw.items()}
    if refused:
        logger.debug("safe_read_repo_tree: %d refused entries: %s", len(refused), refused[:5])
    return files, refused


# ---------------------------------------------------------------------------
# Path safety re-check (plan 09 5.1: the supervisor re-checks every path it reads)
# ---------------------------------------------------------------------------

_SAFE_REL_RE = re.compile(r"^[A-Za-z0-9@_.\-/ ]{1,512}$")


def _recheck_path(raw: str) -> str | None:
    """Re-validate a manifest file path on the supervisor side (09 5.1).

    Returns the path unchanged if safe, None if it must be dropped.
    The git_materializer already checked these paths; this is the second gate.
    """
    if not raw or not _SAFE_REL_RE.match(raw):
        return None
    parts = PurePosixPath(raw).parts
    if not parts:
        return None
    for part in parts:
        if part in ("", ".", "..") or part.startswith("-"):
            return None
        bare = part.rstrip(". ").casefold()
        if bare == ".git" or bare.startswith("git~"):
            return None
    if PurePosixPath(raw).is_absolute():
        return None
    return raw


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def repo_candidate_from_manifest(
    src_dir_str: str | os.PathLike[str],
    manifest: dict[str, Any],
    *,
    explorer_candidate: Candidate | None = None,
    source_url: str | None = None,
    extra_remappings: list[str] | None = None,
) -> tuple[Candidate | None, str | None]:
    """Build a `repo` Candidate from a materialized git tree.

    Parameters
    ----------
    src_dir_str:
        String path to the directory where soken-fetch wrote the files.
        Passed as a string to avoid accidental Path.read_text() calls.
    manifest:
        The soken-fetch.v1 manifest dict (re-read from the container output;
        paths have already been validated by git_materializer and must be
        re-validated here).
    explorer_candidate:
        When an explorer record (Sourcify, eth-bytecode-db, …) exists for the
        same address, pass it so we can copy its compiler version and settings
        (plan 05 section 6.1, rule B4 + section 13.3).
    extra_remappings:
        Remappings for npm packages the supervisor vendored into node_modules/ (hardhat-style
        imports such as `@openzeppelin/contracts/...`), appended after the repo's own.

    Returns
    -------
    (candidate, reason)
        candidate is None and reason is a non-empty string when the repo cannot
        be reviewed (npm-only deps, no Solidity sources, etc.).
        reason is None on success.
    """
    # 0. source_url is required for a repo candidate (repo_url@sha from the supervisor).
    #    None means the supervisor did not resolve the sha — refuse rather than record unknown provenance.
    if source_url is None:
        return None, "source_url_required"

    # 1. Read all files from the materialized tree with O_NOFOLLOW at every level.
    all_files, refused_paths = safe_read_repo_tree(src_dir_str)

    if refused_paths:
        logger.info("repo_candidate: %d path(s) refused during tree read", len(refused_paths))

    if not all_files:
        return None, "no_files"

    # 1b. Cross-check: any manifest path that was refused AND is a .sol file means we may
    #     be missing source — record it.  If the refused path set is non-empty we continue
    #     (the build will simply lack those files) but if the final scope is empty we return
    #     insufficient_source later, not a silent build without them.
    refused_sol_paths = [r for r in refused_paths if ".sol" in r]
    if refused_sol_paths:
        logger.warning("repo_candidate: %d .sol path(s) refused: %s",
                       len(refused_sol_paths), refused_sol_paths[:3])

    # 2. Validate every path from the manifest against the safety re-check gate.
    #    Files that fail the gate are removed (we already read only what was on disk,
    #    but we double-gate path characters).
    safe_files: dict[str, str] = {}
    for rel, content in all_files.items():
        if _recheck_path(rel) is not None:
            safe_files[rel] = content
        else:
            logger.warning("repo_candidate: dropped unsafe path %r after tree read", rel)

    if not safe_files:
        return None, "no_files"

    # 3. Detect Foundry project (foundry.toml or remappings.txt present).
    foundry_cfg = _read_foundry_toml(safe_files)
    remappings_txt = _read_remappings_txt(safe_files)

    # 4. Extract settings from config (compiler version comes from the explorer candidate).
    settings = _extract_settings(foundry_cfg, remappings_txt)
    if extra_remappings:
        own = list(settings.get("remappings") or [])
        for remap in extra_remappings:
            safe = sanitize_remapping(remap)
            if safe is not None and safe not in own:
                own.append(safe)
        if own:
            settings["remappings"] = own

    # 5. Trust check: ffi or build hooks → untrusted.
    #    Also: a committed out/ with solc-output artifacts means the repo pre-baked build
    #    results, same threat as a committed .so for Solana — tier B, never tier A.
    #    Also: auto_detect_solc / solc path / FOUNDRY_* in .env → compiler substitution risk.
    untrusted = (
        _has_ffi_or_hooks(foundry_cfg)
        or _has_committed_build_artifacts(safe_files)
        or _has_forge_compiler_trust_issues(foundry_cfg, safe_files)
    )

    # 7. Select scope files (non-test, non-script, non-dep .sol).
    sol_files = _select_scope_files(safe_files, foundry_cfg)
    if not sol_files:
        # If we refused any .sol paths, the source is incomplete — name it explicitly.
        if refused_sol_paths:
            return None, f"insufficient_source:refused_sol_paths:{len(refused_sol_paths)}"
        return None, "no_solidity_sources"

    # 8. Compiler: priority = (a) foundry.toml solc pin, (b) explorer candidate R1,
    #    (c) pragma guess.  `version_pinned_by` is set by each source; we never override it.
    #    "pragma_guess" → no tier A (plan 05 §6.1: only config or explorer give tier A).
    compiler = (_compiler_from_foundry_toml(foundry_cfg)
                or _compiler_from_explorer(explorer_candidate)
                or _compiler_from_pragma(sol_files))
    if compiler is None:
        return None, "compiler_version_unknown"
    # Do NOT change version_pinned_by — each helper already sets the correct source label.

    # 9. Build the Candidate. make_candidate re-validates all paths.
    cand = make_candidate(
        provider="repo",
        raw_files=sol_files,
        language="solidity",
        compiler=compiler,
        settings=settings,
        std_json_input=None,           # forge build --offline; Standard JSON as fallback (B3)
        entry_contract=None,           # discovered from build output
        explorer_verified=False,       # only set True after 13.1 deployment hash comparison
        sourcify_match=None,
        source_url=source_url,         # repo_url@sha from the supervisor (non-None when known)
        fetched_at=_now_iso(),
        _caller_context="repo",
    )
    cand.untrusted_inputs = untrusted
    # Record refused paths in the candidate so the provenance layer can surface them.
    # Fix 4: refused .sol files are not silently dropped — they are visible in the candidate.
    if refused_paths:
        cand.refused_paths = refused_paths[:50]
    # Carry the FULL O_NOFOLLOW tree (all files, not just scope) to the build step so that
    # _forge_sources_match_pin can verify every lib/ dep forge includes, not only scope files.
    # This is runtime-only; never serialised into persisted/public payloads.
    cand._full_tree = safe_files
    return cand, None


# ---------------------------------------------------------------------------
# foundry.toml / remappings.txt parsers
# ---------------------------------------------------------------------------


def _read_foundry_toml(files: dict[str, str]) -> dict[str, Any]:
    """Parse foundry.toml if present; return {} on any error."""
    content = files.get("foundry.toml") or files.get("Foundry.toml")
    if not content:
        return {}
    try:
        return tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        logger.debug("foundry.toml parse error: %s", exc)
        return {}


def _read_remappings_txt(files: dict[str, str]) -> list[str]:
    """Read remappings.txt lines."""
    content = files.get("remappings.txt") or ""
    return [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]


# ---------------------------------------------------------------------------
# Settings extraction (plan 05 6.1 "Repo config" row)
# ---------------------------------------------------------------------------

def _extract_settings(cfg: dict[str, Any], remappings_txt: list[str]) -> dict[str, Any]:
    """Build a solc-compatible settings dict from foundry.toml + remappings.txt.

    Unknown keys that change bytecode (via_ir, optimizer, evm_version, libraries,
    ffi, build scripts) go into the trust/settings record per plan 05 section 6.1
    (kept in settings but not executed).  Remapping targets are validated; unsafe
    ones are dropped (fail closed).
    """
    profile = (cfg.get("profile") or {}).get("default") or {}

    # Remappings: prefer foundry.toml, fall back to remappings.txt
    raw_remaps: list[str] = list(profile.get("remappings") or []) or remappings_txt
    safe_remaps: list[str] = []
    for r in raw_remaps:
        validated = sanitize_remapping(r)
        if validated is not None:
            safe_remaps.append(validated)
        else:
            logger.warning("repo_candidate: dropped unsafe remapping %r", r)

    settings: dict[str, Any] = {}
    if safe_remaps:
        settings["remappings"] = safe_remaps

    # Optimizer (compile-influencing but not dangerous)
    opt = profile.get("optimizer")
    opt_runs = profile.get("optimizer_runs")
    if opt is not None:
        settings["optimizer"] = {"enabled": bool(opt)}
        if opt_runs is not None:
            settings["optimizer"]["runs"] = int(opt_runs)

    # evm_version
    evm_ver = profile.get("evm_version")
    if evm_ver and isinstance(evm_ver, str):
        settings["evmVersion"] = evm_ver

    # via_ir
    via_ir = profile.get("via_ir")
    if via_ir:
        settings["viaIR"] = True

    return settings


# ---------------------------------------------------------------------------
# Trust check
# ---------------------------------------------------------------------------


def _has_committed_build_artifacts(files: dict[str, str]) -> bool:
    """Return True when the repo has committed solc/forge build artifacts.

    A repo that pre-bakes build outputs (out/, cache/, build-info JSON) could supply
    a forged build-info that our B4 path would accept.  Detect it here and set
    untrusted_inputs=True (tier B ceiling) so even if B4 succeeds the job stays tier B.

    Checks: any .json file under out/, cache/, or build-info/ that contains a top-level
    'abi' or 'bytecode' or 'output' key is a solc build artifact.  We check the first
    512 bytes only (no full parse needed).
    """
    _ARTIFACT_DIRS = ("out/", "cache/", "build-info/")
    for path, content in files.items():
        if not any(path.startswith(d) for d in _ARTIFACT_DIRS):
            continue
        if not path.endswith(".json"):
            continue
        # Quick heuristic: solc output JSON has "abi", "bytecode", or Standard JSON output
        # has "contracts" / "errors" at top level.  Check the first 512 chars.
        snippet = content[:512]
        if any(key in snippet for key in ('"abi"', '"bytecode"', '"contracts"', '"output"', '"input"')):
            logger.info("repo_candidate: committed build artifact at %r → untrusted", path)
            return True
    return False


def _has_ffi_or_hooks(cfg: dict[str, Any]) -> bool:
    """Return True when ffi=true or any script/build hook is set (plan 05 section 6.1 / 09 5.1).

    Any profile that sets ffi=true means the build runs arbitrary code; the candidate
    is reviewed but gets untrusted_inputs=True (tier B, never executed).
    Uses _FFI_KEYS and _HOOK_KEYS so the constant list is the single source of truth.
    """
    for profile_name, profile in (cfg.get("profile") or {}).items():
        if not isinstance(profile, dict):
            continue
        for ffi_key in _FFI_KEYS:
            if profile.get(ffi_key):
                logger.info("repo_candidate: %s=true in profile %r → untrusted", ffi_key, profile_name)
                return True
        for hook_key in _HOOK_KEYS:
            if profile.get(hook_key):
                logger.info("repo_candidate: hook key %r in profile %r → untrusted", hook_key, profile_name)
                return True
    return False


def _has_forge_compiler_trust_issues(cfg: dict[str, Any], files: dict[str, str]) -> bool:
    """Return True when the repo can influence which compiler forge uses.

    These conditions allow a malicious repo to substitute its own solc binary or
    compiler settings, defeating B4 source-resolution integrity (coordinator 2026-10-13):

    1. foundry.toml has `auto_detect_solc = true` in any profile.
    2. foundry.toml `solc` value is a path (starts with `.`, `/`, or `~`) rather than
       an exact semver — this would make forge use a repo-committed binary.
    3. A .env file exists containing FOUNDRY_* keys — these env vars can override
       the compiler path or settings outside foundry.toml.
    """
    for profile_name, profile in (cfg.get("profile") or {}).items():
        if not isinstance(profile, dict):
            continue
        if profile.get("auto_detect_solc"):
            logger.info("repo_candidate: auto_detect_solc=true in profile %r → untrusted", profile_name)
            return True
        solc_val = profile.get("solc") or profile.get("solc_version")
        if solc_val and isinstance(solc_val, str):
            # Allow-list: only bare semver "X.Y.Z" (optionally with +commit... suffix) is trusted.
            # Anything else (path, range, URL, ~version, ^version) can redirect forge to a
            # repo-committed binary and is therefore untrusted (finding 4 allow-list fix).
            bare = solc_val.split("+")[0].strip()
            if not re.fullmatch(r"\d+\.\d+\.\d+", bare):
                logger.info(
                    "repo_candidate: solc %r not a plain semver in profile %r → untrusted",
                    solc_val[:40], profile_name,
                )
                return True

    # Check .env file for FOUNDRY_ keys (case-insensitive)
    for env_file in (".env", ".env.local", ".env.foundry"):
        content = files.get(env_file, "")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key = stripped.split("=", 1)[0].strip().upper()
            if key.startswith("FOUNDRY_"):
                logger.info("repo_candidate: FOUNDRY_* key %r in %r → untrusted", key[:40], env_file)
                return True
    return False


# ---------------------------------------------------------------------------
# Scope file selection (plan 05 section 3.4 / 7 rule B4)
# ---------------------------------------------------------------------------


def _select_scope_files(files: dict[str, str], cfg: dict[str, Any]) -> dict[str, str]:
    """Return the in-scope .sol files: non-test, non-script, non-dependency.

    Reads src_dir from foundry.toml profile.default.src (default "src").
    When no foundry project is found, falls back to all *.sol not in excluded dirs.
    """
    profile = (cfg.get("profile") or {}).get("default") or {}
    src_path = (profile.get("src") or "src").rstrip("/")
    test_path = (profile.get("test") or "test").rstrip("/")
    script_path = (profile.get("script") or "script").rstrip("/")
    out_path = (profile.get("out") or "out").rstrip("/")
    libs: list[str] = list(profile.get("libs") or ["lib"])

    excluded_prefixes = {test_path + "/", script_path + "/", out_path + "/"}
    for lib in libs:
        excluded_prefixes.add(lib.rstrip("/") + "/")
    excluded_prefixes.update(p + "/" for p in _NON_SOURCE_DIRS)
    # Also exclude test/script dirs nested under src/ (e.g. solmate's src/test/).
    # Forge's --skip test script excludes them; B3 must match that scope.
    if not test_path.startswith(src_path + "/"):
        excluded_prefixes.add(src_path + "/" + test_path + "/")
    if not script_path.startswith(src_path + "/"):
        excluded_prefixes.add(src_path + "/" + script_path + "/")

    scope: dict[str, str] = {}
    for path, content in files.items():
        if not path.endswith(".sol"):
            continue
        # Check against excluded prefixes
        if any(path.startswith(prefix) for prefix in excluded_prefixes):
            continue
        # If foundry src is configured, prefer files under it.
        # Allow top-level .sol files only when no src dir is configured.
        if cfg and not path.startswith(src_path + "/") and path != src_path and "/" in path.rstrip("/"):
            continue
        scope[path] = content

    # If empty with strict foundry rules, relax to all non-excluded .sol
    if not scope:
        for path, content in files.items():
            if not path.endswith(".sol"):
                continue
            if any(path.startswith(prefix) for prefix in excluded_prefixes):
                continue
            scope[path] = content

    return scope


# ---------------------------------------------------------------------------
# Compiler helpers
# ---------------------------------------------------------------------------


# Exact-version pattern: "0.8.20" or "0.8.20+commit.xxxxx" — no ranges, no paths, no "auto".
# A range ("^0.8.0", ">=0.7 <0.9"), auto_detect_solc, or a binary path all return None → pragma_guess.
_FOUNDRY_EXACT_VER_RE = re.compile(r"^\s*(\d+\.\d+\.\d+)(?:\+[A-Za-z0-9_.]+)?\s*$")


def _compiler_from_foundry_toml(cfg: dict[str, Any]) -> Compiler | None:
    """Read explicit `solc = "x.y.z"` (or `solc_version`) from foundry.toml (plan 05 §6.1 config row).

    Only an EXACT pinned version string gives version_pinned_by="config".
    Ranges (^0.8.0, >=0.7), `auto_detect_solc = true`, binary paths, and any
    non-string value fall through to pragma_guess (no tier A).
    """
    profile = (cfg.get("profile") or {}).get("default") or {}
    # Foundry uses `solc` (string pinned version) in profile; some older configs use `solc_version`.
    for key in ("solc", "solc_version"):
        val = profile.get(key)
        if not val or not isinstance(val, str):
            continue
        m = _FOUNDRY_EXACT_VER_RE.match(val)
        if m:
            return Compiler(version=m.group(1), version_pinned_by="config")
        # Range or path — not a pin, fall through.
        logger.debug("foundry.toml %s=%r is not an exact version pin → no config label", key, val[:40])
    return None


def _compiler_from_explorer(cand: Candidate | None) -> Compiler | None:
    """Take the compiler version from the explorer candidate if available (plan 05 13.3)."""
    if cand and cand.compiler and cand.compiler.version:
        return Compiler(version=cand.compiler.version, version_pinned_by=cand.compiler.version_pinned_by)
    return None


_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+[^;]{0,80};")
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _compiler_from_pragma(files: dict[str, str]) -> Compiler | None:
    """Guess the compiler version from the first pragma in any file (05 6.1 pragma_guess)."""
    versions: list[str] = []
    for content in files.values():
        for m in _PRAGMA_RE.finditer(content[:4096]):
            vm = _VERSION_RE.search(m.group(0))
            if vm:
                versions.append(vm.group(1))
    if not versions:
        return None
    # Pick the highest semver found
    def _key(v: str) -> tuple[int, ...]:
        try:
            return tuple(int(x) for x in v.split("."))
        except ValueError:
            return (0, 0, 0)

    best = max(versions, key=_key)
    return Compiler(version=best, version_pinned_by="pragma_guess")
