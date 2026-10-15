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
  X1  Sourcify cborAuxdata -> auxdata_ranges
  X2  recompile with trailing newlines to find differing ranges
  X3  appendCBOR=false or solc < 0.4.7 -> no auxdata ranges
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from soken_review.adapters.base import Artifact, BuildResult, Candidate
from soken_review.adapters.evm.compiler import CompilerCacheError, SolcCache, get_cache
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image

# Repo-relative .sbx dir (colima only shares $HOME)
_REPO_ROOT = Path(__file__).resolve().parents[4]
_SBX_ROOT = _REPO_ROOT / ".sbx"

_BUILD_LIMITS = StepLimits(cpus=2, memory="4g", pids=256, max_file=256 * 1024 * 1024)

# Image for build sandbox. In production comes from images.lock.json.
_BUILD_IMAGE = locked_image("evm-analyze")  # digest-pinned (09 4.4); None = fail closed

# SOKEN_SOLC_DIRECT=1: dev-only bypass, never set in production or tests
_DIRECT_SOLC = os.environ.get("SOKEN_SOLC_DIRECT", "0") == "1"

# Minimum solc version that supports appendCBOR output (X3)
_MIN_CBOR_VERSION = (0, 4, 7)


# ---------------------------------------------------------------------------
# Input sanitizer
# ---------------------------------------------------------------------------

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

    # Build and sanitize std-json input
    try:
        std_input = sanitize_std_input(_prepare_std_input(candidate))
    except InputSanitizationError as exc:
        return _fail(candidate, "not_checkable", f"input_sanitization_error: {exc}")

    _SBX_ROOT.mkdir(exist_ok=True)

    if work_dir is not None:
        return _run_build(candidate, std_input, solc_bin, Path(work_dir), cache)

    with tempfile.TemporaryDirectory(dir=_SBX_ROOT) as tmp:
        return _run_build(candidate, std_input, solc_bin, Path(tmp), cache)


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
    settings["outputSelection"] = _OUTPUT_SELECTION
    return {"language": "Solidity", "sources": sources, "settings": settings}


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
        return BuildResult(candidate=candidate, status="failed", reason="failed",
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
