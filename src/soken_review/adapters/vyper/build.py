"""Vyper build inside the sandbox (05 section 15, 7; 09 4.1).

`vyper --standard-json` with the input on stdin (every release since 0.2.x reads it there), the
exact recorded release from the compiler cache, no network. The std-json input is the
candidate's own (Sourcify) or one composed from its files and settings; source keys and
search paths are checked like solc's (relative, no `..`, no backslash). Outputs land in
<work_dir>/out/{input,output}.json, the same place analyzers read solc builds from.

Auxdata and immutables of Vyper (F43, UV5-18) are left to the deployment comparison (13.1).
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.evm.build import (
    _BUILD_IMAGE,
    _BUILD_LIMITS,
    _SBX_ROOT,
    InputSanitizationError,
    _fail,
    _parse_artifacts,
    _safe_relative_path,
    write_host_build_copy,
    write_no_follow,
)
from soken_review.adapters.evm.compiler import CompilerCacheError
from soken_review.adapters.vyper.compiler import PLATFORM_DIR, VyperCache
from soken_review.sandbox.profile import docker_argv, sandbox_writable_dir

_OUTPUT_SELECTION = {"*": ["abi", "evm.bytecode", "evm.deployedBytecode", "ast"]}
_EVM_VERSIONS = frozenset({
    "byzantium", "constantinople", "petersburg", "istanbul", "berlin", "paris", "shanghai", "cancun", "prague",
})
_DIRECT = os.environ.get("SOKEN_VYPER_DIRECT", "0") == "1"  # dev only, never in production or tests
# Vyper 0.2/0.3 compiles large pools in minutes (CRV/ETH 0.3.0: 358 s under amd64 emulation on arm64);
# the 09 step wall bounds the whole step, this only stops a hung compiler.
_TIMEOUT = 900


def prepare_std_input(candidate: Candidate) -> dict[str, Any]:
    """The Vyper std-json input: the candidate's own, or composed from files + settings."""
    if candidate.std_json_input:
        inp = copy.deepcopy(candidate.std_json_input)
    else:
        inp = {
            "language": "Vyper",
            "sources": {path: {"content": content} for path, content in candidate.files.items()},
            "settings": copy.deepcopy(candidate.settings or {}),
        }
    inp["language"] = "Vyper"
    settings = inp.setdefault("settings", {})
    settings["outputSelection"] = _OUTPUT_SELECTION
    return sanitize_vyper_input(inp)


def sanitize_vyper_input(inp: dict) -> dict:
    out = copy.deepcopy(inp)
    for key, src in list((out.get("sources") or {}).items()):
        if not _safe_relative_path(key):
            raise InputSanitizationError(f"unsafe source key: {key!r}")
        if isinstance(src, dict):
            src.pop("urls", None)  # never read by path or URL inside the sandbox
    for key in list((out.get("interfaces") or {}).keys()):
        if not _safe_relative_path(key):
            raise InputSanitizationError(f"unsafe interface key: {key!r}")
    settings = out.setdefault("settings", {})
    paths = settings.get("search_paths")
    if paths is not None and (
        not isinstance(paths, list)
        or not all(isinstance(p, str) and (p == "." or _safe_relative_path(p)) for p in paths)
    ):
        raise InputSanitizationError("unsafe search_paths")
    evm = settings.get("evmVersion")
    if evm is not None and evm not in _EVM_VERSIONS:
        raise InputSanitizationError(f"unknown evmVersion {evm!r}")
    return out


def build(candidate: Candidate, cache_dir: Path | None = None, work_dir: Path | None = None) -> BuildResult:
    version = candidate.compiler.version if candidate.compiler else None
    if not version:
        return _fail(candidate, "not_checkable", "compiler_version_unknown")
    cache = VyperCache(cache_dir)
    try:
        binary = cache.binary(version)
    except CompilerCacheError as exc:
        return _fail(candidate, "not_checkable", exc.reason_detail)
    try:
        std_input = prepare_std_input(candidate)
    except InputSanitizationError as exc:
        return _fail(candidate, "not_checkable", f"input_sanitization_error: {exc}")

    if work_dir is not None:
        return _run(candidate, std_input, binary, cache, Path(work_dir))
    _SBX_ROOT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=_SBX_ROOT) as tmp:
        return _run(candidate, std_input, binary, cache, Path(tmp))


def _invoke(binary: Path, stdin: bytes, work_dir: Path, cache: VyperCache) -> tuple[bytes, str]:
    if _DIRECT:
        proc = subprocess.run([str(binary), "--standard-json"], input=stdin, capture_output=True, timeout=_TIMEOUT, check=False)
    else:
        if not shutil.which("docker") or _BUILD_IMAGE is None:
            raise RuntimeError("sandbox_unavailable")
        # The Vyper release is a PyInstaller one-file binary: it unpacks shared libraries into
        # TMPDIR and maps them executable. /tmp is noexec (09 4.2), so it gets a job-local dir.
        tmp = work_dir / ".vyper-tmp"
        if tmp.is_symlink():
            tmp.unlink()
        sandbox_writable_dir(tmp)
        argv = docker_argv(
            step="build",
            image=_BUILD_IMAGE,
            work_dir=work_dir,
            cache_dir=cache.root,
            limits=_BUILD_LIMITS,
            env={"TMPDIR": "/work/.vyper-tmp"},
            command=[f"/cache/{PLATFORM_DIR}/{binary.name}", "--standard-json"],
            runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
            stdin=True,
        )
        try:
            proc = subprocess.run(argv, input=stdin, capture_output=True, timeout=_TIMEOUT, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("build_timeout") from exc
    stderr = proc.stderr.decode(errors="replace")
    return proc.stdout, "\n".join(stderr.splitlines()[:20])


def _run(candidate: Candidate, std_input: dict, binary: Path, cache: VyperCache, work_dir: Path) -> BuildResult:
    out_dir = work_dir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        stdout, stderr_head = _invoke(binary, json.dumps(std_input).encode(), work_dir, cache)
    except RuntimeError as exc:
        return _fail(candidate, "not_checkable", str(exc))
    except OSError as exc:
        return _fail(candidate, "failed", str(exc)[:200])
    if not stdout:
        return BuildResult(candidate=candidate, status="failed", reason="failed", stderr_head=stderr_head or "no output")
    try:
        output = json.loads(stdout)
    except (json.JSONDecodeError, RecursionError) as exc:  # deeply nested output: a failed build
        return BuildResult(candidate=candidate, status="failed", reason="failed", stderr_head=f"json decode: {exc}\n{stderr_head}")
    fatal = [e for e in output.get("errors", []) if e.get("severity", "error") == "error"]
    if fatal:
        msg = "; ".join(str(e.get("formattedMessage") or e.get("message") or e)[:200] for e in fatal[:5])
        return BuildResult(candidate=candidate, status="failed", reason="failed", stderr_head=(msg + "\n" + stderr_head)[:2000])

    try:  # the container had /work mounted: write without following links (09 3.5)
        write_no_follow(out_dir, "output.json", json.dumps(output).encode())
        write_no_follow(out_dir, "input.json", json.dumps(std_input).encode())
        write_host_build_copy(work_dir, std_input, output)
    except OSError as exc:
        return _fail(candidate, "failed", f"unsafe_build_output: {exc}"[:200])
    return BuildResult(
        candidate=candidate,
        status="ok",
        artifacts=_parse_artifacts(output),
        compiler_advisories=[],
        nsloc=_count_vyper_nsloc(candidate.files),
        work_dir=str(work_dir),
        stderr_head=stderr_head or None,
    )


def _count_vyper_nsloc(files: dict[str, str]) -> int:
    """Vyper: `#` comments and docstrings removed, blanks skipped."""
    total = 0
    for content in files.values():
        in_doc = False
        for line in content.splitlines():
            s = line.strip()
            if s.startswith(('"""', "'''")):
                if not (len(s) >= 6 and s.endswith(s[:3])):
                    in_doc = not in_doc
                continue
            if in_doc or not s or s.startswith("#"):
                continue
            total += 1
    return total
