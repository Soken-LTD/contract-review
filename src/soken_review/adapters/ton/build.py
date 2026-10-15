"""TON build step: FunC / Tact / Tolk compilation inside the sandbox (plan v4 06 4.2, 09 3.5).

build(candidate, work_dir) -> BuildResult

One build = one `docker run` of the ton-build image, offline, read-only root, uid 10001. The
container gets the attempt dir at /work (writable, owned by uid 10001) and the sources at
/work/src (read-only). It writes code cell BoC files only. This process then reads those files
(regular file, size cap, no symlinks) and computes every root cell hash itself with
`cell.root_info` (06 2.4: a hash written by a container never reaches `Out`). Each artifact is
`Artifact(contract=<target>, creation=<boc hex>, runtime=<supervisor hash>)`.

The compiler scripts run from the image (/opt/ton-node/node_scripts), never from /work, so a
file in the job dir cannot replace them.

Trust scan (06 3.3.4) runs first and sets `candidate.untrusted_inputs`; compiler params from a
verifier bundle outside the worker allowlist fail the attempt with `untrusted_args`.

Compilers in the image (docker/ton-build/package.json):
  FunC: @ton-community/func-js FuncCompiler with the worker's 12 func-js-bin versions (F32)
  Tact: @tact-lang/compiler 1.6.13
  Tolk: @ton/tolk-js 0.12.0
A version the image does not carry is `unsupported_toolchain`, never a silent substitution.

Host execution only behind SOKEN_TON_BUILD_DIRECT=1 (dev only, never default, never in CI).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from soken_review.adapters.base import Artifact, BuildResult, Candidate
from soken_review.adapters.ton.cell import BocError, root_info
from soken_review.adapters.ton.tact_config import check_config
from soken_review.adapters.ton.trust_scan import scan_files, scan_params
from soken_review.adapters.ton.units import count_nsloc_ton, safe_store_path
from soken_review.sandbox.output import UnsafeOutput, read_output_files
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SBX_ROOT = _REPO_ROOT / ".sbx"

_BUILD_LIMITS = StepLimits(cpus=2, memory="4g", pids=256, max_file=128 * 1024 * 1024)

_BUILD_IMAGE = locked_image("ton-build")

# Dev-only bypass (never default, never in CI)
_DIRECT = os.environ.get("SOKEN_TON_BUILD_DIRECT", "0") == "1"

_NODE_SCRIPTS = Path(__file__).parent / "node_scripts"
_HANDLER = re.compile(r"\brecv_internal\s*\(|\bonInternalMessage\s*\(|^\s*contract\s+\w+", re.MULTILINE)
_TACT_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_IMAGE_SCRIPTS = "/opt/ton-node/node_scripts"

_MAX_OUTPUT_BOC = 4 * 1024 * 1024
_MAX_OUTPUT_FILES = 64

_BINARY_SOURCE_EXTS = frozenset({".boc", ".cell", ".fif", ".fift", ".bag"})

# FunC: the verifier compiler worker's func-js-bin versions (acton compiler-worker package.json,
# F32), installed in the image as npm aliases `func-<version>`. "latest" = the func-js default bin.
FUNC_VERSIONS = frozenset({
    "0.2.0", "0.3.0", "0.4.0", "0.4.1", "0.4.2", "0.4.3", "0.4.4",
    "0.4.4-newops", "0.4.4-newops.1", "0.4.5", "0.4.6", "0.4.6-wasmfix.0", "latest",
})
TACT_VERSIONS = frozenset({"1.6.13"})
TOLK_VERSIONS = frozenset({"0.12.0"})
_INSTALLED = {"func": FUNC_VERSIONS, "tact": TACT_VERSIONS, "tolk": TOLK_VERSIONS}
_DEFAULT_VERSION = {"func": "latest", "tact": "1.6.13", "tolk": "0.12.0"}


def _validate_version(version: str, language: str) -> str | None:
    """The version if the image carries it, else None (`unsupported_toolchain`)."""
    return version if version in _INSTALLED.get(language, frozenset()) else None


def _candidate_language(candidate: Candidate) -> str:
    lang = candidate.language.lower()
    return {"fift": "func"}.get(lang, lang)


# ── container invocation ──────────────────────────────────────────────────


def _run(script: str, args: list[str], work_dir: Path, timeout: int) -> tuple[str, int]:
    """Run one node script; sandboxed unless DIRECT. Returns (stderr, returncode)."""
    if _DIRECT:
        node = shutil.which("node") or "node"
        host_args = [a.replace("/work", str(work_dir), 1) if a.startswith("/work") else a for a in args]
        cmd = [node, str(_NODE_SCRIPTS / script), *host_args]
    else:
        if _BUILD_IMAGE is None or not shutil.which("docker"):
            return "sandbox_unavailable", 1
        cmd = docker_argv(
            step="build",
            image=_BUILD_IMAGE,
            work_dir=work_dir,
            cache_dir=None,
            limits=_BUILD_LIMITS,
            env={"HOME": "/tmp"},
            command=["node", f"{_IMAGE_SCRIPTS}/{script}", *args],
            runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
            mounts=[(work_dir, "/work", False), (work_dir / "src", "/work/src", True)],
        )
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return "timeout", 1
    return proc.stderr.decode(errors="replace"), proc.returncode


def _read_output(work_dir: Path, pattern: str) -> tuple[dict[str, bytes], str]:
    """Container-written BoCs under /work/out via `sandbox.output` (no symlink, regular files only)."""
    try:
        return read_output_files(work_dir / "out", pattern, _MAX_OUTPUT_FILES, _MAX_OUTPUT_BOC), ""
    except FileNotFoundError:
        return {}, "no output dir"
    except UnsafeOutput as exc:
        logger.warning("ton build output rejected: %s", exc)
        return {}, f"unsafe output: {exc}"


def _write_sources(files: dict[str, str], src_dir: Path) -> None:
    """Write candidate files under src_dir; binary blobs and unsafe paths are skipped."""
    src_base = src_dir.resolve()
    for path, content in files.items():
        if Path(path).suffix.lower() in _BINARY_SOURCE_EXTS:
            continue
        safe = safe_store_path(path)
        if safe is None:
            continue
        dest = (src_dir / safe).resolve()
        if not dest.is_relative_to(src_base):
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def _entry(candidate: Candidate, exts: tuple[str, ...]) -> str | None:
    """Declared entry, else (06 4.2, files without config) the first file, in path order, that
    defines a message handler (`recv_internal`, `onInternalMessage`, a Tact `contract`), else the
    first file of the language."""
    entry = (candidate.settings or {}).get("entry")
    if not entry:
        paths = sorted(p for p in candidate.files if p.endswith(exts))
        entry = next((p for p in paths if _HANDLER.search(candidate.files[p])), paths[0] if paths else None)
    return safe_store_path(str(entry)) if entry else None


# ── per-language builds: each returns ({target: boc bytes}, error) ─────────


def _build_func(candidate: Candidate, version: str, work_dir: Path) -> tuple[dict[str, bytes], str]:
    entry = _entry(candidate, (".fc", ".func"))
    if not entry:
        return {}, "no FunC entrypoint"
    args = [version, f"/work/src/{entry}", "/work/out/output.boc", "/work/src"]
    targets = (candidate.settings or {}).get("func_targets") or []
    if targets:
        safe_targets = [safe_store_path(str(t)) for t in targets]
        if None in safe_targets:
            return {}, "unsafe FunC target path"
        (work_dir / "targets.json").write_text(json.dumps(safe_targets), encoding="utf-8")
        args.append("/work/targets.json")
    stderr, rc = _run("compile_func.mjs", args, work_dir, timeout=180)
    found, why = _read_output(work_dir, "output.boc") if rc == 0 else ({}, "")
    boc = found.get("output.boc")
    if boc is None:
        return {}, f"func compile error (rc={rc}): {why} {stderr[-500:]}"
    return {entry: boc}, ""


def _build_tolk(candidate: Candidate, version: str, work_dir: Path) -> tuple[dict[str, bytes], str]:
    entry = _entry(candidate, (".tolk",))
    if not entry:
        return {}, "no Tolk entrypoint"
    stderr, rc = _run("compile_tolk.mjs", [version, f"/work/src/{entry}", "/work/out/output.boc"], work_dir, timeout=180)
    found, why = _read_output(work_dir, "output.boc") if rc == 0 else ({}, "")
    boc = found.get("output.boc")
    if boc is None:
        return {}, f"tolk compile error (rc={rc}): {why} {stderr[-500:]}"
    return {entry: boc}, ""


def _build_tact(candidate: Candidate, version: str, work_dir: Path) -> tuple[dict[str, bytes], str]:
    """Tact: config at /work/tact.config.json (VFS jail root /work), output /work/out.

    Every `*.code.boc` the compiler writes is a target (06 4.2: each project's contracts).
    """
    src_dir = work_dir / "src"
    config_path = src_dir / "tact.config.json"
    if config_path.exists():
        try:
            cfg = json.loads(config_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return {}, f"bad tact.config.json: {exc}"
        # Rebuilt from the Tact 1.6.13 schema allowlist (tact_config.py): name, path, and the
        # documented options and mode when every one is valid; output is always ./out. A config
        # with anything outside the allowlist compiles from name and path only (trust_scan has
        # already marked that candidate untrusted).
        projects, reasons = check_config(cfg)
        if not projects:
            return {}, "bad tact.config.json: no projects"
        rebuilt = []
        for i, proj in enumerate(projects):
            safe_p = safe_store_path(str(proj.get("path") or ""))
            if safe_p is None:
                return {}, "unsafe path in tact.config.json"
            name = str(proj.get("name") or "")
            entry_cfg: dict = {"name": name if _TACT_NAME.match(name) else f"p{i}", "path": "src/" + safe_p,
                               "output": "./out"}
            if not reasons:
                if proj["options"]:
                    entry_cfg["options"] = proj["options"]
                if "mode" in proj:
                    entry_cfg["mode"] = proj["mode"]
            rebuilt.append(entry_cfg)
        cfg = {"projects": rebuilt}
    else:
        entry = _entry(candidate, (".tact",))
        if not entry:
            return {}, "no Tact entrypoint"
        cfg = {"projects": [{"name": "contract", "path": f"./src/{entry}", "output": "./out"}]}
    (work_dir / "tact.config.json").write_text(json.dumps(cfg), encoding="utf-8")
    # recorded in provenance (tried[].build_config) and the report checks
    candidate.settings = {**(candidate.settings or {}), "tact_build_config": cfg}

    stderr, rc = _run("compile_tact.mjs", [version, "/work/tact.config.json", "/work/out"], work_dir, timeout=600)
    if rc != 0:
        return {}, f"tact compile error (rc={rc}): {stderr[-500:]}"
    found, why = _read_output(work_dir, "*.code.boc")
    out = {rel.rsplit("/", 1)[-1].removesuffix(".code.boc"): boc for rel, boc in found.items()}
    if not out:
        return {}, f"tact compile error: no *.code.boc read {why}"
    return out, ""


_BUILDERS = {"func": _build_func, "tact": _build_tact, "tolk": _build_tolk}


# ── Public API ────────────────────────────────────────────────────────────


def build(candidate: Candidate, work_dir: Path | None = None) -> BuildResult:
    """Compile a TON candidate once (06 4.2 `attempt`); hashes are computed here, not in the container.

    work_dir: an empty attempt dir (created if missing). One dir per attempt: a later attempt
    never sees files an earlier container wrote.
    """
    language = _candidate_language(candidate)
    if work_dir is not None:
        return _run_build(candidate, language, Path(work_dir))
    _SBX_ROOT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=_SBX_ROOT) as tmp:
        return _run_build(candidate, language, Path(tmp) / "attempt")


def _run_build(candidate: Candidate, language: str, work_dir: Path) -> BuildResult:
    reasons = scan_files(candidate.files)
    if reasons:
        candidate.untrusted_inputs = True
        logger.info("ton trust scan: %s", "; ".join(reasons[:5]))

    if language not in _BUILDERS:
        return _fail(candidate, "unsupported_toolchain", f"language {language}")
    bad_params = scan_params((candidate.settings or {}).get("verifier", {}).get("compiler", {}).get("params")
                             if candidate.provider == "ton_verifier" else None)
    if bad_params:
        return _fail(candidate, "untrusted_args", "; ".join(bad_params))
    requested = candidate.compiler.version if candidate.compiler else _DEFAULT_VERSION[language]
    version = _validate_version(requested, language)
    if version is None:
        return _fail(candidate, "unsupported_toolchain", f"{language} {requested} is not in the image")
    if not _DIRECT and _BUILD_IMAGE is None:
        return _fail(candidate, "sandbox_unavailable", "ton-build image not locked and no override")

    if work_dir.exists() and any(work_dir.iterdir()):
        return _fail(candidate, "sandbox_unavailable", "attempt dir is not empty")
    if _DIRECT:
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        sandbox_writable_dir(work_dir)
    src_dir = work_dir / "src"
    src_dir.mkdir()
    _write_sources(candidate.files, src_dir)
    if _DIRECT:
        (work_dir / "out").mkdir()
    else:
        sandbox_writable_dir(work_dir / "out")

    bocs, err = _BUILDERS[language](candidate, version, work_dir)
    if not bocs:
        return BuildResult(candidate=candidate, status="failed", reason="compile_error", stderr_head=_head(err),
                           work_dir=str(work_dir))

    artifacts: list[Artifact] = []
    hashes: dict[str, str] = {}
    for target, boc in bocs.items():
        try:
            info = root_info(boc)
        except BocError as exc:
            logger.warning("ton build output for %s is not a hashable BoC: %s", target, exc)
            continue
        hashes[target] = info.hash
        artifacts.append(Artifact(contract=target, creation=boc.hex(), runtime=info.hash,
                                  immutable_refs={}, link_refs={}, source_map="", storage_layout=None))
    if not artifacts:
        return BuildResult(candidate=candidate, status="failed", reason="compile_error",
                           stderr_head="output is not a code cell BoC", work_dir=str(work_dir))

    # Host-side record for analyzers and map; written by this process, never read back as a hash source.
    meta_dir = work_dir.parent / f"{work_dir.name}.host"
    meta_dir.mkdir(exist_ok=True)
    first = artifacts[0]
    (meta_dir / "build_meta.json").write_text(json.dumps({
        "language": language, "compiler_version": version, "hashes": hashes,
        "code_hash": first.runtime, "untrusted_inputs": candidate.untrusted_inputs,
        "trust_scan": reasons,
    }), encoding="utf-8")

    return BuildResult(
        candidate=candidate,
        status="ok",
        artifacts=artifacts,
        nsloc=sum(count_nsloc_ton(c, language) for c in candidate.files.values()),
        work_dir=str(work_dir),
    )


def _head(text: str) -> str:
    return "\n".join(text.strip().splitlines()[-20:])[:2000]


def _fail(candidate: Candidate, reason: str, detail: str = "") -> BuildResult:
    return BuildResult(candidate=candidate, status="failed", reason=reason, stderr_head=detail or None)

