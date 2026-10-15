"""Vyper analyze step (05 section 15): advisories (F30) always, Slither where it parses (UV5-19).

Slither drives Vyper through crytic-compile, which calls `vyper` from PATH and has no flag for a
binary path. The host-owned, read-only tool-config dir (mounted at /work/.soken-config, never
written by a container) holds bin/vyper as a symlink to the exact release in the read-only cache
and an empty slither.config.json passed with --config-file; PATH puts that bin first. Nothing in
the source tree configures a tool (config basenames are never materialized).

Files a container wrote are read only through sandbox/output.py (no links, regular files, size
caps); the step's own records go to the host-only `<attempt>.host/analyze/`.

Slither supports Vyper on a best-effort basis (its own message: "Vyper != 0.3.7 support is a best
effort"). When it does not produce a result the step is `degraded` with `not_run: [slither]`,
never "no leads": the advisory leads still stand and the coverage says Slither did not run.
Semgrep Vyper rules are not part of this pipeline yet (05 8.1 row "semgrep": open).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from soken_review.adapters.base import BuildResult, Lead
from soken_review.adapters.evm.compiler_bugs import CompilerBugReport
from soken_review.adapters.vyper.advisories import vyper_report
from soken_review.adapters.vyper.compiler import PLATFORM_DIR, CompilerCacheError, VyperCache

_SLITHER_VERSION = "0.11.6"


def advisory_report(result: BuildResult) -> CompilerBugReport:
    from soken_review.adapters.evm.analyze import build_input, build_output

    compiler = result.candidate.compiler
    if compiler is None or not result.work_dir:
        return CompilerBugReport("not_run", "compiler_version_unknown")
    work_dir = Path(result.work_dir)
    std_input = build_input(work_dir)
    if std_input is None:
        return CompilerBugReport("not_run", "build_output_missing", compiler.version)
    output = build_output(work_dir)  # host-only copy; None = advisories from text and tokens only
    return vyper_report(compiler.version, compiler.version_pinned_by, std_input,
                        output if isinstance(output, dict) else None)


def analyze(result: BuildResult) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
    from soken_review.adapters.evm.analyze import (
        _ANALYZE_IMAGE,
        _ANALYZE_LIMITS,
        _NOISE_DETECTORS,
        _SLITHER_CONFIG,
        SBX_MOUNT,
        TOOL_CONFIG_MOUNT,
        _build_leads,
        _materialize_sources,
        host_dir,
        prepare_analyze_dir,
        read_sandbox_json,
        tool_config_mounts,
        write_records,
    )
    from soken_review.sandbox.profile import docker_argv, sandbox_writable_dir

    if result.status != "ok" or not result.work_dir:
        return [], {"status": "not_run", "reason": "build_failed"}, {}
    work_dir = Path(result.work_dir)
    out_dir = prepare_analyze_dir(work_dir)
    proj_dir = out_dir / "proj"
    if not _materialize_sources(work_dir, proj_dir):
        return [], {"status": "not_run", "reason": "project_materialization_failed"}, {}

    adv = advisory_report(result)
    raw: list[dict] = list(adv.raw_leads)
    slither_reason = None
    slither_raw = None

    entry = (result.candidate.entry_contract or "").rpartition(":")[0] or None
    try:
        binary = VyperCache().binary(result.candidate.compiler.version) if result.candidate.compiler else None
    except CompilerCacheError:
        binary = None
    src_dir = proj_dir / "src"
    target = (src_dir / entry).resolve() if entry else None
    if (
        binary is None or target is None or entry.startswith("-")
        or not target.is_relative_to(src_dir.resolve()) or not target.is_file()
    ):
        slither_reason = "entry_or_compiler_missing"
    elif _ANALYZE_IMAGE is None or not shutil.which("docker"):
        slither_reason = "sandbox_unavailable"
    else:
        mounts = tool_config_mounts(work_dir)
        # a second writable dir the host never reads: PyInstaller leaves trees (links) behind
        vytmp = sandbox_writable_dir(out_dir / "vytmp")
        mounts.append((vytmp.resolve(), "/work/analyze/vytmp", False))
        bin_dir = host_dir(work_dir) / "tool-config" / "bin"
        bin_dir.mkdir(exist_ok=True)
        link = bin_dir / "vyper"
        link.unlink(missing_ok=True)
        link.symlink_to(f"/cache/{PLATFORM_DIR}/{binary.name}")  # resolved inside the sandbox
        out_json = out_dir / "sbx" / "slither_out.json"
        argv = docker_argv(
            step="analyze", image=_ANALYZE_IMAGE, work_dir=work_dir, cache_dir=VyperCache().root,
            limits=_ANALYZE_LIMITS,
            # PyInstaller vyper unpacks into TMPDIR and maps it executable; /tmp is noexec
            env={"HOME": "/tmp", "PATH": f"{TOOL_CONFIG_MOUNT}/bin:/usr/local/bin:/usr/bin:/bin",
                 "TMPDIR": "/work/analyze/vytmp"},
            command=["slither", "./" + entry, "--json", f"{SBX_MOUNT}/{out_json.name}",
                     "--disable-color", "--config-file", f"{TOOL_CONFIG_MOUNT}/{_SLITHER_CONFIG}"],
            runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
            workdir="/work/" + src_dir.relative_to(work_dir).as_posix(),
            mounts=mounts,
        )
        try:
            subprocess.run(argv, capture_output=True, timeout=900, check=False)
        except subprocess.TimeoutExpired:
            slither_reason = "slither_timeout"
        data = read_sandbox_json(out_dir / "sbx", out_json.name) if slither_reason is None else None
        if isinstance(data, dict) and data.get("success"):
            slither_raw = []
            for det in data.get("results", {}).get("detectors", []):
                if det.get("check", "") in _NOISE_DETECTORS:
                    continue
                for el in det.get("elements", []):
                    loc = el.get("source_mapping", {})
                    lines = loc.get("lines") or [1]
                    slither_raw.append({
                        "tool": f"slither@{_SLITHER_VERSION}", "rule_id": det.get("check", ""),
                        "severity_raw": det.get("impact", ""), "file": loc.get("filename_relative") or "",
                        "start": lines[0], "end": lines[-1],
                    })
        elif slither_reason is None:
            err = data.get("error") if isinstance(data, dict) else "no readable output"
            slither_reason = "slither_failed: " + str(err or "")[:160]
    not_run = [] if slither_raw is not None else ["slither"]
    raw.extend(slither_raw or [])

    leads = _build_leads(raw)
    static_map: dict[str, Any] = {
        "status": "degraded" if not_run else "ok",
        "not_run": not_run,
        "reason": slither_reason,
        "language": "vyper",
        "contracts": [],
        "tool": f"slither@{_SLITHER_VERSION}",
        "compiler_advisories": {
            "status": adv.status, "reason": adv.reason, "version": adv.version, "rows": adv.advisories,
        },
    }
    read_plan: dict[str, Any] = {"entries": [], "version": "1"}
    write_records(work_dir, leads, static_map, read_plan)
    return leads, static_map, read_plan
