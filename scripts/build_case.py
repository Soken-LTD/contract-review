#!/usr/bin/env python3
"""CLI tool: take a fetch-agent case directory and run build + analyze.

Usage:
    uv run python scripts/build_case.py <case_dir> [candidate_index]

Case directory layout (written by scripts/fetch_case.py):

    <case_dir>/
      case.json         # chain, address, block
      candidates.json   # list of Candidate fields from base.py (except files)
      <provider>_<i>/   # source tree of candidate i

Writes into <case_dir>/:
    build_result.json  # BuildResult fields (no artifacts bytes by default)
    leads.json         # list of lead.v1 documents
    static_map.json    # minimal Slither IR
    read_plan.json     # read plan stub

Exit codes:
    0  build OK
    1  build failed (details in build_result.json)
    2  invalid case directory
    3  build OK, analyzer did not run (degraded)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <case_dir>", file=sys.stderr)
        return 2

    case_dir = Path(sys.argv[1]).resolve()
    if not case_dir.is_dir():
        print(f"Error: {case_dir} is not a directory", file=sys.stderr)
        return 2

    # Layout written by scripts/fetch_case.py: candidates.json (list) + <provider>_<i>/ source trees.
    index = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    try:
        raw = json.loads((case_dir / "candidates.json").read_text())[index]
    except (OSError, ValueError, IndexError) as exc:
        print(f"Error reading candidates.json[{index}]: {exc}", file=sys.stderr)
        return 2
    files_dir = case_dir / f"{raw.get('provider', 'user')}_{index}"
    if not files_dir.is_dir():
        print(f"Error: {files_dir} not found", file=sys.stderr)
        return 2

    files: dict[str, str] = {}
    for src_file in sorted(files_dir.rglob("*")):
        if src_file.is_file():
            files[src_file.relative_to(files_dir).as_posix()] = src_file.read_text(encoding="utf-8")
    settings: dict = {}

    # Build Candidate
    from soken_review.adapters.base import Candidate, Compiler
    compiler_data = raw.get("compiler") or {}
    compiler = Compiler(
        version=compiler_data.get("version", ""),
        version_pinned_by=compiler_data.get("version_pinned_by", "user"),
    ) if compiler_data.get("version") else None

    candidate = Candidate(
        provider=raw.get("provider", "user"),
        files=files,
        sha256=raw.get("sha256", ""),
        language=raw.get("language", "solidity"),
        compiler=compiler,
        settings=settings or raw.get("settings", {}),
        std_json_input=raw.get("std_json_input"),
        entry_contract=raw.get("entry_contract"),
        explorer_verified=raw.get("explorer_verified", False),
        sourcify_match=raw.get("sourcify_match"),
        constructor_args_hex=raw.get("constructor_args_hex"),
        source_url=raw.get("source_url"),
        fetched_at=raw.get("fetched_at"),
    )

    # Run build
    print(f"Building {case_dir.name} ...", file=sys.stderr)
    from soken_review.adapters.evm.build import build

    build_work_dir = case_dir / "work"
    build_work_dir.mkdir(exist_ok=True)

    result = build(candidate, work_dir=build_work_dir)

    # Write build result (exclude large artifact bytes)
    build_out = {
        "status": result.status,
        "reason": result.reason,
        "nsloc": result.nsloc,
        "compiler_advisories": result.compiler_advisories,
        "stderr_head": result.stderr_head,
        "artifacts": [
            {
                "contract": a.contract,
                "creation_len": len(a.creation) // 2 if a.creation else 0,
                "runtime_len": len(a.runtime) // 2 if a.runtime else 0,
            }
            for a in result.artifacts
        ],
        "auxdata_ranges": {
            k: [[s, e] for s, e in v]
            for k, v in result.auxdata_ranges.items()
        },
        "work_dir": result.work_dir,
    }
    (case_dir / "build_result.json").write_text(json.dumps(build_out, indent=2), encoding="utf-8")

    if result.status != "ok":
        print(f"Build failed: {result.reason}", file=sys.stderr)
        return 1

    print(f"Build OK: {len(result.artifacts)} artifact(s), {result.nsloc} nSLOC", file=sys.stderr)

    # Run analyze
    print("Analyzing ...", file=sys.stderr)
    from soken_review.adapters.evm.analyze import analyze

    leads, static_map, read_plan = analyze(result)

    (case_dir / "leads.json").write_text(json.dumps(leads, indent=2), encoding="utf-8")
    (case_dir / "static_map.json").write_text(json.dumps(static_map, indent=2), encoding="utf-8")
    (case_dir / "read_plan.json").write_text(json.dumps(read_plan, indent=2), encoding="utf-8")

    if static_map.get("status") == "not_run":
        print(f"Analysis NOT RUN ({static_map.get('reason')}): job is analyzer_degraded (03 3.1)", file=sys.stderr)
        return 3
    high_count = sum(1 for lead in leads if lead.get("severity_norm") == "High")
    print(f"Analysis done: {len(leads)} lead(s) ({high_count} High). Results in {case_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
