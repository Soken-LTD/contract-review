"""Build and analyze a Solana candidate from a cloned repo.

Usage:
    SOKEN_SOLANA_DIRECT=1 python scripts/build_case_solana.py \
        --repo https://github.com/coral-xyz/anchor \
        --program counter \
        --out soken-output/counter

Produces:
  <out>/candidates.json
  <out>/leads.json
  <out>/static_map.json
  <out>/chain_extras.json
  <out>/build_result.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from soken_review.adapters.solana.build import build
from soken_review.adapters.solana.analyze import analyze
from soken_review.adapters.solana.fetch import _clone_repo, _make_candidate, _walk_source_files
from soken_review.adapters.solana.detect import detect_framework_from_files


def main():
    parser = argparse.ArgumentParser(description="Build and analyze a Solana program")
    parser.add_argument("--repo", required=True, help="Git repo URL")
    parser.add_argument("--program", default=None, help="Program subdirectory (e.g. programs/counter)")
    parser.add_argument("--commit", default=None, help="Git commit hash (40 hex)")
    parser.add_argument("--out", default="soken-output/solana-build", help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Cloning {args.repo} ...")
    with tempfile.TemporaryDirectory() as tmp:
        files = _clone_repo(args.repo, args.commit, Path(tmp))

    if not files:
        print("[-] Clone failed or empty", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Got {len(files)} source files")

    framework = detect_framework_from_files(files) or "native"
    print(f"[+] Framework: {framework}")

    candidate = _make_candidate(files, provider="repo", repo_url=args.repo, commit=args.commit, framework=framework)

    # If --program is given, set mount_path
    if args.program:
        candidate.settings["mount_path"] = args.program
        object.__setattr__(candidate, "mount_path", args.program)  # belt-and-suspenders

    # Save candidate
    cand_data = {
        "provider": candidate.provider,
        "sha256": candidate.sha256,
        "language": candidate.language,
        "framework": framework,
        "file_count": len(candidate.files),
        "repo_url": candidate.source_url,
        "fetched_at": candidate.fetched_at,
    }
    (out_dir / "candidates.json").write_text(json.dumps([cand_data], indent=2))
    print(f"[+] Saved candidates.json")

    print("[+] Building ...")
    result = build(candidate, work_dir=out_dir / "work")
    build_data = {
        "status": result.status,
        "nsloc": result.nsloc,
        "reason": result.reason,
        "stderr_head": result.stderr_head,
        "work_dir": result.work_dir,
    }
    (out_dir / "build_result.json").write_text(json.dumps(build_data, indent=2))
    print(f"[+] Build: {result.status} (nsloc={result.nsloc})")

    if result.status != "ok":
        print(f"[-] Build failed: {result.reason}: {result.stderr_head}", file=sys.stderr)
        sys.exit(1)

    print("[+] Analyzing ...")
    leads, static_map, read_plan = analyze(result)
    (out_dir / "leads.json").write_text(json.dumps(leads, indent=2))
    (out_dir / "static_map.json").write_text(json.dumps(static_map, indent=2, default=str))
    print(f"[+] Leads: {len(leads)}, static_map keys: {list(static_map.keys())}")

    print(f"[+] Done. Output in {out_dir}/")


if __name__ == "__main__":
    main()
