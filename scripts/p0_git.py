"""P0-GIT (09 5.2, UV9-5): depth-1 filtered fetch by sha per git host, and the 09 3.6 exit codes.

    uv run python scripts/p0_git.py [--direct] [--out report.json]

Default: every case runs through `materialize_repo` (git-fetch image by digest, solana egress
family through smokescreen, runtime from SOKEN_SANDBOX_RUNTIME or runsc-egress). `--direct` runs
the materializer on this host (no sandbox) for a quick check. A host whose non-tip sha fetch fails
leaves the allowlist (UV9-5). Exit 1 if any case differs from its expected exit code.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (case, host, url, commit, ref, expected exit). Non-tip shas: commits of release tags.
CASES = [
    ("github non-tip sha", "github.com", "https://github.com/solana-program/token",
     "1f61242183ea9b43d37b47a1b4f745eb1beb32de", None, 0),
    ("github short sha (blobless resolve)", "github.com", "https://github.com/solana-program/token",
     "1f61242", None, 0),
    ("github annotated tag ref", "github.com", "https://github.com/solana-program/token",
     None, "program@v8.0.0", 0),
    ("github unknown sha", "github.com", "https://github.com/solana-program/token", "0" * 40, None, 21),
    ("github missing ref", "github.com", "https://github.com/solana-program/token", None,
     "no-such-ref-soken-p0", 24),
    ("gitlab non-tip sha", "gitlab.com", "https://gitlab.com/gitlab-org/gitlab-shell",
     "754e11b7188865cf16aae0a9f27d9b16f208f601", None, 0),
    ("codeberg non-tip sha", "codeberg.org", "https://codeberg.org/Codeberg/pages-server",
     "838a5bda92846725034218500ea1f498eb2e5d6f", None, 0),
    ("host off the allowlist", "bitbucket.org", "https://bitbucket.org/atlassian/python-bitbucket",
     "0" * 40, None, 25),
]


def run_case(case, root: Path, direct: bool) -> dict:
    name, host, url, commit, ref, expected = case
    job = root / name.replace(" ", "_").replace("(", "").replace(")", "")
    job.mkdir(parents=True)
    t0 = time.time()
    if direct:
        from soken_review.sandbox import git_materializer as gm

        (job / "src").mkdir()
        args = ["--url", url, "--out", str(job / "src"), "--manifest", str(job / "manifest.json"),
                "--scratch", str(job / "tmp")]
        args += ["--commit", commit] if commit else ["--ref", ref]
        code = gm.main(args)
        manifest = json.loads((job / "manifest.json").read_text())
    else:
        from soken_review.sandbox.repo_fetch import materialize_repo

        res = materialize_repo(url, job, "solana", commit=commit, ref=ref)
        code, manifest = res.exit_code, res.manifest
    return {
        "case": name, "host": host, "expected": expected, "exit": code, "ok": code == expected,
        "resolved_commit": manifest.get("resolved_commit"), "files": len(manifest.get("files") or []),
        "too_large": len(manifest.get("too_large") or []), "submodules": len(manifest.get("submodules") or []),
        "error": (manifest.get("error") or {}).get("detail"), "seconds": round(time.time() - t0, 1),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--direct", action="store_true")
    p.add_argument("--out")
    args = p.parse_args()
    (ROOT / ".sbx").mkdir(exist_ok=True)
    rows = []
    with contextlib.nullcontext(tempfile.mkdtemp(dir=ROOT / ".sbx")) as tmp:  # uid 10001 files: a root supervisor removes them
        for case in CASES:
            row = run_case(case, Path(tmp), args.direct)
            rows.append(row)
            print(json.dumps(row), flush=True)
    hosts = {}
    for r in rows:
        if r["expected"] == 0 and "non-tip" in r["case"]:
            hosts[r["host"]] = "keep" if r["ok"] else "leaves allowlist (UV9-5)"
    report = {"mode": "direct" if args.direct else "sandbox", "cases": rows, "hosts": hosts}
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2))
    print(json.dumps({"hosts": hosts, "failed": [r["case"] for r in rows if not r["ok"]]}))
    return 0 if all(r["ok"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
