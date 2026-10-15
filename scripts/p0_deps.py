"""P0-DEPS (09 4.3, UV9-3): the family egress proxy lets allowlisted hosts through and nothing else.

    uv run python scripts/p0_deps.py [--out report.json]

Needs `python -m soken_review.sandbox.egress up <family>` for evm and solana. Each probe is a
`deps` step container (git-fetch image by digest, runtime from SOKEN_SANDBOX_RUNTIME or
runsc-egress) on the internal family network; it requests each URL through the proxy, and once
with the proxy cleared to show there is no direct route. Exit 1 on any unexpected result.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from soken_review.sandbox.egress import network_name
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

ROOT = Path(__file__).resolve().parents[1]
LIMITS = StepLimits(cpus=1, memory="512m", pids=64, max_file=64 * 1024 * 1024)

PROBE = r"""
import json, os, sys, urllib.request
out = []
for url in sys.argv[1:]:
    direct = url.startswith("direct:")
    url = url.removeprefix("direct:")
    handler = urllib.request.ProxyHandler({} if direct else {"https": os.environ["HTTPS_PROXY"], "http": os.environ["HTTP_PROXY"]})
    try:
        with urllib.request.build_opener(handler).open(url, timeout=15) as r:
            out.append({"url": url, "direct": direct, "result": "allowed", "status": r.status})
    except urllib.error.HTTPError as e:
        # 407 = smokescreen refused a plain-http request; any other HTTP status came from the host
        out.append({"url": url, "direct": direct, "result": "blocked" if e.code == 407 else "allowed", "status": e.code})
    except Exception as e:
        out.append({"url": url, "direct": direct, "result": "blocked", "error": str(e)[:160]})
print(json.dumps(out))
"""

# family -> [(url, expected)]
CASES = {
    "solana": [
        ("https://index.crates.io/config.json", "allowed"),
        ("https://static.crates.io/crates/serde/serde-1.0.0.crate", "allowed"),
        ("https://github.com/solana-program/token.git/info/refs?service=git-upload-pack", "allowed"),
        ("https://codeberg.org/", "allowed"),
        ("https://registry.npmjs.org/", "blocked"),         # another family's host
        ("https://pypi.org/simple/", "blocked"),
        ("https://verify.osec.io/status-all/x", "blocked"),  # provider hosts are supervisor-only
        ("http://169.254.169.254/latest/meta-data/", "blocked"),
        ("direct:https://github.com/", "blocked"),           # no route without the proxy
    ],
    "evm": [
        ("https://registry.npmjs.org/", "allowed"),
        ("https://gitlab.com/gitlab-org/gitlab-shell.git/info/refs?service=git-upload-pack", "allowed"),
        ("https://index.crates.io/config.json", "blocked"),
        ("https://sourcify.dev/", "blocked"),
        ("https://api.etherscan.io/", "blocked"),
    ],
}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out")
    args = p.parse_args()
    image = locked_image("git-fetch")
    if not image:
        print("git-fetch image not pinned", file=sys.stderr)
        return 1
    rows, ok = [], True
    (ROOT / ".sbx").mkdir(exist_ok=True)
    for family, cases in CASES.items():
        with contextlib.nullcontext(tempfile.mkdtemp(dir=ROOT / ".sbx")) as tmp:  # uid 10001 files: a root supervisor removes them
            work = sandbox_writable_dir(Path(tmp) / "work")
            argv = docker_argv("deps", image, work, None, LIMITS, {"HOME": "/tmp"},
                               ["python3", "-I", "-c", PROBE, *[u for u, _ in cases]],
                               family_network=network_name(family))
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
        try:
            results = json.loads(proc.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            print(f"{family}: probe failed rc={proc.returncode} {proc.stderr[-500:]}", file=sys.stderr)
            return 1
        runtime = next(a for a in argv if a.startswith("--runtime=")).split("=", 1)[1]
        for (url, expected), res in zip(cases, results, strict=True):
            row = {"family": family, "runtime": runtime, **res, "expected": expected,
                   "ok": res["result"] == expected}
            ok &= row["ok"]
            rows.append(row)
            print(json.dumps(row), flush=True)
    if args.out:
        Path(args.out).write_text(json.dumps(rows, indent=2))
    print(json.dumps({"p0_deps": "pass" if ok else "fail", "cases": len(rows)}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
