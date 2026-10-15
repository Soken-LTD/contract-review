#!/usr/bin/env python3
"""Fail on any GitHub Actions `uses:` not pinned to a full commit SHA (repo rule, CI step).

    python3 scripts/check_actions_pinned.py [root]

Checks .github/workflows/*.yml|yaml and .github/actions/*/action.yml|yaml. Allowed:
  uses: owner/repo[/path]@<40 hex> # vX.Y.Z      (the version comment is required)
  uses: ./local/action                            (repo-local composite action)
  uses: docker://image@sha256:<64 hex>
Also fails when a workflow lacks a top-level `permissions:` block.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)\s*(?:#\s*(?P<comment>.*))?$")
SHA_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$")
DOCKER_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^v\d+(\.\d+){0,2}\b")


def check(root: Path) -> list[str]:
    files = []
    for pattern in ("workflows/*.yml", "workflows/*.yaml", "actions/*/action.yml", "actions/*/action.yaml"):
        files += sorted((root / ".github").glob(pattern))
    bad = []
    for f in files:
        text = f.read_text()
        for n, line in enumerate(text.splitlines(), 1):
            m = USES_RE.match(line)
            if not m:
                continue
            ref = m.group("ref").strip("'\"")
            if ref.startswith("./"):
                continue
            if DOCKER_RE.match(ref):
                continue
            if not SHA_RE.match(ref):
                bad.append(f"{f.relative_to(root)}:{n}: not pinned to a commit SHA: {ref}")
            elif not VERSION_RE.match((m.group("comment") or "").strip()):
                bad.append(f"{f.relative_to(root)}:{n}: missing '# vX.Y.Z' comment: {ref}")
        if "/workflows/" in f.as_posix() and not re.search(r"^permissions:", text, re.MULTILINE):
            bad.append(f"{f.relative_to(root)}: no top-level permissions block")
    return bad


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    bad = check(root)
    print("\n".join(bad) or "all actions pinned")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
