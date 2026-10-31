"""Write contract/mcp/client_baseline.json: the fingerprint of an older released tool list.

Clients cache tools/list (claude.ai per connector, 2026-10-31 blind round 5: every MCP arm ran on a
list from 2026-10-23 or 2026-10-24). The server diffs the current bundle against this fingerprint
to name, in plain words, the tools, arguments and values a stale client cannot see
(soken_review.client_refresh). The fingerprint is the bundled schema of a git revision: tool names,
top-level input properties and top-level enum values.

    uv run python scripts/client_schema_baseline.py df83ada
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from soken_review import contract
from soken_review.client_refresh import fingerprint


def bundle_at(rev: str) -> list[dict]:
    raw = subprocess.run(["git", "archive", rev, "contract", "config"], cwd=REPO, check=True,
                         capture_output=True).stdout
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            tar.extractall(tmp, filter="data")
        root = Path(tmp)
        release = contract.load_release(root / "config" / "release.yaml")
        tools_file = root / "contract" / "mcp" / "tools.v1.json"
        source = json.loads(tools_file.read_text())
        out = []
        for tool in source["tools"]:
            schema = contract._inline(tool["inputSchema"], tools_file)
            schema = contract._drop_empty_enum_arrays(contract._fill_generated(schema, release))
            out.append({"name": tool["name"], "inputSchema": schema})
        contract._load_json.cache_clear()
        return out


def main() -> None:
    rev = sys.argv[1]
    date = subprocess.run(["git", "log", "-1", "--format=%cs", rev], cwd=REPO, check=True,
                          capture_output=True, text=True).stdout.strip()
    sha = subprocess.run(["git", "rev-parse", "--short=12", rev], cwd=REPO, check=True,
                         capture_output=True, text=True).stdout.strip()
    doc = {"rev": sha, "date": date, "tools": fingerprint(bundle_at(rev))}
    path = REPO / "contract" / "mcp" / "client_baseline.json"
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {path.relative_to(REPO)} ({len(doc['tools'])} tools, {date})")


if __name__ == "__main__":
    main()
