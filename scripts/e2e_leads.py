"""W1-W4 exit check (10 8.3): fetched and built EVM cases reach `review_leads` locally.

    uv run python scripts/e2e_leads.py [--require=RULE_PREFIX] .sbx/cases/<case> [...]

For each case dir written by fetch_case.py + build_case.py: pin the candidate sources into a job
dir, place leads.json, then call review_leads and review_read_code through the MCP client and
check that the first lead's lines are readable from the pin.

`--require=compiler.` (any rule_id prefix): the case FAILS unless review_leads lists at least one
lead whose rule_id starts with the prefix, and every such lead's lines are readable from the pin.
`--require=` can be given per case as `<case>:<prefix>` too.
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

from mcp import Client

import soken_review.tools  # noqa: F401  registers handlers
from soken_review.db.job_repo import new_job_id
from soken_review.mapping.step import run_map_step
from soken_review.pinning.store import PinnedSource
from soken_review.server import SokenServer
from soken_review.tools.context import MemoryJobContext
from soken_review.tools.read import set_context


async def _read(client: Client, job_id: str, lead: dict) -> str | None:
    read = await client.call_tool(
        "review_read_code",
        {"job_id": job_id, "path": lead["file"], "start_line": lead["start"], "end_line": lead["end"]},
    )
    if read.is_error or '"accepted":false' in read.content[0].text:
        return f"FAIL read {lead['file']}:{lead['start']}-{lead['end']}: {read.content[0].text[:200]}"
    return None


async def check_case(case_dir: Path, root: Path, ctx: MemoryJobContext, require: str | None) -> str:
    cand = json.loads((case_dir / "candidates.json").read_text())[0]
    src = case_dir / f"{cand['provider']}_0"
    files = {p.relative_to(src).as_posix(): p.read_bytes() for p in sorted(src.rglob("*")) if p.is_file()}
    job_id = new_job_id()
    PinnedSource.from_files(files).persist(root, job_id)
    # The map step writes map/ and the J1-J5 flags at pin time (04 12); review_read_code needs them.
    # Solc output comes from the build's host-only copy; a Vyper build has no solc AST.
    out_copy = case_dir / "work.host" / "build" / "output.json"
    solc = cand.get("language", "solidity") == "solidity" and out_copy.is_file()
    run_map_step(root, job_id, solc_output_path=out_copy if solc else None, build_ok=solc)
    leads = json.loads((case_dir / "leads.json").read_text())
    (root / job_id / "leads.json").write_text(json.dumps(leads))
    ctx.set_state(job_id, "ready")

    async with Client(SokenServer()) as client:
        listed = await client.call_tool("review_leads", {"job_id": job_id})
        text = listed.content[0].text
        if listed.is_error or (leads and leads[0]["id"] not in text):
            return f"FAIL review_leads: {text[:200]}"
        if not leads:
            return "FAIL no leads" if require else "ok, 0 leads"
        first = leads[0]
        if (err := await _read(client, job_id, first)) is not None:
            return err
        note = ""
        if require:
            wanted = [lead for lead in leads if lead["rule_id"].startswith(require)]
            if not wanted:
                return f"FAIL no {require}* lead among {len(leads)}"
            listed_by_rule: dict[str, str] = {}
            for rid in sorted({lead["rule_id"] for lead in wanted}):
                res = await client.call_tool("review_leads", {"job_id": job_id, "detector": rid, "page_size": 50})
                if res.is_error:
                    return f"FAIL review_leads detector={rid}: {res.content[0].text[:200]}"
                listed_by_rule[rid] = res.content[0].text
            for lead in wanted:
                if lead["id"] not in listed_by_rule[lead["rule_id"]]:
                    return f"FAIL {lead['id']} missing from review_leads detector={lead['rule_id']}"
                if (err := await _read(client, job_id, lead)) is not None:
                    return err
            note = "; " + ", ".join(
                f"{lead['id']} {lead['rule_id']} {lead['severity_norm']} at {lead['file']}:{lead['start']}" for lead in wanted
            ) + " listed and readable"
    return f"ok, {len(leads)} leads, first {first['id']} {first['category']} at {first['file']}:{first['start']} readable{note}"


async def main(argv: list[str]) -> int:
    default_require = next((a.split("=", 1)[1] for a in argv if a.startswith("--require=")), None)
    paths = [a for a in argv if not a.startswith("--")]
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        ctx = MemoryJobContext(root)
        set_context(ctx)
        for p in paths:
            path, _, prefix = p.partition(":")
            result = await check_case(Path(path), root, ctx, prefix or default_require)
            failed += result.startswith("FAIL")
            print(f"{Path(path).name}: {result}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
