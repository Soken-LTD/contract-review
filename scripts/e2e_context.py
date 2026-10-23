#!/usr/bin/env python3
"""Context ingestion driver against a deployed connector (context ingestion spec 2026-10-23, 9).

    uv run python scripts/e2e_context.py --url https://mcp.soken.dev/mcp                      # new job
    uv run python scripts/e2e_context.py --url https://mcp.soken.dev/mcp --job job_...        # existing job
    uv run python scripts/e2e_context.py --url ... --website https://www.sushi.com --docs https://docs.sushi.com \\
        --terms https://www.sushi.com/legal/terms-of-service --privacy https://www.sushi.com/legal/privacy-policy

Without `--job`: starts a review of the MasterChef deployment (Ethereum mainnet
0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd) with `context` (website, docs, terms, privacy), polls
`review_status` until `ready` and until `context.done + context.failed == context.requested`, prints
the `context.*` keys of `review_facts` and reads the first lines of one context document.
With `--job`: calls `review_add_context` on that job with the same items, then the same polling and
reads. Exit 0 when at least one document was ingested and its first line reads back; 1 otherwise.
The Terms and Privacy URLs default to the pages linked from sushi.com's footer; override them if the
site moved them (the driver prints each document's status either way).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any

from mcp import Client

MASTERCHEF = "0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd"
DEFAULTS = {
    "website": "https://www.sushi.com",
    "docs": "https://docs.sushi.com",
    "terms": "https://www.sushi.com/legal/terms-of-service",
    "privacy": "https://www.sushi.com/legal/privacy-policy",
}


def _items(args: argparse.Namespace) -> list[dict[str, str]]:
    return [{"kind": kind, "url": getattr(args, kind)} for kind in ("website", "docs", "terms", "privacy")
            if getattr(args, kind)]


async def _call(client: Client, tool: str, **arguments: Any) -> Any:
    res = await client.call_tool(tool, arguments)
    text = res.content[0].text if res.content else ""
    if res.is_error:
        raise SystemExit(f"{tool}: error result: {text[:400]}")
    if res.structured_content is not None:
        return res.structured_content
    return text


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="connector URL, e.g. https://mcp.soken.dev/mcp")
    ap.add_argument("--job", default=None, help="existing job id: call review_add_context instead of review_start")
    ap.add_argument("--chain-id", type=int, default=1)
    ap.add_argument("--address", default=MASTERCHEF)
    for kind, default in DEFAULTS.items():
        ap.add_argument(f"--{kind}", default=default, help=f"{kind} URL ('' to skip)")
    ap.add_argument("--timeout", type=int, default=900, help="seconds to wait for ready and the documents")
    args = ap.parse_args()
    items = _items(args)
    if not items:
        raise SystemExit("no context items")

    async with Client(args.url) as client:
        if args.job:
            job_id = args.job
            added = await _call(client, "review_add_context", job_id=job_id, items=items)
            print("review_add_context:", json.dumps(added, indent=1))
            if not added.get("accepted"):
                return 1
        else:
            started = await _call(client, "review_start",
                                  source={"kind": "deployed", "chain": "evm", "chain_id": args.chain_id,
                                          "address": args.address},
                                  context={"items": items})
            print("review_start:", json.dumps({k: started.get(k) for k in ("accepted", "job_id", "state", "context",
                                                                             "errors")}, indent=1))
            if not started.get("accepted"):
                return 1
            job_id = started["job_id"]

        deadline = time.monotonic() + args.timeout
        status: dict[str, Any] = {}
        while time.monotonic() < deadline:
            status = await _call(client, "review_status", job_id=job_id, wait_seconds=20)
            ctx = status.get("context") or {}
            print(f"status {status.get('state')} {status.get('percent')}% context={ctx} error={status.get('error')}")
            if status.get("state") in ("failed", "insufficient_source", "expired", "deleted"):
                print("job ended before ready")
                return 1
            if status.get("state") in ("ready", "finalized", "rendered", "render_queued", "rendering", "render_failed") \
                    and ctx and ctx.get("done", 0) + ctx.get("failed", 0) >= ctx.get("requested", 0):
                break
            await asyncio.sleep(5)
        else:
            print("timed out waiting for ready and the documents")
            return 1

        facts = await _call(client, "review_facts", job_id=job_id, filter="context.", page_size=200)
        fact_lines = [ln for ln in str(facts).splitlines() if ln.startswith("context.")]
        keys = sorted({ln.split(" ", 1)[0] for ln in fact_lines})
        print(f"review_facts context keys ({len(fact_lines)} records):")
        for k in keys:
            print("  ", k)

        search = await _call(client, "review_search_code", job_id=job_id, pattern="source: https://", mode="literal",
                             path_glob="context/*", max_hits=12)
        paths = sorted({ln.split(":", 1)[0] for ln in str(search).splitlines() if ln.startswith("context/")})
        print("context documents:", paths)
        if not paths:
            print("no readable context document")
            return 1
        read = await _call(client, "review_read_code", job_id=job_id, path=paths[0], start_line=1, end_line=12)
        print(read)
        ok = "1| # " in str(read) and "2| source: " in str(read)
        print("RESULT", "ok" if ok else "FAIL", f"job {job_id}")
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
