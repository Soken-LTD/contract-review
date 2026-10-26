#!/usr/bin/env python3
"""Live proof over HTTP: review_start -> ready through the worker, then map, facts, flags and drafts
through the MCP client (04 2.1, 6.3, 12; 03 4.2 to 4.8).

Usage: uv run python scripts/e2e_map_live.py http://127.0.0.1:18431/mcp <chain_id> <address>
Needs scripts/run_local.py (server and worker) running against the same Postgres and pin root.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time

from mcp import Client


def _text(result) -> str:
    return result.content[0].text


async def main(url: str, chain_id: int, address: str) -> int:
    async with Client(url) as c:
        t0 = time.monotonic()
        r = await c.call_tool("review_start", {"source": {"kind": "deployed", "chain": "evm", "chain_id": chain_id,
                                                          "address": address}})
        start = json.loads(_text(r))
        job = start["job_id"]
        print(f"review_start accepted={start['accepted']} state={start['state']} job=...{job[-6:]}")
        state = start["state"]
        polls = 0
        while state not in ("ready", "failed", "insufficient_source"):
            t = time.monotonic()
            st = json.loads(_text(await c.call_tool("review_status", {"job_id": job, "wait_seconds": 45})))
            polls += 1
            print(f"  status poll {polls}: state={st['state']} step={st['step']} percent={st['percent']} "
                  f"eta_s={st.get('eta_s')} returned_after={time.monotonic() - t:.1f}s")
            state = st["state"]
            if polls > 40:
                break
        print(f"reached {state} in {time.monotonic() - t0:.0f}s; map_status={st.get('map_status')} "
              f"analyzer_degraded={st.get('analyzer_degraded')} drafts={st.get('drafts')}")
        if state != "ready":
            print(json.dumps(st, indent=1))
            return 1

        cmap = _text(await c.call_tool("review_contract_map", {"job_id": job, "contract": "GBLIN"}))
        print("\n== review_contract_map (concise, first 12 lines)")
        print("\n".join(cmap.splitlines()[:12]))
        det = _text(await c.call_tool("review_contract_map", {"job_id": job, "contract": "GBLIN",
                                                              "response_format": "detailed"}))
        entry = [ln for ln in det.splitlines() if "setParam" in ln or ln.startswith("    guards")][:4]
        print("\n== review_contract_map detailed (setParam entry)")
        i = next(k for k, ln in enumerate(det.splitlines()) if ln.startswith("  entry GBLIN.setParam"))
        print("\n".join(det.splitlines()[i : i + 4]))
        del entry

        facts = _text(await c.call_tool("review_facts", {"job_id": job}))
        print("\n== review_facts")
        print(facts)

        search = _text(await c.call_tool("review_search_code", {"job_id": job, "pattern": "function setParam",
                                                                "path_glob": "src/*"}))
        hit = search.splitlines()[1]
        path, line = hit.split("|")[0].rsplit(":", 1)
        print(f"\n== review_search_code -> {hit[:100]}")
        read = _text(await c.call_tool("review_read_code", {"job_id": job, "path": path, "start_line": int(line),
                                                            "end_line": int(line) + 12,
                                                            "response_format": "detailed"}))
        print("\n== review_read_code detailed (header and tail)")
        lines = read.splitlines()
        print("\n".join(lines[:2]))
        print("...")
        print("\n".join(lines[lines.index("```", 2) + 1 :]))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1], int(sys.argv[2]), sys.argv[3])))
