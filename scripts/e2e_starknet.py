"""Starknet live proof through review_start -> supervisor -> ready (07 8, 9; 09 3.1).

    SOKEN_DATABASE_URL=postgresql://... uv run python scripts/e2e_starknet.py [name ...]

Per target: the MCP tool review_start (in-process ASGI app, real Postgres), one real Supervisor
running the Starknet step runners (sandboxed git fetch, scarb deps with egress, offline build,
supervisor class hash + dep.match, scarb lint + soken-cairo-rules), review_status polled to a
terminal state, then review_leads. Prints job state, tier, provenance and the first leads.
Needs SOKEN_GIT_FETCH_IMAGE, SOKEN_IMAGE_STARKNET_BUILD_<maj>_<min>_<patch>, SOKEN_SANDBOX_RUNTIME
and the soken-egress-starknet docker network (up via `python -m soken_review.sandbox.egress up starknet`).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OZ = "https://github.com/OpenZeppelin/cairo-contracts"

TARGETS = [
    # OpenZeppelin AccountUpgradeable v3.0.0 preset on mainnet (class 0x1d1777..., Cairo 2.13.1).
    {"name": "oz-account-v3", "expect": {"state": "ready"},
     "source": {"kind": "repo", "repo_url": OZ, "commit": "ddd3338e787a3fbf4a92b366640a57ee364390cb",
                "subdir": "packages/presets",
                "deployment": {"chain": "starknet",
                               "address": "0x0126a7a572cf8935d069af937e9f7b27a24949e271e1fbccfe4de0c0d8dc8ea9"}}},
    # OpenZeppelin UniversalDeployer (mainnet UDC, class 0x1b2df6..., Cairo 2.11.4) from OZ v2.0.0.
    {"name": "oz-udc-v2", "expect": {"state": "ready"},
     "source": {"kind": "repo", "repo_url": OZ, "commit": "f1c15a30a44311166e0368081c5f79ab5a02c1d3",
                "subdir": "packages/presets",
                "deployment": {"chain": "starknet",
                               "address": "0x02ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125"}}},
    # Negative control: legacy UDC, a Cairo 0 class -> insufficient_source, detail cairo0_class.
    {"name": "neg-cairo0", "expect": {"state": "insufficient_source"},
     "source": {"kind": "deployed", "chain": "starknet",
                "address": "0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf"}},
    # Negative control: invalid address (>= P) -> rejected by review_start.
    {"name": "neg-address", "expect": {"accepted": False},
     "source": {"kind": "deployed", "chain": "starknet", "address": "0x" + "f" * 64}},
]


async def _call(client, tool: str, **kwargs) -> dict:
    resp = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                           "params": {"name": tool, "arguments": kwargs}},
                             headers={"MCP-Protocol-Version": "2025-11-25", "Accept": "application/json, text/event-stream"})
    resp.raise_for_status()
    result = resp.json().get("result", {})
    text = (result.get("content") or [{}])[0].get("text", "")
    return json.loads(text) if text.startswith("{") else {"text": text, "is_error": result.get("isError")}


async def run(names: list[str]) -> int:
    import httpx
    import psycopg_pool
    from asgi_lifespan import LifespanManager

    from soken_review.db import migrate
    from soken_review.tools.context_pg import create_app
    from soken_review.worker.supervisor import Supervisor

    dsn = os.environ["SOKEN_DATABASE_URL"]
    pin_root = Path(os.environ.setdefault("SOKEN_PIN_ROOT", str(ROOT / ".sbx" / "stk-e2e" / "pins")))
    pin_root.mkdir(parents=True, exist_ok=True)
    (pin_root.parent / "work").mkdir(parents=True, exist_ok=True)
    await migrate.run_migrations(dsn)
    pool = psycopg_pool.AsyncConnectionPool(dsn, min_size=2, max_size=6, open=False)
    await pool.open()
    sup = Supervisor(pool, pin_root, host_name="starknet-e2e", poll_interval=0.5)
    sup_task = asyncio.create_task(sup.run())
    rows = []
    ok = True
    try:
        app = create_app()
        async with LifespanManager(app) as mgr, httpx.AsyncClient(
                transport=httpx.ASGITransport(app=mgr.app), base_url="http://127.0.0.1:8000", timeout=60) as client:
            for t in TARGETS:
                if names and t["name"] not in names:
                    continue
                start = await _call(client, "review_start", source=t["source"])
                row: dict = {"name": t["name"], "accepted": start.get("accepted"), "job_id": start.get("job_id")}
                if not start.get("accepted"):
                    row["errors"] = start.get("errors")
                    ok &= t["expect"].get("accepted") is False
                    rows.append(row)
                    print(json.dumps(row), flush=True)
                    continue
                job_id = start["job_id"]
                status: dict = {}
                for _ in range(1800):
                    status = await _call(client, "review_status", job_id=job_id)
                    if status.get("state") in ("ready", "insufficient_source", "failed"):
                        break
                    await asyncio.sleep(2)
                row["state"] = status.get("state")
                row["status"] = {k: status.get(k) for k in ("tier", "error", "errors", "analyzer_degraded", "percent")
                                 if k in status}
                async with pool.connection() as conn, conn.cursor() as cur:
                    await cur.execute("select tier, code_hash, error_code, error_detail, analyzer_degraded, map_status "
                                      "from jobs where job_id=%s", (job_id,))
                    tier, code_hash, err, detail, degraded, map_status = await cur.fetchone()
                row.update(tier=tier, code_hash=code_hash, error_code=err, error_detail=detail,
                           analyzer_degraded=degraded, map_status=map_status)
                work = pin_root.parent / "work" / job_id
                for name in ("provenance.json", "build_result.json"):
                    if (work / name).exists():
                        row[name.removesuffix(".json")] = json.loads((work / name).read_text())
                if (work / "map.json").exists():
                    m = json.loads((work / "map.json").read_text())
                    ex = m["chain_extras"]["starknet"]
                    row["map"] = {"nr": ex["nr"], "facts": ex["facts"], "compiler": ex["compiler"],
                                  "tools": m["static"]["tools"], "replace_class": ex["replace_class"]}
                if row["state"] == "ready":
                    leads = await _call(client, "review_leads", job_id=job_id)
                    row["leads_head"] = (leads.get("text") or "").splitlines()[:12]
                ok &= row["state"] == t["expect"].get("state")
                rows.append(row)
                print(json.dumps(row, indent=1, default=str), flush=True)
    finally:
        sup_task.cancel()
        try:
            await sup_task
        except asyncio.CancelledError:
            pass
        await pool.close()
    print("SUMMARY", json.dumps([{k: r.get(k) for k in ("name", "accepted", "state", "tier", "error_code")} for r in rows]))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run(sys.argv[1:])))
