#!/usr/bin/env python3
"""Measure inactive opcodes per chain via eth_call with state override (05 4.1, F18).

Probes live in soken_review.adapters.evm.opcode_probe: a control probe, then one probe per opcode
added since Shanghai (PUSH0, TLOAD, TSTORE, MCOPY, BLOBHASH, BLOBBASEFEE, CLZ). The registry RPCs
are tried in order until one gives a complete measurement.

Usage:
    uv run python scripts/measure_opcodes.py [--chain-id=CHAIN_ID] [--dry-run]

Writes per chain into data/chains.json:
    inactive_opcodes   the opcodes a node rejected (only from a complete measurement)
    opcode_probe       {block, rpc, checked_at, measured, results, source_url}

A chain with no complete measurement keeps `measured: false`; 6.4 then reports `not_checked`.
TRON is skipped: TronGrid rejects state overrides (F41), its row comes from getchainparameters.
A state-override eth_call is a read (05 4.1); no transaction is sent.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import sys
from pathlib import Path

_SOURCE = "scripts/measure_opcodes.py (soken_review.adapters.evm.opcode_probe)"


async def measure(entry: dict) -> dict:
    from soken_review.adapters.evm.opcode_probe import probe_chain
    from soken_review.adapters.evm.rpc import RpcClient

    last: dict | None = None
    for row in entry.get("rpc", []):
        try:
            rec = await probe_chain(RpcClient(row["url"]))
        except Exception as exc:  # noqa: BLE001
            print(f"  {row['url']}: unavailable ({str(exc)[:120]})")
            continue
        rec["rpc"] = row["url"]
        print(f"  {row['url']} block {rec['block']}: {rec['results'] or rec['control']}")
        if rec["measured"]:
            return rec
        last = rec
    return last or {"measured": False, "results": {}, "inactive": [], "control": "no RPC answered"}


async def main_async(chain_ids: list[int] | None, dry_run: bool) -> int:
    data_file = Path(__file__).parents[1] / "src" / "soken_review" / "adapters" / "evm" / "data" / "chains.json"
    data = json.loads(data_file.read_text())
    today = dt.datetime.now(dt.UTC).date().isoformat()
    unmeasured = 0
    for entry in data["chains"]:
        cid = int(entry["chain_id"])
        if chain_ids and cid not in chain_ids:
            continue
        if entry.get("family") == "tron":
            print(f"Chain {cid}: TRON, skipped (getchainparameters, F41)")
            continue
        print(f"Chain {cid} ({entry['name']}):")
        rec = await measure(entry)
        entry.pop("_opcode_probe_note", None)
        entry.pop("inactive_opcodes_source", None)
        entry["opcode_probe"] = {
            "block": rec.get("block"),
            "rpc": rec.get("rpc"),
            "checked_at": today,
            "measured": rec["measured"],
            "control": rec["control"],
            "results": rec["results"],
            "source_url": _SOURCE,
        }
        if rec["measured"]:
            entry["inactive_opcodes"] = rec["inactive"]
        else:
            unmeasured += 1
        print(f"  measured={rec['measured']} inactive_opcodes={entry.get('inactive_opcodes')}")
    if not dry_run:
        data_file.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Updated {data_file}")
    return 1 if unmeasured else 0


def main() -> None:
    chain_ids: list[int] | None = None
    dry_run = "--dry-run" in sys.argv
    for arg in sys.argv[1:]:
        if arg.startswith("--chain-id="):
            chain_ids = [int(arg.split("=")[1])]
    sys.exit(asyncio.run(main_async(chain_ids, dry_run)))


if __name__ == "__main__":
    main()
