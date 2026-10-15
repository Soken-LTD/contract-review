#!/usr/bin/env python3
"""Fetch EVM source for one contract and write candidate files + settings to disk.

Usage:
    python scripts/fetch_case.py <chain_id> <address> <out_dir>

Writes to <out_dir>/:
  candidates.json          - list of Candidate dicts
  <provider>/<path>        - source files for each candidate
  proxy.json               - proxy detection result (if available via RPC)

This is the sprint goal: 5 EVM cases reach review_leads locally.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path


async def _run(chain_id: int, address: str, out_dir: Path) -> None:
    # Import here to allow running with uv run python scripts/fetch_case.py
    from soken_review.adapters.evm.fetch import fetch_source
    from soken_review.adapters.evm.proxy import (
        detect_proxy,
        read_proxy_authority,
        read_proxy_calls,
        read_proxy_slots,
    )
    from soken_review.adapters.evm.registry import get_chain
    from soken_review.adapters.evm.rpc import RpcClient
    from soken_review.adapters.evm.units import make_unit_label

    chain = get_chain(chain_id)
    if chain is None:
        print(f"ERROR: chain_id {chain_id} not in registry", file=sys.stderr)
        sys.exit(1)

    print(f"Chain: {chain.name} ({chain_id})")
    print(f"Address: {address}")

    # 1. Read runtime bytecode via the first registry RPC that answers
    runtime_bytecode = "0x"
    block_num: int | None = None
    rpc_url: str | None = None
    for entry in chain.rpc:
        rpc = RpcClient(entry.url)
        try:
            block_num = await rpc.block_number()
            runtime_bytecode = await rpc.get_code(address, block=block_num)
            rpc_url = entry.url
            print(f"RPC {entry.url} block: {block_num}, bytecode length: {len(runtime_bytecode) // 2 - 1} bytes")
            break
        except Exception as exc:
            block_num = None
            print(f"WARNING: RPC {entry.url} failed ({exc})", file=sys.stderr)
    if rpc_url is None:
        print("WARNING: no RPC answered; proceeding without runtime bytecode", file=sys.stderr)

    # 2. Fetch source candidates
    candidates = await fetch_source(chain_id=chain_id, address=address, runtime_bytecode=runtime_bytecode)
    print(f"Candidates found: {len(candidates)} ({', '.join(c.provider for c in candidates)})")

    out_dir.mkdir(parents=True, exist_ok=True)

    # 3. Write candidate files
    cand_records = []
    for i, cand in enumerate(candidates):
        provider_dir = out_dir / f"{cand.provider}_{i}"
        provider_dir.mkdir(exist_ok=True)
        base_resolved = provider_dir.resolve()
        for path, content in cand.files.items():
            # All paths in cand.files were already validated by filter_candidate_files
            # in the fetch pipeline, but we re-check here with path traversal guard.
            dest = (provider_dir / path).resolve()
            if not dest.is_relative_to(base_resolved):
                print(f"WARNING: skipping unsafe path {path!r} (would escape output dir)", file=sys.stderr)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)

        # Unit label
        name = (cand.entry_contract or "Unknown").split(":")[-1].split("/")[-1].replace(".sol", "")
        unit_label = make_unit_label(name, address)

        cand_records.append(
            {
                "provider": cand.provider,
                "sha256": cand.sha256,
                "language": cand.language,
                "compiler": {
                    "version": cand.compiler.version if cand.compiler else None,
                    "version_pinned_by": cand.compiler.version_pinned_by if cand.compiler else None,
                },
                "settings": cand.settings,
                "sourcify_match": cand.sourcify_match,
                "explorer_verified": cand.explorer_verified,
                "entry_contract": cand.entry_contract,
                "unit_label": unit_label,
                "files_count": len(cand.files),
                "files_dir": str(provider_dir.relative_to(out_dir)),
                "source_url": cand.source_url,
                "fetched_at": cand.fetched_at,
            }
        )

    (out_dir / "candidates.json").write_text(json.dumps(cand_records, indent=2))
    print(f"Wrote candidates.json with {len(cand_records)} entries")

    # 4. Proxy detection (if RPC available)
    if rpc_url is not None and block_num is not None and runtime_bytecode != "0x":
        try:
            rpc = RpcClient(rpc_url, block=block_num)
            slots = await read_proxy_slots(rpc, address)
            calls = await read_proxy_calls(rpc, address)
            proxy_result = detect_proxy(runtime_bytecode, slots, calls)
            proxy_dict = {
                "pattern": proxy_result.pattern,
                "pattern_name": proxy_result.pattern_name,
                "implementation": proxy_result.implementation,
                "admin": proxy_result.admin,
                "beacon": proxy_result.beacon,
                "extra": proxy_result.extra,
                "authority": await read_proxy_authority(rpc, address, proxy_result),
                "block": block_num,
                "rpc": rpc_url,
            }
            (out_dir / "proxy.json").write_text(json.dumps(proxy_dict, indent=2))
            print(f"Proxy: {proxy_result.pattern_name} (impl={proxy_result.implementation})")
        except Exception as exc:
            print(f"WARNING: proxy detection failed: {exc}", file=sys.stderr)

    # 5. Settings summary
    settings = {
        "chain_id": chain_id,
        "address": address,
        "chain_name": chain.name,
        "block": block_num,
        "candidates_count": len(candidates),
        "runtime_bytecode_len": len(runtime_bytecode) // 2 - 1 if runtime_bytecode != "0x" else 0,
    }
    (out_dir / "case.json").write_text(json.dumps(settings, indent=2))
    print(f"Output written to {out_dir}/")


def main() -> None:
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <chain_id> <address> <out_dir>", file=sys.stderr)
        sys.exit(1)
    chain_id = int(sys.argv[1])
    address = sys.argv[2]
    out_dir = Path(sys.argv[3])
    asyncio.run(_run(chain_id, address, out_dir))


if __name__ == "__main__":
    main()
