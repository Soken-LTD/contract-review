#!/usr/bin/env python3
"""Live 05 13.1 deployment check: fetch, sandboxed build, masked comparison, provenance tier.

    uv run python scripts/e2e_deployment.py evm:<chain_id>:<address> [tron:<T-address> ...]

Per target: read the runtime at a pinned block, fetch the source candidate, build it in the
sandbox, run the same `evm_deployment_check` + `resolve_provenance` the supervisor runs, then a
negative control: one on-chain byte outside every mask flipped must not give tier A.
Exit 1 when a target does not reach tier A or a negative control does.

Env: SOKEN_IMAGE_EVM_ANALYZE (local build image), SOKEN_SANDBOX_RUNTIME=runc on a dev host.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.engine.provenance import evm_deployment_check, resolve_provenance

REPO = Path(__file__).resolve().parents[1]


async def _evm(chain_id: int, address: str) -> tuple[str, Candidate | None, str, str]:
    from soken_review.adapters.evm.fetch import fetch_source
    from soken_review.adapters.evm.registry import get_chain
    from soken_review.adapters.evm.rpc import RpcClient
    from soken_review.worker.supervisor import _rpc_url

    chain = get_chain(chain_id)
    family = "hyperevm" if chain_id in (998, 999) else "evm"
    url = _rpc_url(chain_id)
    block = await RpcClient(url).block_number() - 1
    code = await RpcClient(url, block=block).get_code(address)
    cands = await fetch_source(chain_id=chain_id, address=address, runtime_bytecode=code)
    return family, (cands[0] if cands else None), code, f"{chain.name if chain else chain_id} block {block}"


async def _tron(address: str) -> tuple[str, Candidate | None, str, str]:
    from soken_review.adapters.tron.fetch import fetch_source_tron

    cands, runtime, _creation = await fetch_source_tron(address)
    return "tron", (cands[0] if cands else None), runtime or "", "TRON latest (TronGrid getcontractinfo)"


def _build(family: str, cand: Candidate, work: Path) -> BuildResult:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    if family == "tron":
        from soken_review.adapters.tron.build import build_tron
        return build_tron(cand, work_dir=work)
    from soken_review.adapters.evm.build import build
    return build(cand, work_dir=work)


def _tamper(code: str, comparison: dict) -> tuple[str, int]:
    """Flip one byte that lies outside every mask."""
    raw = bytearray.fromhex(code.removeprefix("0x"))
    masked = [tuple(r) for k in ("immutable_ranges", "link_ranges", "auxdata_ranges") for r in comparison[k]]
    pos = next(i for i in range(len(raw) // 3, len(raw)) if not any(s <= i < e for s, e in masked))
    raw[pos] ^= 0x01
    return "0x" + raw.hex(), pos


async def run(spec: str) -> bool:
    kind, _, rest = spec.partition(":")
    if kind == "tron":
        family, cand, code, pin = await _tron(rest)
        address = rest
        from soken_review.adapters.tron.address import b58_to_hex
        raw_address = "0x" + b58_to_hex(rest)  # the 20 bytes after 0x41
    else:
        chain_id, _, address = rest.partition(":")
        family, cand, code, pin = await _evm(int(chain_id), address)
        raw_address = address
    print(f"\n== {spec} ({pin}), on-chain runtime {len(code) // 2 - 1} bytes")
    if cand is None:
        print("   FAIL no source candidate")
        return False
    print(f"   candidate {cand.provider} {cand.compiler.version if cand.compiler else None} entry {cand.entry_contract}")
    build = _build(family, cand, REPO / ".sbx" / "e2e_deployment" / spec.replace(":", "_"))
    print(f"   build {build.status} {build.reason or ''} artifacts={len(build.artifacts)}")
    dep = evm_deployment_check(family=family, build=build, onchain_runtime=code, address=raw_address)
    prov = resolve_provenance(candidate=cand, address=address, dep=dep)
    cmp = dep.comparison or {}
    print(f"   dep.match={dep.match} reason={dep.reason} contract={dep.contract} tier={prov['tier']}")
    print(f"   masks: immutables={cmp.get('immutable_ranges')} auxdata={cmp.get('auxdata_ranges')} "
          f"({cmp.get('auxdata_source')}) links={cmp.get('link_ranges')}")
    ok = prov["tier"] == "A"

    if dep.comparison:
        bad, pos = _tamper(code, dep.comparison)
        neg = evm_deployment_check(family=family, build=build, onchain_runtime=bad, address=raw_address)
        nprov = resolve_provenance(candidate=cand, address=address, dep=neg)
        print(f"   negative control (byte {pos} flipped): dep.match={neg.match} reason={neg.reason} "
              f"tier={nprov['tier']} differing={(neg.comparison or {}).get('differing')}")
        ok = ok and nprov["tier"] != "A"
    out = REPO / ".sbx" / "e2e_deployment" / (spec.replace(":", "_") + ".json")
    out.write_text(json.dumps(prov, indent=2))
    print(f"   {'OK' if ok else 'FAIL'}")
    return ok


async def main(specs: list[str]) -> int:
    results = [await run(s) for s in specs]
    print(f"\n{sum(results)}/{len(results)} targets tier A with a failing negative control")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
