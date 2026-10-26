"""TON tier A proof on mainnet through the adapter path (06 2.4, 4.2, 4.3; G-TON-PROV).

    SOKEN_IMAGE_TON_BUILD=<image> SOKEN_SANDBOX_RUNTIME=runc uv run python scripts/e2e_ton_provenance.py

1. chain_state 0: toncenter v2 pinned to one mc seqno; the supervisor hashes the code cell.
2. fetch: the verifier.ton.org bundle for that hash (not owner-linked, 06 2.3).
3. build in the sandbox, supervisor hashes the BoC, resolve_provenance -> expect exact, tier A.
Controls, same address and pinned state:
  N1 one constant changed in the entry file          -> rebuild differs -> tier D
  N2 bundle plus an unused file with an asm BoC literal -> same hash, trust scan flags the
     candidate -> tier D (the trust flag decides at resolve_provenance, not the hash)
Exit 0 only when all three outcomes hold.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import sys
import tempfile
from pathlib import Path

from soken_review.adapters.ton.build import build
from soken_review.adapters.ton.fetch import fetch_ton_sources, read_ton_chain_state
from soken_review.adapters.ton.provenance import Attempt, Dep, resolve_provenance

USDT_MASTER = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"
USDT_RAW = "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"

FORGED_FILE = """;; never included in the targets; carries a BoC literal (06 3.3.4)
cell forged() asm "B{b5ee9c72010101010023000842028f452d7a4dfd74066b682365177259ed05734435be76b5fd4bd5d8af2b7c3d68} B>boc PUSHREF";
"""


def run_case(label: str, dep: Dep, cand, root: Path) -> dict:
    def attempt(i, c):
        br = build(c, work_dir=root / label / str(i))
        hashes = {a.contract: a.runtime for a in br.artifacts} if br.status == "ok" else {}
        print(f"  [{label}] build {br.status} {br.reason or ''} hashes={hashes} untrusted={c.untrusted_inputs}")
        if br.status != "ok":
            print("   ", (br.stderr_head or "")[-400:])
        return Attempt(i, c.provider, "ok" if br.status == "ok" else (br.reason or "compile_error"), hashes,
                       untrusted_inputs=c.untrusted_inputs)

    out = resolve_provenance(dep, [cand], attempt)
    print(f"  [{label}] Out: match={out.match} reason={out.reason} tier={out.tier} why={out.why}")
    return out.to_json()


async def main() -> int:
    if os.environ.get("SOKEN_TON_BUILD_DIRECT") == "1":
        print("SOKEN_TON_BUILD_DIRECT=1 is set; this proof runs in the sandbox only", file=sys.stderr)
        return 1
    cs = await read_ton_chain_state(USDT_RAW)
    acct = cs["accounts"][USDT_RAW]
    print(f"chain_state: mc_seqno={cs['mc_seqno']} status={acct['status']} code_hash={acct['code_hash']} "
          f"library_ref={acct['code_is_library_ref']} dep_hash={acct['dep_hash']}")
    dep = Dep(address=USDT_RAW, status=acct["status"], hash=acct["dep_hash"], why=acct["why"])

    read_status: dict[str, str] = {}
    cands = await fetch_ton_sources(USDT_RAW, acct["dep_hash"], read_status=read_status)
    print(f"fetch: {read_status} candidates={[(c.provider, c.language, c.compiler.version if c.compiler else None, sorted(c.files)) for c in cands]}")
    if not cands:
        return 1
    bundle = cands[0]
    print(f"verifier bundle: {json.dumps(bundle.settings.get('verifier'))}")

    root = Path(os.environ.get("SOKEN_E2E_ROOT") or tempfile.mkdtemp(prefix="ton-prov-", dir=Path.home()))
    results = {"chain_state": {k: v for k, v in acct.items() if not k.endswith("_boc")}, "mc_seqno": cs["mc_seqno"]}

    results["A"] = run_case("A", dep, copy.deepcopy(bundle), root)

    mutated = copy.deepcopy(bundle)
    needle = "throw_unless(error::not_owner,"
    entry = mutated.settings.get("entry")
    if entry not in mutated.files or needle not in mutated.files[entry]:
        entry = next(path for path, body in sorted(mutated.files.items()) if needle in body)
    text = mutated.files[entry]
    # one error code in the admin check: `error::not_owner` (73) becomes the literal 999
    mutated.files[entry] = text.replace(needle, "throw_unless(999,", 1)
    assert mutated.files[entry] != text, "control mutation did not apply"
    results["N1"] = run_case("N1", dep, mutated, root)

    forged = copy.deepcopy(bundle)
    forged.files["forged.fc"] = FORGED_FILE
    results["N2"] = run_case("N2", dep, forged, root)

    ok = (results["A"]["match"] == "exact" and results["A"]["tier"] == "A"
          and results["N1"]["tier"] == "D" and results["N1"]["why"] == "rebuild_differs"
          and results["N2"]["tier"] == "D" and results["N2"]["why"] == "untrusted_inputs"
          and results["N2"]["tried"][0]["hashes"] and dep.hash in results["N2"]["tried"][0]["hashes"].values())
    (root / "e2e_ton_provenance.json").write_text(json.dumps(results, indent=2))
    print(f"\nresults: {root / 'e2e_ton_provenance.json'}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
