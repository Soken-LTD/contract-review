"""Opcode activation probes for registry `inactive_opcodes[]` (05 section 4.1, F18).

One `eth_call` with a state override per opcode added since Shanghai: the probe code is placed on
an unused address and called at a recorded block. Each probe runs its opcode, then returns one
32-byte word whose value is known in advance, so three outcomes are told apart:

  active    the call succeeded and returned the expected word
  inactive  the node rejected the opcode (invalid opcode, NotActivated, opcode not defined)
  error     anything else (rate limit, override unsupported, unexpected output): not measured

A control probe (no new opcode) runs first; if it does not return its word, the RPC does not
honour state overrides and the whole chain is "not measured", never "all active".
A state-override eth_call is a read (05 4.1); nothing is sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

PROBE_ADDRESS = "0x00000000000000000000000000000000005ec0de"

# Return-word epilogue: PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN (stack top is the value to return)
_RET = "6000526020" + "6000f3"
_W2A = "00" * 31 + "2a"   # 0x2a as a 32-byte word
_WFF = "00" * 31 + "ff"


@dataclass(frozen=True)
class Probe:
    opcode: str
    eip: str
    fork: str
    code: str          # runtime hex, no 0x
    expected: str      # 32-byte return word hex, no 0x


# Each code: runs the opcode, leaves a known value on the stack, returns it as one word.
PROBES: tuple[Probe, ...] = (
    # PUSH1 0x2a, PUSH0, MSTORE, PUSH1 0x20, PUSH0, RETURN
    Probe("PUSH0", "EIP-3855", "shanghai", "602a5f5260205ff3", _W2A),
    # PUSH1 0x2a, PUSH1 0, TSTORE(key 0, value 0x2a); PUSH1 0x2a; return
    Probe("TSTORE", "EIP-1153", "cancun", "602a60005d602a" + _RET, _W2A),
    # PUSH1 0, TLOAD (empty slot = 0), PUSH1 0x2a, ADD; return
    Probe("TLOAD", "EIP-1153", "cancun", "60005c602a01" + _RET, _W2A),
    # MSTORE(0x20, 0x2a); MCOPY(dst 0, src 0x20, len 0x20); RETURN(0, 0x20)
    Probe("MCOPY", "EIP-5656", "cancun", "602a602052" + "602060206000" + "5e" + "60206000f3", _W2A),
    # PUSH1 0, BLOBHASH (no blobs = 0), PUSH1 0x2a, ADD; return
    Probe("BLOBHASH", "EIP-4844", "cancun", "600049602a01" + _RET, _W2A),
    # BLOBBASEFEE, POP, PUSH1 0x2a; return
    Probe("BLOBBASEFEE", "EIP-7516", "cancun", "4a50602a" + _RET, _W2A),
    # PUSH1 1, CLZ (= 255); return
    Probe("CLZ", "EIP-7939", "osaka", "60011e" + _RET, _WFF),
)

# No new opcode: PUSH1 0x2a; return. Proves the RPC honours the state override.
CONTROL = Probe("CONTROL", "-", "frontier", "602a" + _RET, _W2A)

_INACTIVE_RE = re.compile(
    r"invalid opcode|not ?activated|opcode 0x[0-9a-f]{1,2} not defined|undefined (instruction|opcode)"
    r"|bad ?instruction|invalidfeopcode|opcodenotfound|unknown opcode",
    re.IGNORECASE,
)


def classify(probe: Probe, output: str | None, error: str | None) -> str:
    """Return `active`, `inactive` or `error: <detail>` for one probe call."""
    if error is not None:
        if _INACTIVE_RE.search(error[:500]):
            return "inactive"
        # Arbitrum: "BLOBBASEFEE is not supported on Arbitrum" (opcode defined, always fails).
        # Only when the node names this probe's opcode: "method not supported" is not a verdict.
        low = error[:500].lower()
        at = low.find(probe.opcode.lower() + " ")
        if at != -1 and "not supported" in low[at:]:
            return "inactive"
        return f"error: {error[:160]}"
    got = (output or "").removeprefix("0x").lower()
    if got == probe.expected:
        return "active"
    return f"error: unexpected output {got[:80] or 'empty'}"


async def _run_one(rpc: Any, probe: Probe, block: int) -> str:
    from soken_review.adapters.evm.rpc import RpcError

    try:
        out = await rpc.eth_call(
            to=PROBE_ADDRESS, data="0x", block=block, state_override={PROBE_ADDRESS: {"code": "0x" + probe.code}}
        )
    except RpcError as exc:
        return classify(probe, None, exc.rpc_message or str(exc))
    except Exception as exc:  # noqa: BLE001  a transport failure is "not measured", never "inactive"
        return f"error: transport {str(exc)[:160]}"
    return classify(probe, out, None)


async def probe_chain(rpc: Any) -> dict[str, Any]:
    """Run the control and every probe at one block. Returns the registry `opcode_probe` record."""
    block = await rpc.block_number()
    control = await _run_one(rpc, CONTROL, block)
    results: dict[str, str] = {}
    if control == "active":
        for probe in PROBES:
            results[probe.opcode] = await _run_one(rpc, probe, block)
    measured = control == "active" and all(r in ("active", "inactive") for r in results.values())
    return {
        "block": block,
        "control": control,
        "results": results,
        "measured": measured,
        "inactive": [op for op, r in results.items() if r == "inactive"],
    }
