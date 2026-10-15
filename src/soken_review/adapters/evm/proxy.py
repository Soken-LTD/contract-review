"""EVM proxy pattern detection (05 section 5).

Patterns 0–7 are resolved from chain state 0 reads (eth_getCode + eth_getStorageAt + one eth_call).
Pattern 8 (custom delegatecall) requires source analysis and is handled in analyze.py.

Slot constants from F33:
  EIP-1967 impl:   0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
  EIP-1967 admin:  0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
  EIP-1967 beacon: 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
  EIP-1822 PROXIABLE: keccak256("PROXIABLE") = 0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7
  ZeppelinOS impl:  keccak256("org.zeppelinos.proxy.implementation") = 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3
  ZeppelinOS admin: keccak256("org.zeppelinos.proxy.admin") = 0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b
  Safe singleton:   slot 0 (pattern 6; runtime listed in data/safe_proxy_runtimes.json, UV5-07)

Pattern 7 (EIP-2535 diamond) needs one eth_call, `facets()`, made in chain_state 0 by
read_proxy_calls(); its result reaches detect_proxy() as `calls`.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Slot constants (F33)
# ---------------------------------------------------------------------------

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1822_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
ZOS_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
ZOS_ADMIN_SLOT = "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b"
SAFE_SINGLETON_SLOT = "0x" + "0" * 64

# Selectors (cast sig)
FACETS_SELECTOR = "0x7a0ed627"             # facets() -> (address,bytes4[])[]  (EIP-2535 loupe)
DIAMOND_CUT_SELECTOR = "0x1f931c1c"        # diamondCut((address,uint8,bytes4[])[],address,bytes)
OWNER_SELECTOR = "0x8da5cb5b"              # owner()
SAFE_GET_OWNERS = "0xa0e67e2b"             # getOwners()
SAFE_GET_THRESHOLD = "0xe75235b8"          # getThreshold()
SAFE_GET_MODULES_PAGINATED = "0xcc2f8452"  # getModulesPaginated(address,uint256)
_SAFE_SENTINEL = "0x" + "0" * 39 + "1"
_SAFE_MODULE_PAGE = 50
_ZERO_ADDRESS = "0x" + "0" * 40

# EIP-1167 minimal proxy prefix (pattern 1, 05 table)
_EIP1167_PREFIX = "363d3d373d3d3d363d73"
_EIP1167_SUFFIX = "5af43d82803e903d91602b57fd5bf3"

# EIP-7702 delegated EOA code prefix (pattern 0)
_EIP7702_PREFIX = "ef0100"

# A diamond listing more than this is not decoded (bounded work on untrusted return data).
_MAX_FACETS = 256
_MAX_SELECTORS = 4096

_SAFE_RUNTIMES_FILE = Path(__file__).parent / "data" / "safe_proxy_runtimes.json"


def _load_safe_runtimes() -> dict[str, str]:
    """sha256 of a Safe proxy runtime -> Safe version (05 section 5 pattern 6, UV5-07)."""
    data = json.loads(_SAFE_RUNTIMES_FILE.read_text())
    return {row["runtime_sha256"]: row["version"] for row in data["runtimes"]}


SAFE_RUNTIMES = _load_safe_runtimes()


@dataclass
class ProxyResult:
    """Result of proxy detection for one address (05 section 5)."""

    pattern: int | None        # 0–7 or None if not a proxy
    pattern_name: str          # human-readable name matching the 05 table
    implementation: str | None  # lower-case 0x hex address (if resolvable in chain_state 0)
    admin: str | None           # lower-case 0x hex admin address
    beacon: str | None          # lower-case 0x for beacon (pattern 3)
    extra: dict[str, Any] = field(default_factory=dict)  # pattern-specific info


def _slot_to_address(raw: str) -> str | None:
    """Convert a 32-byte storage value to a 0x-prefixed 20-byte address, or None if zero."""
    # raw is 0x + 64 hex chars (32 bytes)
    if not raw or raw == "0x" + "0" * 64:
        return None
    # last 20 bytes = last 40 hex chars
    addr = "0x" + raw[-40:].lower()
    if addr == _ZERO_ADDRESS:
        return None
    return addr


def _strip0x(s: str) -> str:
    return s.removeprefix("0x")


# ---------------------------------------------------------------------------
# Strict ABI reads on untrusted return data
# ---------------------------------------------------------------------------

def _word(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 32 > len(data):
        raise ValueError("abi: read past end")
    return int.from_bytes(data[offset : offset + 32], "big")


def _word_address(data: bytes, offset: int) -> str:
    value = _word(data, offset)
    if value >> 160:
        raise ValueError("abi: address word has high bits set")
    return "0x" + value.to_bytes(20, "big").hex()


def _decode_address_array(data: bytes, head_offset: int) -> list[str]:
    off = _word(data, head_offset)
    n = _word(data, off)
    if n > 1000:
        raise ValueError("abi: array too long")
    return [_word_address(data, off + 32 + 32 * i) for i in range(n)]


def decode_facets(raw: str | None) -> list[dict[str, Any]] | None:
    """Strictly decode `facets()` return data: `(address facetAddress, bytes4[] selectors)[]`.

    Returns None unless the data is a well-formed, non-empty facet list in which every facet has a
    non-zero address and at least one selector, and the loupe lists `facets()` itself (EIP-2535
    requires the loupe functions to be registered). Anything else reads as "not a diamond".
    """
    if not raw:
        return None
    try:
        data = bytes.fromhex(_strip0x(raw))
        head = _word(data, 0)
        count = _word(data, head)
        if count == 0 or count > _MAX_FACETS:
            return None
        base = head + 32
        facets: list[dict[str, Any]] = []
        total = 0
        for i in range(count):
            tup = base + _word(data, base + 32 * i)
            address = _word_address(data, tup)
            sel_off = tup + _word(data, tup + 32)
            n_sel = _word(data, sel_off)
            total += n_sel
            if n_sel == 0 or total > _MAX_SELECTORS or address == _ZERO_ADDRESS:
                return None
            selectors = []
            for j in range(n_sel):
                word = data[sel_off + 32 + 32 * j : sel_off + 64 + 32 * j]
                if len(word) != 32 or any(word[4:]):
                    return None  # bytes4 is left-aligned; the rest of the word must be zero
                selectors.append("0x" + word[:4].hex())
            facets.append({"address": address, "selectors": selectors})
    except ValueError:
        return None
    if not any(FACETS_SELECTOR in f["selectors"] for f in facets):
        return None
    return facets


_DELEGATECALL = 0xF4


def _cbor_metadata_len(code: bytes) -> int:
    """Length of the trailing solc/vyper CBOR metadata (last 2 bytes = big-endian length), or 0
    when the tail does not look like one (then nothing is excluded)."""
    if len(code) < 4:
        return 0
    n = int.from_bytes(code[-2:], "big")
    if 0 < n <= len(code) - 2 and 0xA1 <= code[-2 - n] <= 0xA9:  # CBOR map header
        return n + 2
    return 0


def has_delegatecall(runtime_hex: str) -> bool:
    """DELEGATECALL opcode in the runtime: linear scan that skips PUSH data and the CBOR tail."""
    try:
        code = bytes.fromhex(_strip0x(runtime_hex))
    except ValueError:
        return False
    end = len(code) - _cbor_metadata_len(code)
    i = 0
    while i < end:
        op = code[i]
        if op == _DELEGATECALL:
            return True
        i += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)  # PUSH1..PUSH32 data
    return False


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_proxy(code: str, storage_reader: dict[str, str], calls: dict[str, str] | None = None) -> ProxyResult:
    """Detect proxy pattern from runtime bytecode, pre-read storage slots and pre-made calls.

    Args:
        code: runtime bytecode hex (0x-prefixed) from eth_getCode.
        storage_reader: mapping of slot hex -> value hex (pre-read in chain_state 0).
            Caller must pre-read the known slots (read_proxy_slots).
        calls: mapping of selector -> eth_call return hex (read_proxy_calls). Only FACETS_SELECTOR
            is used (pattern 7); a missing key means the call reverted or was not made.

    Returns:
        ProxyResult with the detected pattern (or None if not a proxy).

    Note: Pattern 8 (custom delegatecall) requires source analysis (chain_state 1).
    """
    raw = _strip0x(code).lower()

    # Pattern 0: EIP-7702 delegated EOA (0xef0100 + 20-byte address)
    if raw.startswith(_EIP7702_PREFIX) and len(raw) == len(_EIP7702_PREFIX) + 40:
        impl = "0x" + raw[len(_EIP7702_PREFIX):]
        return ProxyResult(pattern=0, pattern_name="eip7702_delegated_eoa", implementation=impl, admin=None, beacon=None)

    # Pattern 1: EIP-1167 minimal proxy
    if raw.startswith(_EIP1167_PREFIX) and raw.endswith(_EIP1167_SUFFIX):
        impl = "0x" + raw[len(_EIP1167_PREFIX) : len(_EIP1167_PREFIX) + 40]
        return ProxyResult(pattern=1, pattern_name="eip1167_minimal_proxy", implementation=impl, admin=None, beacon=None)

    # Pattern 6: Safe proxy. The runtime equals one measured Safe proxy runtime (exact bytes,
    # UV5-07); the singleton is slot 0. Checked before the slot patterns because it is exact.
    try:
        runtime_sha = hashlib.sha256(bytes.fromhex(raw)).hexdigest() if raw else None
    except ValueError:
        runtime_sha = None
    safe_version = SAFE_RUNTIMES.get(runtime_sha) if runtime_sha else None
    if safe_version is not None:
        singleton = _slot_to_address(storage_reader.get(SAFE_SINGLETON_SLOT, "0x" + "0" * 64))
        return ProxyResult(
            pattern=6,
            pattern_name="safe",
            implementation=singleton,
            admin=None,  # authority = the Safe's owners, threshold, modules (read_proxy_authority)
            beacon=None,
            extra={"safe_version": safe_version},
        )

    # Pattern 3: EIP-1967 beacon proxy (check before transparent/UUPS since beacon slot may be set)
    beacon_raw = storage_reader.get(EIP1967_BEACON_SLOT, "0x" + "0" * 64)
    beacon_addr = _slot_to_address(beacon_raw)
    if beacon_addr is not None:
        # implementation comes from calling implementation() on the beacon — deferred to chain_state 1
        admin_raw = storage_reader.get(EIP1967_ADMIN_SLOT, "0x" + "0" * 64)
        admin_addr = _slot_to_address(admin_raw)
        return ProxyResult(
            pattern=3,
            pattern_name="eip1967_beacon",
            implementation=None,  # requires beacon.implementation() call in chain_state 1
            admin=admin_addr,
            beacon=beacon_addr,
        )

    # Pattern 2: EIP-1967 transparent or UUPS
    impl_raw = storage_reader.get(EIP1967_IMPL_SLOT, "0x" + "0" * 64)
    impl_addr = _slot_to_address(impl_raw)
    if impl_addr is not None:
        admin_raw = storage_reader.get(EIP1967_ADMIN_SLOT, "0x" + "0" * 64)
        admin_addr = _slot_to_address(admin_raw)
        # Distinguish UUPS: check for upgradeTo (0x3659cfe6) or upgradeToAndCall (0x4f1ef286) in code
        is_uups = "3659cfe6" in raw or "4f1ef286" in raw
        return ProxyResult(
            pattern=2,
            pattern_name="eip1967_uups" if is_uups else "eip1967_transparent",
            implementation=impl_addr,
            admin=admin_addr,
            beacon=None,
        )

    # Pattern 4: EIP-1822 (PROXIABLE slot)
    eip1822_raw = storage_reader.get(EIP1822_SLOT, "0x" + "0" * 64)
    eip1822_addr = _slot_to_address(eip1822_raw)
    if eip1822_addr is not None:
        return ProxyResult(pattern=4, pattern_name="eip1822", implementation=eip1822_addr, admin=None, beacon=None)

    # Pattern 5: ZeppelinOS proxy (F11, F33, F39)
    zos_raw = storage_reader.get(ZOS_IMPL_SLOT, "0x" + "0" * 64)
    zos_addr = _slot_to_address(zos_raw)
    if zos_addr is not None:
        zos_admin_raw = storage_reader.get(ZOS_ADMIN_SLOT, "0x" + "0" * 64)
        zos_admin = _slot_to_address(zos_admin_raw)
        return ProxyResult(pattern=5, pattern_name="zeppelinos", implementation=zos_addr, admin=zos_admin, beacon=None)

    # Pattern 7: EIP-2535 diamond. facets() is self-reported by the contract, so it is accepted
    # only with structural evidence: a DELEGATECALL in the runtime outside the CBOR metadata.
    facets = decode_facets((calls or {}).get(FACETS_SELECTOR))
    if facets is not None and has_delegatecall(raw):
        return ProxyResult(
            pattern=7,
            pattern_name="eip2535_diamond",
            implementation=None,  # each facet is its own unit (04 2.1)
            admin=None,           # owner() is read by read_proxy_authority
            beacon=None,
            extra={
                "facets": facets,
                "facets_source": "self_reported_loupe",
                # the diamond's own runtime and source stay a review unit beside the facets
                "diamond_unit": True,
                "coverage_note": "facet list reported by the contract's own loupe; it is not proven "
                                 "to be the complete set of code the diamond can execute",
                "diamond_cut_present": any(DIAMOND_CUT_SELECTOR in f["selectors"] for f in facets),
            },
        )

    # Pattern 8: custom delegatecall (requires source analysis)

    return ProxyResult(pattern=None, pattern_name="not_a_proxy", implementation=None, admin=None, beacon=None)


# ---------------------------------------------------------------------------
# chain_state 0 reads
# ---------------------------------------------------------------------------

async def read_proxy_slots(rpc_client: Any, address: str) -> dict[str, str]:
    """Pre-read all known proxy detection slots in parallel (chain_state 0).

    Returns dict of slot_hex -> value_hex.
    """
    import asyncio

    slots = [
        EIP1967_IMPL_SLOT, EIP1967_ADMIN_SLOT, EIP1967_BEACON_SLOT, EIP1822_SLOT, ZOS_IMPL_SLOT, ZOS_ADMIN_SLOT,
        SAFE_SINGLETON_SLOT,
    ]
    tasks = [rpc_client.get_storage_at(address, slot) for slot in slots]
    values = await asyncio.gather(*tasks, return_exceptions=True)
    result: dict[str, str] = {}
    for slot, val in zip(slots, values):
        if isinstance(val, Exception):
            result[slot] = "0x" + "0" * 64
        else:
            result[slot] = val
    return result


async def read_proxy_calls(rpc_client: Any, address: str) -> dict[str, str]:
    """The eth_calls detect_proxy uses in chain_state 0: `facets()` (pattern 7).

    A revert or RPC error leaves the selector out, which detect_proxy reads as "not a diamond".
    """
    calls: dict[str, str] = {}
    try:
        calls[FACETS_SELECTOR] = await rpc_client.eth_call(to=address, data=FACETS_SELECTOR)
    except Exception as exc:  # noqa: BLE001  revert, RpcError, transport error: no facets
        logger.debug("facets() on %s: %s", address, exc)
    return calls


async def read_proxy_authority(rpc_client: Any, address: str, result: ProxyResult) -> dict[str, Any]:
    """Authority reads for patterns 6 and 7 (05 section 5, column Authority).

    Safe: owners, threshold, modules (every module page). Diamond: owner() and whether the
    diamondCut selector is registered. A value that cannot be read is None with an entry in
    `errors`, never a guess.
    """
    out: dict[str, Any] = {}

    async def call(data: str) -> bytes | None:
        try:
            ret = await rpc_client.eth_call(to=address, data=data)
        except Exception as exc:  # noqa: BLE001
            out.setdefault("errors", []).append(f"{data[:10]}: {str(exc)[:120]}")
            return None
        return bytes.fromhex(_strip0x(ret))

    try:
        if result.pattern == 6:
            raw = await call(SAFE_GET_OWNERS)
            out["owners"] = _decode_address_array(raw, 0) if raw else None
            raw = await call(SAFE_GET_THRESHOLD)
            out["threshold"] = _word(raw, 0) if raw else None
            # setup() never ran (threshold 0): anyone can call setup() and take the Safe over
            out["initialized"] = None if out["threshold"] is None else out["threshold"] > 0
            modules: list[str] | None = []
            start = _SAFE_SENTINEL
            for _ in range(20):  # at most 20 pages of _SAFE_MODULE_PAGE modules
                arg = start[2:].rjust(64, "0") + format(_SAFE_MODULE_PAGE, "064x")
                raw = await call(SAFE_GET_MODULES_PAGINATED + arg)
                if raw is None:
                    modules = None
                    break
                modules.extend(_decode_address_array(raw, 0))
                start = _word_address(raw, 32)
                if start in (_SAFE_SENTINEL, _ZERO_ADDRESS):
                    break
            else:
                out.setdefault("errors", []).append("modules: more than 20 pages, list truncated")
            out["modules"] = modules
        elif result.pattern == 7:
            raw = await call(OWNER_SELECTOR)
            out["owner"] = _word_address(raw, 0) if raw else None
            out["diamond_cut_present"] = bool(result.extra.get("diamond_cut_present"))
    except ValueError as exc:
        out.setdefault("errors", []).append(f"abi: {exc}")
    return out
