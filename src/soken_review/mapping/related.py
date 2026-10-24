"""Related-contract classification and state-parameter probing (feat/context-related-state).

Related contracts
-----------------
Collects every unique address from the ``onchain_facts`` result (holder values, EIP-1967
slots) and classifies each:

  eoa        – ``eth_getCode`` returned empty / ``0x``
  multisig   – Safe-proxy bytecode match (structural, same check as ``holder_facts``)
  contract   – any other non-zero code

For Safe multisigs the owner list and threshold are read via the published selectors
(``SAFE_GET_OWNERS`` / ``SAFE_GET_THRESHOLD`` from ``adapters/evm/proxy.py``).

For every contract, ``getMinDelay()`` (selector ``0xf27a0c92``) is attempted once; when
it returns a non-zero uint value the result is included as informational metadata
(``min_delay_s``).  This is *not used to classify* the contract as a Timelock
(that would be spoofable); it is exposed as extra context so findings can cite it.

Security note: classification relies only on ``eth_getCode`` byte structure (the Safe
singleton-slot check uses ``eth_getStorageAt`` of slot 0 against the published singletons
list, same as ``holder_facts``).  ``getThreshold()`` / ``getMinDelay()`` are used
exclusively to populate display metadata, never to change the ``kind`` field.

State parameters
----------------
``state_parameter_facts`` probes every public zero-arg entry function in the semantic map
that is not already covered by the HOLDER_GETTERS or the fixed reads in
``onchain_facts``.  Results are stored as ``state.<snake_name>`` facts.  The probe is
gas-capped (a single ``eth_call`` per function), read-only, and capped at
``MAX_STATE_PROBES`` total.

All RPC calls degrade gracefully: a failed call leaves the field absent, never raises.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from .facts import (
    HOLDER_GETTERS,
    _decode_word,
    _safe_proxy_prefix,
    _safe_singletons,
    fact,
    getter_selector,
)

logger = logging.getLogger(__name__)

RELATED_CONTRACTS_FILE = "related_contracts.json"

# Selector for getMinDelay() (TimelockController, OZ AccessControl-based)
_GET_MIN_DELAY_SEL = "0xf27a0c92"

# Selectors imported from proxy.py (avoid circular import: duplicate string only)
_SAFE_GET_OWNERS = "0xa0e67e2b"
_SAFE_GET_THRESHOLD = "0xe75235b8"
_SAFE_SENTINEL = "0x" + "0" * 39 + "1"

# Maximum number of state-parameter probes per job (including already-done HOLDER reads)
MAX_STATE_PROBES = 64

# Getter names already read by onchain_facts; skip them in state_parameter_facts
_ALREADY_READ: frozenset[str] = frozenset(
    {"owner", "totalSupply", "decimals"} | set(HOLDER_GETTERS)
)

# Convert camelCase → snake_case (same helper as in mapping.facts)
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _snake(name: str) -> str:
    return _CAMEL_RE.sub("_", name).lower()


# ---------------------------------------------------------------------------
# Safe proxy bytecode check (mirrors facts.is_safe_proxy_code)
# ---------------------------------------------------------------------------

def _is_safe_proxy(code_bytes: bytes) -> bool:
    prefix, max_bytes = _safe_proxy_prefix()
    return (
        0 < len(code_bytes) <= max_bytes
        and code_bytes.startswith(prefix)
        and len(code_bytes) > len(prefix)
        and code_bytes[len(prefix)] == 0xFE
    )


# ---------------------------------------------------------------------------
# ABI helpers for Safe reads (mirrors proxy.py without circular import)
# ---------------------------------------------------------------------------

def _decode_address_array(raw: bytes, offset: int) -> list[str]:
    """Decode a dynamic bytes32-array of addresses starting at `offset`."""
    if len(raw) < offset + 32:
        return []
    try:
        arr_off = int.from_bytes(raw[offset : offset + 32], "big")
        if arr_off + 32 > len(raw):
            return []
        count = int.from_bytes(raw[arr_off : arr_off + 32], "big")
        if count > 500:
            return []
        result = []
        for i in range(count):
            pos = arr_off + 32 + i * 32
            if pos + 32 > len(raw):
                break
            word = raw[pos : pos + 32]
            if word[:12] != b"\x00" * 12:
                break
            addr = "0x" + word[12:].hex()
            result.append(addr)
        return result
    except (ValueError, OverflowError):
        return []


def _decode_uint(raw_hex: str | None) -> int | None:
    """Decode a single uint256 from a 32-byte hex word."""
    if not raw_hex or not isinstance(raw_hex, str) or not raw_hex.startswith("0x"):
        return None
    try:
        word = raw_hex[2:]
        if len(word) < 64:
            word = word.zfill(64)
        return int(word[:64], 16)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Classify one address
# ---------------------------------------------------------------------------

async def _classify(
    rpc: Any,
    address: str,
    block: int,
) -> dict[str, Any]:
    """Return a classification record for one address."""
    entry: dict[str, Any] = {"address": address, "kind": "eoa", "verified": None, "name": None}
    try:
        code_hex = await rpc.get_code(address, block=block)
    except Exception as exc:  # noqa: BLE001
        logger.info("get_code %s failed: %s", address, type(exc).__name__)
        return entry  # unknown; leave as eoa default
    if not isinstance(code_hex, str) or not code_hex.startswith("0x"):
        return entry
    try:
        code_bytes = bytes.fromhex(code_hex[2:])
    except ValueError:
        return entry
    if not code_bytes:
        return entry  # EOA confirmed

    # Has code: at minimum it's a contract
    entry["kind"] = "contract"

    # Safe multisig structural detection
    if _is_safe_proxy(code_bytes):
        try:
            raw_slot = await rpc.get_storage_at(address, "0x" + "0" * 64, block=block)
        except Exception as exc:  # noqa: BLE001
            raw_slot = None
            logger.info("get_storage_at slot0 %s: %s", address, type(exc).__name__)
        singleton = _decode_word(raw_slot, "address") if isinstance(raw_slot, str) else None
        if singleton and singleton.lower() in _safe_singletons():
            entry["kind"] = "multisig"
            # Read owners and threshold
            try:
                raw_owners = await rpc.eth_call(address, _SAFE_GET_OWNERS, block=block)
                owners = _decode_address_array(bytes.fromhex(raw_owners[2:]) if raw_owners and raw_owners.startswith("0x") else b"", 0)
                entry["owners"] = owners
                entry["owners_count"] = len(owners)
            except Exception as exc:  # noqa: BLE001
                logger.info("getOwners %s: %s", address, type(exc).__name__)
            try:
                raw_th = await rpc.eth_call(address, _SAFE_GET_THRESHOLD, block=block)
                th = _decode_uint(raw_th)
                if th is not None:
                    entry["threshold"] = th
            except Exception as exc:  # noqa: BLE001
                logger.info("getThreshold %s: %s", address, type(exc).__name__)
            return entry

    # For any non-EOA, non-Safe contract: attempt getMinDelay() (informational)
    try:
        raw_delay = await rpc.eth_call(address, _GET_MIN_DELAY_SEL, block=block)
        delay = _decode_uint(raw_delay)
        if delay is not None and delay > 0:
            entry["min_delay_s"] = delay
    except Exception as exc:  # noqa: BLE001
        logger.debug("getMinDelay %s: %s", address, type(exc).__name__)

    return entry


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def classify_related_contracts(
    rpc: Any,
    block: int,
    onchain_fact_list: list[dict[str, Any]],
    chain_id: int | None = None,
) -> list[dict[str, Any]]:
    """Classify all unique non-zero addresses from ``onchain_facts`` output.

    For each address of kind ``contract`` or ``multisig``, checks Sourcify for
    verified source (requires ``chain_id``).  The ``verified`` field is:
    - ``True``  – Sourcify has an exact_match or match
    - ``False`` – Sourcify returned 404 (not verified)
    - ``None``  – unknown (no chain_id supplied, or network error)

    Returns a list of classification dicts, one per unique address, de-duplicated
    and ordered by the fact key they were first seen under.
    """
    from .verify import check_sourcify_verified  # lazy import to avoid circular at module level

    # Collect (role, address) pairs from holder facts and EIP-1967 slots
    role_map: dict[str, str] = {}  # address (lower) -> first role name seen
    for f in onchain_fact_list:
        key = f.get("key", "")
        value = f.get("value", "")
        if not isinstance(value, str) or not value.startswith("0x"):
            continue
        # Only address-looking values (20-byte hex after 0x)
        hex_part = value[2:]
        if len(hex_part) != 40:
            continue
        try:
            int(hex_part, 16)
        except ValueError:
            continue
        if int(hex_part, 16) == 0:
            continue  # zero address is not interesting
        addr_lower = value.lower()
        if addr_lower not in role_map:
            # Derive a human role label from the fact key
            role_label = _role_label_from_key(key)
            role_map[addr_lower] = role_label

    results: list[dict[str, Any]] = []
    for address, role in role_map.items():
        entry = await _classify(rpc, address, block)
        entry["role"] = role

        # Check source verification for contracts/multisigs when chain_id is known
        if chain_id is not None and entry["kind"] in ("contract", "multisig"):
            try:
                verified, name = await check_sourcify_verified(chain_id, address)
            except Exception as exc:  # noqa: BLE001
                logger.debug("verify: check failed for %s: %s", address, type(exc).__name__)
                verified, name = None, None
            entry["verified"] = verified
            if name:
                entry["name"] = name
        else:
            entry["verified"] = None  # EOA or unknown chain

        results.append(entry)

    return results


def _role_label_from_key(key: str) -> str:
    """'onchain.owner' -> 'owner', 'onchain.governance' -> 'governance', etc."""
    # strip 'onchain.' prefix, drop '.holder_*' suffixes
    stem = key.removeprefix("onchain.")
    stem = stem.split(".")[0]  # drop any sub-key like .holder_kind
    return stem


# ---------------------------------------------------------------------------
# State parameter facts
# ---------------------------------------------------------------------------

async def state_parameter_facts(
    rpc: Any,
    address: str,
    block: int,
    map_doc: dict[str, Any] | None,
    unit_id: str | None,
) -> list[dict[str, Any]]:
    """Probe all public zero-arg entry functions not already read by ``onchain_facts``.

    Returns ``state.<snake_name>`` facts for each successful read.  The value is
    decoded as: address (top-12 bytes zero, bottom-20 non-zero), uint, or uint
    (bool is a subtype of uint in this representation).  Boolean values (0 or 1)
    that fit in a uint8 are stored as the string ``"true"`` / ``"false"`` when the
    function name starts with ``is`` / ``has`` / ``can`` / ``paused`` / ``enabled``
    (naming convention); all others are stored as decimal strings.

    Capped at ``MAX_STATE_PROBES`` calls total (all holder probes count toward this
    budget; the cap prevents DoS on contracts with many getters).
    """
    names = _getter_names_to_probe(map_doc, unit_id)
    out: list[dict[str, Any]] = []
    probes_done = 0

    for name in sorted(names):
        if probes_done >= MAX_STATE_PROBES:
            break
        sel = getter_selector(name)
        probes_done += 1
        try:
            raw = await rpc.eth_call(address, sel, block=block)
        except Exception as exc:  # noqa: BLE001
            logger.debug("eth_call %s() failed: %s", name, type(exc).__name__)
            continue
        value = _decode_state_value(raw, name)
        if value is None:
            continue
        key = f"state.{_snake(name)}"
        # Validate key grammar
        if not re.fullmatch(r"[a-z][a-z0-9_.]*", key):
            continue
        out.append(fact(key, value, unit=None, unit_id=unit_id,
                        source=f"eth_call {name}() at block {block}"))
    return out


def _getter_names_to_probe(
    map_doc: dict[str, Any] | None,
    unit_id: str | None,  # reserved for future unit-scoping
) -> set[str]:
    """Names to probe: public entry functions + public state vars, minus already-read ones."""
    sem = (map_doc or {}).get("semantic") or {}
    spans = {s["id"]: s for s in (map_doc or {}).get("spans") or []}
    names: set[str] = set()
    for f in sem.get("functions") or []:
        if not f.get("is_entry"):
            continue
        sp = spans.get(f.get("span", "")) or {}
        name = sp.get("name", "")
        if name and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
            names.add(name)
    for v in sem.get("state_vars") or []:
        name = v.get("name", "")
        if name and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
            names.add(name)
    return names - _ALREADY_READ


def _decode_state_value(raw: str | None, name: str) -> str | None:
    """Decode a 32-byte eth_call result as address, bool, or uint.

    Priority order (prevents misclassifying ``paused=1`` as address ``0x...0001``):
    1. Bool by naming convention (is*, has*, can*, paused, …): 0/1 → "false"/"true".
    2. Address: top-12 bytes zero, bottom-20 bytes with enough entropy (≥4 non-zero bytes).
    3. All-zero result: not interesting (default storage) → None.
    4. Uint: everything else.
    """
    if not raw or not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    hex_data = raw[2:]
    if len(hex_data) < 64:
        hex_data = hex_data.zfill(64)
    word = hex_data[:64]
    try:
        n = int(word, 16)
    except ValueError:
        return None

    # 1. Bool by naming convention: check BEFORE address to avoid 0x..0001 misclassification
    low = name.lower()
    if (low.startswith(("is", "has", "can")) or low in ("paused", "enabled", "frozen", "active",
                                                          "initialized", "deprecated", "killed",
                                                          "stopped", "halted", "locked")):
        if n == 0:
            return "false"
        if n == 1:
            return "true"
        # Bool name but value not 0/1 — fall through to uint

    # 2. Address: top-12 bytes zero AND bottom-20 bytes have ≥4 non-zero bytes
    #    (filters out small integers like 1, 2, … which also have top-12 = 0)
    top = int(word[:24], 16)
    if top == 0 and n != 0:
        bottom_bytes = bytes.fromhex(word[24:])
        nonzero_count = sum(1 for b in bottom_bytes if b != 0)
        if nonzero_count >= 4:
            return "0x" + word[24:]

    # 3. All zeros: not interesting (zero is the default value, not a meaningful state)
    if n == 0:
        return None

    # 4. Uint
    return str(n)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def write_related_contracts(
    root: Path,
    job_id: str,
    contracts: list[dict[str, Any]],
) -> None:
    """Write ``<pin_root>/<job_id>/related_contracts.json``."""
    d = root / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / RELATED_CONTRACTS_FILE).write_text(
        json.dumps(contracts, indent=1),
        encoding="utf-8",
    )


def load_related_contracts(root: Path, job_id: str) -> list[dict[str, Any]]:
    """Return related-contracts list; empty list when not present."""
    p = root / job_id / RELATED_CONTRACTS_FILE
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []
