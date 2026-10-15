"""EVM chain registry loader (05 section 4.1).

Loads data/chains.json, exposes typed chain records and lookup helpers.
Every value in chains.json carries source_url and checked_at per the plan spec.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DATA_FILE = Path(__file__).with_suffix("").parent / "data" / "chains.json"


@dataclass
class RpcEntry:
    """One RPC endpoint row (09 allowlist format)."""

    url: str
    log_window: int
    archive: bool
    source_url: str
    checked_at: str


@dataclass
class ChainRecord:
    """One row from data/chains.json (05 4.1)."""

    chain_id: int
    family: str                      # evm | hyperevm | tron
    name: str
    address_format: str              # evm_checksum | tron_base58
    enabled: bool
    native_symbol: str
    native_decimals: int
    addr_url: str | None             # template or null (no licence row yet)
    rpc: list[RpcEntry]
    sourcify_supported: bool
    inactive_opcodes: list[str]      # measured by scripts/measure_opcodes.py (F18)
    opcodes_measured: bool           # opcode_probe.measured; False: 6.4 reports not_checked
    selfdestruct_semantics: str | None  # eip6780 | legacy | tron_restricted | null
    raw: dict[str, Any]              # original JSON for provenance fields


def _load_chains() -> dict[int, ChainRecord]:
    with _DATA_FILE.open() as fh:
        data = json.load(fh)
    result: dict[int, ChainRecord] = {}
    for entry in data["chains"]:
        rpcs = [
            RpcEntry(
                url=r["url"],
                log_window=r["log_window"],
                archive=r["archive"],
                source_url=r["source_url"],
                checked_at=r["checked_at"],
            )
            for r in entry.get("rpc", [])
        ]
        sd = entry.get("selfdestruct_semantics")
        sd_val = sd["value"] if isinstance(sd, dict) else sd
        src_sup = entry.get("sourcify_supported", {})
        src_supported = src_sup.get("value", False) if isinstance(src_sup, dict) else bool(src_sup)
        rec = ChainRecord(
            chain_id=int(entry["chain_id"]),
            family=entry["family"],
            name=entry["name"],
            address_format=entry["address_format"],
            enabled=entry.get("enabled", False),
            native_symbol=entry.get("native_symbol", ""),
            native_decimals=entry.get("native_decimals", 18),
            addr_url=entry.get("addr_url"),
            rpc=rpcs,
            sourcify_supported=src_supported,
            inactive_opcodes=entry.get("inactive_opcodes", []),
            # EVM chains: a complete probe run; TRON: getchainparameters keys (F41), no probe
            opcodes_measured=bool((entry.get("opcode_probe") or {}).get("measured"))
            or (entry["family"] == "tron" and "inactive_opcodes_source" in entry),
            selfdestruct_semantics=sd_val,
            raw=entry,
        )
        result[rec.chain_id] = rec
    return result


# Module-level singleton; reload with reload_registry() in tests.
_REGISTRY: dict[int, ChainRecord] = {}


def _ensure_loaded() -> None:
    global _REGISTRY
    if not _REGISTRY:
        _REGISTRY = _load_chains()


def get_chain(chain_id: int) -> ChainRecord | None:
    """Return chain record or None if unknown (05 4.1)."""
    _ensure_loaded()
    return _REGISTRY.get(chain_id)


def all_chains() -> list[ChainRecord]:
    """All enabled chain records."""
    _ensure_loaded()
    return list(_REGISTRY.values())


def enabled_chains() -> list[ChainRecord]:
    """Chains with enabled=true (SCOPE section 1 EVM release list gate Q3)."""
    return [c for c in all_chains() if c.enabled]


def reload_registry() -> None:
    """Force reload from disk (used in tests)."""
    global _REGISTRY
    _REGISTRY = _load_chains()
