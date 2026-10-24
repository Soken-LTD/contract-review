"""Chain families and the launch switch that turns one off (decision 2026-10-23: launch without
Starknet while the worker host has 3.9 GiB and Scarb/Caracal builds need 8 GiB; 2026-10-24: launch
without Sui, whose lock v4 / framework-rev builds fail offline, while Aptos in the same family stays).

`SOKEN_DISABLED_FAMILIES` (comma list of family or chain names, e.g. `starknet,sui`) is read on every call, so
a unit restart is the whole rollout. A disabled family is refused at `review_start` with
E_CHAIN_DISABLED (deployed chain, deployment of a repo/upload/files source, inline language) and a
repo-only job whose tree turns out to be that family ends `failed` with the same code."""

from __future__ import annotations

import os

from .errors import ReviewError

FAMILY_OF_CHAIN = {"evm": "evm", "hyperevm": "evm", "tron": "evm", "solana": "solana", "ton": "ton",
                   "sui": "move", "aptos": "move", "starknet": "starknet"}
FAMILY_OF_LANGUAGE = {"solidity": "evm", "vyper": "evm", "func": "ton", "tact": "ton", "tolk": "ton",
                      "move_sui": "move", "move_aptos": "move", "cairo": "starknet"}
# Languages bound to one chain, so a chain entry in the switch (`sui`) also refuses its inline language.
CHAIN_OF_LANGUAGE = {"move_sui": "sui", "move_aptos": "aptos", "cairo": "starknet"}


def disabled_families() -> set[str]:
    raw = os.environ.get("SOKEN_DISABLED_FAMILIES", "")
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def family_disabled(*, chain: str | None = None, language: str | None = None) -> str | None:
    """The disabled family (or chain) `chain` or `language` belongs to, else None."""
    off = disabled_families()
    if not off:
        return None
    for fam in (FAMILY_OF_CHAIN.get(chain or ""), FAMILY_OF_LANGUAGE.get(language or "")):
        if fam and fam in off:
            return fam
    for name in (chain, CHAIN_OF_LANGUAGE.get(language or "")):
        if name and name in off:
            return name
    return None


def enabled_chains() -> list[str]:
    off = disabled_families()
    return sorted(c for c, fam in FAMILY_OF_CHAIN.items() if fam not in off and c not in off)


def require_enabled(*, chain: str | None = None, language: str | None = None) -> None:
    if family_disabled(chain=chain, language=language):
        raise ReviewError("E_CHAIN_DISABLED", value=chain or language or "", enabled=", ".join(enabled_chains()))
