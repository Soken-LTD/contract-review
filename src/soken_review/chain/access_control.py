"""OpenZeppelin AccessControl holders without an indexer (blind round 5b: review_chain_roles returned
no holders for TimelockController and AccessControl contracts).

Members come from `getRoleMember` when the contract is AccessControlEnumerable, else from the
contract's own RoleGranted / RoleRevoked logs read through the free pool in bounded ranges, every
candidate confirmed with `hasRole` at the resolved block. Free endpoints cap log ranges (10 to
100,000 blocks) and many refuse old ranges, so a long-lived contract is scanned at both ends (from
its creation block forward, from the read block back) within a call cap; anything not covered makes
the answer `complete: false` with the blocks that were and were not read. A role a log shows but
`hasRole` denies is reported as revoked, never as a holder.

Role names are labels only: a contract constant read on chain, else keccak256 of a common role name
that matches the id, else `role_<first 8 hex>`. No text from logs ever reaches a result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..mapping.keccak import keccak256

ROLE_GRANTED = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
ROLE_REVOKED = "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b"
IACCESS_CONTROL = bytes.fromhex("7965db0b")
IACCESS_CONTROL_ENUMERABLE = bytes.fromhex("5a05180f")
DEFAULT_ADMIN = b"\0" * 32
ZERO = "0x" + "0" * 40
# Common role constant names (OpenZeppelin, TimelockController, frequent protocol roles). Reference data: an
# id is named from this list only when keccak256(name) equals it exactly.
COMMON_ROLE_NAMES = (
    "TIMELOCK_ADMIN_ROLE", "PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE", "ADMIN_ROLE", "MINTER_ROLE",
    "BURNER_ROLE", "PAUSER_ROLE", "UNPAUSER_ROLE", "UPGRADER_ROLE", "OPERATOR_ROLE", "MANAGER_ROLE",
    "GUARDIAN_ROLE", "GOVERNOR_ROLE", "GOVERNANCE_ROLE", "KEEPER_ROLE", "STRATEGIST_ROLE", "EMERGENCY_ROLE",
    "ORACLE_ROLE", "LIQUIDATOR_ROLE", "TREASURY_ROLE", "FEE_MANAGER_ROLE", "RISK_MANAGER_ROLE",
    "WHITELIST_ROLE", "BLACKLISTER_ROLE", "RELAYER_ROLE", "BRIDGE_ROLE", "REBALANCER_ROLE", "HARVESTER_ROLE",
    "VAULT_MANAGER_ROLE", "POOL_ADMIN_ROLE", "EMERGENCY_ADMIN_ROLE", "CONFIGURATOR_ROLE", "SETTER_ROLE",
)
_HEX32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_QTY = re.compile(r"^0x[0-9a-fA-F]{1,16}$")


def common_role_ids() -> dict[bytes, str]:
    return {keccak256(n.encode()): n for n in COMMON_ROLE_NAMES}


@dataclass(frozen=True)
class RoleEvent:
    block: int
    index: int
    tx: str
    granted: bool
    role: bytes
    account: str


def parse_log(log: Any, address: str) -> RoleEvent | None:
    """A RoleGranted / RoleRevoked log of `address`, or None for anything malformed or foreign."""
    if not isinstance(log, dict) or log.get("removed"):
        return None
    if str(log.get("address") or "").lower() != address.lower():
        return None
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) != 4 or not all(isinstance(t, str) and _HEX32.match(t) for t in topics):
        return None
    t0 = topics[0].lower()
    if t0 not in (ROLE_GRANTED, ROLE_REVOKED):
        return None
    acct = topics[2].lower()
    if int(acct[2:26], 16):
        return None
    bn, li, tx = log.get("blockNumber"), log.get("logIndex"), str(log.get("transactionHash") or "")
    if not (isinstance(bn, str) and _QTY.match(bn) and isinstance(li, str) and _QTY.match(li)):
        return None
    return RoleEvent(int(bn, 16), int(li, 16), tx.lower() if _HEX32.match(tx) else "", t0 == ROLE_GRANTED,
                     bytes.fromhex(topics[1][2:]), "0x" + acct[26:])


def replay(events: list[RoleEvent]) -> tuple[dict[bytes, set[str]], dict[bytes, set[str]]]:
    """(members now per the logs, every account ever granted) per role, in (block, log index) order."""
    now: dict[bytes, set[str]] = {}
    ever: dict[bytes, set[str]] = {}
    seen: set[tuple[int, int, str]] = set()
    for ev in sorted(events, key=lambda e: (e.block, e.index)):
        k = (ev.block, ev.index, ev.tx)
        if k in seen:
            continue
        seen.add(k)
        if ev.granted:
            now.setdefault(ev.role, set()).add(ev.account)
            ever.setdefault(ev.role, set()).add(ev.account)
        else:
            now.setdefault(ev.role, set()).discard(ev.account)
            ever.setdefault(ev.role, set())
    return now, ever


@dataclass
class ScanPlan:
    """Log windows for [first, last] with `calls` getLogs of `chunk` blocks: the whole span when it fits,
    else the first half of the calls from `first` forward and the rest from `last` back."""
    first: int | None
    last: int
    chunk: int
    calls: int
    windows: list[tuple[int, int]] = field(default_factory=list)
    split: int = 0              # index of the first window counted back from `last` (0: one pass)

    def __post_init__(self) -> None:
        c, n, lo, last = max(1, self.chunk), max(1, self.calls), self.first, self.last
        if lo is not None and last - lo + 1 <= c * n:
            self.windows = [(b, min(b + c - 1, last)) for b in range(lo, last + 1, c)]
            return
        fwd = n // 2 if lo is not None else 0
        wins = [(lo + i * c, lo + (i + 1) * c - 1) for i in range(fwd)] if lo is not None else []
        self.split = len(wins)
        for i in range(n - fwd):   # no overlap: the span is longer than all the windows together
            hi = last - i * c
            if hi < 0:
                break
            wins.append((max(hi - c + 1, 0), hi))
        self.windows = wins


def merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def covered(ranges: list[tuple[int, int]], first: int | None, last: int) -> bool:
    if first is None:
        return False
    return any(lo <= first and hi >= last for lo, hi in merge(ranges))


def blocks_in(ranges: list[tuple[int, int]]) -> int:
    return sum(hi - lo + 1 for lo, hi in merge(ranges))
