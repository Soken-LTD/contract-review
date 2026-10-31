"""Free endpoint pool per chain family (chain access design 2.1; CEO 2026-10-28: zero budget).

Only free sources: the endpoints of `chains.json` (EVM) plus the measured free pool of
`chain/data/free_rpc.json`, TronGrid keyless, the public Solana RPC and toncenter v2 keyless.
Optional free-tier keys (no cost) are environment variables named in `.env.example`, never in code:

    SOKEN_CHAIN_RPC_<chain_id>    comma-separated extra RPC URLs for one EVM chain, for example a
                                  free-tier key endpoint; tried first
    SOKEN_RPC_<chain_id>          existing single override used by the pipeline
    TRON_GRID_API_KEY             TronGrid free key (header TRON-PRO-API-KEY), raises the keyless limit
    SOKEN_SOLANA_RPC              Solana RPC URL (a free-tier key URL, for example)
    SOKEN_TONCENTER_API_KEY       toncenter free key (header X-API-Key)

The pool rotates: `ordered()` puts endpoints that can serve the requested depth first (by the
measured `depth` and by what each host failed to serve at run time), skips hosts that are cooling
down after a rate limit or an outage, and rotates the start among equals so one free host does
not take every call. `capability()` and the tool results say honestly what a free source capped.

URLs may carry a key in the path or query; only `redact(url)` (scheme and host) ever leaves this
module, in results, logs or facts.
"""

from __future__ import annotations

import itertools
import json
import os
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar

from ..adapters.evm.rpc import _redact as redact

TRONGRID = "https://api.trongrid.io"
SOLANA_PUBLIC = "https://api.mainnet-beta.solana.com"
TONCENTER_V2 = "https://toncenter.com/api/v2"


_FREE_RPC = Path(__file__).resolve().parent / "data" / "free_rpc.json"
DEPTH_BLOCKS = {"head": 100, "recent": 5_000, "archive": 1 << 62, "unknown": 100}


@dataclass(frozen=True)
class Endpoint:
    url: str
    keyed: bool                 # an optional free-tier key is configured for it
    depth: str = "unknown"      # head | recent | archive | unknown (measured, see free_rpc.json)
    headers: tuple[tuple[str, str], ...] = ()
    per_s: float = 5.0

    @property
    def host(self) -> str:
        return redact(self.url)

    @property
    def archive(self) -> bool:
        return self.depth == "archive"

    @property
    def operator(self) -> str | None:
        return operator_of(self.url)


class Health:
    """Per-host run-time memory: cooldown after a rate limit or outage, and the shallowest depth
    (blocks behind the head) a host failed to serve, so later deep reads skip it for an hour."""

    cool_until: ClassVar[dict[str, float]] = {}
    no_state_depth: ClassVar[dict[str, tuple[int, float]]] = {}
    fails: ClassVar[dict[str, int]] = {}
    _rot = itertools.count()

    @classmethod
    def ok(cls, host: str) -> None:
        cls.fails[host] = 0

    @classmethod
    def fail(cls, host: str, reason: str) -> None:
        n = cls.fails.get(host, 0) + 1
        cls.fails[host] = n
        if reason in ("rate_limited", "upstream"):
            cls.cool_until[host] = time.monotonic() + min(300.0, 15.0 * n)

    @classmethod
    def no_state(cls, host: str, depth: int | None) -> None:
        if depth is None:
            return
        prev = cls.no_state_depth.get(host)
        if prev is None or depth < prev[0] or time.monotonic() > prev[1]:
            cls.no_state_depth[host] = (max(0, depth), time.monotonic() + 3600.0)

    @classmethod
    def reset(cls) -> None:
        cls.cool_until.clear()
        cls.no_state_depth.clear()
        cls.fails.clear()


def ordered(eps: list[Endpoint], depth: int | None = None) -> list[Endpoint]:
    """The pool in the order to try for a read `depth` blocks behind the head (None: unknown or
    latest). Hosts that cannot serve the depth or are cooling down go last, never away: a stale
    measurement must not hide the only host that would have answered."""
    now = time.monotonic()
    rot = next(Health._rot)

    def rank(ix_ep: tuple[int, Endpoint]) -> tuple[int, int, int, int, int]:
        i, ep = ix_ep
        d = depth or 0
        fits = d <= DEPTH_BLOCKS.get(ep.depth, 100)
        ns = Health.no_state_depth.get(ep.host)
        failed_here = bool(ns and now < ns[1] and d >= ns[0])   # this host already said it has no such state
        cooling = Health.cool_until.get(ep.host, 0.0) > now
        return (1 if failed_here else 0, 0 if fits else 1, 1 if cooling else 0, 0 if ep.keyed else 1,
                (i - rot) % max(len(eps), 1))

    return [ep for _i, ep in sorted(enumerate(eps), key=rank)]


@lru_cache(maxsize=1)
def _free_rpc() -> dict[str, Any]:
    return json.loads(_FREE_RPC.read_text(encoding="utf-8"))


def operator_of(url: str) -> str | None:
    """Independent operator of a host from the curated `operators` table of free_rpc.json (longest
    matching suffix), None for a host the table does not know. Used for cache quorum only."""
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    table = {k: v for k, v in (_free_rpc().get("operators") or {}).items() if not k.startswith("_")}
    best = None
    for suffix, op in table.items():
        if (host == suffix or host.endswith("." + suffix)) and (best is None or len(suffix) > len(best[0])):
            best = (suffix, op)
    return best[1] if best else None


@dataclass
class Capability:
    family: str
    keyed: bool
    history: str            # "archive" | "recent" (about 5,000 blocks) | "head" (about 100) | "latest_only"
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"family": self.family, "keyed": self.keyed, "history": self.history,
                "sources": self.sources[:6], "degraded": bool(self.notes), "notes": self.notes[:4]}


def _split(v: str | None) -> list[str]:
    return [u.strip() for u in (v or "").split(",") if u.strip()]


def evm_endpoints(chain_id: int) -> list[Endpoint]:
    """Optional free-tier URLs, the pipeline override, the measured pool (best first), then the
    registry rows the probe did not rank, and last the rows the probe found down."""
    out = [Endpoint(u, keyed=True, depth="unknown", per_s=10.0) for u in _split(os.environ.get(f"SOKEN_CHAIN_RPC_{chain_id}"))]
    override = os.environ.get(f"SOKEN_RPC_{chain_id}")
    if override:
        out.append(Endpoint(override, keyed=True, depth="unknown", per_s=10.0))
    free = _free_rpc()
    down = set((free.get("down") or {}).get(str(chain_id)) or [])
    for row in (free.get("chains") or {}).get(str(chain_id)) or []:
        if all(e.url != row["url"] for e in out):
            out.append(Endpoint(row["url"], keyed=False, depth=row.get("depth", "unknown"), per_s=4.0))
    from ..adapters.evm.registry import get_chain

    rec = get_chain(chain_id)
    # the registry's archive flag is not trusted: depth comes from the measured pool only
    rows = [r.url for r in (rec.rpc if rec else []) if not r.disabled]
    for url in sorted(rows, key=lambda u: u in down):
        if all(e.url != url for e in out):
            out.append(Endpoint(url, keyed=False, depth="unknown", per_s=4.0))
    return out


def tron_endpoints() -> list[Endpoint]:
    key = os.environ.get("TRON_GRID_API_KEY", "")
    out = [Endpoint(TRONGRID, keyed=True, depth="head", headers=(("TRON-PRO-API-KEY", key),), per_s=10.0)] if key else []
    out.append(Endpoint(TRONGRID, keyed=False, depth="head", per_s=2.0))
    return out


def solana_endpoints() -> list[Endpoint]:
    url = os.environ.get("SOKEN_SOLANA_RPC", "")
    out = [Endpoint(url, keyed=True, depth="head", per_s=10.0)] if url and url != SOLANA_PUBLIC else []
    out.append(Endpoint(SOLANA_PUBLIC, keyed=False, depth="head", per_s=3.0))
    return out


def ton_endpoints() -> list[Endpoint]:
    key = os.environ.get("SOKEN_TONCENTER_API_KEY", "")
    if key:
        return [Endpoint(TONCENTER_V2, keyed=True, depth="archive", headers=(("X-API-Key", key),), per_s=10.0)]
    return [Endpoint(TONCENTER_V2, keyed=False, depth="archive", per_s=0.9)]


def endpoints(family: str, chain_id: int | None = None) -> list[Endpoint]:
    if family == "evm":
        return evm_endpoints(int(chain_id or 0))
    return {"tron": tron_endpoints, "solana": solana_endpoints, "ton": ton_endpoints}[family]()


def capability(family: str, chain_id: int | None = None) -> Capability:
    eps = endpoints(family, chain_id)
    keyed = any(e.keyed for e in eps)
    hosts = [e.host for e in eps]
    if family == "evm":
        archive = any(e.archive for e in eps)
        recent = any(e.depth in ("archive", "recent") for e in eps)
        cap = Capability("evm", keyed, "archive" if archive else "recent" if recent else "head", hosts)
        arch_hosts = [e.host for e in eps if e.archive]
        if not archive:
            cap.notes.append("No free endpoint in the pool serves old state for this chain: reads more than about "
                             f"{'5,000' if recent else '100'} blocks behind the head (the pinned block once it is that "
                             "old) can fail; read at latest instead.")
        elif len(arch_hosts) == 1:
            cap.notes.append(f"Only one free endpoint in the pool is known to serve old state for this chain "
                             f"({arch_hosts[0]}); a read at an old block fails when that host refuses.")
        cap.notes.append("Free public endpoints only: calls are rate limited and a host may refuse or time out; the "
                         "pool rotates and falls back, and an item says so when every host failed.")
        return cap
    if family == "tron":
        cap = Capability("tron", keyed, "latest_only", hosts)
        cap.notes.append("TRON nodes serve the latest state only; every value is labelled with the block it was read at.")
        if not keyed:
            cap.notes.append("TronGrid without a key allows about 2 calls per second.")
        return cap
    if family == "solana":
        cap = Capability("solana", keyed, "latest_only", hosts)
        cap.notes.append("Solana JSON-RPC has no account state at a past slot; values carry the slot they were read at.")
        if not keyed:
            cap.notes.append("Public Solana RPC only: calls are rate limited.")
        return cap
    cap = Capability("ton", keyed, "archive", hosts)
    if not keyed:
        cap.notes.append("toncenter without a key allows about 1 call per second.")
    return cap
