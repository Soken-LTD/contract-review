"""`resolve_provenance` for TON units (plan v4 06 2.4, 2.5; dep_match.yaml `ton`).

Supervisor function and sole producer of `match` for a TON unit. `attempt(cand)` runs one build
container and returns the hashes the supervisor computed from the BoC files the container wrote
(`{target: hash}`); a container never supplies a hash.

TON has no owner link (06 2.3: the verifier registry is pay-to-submit and there is no on-chain
owner statement), so a unit with an address resolves to `exact` (tier A) or to a section 9
outcome (tier D). Without an address the user source is reviewed as tier B.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from soken_review.adapters.base import Candidate

# 06 2.5 reason codes used by TON
MATCH_REBUILD = "MATCH_REBUILD"
NO_DEPLOYMENT_GIVEN = "NO_DEPLOYMENT_GIVEN"
NO_DEPLOYED_CODE = "NO_DEPLOYED_CODE"
NO_SOURCE_FOUND = "NO_SOURCE_FOUND"
NO_CHECKABLE_SOURCE = "NO_CHECKABLE_SOURCE"
SOURCE_NOT_OWNER_LINKED = "SOURCE_NOT_OWNER_LINKED"

# 04 tier per reason (08 tier_labels keys in the comment)
_TIER = {
    MATCH_REBUILD: "A",            # tier_a
    NO_DEPLOYMENT_GIVEN: "B",      # tier_b_commit / tier_b_files
    NO_DEPLOYED_CODE: "D",         # section 9
    NO_SOURCE_FOUND: "D",
    NO_CHECKABLE_SOURCE: "D",
    SOURCE_NOT_OWNER_LINKED: "D",
}


@dataclass
class Attempt:
    cand_index: int
    provider: str
    status: str                         # ok | compile_error | unsupported_toolchain | untrusted_args | ...
    hashes: dict[str, str] = field(default_factory=dict)   # target -> supervisor-computed hash
    untrusted_inputs: bool = False
    build_config: dict[str, Any] | None = None   # exact compiler config used (Tact projects/options)


@dataclass
class Dep:
    address: str                        # raw address
    status: str                         # active | uninit | frozen | nonexist
    hash: str | None                    # code hash, or library body hash when library-coded
    why: str | None = None              # library_not_found | code_not_hashable


@dataclass
class Out:
    src: int | None                     # index of the candidate that enters the pinned store
    match: str | None                   # exact | None
    reason: str
    tried: list[Attempt] = field(default_factory=list)
    matched_target: str | None = None
    dep_hash: str | None = None
    build_hash: str | None = None
    why: str | None = None

    @property
    def tier(self) -> str:
        return _TIER[self.reason]

    def to_json(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "match": self.match,
            "reason": self.reason,
            "tier": self.tier,
            "why": self.why,
            "dep_hash": self.dep_hash,
            "build_hash": self.build_hash,
            "matched_target": self.matched_target,
            "tried": [
                {
                    "cand": a.cand_index,
                    "provider": a.provider,
                    "status": a.status,
                    "hashes": a.hashes,
                    "untrusted_inputs": a.untrusted_inputs,
                    "build_config": a.build_config,
                }
                for a in self.tried
            ],
            "checks": self.checks(),
        }

    def checks(self) -> list[dict[str, Any]]:
        """Report checks[] rows for the source used: the exact compiler config it was built with."""
        used = next((a for a in self.tried if a.cand_index == self.src), None)
        if used is None or not used.build_config:
            return []
        return [{"check": "tact_config", "value": used.build_config}]


def resolve_provenance(
    dep: Dep | None,
    cands: list[Candidate],
    attempt: Callable[[int, Candidate], Attempt],
) -> Out:
    """06 2.4 for TON. Total: always returns an Out."""
    if dep is None:
        for i, c in enumerate(cands):
            if c.provider in ("user", "repo"):
                return Out(i, None, NO_DEPLOYMENT_GIVEN, tried=[attempt(i, c)])
        return Out(None, None, NO_SOURCE_FOUND)
    if dep.status != "active":
        return Out(None, None, NO_DEPLOYED_CODE, why=dep.status)
    if not cands:
        return Out(None, None, NO_SOURCE_FOUND, dep_hash=dep.hash)
    if dep.hash is None:
        # no owner-linked candidate exists on TON, so this is never DEPLOYMENT_NOT_HASHABLE
        return Out(None, None, NO_CHECKABLE_SOURCE, why=dep.why)

    tried: list[Attempt] = []
    for i, c in enumerate(cands):
        a = attempt(i, c)
        tried.append(a)
        untrusted = c.untrusted_inputs or a.untrusted_inputs
        if a.status != "ok" or untrusted:
            continue
        for target, h in a.hashes.items():
            if h == dep.hash:
                return Out(i, "exact", MATCH_REBUILD, tried=tried, matched_target=target,
                           dep_hash=dep.hash, build_hash=h)
    build_hash = next((h for a in tried for h in a.hashes.values()), None)
    return Out(None, None, SOURCE_NOT_OWNER_LINKED, tried=tried, dep_hash=dep.hash,
               build_hash=build_hash, why=_why(tried))


def _why(tried: list[Attempt]) -> str:
    if any(a.status == "ok" and not a.untrusted_inputs for a in tried):
        return "rebuild_differs"
    if any(a.untrusted_inputs for a in tried):
        return "untrusted_inputs"
    return tried[0].status if tried else "no_attempt"
