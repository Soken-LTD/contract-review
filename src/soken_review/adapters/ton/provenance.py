"""`resolve_provenance` for TON units (plan v4 06 2.4, 2.5; dep_match.yaml `ton`).

Supervisor function and sole producer of `match` for a TON unit. `attempt(cand)` runs one build
container and returns the hashes the supervisor computed from the BoC files the container wrote
(`{target: hash}`); a container never supplies a hash.

TON has no owner link (06 2.3: the verifier registry is pay-to-submit and there is no on-chain
owner statement), so a unit with an address resolves to `exact` (tier A) or to a section 9
outcome (tier D). Without an address the user source is reviewed as tier B.

A unit with an address AND a source the requester named (repo or files) that cannot be tied to the
deployed code (rebuild differs, untrusted build inputs, no compiler, no active code at the address)
is SOURCE_UNLINKED, tier B: the named source is reviewed, the cover says the deployment could not be
matched, and the job never stops in insufficient_source for it (Hipo blind run 2026-10-27: a third
party could not review a public FunC repo at all). Tier D stays for verifier-only units.
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
SOURCE_TOOLCHAIN_GAP = "SOURCE_TOOLCHAIN_GAP"
SOURCE_UNLINKED = "SOURCE_UNLINKED"

# 04 tier per reason (08 tier_labels keys in the comment)
_TIER = {
    MATCH_REBUILD: "A",            # tier_a
    NO_DEPLOYMENT_GIVEN: "B",      # tier_b_commit / tier_b_files
    SOURCE_TOOLCHAIN_GAP: "B",     # tier_b_third_party (verifier-attested, rebuild skipped)
    SOURCE_UNLINKED: "B",          # tier_b_not_checked (requester's source, deployment not matched)
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
    named = next((i for i, c in enumerate(cands) if c.provider in ("user", "repo")), None)
    if dep is None:
        if named is not None:
            return Out(named, None, NO_DEPLOYMENT_GIVEN, tried=[attempt(named, cands[named])])
        return Out(None, None, NO_SOURCE_FOUND)
    if dep.status != "active":
        if named is not None:
            return Out(named, None, SOURCE_UNLINKED, tried=[attempt(named, cands[named])], why=dep.status)
        return Out(None, None, NO_DEPLOYED_CODE, why=dep.status)
    if not cands:
        return Out(None, None, NO_SOURCE_FOUND, dep_hash=dep.hash)
    if dep.hash is None:
        # no owner-linked candidate exists on TON, so this is never DEPLOYMENT_NOT_HASHABLE
        if named is not None:
            return Out(named, None, SOURCE_UNLINKED, tried=[attempt(named, cands[named])],
                       why=dep.why or "code_not_hashable")
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

    # Toolchain-gap promotion (06 2.4 exception).
    #
    # When every failed attempt is due only to an unsupported compiler version
    # (no successful rebuild exists, no untrusted inputs), AND a ton_verifier
    # candidate carries a fetch-time attestation that the manifest hash equals
    # the deployed code hash (hash_attested=True, code_hash==dep.hash), accept
    # that candidate as tier B third-party-verified.  Every other failure type
    # (hash mismatch, untrusted_args, build error) keeps the existing behaviour.
    if not any(a.status == "ok" for a in tried):
        for i, (c, a) in enumerate(zip(cands, tried)):
            if (
                a.status == "unsupported_toolchain"
                and c.provider == "ton_verifier"
                and not c.untrusted_inputs
                and not a.untrusted_inputs
            ):
                verifier = (c.settings or {}).get("verifier") or {}
                if verifier.get("hash_attested") is True and verifier.get("code_hash") == dep.hash:
                    compiler_info = verifier.get("compiler") or {}
                    ver = (
                        compiler_info.get("version") or "unknown"
                    ) if isinstance(compiler_info, dict) else "unknown"
                    vid = verifier.get("verifier_id") or "ton_verifier"
                    sitem = verifier.get("source_item_address") or "unknown"
                    why = (
                        f"rebuild not attempted: {c.language} {ver} not installed; "
                        f"attested by verifier_id {vid!r} via registry item {sitem!r}"
                    )
                    return Out(i, None, SOURCE_TOOLCHAIN_GAP, tried=tried,
                               dep_hash=dep.hash, why=why)

    if named is not None:
        # The requester's own source: reviewed as tier B, never A, with the deployment unmatched.
        a = tried[named]
        if cands[named].untrusted_inputs or a.untrusted_inputs:
            why = "untrusted_inputs"
        else:
            why = "rebuild_differs" if a.status == "ok" else a.status
        return Out(named, None, SOURCE_UNLINKED, tried=tried, dep_hash=dep.hash,
                   build_hash=next(iter(a.hashes.values()), None) or build_hash, why=why)
    return Out(None, None, SOURCE_NOT_OWNER_LINKED, tried=tried, dep_hash=dep.hash,
               build_hash=build_hash, why=_why(tried))


# TON reason codes -> dep.match vocabulary (contract/rubric/dep_match.yaml). Tier D reasons never
# reach the report (the job ends insufficient_source), so they have no row here.
_DEP_MATCH = {
    MATCH_REBUILD: "exact",
    SOURCE_TOOLCHAIN_GAP: "third_party_verified_only",
}


def deployment_doc(prov: dict[str, Any], candidate: dict[str, Any] | None, address: str | None) -> dict[str, Any]:
    """The `deployment.json` document the report assembly reads for a TON unit.

    `prov` is `Out.to_json()` plus the `mc_seqno` and raw `address` the pipeline adds
    (provenance.json); `candidate` is the candidates.json summary row of `prov["src"]`. The shape is
    the one the EVM supervisor writes (engine/provenance.py `resolve_provenance`: tier, dep,
    candidate, block) plus what the cover needs on a chain without EVM bytecode: `code_hash` (the
    account code cell hash this supervisor computed), `unit` ("seqno": the pin is a masterchain
    seqno, not a block) and `chain`.

    Until 2026-10-26 the TON pipeline wrote only provenance.json, and the first tier A TON job
    (Forton after PR #68) failed at render with "tier A provenance requires deployment.json data".
    The assembly also builds this document from provenance.json for jobs built before the fix.
    """
    reason = str(prov.get("reason") or "")
    dep: dict[str, Any] | None = None
    match = _DEP_MATCH.get(reason)
    if match is not None and prov.get("address"):
        dep = {
            "match": match,
            "reason": reason.lower(),
            "contract": prov.get("matched_target"),
            "comparison": {"outcome": match, "local_hash": prov.get("build_hash"),
                           "onchain_hash": prov.get("dep_hash")},
            "notes": [prov["why"]] if prov.get("why") else [],
        }
    comp = (candidate or {}).get("compiler")
    comp = comp if isinstance(comp, dict) else {}
    out_doc = {
        "tier": prov.get("tier"),
        "label_reason": None,
        "checks": list(prov.get("checks") or []),
        "dep": dep,
        "candidate": {
            "provider": candidate.get("provider"),
            "sha256": candidate.get("sha256"),
            "compiler": comp.get("version"),
            "version_pinned_by": comp.get("version_pinned_by"),
            "untrusted_inputs": bool(candidate.get("untrusted_inputs", False)),
        } if candidate else None,
        "block": prov.get("mc_seqno"),
        "unit": "seqno",
        "chain": "ton",
        "address": address or prov.get("address"),
        "code_hash": prov.get("dep_hash") or prov.get("build_hash"),
    }
    libs = [r for r in (prov.get("library_refs") or []) if isinstance(r, dict) and r.get("hash")]
    if libs:
        out_doc["library_refs"] = [{"hash": str(r["hash"])[:64], "status": r.get("status"),
                                    "verified_source": r.get("verified_source")} for r in libs[:8]]
    if reason == SOURCE_UNLINKED and prov.get("address"):
        # the report method row says why the deployment could not be matched (assemble.py)
        out_doc["unlinked_reason"] = unlinked_reason(prov.get("why"))
    return out_doc


# Plain-language reason a named source could not be matched to the deployment (review_status
# build.deployment label and the report method row): `why` of SOURCE_UNLINKED.
UNLINKED_REASON = {
    "rebuild_differs": "the rebuilt code differs from the deployed code",
    "untrusted_inputs": "the repository build inputs cannot be trusted for a rebuild",
    "compile_error": "the source did not compile",
    "unsupported_toolchain": "the compiler version is not installed",
    "uninit": "the address holds no deployed code",
    "frozen": "the account at the address is frozen",
    "nonexist": "the address holds no deployed code",
    "library_not_found": "the deployed library code could not be read",
    "code_not_hashable": "the deployed code could not be hashed",
}


def unlinked_reason(why: str | None) -> str:
    return UNLINKED_REASON.get(str(why or ""), "the deployed code could not be compared with the source")


def _why(tried: list[Attempt]) -> str:
    if any(a.status == "ok" and not a.untrusted_inputs for a in tried):
        return "rebuild_differs"
    if any(a.untrusted_inputs for a in tried):
        return "untrusted_inputs"
    return tried[0].status if tried else "no_attempt"
