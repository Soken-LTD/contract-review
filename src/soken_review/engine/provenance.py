"""Provenance decision: `dep.match` (05 13.3) and the code tier (04 section 3, E1).

The supervisor is the only caller. It feeds the 13.1 comparison it computed itself from the
build artifacts and the pinned on-chain runtime; nothing a build container writes is read as a
verdict (05 3.1). Tier A comes only from a masked rebuild match (`exact` or `metadata_only`) of a
candidate without untrusted build inputs.

Vocabulary: `contract/rubric/dep_match.yaml` (the only one); a value outside it fails with
E_TIER_UNKNOWN (04 section 3, V0).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, Literal

import yaml

from ..adapters.base import Artifact, BuildResult, Candidate
from ..adapters.evm.build import auxdata_x3
from ..adapters.evm.compare import Comparison, compare_runtime
from ..errors import ReviewError

RUBRIC_DIR = Path(__file__).resolve().parents[3] / "contract" / "rubric"

Tier = Literal["A", "B", "C", "D"]
_TIER_ORDER = "ABCD"

# 05 13.3: these builds have no recorded settings; a differing result is never `mismatch`.
_NO_RECORDED_SETTINGS = {"pragma", "pragma_guess", "cbor"}

# Build failure details (adapters/evm/build.py, tron/build.py, compiler caches) -> 13.3 reasons.
_BUILD_REASON_MAP = {
    "compiler_version_unknown": "settings_unknown",
    "compiler_binary_missing": "compiler_binary_missing",
    "tron_compiler_unmapped": "tron_compiler_unmapped",
    "tron_compiler_ambiguous": "tron_compiler_ambiguous",
}


@cache
def dep_match_vocabulary() -> tuple[frozenset[str], frozenset[str]]:
    """(dep.match values, not_checkable EVM reasons) from dep_match.yaml."""
    data = yaml.safe_load((RUBRIC_DIR / "dep_match.yaml").read_text())
    reasons = frozenset(data["not_checkable"]["evm_reasons"])
    return frozenset(data), reasons


@dataclass
class DepResult:
    match: str
    reason: str | None = None
    contract: str | None = None                 # "path:Name" of the compared artifact
    comparison: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"match": self.match, "reason": self.reason, "contract": self.contract,
                "comparison": self.comparison, "notes": self.notes}


def evm_dep_match(
    *,
    family: str,
    candidate: Candidate,
    build_status: str,
    build_reason: str | None,
    comparison: Comparison | None,
    contract: str | None = None,
    uv5_05_passed: bool = False,
) -> DepResult:
    """05 13.3 applied to one 13.1 result for an EVM-family unit (evm, hyperevm, tron)."""
    if build_status != "ok":
        reason = _BUILD_REASON_MAP.get(build_reason or "", "build_failed")
        return _checked(DepResult("not_checkable", reason, contract))
    if comparison is None:
        return _checked(DepResult("not_checkable", "build_failed", contract, notes=["no runtime artifact to compare"]))

    cmp = comparison.as_dict()
    if comparison.outcome in ("exact", "metadata_only"):
        return _checked(DepResult(comparison.outcome, None, contract, cmp))
    if comparison.outcome == "invalid_refs":
        return _checked(DepResult("not_checkable", "build_failed", contract, cmp, [comparison.detail or ""]))

    # differs
    pinned_by = candidate.compiler.version_pinned_by if candidate.compiler else None
    if pinned_by is None or pinned_by in _NO_RECORDED_SETTINGS:
        return _checked(DepResult("not_checkable", "settings_unknown", contract, cmp))
    if candidate.language != "solidity" or comparison.auxdata_source in ("trailer", "x2_partial", "unknown"):
        # Vyper rules (X4) are not implemented; without X2 ranges child CBOR may be unmasked.
        return _checked(DepResult("not_checkable", "auxdata_rule_missing", contract, cmp))
    if family == "tron" and not uv5_05_passed:
        return _checked(DepResult("not_checkable", "tron_compiler_unmapped", contract, cmp,
                                  ["UV5-05 not passed: a TRON difference is not a mismatch"]))
    return _checked(DepResult("mismatch", None, contract, cmp))


def _checked(dep: DepResult) -> DepResult:
    values, reasons = dep_match_vocabulary()
    if dep.match not in values:
        raise ReviewError("E_TIER_UNKNOWN", incident=f"dep.match={dep.match!r}")
    if dep.match == "not_checkable" and dep.reason not in reasons:
        raise ReviewError("E_TIER_UNKNOWN", incident=f"not_checkable reason {dep.reason!r}")
    return dep


def code_tier(src_present: bool, address: str | None, match: str | None) -> Tier:
    """04 section 3 `code_tier`, verbatim."""
    if not src_present:
        return "D"
    if address is None:
        return "B"
    if match in ("exact", "metadata_only"):
        return "A"
    if match in ("third_party_verified_only", "not_checkable"):
        return "B"
    if match == "mismatch":
        return "C"
    raise ReviewError("E_TIER_UNKNOWN", incident=f"dep.match={match!r}")


def worst(*tiers: Tier) -> Tier:
    return max(tiers, key=_TIER_ORDER.index)


def unit_tier(
    impl: Tier,
    proxy: dict[str, Any] | None = None,
) -> tuple[Tier, str | None]:
    """04 section 3 `unit_tier`. proxy: None, or {runtime_matches_standard_proxy, tier}."""
    if proxy is None:
        return impl, None
    if proxy.get("runtime_matches_standard_proxy"):
        p: Tier = "A"
    elif proxy.get("tier") is not None:
        p = proxy["tier"]
    else:
        return worst(impl, "B"), "proxy_unmatched"
    return worst(impl, p), None


def resolve_provenance(
    *,
    candidate: Candidate | None,
    address: str | None,
    dep: DepResult | None,
    proxy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The supervisor's provenance decision for one unit: dep.match, tier, label reason.

    Trust flags apply here, at the decision point: a candidate with untrusted build inputs
    (06 3.3.4) never reaches tier A, whatever the comparison says.
    """
    if dep is not None and candidate is not None and candidate.untrusted_inputs \
            and dep.match in ("exact", "metadata_only"):
        dep = DepResult("not_checkable", "untrusted_build_inputs", dep.contract, dep.comparison,
                        dep.notes + [f"rebuild matched ({dep.match}) but build inputs are untrusted"])
    match = dep.match if dep is not None else None
    impl = code_tier(candidate is not None, address, match)
    tier, label_reason = unit_tier(impl, proxy)
    # 13.4 checks[]: linked libraries are code outside the reviewed source; masking their
    # addresses is only a match of the caller. Until each library is compared as its own unit,
    # a unit with linked libraries is not tier A.
    libraries = ((dep.comparison or {}).get("linked_libraries") or {}) if dep is not None else {}
    checks = [{"check": "libraries", "result": "unverified", "library": lib, "address": addr}
              for lib, addr in sorted(libraries.items())]
    # Libraries the candidate linked at compile time (`settings.libraries`; the build strips
    # them so they appear as link references, but the recorded entries are listed either way).
    checks += [{"check": "libraries", "result": "unverified", "library": lib, "address": addr,
                "source": "settings.libraries"} for lib, addr in _settings_libraries(candidate)]
    if checks and tier == "A":
        tier, label_reason = "B", "libraries_unverified"
    return {
        "tier": tier,
        "label_reason": label_reason,
        "checks": checks,
        "dep": dep.as_dict() if dep is not None else None,
        "candidate": {
            "provider": candidate.provider,
            "sha256": candidate.sha256,
            "compiler": candidate.compiler.version if candidate.compiler else None,
            "version_pinned_by": candidate.compiler.version_pinned_by if candidate.compiler else None,
            "untrusted_inputs": candidate.untrusted_inputs,
        } if candidate is not None else None,
    }


def evm_deployment_check(
    *,
    family: str,
    build: BuildResult,
    onchain_runtime: str | None,
    address: str | None = None,
    uv5_05_passed: bool = False,
) -> DepResult:
    """05 13.1 for one EVM-family unit: pick the reviewed artifact, compare, apply 13.3.

    The artifact is the candidate's `entry_contract`; when the candidate names none (TronScan
    records without a file path), the first artifact whose masked runtime equals the chain wins,
    and the result names it.
    """
    cand = build.candidate
    if build.status != "ok":
        return evm_dep_match(family=family, candidate=cand, build_status=build.status,
                             build_reason=build.reason, comparison=None)
    onchain = (onchain_runtime or "").removeprefix("0x")
    if not onchain:
        return _checked(DepResult("not_checkable", "state_changed_during_read",
                                  notes=["no on-chain runtime at the pinned block"]))
    no_aux = auxdata_x3(cand.compiler.version if cand.compiler else "", cand.std_json_input, cand.settings)

    def run(art: Artifact) -> Comparison:
        return compare_runtime(art.runtime, onchain, immutable_refs=art.immutable_refs,
                               link_refs=art.link_refs, x2_ranges=build.auxdata_ranges.get(art.contract),
                               no_auxdata=no_aux, self_address=address)

    arts = [a for a in build.artifacts if a.runtime]
    named = [a for a in arts if cand.entry_contract and _same_contract(a.contract, cand.entry_contract)]
    if named:
        art = named[0]
        return evm_dep_match(family=family, candidate=cand, build_status="ok", build_reason=None,
                             comparison=run(art), contract=art.contract, uv5_05_passed=uv5_05_passed)
    if cand.entry_contract:
        # The named unit is not in the build: another contract that happens to match is not it.
        return _checked(DepResult("not_checkable", "build_failed",
                                  notes=[f"entry contract {cand.entry_contract} has no runtime in the build"]))
    best: tuple[Artifact, Comparison] | None = None
    for art in arts:
        cmp = run(art)
        better = best is None or (cmp.outcome == "exact" and best[1].outcome != "exact")
        if cmp.outcome in ("exact", "metadata_only") and better:
            best = (art, cmp)
    if best is not None:
        dep = evm_dep_match(family=family, candidate=cand, build_status="ok", build_reason=None,
                            comparison=best[1], contract=best[0].contract)
        dep.notes.append("candidate names no entry contract; artifact chosen by masked runtime")
        return dep
    # No artifact matches and none is named: the reviewed contract is unknown, so no mismatch.
    return _checked(DepResult("not_checkable", "settings_unknown",
                              notes=[f"no entry contract named; {len(arts)} artifacts, none matches"]))


def _same_contract(artifact: str, entry: str) -> bool:
    """`path:Name` equality; an entry without a path matches by name."""
    return artifact == entry or (":" not in entry and artifact.rsplit(":", 1)[-1] == entry)


def _settings_libraries(candidate: Candidate | None) -> list[tuple[str, str]]:
    """("file:Lib", address) for every `settings.libraries` entry of the candidate."""
    if candidate is None:
        return []
    settings = (candidate.std_json_input or {}).get("settings") or candidate.settings or {}
    out: list[tuple[str, str]] = []
    for file, libs in (settings.get("libraries") or {}).items():
        for lib, addr in (libs or {}).items() if isinstance(libs, dict) else []:
            out.append((f"{file}:{lib}", str(addr)))
    return sorted(out)
