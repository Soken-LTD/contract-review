"""Starknet dep.match and code tier (07 8.2, 9.1; 04 section 3 code_tier). Supervisor only.

The inputs are values the supervisor computed itself: the on-chain class (pinned RPC read) and,
per artifact, the class hash and selector sets computed in Python from artifact bytes read with
lstat checks. Nothing a build container wrote about hashes or matches is read.

dep.match (rubric/dep_match.yaml starknet rows):
  exact          an artifact's class hash equals the deployed class hash (trusted inputs only)
  mismatch       no artifact has the deployed entry point selector set
  not_checkable  build_failed | toolchain_unavailable | deps_unreachable | build_settings_unknown (equal selectors,
                 other hash) | build_input_untrusted (trust scan flagged the tree)
"""

from __future__ import annotations

from typing import Any

ENTRY_TYPES = ("EXTERNAL", "L1_HANDLER", "CONSTRUCTOR")


def _sel(d: dict[str, Any]) -> dict[str, frozenset[int]]:
    return {k: frozenset(int(x, 16) if isinstance(x, str) else int(x) for x in (d.get(k) or [])) for k in ENTRY_TYPES}


def decide_dep_match(
    *,
    onchain_class_hash: str,
    onchain_selectors: dict[str, list[str]],
    artifacts: list[dict[str, Any]],
    build_status: str,
    build_reason: str | None,
    untrusted_inputs: bool,
) -> dict[str, Any]:
    """Return {"match", "reason", "artifact", "rebuilt_class_hash"} for the deployed unit.

    `artifacts`: [{"contract", "class_hash", "selectors": {type: [hex]}}] from the supervisor.
    """
    out: dict[str, Any] = {"match": "not_checkable", "reason": None, "artifact": None, "rebuilt_class_hash": None}
    if build_status != "ok":
        passthrough = {"toolchain_unavailable", "deps_unreachable"}
        out["reason"] = build_reason if build_reason in passthrough else "build_failed"
        return out
    target = int(onchain_class_hash, 16)
    want = _sel(onchain_selectors)
    same_iface = [a for a in artifacts if _sel(a.get("selectors") or {}) == want]
    equal = [a for a in same_iface if int(a["class_hash"], 16) == target]
    if untrusted_inputs:
        # Trust flag reaches the decision: a matching hash from untrusted build inputs proves nothing.
        out["reason"] = "build_input_untrusted"
        if equal:
            out["artifact"], out["rebuilt_class_hash"] = equal[0]["contract"], equal[0]["class_hash"]
        return out
    if equal:
        out.update(match="exact", artifact=equal[0]["contract"], rebuilt_class_hash=equal[0]["class_hash"])
        return out
    if same_iface:
        out.update(reason="build_settings_unknown", artifact=same_iface[0]["contract"],
                   rebuilt_class_hash=same_iface[0]["class_hash"])
        return out
    out.update(match="mismatch")
    return out


def code_tier(has_source: bool, has_deployment: bool, dep_match: str | None) -> str:
    """04 section 3 code_tier for one unit."""
    if not has_source:
        return "D"
    if not has_deployment:
        return "B"
    if dep_match == "exact":
        return "A"
    if dep_match == "not_checkable":
        return "B"
    if dep_match == "mismatch":
        return "C"
    raise ValueError(f"E_TIER_UNKNOWN: dep.match {dep_match!r}")
