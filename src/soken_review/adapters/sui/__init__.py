"""SuiAdapter: ChainAdapter for Sui Move (plan v4 07 sections 2, 4, 6, 9, 10).

chain_state (supervisor) -> sui.chain.read_chain_state (GraphQL, pinned checkpoint); fetch ->
sui.fetch (user repo, else MVR GitInfo; git in the sandbox); build -> sui.build (deps with egress,
build offline, supervisor-side DESIGN.md comparison); analyze -> move.analyze; map -> chain_extras.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from soken_review.adapters.aptos import checklist_ids
from soken_review.adapters.base import BuildResult, Candidate, ChainState, Lead, SourceBundle, Target
from soken_review.adapters.move.units import normalize_address, unit_label

_HERE = Path(__file__).parent
_CHECKLIST = Path(__file__).resolve().parents[4] / "contract" / "rubric" / "checklists" / "move.yaml"


class SuiAdapter:
    family: str = "move"
    chains: ClassVar[set[str]] = {"sui"}

    def fetch_source(self, job: Any, cs: ChainState) -> list[SourceBundle]:
        """job: dict with address (+ chain_state_file, work_dir), optional repo_url/commit/package_dir,
        or files (07 6.1.3). An address with no repo and no MVR GitInfo gives no candidate (tier D)."""
        from soken_review.adapters.sui import fetch

        j = job if isinstance(job, dict) else vars(job)
        state = cs.get("sui").value if cs and "sui" in cs else None
        address = normalize_address(j["address"]) if j.get("address") else None
        cand: Candidate | None = None
        mvr = None
        if j.get("repo_url"):
            cand = fetch.candidate_from_git(state, j["repo_url"], j["commit"], j.get("package_dir") or ".",
                                            Path(j["work_dir"]), "repo", j.get("chain_state_file"))
        elif j.get("files"):
            cand = fetch.candidate_from_inline(j["files"])
        elif state is not None:
            mvr = fetch.mvr_git_info(state["address"], state["version"])
            if mvr is not None:
                cand = fetch.candidate_from_git(state, mvr["repository_url"], mvr["tag"], mvr["path"],
                                                Path(j["work_dir"]), "mvr", j.get("chain_state_file"), mvr["name"])
        name = (cand.settings.get("package_name") if cand else None) or "package"
        target = Target(address=address, display_address=address, unit_label=unit_label(name, address),
                        repo_url=cand.source_url if cand else None,
                        commit=cand.settings.get("commit") if cand else None, files=sorted(cand.files) if cand else [])
        return [SourceBundle(target=target, candidates=[cand] if cand else [])]

    def build(self, c: Candidate, work_dir: Path | None = None) -> BuildResult:
        from soken_review.adapters.sui.build import build

        return build(c, work_dir)

    def analyze(self, r: BuildResult, *, step_deadline: float | None = None) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
        from soken_review.adapters.move.analyze import analyze, printed_to_pin
        from soken_review.adapters.sui.build import LINT_VERSION, in_scope_for, lint_argv, load_chain_state

        cs = load_chain_state(r.candidate)
        extras = chain_extras(cs)
        pkg_dir = r.candidate.settings.get("package_dir") or "."
        runs = [(lint_argv(pkg_dir), printed_to_pin(r.candidate.files, pkg_dir))]
        return analyze(r, chain="sui", lint_runs=runs, lint_version=LINT_VERSION, chain_extras=extras,
                       upgrade=extras.get("upgrade"), in_scope=in_scope_for(r.candidate), rules_dir=_HERE / "rules",
                       lint_map_path=_HERE / "lint_map.yaml", dep_modules=onchain_dependencies(cs),
                       step_deadline=step_deadline)

    def map(self, r: BuildResult, s: dict[str, Any], cs: ChainState) -> tuple[dict[str, Any], Any]:
        prov = {}
        if r.work_dir and (Path(r.work_dir) / "host" / "provenance.json").is_file():
            prov = json.loads((Path(r.work_dir) / "host" / "provenance.json").read_text())
        return {"sui": s.get("chain_extras") or {}}, prov

    def checklists(self, language: str = "move_sui") -> list[str]:
        return checklist_ids(_CHECKLIST, "sui")


def onchain_dependencies(cs: dict[str, Any] | None) -> dict[str, bytes]:
    """Dependency bytecode from chain_state only (linkage at the pinned checkpoint)."""
    import base64

    out: dict[str, bytes] = {}
    for storage_id, mods in ((cs or {}).get("dep_modules") or {}).items():
        for name, b64 in mods.items():
            out[f"{storage_id}/{name}"] = base64.b64decode(b64)
    return out


def chain_extras(cs: dict[str, Any] | None) -> dict[str, Any]:
    """07 10 Sui: upgrade, linkage (shared_types, capabilities, otw and randomness come from facts)."""
    if not cs:
        return {"upgrade": {"state": "unknown", "reason": "no_deployment"}, "linkage": []}
    up = cs.get("upgrade") or {}
    return {"upgrade": up, "linkage": cs.get("linkage", []), "package_version": cs.get("version"),
            "original_id": cs.get("original_id"), "checkpoint": cs.get("checkpoint")}


__all__ = ["SuiAdapter"]
