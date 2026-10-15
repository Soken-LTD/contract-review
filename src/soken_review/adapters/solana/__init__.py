"""SolanaAdapter: ChainAdapter implementation for Solana programs (plan 06).

Wires together fetch -> build -> analyze -> map steps.

Usage:
    adapter = SolanaAdapter()
    bundles = adapter.fetch_source(job, chain_state)
    for bundle in bundles:
        for candidate in bundle.candidates:
            result = adapter.build(candidate)
            leads, static_map, read_plan = adapter.analyze(result)
            chain_extras, deployment_rows = adapter.map(result, static_map, chain_state)
"""

from __future__ import annotations

from typing import Any

from soken_review.adapters.base import BuildResult, Candidate, ChainState, Lead, SourceBundle


class SolanaAdapter:
    family: str = "solana"
    chains: set[str] = frozenset({"mainnet-beta", "devnet", "testnet", "localnet"})  # type: ignore[assignment]

    # ----- fetch -----

    def fetch_source(self, job: Any, cs: ChainState) -> list[SourceBundle]:
        from soken_review.adapters.solana.fetch import fetch_source
        return fetch_source(job, cs)

    # ----- build -----

    def build(self, c: Candidate) -> BuildResult:
        from soken_review.adapters.solana.build import build
        return build(c)

    # ----- analyze -----

    def analyze(self, r: BuildResult) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
        from soken_review.adapters.solana.analyze import analyze
        return analyze(r)

    # ----- map -----

    def map(
        self,
        r: BuildResult,
        s: dict[str, Any],
        cs: ChainState,
    ) -> tuple[dict[str, Any], Any]:
        from soken_review.adapters.solana.map import map_result
        return map_result(r, s, cs)

    # ----- checklists -----

    def checklists(self, language: str = "solana") -> list[str]:
        """Return checklist item IDs for Solana from contract/rubric/checklists/solana.yaml."""
        from pathlib import Path

        import yaml

        checklist_path = Path(__file__).resolve().parents[4] / "contract" / "rubric" / "checklists" / "solana.yaml"
        if not checklist_path.exists():
            return []
        try:
            data = yaml.safe_load(checklist_path.read_text())
        except Exception:  # noqa: BLE001
            return []
        items: list[str] = []
        for category in (data or {}).values():
            if isinstance(category, list):
                for item in category:
                    if isinstance(item, dict) and "id" in item:
                        items.append(item["id"])
                    elif isinstance(item, str):
                        items.append(item)
            elif isinstance(category, dict):
                for subcategory in category.values():
                    if isinstance(subcategory, list):
                        for item in subcategory:
                            if isinstance(item, dict) and "id" in item:
                                items.append(item["id"])
        return items


__all__ = ["SolanaAdapter"]
