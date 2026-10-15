"""StarknetAdapter: ChainAdapter for Starknet Sierra classes (plan-v4 07 sections 8 to 12).

Steps (09 3.1): chain_state (pinned RPC read of the class) -> fetch (repo at commit, sandboxed git)
-> build (scarb fetch with egress, then offline `scarb build`; supervisor hashes artifacts and
decides dep.match) -> analyze (scarb lint in the sandbox + soken-cairo-rules over pinned source and
facts decoded from the hashed program) -> map (chain_extras, nr_* predicates).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from soken_review.adapters.base import BuildResult, Candidate, ChainState, Lead, SourceBundle, Target

_CHECKLIST = Path(__file__).resolve().parents[4] / "contract" / "rubric" / "checklists" / "cairo.yaml"


class StarknetAdapter:
    family: str = "starknet"
    chains: set[str] = frozenset({"starknet"})  # type: ignore[assignment]

    def fetch_source(self, job: Any, cs: ChainState) -> list[SourceBundle]:
        """Repo at a full commit only (07 8.1 step 4); job is the jobs row (source_args used)."""
        import tempfile

        from soken_review.adapters.starknet.fetch import clone_repo, make_candidate

        args = (job.get("source_args") if isinstance(job, dict) else getattr(job, "source_args", None)) or {}
        repo_url, commit = args.get("repo_url"), args.get("commit")
        if not repo_url or not commit:
            return []
        work = Path(tempfile.mkdtemp(dir=Path(__file__).resolve().parents[4] / ".sbx"))
        files = clone_repo(repo_url, commit, work)
        if not files:
            return []
        cairo = cs.get("cairo_version").value if cs.get("cairo_version") else None
        cand = make_candidate(files, provider="repo", repo_url=repo_url, commit=commit,
                              subdir=args.get("subdir"), cairo_version=cairo)
        addr = cs.get("address").value if cs.get("address") else None
        target = Target(address=addr, display_address=addr, repo_url=repo_url, commit=commit, files=list(files))
        return [SourceBundle(target=target, candidates=[cand])]

    def build(self, c: Candidate, work_dir: Path | None = None) -> BuildResult:
        import tempfile

        from soken_review.adapters.starknet.build import build

        wd = work_dir or Path(tempfile.mkdtemp(dir=Path(__file__).resolve().parents[4] / ".sbx"))
        return build(c, wd, c.compiler.version if c.compiler else None)

    def analyze(self, r: BuildResult, facts: Any = None) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
        from soken_review.adapters.starknet.analyze import analyze

        return analyze(r, facts, r.candidate.compiler.version if r.candidate.compiler else None)

    def map(self, r: BuildResult, s: dict[str, Any], cs: ChainState, facts: Any = None,
            provenance: dict[str, Any] | None = None) -> tuple[dict[str, Any], Any]:
        from soken_review.adapters.starknet.map import chain_extras

        plain = {k: (v.value if hasattr(v, "value") else v) for k, v in (cs or {}).items()}
        extras = chain_extras(plain, facts, s, provenance)
        row = {
            "contract": (provenance or {}).get("artifact"),
            "onchain_class_hash": plain.get("class_hash"),
            "rebuilt_class_hash": (provenance or {}).get("rebuilt_class_hash"),
            "result": (provenance or {}).get("match"),
        }
        return extras, [row]

    def checklists(self, language: str = "cairo") -> list[str]:
        data = yaml.safe_load(_CHECKLIST.read_text()) or {}
        ids = [i["id"] for i in data.get("generic_items") or []]
        for cat in (data.get("categories") or {}).values():
            ids += [i["id"] for i in cat.get("items") or []]
        return ids


__all__ = ["StarknetAdapter"]
