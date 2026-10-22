"""AptosAdapter: ChainAdapter for Aptos Move (plan v4 07 sections 2, 4, 7, 9, 10).

chain_state (supervisor) -> aptos.chain.read_chain_state; fetch -> aptos.fetch; build ->
aptos.build (sandbox, supervisor-side comparison); analyze -> move.analyze; map -> chain_extras.
Licence: Aptos CLI image is U-21.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, ClassVar

import yaml

from soken_review.adapters.base import BuildResult, Candidate, ChainState, Lead, SourceBundle, Target
from soken_review.adapters.move.units import normalize_address, unit_label

_HERE = Path(__file__).parent
_CHECKLIST = Path(__file__).resolve().parents[4] / "contract" / "rubric" / "checklists" / "move.yaml"
LINT_VERSION = "9.6.0"


class AptosAdapter:
    family: str = "move"
    chains: ClassVar[set[str]] = {"aptos"}

    def fetch_source(self, job: Any, cs: ChainState) -> list[SourceBundle]:
        """job: dict with address and chain_state_file, or repo_url/commit, or files (07 7.1)."""
        from soken_review.adapters.aptos import fetch

        j = job if isinstance(job, dict) else vars(job)
        state = cs.get("aptos").value if cs and "aptos" in cs else None
        address = normalize_address(j["address"]) if j.get("address") else None
        if j.get("repo_url"):
            cand = fetch.candidate_from_repo(j["repo_url"], j["commit"], Path(j["work_dir"]), j.get("package"),
                                             state, j.get("chain_state_file"))
        elif j.get("files"):
            cand = fetch.candidate_from_inline(j["files"])
        elif state is not None:
            cand = fetch.candidate_from_registry(state, j.get("chain_state_file"))
        else:
            cand = None
        names = [u["name"] for u in (cand.settings["units"] if cand else [])]
        target = Target(address=address, display_address=address,
                        unit_label=unit_label(names[0] if names else "package", address),
                        repo_url=j.get("repo_url"), commit=cand.settings.get("commit") if cand else None,
                        files=sorted(cand.files) if cand else [])
        return [SourceBundle(target=target, candidates=[cand] if cand else [])]

    def build(self, c: Candidate, work_dir: Path | None = None) -> BuildResult:
        from soken_review.adapters.aptos.build import build

        return build(c, work_dir)

    def analyze(self, r: BuildResult, *, step_deadline: float | None = None) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
        from soken_review.adapters.aptos.build import _argv, in_scope_for, load_chain_state
        from soken_review.adapters.move import prover as prover_mod
        from soken_review.adapters.move.analyze import analyze, printed_to_pin

        cs = load_chain_state(r.candidate)
        extras = chain_extras(r.candidate, cs)
        units = r.candidate.settings.get("units", [])
        runs = [(_argv(u["dir"], f"lint-{u['name']}", None, lint=True), printed_to_pin(r.candidate.files, ""))
                for u in units]
        # One prove entry per unit package; argv uses /work/src paths (replaced in analyze).
        prove_runs = [
            (prover_mod.prove_argv("aptos", u["dir"]), printed_to_pin(r.candidate.files, ""))
            for u in units
        ]
        return analyze(r, chain="aptos", lint_runs=runs, lint_version=LINT_VERSION,
                       prove_runs=prove_runs, prover_version=LINT_VERSION,
                       chain_extras=extras,
                       upgrade=extras.get("upgrade"), in_scope=in_scope_for(r.candidate), rules_dir=_HERE / "rules",
                       lint_map_path=_HERE / "lint_map.yaml", dep_modules=onchain_dependencies(r.candidate, cs),
                       step_deadline=step_deadline)

    def map(self, r: BuildResult, s: dict[str, Any], cs: ChainState) -> tuple[dict[str, Any], Any]:
        """map.v1 chain_extras.aptos (07 10) and deployment rows from host/provenance.json."""
        prov = _provenance(r)
        rows = []
        for name, p in (prov.get("units") or {}).items():
            for row in p.get("rows", []):
                rows.append({"package": name, **row, "dep_match": p.get("dep_match"), "reason": p.get("reason")})
        return {"aptos": s.get("chain_extras") or {}}, {"units": prov.get("units") or {}, "rows": rows}

    def checklists(self, language: str = "move_aptos") -> list[str]:
        return checklist_ids(_CHECKLIST, "aptos")


def onchain_dependencies(c: Candidate, cs: dict[str, Any] | None) -> dict[str, bytes]:
    """Dependency bytecode for the facts layer, from chain_state only (pinned ledger version):
    every module of the dependency accounts, plus the account's own modules that are not a
    rebuilt unit. Nothing from the build output."""
    if not cs:
        return {}
    unit_modules = {m for u in c.settings.get("units", []) for m in (u.get("modules") or [])}
    out: dict[str, bytes] = {}
    for acct, mods in (cs.get("dep_module_bytecode") or {}).items():
        for name, code in mods.items():
            out[f"{acct}/{name}"] = bytes.fromhex(code.removeprefix("0x"))
    for name, code in (cs.get("module_bytecode") or {}).items():
        if name not in unit_modules:
            out[f"{cs['address']}/{name}"] = bytes.fromhex(code.removeprefix("0x"))
    return out


def _provenance(r: BuildResult) -> dict[str, Any]:
    if not r.work_dir:
        return {}
    f = Path(r.work_dir) / "host" / "provenance.json"
    return json.loads(f.read_text()) if f.is_file() else {}


def chain_extras(c: Candidate, cs: dict[str, Any] | None) -> dict[str, Any]:
    """07 10 Aptos: upgrade {policy, upgrade_number, publisher_kind}, signer_capabilities[],
    object_refs[], randomness_fns[], dispatchable_hooks[] (source layer)."""
    units = c.settings.get("units") or []
    # Every package of the account at the pinned version counts, with or without source.
    policies = ([pk.get("upgrade_policy") for pk in cs["packages"]] if cs and cs.get("packages")
                else [u.get("upgrade_policy") for u in units])
    upgrade = {"policy": aggregate_policy(policies),
               "packages": {pk["name"]: pk.get("upgrade_policy") for pk in (cs or {}).get("packages", [])},
               "units": {u["name"]: {"policy": u.get("upgrade_policy"), "upgrade_number": u.get("upgrade_number")}
                         for u in units},
               "upgrade_number": max((u.get("upgrade_number") or 0 for u in units), default=None),
               "publisher_kind": (cs or {}).get("publisher_kind", "unknown")}
    signer_caps, refs, rand, hooks = [], [], [], []
    for path, text in sorted(c.files.items()):
        if not path.endswith(".move") or path.startswith("deps/"):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if "SignerCapability" in line and ":" in line and "struct" not in line:
                signer_caps.append(f"{path}:{i}")
            for kind in ("ConstructorRef", "ExtendRef", "TransferRef", "DeleteRef"):
                if re.search(rf"\b{kind}\b", line):
                    refs.append({"kind": kind, "at": f"{path}:{i}"})
            if "#[randomness" in line:
                rand.append(f"{path}:{i}")
            if "dispatchable_fungible_asset" in line or "register_dispatch_functions" in line:
                hooks.append(f"{path}:{i}")
    return {"upgrade": upgrade, "signer_capabilities": signer_caps, "object_refs": refs[:200],
            "randomness_fns": rand, "dispatchable_hooks": hooks,
            "units_without_source": c.settings.get("units_without_source", [])}


def aggregate_policy(policies: list[int | None]) -> int | None:
    """One upgrade policy for all units of the address: immutable (2) only when every unit is
    immutable; otherwise the most permissive one present; any unknown unit makes it unknown."""
    if not policies or any(p is None for p in policies):
        return None
    return 2 if all(p == 2 for p in policies) else min(p for p in policies if p is not None)


def checklist_ids(path: Path, chain: str) -> list[str]:
    """Item ids of rubric/checklists/move.yaml for one chain (item `chains` restricts)."""
    data = yaml.safe_load(path.read_text())
    ids = [i["id"] for i in data.get("generic_items", [])]
    for cat, body in (data.get("categories") or {}).items():
        for item in body.get("items", []):
            if not item.get("chains") or chain in item["chains"]:
                ids.append(f"{cat}:{item['id']}")
    return ids


__all__ = ["AptosAdapter"]
