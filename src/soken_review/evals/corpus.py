"""`soken-eval corpus check` (10 section 2.1 and 2.4): one case.yaml, list of problems.

Licence rules (`benchmark_use: false`, `own_audit` without consent) are warnings while the
product is in development;
`enforce_licences=True` turns them into errors for the release corpus.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..contract import CONTRACT_DIR, REPO_ROOT

CHAIN_FAMILY = {
    "evm": "evm", "hyperevm": "evm", "tron": "evm",
    "solana": "solana", "ton": "ton",
    "sui": "move", "aptos": "move", "starknet": "cairo",
}
SPLITS = {"dev", "gate", "neg", "canary"}
ORIGINS = {"seeded", "contest", "incident", "pattern", "own_audit", "reference"}
INPUT_MODES = {"address", "repo", "files", "upload"}
TIERS = {"A", "B", "C", "D"}
OUTCOMES = {"report", "refuse_tier_d", "refuse_source_not_found", "refuse_too_large", "refuse_unsupported"}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
MIN_MATCH = {"location_and_category", "location_only"}
J_CLASSES = {f"J{i}" for i in range(1, 6)}
CASE_ID = re.compile(r"^[a-z]+-[a-z_]+-[0-9]{4}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
EVMBENCH_TEMPO = re.compile(r"(evmbench-org/|evmbench@\S*/audits/)\d{4}-\d{2}-tempo-")
UNLICENSED = {"none", "noassertion", "unknown", ""}


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _categories() -> dict[str, dict[str, Any]]:
    data = yaml.safe_load((CONTRACT_DIR / "rubric" / "enums.yaml").read_text())
    return {row["id"]: row for row in data["categories"]}


def _providers() -> dict[str, dict[str, Any]]:
    rows = yaml.safe_load((REPO_ROOT / "compliance" / "providers.yaml").read_text())
    return {row["id"]: row for row in rows}


def check_case(path: Path, tree: Path | None = None, enforce_licences: bool = False) -> Report:
    """Check one case file. `tree` is the checked-out source, for line-range checks."""
    report = Report()
    err, warn = report.errors.append, report.warnings.append
    licence = err if enforce_licences else warn

    try:
        case = next(yaml.safe_load_all(path.read_text()))
    except (yaml.YAMLError, StopIteration) as exc:
        err(f"not YAML: {exc}")
        return report
    if not isinstance(case, dict):
        err("case is not a mapping")
        return report

    def enum(key: str, allowed: set[str], value: Any = None, nullable: bool = False) -> Any:
        value = case.get(key) if value is None else value
        if value is None and nullable:
            return None
        if value not in allowed:
            err(f"{key}: {value!r} not in {sorted(allowed)}")
        return value

    case_id = case.get("case_id", "")
    if not CASE_ID.match(str(case_id)):
        err(f"case_id {case_id!r} breaks <chain>-<origin>-<4 digits>")
    chain = enum("chain", set(CHAIN_FAMILY))
    family = CHAIN_FAMILY.get(str(chain))
    if family == "evm" and chain == "evm" and not isinstance(case.get("chain_id"), int):
        err("chain_id required for evm")
    if family != "evm" and case.get("chain_id") is not None:
        err("chain_id only for the EVM family")
    split = enum("split", SPLITS)
    origin = enum("origin", ORIGINS)
    mode = enum("input_mode", INPUT_MODES)
    enum("run_as_chain", {"hyperevm", "tron"}, nullable=True)
    enum("provenance_tier_expected", TIERS)
    outcome = enum("expected_outcome", OUTCOMES)
    enum("j_class", J_CLASSES, nullable=True)
    enum("consent", {"not_needed", "on_file"})

    source = case.get("source") or {}
    provider = _providers().get(source.get("provider"))
    if source.get("provider") not in ("repo", "upload", "files", None) and provider is None:
        err(f"source.provider {source.get('provider')!r} not in compliance/providers.yaml")
    if provider is not None and provider.get("benchmark_use") is False:
        licence(f"source.provider {provider['id']} has benchmark_use: false")
    if mode in ("repo", "upload") and not COMMIT.match(str(source.get("commit", ""))):
        err("source.commit must be a full 40-hex sha")
    if origin == "own_audit" and case.get("consent") != "on_file":
        licence("own_audit without consent: on_file")
    if origin == "seeded" and mode != "upload":
        err("seeded cases are delivered by upload (10 2.4)")
    if origin == "incident" and "DeFiHackLabs" in str(source.get("repo", "")) and source.get("subdir") is None:
        err("DeFiHackLabs: reference the upstream path, never copied exploit files")
    if EVMBENCH_TEMPO.search(f"{source.get('repo', '')} {source.get('dataset', '')}"):
        err("EVMbench Tempo tasks are not corpus cases (10 2.1)")
    if str(source.get("license") or "none").lower() in UNLICENSED:
        licence(f"source.license {source.get('license')!r}: no licence recorded for the audited code")

    categories = _categories()
    gts = case.get("ground_truth") or []
    if outcome == "report" and split != "neg" and not gts:
        err("positive case without ground_truth")
    if split == "neg" and gts:
        err("neg case carries ground_truth")
    if split == "neg" and not case.get("negatives_note"):
        warn("neg case without negatives_note (audit URL with 0 High and 0 Medium)")
    seen = set()
    for gt in gts:
        gid = gt.get("gt_id")
        if gid in seen:
            err(f"duplicate gt_id {gid}")
        seen.add(gid)
        enum("severity", SEVERITIES, gt.get("severity"))
        enum("min_match", MIN_MATCH, gt.get("min_match"))
        cat = categories.get(gt.get("category"))
        if cat is None:
            err(f"{gid}: category {gt.get('category')!r} not in rubric/enums.yaml")
        elif family and cat["family"] != family:
            err(f"{gid}: category family {cat['family']} does not match chain {chain}")
        elif cat.get("chains") and chain not in cat["chains"]:
            err(f"{gid}: category {cat['id']} not defined for {chain}")
        if not gt.get("root_cause_lines"):
            err(f"{gid}: root_cause_lines empty")
        for rng in (gt.get("root_cause_lines") or []) + (gt.get("related_lines") or []):
            _check_range(rng, tree, gid, err)
        if case.get("judged") and origin in ("contest", "own_audit") and not gt.get("source_url"):
            warn(f"{gid}: judged without source_url")

    seeded = case.get("seeded")
    if (origin == "seeded") != bool(seeded):
        err("seeded block must be present exactly for origin: seeded")
    if seeded and chain == "tron" and seeded.get("reachability") != "proven" and split == "gate":
        err("TRON seeded case with unproven reachability cannot be in gate (O10-6)")
    return report


def _check_range(rng: dict[str, Any], tree: Path | None, gid: str, err) -> None:
    start, end, name = rng.get("start"), rng.get("end"), rng.get("file")
    if not (isinstance(start, int) and isinstance(end, int) and 1 <= start <= end):
        err(f"{gid}: bad line range {rng}")
        return
    if tree is None:
        return
    from .locate import safe_read

    text = safe_read(tree, str(name))   # no symlinks, never outside the tree
    if text is None:
        err(f"{gid}: file {name} not a regular file in the source tree")
        return
    lines = text.count("\n") + 1
    if end > lines:
        err(f"{gid}: {name}:{start}-{end} past end of file ({lines} lines)")
