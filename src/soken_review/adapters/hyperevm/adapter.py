"""HyperEVM chain adapter (plan-v4 05 sections 2, 10, 12.1).

Subclasses the EVM build and analyze steps; adds HL-* Slither plugin detectors
and a HyperEVM-specific rule_map extension.  Does not fork any EVM code (RULES.md).

Chain facts (05 section 1):
  F13: Cancun without blobs; RPC rpc.hyperliquid.xyz/evm; dual-block architecture.
  F14: Read precompiles 0x800-0x813 return HyperCore state; invalid input burns all gas.
  F15: CoreWriter 0x3333...3333 sendRawAction; actions delayed a few seconds.
  F16: Precompiles 0x800 to 0x813 (HLConstants.sol, MIT).
  F17: Token system addresses 0x20+zeros+index; HYPE 0x2222...2222; non-round amounts burned.
  F18: CLZ inactive on HyperEVM (measured via eth_call state-override 2026-10-07).
  F33: HyperCore finalizer slot keccak256("HyperCore deployer").
  F42: Hyperliquid spotMeta API: evmExtraWeiDecimals per token.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, ClassVar

from soken_review.adapters.base import BuildResult, Candidate, Lead
from soken_review.adapters.evm.analyze import (
    _build_static_map,
    _extract_settings,
    _materialize_sources,
    _run_aderyn,
    _solc_path,
    compiler_bug_report,
)
from soken_review.adapters.evm.build import build

logger = logging.getLogger(__name__)

_HERE = Path(__file__).parent
_RULE_MAP_EVM = Path(__file__).parents[1] / "evm" / "data" / "rule_map.json"
_RULE_MAP_HL = _HERE / "data" / "rule_map_hl.json"

# Upstream snapshot freshness guard (05 section 11): if stale, HL-* rules are disabled.
_UPSTREAM_DIR = _HERE / "data" / "upstream"
_MAX_STALE_DAYS = 14

# HyperEVM precompile/system addresses for chain_extras enrichment.
COREWRITER_ADDR = "0x3333333333333333333333333333333333333333"
HYPE_ADDR = "0x2222222222222222222222222222222222222222"
WHYPE_ADDR = "0x5555555555555555555555555555555555555555"
CORE_USER_EXISTS_PRECOMPILE = "0x0000000000000000000000000000000000000810"
CORE_TOKEN_INFO_PRECOMPILE = "0x000000000000000000000000000000000000080c"

# HyperEVM analyze image (extends evm-analyze with HL plugins; 05 section 8.2).
_HL_IMAGE_NAME = "hyperevm-analyze"


def _load_merged_rule_map() -> dict[str, Any]:
    """Load EVM rule_map and extend with HL-* entries (05 section 8.3).

    Reference data the adapter cannot run without: a missing or broken file raises, it never
    degrades to an empty map (leads would lose their categories silently).
    """
    with _RULE_MAP_EVM.open() as fh:
        base: dict[str, Any] = json.load(fh)
    with _RULE_MAP_HL.open() as fh:
        hl: dict[str, Any] = json.load(fh)
    base.setdefault("slither", {}).update(hl.get("slither", {}))
    return base


def _upstream_is_fresh(name: str) -> bool:
    """Return True if the upstream snapshot file is within the 14-day freshness window (05 section 11)."""
    import datetime
    snap = _UPSTREAM_DIR / f"{name}.json"
    if not snap.exists():
        return False
    try:
        data = json.loads(snap.read_text())
        fetched_at = data.get("fetched_at", "")
        if not fetched_at or fetched_at == "UNVERIFIED":
            return False  # no date recorded — treat as stale in production
        dt = datetime.date.fromisoformat(fetched_at)
        age = (datetime.datetime.now(tz=datetime.UTC).date() - dt).days
        return age <= _MAX_STALE_DAYS
    except (ValueError, KeyError):
        return False


def _plugins_available() -> bool:
    """Return True if slither_plugins can be imported (plugin installed in the environment)."""
    try:
        import slither_plugins  # noqa: F401
        return True
    except ImportError:
        return False


class HyperEvmAdapter:
    """HyperEVM chain adapter (chain 999, plan-v4 05 section 2).

    Reuses EVM build and analyze unchanged; extends analyze with HL-* detectors
    loaded from the slither_plugins entry point (F38).

    chain facts applied:
      - inactive_opcodes: ["CLZ"] (F18 measured 2026-10-07)
      - Cancun without blobs (F13)
      - CoreWriter, precompiles, system tokens documented in rules/*.yaml
    """

    family = "hyperevm"
    chains: ClassVar[set[str]] = {"hyperevm"}

    def __init__(self) -> None:
        self._rule_map = _load_merged_rule_map()

    # ------------------------------------------------------------------
    # Adapter Protocol implementation
    # ------------------------------------------------------------------

    def fetch_source(self, job: Any, cs: Any) -> list:
        """Delegate to the EVM fetch step (same Sourcify/IPFS/user order, 05 4.2)."""
        # Thin pass-through; the orchestrator (09) calls this directly.
        # HyperEVM fetch is identical to EVM except chain_id=999 (F9 confirms Sourcify supports 999).
        raise NotImplementedError("fetch_source is called by the orchestrator via the EVM pipeline")

    def build(self, c: Candidate) -> BuildResult:
        """Delegate to the EVM build step unchanged (plan 05 sections 6, 7)."""
        return build(c)

    def analyze(self, r: BuildResult) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
        """Run EVM analyzers plus HL-* Slither plugin detectors (05 8.1, 8.2, 10).

        Returns (leads, static_map, read_plan).
        """
        if r.status != "ok" or not r.work_dir:
            return [], {"status": "not_run", "reason": "build_failed"}, {}

        work_dir = Path(r.work_dir)
        from soken_review.adapters.evm.analyze import prepare_analyze_dir, write_records

        out_dir = prepare_analyze_dir(work_dir)  # fresh; no link a container left is followed

        proj_dir = out_dir / "proj"
        settings = _extract_settings(work_dir)
        if not _materialize_sources(work_dir, proj_dir):
            return [], {"status": "not_run", "reason": "project_materialization_failed"}, {}

        solc_bin = _solc_path(r)
        if solc_bin is None:
            return [], {"status": "not_run", "reason": "compiler_binary_missing"}, {}

        all_raw: list[dict] = []
        entry = (r.candidate.entry_contract or "").rpartition(":")[0] or None

        # Standard Slither pass (EVM, with HL plugins registered if installed).
        slither_raw = self._run_slither_with_plugins(proj_dir, out_dir, solc_bin, settings, entry)
        if slither_raw is None:
            from soken_review.sandbox.profile import locked_image
            hl_img = locked_image(_HL_IMAGE_NAME)
            reason = (
                "sandbox_unavailable"
                if hl_img is None and os.environ.get("SOKEN_ANALYZE_DIRECT", "0") != "1"
                else "analyzer_failed"
            )
            return [], {"status": "not_run", "reason": reason}, {}
        all_raw.extend(slither_raw)

        aderyn_raw = _run_aderyn(proj_dir, out_dir)
        if aderyn_raw is not None:
            all_raw.extend(aderyn_raw)

        # Compiler advisories (05 6.2): same solc releases as EVM
        bug_report = compiler_bug_report(r)
        all_raw.extend(bug_report.raw_leads)

        # Apply merged (EVM + HL) rule_map for category resolution.
        leads = _build_leads_with_map(all_raw, self._rule_map)
        static_map = _build_static_map(out_dir, aderyn_available=aderyn_raw is not None)
        static_map["compiler_advisories"] = {
            "status": bug_report.status,
            "reason": bug_report.reason,
            "version": bug_report.version,
            "rows": bug_report.advisories,
        }
        read_plan: dict[str, Any] = {
            "entries": self._precompile_read_plan_entries(),
            "version": "1",
        }

        write_records(work_dir, leads, static_map, read_plan)  # host-only dir (09 3.5)

        return leads, static_map, read_plan

    def map(self, r: BuildResult, s: dict[str, Any], cs: Any) -> tuple[dict[str, Any], Any]:
        """Build map.v1 with chain_extras.hyperevm fields (05 12.1)."""
        chain_extras: dict[str, Any] = {
            "hyperevm": {
                "corewriter_calls": _count_corewriter_calls(s),
                "precompile_reads": _count_precompile_reads(s),
                "system_transfers": _count_system_transfers(s),
                "token_linked": "unknown",  # resolved in chain_state 1 via 0x80c
            }
        }
        map_v1 = {
            "chain": "hyperevm",
            "chain_id": 999,
            "chain_extras": chain_extras,
            "static_map_summary": s.get("contracts", []),
        }
        return map_v1, None

    def checklists(self, language: str) -> list[str]:
        """Return HyperEVM checklist section ids from contract/rubric/checklists/evm.yaml (05 14)."""
        return [
            "evm.hyperevm.corewriter",
            "evm.hyperevm.precompile",
            "evm.hyperevm.bridge_decimals",
            "evm.hyperevm.linking",
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_slither_with_plugins(
        self,
        proj_dir: Path,
        out_dir: Path,
        solc_path: str,
        settings: dict,
        entry_file: str | None,
    ) -> list[dict] | None:
        """Run Slither with HL plugin detectors registered (05 8.2, F38).

        Delegates to the EVM _run_slither; the HL plugins are auto-loaded by Slither
        from the `slither_analyzer.plugin` entry point when the slither_plugins package
        is installed in the analyze image (see docker/hyperevm-analyze/Dockerfile).
        """
        from soken_review.adapters.evm.analyze import _run_slither
        from soken_review.sandbox.profile import locked_image

        # HL detectors exist only in the hyperevm-analyze image (05 8.2): never fall back to the
        # plain EVM image, which would report a run without HL detectors as complete.
        hl_img = locked_image(_HL_IMAGE_NAME)
        if hl_img is None and os.environ.get("SOKEN_ANALYZE_DIRECT") != "1":
            return None  # analyze() reports not_run (sandbox_unavailable)
        return _run_slither(proj_dir, out_dir, solc_path, settings, entry_file, image=hl_img)

    def _precompile_read_plan_entries(self) -> list[dict]:
        """Emit a read_plan entry for coreTokenInfo (0x80c) to resolve token_linked (05 12.2)."""
        return [
            {
                "kind": "precompile_read",
                "address": CORE_TOKEN_INFO_PRECOMPILE,
                "purpose": "resolve token_linked (chain_extras.hyperevm.token_linked)",
                "chain": "hyperevm",
            }
        ]


# ------------------------------------------------------------------
# Lead-building with merged rule_map (extends EVM _build_leads)
# ------------------------------------------------------------------

def _build_leads_with_map(raw_items: list[dict], rule_map: dict[str, Any]) -> list[Lead]:
    """Like evm analyze._build_leads but uses the supplied merged rule_map (HL-* aware)."""
    import jsonschema

    from soken_review.adapters.evm.analyze import (
        _LEAD_SCHEMA,
        _SEVERITY_MAP,
        _merge_overlapping,
    )

    def _cat(tool_name: str, rule_id: str) -> str:
        base_tool = tool_name.split("@")[0]
        return rule_map.get(base_tool, {}).get(rule_id, "evm.other")

    def _sev(tool_name: str, raw: str) -> str:
        base_tool = tool_name.split("@")[0]
        tool_map = _SEVERITY_MAP.get("analyzers", {}).get(base_tool, {})
        return tool_map.get(raw) or _SEVERITY_MAP.get("default", "High")

    groups: dict[tuple[str, str], list[dict]] = {}
    for item in raw_items:
        cat = item.get("category") or _cat(item["tool"], item["rule_id"])
        groups.setdefault((cat, item["file"]), []).append(item)

    leads: list[Lead] = []
    sev_rank = {"High": 4, "Medium": 3, "Low": 2, "Info": 1}
    lead_idx = 1

    for (cat, file_path), items in groups.items():
        for group_items in _merge_overlapping(items):
            best_sev = "Info"
            tools_seen: list[str] = []
            rule_ids: list[str] = []
            for item in group_items:
                norm = _sev(item["tool"], item["severity_raw"])
                if sev_rank.get(norm, 0) > sev_rank.get(best_sev, 0):
                    best_sev = norm
                if item["tool"] not in tools_seen:
                    tools_seen.append(item["tool"])
                if item["rule_id"] not in rule_ids:
                    rule_ids.append(item["rule_id"])

            lead: Lead = {
                "id": f"LEAD-{lead_idx:04d}",
                "rule_id": rule_ids[0] if rule_ids else "unknown",
                "tools": tools_seen,
                "category": cat,
                "analyzer_severity_raw": group_items[0]["severity_raw"],
                "severity_norm": best_sev,
                "file": file_path,
                "start": min(i["start"] for i in group_items),
                "end": max(i["end"] for i in group_items),
                "state": "open",
            }
            try:
                jsonschema.validate(lead, _LEAD_SCHEMA)
                leads.append(lead)
                lead_idx += 1
            except jsonschema.ValidationError:
                pass

    return leads


# ------------------------------------------------------------------
# chain_extras helpers (minimal static pass)
# ------------------------------------------------------------------

def _count_corewriter_calls(static_map: dict[str, Any]) -> int:
    """Count functions that reference the CoreWriter address in the static map."""
    count = 0
    for contract_entry in static_map.get("contracts", []):
        for fname in contract_entry.get("functions", []):
            if "sendRawAction" in fname or "corewriter" in fname.lower():
                count += 1
    return count


def _count_precompile_reads(static_map: dict[str, Any]) -> int:
    """Count functions that call any 0x800-series precompile (rough heuristic)."""
    count = 0
    for contract_entry in static_map.get("contracts", []):
        for fname in contract_entry.get("functions", []):
            if "precompile" in fname.lower() or "oracle" in fname.lower():
                count += 1
    return count


def _count_system_transfers(static_map: dict[str, Any]) -> int:
    """Count functions that interact with system token addresses."""
    count = 0
    for contract_entry in static_map.get("contracts", []):
        for fname in contract_entry.get("functions", []):
            if "hype" in fname.lower() or "bridge" in fname.lower():
                count += 1
    return count
