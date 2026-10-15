"""TonAdapter: ChainAdapter implementation for TON (plan v4 06 section 4).

Implements the ChainAdapter protocol (adapters/base.py):
  fetch_source -> SourceBundle list (chain_state 0 + fetch)
  build        -> BuildResult per Candidate
  analyze      -> (leads, static_map, read_plan)
  map          -> (map.v1, deployment_row)
  checklists   -> checklist ids for the language

Chain: TON mainnet only (SCOPE C5).
Languages: FunC, Tact, Tolk.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, ClassVar

from soken_review.adapters.base import (
    BuildResult,
    Candidate,
    ChainState,
    Lead,
    SourceBundle,
    Target,
)
from soken_review.adapters.ton.analyze import analyze as _analyze
from soken_review.adapters.ton.build import build as _build
from soken_review.adapters.ton.detect import parse_ton_address, raw_to_friendly
from soken_review.adapters.ton.fetch import fetch_ton_sources, make_user_candidate
from soken_review.adapters.ton.units import make_unit_label

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_TON_CHECKLISTS = _REPO_ROOT / "contract" / "rubric" / "checklists" / "ton.yaml"


class TonAdapter:
    """TON chain adapter (plan v4 06 section 4)."""

    family: str = "ton"
    chains: ClassVar[set[str]] = {"ton"}

    def __init__(self, api_key: str | None = None) -> None:
        """api_key: toncenter API key (optional; keyless hits 429, F34)."""
        self._api_key = api_key

    # ── fetch_source ─────────────────────────────────────────────────────

    def fetch_source(self, job: Any, cs: ChainState) -> list[SourceBundle]:
        """Fetch source for all input targets (plan 06 4.2, 4.3).

        job: a dict with keys:
          address: TON raw or user-friendly address (optional)
          repo_url: GitHub repo URL (optional)
          repo_commit: commit sha (optional)
          repo_subdir: subdirectory (optional, default "")
          user_files: {path: content} dict (optional)
          compiler_version: version hint (optional)
          language: language hint (optional)
        """
        # Normalise job to a dict
        job_dict: dict[str, Any] = job if isinstance(job, dict) else {}

        raw_address: str | None = None
        display_address: str | None = None
        addr_input = job_dict.get("address")
        if addr_input:
            raw_address, display_address = parse_ton_address(str(addr_input))
            if raw_address is None:
                logger.warning("TonAdapter: invalid TON address %r", addr_input)

        # chain_state from cs (pre-populated by supervisor) or read now
        code_hash: str | None = None
        if raw_address:
            acct_cs = cs.get(f"ton_account_{raw_address}")
            if acct_cs is not None:
                chain_data = acct_cs.value
                code_hash = _extract_code_hash(chain_data, raw_address)

        candidates = asyncio.get_event_loop().run_until_complete(
            fetch_ton_sources(
                raw_address=raw_address,
                code_hash=code_hash,
                user_files=job_dict.get("user_files"),
                repo_url=job_dict.get("repo_url"),
                repo_commit=job_dict.get("repo_commit"),
                repo_subdir=job_dict.get("repo_subdir", ""),
                api_key=self._api_key,
            )
        )

        if not candidates and (job_dict.get("user_files") or job_dict.get("repo_url")):
            # Fallback: create a user candidate from any provided inline content
            user_files = job_dict.get("user_files") or {}
            if user_files:
                candidates = [make_user_candidate(user_files,
                              compiler_version=job_dict.get("compiler_version"),
                              language=job_dict.get("language"))]

        # Determine unit label
        contract_name = _infer_name(candidates) if candidates else "unknown"
        target = Target(
            address=raw_address,
            display_address=display_address or raw_to_friendly(raw_address) if raw_address else None,
            unit_label=make_unit_label(contract_name, raw_address),
            repo_url=job_dict.get("repo_url"),
            commit=job_dict.get("repo_commit"),
        )

        return [SourceBundle(target=target, candidates=candidates)]

    # ── build ─────────────────────────────────────────────────────────────

    def build(self, c: Candidate) -> BuildResult:
        """Build (compile) one TON candidate (plan 06 4.2)."""
        return _build(c)

    # ── analyze ───────────────────────────────────────────────────────────

    def analyze(self, r: BuildResult) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
        """Run analyzers on a build result (plan 06 4.4)."""
        return _analyze(r)

    # ── map ───────────────────────────────────────────────────────────────

    def map(self, r: BuildResult, s: dict[str, Any], cs: ChainState) -> tuple[dict[str, Any], Any]:
        """Produce map.v1 and deployment row (plan 06 4.6)."""
        language = r.candidate.language.lower()

        # Extract chain extras from build metadata
        build_meta: dict[str, Any] = {}
        if r.work_dir:
            wd = Path(r.work_dir)
            meta_path = wd.parent / f"{wd.name}.host" / "build_meta.json"
            if meta_path.exists():
                try:
                    build_meta = json.loads(meta_path.read_text())
                except Exception as exc:  # noqa: BLE001
                    logger.debug("could not read build_meta.json: %s", exc)

        chain_extras: dict[str, Any] = {
            "language": language,
            "compiler": r.candidate.compiler.version if r.candidate.compiler else None,
            "status": "active",
            "code_hash": build_meta.get("code_hash"),
            "entry_points": _extract_entry_points(r.candidate.files, language),
            "ops": [],
            "getters": _extract_getters(r.candidate.files, language),
            "storage": [],
            "sends": [],
            "set_code_paths": _extract_set_code_paths(r.candidate.files, language),
            "child": None,
        }

        # Deployment row (plan 06 4.6)
        address = r.candidate.settings.get("address") if r.candidate.settings else None
        deployment_row: dict[str, Any] = {
            "status": "active",
            "code_hash": build_meta.get("code_hash"),
            "compiler_language": language,
            "compiler_version": r.candidate.compiler.version if r.candidate.compiler else None,
            "address": address,
            "setcode_reachable": bool(chain_extras["set_code_paths"]),
            "library_ref": False,
        }

        map_v1: dict[str, Any] = {
            "version": "1",
            "family": "ton",
            "chain_extras": {"ton": chain_extras},
            "deployment": deployment_row,
        }
        return map_v1, deployment_row

    # ── checklists ────────────────────────────────────────────────────────

    def checklists(self, language: str) -> list[str]:
        """Return checklist item ids for the TON language (plan 06 4.4, 5)."""
        if not _TON_CHECKLISTS.exists():
            return []
        try:
            import yaml
            with _TON_CHECKLISTS.open() as fh:
                data = yaml.safe_load(fh)
            ids: list[str] = []
            for item in data.get("generic_items", []):
                ids.append(item.get("id", ""))
            for cat_data in data.get("categories", {}).values():
                for item in cat_data.get("items", []):
                    ids.append(item.get("id", ""))
            return [i for i in ids if i]
        except Exception:  # noqa: BLE001
            return []


# ── helpers ───────────────────────────────────────────────────────────────

def _extract_code_hash(chain_data: Any, raw_address: str) -> str | None:
    """Extract code hash from chain_state account data."""
    if not isinstance(chain_data, dict):
        return None
    acct = chain_data.get("accounts", {}).get(raw_address, {})
    # dep_hash: code cell hash, or library body hash when library-coded (fetch.read_ton_chain_state)
    return acct.get("dep_hash")


def _infer_name(candidates: list[Candidate]) -> str:
    """Infer a contract name from the first candidate's files."""
    for c in candidates:
        for path in c.files:
            name = path.rsplit("/", 1)[-1]
            for ext in (".fc", ".func", ".tact", ".tolk"):
                if name.endswith(ext):
                    return name[: -len(ext)]
        if c.entry_contract:
            n = str(c.entry_contract).rsplit("/", 1)[-1].rsplit(".", 1)[0]
            if n:
                return n
    return "contract"


def _extract_entry_points(files: dict[str, str], language: str) -> list[str]:
    """Extract entry point function names from source files."""
    import re
    entries: list[str] = []
    if language == "func":
        pattern = re.compile(r"^\(\)\s+(recv_internal|recv_external)\s*\(", re.MULTILINE)
    elif language == "tact":
        pattern = re.compile(r"\breceive\s*\(|\bonInternalMessage\b|\bonExternalMessage\b|\bonBouncedMessage\b", re.IGNORECASE)
    elif language == "tolk":
        pattern = re.compile(r"\bfun\s+(onInternalMessage|onExternalMessage|onBouncedMessage)\s*\(", re.IGNORECASE)
    else:
        return entries
    for content in files.values():
        for m in pattern.finditer(content):
            entries.append(m.group(0).strip()[:60])
    return entries


def _extract_getters(files: dict[str, str], language: str) -> list[str]:
    """Extract getter function names from source files."""
    import re
    getters: list[str] = []
    if language == "func":
        pattern = re.compile(r"^(?:int|slice|cell|tuple|cont|builder)\s+([a-z_][a-zA-Z0-9_]*)\s*\(", re.MULTILINE)
        for content in files.values():
            for m in pattern.finditer(content):
                getters.append(m.group(1))
    elif language == "tact":
        pattern = re.compile(r"\bget\s+fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.IGNORECASE)
        for content in files.values():
            for m in pattern.finditer(content):
                getters.append(m.group(1))
    elif language == "tolk":
        pattern = re.compile(r"\bget\s+fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", re.IGNORECASE)
        for content in files.values():
            for m in pattern.finditer(content):
                getters.append(m.group(1))
    return getters


def _extract_set_code_paths(files: dict[str, str], language: str) -> list[str]:
    """Find lines where set_code / SETCODE is called."""
    import re
    paths: list[str] = []
    pattern = re.compile(r"\bset_code\b|\bSETCODE\b|\bsetCode\b", re.IGNORECASE)
    for file_path, content in files.items():
        for i, line in enumerate(content.splitlines(), 1):
            if pattern.search(line):
                paths.append(f"{file_path}:{i}")
    return paths
