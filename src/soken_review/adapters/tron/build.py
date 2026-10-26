"""TRON build step: tron-solc --standard-json inside the sandbox (05 sections 6.3, 7, 13.2 X5).

Reuses the EVM build pipeline (adapters/evm/build.py) but substitutes the
tron-solc binary from the TronSolcCache (6.3) instead of the standard solc.

TRON-specific rules:
  X5  Auxdata: X2 (trailing-newline recompile) with tron-solc.
  6.3 Exact tag mapping tv_<version>; never the nearest tron-solc release.
  F21 CBOR auxdata key is 'tron' (not 'ipfs'); tron-solc adds TRC-10 checks.
  When no pinned tron-solc exists for the tag (most Tronscan fields, e.g.
  "tron_0.6.2_Plato_v4.2"), the upstream solc of the same version compiles the
  source for the map and the analyzers (resolve_tron_solc); the build notes say so.

The sandbox image and limits are the same as EVM (evm-analyze).
"""

from __future__ import annotations

import logging
import os
import re as _re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.evm.build import (
    _SBX_ROOT,
    InputSanitizationError,
    _fail,
    _prepare_std_input,
    _run_build,
    sanitize_std_input,
)
from soken_review.adapters.tron.compiler import _TAG_RE, TronCompilerCacheError, get_tron_cache

# Regex to extract the leading semver from a version string after prefix stripping
_VER_RE = _re.compile(r"^([0-9]+\.[0-9]+\.[0-9]+)")
# Any x.y.z inside an explorer compiler field ("tron_0.6.2_Plato_v4.2" -> 0.6.2)
_SEMVER_RE = _re.compile(r"(?<![0-9.])([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})(?![0-9])")

logger = logging.getLogger(__name__)

# SOKEN_TRON_SOLC_DIRECT=1: dev-only bypass, never set in production or tests
_DIRECT_TRON_SOLC = os.environ.get("SOKEN_TRON_SOLC_DIRECT", "0") == "1"


@dataclass(frozen=True)
class TronSolc:
    """The compiler a TRON build runs: the exact tron-solc release, or an upstream solc substitute.

    kind `tron_solc`: the pinned tron-solc tag the explorer names (6.3), cache root <cache>/tron.
    kind `upstream_solc`: no pinned tron-solc for that tag; the upstream solc release of the same
    version (or the newest one every pragma allows) from binaries.soliditylang.org, sha256-checked
    against list.json. tron-solc is a fork of upstream solc that adds TRC-10/TRC-7 builtins, so a
    verified source without them compiles the same AST; the bytecode is never compared with the
    chain (tier stays B), the build only feeds the map and the analyzers.
    """

    path: Path
    version: str          # tron tag (tv_0.8.18) or upstream long version (0.6.2+commit.bacdbe57)
    kind: str             # tron_solc | upstream_solc
    cache: Any            # SolcCache-compatible: `_root` is the sandbox /cache mount


def resolve_tron_solc(version: str | None, sources: dict[str, str],
                      cache_dir: Path | None = None) -> tuple[TronSolc | None, str]:
    """Pick the compiler for a TRON source: exact tron-solc first, else upstream solc.

    Returns (solc, "") or (None, reason). The upstream version is the semver in the explorer
    compiler field when that release exists and satisfies every pragma, else the newest release
    every `pragma solidity` allows; never a version a pragma rejects.
    """
    reason = "compiler_version_unknown"
    tag = _resolve_tag(version) if version else None
    if version and tag is None:
        reason = "tron_compiler_unmapped"
    if tag is not None:
        try:
            binary = get_tron_cache(cache_dir).binary(tag)
            return TronSolc(binary, tag, "tron_solc", _TronBinaryAdapter(binary)), ""
        except TronCompilerCacheError as exc:
            reason = exc.reason_detail

    from soken_review.adapters.evm.compiler import CompilerCacheError, get_cache
    from soken_review.adapters.evm.files import PRAGMA, pick_solc, satisfies

    sol_sources = {p: t for p, t in sources.items() if p.endswith(".sol")}
    cache = get_cache(cache_dir)
    try:
        builds = cache._load_list().get("builds", [])
    except (OSError, ValueError) as exc:
        logger.warning("tron: solc list.json unavailable: %s", exc)
        return None, reason
    long_version = None
    m = _SEMVER_RE.search(version or "")
    if m:
        want = tuple(int(x) for x in m.groups())
        exprs = [p.group(1) for text in sol_sources.values() for p in PRAGMA.finditer(text)]
        if all(satisfies(e, want) for e in exprs):  # type: ignore[arg-type]
            long_version = next((b.get("longVersion") or b.get("version") for b in builds
                                 if b.get("version") == ".".join(m.groups()) and not b.get("prerelease")), None)
    if long_version is None and sol_sources:
        long_version = pick_solc(sol_sources, builds)
    if long_version is None:
        return None, reason
    try:
        binary = cache.binary(long_version)
    except CompilerCacheError as exc:
        return None, exc.reason_detail
    return TronSolc(binary, long_version, "upstream_solc", cache), ""


def build_tron(candidate: Candidate, cache_dir: Path | None = None, work_dir: Path | None = None) -> BuildResult:
    """Compile a TRON Solidity candidate inside the sandbox (evm build pipeline, TRON compiler).

    Compiler: `resolve_tron_solc` (exact tron-solc tag 6.3, else the upstream solc substitute).
    The build notes record which one ran (`compiler_kind`, `compiler_used`), so the map, the
    analyzers and the report never present a substitute as the deployed compiler.
    """
    import tempfile

    version = candidate.compiler.version if candidate.compiler else None
    solc, reason = resolve_tron_solc(version, candidate.files, cache_dir)
    if solc is None:
        return _fail(candidate, "not_checkable", reason)

    try:
        std_input = sanitize_std_input(_prepare_std_input(candidate))
    except InputSanitizationError as exc:
        return _fail(candidate, "not_checkable", f"input_sanitization_error: {exc}")

    _SBX_ROOT.mkdir(exist_ok=True)
    notes = {"compiler_kind": solc.kind, "compiler_used": solc.version}
    if work_dir is not None:
        br = _run_build(candidate, std_input, solc.path, Path(work_dir), solc.cache)
        br.build_notes.update(notes)
        return br

    with tempfile.TemporaryDirectory(dir=_SBX_ROOT) as tmp:
        br = _run_build(candidate, std_input, solc.path, Path(tmp), solc.cache)
        br.build_notes.update(notes)
        return br


def _resolve_tag(version: str) -> str | None:
    """Resolve a compiler version string to an exact tron-solc tag (6.3).

    Security gate: the resolved tag is validated with the strict regex from
    compiler._TAG_RE before being returned. Malicious or out-of-range version
    strings (e.g. '../../../etc', 'tv_../x', excessively long strings) return None.

    Mappings:
      'tv_0.8.31'                              -> 'tv_0.8.31'  (already a tag)
      'tron-0.8.31' or '0.8.31' (from TronScan) -> 'tv_0.8.31'
      'tv_0.4.25_Odyssey_v3.2.3'              -> 'tv_0.4.25_Odyssey_v3.2.3' (exact)
      Invalid/ambiguous                        -> None (tron_compiler_unmapped)

    Returns None for unmapped, ambiguous, or malformed version strings.
    """
    if not version or len(version) > 80:
        return None
    # For tv_ tags: use the exact input WITHOUT stripping so trailing whitespace
    # or embedded special characters fail the strict regex (security gate).
    if version.startswith("tv_"):
        tag = version
    # "tron_v0.8.18+commit.xxx" — newer TronScan format with commit hash
    elif version.startswith("tron_v"):
        inner = version[6:].split("+")[0].strip()
        if not inner:
            return None
        tag = "tv_" + inner
    # "tron_0.5.12_GreatVoyage_v4.0.1" — TronScan format with network name (no 'v' after _)
    # Strip to semver only: the release tag on GitHub is just tv_X.Y.Z
    elif version.startswith("tron_"):
        inner = version[5:]  # "0.5.12_GreatVoyage_v4.0.1"
        m = _VER_RE.match(inner)
        if not m:
            return None
        tag = "tv_" + m.group(1)
    # "tron-0.4.25_Odyssey_v3.2.3" or "tron-0.5.10_Odyssey_v3.6.6"
    # Keep the full suffix: the 0.4.25 Odyssey release tag includes it;
    # for others, compiler.py does a semver-only fallback if needed.
    elif version.startswith("tron-"):
        inner = version[5:]
        tag = "tv_" + inner
    else:
        # Plain 'x.y.z' or 'x.y.z+commit...' — strip commit suffix
        v = version.strip()
        base = v.split("+")[0].strip()
        if not base:
            return None
        tag = "tv_" + base

    # Strict regex validation (path traversal / injection prevention)
    if not _TAG_RE.match(tag):
        return None
    return tag


class _TronBinaryAdapter:
    """Minimal SolcCache-compatible shim that always returns the given tron-solc path.

    Only the _root attribute and binary() method are used by _run_build/_invoke_solc.
    """

    def __init__(self, binary_path: Path) -> None:
        self._binary = binary_path
        self._root = binary_path.parent.parent  # cache root for sandbox mount

    def binary(self, version: str) -> Path:
        return self._binary
