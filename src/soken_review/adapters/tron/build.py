"""TRON build step: tron-solc --standard-json inside the sandbox (05 sections 6.3, 7, 13.2 X5).

Reuses the EVM build pipeline (adapters/evm/build.py) but substitutes the
tron-solc binary from the TronSolcCache (6.3) instead of the standard solc.

TRON-specific rules:
  X5  Auxdata: X2 (trailing-newline recompile) with tron-solc.
  6.3 Exact tag mapping tv_<version>; 'not_checkable' if unmapped or ambiguous.
  F21 CBOR auxdata key is 'tron' (not 'ipfs'); tron-solc adds TRC-10 checks.

The sandbox image and limits are the same as EVM (evm-analyze).
"""

from __future__ import annotations

import os
import re as _re
from pathlib import Path

# Regex to extract the leading semver from a version string after prefix stripping
_VER_RE = _re.compile(r"^([0-9]+\.[0-9]+\.[0-9]+)")

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

# SOKEN_TRON_SOLC_DIRECT=1: dev-only bypass, never set in production or tests
_DIRECT_TRON_SOLC = os.environ.get("SOKEN_TRON_SOLC_DIRECT", "0") == "1"


def build_tron(candidate: Candidate, cache_dir: Path | None = None, work_dir: Path | None = None) -> BuildResult:
    """Compile a TRON Solidity candidate with tron-solc inside the sandbox.

    Reuses the EVM build pipeline (build.py _run_build) with the tron-solc binary.
    Falls back to status='failed', reason='not_checkable' when the binary is unavailable.

    version_pinned_by='tronscan': candidate.compiler.version must be a tron-solc tag
    (e.g. 'tron-0.8.18' -> tag 'tv_0.8.18', or already 'tv_0.8.31').

    Rules 6.3:
      - Exact tag only; ambiguous or unmapped -> not_checkable(tron_compiler_ambiguous
        / tron_compiler_unmapped).
      - Never the nearest upstream version.
    """
    import tempfile

    version = candidate.compiler.version if candidate.compiler else None
    if not version:
        return _fail(candidate, "not_checkable", "compiler_version_unknown")

    # Resolve compiler version string to a tron-solc tag (6.3)
    tag = _resolve_tag(version)
    if tag is None:
        return _fail(candidate, "not_checkable", "tron_compiler_unmapped")

    cache = get_tron_cache(cache_dir)
    try:
        tron_solc_bin = cache.binary(tag)
    except TronCompilerCacheError as exc:
        return _fail(candidate, "not_checkable", exc.reason_detail)

    # Use the same EVM SolcCache wrapper but with tron-solc path
    # We need a SolcCache-compatible object so _run_build can find the binary
    mock_cache = _TronBinaryAdapter(tron_solc_bin)

    try:
        std_input = sanitize_std_input(_prepare_std_input(candidate))
    except InputSanitizationError as exc:
        return _fail(candidate, "not_checkable", f"input_sanitization_error: {exc}")

    _SBX_ROOT.mkdir(exist_ok=True)

    if work_dir is not None:
        return _run_build(candidate, std_input, tron_solc_bin, Path(work_dir), mock_cache)

    with tempfile.TemporaryDirectory(dir=_SBX_ROOT) as tmp:
        return _run_build(candidate, std_input, tron_solc_bin, Path(tmp), mock_cache)


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
