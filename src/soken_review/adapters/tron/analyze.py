"""TRON analyze step: Slither (tron-analyze image with shim baked in) -> lead.v1 list (05 8.1-8.2, 9).

The TRON Slither shim (05 8.2, F23) must run INSIDE the container that runs Slither.
It cannot be applied in the host Python because Slither runs in an isolated sandbox image.

Architecture:
  Host Python calls analyze() -> _run_slither(..., image=tron-analyze).
  Inside the container, slither_plugins is installed and registered via the
  slither_analyzer.plugin entry point.  When Slither starts it calls make_plugin(),
  which calls apply_tron_shim() as a side effect.  This patches ElementaryTypeName
  and SOLIDITY_VARIABLES_COMPOSED before any source file is parsed (F23).

  The tron-analyze image is required (locked_image fails closed when the digest is a
  placeholder or SOKEN_IMAGE_TRON_ANALYZE is unset).  This matches the HyperEVM pattern
  (05 8.2): never fall back to the plain EVM image, which would report a run without
  the TRON patches as complete.

Direct mode (SOKEN_ANALYZE_DIRECT=1, dev only):
  Slither runs in the host process.  apply_tron_shim() is called in-process before
  the EVM analyze pipeline runs, replicating what make_plugin() does in the container.

static_map extra field:
  "tron_shim": "applied" | "unavailable"
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from soken_review.adapters.base import BuildResult, Lead

logger = logging.getLogger(__name__)

_TRON_IMAGE_NAME = "tron-analyze"
_DIRECT_TOOLS = os.environ.get("SOKEN_ANALYZE_DIRECT", "0") == "1"


def analyze(result: BuildResult) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]:
    """Run Slither (with TRON shim active in the tron-analyze image) on a TRON BuildResult.

    Returns (leads, static_map, read_plan).
    Fails closed if the tron-analyze image is unavailable and not in direct mode.
    """
    from soken_review.adapters.evm.analyze import (
        _build_leads,
        _build_static_map,
        _extract_settings,
        _materialize_sources,
        _run_aderyn,
        _run_slither,
    )

    if result.status != "ok" or not result.work_dir:
        return [], {"status": "not_run", "reason": "build_failed"}, {}

    work_dir = Path(result.work_dir)
    from soken_review.adapters.evm.analyze import prepare_analyze_dir, write_records

    out_dir = prepare_analyze_dir(work_dir)  # fresh; no link a container left is followed

    proj_dir = out_dir / "proj"
    settings = _extract_settings(work_dir)
    if not _materialize_sources(work_dir, proj_dir):
        return [], {"status": "not_run", "reason": "project_materialization_failed"}, {}

    # Use the TRON compiler cache instead of the EVM one: _solc_path uses evm.get_cache()
    # which doesn't know TRON version strings.  Resolve via TronSolcCache directly.
    solc_path = _tron_solc_path(result)
    if solc_path is None:
        return [], {"status": "not_run", "reason": "compiler_binary_missing"}, {}

    entry = (result.candidate.entry_contract or "").rpartition(":")[0] or None

    tron_img = _tron_image()
    if tron_img is None and not _DIRECT_TOOLS:
        return [], {"status": "not_run", "reason": "sandbox_unavailable"}, {}

    # In direct mode, apply the shim in-process before Slither runs (replicates make_plugin).
    shim_applied = False
    if _DIRECT_TOOLS:
        shim_applied = _apply_shim_direct()

    slither_raw = _run_slither(proj_dir, out_dir, solc_path, settings, entry, image=tron_img)
    if slither_raw is None:
        reason = "sandbox_unavailable" if tron_img is None else "analyzer_failed"
        return [], {"status": "not_run", "reason": reason}, {}

    aderyn_raw = _run_aderyn(proj_dir, out_dir)
    all_raw: list[dict] = list(slither_raw)
    if aderyn_raw is not None:
        all_raw.extend(aderyn_raw)

    leads = _build_leads(all_raw)
    static_map = _build_static_map(out_dir, aderyn_available=aderyn_raw is not None)
    # In container mode the shim is always applied (baked into the image).
    # In direct mode, report whether apply_tron_shim() succeeded.
    static_map["tron_shim"] = "applied" if (not _DIRECT_TOOLS or shim_applied) else "unavailable"
    # 05 6.2 A5: tron-solc bugs are not mapped to upstream solc until the base is documented (UV5-29)
    static_map["compiler_advisories"] = {
        "status": "not_covered", "reason": "tron_upstream_base_undocumented", "version": None, "rows": [],
    }
    read_plan: dict[str, Any] = {"entries": [], "version": "1"}

    write_records(work_dir, leads, static_map, read_plan)  # host-only dir (09 3.5)

    return leads, static_map, read_plan


def _tron_solc_path(result: BuildResult) -> str | None:
    """Resolve the tron-solc binary path from TronSolcCache for this build result.

    Returns the path as a string (for Slither's --solc argument), or None if unavailable.
    The binary is passed into the container via the cache mount at /cache/<tag>/solc.
    """
    from soken_review.adapters.tron.build import _resolve_tag
    from soken_review.adapters.tron.compiler import TronCompilerCacheError, get_tron_cache

    compiler = result.candidate.compiler
    if compiler is None:
        return None
    tag = _resolve_tag(compiler.version)
    if tag is None:
        return None
    try:
        return str(get_tron_cache().binary(tag))
    except TronCompilerCacheError:
        return None


def _tron_image() -> str | None:
    """Return the locked tron-analyze image reference, or None (fail closed)."""
    from soken_review.sandbox.profile import locked_image
    return locked_image(_TRON_IMAGE_NAME)


def _apply_shim_direct() -> bool:
    """Apply the TRON Slither shim in-process (direct mode only). Returns True on success."""
    try:
        from slither_plugins.tron_shim.shim import apply_tron_shim
        return apply_tron_shim()
    except ImportError:
        logger.debug("slither_plugins not installed; TRON shim unavailable in direct mode")
        return False
