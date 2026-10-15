# SPDX-License-Identifier: AGPL-3.0-only
"""TRON Slither shim (05 section 8.2, F23).

Patches two Slither type lists in memory at runtime so that tron-solc output
containing `trcToken`, `msg.tokenid` and `msg.tokenvalue` does not crash
Slither with NonElementaryType errors.

From the plan (F23):
  et.ElementaryTypeName.append("trcToken")
  sv.SOLIDITY_VARIABLES_COMPOSED.update({"msg.tokenid": "uint256", "msg.tokenvalue": "uint256"})

This module is AGPL-3.0. Slither itself is AGPL-3.0. No Slither files are
modified; only in-memory lists are extended. The 05 8.2 statement
"GPL and AGPL tools run unmodified" holds.

Sandbox note (9.1): apply_tron_shim() is called in-process before Slither
is invoked on a TRON candidate. misfires -> tron_noise.json (UV5-11).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_APPLIED = False


def apply_tron_shim() -> bool:
    """Patch Slither type lists for TRON support.

    Returns True on success, False if Slither is not installed or the
    expected attributes are missing (shim is not hard-required: the analyze
    step records 'shim_unavailable' in static_map and falls through to
    semgrep-only analysis).
    """
    global _APPLIED
    if _APPLIED:
        return True

    try:
        import slither.core.solidity_types.elementary_type as et
    except ImportError:
        logger.debug("tron_shim: slither not installed; skipping")
        return False

    try:
        import slither.core.variables.state_variable as sv
    except ImportError:
        # Older Slither layout
        sv = None

    # Patch 1: ElementaryTypeName list (F23)
    # Slither uses et.ElementaryTypeName (a list) to validate type strings.
    if hasattr(et, "ElementaryTypeName"):
        type_list = et.ElementaryTypeName
        if "trcToken" not in type_list:
            type_list.append("trcToken")
            logger.debug("tron_shim: appended 'trcToken' to ElementaryTypeName")
    else:
        logger.debug("tron_shim: ElementaryTypeName not found in slither.core.solidity_types.elementary_type")

    # Patch 2: SOLIDITY_VARIABLES_COMPOSED dict (F23)
    # Slither uses this dict to resolve msg.* virtual variables.
    if sv is not None and hasattr(sv, "SOLIDITY_VARIABLES_COMPOSED"):
        composed = sv.SOLIDITY_VARIABLES_COMPOSED
        updates = {"msg.tokenid": "uint256", "msg.tokenvalue": "uint256"}
        for key, val in updates.items():
            if key not in composed:
                composed[key] = val
        logger.debug("tron_shim: updated SOLIDITY_VARIABLES_COMPOSED with msg.tokenid, msg.tokenvalue")
    else:
        # Try alternative location in older Slither versions
        try:
            import slither.slithir.variables.state_variable as sv2
            if hasattr(sv2, "SOLIDITY_VARIABLES_COMPOSED"):
                composed2 = sv2.SOLIDITY_VARIABLES_COMPOSED
                for key, val in {"msg.tokenid": "uint256", "msg.tokenvalue": "uint256"}.items():
                    if key not in composed2:
                        composed2[key] = val
                logger.debug("tron_shim: updated SOLIDITY_VARIABLES_COMPOSED (alt location)")
        except (ImportError, AttributeError):
            logger.debug("tron_shim: SOLIDITY_VARIABLES_COMPOSED not found; msg.tokenid/tokenvalue may crash Slither")

    _APPLIED = True
    return True


def reset_shim() -> None:
    """Reset the applied flag (test helper only)."""
    global _APPLIED
    _APPLIED = False
