# SPDX-License-Identifier: AGPL-3.0-only
"""TRON Slither shim (05 section 8.2, F23).

Patches two Slither type lists in memory at runtime so that tron-solc output
containing `trcToken`, `msg.tokenid` and `msg.tokenvalue` does not crash
Slither with NonElementaryType errors.

From the plan (F23):
  et.ElementaryTypeName.append("trcToken")
  sv.SOLIDITY_VARIABLES_COMPOSED.update({"msg.tokenid": "uint256", "msg.tokenvalue": "uint256"})

Where the two symbols live (slither-analyzer 0.11.6, the pinned version):
  slither.core.solidity_types.elementary_type.ElementaryTypeName      (list)
  slither.core.declarations.solidity_variables.SOLIDITY_VARIABLES_COMPOSED (dict)
The dict is defined once and imported BY NAME into
slither.solc_parsing.expressions.expression_parsing, so it must be mutated in
place (never rebound) for the parser to see the patch.

This module is AGPL-3.0. Slither itself is AGPL-3.0. No Slither files are
modified; only in-memory lists are extended. The 05 8.2 statement
"GPL and AGPL tools run unmodified" holds.

Sandbox note (9.1): apply_tron_shim() is called in-process before Slither
is invoked on a TRON candidate. misfires -> tron_noise.json (UV5-11).
"""

from __future__ import annotations

import importlib
import logging

logger = logging.getLogger(__name__)

_APPLIED = False

# Candidate modules for SOLIDITY_VARIABLES_COMPOSED, most specific first.
# 0.11.x defines it in core.declarations.solidity_variables; the other entry
# is kept for older layouts so a downgrade does not silently drop the patch.
_COMPOSED_MODULES = (
    "slither.core.declarations.solidity_variables",
    "slither.core.variables.state_variable",
)

_COMPOSED_UPDATES = {"msg.tokenid": "uint256", "msg.tokenvalue": "uint256"}


def _find_composed() -> dict | None:
    """Return the live SOLIDITY_VARIABLES_COMPOSED dict, or None if no known module exposes it."""
    for mod_name in _COMPOSED_MODULES:
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            continue
        composed = getattr(mod, "SOLIDITY_VARIABLES_COMPOSED", None)
        if isinstance(composed, dict):
            logger.debug("tron_shim: SOLIDITY_VARIABLES_COMPOSED found in %s", mod_name)
            return composed
    return None


def apply_tron_shim() -> bool:
    """Patch Slither type lists for TRON support.

    Returns True only when BOTH patches are in place. Returns False if Slither is
    not installed or SOLIDITY_VARIABLES_COMPOSED is not where any known Slither
    layout puts it; the analyze step then records 'shim_unavailable' in
    static_map and falls through to semgrep-only analysis. A False result does
    not latch, so a later call can succeed.
    """
    global _APPLIED
    if _APPLIED:
        return True

    try:
        import slither.core.solidity_types.elementary_type as et
    except ImportError:
        logger.debug("tron_shim: slither not installed; skipping")
        return False

    # Patch 1: ElementaryTypeName list (F23)
    # Slither uses et.ElementaryTypeName (a list) to validate type strings.
    type_list = getattr(et, "ElementaryTypeName", None)
    if not isinstance(type_list, list):
        logger.warning("tron_shim: ElementaryTypeName not found in %s", et.__name__)
        return False
    if "trcToken" not in type_list:
        type_list.append("trcToken")
        logger.debug("tron_shim: appended 'trcToken' to ElementaryTypeName")

    # Patch 2: SOLIDITY_VARIABLES_COMPOSED dict (F23)
    # Slither uses this dict to resolve msg.* virtual variables.
    composed = _find_composed()
    if composed is None:
        logger.warning(
            "tron_shim: SOLIDITY_VARIABLES_COMPOSED not found in %s; msg.tokenid/tokenvalue would crash Slither",
            ", ".join(_COMPOSED_MODULES),
        )
        return False
    for key, val in _COMPOSED_UPDATES.items():
        composed.setdefault(key, val)
    logger.debug("tron_shim: updated SOLIDITY_VARIABLES_COMPOSED with msg.tokenid, msg.tokenvalue")

    _APPLIED = True
    return True


def reset_shim() -> None:
    """Reset the applied flag (test helper only)."""
    global _APPLIED
    _APPLIED = False
