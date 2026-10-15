# SPDX-License-Identifier: AGPL-3.0-only
"""TRON Slither shim — patches type lists in memory for tron-solc support (05 section 8.2, F23).

Published under AGPL-3.0 per 05 8.2 (U13). Slither files are unchanged;
the shim patches two in-memory lists at import time.

Verified against the pinned slither-analyzer 0.11.6 (docker/tron-analyze build step).
"""

from slither_plugins.tron_shim.shim import apply_tron_shim

__all__ = ["apply_tron_shim"]
