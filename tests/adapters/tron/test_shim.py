"""Tests for the TRON Slither shim (05 section 8.2, F23).

Verifies that apply_tron_shim() patches Slither type lists when Slither is
available, and fails gracefully when it's not installed.

The shim is tested on a fixture that simulates Slither's internal structure.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import patch

from slither_plugins.tron_shim.shim import apply_tron_shim, reset_shim


class TestShimWithFakeSlither:
    """Test the shim using a fake Slither module structure."""

    def setup_method(self):
        reset_shim()

    def teardown_method(self):
        # Remove fake modules from sys.modules
        for mod in list(sys.modules.keys()):
            if "slither" in mod and "soken" not in mod and (
                sys.modules[mod] is None or (
                    hasattr(sys.modules[mod], "_fake_for_test") and sys.modules[mod]._fake_for_test
                )
            ):
                del sys.modules[mod]
        reset_shim()

    def _inject_fake_slither(self):
        """Inject fake slither modules with the expected attributes."""
        # Create fake elementary_type module
        et_mod = ModuleType("slither.core.solidity_types.elementary_type")
        et_mod.ElementaryTypeName = ["uint256", "int256", "bool", "address", "bytes", "string"]
        et_mod._fake_for_test = True

        # Create fake state_variable module
        sv_mod = ModuleType("slither.core.variables.state_variable")
        sv_mod.SOLIDITY_VARIABLES_COMPOSED = {"msg.sender": "address", "msg.value": "uint256"}
        sv_mod._fake_for_test = True

        # Inject parent packages
        for pkg in [
            "slither",
            "slither.core",
            "slither.core.solidity_types",
            "slither.core.variables",
        ]:
            if pkg not in sys.modules:
                m = ModuleType(pkg)
                m._fake_for_test = True
                sys.modules[pkg] = m

        sys.modules["slither.core.solidity_types.elementary_type"] = et_mod
        sys.modules["slither.core.variables.state_variable"] = sv_mod
        return et_mod, sv_mod

    def test_patches_elementary_type_name(self):
        """trcToken is added to ElementaryTypeName (F23)."""
        et_mod, _ = self._inject_fake_slither()
        result = apply_tron_shim()
        assert result is True
        assert "trcToken" in et_mod.ElementaryTypeName

    def test_patches_msg_tokenid(self):
        """msg.tokenid is added to SOLIDITY_VARIABLES_COMPOSED (F23)."""
        _, sv_mod = self._inject_fake_slither()
        apply_tron_shim()
        assert "msg.tokenid" in sv_mod.SOLIDITY_VARIABLES_COMPOSED
        assert sv_mod.SOLIDITY_VARIABLES_COMPOSED["msg.tokenid"] == "uint256"

    def test_patches_msg_tokenvalue(self):
        """msg.tokenvalue is added to SOLIDITY_VARIABLES_COMPOSED (F23)."""
        _, sv_mod = self._inject_fake_slither()
        apply_tron_shim()
        assert "msg.tokenvalue" in sv_mod.SOLIDITY_VARIABLES_COMPOSED
        assert sv_mod.SOLIDITY_VARIABLES_COMPOSED["msg.tokenvalue"] == "uint256"

    def test_idempotent_second_call(self):
        """Calling apply_tron_shim twice does not add duplicates."""
        et_mod, _sv_mod = self._inject_fake_slither()
        apply_tron_shim()
        count_before = et_mod.ElementaryTypeName.count("trcToken")
        # Second call should be a no-op due to _APPLIED flag
        apply_tron_shim()
        count_after = et_mod.ElementaryTypeName.count("trcToken")
        assert count_before == count_after == 1

    def test_graceful_when_slither_missing(self):
        """Returns False gracefully when Slither is not installed."""
        # Ensure slither is NOT in sys.modules
        old = sys.modules.pop("slither", None)
        old_et = sys.modules.pop("slither.core.solidity_types.elementary_type", None)
        try:
            with patch.dict(sys.modules, {"slither": None,
                                           "slither.core.solidity_types.elementary_type": None}):
                result = apply_tron_shim()
            # Should return False (Slither not available)
            assert result is False
        finally:
            if old is not None:
                sys.modules["slither"] = old
            if old_et is not None:
                sys.modules["slither.core.solidity_types.elementary_type"] = old_et

    def test_does_not_overwrite_existing_values(self):
        """Existing entries in SOLIDITY_VARIABLES_COMPOSED are not overwritten."""
        _, sv_mod = self._inject_fake_slither()
        sv_mod.SOLIDITY_VARIABLES_COMPOSED["msg.tokenid"] = "bytes"  # already present
        apply_tron_shim()
        # Should not overwrite: the existing value stays
        # (per the `if key not in composed` check in shim.py)
        assert sv_mod.SOLIDITY_VARIABLES_COMPOSED["msg.tokenid"] == "bytes"
