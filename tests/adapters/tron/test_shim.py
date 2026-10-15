"""Tests for the TRON Slither shim (05 section 8.2, F23).

Verifies that apply_tron_shim() patches Slither type lists when Slither is
available, and fails gracefully when it's not installed.

The shim is tested on a fixture that simulates Slither's internal structure.
The fixture mirrors the pinned slither-analyzer 0.11.6 layout:
  slither.core.solidity_types.elementary_type.ElementaryTypeName   (list)
  slither.core.declarations.solidity_variables.SOLIDITY_VARIABLES_COMPOSED (dict)
The second module is the only place the dict is defined; solc_parsing imports
it by name, so an in-place update is visible to the parser.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import patch

from slither_plugins.tron_shim.shim import apply_tron_shim, reset_shim

_ET_PATH = "slither.core.solidity_types.elementary_type"
_SV_PATH = "slither.core.declarations.solidity_variables"
_SV_LEGACY_PATH = "slither.core.variables.state_variable"


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

    @staticmethod
    def _fake_module(path: str, **attrs) -> ModuleType:
        mod = ModuleType(path)
        for key, val in attrs.items():
            setattr(mod, key, val)
        mod._fake_for_test = True
        # Register every parent package so `import a.b.c` resolves.
        parts = path.split(".")
        for i in range(1, len(parts)):
            pkg = ".".join(parts[:i])
            if pkg not in sys.modules:
                m = ModuleType(pkg)
                m._fake_for_test = True
                sys.modules[pkg] = m
        sys.modules[path] = mod
        return mod

    def _inject_fake_slither(self, *, composed_path: str = _SV_PATH):
        """Inject fake slither modules with the expected attributes (0.11.6 layout by default)."""
        et_mod = self._fake_module(
            _ET_PATH, ElementaryTypeName=["uint256", "int256", "bool", "address", "bytes", "string"]
        )
        sv_mod = self._fake_module(
            composed_path, SOLIDITY_VARIABLES_COMPOSED={"msg.sender": "address", "msg.value": "uint256"}
        )
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

    def test_composed_patched_in_place(self):
        """The dict object is mutated, not rebound: modules that imported it by name see the patch."""
        _, sv_mod = self._inject_fake_slither()
        alias = sv_mod.SOLIDITY_VARIABLES_COMPOSED  # same object as solc_parsing's import
        apply_tron_shim()
        assert alias is sv_mod.SOLIDITY_VARIABLES_COMPOSED
        assert "msg.tokenid" in alias

    def test_legacy_location_still_patched(self):
        """A pre-0.11 layout exposing the dict from core.variables.state_variable is still patched."""
        _, sv_mod = self._inject_fake_slither(composed_path=_SV_LEGACY_PATH)
        assert apply_tron_shim() is True
        assert "msg.tokenid" in sv_mod.SOLIDITY_VARIABLES_COMPOSED

    def test_returns_false_when_composed_missing(self):
        """Slither present but SOLIDITY_VARIABLES_COMPOSED nowhere: the shim reports failure.

        analyze.py maps False to static_map['tron_shim'] = 'unavailable' (05 9.1), so a
        half-applied shim is never reported as 'applied'.
        """
        self._fake_module(
            _ET_PATH, ElementaryTypeName=["uint256", "bool"]
        )
        assert apply_tron_shim() is False
        # The list patch still happened (harmless), but the result is honest.
        assert "trcToken" in sys.modules[_ET_PATH].ElementaryTypeName

    def test_idempotent_second_call(self):
        """Calling apply_tron_shim twice does not add duplicates."""
        et_mod, _sv_mod = self._inject_fake_slither()
        apply_tron_shim()
        count_before = et_mod.ElementaryTypeName.count("trcToken")
        # Second call should be a no-op due to _APPLIED flag
        apply_tron_shim()
        count_after = et_mod.ElementaryTypeName.count("trcToken")
        assert count_before == count_after == 1

    def test_failed_apply_is_retried(self):
        """A failed apply does not latch: once the dict becomes importable, the next call succeeds."""
        self._fake_module(_ET_PATH, ElementaryTypeName=["uint256"])
        assert apply_tron_shim() is False
        sv_mod = self._fake_module(_SV_PATH, SOLIDITY_VARIABLES_COMPOSED={})
        assert apply_tron_shim() is True
        assert "msg.tokenvalue" in sv_mod.SOLIDITY_VARIABLES_COMPOSED

    def test_graceful_when_slither_missing(self):
        """Returns False gracefully when Slither is not installed."""
        # Ensure slither is NOT in sys.modules
        old = sys.modules.pop("slither", None)
        old_et = sys.modules.pop(_ET_PATH, None)
        try:
            with patch.dict(sys.modules, {"slither": None, _ET_PATH: None}):
                result = apply_tron_shim()
            # Should return False (Slither not available)
            assert result is False
        finally:
            if old is not None:
                sys.modules["slither"] = old
            if old_et is not None:
                sys.modules[_ET_PATH] = old_et

    def test_does_not_overwrite_existing_values(self):
        """Existing entries in SOLIDITY_VARIABLES_COMPOSED are not overwritten."""
        _, sv_mod = self._inject_fake_slither()
        sv_mod.SOLIDITY_VARIABLES_COMPOSED["msg.tokenid"] = "bytes"  # already present
        apply_tron_shim()
        # Should not overwrite: the existing value stays
        # (per the `if key not in composed` check in shim.py)
        assert sv_mod.SOLIDITY_VARIABLES_COMPOSED["msg.tokenid"] == "bytes"
