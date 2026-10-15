"""Aptos fetch security: path namespace collision and unsafe name rejection (wave-5 fix).

Two packages with the same name (whether from the same account, different
accounts sharing a registry entry, or a name containing path-separators / `..`)
must never silently overwrite each other in the store-path ``files`` dict.
The fix (security finding): store path includes the account address as a prefix,
and any collision rejects the job with ``ValueError`` (fail closed).
"""

from __future__ import annotations

import pytest

from soken_review.adapters.aptos.fetch import candidate_from_registry
from soken_review.adapters.move.units import normalize_address

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkg(name: str, modules: list[str] | None = None) -> dict:
    mods = modules or ["mod_a"]
    return {
        "name": name,
        "manifest": f"[package]\nname = \"{name}\"\n",
        "modules": [{"name": m, "source": f"module addr::{m} {{}}"} for m in mods],
        "upgrade_policy": 2,
        "upgrade_number": 0,
    }


def _cs(address: str, packages: list[dict], deps: dict | None = None) -> dict:
    return {
        "address": address,
        "ledger_version": 1000,
        "packages": packages,
        "module_bytecode": {},
        "deps": deps or {},
    }


ADDR_A = "0x" + "aa" * 32
ADDR_B = "0x" + "bb" * 32


# ---------------------------------------------------------------------------
# Tests that FAIL before the fix (store path collision)
# ---------------------------------------------------------------------------

def test_same_name_packages_within_one_account_raise_collision():
    """Two packages at the same account with identical names must fail closed.

    Before the fix: ``files[f"{pkg['name']}/Move.toml"]`` — second write silently
    overwrites the first.  After the fix: duplicate key detected, ValueError raised.
    """
    # Simulate two packages with the same name (should not happen on-chain, but
    # the code must be defensive against a malformed or adversarial chain-state payload).
    cs = _cs(ADDR_A, [_pkg("Token"), _pkg("Token")])
    with pytest.raises(ValueError, match="collision"):
        candidate_from_registry(cs, None)


def test_unsafe_package_name_with_path_separator_is_rejected():
    """A package name containing ``/`` must be rejected (unsafe store path).

    Before the fix: ``files["foo/bar/Move.toml"]`` — a slash in the name creates a
    subdirectory that can collide with other packages or the ``deps/`` namespace.
    After the fix: name validated against IDENT_RE, ValueError raised.
    """
    cs = _cs(ADDR_A, [_pkg("foo/bar")])
    with pytest.raises(ValueError, match="unsafe package name"):
        candidate_from_registry(cs, None)


def test_unsafe_package_name_with_dotdot_is_rejected():
    """A package name of ``..`` must be rejected.

    Without this check a crafted chain-state could traverse out of the store root.
    """
    cs = _cs(ADDR_A, [_pkg("..")])
    with pytest.raises(ValueError, match="unsafe package name"):
        candidate_from_registry(cs, None)


def test_unsafe_module_name_is_rejected():
    """A module name containing path-unsafe characters must be rejected."""
    cs = _cs(ADDR_A, [_pkg("ValidPkg", modules=["mod/bad"])])
    with pytest.raises(ValueError, match="unsafe module name"):
        candidate_from_registry(cs, None)


# ---------------------------------------------------------------------------
# Tests for correct store-path layout after the fix
# ---------------------------------------------------------------------------

def test_store_path_includes_account_address():
    """After the fix, every package file is stored under ``<account_addr>/<PkgName>/...``.

    This ensures packages from different accounts with identical names land on
    distinct paths (unique identity = address + package name).
    """
    cs = _cs(ADDR_A, [_pkg("Token")])
    cand = candidate_from_registry(cs, None)
    assert cand is not None
    addr = normalize_address(ADDR_A)
    assert f"{addr}/Token/Move.toml" in cand.files
    assert f"{addr}/Token/sources/mod_a.move" in cand.files
    # Old layout must not be present
    assert "Token/Move.toml" not in cand.files


def test_unit_dir_matches_store_path_prefix():
    """``settings['units'][*]['dir']`` must match the store-path prefix so the build
    command (``aptos move compile --package-dir /work/src/<dir>``) finds the manifest.
    """
    cs = _cs(ADDR_A, [_pkg("MyPkg")])
    cand = candidate_from_registry(cs, None)
    assert cand is not None
    addr = normalize_address(ADDR_A)
    units = cand.settings["units"]
    assert len(units) == 1
    assert units[0]["dir"] == f"{addr}/MyPkg"


def test_dep_paths_do_not_collide_with_package_paths():
    """Dependency paths (``deps/<account>/<name>/...``) must not collide with
    the new main-package paths (``<account_addr>/<name>/...``).
    """
    dep_key = "dep1"
    cs = _cs(
        ADDR_A,
        [_pkg("Shared")],
        deps={dep_key: {
            "account": ADDR_B,
            "name": "Shared",
            "manifest": "[package]\nname = \"Shared\"\n",
            "modules": [{"name": "shared_mod", "source": "module b::shared_mod {}"}],
        }},
    )
    cand = candidate_from_registry(cs, None)
    assert cand is not None
    addr_a = normalize_address(ADDR_A)
    # Main package
    assert f"{addr_a}/Shared/Move.toml" in cand.files
    # Dependency (different path prefix)
    assert f"deps/{ADDR_B}/Shared/Move.toml" in cand.files
    # Both keys exist independently — no collision overwrote either
    main_key = f"{addr_a}/Shared/Move.toml"
    dep_key_path = f"deps/{ADDR_B}/Shared/Move.toml"
    assert main_key in cand.files
    assert dep_key_path in cand.files
    assert main_key != dep_key_path  # distinct paths — the fix: address prefix separates namespaces


def test_invalid_account_address_raises():
    """An account address that cannot be normalized must raise ValueError."""
    cs = _cs("not_an_address", [_pkg("Token")])
    with pytest.raises(ValueError, match="invalid account address"):
        candidate_from_registry(cs, None)
