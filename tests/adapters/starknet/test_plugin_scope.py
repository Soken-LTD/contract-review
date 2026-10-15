"""Plugin-scope trust refinement: allowlist-based check (feat/starknet-plugin-scope).

All tests use the new plugin_allowed_for_unit() API.  plugin_used_by_unit() no longer
exists — all old references are removed.

Scenarios tested:
  A. Unit tests for plugin_allowed_for_unit():
     1. No cairo_plugins at all (key absent) -> None (fail closed, not False).
     2. cairo_plugins = [] with allowlist empty -> False (positive proof: no plugins).
     3. Path plugin (not allowlisted) -> True (not allowed).
     4. git+file plugin -> True (not allowlisted; source form irrelevant since we use allowlist).
     5. registry+file plugin -> True (not allowlisted).
     6. Name collision: two packages with the same name -> None (ambiguous).
     7. Two starknet-contract units for the same package -> None (ambiguous).
     8. Allowlisted plugin with correct checksum -> False (positive proof).
     9. Allowlisted plugin with WRONG checksum -> None (fail closed).
     10. Duplicate plugin ID in cairo_plugins -> None (suspicious, fail closed).
     11. Invalid/non-dict metadata -> None.
     12. Missing lock_text -> None.
     13. Plugin entry has no package.id -> None.
     14. Plugin package referenced in cairo_plugins but absent from packages list -> None.

  B. Integration tests: decide() via starknet_steps._refine_plugin_trust:
     1. Plugin in workspace, NOT in unit, allowlisted & correct checksum -> tier A.
     2. Plugin in workspace AND in unit -> tier B.
     3. Missing scarb_metadata.json -> tier B.
     4. Invalid JSON in scarb_metadata.json -> tier B.
     5. Missing build_context.json -> tier B.
     6. Missing Scarb.lock.pinned -> tier B.
     7. Supervisor metadata not overridable by build (provenance integrity).
     8. Other trust reason alongside cairo_plugin_in_tree -> tier B.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.adapters.starknet.plugin_scope import plugin_allowed_for_unit
from soken_review.adapters.starknet.sierra import class_hash, hex_felt, selector_set
from soken_review.worker.starknet_steps import decide

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "starknet"

# ---------------------------------------------------------------------------
# Allowlist constants for tests
# ---------------------------------------------------------------------------
# A fake allowlisted plugin that we inject into the allowlist for tests that need it.
_ALLOWED_ID = "openzeppelin_macros 0.20.0 (registry+https://scarbs.xyz/)"
_ALLOWED_CHECKSUM = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
_WRONG_CHECKSUM   = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

# A valid Scarb.lock snippet with the above package entry.
_LOCK_WITH_ALLOWED = f"""
[[package]]
name = "openzeppelin_macros"
version = "0.20.0"
source = "registry+https://scarbs.xyz/"
checksum = "{_ALLOWED_CHECKSUM}"
"""

# Monkeypatch helper: inject one entry into the allowlist dict without touching the JSON file.
import soken_review.adapters.starknet.plugin_scope as _ps_module


def _patch_allowlist(monkeypatch: pytest.MonkeyPatch, entries: dict[str, str]) -> None:
    monkeypatch.setattr(_ps_module, "_load_allowlist", lambda: dict(entries))


# ---------------------------------------------------------------------------
# Helpers: minimal scarb metadata JSON
# ---------------------------------------------------------------------------

def _pkg(name: str, pkg_id: str) -> dict:
    return {"id": pkg_id, "name": name, "version": "0.1.0"}


def _sc_unit(package_id: str, plugins: list[dict] | None = None, *, include_key: bool = True) -> dict:
    """Starknet-contract compilation unit for the given package ID."""
    u: dict = {
        "id": f"{package_id}_unit",
        "package": {"id": package_id},
        "target": {"kind": "starknet-contract", "name": "MyContract"},
    }
    if include_key:
        u["cairo_plugins"] = plugins or []
    return u


def _plugin_entry(pkg_id: str, *, builtin: bool = False) -> dict:
    return {"id": f"entry_{pkg_id}", "builtin": builtin, "package": {"id": pkg_id, "name": pkg_id.split()[0]}}


def _meta(packages: list, units: list) -> dict:
    return {"version": 1, "packages": packages, "compilation_units": units}


# ============================================================================
# A. Unit tests for plugin_allowed_for_unit()
# ============================================================================

class TestPluginAllowedForUnitClosed:
    """Cases that must return None (fail closed)."""

    def test_cairo_plugins_key_absent_is_closed(self) -> None:
        """cairo_plugins key missing entirely != empty list; must fail closed."""
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        unit = _sc_unit(pkg["id"], include_key=False)  # no cairo_plugins key
        meta = _meta([pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is None

    def test_invalid_metadata_returns_none(self) -> None:
        assert plugin_allowed_for_unit(None, "pkg", _LOCK_WITH_ALLOWED) is None
        assert plugin_allowed_for_unit("string", "pkg", _LOCK_WITH_ALLOWED) is None
        assert plugin_allowed_for_unit([], "pkg", _LOCK_WITH_ALLOWED) is None

    def test_none_lock_text_returns_none(self) -> None:
        """lock_text=None means the caller failed to read the lock file at all; fail closed.

        An empty string "" is NOT the same: it means the Scarb.lock was read but has no
        registry entries (pure path-dep project). That case is fine when the unit has no
        allowlisted plugins needing checksum verification.
        """
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        unit = _sc_unit(pkg["id"], [])
        meta = _meta([pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", None) is None

    def test_package_not_found_returns_none(self) -> None:
        pkg = _pkg("other", "other 0.1.0 (path+file:///tree)")
        unit = _sc_unit(pkg["id"], [])
        meta = _meta([pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is None

    def test_duplicate_package_name_returns_none(self) -> None:
        """Two packages with the same name are ambiguous — fail closed."""
        pkg1 = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        pkg2 = _pkg("my_contract", "my_contract 0.1.0 (path+file:///other)")
        unit = _sc_unit(pkg1["id"], [])
        meta = _meta([pkg1, pkg2], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is None

    def test_two_starknet_contract_units_is_closed(self) -> None:
        """Two starknet-contract units for the same package: ambiguous."""
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        unit_a = _sc_unit(pkg["id"], [])
        unit_b = _sc_unit(pkg["id"], [])
        unit_b["id"] = "unit_b"
        meta = _meta([pkg], [unit_a, unit_b])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is None

    def test_plugin_entry_no_package_id_is_closed(self) -> None:
        """Plugin entry with no package.id: unidentifiable, fail closed."""
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        bad_entry = {"id": "e1", "builtin": False, "package": {}}
        unit = _sc_unit(pkg["id"], [bad_entry])
        meta = _meta([pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is None

    def test_plugin_package_not_in_metadata_is_closed(self) -> None:
        """Plugin referenced in cairo_plugins but not in packages list."""
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        ghost_entry = _plugin_entry("ghost 0.5.0 (path+file:///ghost)")
        unit = _sc_unit(pkg["id"], [ghost_entry])
        meta = _meta([pkg], [unit])  # ghost package absent from packages
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is None

    def test_duplicate_plugin_id_in_unit_is_closed(self) -> None:
        """Duplicate plugin IDs in cairo_plugins of one unit: suspicious, fail closed."""
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        pid = "macros 0.1.0 (path+file:///tree/macros)"
        macro_pkg = _pkg("macros", pid)
        entry = _plugin_entry(pid)
        unit = _sc_unit(pkg["id"], [entry, entry])  # same entry twice
        meta = _meta([pkg, macro_pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is None

    def test_allowlisted_wrong_checksum_is_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Same allowlisted ID but lock checksum does not match allowlist entry."""
        _patch_allowlist(monkeypatch, {_ALLOWED_ID: _ALLOWED_CHECKSUM})
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        macro_pkg = _pkg("openzeppelin_macros", _ALLOWED_ID)
        entry = _plugin_entry(_ALLOWED_ID)
        unit = _sc_unit(pkg["id"], [entry])
        meta = _meta([pkg, macro_pkg], [unit])
        # Lock has a different checksum for the same package ID.
        wrong_lock = f"""
[[package]]
name = "openzeppelin_macros"
version = "0.20.0"
source = "registry+https://scarbs.xyz/"
checksum = "{_WRONG_CHECKSUM}"
"""
        assert plugin_allowed_for_unit(meta, "my_contract", wrong_lock) is None


class TestPluginAllowedForUnitNotAllowed:
    """Cases that must return True (non-allowlisted plugin found)."""

    def test_path_plugin_not_allowlisted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """In-tree path plugin: not on allowlist -> True (not allowed)."""
        _patch_allowlist(monkeypatch, {})  # empty allowlist
        pid = "macros 0.1.0 (path+file:///tree/macros)"
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        macro_pkg = _pkg("macros", pid)
        entry = _plugin_entry(pid)
        unit = _sc_unit(pkg["id"], [entry])
        meta = _meta([pkg, macro_pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is True

    def test_git_file_plugin_gives_not_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """git+file:/// plugin is NOT on allowlist -> True.

        Per coordinator: git+file is an in-tree source form; source-string prefix logic
        is deleted; the allowlist gate catches it because the ID is not in the allowlist.
        """
        _patch_allowlist(monkeypatch, {})
        pid = "macros 0.1.0 (git+file:///tree/.git?rev=abc123)"
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        macro_pkg = _pkg("macros", pid)
        entry = _plugin_entry(pid)
        unit = _sc_unit(pkg["id"], [entry])
        meta = _meta([pkg, macro_pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is True

    def test_registry_file_plugin_gives_not_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """registry+file:// plugin (local registry) is NOT on allowlist -> True."""
        _patch_allowlist(monkeypatch, {})
        pid = "macros 0.1.0 (registry+file:///local/registry)"
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        macro_pkg = _pkg("macros", pid)
        entry = _plugin_entry(pid)
        unit = _sc_unit(pkg["id"], [entry])
        meta = _meta([pkg, macro_pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is True


class TestPluginAllowedForUnitPositiveProof:
    """Cases that must return False (positive proof: can clear trust)."""

    def test_no_plugins_empty_list_returns_false(self) -> None:
        """cairo_plugins = [] with no entries: all zero non-builtin plugins -> positive proof."""
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        unit = _sc_unit(pkg["id"], [])
        meta = _meta([pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is False

    def test_only_builtin_plugins_returns_false(self) -> None:
        """All plugins are builtin: nothing to check against allowlist -> False."""
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        builtin_entry = {"id": "builtin_starknet", "builtin": True, "package": {"id": "starknet 0.1.0", "name": "starknet"}}
        unit = _sc_unit(pkg["id"], [builtin_entry])
        meta = _meta([pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is False

    def test_allowlisted_plugin_correct_checksum_returns_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Allowlisted registry plugin with matching lock checksum -> False (A-eligible).

        This is the key success path: the OZ macros crate from scarbs.xyz, if we add it
        to the allowlist after auditing it, would unlock tier A.
        """
        _patch_allowlist(monkeypatch, {_ALLOWED_ID: _ALLOWED_CHECKSUM})
        pkg = _pkg("my_contract", "my_contract 0.1.0 (path+file:///tree)")
        macro_pkg = _pkg("openzeppelin_macros", _ALLOWED_ID)
        entry = _plugin_entry(_ALLOWED_ID)
        unit = _sc_unit(pkg["id"], [entry])
        meta = _meta([pkg, macro_pkg], [unit])
        assert plugin_allowed_for_unit(meta, "my_contract", _LOCK_WITH_ALLOWED) is False


# ============================================================================
# B. Integration tests: decide() via starknet_steps._refine_plugin_trust
# ============================================================================

def _setup_decide_dir(
    tmp_path: Path,
    *,
    plugin_in_unit: bool,
    allowlist_entries: dict[str, str] | None = None,
    lock_text: str | None = None,
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> tuple[str, dict, Path]:
    """Prepare a job output dir with chain_state, artifacts, trust_scan (cairo_plugin only)
    and scarb_metadata.json, build_context.json, Scarb.lock.pinned.

    Returns (class_hash_str, selectors, out_path).

    The setup uses an in-tree path plugin (_pkg macros).  When plugin_in_unit=False and
    allowlist_entries is given, the plugin is on the allowlist with correct checksum -> tier A.
    When allowlist_entries is None or empty, or plugin_in_unit=True -> tier B.
    """
    udc = json.loads((FIX / "udc_class_0x1b2df6d8.json").read_text())
    h = hex_felt(class_hash(udc))
    sels = {k: [hex(s) for s in v] for k, v in selector_set(udc).items()}

    host = tmp_path / "build" / "host"
    host.mkdir(parents=True)
    art = {"contract": "p_UDC", "class_hash": h, "selectors": sels}
    (host / "artifacts.json").write_text(json.dumps([art]))
    (host / "trust_scan.json").write_text(json.dumps({
        "untrusted": True,
        "reasons": ["cairo_plugin_in_tree:packages/macros/Scarb.toml"],
    }))
    (tmp_path / "chain_state.json").write_text(json.dumps({
        "class_hash": h, "selectors": sels, "class_verified": True,
    }))

    # Build context: package name for the supervisor build.
    (host / "build_context.json").write_text(json.dumps({"package_name": "presets", "lock_path": "Scarb.lock"}))

    # Pinned lock: empty unless caller provides one (path plugins have no checksum).
    actual_lock = lock_text if lock_text is not None else ""
    (host / "Scarb.lock.pinned").write_text(actual_lock)

    # Scarb metadata.
    # Plugin is a path dep by default (not on any allowlist unless monkeypatched).
    plugin_id = "macros 0.1.0 (path+file:///work/tree/packages/macros)"
    plugin_pkg = _pkg("macros", plugin_id)
    main_pkg = _pkg("presets", "presets 0.1.0 (path+file:///work/tree/packages/presets)")
    plugins_list = [_plugin_entry(plugin_id)] if plugin_in_unit else []
    unit = _sc_unit(main_pkg["id"], plugins_list)
    meta = _meta([plugin_pkg, main_pkg], [unit])
    (host / "scarb_metadata.json").write_text(json.dumps(meta))

    if monkeypatch is not None and allowlist_entries is not None:
        monkeypatch.setattr(_ps_module, "_load_allowlist", lambda: dict(allowlist_entries))

    return h, sels, tmp_path


def test_decide_no_plugins_in_unit_gives_tier_a(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plugin in workspace but NOT in compilation unit, no plugins at all -> trust cleared -> tier A."""
    _setup_decide_dir(tmp_path, plugin_in_unit=False, monkeypatch=monkeypatch, allowlist_entries={})
    prov = decide(tmp_path, "ok", None, has_deployment=True)
    assert prov["untrusted_inputs"] is False, "trust should be cleared when unit has no plugins"
    assert prov["match"] == "exact" and prov["tier"] == "A"


def test_decide_plugin_in_unit_stays_tier_b(tmp_path: Path) -> None:
    """Plugin IS in the compilation unit -> inputs stay untrusted -> tier B."""
    _setup_decide_dir(tmp_path, plugin_in_unit=True)
    prov = decide(tmp_path, "ok", None, has_deployment=True)
    assert prov["untrusted_inputs"] is True, "trust must stay set"
    assert prov["match"] == "not_checkable" and prov["reason"] == "build_input_untrusted"
    assert prov["tier"] == "B"


def test_decide_no_metadata_stays_tier_b(tmp_path: Path) -> None:
    """scarb_metadata.json missing -> fail closed -> tier B."""
    _, _, out = _setup_decide_dir(tmp_path, plugin_in_unit=False)
    (out / "build" / "host" / "scarb_metadata.json").unlink()
    prov = decide(out, "ok", None, has_deployment=True)
    assert prov["untrusted_inputs"] is True
    assert prov["tier"] == "B"


def test_decide_metadata_invalid_json_stays_tier_b(tmp_path: Path) -> None:
    """Invalid JSON in scarb_metadata.json -> fail closed -> tier B."""
    _, _, out = _setup_decide_dir(tmp_path, plugin_in_unit=False)
    (out / "build" / "host" / "scarb_metadata.json").write_text("not valid json {{{")
    prov = decide(out, "ok", None, has_deployment=True)
    assert prov["untrusted_inputs"] is True
    assert prov["tier"] == "B"


def test_decide_missing_build_context_stays_tier_b(tmp_path: Path) -> None:
    """build_context.json missing -> fail closed -> tier B."""
    _, _, out = _setup_decide_dir(tmp_path, plugin_in_unit=False)
    (out / "build" / "host" / "build_context.json").unlink()
    prov = decide(out, "ok", None, has_deployment=True)
    assert prov["untrusted_inputs"] is True
    assert prov["tier"] == "B"


def test_decide_missing_lock_pinned_stays_tier_b(tmp_path: Path) -> None:
    """Scarb.lock.pinned missing -> fail closed -> tier B (need lock for checksum)."""
    _, _, out = _setup_decide_dir(tmp_path, plugin_in_unit=False)
    (out / "build" / "host" / "Scarb.lock.pinned").unlink()
    prov = decide(out, "ok", None, has_deployment=True)
    assert prov["untrusted_inputs"] is True
    assert prov["tier"] == "B"


def test_decide_supervisor_metadata_not_overridable_by_build(tmp_path: Path) -> None:
    """Provenance integrity: only host/ (supervisor-written, never mounted) is authoritative.

    Confirm that decide() reads from host/scarb_metadata.json and that corrupting that
    file changes the tier — proving it is the only path.
    """
    _setup_decide_dir(tmp_path, plugin_in_unit=False)
    host = tmp_path / "build" / "host"
    # Corrupt the metadata to have no units -> unit not found -> None -> untrusted -> tier B.
    good = json.loads((host / "scarb_metadata.json").read_text())
    bad_meta = _meta(good["packages"], [])
    (host / "scarb_metadata.json").write_text(json.dumps(bad_meta))
    prov_bad = decide(tmp_path, "ok", None, has_deployment=True)
    assert prov_bad["tier"] == "B", "corrupted metadata (no units) must give tier B"
    # Restore.
    (host / "scarb_metadata.json").write_text(json.dumps(good))
    prov_good = decide(tmp_path, "ok", None, has_deployment=True)
    assert prov_good["tier"] == "A", "restored metadata (no plugins in unit) must give tier A"


def test_decide_other_trust_reason_stays_untrusted(tmp_path: Path) -> None:
    """Mixed trust reasons: cairo_plugin_in_tree + other reason -> do NOT clear trust."""
    _, _, out = _setup_decide_dir(tmp_path, plugin_in_unit=False)
    host = out / "build" / "host"
    (host / "trust_scan.json").write_text(json.dumps({
        "untrusted": True,
        "reasons": ["cairo_plugin_in_tree:packages/macros/Scarb.toml", "git_dependency:somepkg"],
    }))
    prov = decide(out, "ok", None, has_deployment=True)
    assert prov["untrusted_inputs"] is True
    assert prov["tier"] == "B"
