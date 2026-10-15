"""Scarb metadata plugin-in-unit scope check via an explicit allow-list (feat/starknet-plugin-scope).

Supervisor only. After `scarb fetch` the supervisor runs `scarb metadata --format-version 1
--offline` in the sandbox (capturing stdout; host/ is never mounted into containers so the
build step cannot overwrite it), then calls plugin_allowed_for_unit() to check whether every
non-builtin entry in the compilation unit's `cairo_plugins` is exactly one of the entries in
data/cairo_plugin_allowlist.json with a matching checksum from the pinned Scarb.lock.

Design principles (per coordinator review):
- No path or substring logic on source strings (deleted `_is_in_tree`).
- Only `registry+https://scarbs.xyz/` entries are ever added to the allowlist;
  path, git, registry+file, and any unknown source forms are never allowlisted.
- The unit is tied to the class by package_name + kind=starknet-contract, not by
  artifact stem or target name.  The supervisor built this package; metadata must show
  exactly ONE starknet-contract compilation unit for it.  All artifacts from that build
  came from that unit.
- Checksum from the pinned Scarb.lock (supervisor-written, byte-compared after deps)
  must match the allowlist entry exactly.
- Every ambiguous, missing, or unexpected field returns None (fail closed).

Returns (from plugin_allowed_for_unit):
  False  -- POSITIVE PROOF: exactly one starknet-contract unit, cairo_plugins field
            present, every non-builtin entry is on the allowlist with a matching
            checksum.  The cairo_plugin_in_tree trust hit may be cleared.
  True   -- at least one non-builtin entry is NOT on the allowlist.
  None   -- cannot determine; fail closed (keep untrusted).  Returned when:
            * metadata is not a dict
            * package_name not found in packages, or found more than once
            * zero or more-than-one starknet-contract units for the package
            * cairo_plugins field absent from the unit
            * any non-builtin entry has no package.id or a duplicate id
            * any non-builtin entry's package not in the packages list
            * lock_text missing or unparsable
            * checksum mismatch or lock entry absent for an allowlisted plugin
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

_ALLOWLIST_PATH = Path(__file__).parent / "data" / "cairo_plugin_allowlist.json"


def _load_allowlist() -> dict[str, str]:
    """Return {package_id: checksum} from the allowlist file."""
    try:
        data = json.loads(_ALLOWLIST_PATH.read_text())
        return {
            entry["id"]: entry["checksum"]
            for entry in (data.get("packages") or [])
            if isinstance(entry, dict) and entry.get("id") and entry.get("checksum")
        }
    except (OSError, ValueError, KeyError):
        return {}


def _parse_lock_checksums(lock_text: str) -> dict[str, str]:
    """Parse Scarb.lock and return {package_id: checksum} for entries that have a checksum.

    Package ID is reconstructed as "name version (source)" to match Scarb metadata IDs.
    Entries without a source or checksum (path deps) are omitted.
    """
    try:
        data = tomllib.loads(lock_text)
    except tomllib.TOMLDecodeError:
        return {}
    result: dict[str, str] = {}
    for pkg in (data.get("package") or []):
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source")
        checksum = pkg.get("checksum")
        if name and version and source and checksum:
            pkg_id = f"{name} {version} ({source})"
            result[pkg_id] = checksum
    return result


def plugin_allowed_for_unit(
    metadata: object,
    package_name: str,
    lock_text: str | None,
) -> bool | None:
    """Check whether every non-builtin plugin in the starknet-contract compilation unit
    for `package_name` is exactly on the allow-list with a checksum that matches the
    pinned Scarb.lock.

    Parameters
    ----------
    metadata:
        Parsed JSON from `scarb metadata --format-version 1` (supervisor-captured stdout).
    package_name:
        The Scarb package name that was compiled (from build_context.json).
    lock_text:
        Contents of the supervisor-pinned Scarb.lock (from host/Scarb.lock.pinned).

    Returns
    -------
    False  -- positive proof: can clear cairo_plugin_in_tree.
    True   -- non-allowlisted plugin found.
    None   -- cannot determine; fail closed.
    """
    if not isinstance(metadata, dict):
        return None
    if not package_name or not isinstance(package_name, str):
        return None

    if lock_text is None:
        return None  # caller could not read the lock file; fail closed

    allowlist = _load_allowlist()
    # Parse lock lazily: only needed when we reach checksum verification.
    # An empty string means the lock was read but has no registry entries (pure path-dep
    # project); that is fine when no allowlisted plugins need checksum verification.
    _lock_checksums: dict[str, str] | None = None

    def _get_lock_checksums() -> dict[str, str] | None:
        nonlocal _lock_checksums
        if _lock_checksums is not None:
            return _lock_checksums
        if not isinstance(lock_text, str) or not lock_text.strip():
            return None  # empty lock: will cause fail-closed at checksum step
        _lock_checksums = _parse_lock_checksums(lock_text)
        return _lock_checksums

    packages: list[Any] = metadata.get("packages") or []
    units: list[Any] = metadata.get("compilation_units") or []

    # Build canonical package ID lookup.
    pkg_by_id: dict[str, Any] = {}
    for pkg in packages:
        if isinstance(pkg, dict):
            pid = pkg.get("id")
            if pid and isinstance(pid, str):
                pkg_by_id[pid] = pkg

    # Find the exact package that was built by name.
    # Multiple packages with the same name (e.g. different versions in a dep graph) is
    # ambiguous; fail closed.
    target_pkg_ids = [
        pkg["id"]
        for pkg in packages
        if isinstance(pkg, dict) and pkg.get("name") == package_name and pkg.get("id")
    ]
    if len(target_pkg_ids) != 1:
        return None  # 0 = not found, 2+ = ambiguous

    target_pkg_id = target_pkg_ids[0]

    # Find the starknet-contract compilation unit(s) for this package.
    # There must be EXACTLY ONE; zero means no contract targets, two-or-more is ambiguous.
    sc_units = [
        u for u in units
        if isinstance(u, dict)
        and (u.get("package") or {}).get("id") == target_pkg_id
        and (u.get("target") or {}).get("kind") == "starknet-contract"
    ]
    if len(sc_units) != 1:
        return None

    unit = sc_units[0]

    # cairo_plugins absent (key not present) != cairo_plugins = [].
    # Absent means the metadata format may omit the field; cannot prove plugins are unused.
    if "cairo_plugins" not in unit:
        return None

    # Pre-pass: collect non-builtin PIDs and reject duplicates before any per-entry logic.
    non_builtin_pids: list[str] = []
    for entry in (unit["cairo_plugins"] or []):
        if not isinstance(entry, dict):
            return None
        if entry.get("builtin"):
            continue
        pkg_info = entry.get("package")
        if not isinstance(pkg_info, dict):
            return None
        pid = pkg_info.get("id")
        if not pid or not isinstance(pid, str):
            return None  # unidentifiable entry; fail closed
        non_builtin_pids.append(pid)
    if len(non_builtin_pids) != len(set(non_builtin_pids)):
        return None  # duplicate package IDs in cairo_plugins; suspicious

    for pid in non_builtin_pids:

        # The plugin package must be present in the metadata packages list.
        # If absent the metadata is incomplete (or forged); fail closed.
        pkg_data = pkg_by_id.get(pid)
        if pkg_data is None:
            return None  # plugin package not in metadata; fail closed

        # Every non-builtin plugin must be exactly on the allowlist.
        expected_checksum = allowlist.get(pid)
        if expected_checksum is None:
            # Not on the allowlist: this includes path, git, registry+file, and any
            # unknown source form.
            return True  # not allowed

        # The checksum in the pinned Scarb.lock must match the allowlist entry.
        checksums = _get_lock_checksums()
        if checksums is None:
            return None  # no lock available but we need checksum verification
        actual_checksum = checksums.get(pid)
        if actual_checksum != expected_checksum:
            # Wrong checksum or plugin not in lock (e.g. a path dep has no checksum).
            return None

    # Positive proof: every non-builtin plugin is allowlisted with matching checksum.
    return False
