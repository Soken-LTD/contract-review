"""Build-input trust scan for Scarb trees (06 3.3.4 applied to 07 8.2). Supervisor only.

A rebuilt class hash proves the reviewed source only when the build ran nothing but the pinned
compiler on that source. The scan is fail-closed and does not re-implement Scarb resolution: it
reads every manifest in the pinned tree and the pinned Scarb.lock. Untrusted blocks tier A
(provenance.decide_dep_match), never the build.

Untrusted when any of:
- any Scarb.toml anywhere in the tree declares a `[cairo-plugin]` target (procedural macro: native
  code at build time that can rewrite code), whether or not the built package uses it;
- the selected package has no manifest, or the root is a virtual workspace and no package is
  selected (Scarb would build every member);
- `[patch...]` sections, or `allow-prebuilt-plugins` with any entry;
- a path dependency (direct or `workspace = true`, resolved against the workspace root) that
  leaves the tree or names a directory with no manifest;
- a git dependency, or a registry dependency, in any manifest that is not pinned in
  data/dep_allowlist.yaml (checked through the lockfile rows);
- no Scarb.lock at the workspace root, an unparsable manifest or lockfile;
- a Scarb.lock package that is neither a manifest in the tree nor an allowlisted external package
  (name, version, source, checksum all equal), or an allowlisted one marked `cairo_plugin`;
- `rust-toolchain*` or `.cargo/config*` files.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

_ALLOWLIST = Path(__file__).parent / "data" / "dep_allowlist.yaml"
_BLOCKED = [re.compile(r"(?:^|/)rust-toolchain(?:\.toml)?$", re.IGNORECASE), re.compile(r"(?:^|/)\.cargo/config(?:\.toml)?$", re.IGNORECASE)]
_DEP_TABLES = ("dependencies", "dev-dependencies")
# Built into Scarb (corelib and its companions); never in a lockfile with a source.
_BUILTIN = {"core", "starknet", "assert_macros", "cairo_test"}


_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
_SEMVER_RE = re.compile(r"^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.]{1,40})?$")


def _n(name: object) -> str:
    """Package name for a reason code: the Scarb name grammar, else a fixed token with a short hash
    (reason codes reach the model through the map; raw manifest strings never do)."""
    if isinstance(name, str) and _NAME_RE.match(name):
        return name
    return "invalid_name_" + hashlib.sha256(repr(name).encode()).hexdigest()[:8]


def _v(version: object) -> str:
    return version if isinstance(version, str) and _SEMVER_RE.match(version) else "invalid_version"


def _load_allowlist() -> list[dict[str, Any]]:
    return (yaml.safe_load(_ALLOWLIST.read_text()) or {}).get("packages") or []


def _dir_of(path: str) -> str:
    return str(PurePosixPath(path).parent) if "/" in path else ""


def _join(base: str, rel: str) -> str | None:
    """Normalized tree path of `rel` from dir `base`; None when it leaves the tree."""
    if rel.startswith("/"):
        return None
    target = posixpath.normpath(posixpath.join(base, rel) if base else rel)
    if target == ".":
        return ""
    if target.startswith("../") or target == "..":
        return None
    return target


def scan_files(files: dict[str, str], package_dir: str = "") -> tuple[bool, list[str]]:
    """Return (untrusted, reasons) for the pinned tree and the package selected at `package_dir`."""
    reasons: set[str] = set()
    manifests: dict[str, dict[str, Any]] = {}
    for path, text in files.items():
        if any(p.search(path) for p in _BLOCKED):
            reasons.add(f"toolchain_override:{path}")
        if PurePosixPath(path).name != "Scarb.toml":
            continue
        try:
            manifests[_dir_of(path)] = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            reasons.add(f"manifest_unparsable:{path}")

    pkg_dir = package_dir.strip("/")
    selected = manifests.get(pkg_dir)
    if selected is None:
        reasons.add(f"package_manifest_missing:{pkg_dir or '.'}")
    elif "package" not in selected:
        reasons.add("virtual_workspace_no_package_selected")

    root_dir = workspace_root(manifests, pkg_dir)
    root = manifests.get(root_dir, {})
    ws_deps = (root.get("workspace") or {}).get("dependencies") or {}

    external: set[str] = set()
    for d, m in manifests.items():
        label = f"{d or '.'}/Scarb.toml"
        if "cairo-plugin" in m:
            reasons.add(f"cairo_plugin_in_tree:{label}")
        if any(k == "patch" or k.startswith("patch.") for k in m):
            reasons.add(f"patch_section:{label}")
        for tool in (m.get("tool") or {}, (m.get("workspace") or {}).get("tool") or {}):
            if (tool.get("scarb") or {}).get("allow-prebuilt-plugins"):
                reasons.add(f"prebuilt_plugins_allowed:{label}")
        tables = [m.get(t) or {} for t in _DEP_TABLES]
        for table in tables:
            for name, spec in table.items():
                base = d
                if isinstance(spec, dict) and spec.get("workspace") is True:
                    spec, base = ws_deps.get(name), root_dir
                    if spec is None:
                        reasons.add(f"workspace_dep_missing:{_n(name)}")
                        continue
                if isinstance(spec, dict) and "path" in spec:
                    target = _join(base, str(spec["path"]))
                    if target is None:
                        reasons.add(f"path_dep_outside_tree:{_n(name)}")
                    elif target not in manifests:
                        reasons.add(f"path_dep_missing:{_n(name)}")
                elif isinstance(spec, dict) and "git" in spec:
                    reasons.add(f"git_dependency:{_n(name)}")
                elif name not in _BUILTIN:
                    external.add(name)

    # Lockfile cross-check (pinned source, read here; Scarb in the deps container may rewrite its copy).
    lock_text = files.get(f"{root_dir}/Scarb.lock" if root_dir else "Scarb.lock")
    if lock_text is None:
        reasons.add("lock_missing")
        lock_pkgs: list[dict[str, Any]] = []
    else:
        try:
            lock_pkgs = tomllib.loads(lock_text).get("package") or []
        except tomllib.TOMLDecodeError:
            reasons.add("lock_unparsable")
            lock_pkgs = []
    tree_names = {(m.get("package") or {}).get("name") for m in manifests.values()}
    allow = _load_allowlist()
    locked_external: set[str] = set()
    for row in lock_pkgs:
        name = row.get("name")
        if "source" not in row:
            if name not in tree_names:
                reasons.add(f"lock_package_not_in_tree:{_n(name)}")
            continue
        locked_external.add(name)
        hit = next((a for a in allow if all(str(a.get(k)) == str(row.get(k)) for k in ("name", "version", "source", "checksum"))), None)
        if hit is None:
            reasons.add(f"external_package_not_allowlisted:{_n(name)}@{_v(row.get('version'))}")
        elif hit.get("cairo_plugin"):
            reasons.add(f"cairo_plugin_in_lock:{_n(name)}@{_v(row.get('version'))}")
    for name in sorted(external - locked_external):
        reasons.add(f"dependency_not_in_lock:{_n(name)}")
    return bool(reasons), sorted(reasons)


def workspace_root(manifests: dict[str, dict[str, Any]], pkg_dir: str) -> str:
    """Nearest dir at or above the package whose manifest has [workspace]; else the package dir."""
    probe: str | None = pkg_dir
    while probe is not None:
        if "workspace" in manifests.get(probe, {}):
            return probe
        probe = None if probe == "" else _dir_of(probe)
    return pkg_dir


def path_dependency_dirs(files: dict[str, str], package_dir: str) -> list[str] | None:
    """Package dir plus the in-tree dirs of its non-dev path dependencies, transitively
    (`workspace = true` resolved against the workspace root). None when a manifest does not parse
    or a path dependency leaves the tree or has no manifest (callers fall back to wider scope)."""
    manifests: dict[str, dict[str, Any]] = {}
    for path, text in files.items():
        if PurePosixPath(path).name == "Scarb.toml":
            try:
                manifests[_dir_of(path)] = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                return None
    start = package_dir.strip("/")
    if start not in manifests:
        return None
    seen: list[str] = []
    stack = [start]
    while stack:
        d = stack.pop()
        if d in seen:
            continue
        seen.append(d)
        root_dir = workspace_root(manifests, d)
        ws_deps = (manifests.get(root_dir, {}).get("workspace") or {}).get("dependencies") or {}
        for name, spec in (manifests[d].get("dependencies") or {}).items():
            base = d
            if isinstance(spec, dict) and spec.get("workspace") is True:
                spec, base = ws_deps.get(name), root_dir
            if isinstance(spec, dict) and "path" in spec:
                target = _join(base, str(spec["path"]))
                if target is None or target not in manifests:
                    return None
                stack.append(target)
    return seen


def lock_path(files: dict[str, str], package_dir: str) -> str:
    """Store path of the Scarb.lock Scarb uses for this package (workspace root)."""
    manifests: dict[str, dict[str, Any]] = {}
    for path, text in files.items():
        if PurePosixPath(path).name == "Scarb.toml":
            try:
                manifests[_dir_of(path)] = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
    root = workspace_root(manifests, package_dir.strip("/"))
    return f"{root}/Scarb.lock" if root else "Scarb.lock"


def package_name(files: dict[str, str], package_dir: str) -> str | None:
    """`[package] name` of the selected manifest, for `scarb build --package`."""
    pkg_dir = package_dir.strip("/")
    text = files.get(f"{pkg_dir}/Scarb.toml" if pkg_dir else "Scarb.toml")
    if text is None:
        return None
    try:
        name = (tomllib.loads(text).get("package") or {}).get("name")
    except tomllib.TOMLDecodeError:
        return None
    return name if isinstance(name, str) and re.match(r"^[a-z_][a-z0-9_]{0,63}$", name) else None
