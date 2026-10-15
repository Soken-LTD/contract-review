"""Aptos package staging from registry data (plan v4 07 sections 4 and 7.1.4).

The adapter never hands a fetched manifest to the CLI. It parses the published manifest with
`tomllib`, keeps only validated values (package name, version, named addresses) and writes a new
`Move.toml` from one fixed template whose dependencies are local paths to the registry packages
read in `chain_state` (07 7.1.4: "the published manifest [dependencies] are rewritten to those
local paths"). RULES.md: no fetched value reaches a tool config file unvalidated.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import PurePosixPath
from typing import Any

from soken_review.adapters.move.units import IDENT_RE, normalize_address

_VERSION_RE = re.compile(r"^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$")
FRAMEWORK_DIR = "/opt/aptos-framework"      # docker/aptos-build, aptos-core at the CLI tag commit
_LANG_RE = re.compile(r"^[0-9]{1,2}\.[0-9]{1,2}$")


class ManifestError(ValueError):
    """The published manifest cannot be turned into a template manifest."""


def parse_manifest(text: str, deployment: str | None) -> dict[str, Any]:
    """Validated subset of a Move.toml: name, version, addresses, language_version."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"manifest is not TOML: {exc}") from exc
    pkg = data.get("package") or {}
    name = pkg.get("name")
    if not isinstance(name, str) or not IDENT_RE.match(name.replace("-", "_")):
        raise ManifestError("bad package name")
    version = pkg.get("version", "0.0.0")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        version = "0.0.0"
    addresses: dict[str, str] = {}
    for key, value in (data.get("addresses") or {}).items():
        if not IDENT_RE.match(str(key)):
            raise ManifestError(f"bad named address {key!r}")
        if value == "_":
            if deployment is None:
                raise ManifestError(f"unassigned named address {key}")
            addresses[key] = deployment
            continue
        addr = normalize_address(str(value))
        if addr is None:
            raise ManifestError(f"bad address value for {key}")
        addresses[key] = addr
    lang = (data.get("build") or {}).get("language_version")
    return {
        "name": name,
        "version": version,
        "addresses": addresses,
        "language_version": lang if isinstance(lang, str) and _LANG_RE.match(lang) else None,
    }


def render_manifest(name: str, version: str, addresses: dict[str, str], deps: dict[str, str]) -> str:
    """The one fixed template (07 4). Every value was validated by the caller or this function."""
    if not IDENT_RE.match(name.replace("-", "_")) or not _VERSION_RE.match(version):
        raise ManifestError("bad template value")
    lines = ["[package]", f'name = "{name}"', f'version = "{version}"', "", "[addresses]"]
    for key in sorted(addresses):
        addr = normalize_address(addresses[key])
        if not IDENT_RE.match(key) or addr is None:
            raise ManifestError("bad template address")
        lines.append(f'{key} = "{addr}"')
    lines += ["", "[dependencies]"]
    for dep in sorted(deps):
        path = deps[dep]
        if not IDENT_RE.match(dep.replace("-", "_")) or not re.match(r"^[A-Za-z0-9_./-]{1,200}$", path):
            raise ManifestError("bad template dependency")
        lines.append(f'{dep} = {{ local = "{path}" }}')
    return "\n".join(lines) + "\n"


def dep_path(dep: dict[str, str], deps_root: str) -> str:
    """Local path for a registry dependency: the image framework copy or `deps/<account>/<name>`."""
    from soken_review.adapters.aptos.chain import FRAMEWORK_ACCOUNTS, FRAMEWORK_PACKAGES

    if dep["account"] in FRAMEWORK_ACCOUNTS and dep["package_name"] in FRAMEWORK_PACKAGES:
        return f"{FRAMEWORK_DIR}/{FRAMEWORK_PACKAGES[dep['package_name']]}"
    return f"{deps_root}/{dep['account']}/{dep['package_name']}"


def registry_manifests(cs: dict[str, Any], unit_names: set[str],
                       account_addr: str | None = None) -> dict[str, str]:
    """Template Move.toml for every unit package and registry dependency, from chain_state.

    Unit package manifests are stored at ``<account_addr>/<Name>/Move.toml`` (matching the
    key layout produced by ``candidate_from_registry``), so that the overlay in ``build.py``
    correctly replaces the original published manifest (which may contain git dependencies that
    cannot be fetched inside the no-network sandbox).

    Registry-dep manifests stay at ``deps/<dep_account>/<Name>/Move.toml`` (unchanged from
    ``candidate_from_registry``).

    Path resolution from a unit manifest at ``<addr>/<PkgName>/Move.toml`` (depth 2):
      - same-account sibling unit: ``../<DepName>``  (up 1 → <addr>/, then down to <DepName>)
      - cross-account registry dep at ``deps/<dep_acc>/<DepName>``: ``../../deps/<dep_acc>/<DepName>``
      - framework dep: absolute path (see dep_path / FRAMEWORK_DIR)
    """
    addr = account_addr or cs.get("address", "")

    def path_for_unit(dep: dict[str, str]) -> str:
        """Path from a unit manifest at addr/PkgName/ to a dependency."""
        if dep["account"] == cs["address"] and dep["package_name"] in unit_names:
            # Same-account sibling: go up 1 from PkgName to addr/, then down to DepName.
            return f"../{dep['package_name']}"
        # Cross-account or framework: go up 2 levels (past PkgName and addr) to tree root.
        return dep_path(dep, "../../deps")

    def path_for_dep(dep: dict[str, str]) -> str:
        """Path from a cross-account dep manifest at deps/acc/Name/ to a dependency."""
        if dep["account"] == cs["address"] and dep["package_name"] in unit_names:
            # Unit package is at addr/DepName/ — go up 3 levels to root then into addr/.
            return f"../../../{addr}/{dep['package_name']}"
        return dep_path(dep, "../../../deps")

    out: dict[str, str] = {}
    for pkg in cs["packages"]:
        if pkg["name"] not in unit_names:
            continue
        info = parse_manifest(pkg["manifest"] or "", cs["address"])
        # Key uses account_addr prefix so it overrides the original manifest in the build tree.
        out[f"{addr}/{pkg['name']}/Move.toml"] = render_manifest(
            info["name"], info["version"], info["addresses"],
            {d["package_name"]: path_for_unit(d) for d in pkg["deps"]})
    for dep in cs["deps"].values():
        if dep["account"] == cs["address"] and dep["name"] in unit_names:
            continue
        info = parse_manifest(dep["manifest"] or "", dep["account"])
        out[f"deps/{dep['account']}/{dep['name']}/Move.toml"] = render_manifest(
            info["name"], info["version"], info["addresses"],
            {d["package_name"]: path_for_dep(d) for d in dep["deps"]})
    return out


def repo_manifest(text: str, package_dir: str, files: set[str], deployment: str | None) -> str:
    """Template Move.toml for a repo or inline package: framework dependencies to the image copy,
    local dependencies kept only when they stay inside the pinned tree, anything else refused."""
    from soken_review.adapters.aptos.chain import FRAMEWORK_PACKAGES
    from soken_review.adapters.move.trust import _norm

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"manifest is not TOML: {exc}") from exc
    info = parse_manifest(text, deployment)
    deps: dict[str, str] = {}
    for name, dep in (data.get("dependencies") or {}).items():
        if name in FRAMEWORK_PACKAGES:
            deps[name] = f"{FRAMEWORK_DIR}/{FRAMEWORK_PACKAGES[name]}"
            continue
        local = dep.get("local") if isinstance(dep, dict) else None
        if isinstance(local, str):
            target = _norm(PurePosixPath(package_dir) / local)
            if target is None or f"{target}/Move.toml".removeprefix("./") not in files:
                raise ManifestError(f"local dependency {name} outside the pinned tree")
            deps[name] = local
            continue
        raise ManifestError(f"dependency {name} is not a framework or local package (deps_unreachable)")
    return render_manifest(info["name"], info["version"], info["addresses"], deps)


def inline_manifest(named: dict[str, str]) -> str:
    from soken_review.adapters.aptos.chain import FRAMEWORK_PACKAGES

    deps = {n: f"{FRAMEWORK_DIR}/{FRAMEWORK_PACKAGES[n]}" for n in ("MoveStdlib", "AptosStdlib", "AptosFramework")}
    addresses = {"std": "0x1", "aptos_std": "0x1", "aptos_framework": "0x1", **named}
    return render_manifest("inline", "0.0.0", addresses, deps)
