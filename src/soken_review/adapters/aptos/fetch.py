"""Aptos source intake (plan v4 07 section 7.1).

Source used, in order: user repo and commit; else the decompressed on-chain source of every
registry package (07 7.1.3: publisher-supplied metadata, tier A needs the byte compare of 7.2);
else tier D. Inline files (language `move_aptos`) are a third input (07 4).

Candidate layout (store paths = build paths, so diagnostics map back without guessing):
  <Package>/Move.toml, <Package>/sources/*.move      each unit package (registry case)
  deps/<account>/<Package>/...                        registry dependencies (not in scope)
  <repo tree>                                         repo case, settings.package_dir names the unit
"""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.move import gitfetch
from soken_review.adapters.move.units import IDENT_RE, candidate_sha256, normalize_address, safe_store_path

_MODULE_ADDR_RE = re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_]*)\s*::")
INLINE_PLACEHOLDER = "0xcafe"            # 07 4: Aptos one fixed placeholder address
_FRAMEWORK_NAMED = {"std", "aptos_std", "aptos_framework", "aptos_token", "aptos_token_objects", "aptos_fungible_asset"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _compiler(cs: dict[str, Any]) -> Compiler | None:
    """Compiler/language from on-chain compilation_metadata of the first module that has it."""
    from soken_review.adapters.move.bytecode import BytecodeError, aptos_compilation_metadata, parse_module

    for code in cs.get("module_bytecode", {}).values():
        try:
            meta = aptos_compilation_metadata(parse_module(bytes.fromhex(code.removeprefix("0x")), "aptos"))
        except (BytecodeError, ValueError):
            continue
        if meta:
            return Compiler(version=f"compiler {meta['compiler_version']} language {meta['language_version']}",
                            version_pinned_by="metadata")
    return None


def candidate_from_registry(cs: dict[str, Any], chain_state_file: str | None) -> Candidate | None:
    """One candidate holding every registry package of the account that has source (07 7.1.1).

    Store-path layout: ``<account_addr>/<PackageName>/Move.toml`` and
    ``<account_addr>/<PackageName>/sources/<Module>.move``.  Including the account address in
    the prefix guarantees that packages from different addresses (e.g. a target and a dep that
    share a name) land on distinct paths.  A collision — two packages that resolve to the same
    store path — rejects the whole job (fail closed) so the reviewed tree always matches the
    compiled tree exactly (security fix: path namespace collision).
    """
    account_addr = normalize_address(cs["address"])
    if account_addr is None:
        raise ValueError(f"invalid account address: {cs['address']!r}")

    files: dict[str, str] = {}
    units, without = [], []
    for pkg in cs["packages"]:
        if pkg["manifest"] is None or not pkg["modules"] or any(m["source"] is None for m in pkg["modules"]):
            without.append(pkg["name"])
            continue
        # Validate names as Move identifiers: single path component, no ``/`` or ``..``.
        if not IDENT_RE.match(pkg["name"]):
            raise ValueError(f"unsafe package name: {pkg['name']!r}")
        prefix = f"{account_addr}/{pkg['name']}"
        manifest_key = f"{prefix}/Move.toml"
        if manifest_key in files:
            raise ValueError(f"store path collision: {manifest_key!r}")
        files[manifest_key] = pkg["manifest"]
        for m in pkg["modules"]:
            if not IDENT_RE.match(m["name"]):
                raise ValueError(f"unsafe module name: {m['name']!r}")
            mod_key = f"{prefix}/sources/{m['name']}.move"
            if mod_key in files:
                raise ValueError(f"store path collision: {mod_key!r}")
            files[mod_key] = m["source"]
        units.append({"name": pkg["name"], "dir": prefix, "modules": [m["name"] for m in pkg["modules"]],
                      "upgrade_policy": pkg["upgrade_policy"], "upgrade_number": pkg["upgrade_number"]})
    if not units:
        return None
    for key, dep in sorted(cs["deps"].items()):
        if dep["account"] == cs["address"] and dep["name"] in {u["name"] for u in units}:
            continue                                  # a unit of this account, already present
        prefix = f"deps/{dep['account']}/{dep['name']}"
        files[f"{prefix}/Move.toml"] = dep["manifest"]
        for m in dep["modules"]:
            files[f"{prefix}/sources/{m['name']}.move"] = m["source"]
    return Candidate(
        provider="aptos_registry",  # type: ignore[arg-type]  # base.Provider lacks Move providers (W0 finding)
        files=files, sha256=candidate_sha256(files), language="move_aptos", compiler=_compiler(cs),
        settings={"chain": "aptos", "kind": "registry", "address": cs["address"], "ledger_version": cs["ledger_version"],
                  "units": units, "units_without_source": without, "chain_state_file": chain_state_file},
        std_json_input=None, entry_contract=None, fetched_at=_now(),
    )


def find_package_dir(files: dict[str, str], name: str | None) -> str | None:
    """Directory of the Move.toml whose [package] name is `name` (or the only one when None)."""
    dirs = []
    for path, text in files.items():
        if PurePosixPath(path).name != "Move.toml" or path.startswith("deps/"):
            continue
        try:
            pname = (tomllib.loads(text).get("package") or {}).get("name")
        except tomllib.TOMLDecodeError:
            continue
        if name is None or pname == name:
            dirs.append(str(PurePosixPath(path).parent))
    return dirs[0] if len(dirs) == 1 else None


def candidate_from_repo(repo_url: str, commit: str, work: Path, package: str | None,
                        cs: dict[str, Any] | None, chain_state_file: str | None,
                        package_dir: str | None = None) -> Candidate:
    """User repo at commit (07 7.1.3). With an address, the unit is the package the manifest names;
    a name absent from the registry is not_checkable package_not_found (07 7.1.1). `package_dir`
    (the request's `subdir`, or the directory repo detection chose) names the package directly
    when the repository holds several."""
    files, resolved = gitfetch.fetch_repo(repo_url, commit, work)
    wanted = (package_dir or "").strip("/")
    if wanted and wanted != "." and f"{wanted}/Move.toml" in files:
        pkg_dir = wanted
    else:
        pkg_dir = find_package_dir(files, package)
    if pkg_dir is None:
        raise gitfetch.FetchError("package manifest not found in repository")
    name = tomllib.loads(files[f"{pkg_dir}/Move.toml" if pkg_dir != "." else "Move.toml"])["package"]["name"]
    registry = next((p for p in (cs or {}).get("packages", []) if p["name"] == name), None)
    return Candidate(
        provider="repo", files=files, sha256=candidate_sha256(files), language="move_aptos",
        compiler=_compiler(cs) if cs else None,
        settings={"chain": "aptos", "kind": "repo", "address": (cs or {}).get("address"),
                  "ledger_version": (cs or {}).get("ledger_version"), "repo_url": repo_url, "commit": resolved,
                  "units": [{"name": name, "dir": pkg_dir,
                             "modules": [m["name"] for m in registry["modules"]] if registry else None,
                             "upgrade_policy": registry["upgrade_policy"] if registry else None,
                             "upgrade_number": registry["upgrade_number"] if registry else None}],
                  "package_not_found": bool(cs) and registry is None, "chain_state_file": chain_state_file},
        std_json_input=None, entry_contract=None, source_url=repo_url, fetched_at=_now(),
    )


def candidate_from_inline(files: dict[str, str]) -> Candidate:
    """Inline `move_aptos` files (07 4): sources only; the manifest comes from the fixed template
    with one placeholder address for every non-framework named address."""
    clean: dict[str, str] = {}
    for path, text in files.items():
        norm = safe_store_path(path)
        if norm is None or not norm.endswith(".move"):
            continue
        clean[norm if norm.startswith("sources/") else f"sources/{PurePosixPath(norm).name}"] = text
    named = sorted({m for t in clean.values() for m in _MODULE_ADDR_RE.findall(t)} - _FRAMEWORK_NAMED)
    return Candidate(
        provider="user", files=clean, sha256=candidate_sha256(clean), language="move_aptos", compiler=None,
        settings={"chain": "aptos", "kind": "inline", "address": None,
                  "units": [{"name": "inline", "dir": ".", "modules": None}],
                  "named_addresses": {n: INLINE_PLACEHOLDER for n in named}},
        std_json_input=None, entry_contract=None, fetched_at=_now(),
    )
