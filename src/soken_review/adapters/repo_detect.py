"""Family of a repository that holds no Solidity: Scarb (Starknet), Move (Sui / Aptos), Solana, TON.

A repo-only job carries no chain (`review_start` sets `chain` from `deployment` only), so the
supervisor materialises it on the EVM path and asks `repo_candidate_from_manifest` for a Foundry
candidate. When that answers `no_solidity_sources`, the supervisor calls `detect_repo_family` on
the fetched tree and hands the same fetch step to the family runner (plan-v4 07 for Starknet,
07 section 4 for Move) instead of ending the job in `insufficient_source`.

Rules (reference data, not heuristics on code):
  * `Scarb.toml` anywhere outside dependency/build dirs: Starknet. The package dir is the
    requested `subdir` when it holds a manifest, else the shallowest manifest dir (a workspace
    root wins over its members; several roots at the same depth: the tree root, every member
    stays in scope through `in_scope_paths`).
  * `Move.toml` (and no Scarb): Sui or Aptos from the manifest's `[dependencies]`: a dependency
    named `Sui` / `SuiFramework` / `Bridge` / `DeepBook` or pointing at MystenLabs' repository is
    Sui; `AptosFramework` / `AptosStdlib` / `AptosToken*` / `MoveStdlib` from aptos-core is Aptos.
    A manifest that names neither (or both) is `unknown_move_flavour`; several packages without a
    `subdir` to choose from is `ambiguous_package`. Both end the job with that detail.
  * `Anchor.toml`, or a `Cargo.toml` whose dependencies name a Solana program crate
    (`anchor-lang`, `solana-program`, `pinocchio`, ...): Solana. The package dir is the requested
    `subdir`, else the one program crate, else the Anchor workspace root.
  * TON sources (`*.fc`, `*.func`, `*.tolk`, `*.tact`) or a `tact.config.json`: TON (a Blueprint
    project keeps them under contracts/). The package dir is the requested `subdir` (it must hold
    TON sources), else the tree root.
  * Solidity or Vyper sources, `foundry.toml`, `hardhat.config.*`: EVM (the supervisor reaches
    detection only after the EVM candidate failed, so this answer names the family for the client).

`family` (review_start `source.chain` in repo mode, mapped to its family) overrides detection: only
that family's rule runs, and a tree without its sources is `no_<family>_sources`.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath

_SKIP_DIRS = frozenset({".git", "node_modules", "deps", "target", "build", "out", ".scarb", ".move", "vendor"})
_SUI_DEP_NAMES = frozenset({"sui", "suiframework", "sui_framework", "bridge", "deepbook", "suisystem", "sui_system"})
_APTOS_DEP_NAMES = frozenset({"aptosframework", "aptosstdlib", "aptostoken", "aptostokenobjects", "aptos_framework",
                              "aptos_std", "aptos_token", "aptos_token_objects"})
_SUI_REPO_MARKERS = ("mystenlabs/sui", "/sui.git")
_APTOS_REPO_MARKERS = ("aptos-labs/aptos-core", "aptos-labs/aptos-framework")
_MAX_MANIFEST_BYTES = 64 * 1024


_SOLANA_DEP_NAMES = frozenset({"anchor-lang", "anchor_lang", "solana-program", "solana_program", "pinocchio",
                               "solana-sdk", "solana_sdk", "steel", "nitrogen"})
_TON_SOURCE_EXTS = (".fc", ".func", ".tolk", ".tact")
_TON_CONFIGS = frozenset({"tact.config.json"})
_EVM_SOURCE_EXTS = (".sol", ".vy")
_EVM_CONFIGS = frozenset({"foundry.toml", "hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs",
                          "hardhat.config.mjs", "truffle-config.js"})
# review_start `source.chain` -> the family whose rule runs (repo mode)
FAMILY_OF_HINT = {"ton": "ton", "solana": "solana", "sui": "sui", "aptos": "aptos", "starknet": "starknet",
                  "evm": "evm", "hyperevm": "evm", "tron": "evm"}


@dataclass(frozen=True)
class RepoFamily:
    chain: str              # "starknet" | "sui" | "aptos" | "solana" | "ton" | "evm"
    package_dir: str        # store path of the package ("" = tree root)
    manifest: str           # store path of the manifest the decision came from


@dataclass(frozen=True)
class Undetected:
    reason: str             # "no_manifest" | "unknown_move_flavour" | "ambiguous_package" | "no_<family>_sources"
    manifests: tuple[str, ...] = ()


def _in_skipped_dir(path: str) -> bool:
    return any(part in _SKIP_DIRS or part.startswith(".") for part in PurePosixPath(path).parts[:-1])


def _manifests(files: dict[str, str], name: str) -> list[str]:
    return sorted(p for p in files if PurePosixPath(p).name == name and not _in_skipped_dir(p))


def _dir_of(path: str) -> str:
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def _depth(path: str) -> int:
    return len(PurePosixPath(path).parts) - 1


def _toml(text: str) -> dict:
    if len(text.encode("utf-8", errors="replace")) > _MAX_MANIFEST_BYTES:
        return {}
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}


def _pick_package_dir(files: dict[str, str], manifests: list[str], subdir: str | None,
                      workspace_key: str | None) -> str | None:
    """`subdir` with a manifest wins; else one manifest; else the shallowest (a workspace root
    first); several at the same depth without a workspace: None."""
    wanted = (subdir or "").strip("/")
    if wanted:
        return wanted if any(_dir_of(m) == wanted for m in manifests) else None
    if len(manifests) == 1:
        return _dir_of(manifests[0])
    if workspace_key:
        roots = [m for m in manifests if workspace_key in _toml(files[m])]
        if len(roots) == 1:
            return _dir_of(roots[0])
    shallowest = min(_depth(m) for m in manifests)
    top = [m for m in manifests if _depth(m) == shallowest]
    return _dir_of(top[0]) if len(top) == 1 else None


def _move_flavour(manifest: dict) -> str | None:
    deps = manifest.get("dependencies") or {}
    if not isinstance(deps, dict):
        return None
    votes: set[str] = set()
    for name, spec in deps.items():
        key = str(name).replace("-", "").lower()
        git = str(spec.get("git", "")).lower() if isinstance(spec, dict) else ""
        if key in _SUI_DEP_NAMES or any(m in git for m in _SUI_REPO_MARKERS):
            votes.add("sui")
        if key in _APTOS_DEP_NAMES or any(m in git for m in _APTOS_REPO_MARKERS):
            votes.add("aptos")
        if key == "movestdlib" and git and "aptos" in git:
            votes.add("aptos")
    if len(votes) == 1:
        return votes.pop()
    package = manifest.get("package")
    edition = str(package.get("edition", "")).lower() if isinstance(package, dict) else ""
    if not votes and edition.startswith("2024"):
        return "sui"            # Move 2024 editions are Sui's; Aptos packages carry no edition
    return None


def _under(path: str, wanted: str) -> bool:
    return not wanted or path.startswith(wanted + "/")


def _detect_starknet(files: dict[str, str], subdir: str | None) -> RepoFamily | Undetected | None:
    scarb = _manifests(files, "Scarb.toml")
    if not scarb:
        return None
    pkg = _pick_package_dir(files, scarb, subdir, workspace_key="workspace")
    if pkg is None and (subdir or "").strip("/"):
        return Undetected("ambiguous_package", tuple(scarb))
    pkg = pkg or ""
    manifest = next((m for m in scarb if _dir_of(m) == pkg), scarb[0])
    return RepoFamily("starknet", pkg, manifest)


def _detect_move(files: dict[str, str], subdir: str | None, forced: str | None = None) -> RepoFamily | Undetected | None:
    move = _manifests(files, "Move.toml")
    if not move:
        return None
    pkg = _pick_package_dir(files, move, subdir, workspace_key=None)
    if pkg is None:
        return Undetected("ambiguous_package", tuple(move))
    manifest = next(m for m in move if _dir_of(m) == pkg)
    flavour = _move_flavour(_toml(files[manifest])) or forced
    if flavour is None:
        return Undetected("unknown_move_flavour", (manifest,))
    return RepoFamily(flavour, pkg, manifest)


def _solana_crate(manifest: dict) -> bool:
    for key in ("dependencies", "dev-dependencies"):
        deps = manifest.get(key) or {}
        if isinstance(deps, dict) and any(str(n).lower() in _SOLANA_DEP_NAMES for n in deps):
            return True
    workspace = manifest.get("workspace")
    deps = workspace.get("dependencies") if isinstance(workspace, dict) else None
    return isinstance(deps, dict) and any(str(n).lower() in _SOLANA_DEP_NAMES for n in deps)


def _crate_types(manifest: dict) -> list[str]:
    lib = manifest.get("lib")
    types = lib.get("crate-type") if isinstance(lib, dict) else None
    return [str(t) for t in types] if isinstance(types, list) else []


def _detect_solana(files: dict[str, str], subdir: str | None) -> RepoFamily | None:
    wanted = (subdir or "").strip("/")
    anchors = [m for m in _manifests(files, "Anchor.toml") if _under(m, wanted) or _dir_of(m) == wanted]
    cargo = [m for m in _manifests(files, "Cargo.toml") if _under(m, wanted) or _dir_of(m) == wanted]
    crates = [m for m in cargo if _solana_crate(_toml(files[m]))]
    if not anchors and not crates:
        return None
    if wanted:
        manifest = next((m for m in [*anchors, *crates] if _dir_of(m) == wanted), (anchors or crates)[0])
        return RepoFamily("solana", wanted, manifest)
    programs = [m for m in crates if "workspace" not in _toml(files[m])]
    if len(programs) > 1:
        # a workspace with a program and a client crate (Pump Science: programs/pump-science and
        # clients/rust): the program is the cdylib, else the crate under programs/
        cdylib = [m for m in programs if "cdylib" in _crate_types(_toml(files[m]))]
        programs = cdylib or programs
    if len(programs) > 1:
        programs = [m for m in programs if m.startswith("programs/")] or programs
    if len(programs) == 1:
        return RepoFamily("solana", _dir_of(programs[0]), programs[0])
    root = min(anchors or crates, key=_depth)
    return RepoFamily("solana", _dir_of(root), root)


def _detect_ton(files: dict[str, str], subdir: str | None) -> RepoFamily | None:
    wanted = (subdir or "").strip("/")
    sources = sorted(p for p in files if not _in_skipped_dir(p) and _under(p, wanted)
                     and (p.lower().endswith(_TON_SOURCE_EXTS) or PurePosixPath(p).name in _TON_CONFIGS))
    if not sources:
        return None
    return RepoFamily("ton", wanted, sources[0])


def _detect_evm(files: dict[str, str], subdir: str | None) -> RepoFamily | None:
    wanted = (subdir or "").strip("/")
    hits = sorted(p for p in files if not _in_skipped_dir(p) and _under(p, wanted)
                  and (p.lower().endswith(_EVM_SOURCE_EXTS) or PurePosixPath(p).name in _EVM_CONFIGS))
    return RepoFamily("evm", wanted, hits[0]) if hits else None


def detect_repo_family(files: dict[str, str], subdir: str | None = None,
                       family: str | None = None) -> RepoFamily | Undetected:
    """Decide the family of a fetched tree (`files`: store path -> text, as the materialiser and
    `safe_read_repo_tree` return it). `family` (a FAMILY_OF_HINT value) runs that rule only."""
    if family is not None:
        if family == "starknet":
            found = _detect_starknet(files, subdir)
        elif family in ("sui", "aptos"):
            found = _detect_move(files, subdir, forced=family)
            if isinstance(found, RepoFamily) and found.chain != family:
                found = RepoFamily(family, found.package_dir, found.manifest)   # the requester names the chain
        elif family == "solana":
            found = _detect_solana(files, subdir)
        elif family == "ton":
            found = _detect_ton(files, subdir)
        else:
            found = _detect_evm(files, subdir)
        return found if found is not None else Undetected(f"no_{family}_sources")
    for rule in (_detect_starknet, _detect_move):
        found = rule(files, subdir)
        if found is not None:
            return found
    for rule in (_detect_solana, _detect_ton, _detect_evm):
        found = rule(files, subdir)
        if found is not None:
            return found
    return Undetected("no_manifest")
