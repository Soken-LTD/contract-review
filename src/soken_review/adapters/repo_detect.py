"""Family of a repository that holds no Solidity: Scarb (Starknet) or Move (Sui / Aptos).

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


@dataclass(frozen=True)
class RepoFamily:
    chain: str              # "starknet" | "sui" | "aptos"
    package_dir: str        # store path of the package ("" = tree root)
    manifest: str           # store path of the manifest the decision came from


@dataclass(frozen=True)
class Undetected:
    reason: str             # "no_manifest" | "unknown_move_flavour" | "ambiguous_package"
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
    edition = str((manifest.get("package") or {}).get("edition", "")).lower()
    if not votes and edition.startswith("2024"):
        return "sui"            # Move 2024 editions are Sui's; Aptos packages carry no edition
    return None


def detect_repo_family(files: dict[str, str], subdir: str | None = None) -> RepoFamily | Undetected:
    """Decide the family of a fetched tree (`files`: store path -> text, as the materialiser and
    `safe_read_repo_tree` return it)."""
    scarb = _manifests(files, "Scarb.toml")
    if scarb:
        pkg = _pick_package_dir(files, scarb, subdir, workspace_key="workspace")
        if pkg is None and (subdir or "").strip("/"):
            return Undetected("ambiguous_package", tuple(scarb))
        pkg = pkg or ""
        manifest = next((m for m in scarb if _dir_of(m) == pkg), scarb[0])
        return RepoFamily("starknet", pkg, manifest)
    move = _manifests(files, "Move.toml")
    if not move:
        return Undetected("no_manifest")
    pkg = _pick_package_dir(files, move, subdir, workspace_key=None)
    if pkg is None:
        return Undetected("ambiguous_package", tuple(move))
    manifest = next(m for m in move if _dir_of(m) == pkg)
    flavour = _move_flavour(_toml(files[manifest]))
    if flavour is None:
        return Undetected("unknown_move_flavour", (manifest,))
    return RepoFamily(flavour, pkg, manifest)
