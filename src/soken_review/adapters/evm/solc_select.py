"""solc version choice for repo and files sources (held-out friction 2026-10-27, 1inch farming).

Order (05 6.1 config row first, then the pragma rule):
  1. an exact version pinned by the project config: foundry.toml `solc`/`solc_version`,
     hardhat.config.{js,cjs,mjs,ts} `solidity: "x.y.z"`, `solidity.version`, `solidity.compilers[].version`
     (the newest that satisfies every pragma, else the newest), truffle-config.js / truffle.js
     `compilers.solc.version`           -> version_pinned_by "config"
  2. the newest release that satisfies every `pragma solidity` of the reviewed files AND of the
     files they import (the import closure over the repo tree with its remappings)
                                       -> version_pinned_by "pragma"
  3. the pragma floor, only when the release list is unavailable
                                       -> version_pinned_by "pragma_guess"

`^0.8.0` with custom errors parsed at the floor (0.8.0) and failed; the newest satisfying release
is what the project's own toolchain would pick. Config texts are matched with regexes only; no
JavaScript is evaluated.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from soken_review.adapters.evm.files import PRAGMA, satisfies

logger = logging.getLogger(__name__)

_EXACT = re.compile(r"^v?(\d+\.\d+\.\d+)$")
_HARDHAT_NAMES = ("hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts")
_TRUFFLE_NAMES = ("truffle-config.js", "truffle.js")
# solidity: "0.8.17"  |  solidity: { version: "0.8.17", ... }  |  compilers: [{ version: "0.8.17" }, ...]
_HH_STRING = re.compile(r"\bsolidity\s*:\s*['\"]v?(\d+\.\d+\.\d+)['\"]")
_HH_BLOCK = re.compile(r"\bsolidity\s*:\s*\{(.{0,4000}?)\}\s*,?\s*\n", re.DOTALL)
_HH_VERSION = re.compile(r"\bversion\s*:\s*['\"]v?(\d+\.\d+\.\d+)['\"]")
_TRUFFLE_SOLC = re.compile(r"\bsolc\s*:\s*\{(.{0,2000}?)\bversion\s*:\s*['\"]v?(\d+\.\d+\.\d+)['\"]", re.DOTALL)
_PINNED_BY_TEXT = {
    "config": "project config pin (foundry.toml, hardhat.config or truffle-config)",
    "pragma": "newest release satisfying every pragma of the reviewed files and their imports",
    "pragma_guess": "pragma floor (compiler release list unavailable)",
    "user": "compiler_version given with the files",
    "sourcify": "Sourcify metadata", "eth_bytecode_db": "eth-bytecode-db record", "ipfs": "metadata on IPFS",
    "metadata": "contract metadata", "std_json": "explorer Standard JSON", "cbor": "CBOR metadata hash",
    "tronscan": "Tronscan record", "lock": "lockfile", "sierra_program": "Sierra program version",
}

Version = tuple[int, int, int]


def pinned_by_text(pinned_by: str | None) -> str:
    """Client-facing name of a `version_pinned_by` value (review_facts compiler.version source)."""
    return _PINNED_BY_TEXT.get(pinned_by or "", pinned_by or "unknown")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def config_versions(files: dict[str, str]) -> list[tuple[str, str]]:
    """Exact versions a project config pins, as (version, config file). Ranges are ignored.

    Only the top-level config (no slash in the path) of each kind counts; a nested package's
    config is not the build of the reviewed tree."""
    out: list[tuple[str, str]] = []
    for path, text in files.items():
        if "/" in path or not isinstance(text, str):
            continue
        name = _basename(path)
        head = text[:200_000]
        if name in _HARDHAT_NAMES:
            m = _HH_STRING.search(head)
            if m:
                out.append((m.group(1), name))
                continue
            block = _HH_BLOCK.search(head)
            if block:
                for v in _HH_VERSION.findall(block.group(1)):
                    out.append((v, name))
        elif name in _TRUFFLE_NAMES:
            m = _TRUFFLE_SOLC.search(head)
            if m:
                out.append((m.group(2), name))
    return out


def pragma_exprs(sources: dict[str, str]) -> list[str]:
    """Every `pragma solidity` expression of `sources` (duplicates kept; order by path)."""
    return [m.group(1).strip() for _, text in sorted(sources.items()) for m in PRAGMA.finditer(text[:8192])]


def closure_sources(scope: dict[str, str], tree: dict[str, str] | None, remappings: list[str]) -> dict[str, str]:
    """`scope` plus every tree file its imports reach (dependencies included)."""
    if not tree:
        return dict(scope)
    from soken_review.adapters.evm.npm_deps import import_closure

    visited, _missing = import_closure(list(scope), tree, list(remappings or []), node_modules=True, forge_libs=True)
    out = dict(scope)
    for path in visited:
        if path not in out and path in tree:
            out[path] = tree[path]
    return out


def _releases(builds: list[dict[str, Any]]) -> list[tuple[Version, str]]:
    releases: list[tuple[Version, str]] = []
    for b in builds or []:
        if b.get("prerelease"):
            continue
        try:
            v = tuple(int(x) for x in str(b["version"]).split("."))
        except (KeyError, ValueError):
            continue
        if len(v) == 3:
            releases.append((v, b.get("longVersion") or b["version"]))  # type: ignore[arg-type]
    return sorted(releases, reverse=True)


def newest_satisfying(exprs: list[str], builds: list[dict[str, Any]]) -> str | None:
    """Newest release (no prerelease) satisfying every expression; long version string or None."""
    for v, long_version in _releases(builds):
        if all(satisfies(e, v) for e in exprs):
            return long_version
    return None


def version_satisfies_all(version: str, exprs: list[str]) -> bool:
    m = _EXACT.match(version.split("+", 1)[0])
    if not m:
        return False
    v = tuple(int(x) for x in m.group(1).split("."))
    return all(satisfies(e, v) for e in exprs)  # type: ignore[arg-type]


def floor_version(exprs: list[str]) -> str | None:
    """Highest version literal named by the pragmas (the old pragma_guess): the floor of `^x.y.z`."""
    versions: list[Version] = []
    for e in exprs:
        for m in re.finditer(r"(\d+)\.(\d+)\.(\d+)", e):
            versions.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
    if not versions:
        return None
    return ".".join(str(x) for x in max(versions))


def load_builds() -> list[dict[str, Any]] | None:
    """The solc release list of the compiler cache, or None when it cannot be read."""
    try:
        from soken_review.adapters.evm.compiler import get_cache

        return list(get_cache()._load_list().get("builds") or [])
    except Exception as exc:  # noqa: BLE001  # offline cache miss: fall back to the pragma floor
        logger.info("solc release list unavailable (%s); pragma floor only", type(exc).__name__)
        return None


def pick_config_version(config: list[tuple[str, str]], exprs: list[str]) -> tuple[str, str] | None:
    """Among the config-pinned versions, the newest that satisfies every pragma; else the newest."""
    if not config:
        return None
    exact = [(v, src) for v, src in config if _EXACT.match(v)]
    if not exact:
        return None

    def key(item: tuple[str, str]) -> Version:
        return tuple(int(x) for x in item[0].split("."))  # type: ignore[return-value]

    fitting = [c for c in exact if version_satisfies_all(c[0], exprs)]
    return max(fitting or exact, key=key)


def choose_pragma_version(exprs: list[str], builds: list[dict[str, Any]] | None) -> tuple[str, str] | None:
    """(version, version_pinned_by) from the pragmas: newest satisfying release, else the floor."""
    if not exprs:
        return None
    if builds:
        v = newest_satisfying(exprs, builds)
        if v:
            return v, "pragma"
    floor = floor_version(exprs)
    return (floor, "pragma_guess") if floor else None


def is_parse_error(stderr_head: str | None) -> bool:
    """A compile failure that a newer release of the same pragma range may fix (syntax the chosen
    release does not know: custom errors before 0.8.4, user-defined types, `unchecked`, ...)."""
    text = stderr_head or ""
    return bool(re.search(r"\b(ParserError|SyntaxError)\b", text))
