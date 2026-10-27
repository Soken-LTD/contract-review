"""Build scope for repo candidates: the compilation closure of the reviewed entry contracts and
the exclusion of a file that does not compile when nothing reviewed imports it.

Lambo.win run 2026-10-27 (code-423n4/2024-12-lambowin, Foundry, src/): the build compiled every
file under src/, and the vendored, unused `src/libraries/1inchV6.sol` (`pragma solidity 0.8.23`,
6018 lines) failed it with ParserError at 0.8.24. No map, no analyzers, 0 leads, and the report
subject came out as "1inchV6". A file in the tree that nothing reviewed imports must not break
the build of the reviewed contracts.

The supervisor build step (worker/supervisor.py) uses these helpers after the full build failed:

  1. closure: the scope files that define a deployable contract (a non-abstract `contract`),
     plus every scope file their imports reach; dependencies (lib/, node_modules/) come in
     through the build's own import closure as before.
  2. exclusion: the files the compiler names in its errors, plus the files whose own pragma the
     chosen release does not satisfy, leave the build with reason `build_excluded`, unless a
     remaining file imports one of them (then the build fails as before: reviewed code depends
     on it).

Pure functions over {path: text}; nothing here reads the disk.
"""

from __future__ import annotations

import re
from typing import Any

from soken_review.adapters.evm.files import PRAGMA, satisfies

# Reason code of a file the build left out (report kit `scope_reasons`).
BUILD_EXCLUDED = "build_excluded"

_COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_STRINGS = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'')
# `contract Name` at a statement start; `abstract contract` does not match (preceded by a word).
_CONTRACT_DEF = re.compile(r"(?:^|[;}])\s*contract\s+([A-Za-z_$][A-Za-z0-9_$]*)", re.MULTILINE)
_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def strip_comments(text: str) -> str:
    """Solidity text without comments and string literals (so a `contract` in a comment or a
    string does not count)."""
    return _COMMENTS.sub(" ", _STRINGS.sub('""', text))


def deployable_contracts(text: str) -> list[str]:
    """Names of the non-abstract contracts a Solidity file defines (no libraries, interfaces)."""
    return _CONTRACT_DEF.findall(strip_comments(text))


def deployable_roots(scope: dict[str, str]) -> list[str]:
    """Scope files that define at least one deployable contract, sorted."""
    return sorted(p for p, t in scope.items() if p.endswith(".sol") and deployable_contracts(t))


def _reach(start: list[str], tree: dict[str, str], remappings: list[str]) -> set[str]:
    from soken_review.adapters.evm.npm_deps import import_closure

    visited, _missing = import_closure(start, tree, list(remappings or []), node_modules=True, forge_libs=True)
    return visited


def closure_files(scope: dict[str, str], tree: dict[str, str] | None, remappings: list[str]) -> dict[str, str]:
    """The scope files the build of the deployable entry contracts needs: the roots plus every
    scope file their imports reach. The whole scope when no file defines a deployable contract
    (a library-only or interface-only scope is reviewed as it is)."""
    roots = deployable_roots(scope)
    if not roots:
        return dict(scope)
    lookup = {**(tree or {}), **scope}
    reached = _reach(roots, lookup, remappings)
    return {p: scope[p] for p in scope if p in reached}


def _version(version: str | None) -> tuple[int, int, int] | None:
    m = _VERSION.match((version or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def pragma_conflicts(files: dict[str, str], version: str | None) -> set[str]:
    """Files whose own `pragma solidity` the release `version` does not satisfy."""
    v = _version(version)
    if v is None:
        return set()
    out: set[str] = set()
    for path, text in files.items():
        for m in PRAGMA.finditer(text[:8192]):
            if not satisfies(m.group(1).strip(), v):
                out.add(path)
                break
    return out


def failing_files(build_notes: dict[str, Any] | None, files: dict[str, str], version: str | None) -> set[str]:
    """Build files a failed compile points at: the files named in the compiler's error source
    locations (`error_sources` build note) and the files whose pragma the release does not
    satisfy. Only paths of `files` count (a dependency is never excluded this way)."""
    named = {str(p) for p in ((build_notes or {}).get("error_sources") or [])}
    return ({p for p in named if p in files} | pragma_conflicts(files, version))


def plan_exclusion(files: dict[str, str], failing: set[str], tree: dict[str, str] | None,
                   remappings: list[str]) -> tuple[dict[str, str], list[str]] | None:
    """(kept files, excluded paths) when every failing file can leave the build, else None.

    None when there is nothing to exclude, when nothing would remain, or when a remaining file
    imports a failing one directly or through other files (reviewed code depends on it, so the
    build must not go on without it)."""
    failing = {p for p in failing if p in files}
    if not failing:
        return None
    kept = {p: t for p, t in files.items() if p not in failing}
    if not kept:
        return None
    lookup = {**(tree or {}), **files}
    if _reach(sorted(kept), lookup, remappings) & failing:
        return None
    return kept, sorted(failing)


def subject_unit(scope: dict[str, str], excluded: set[str] | frozenset[str] = frozenset()) -> str | None:
    """Path of the main deployable unit of a scope: the largest file defining a deployable
    contract, files under a library or interface directory last; None when no file defines one.

    Lambo.win 2026-10-27: the largest scope file was a vendored library bundle (1inchV6.sol),
    which became the report subject."""
    rows = []
    for path, text in scope.items():
        if path in excluded or not path.endswith(".sol") or not deployable_contracts(text):
            continue
        dirs = {seg.lower() for seg in path.split("/")[:-1]}
        vendored = bool(dirs & {"libraries", "library", "lib", "libs", "interfaces", "interface", "vendor",
                                "vendored", "external", "utils", "util"})
        rows.append((vendored, -len(strip_comments(text).split("\n")), path))
    return min(rows)[2] if rows else None
