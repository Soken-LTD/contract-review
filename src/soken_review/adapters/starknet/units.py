"""Cairo review scope and nSLOC (07 4).

Scope = every `.cairo` file of the package reachable from `<package>/src/lib.cairo` through `mod x;`
declarations, except modules gated by `#[cfg(test)]`. No name-based exclusion: a `mocks/` or
`test_*.cairo` file compiled into the class through a plain `mod` is production code and in scope.
When the mod tree cannot be resolved (no lib.cairo, a declared module file missing), every
`.cairo` file of the package is in scope (fail open toward review).
"""

from __future__ import annotations

import posixpath
import re

from soken_review.adapters.starknet.source import attrs_before as _attrs_before
from soken_review.adapters.starknet.source import blank_comments_strings

_MOD_RE = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*([;{])")


def _is_test_gated(attrs: list[str]) -> bool:
    return any(a == "#[cfg(test)]" for a in attrs)


def _children(text: str, child_dir: str) -> list[str]:
    """Files declared by `mod x;` in a module file whose children live in `child_dir`.

    Inline `mod a { ... }` blocks nest the directory (child_dir/a/) and pass on cfg(test) gating.
    """
    blank = blank_comments_strings(text)
    inline_open: dict[int, tuple[str, bool]] = {}     # position of `{` -> (dir, gated)
    mods = {m.start(): m for m in _MOD_RE.finditer(blank)}
    out: list[str] = []
    stack: list[tuple[int, str, bool]] = []            # (depth, dir, gated) of open inline mods
    depth = 0
    for i, c in enumerate(blank):
        m = mods.get(i)
        if m is not None:
            cur_dir, cur_gated = (stack[-1][1], stack[-1][2]) if stack else (child_dir, False)
            gated = cur_gated or _is_test_gated(_attrs_before(blank, i))
            name = m.group(1)
            if m.group(2) == ";":
                if not gated:
                    out.append(posixpath.join(cur_dir, name + ".cairo") if cur_dir else name + ".cairo")
            else:
                inline_open[m.end() - 1] = (posixpath.join(cur_dir, name) if cur_dir else name, gated)
        if c == "{":
            depth += 1
            if i in inline_open:
                d, g = inline_open[i]
                stack.append((depth, d, g))
        elif c == "}":
            if stack and stack[-1][0] == depth:
                stack.pop()
            depth -= 1
    return out


def in_scope_paths(files: dict[str, str], package_dir: str = "") -> set[str]:
    """Mod-tree scope of the package and of every in-tree non-dev path dependency: all of it is
    compiled into the deployed class. Unresolvable dependencies: the whole tree's Cairo files."""
    from soken_review.adapters.starknet.trust_scan import path_dependency_dirs

    dirs = path_dependency_dirs(files, package_dir)
    if dirs is None:
        return {p for p in files if p.endswith(".cairo")}
    out: set[str] = set()
    for d in dirs:
        out |= package_scope(files, d)
    return out


def package_scope(files: dict[str, str], package_dir: str = "") -> set[str]:
    pkg = package_dir.strip("/")
    prefix = f"{pkg}/" if pkg else ""
    pkg_cairo = {p for p in files if p.endswith(".cairo") and p.startswith(prefix)}
    lib = f"{prefix}src/lib.cairo"
    if lib not in files:
        return pkg_cairo
    seen: set[str] = set()
    queue = [(lib, f"{prefix}src")]
    while queue:
        path, child_dir = queue.pop()
        if path in seen:
            continue
        if path not in files:
            return pkg_cairo                      # unresolved module: everything in scope
        seen.add(path)
        for k in _children(files[path], child_dir):
            queue.append((k, k.removesuffix(".cairo")))
    return seen


def count_nsloc_cairo(text: str) -> int:
    """Lines minus blank and comment-only lines (07 4)."""
    n = 0
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("//"):
            n += 1
    return n
