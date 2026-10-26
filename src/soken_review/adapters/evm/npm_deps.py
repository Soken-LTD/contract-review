"""npm dependency resolution for EVM repo reviews (Hardhat, Foundry with npm packages).

Most real Solidity repositories import `@openzeppelin/*`, `@chainlink/*`, `solmate` and similar
from `node_modules`, which git does not carry. This module vendors exactly the packages the
reviewed sources import, pinned and integrity-checked, into `<src>/node_modules/` of the
materialized tree before the candidate is built:

  1. Imports are read from the scope files (the same selection the build compiles) and followed
     transitively through local files and vendored packages. Only an import that does not
     resolve inside the tree names a package to fetch.
  2. The version comes from the lockfile (package-lock.json / npm-shrinkwrap.json, yarn.lock
     classic and berry, pnpm-lock.yaml). Without a lockfile the package.json semver range is
     resolved against registry metadata (`pinned_by: registry_range`, a weaker pin that the
     status shows).
  3. Tarballs come only from registry.npmjs.org, downloaded inside the sandbox on the `evm`
     egress network (sandbox/npm_fetch.py). Every tarball is checked against its sha512
     integrity (lockfile value; registry `dist.integrity` when the lockfile carries none)
     BEFORE a member is read. No install script, no npm, no package code ever runs.
  4. Only `.sol` files and the package's `package.json` are extracted, from regular tar members
     with safe relative paths, under per-package and total caps, and written with O_NOFOLLOW /
     O_EXCL below an fd opened on the source root (the tree was written by an untrusted
     container, so no path component is trusted).

The result names every package with its version and pin source, and every import that could not
be satisfied with a reason, which the supervisor turns into `E_DEPENDENCY_UNRESOLVED`.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import posixpath
import re
import stat
import tarfile
import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

REGISTRY = "https://registry.npmjs.org/"

# Caps. Real packages are far below them (@openzeppelin/contracts 5.x: ~1.6 MiB tgz, ~400 .sol).
MAX_PACKAGES = 60
MAX_ROUNDS = 6
MAX_TARBALL_BYTES = 32 * 1024 * 1024
MAX_METADATA_BYTES = 48 * 1024 * 1024
MAX_TAR_BYTES = 192 * 1024 * 1024           # decompressed tar stream per package
MAX_FILE_BYTES = 2 * 1024 * 1024            # one extracted file
MAX_PACKAGE_BYTES = 40 * 1024 * 1024        # extracted bytes per package
MAX_PACKAGE_FILES = 5_000                   # extracted files per package
MAX_TOTAL_BYTES = 150 * 1024 * 1024         # extracted bytes, all packages
MAX_TOTAL_FILES = 15_000                    # extracted files, all packages
MAX_LOCKFILE_CHARS = 30 * 1024 * 1024
MAX_PATH_DEPTH = 24

# npm package name rules (validate-npm-package-name): lowercase, URL-safe, optional scope.
_PKG_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]{0,100}/)?[a-z0-9][a-z0-9._~-]{0,100}$")
_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$")
_STRICT_SEMVER_RE = re.compile(r"^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})(?:-[0-9A-Za-z.-]{1,40})?$")
_SRI_RE = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
_SAFE_SEG_RE = re.compile(r"^[A-Za-z0-9@_.+ -]{1,200}$")
_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_IMPORT_RE = re.compile(r"\bimport\s+(?:[^;\"']*?\bfrom\s+)?[\"']([^\"'\n]{1,400})[\"']", re.DOTALL)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class DepPackage:
    name: str                 # directory under node_modules/ (the name imports use)
    version: str
    integrity: str            # the sha512 value the tarball was verified against
    pinned_by: str            # lockfile | lockfile_version | registry_range
    files: int = 0
    real_name: str | None = None   # registry name when `name` is an npm alias

    def as_dict(self) -> dict[str, Any]:
        # Every string here may reach the client (review_status.dependencies): names must be npm
        # names, versions strict semver, integrity a plain SRI value; anything else is dropped.
        out: dict[str, Any] = {"name": self.name, "pinned_by": self.pinned_by, "files": self.files}
        if safe_version(self.version):
            out["version"] = self.version
        if _SRI_RE.fullmatch(self.integrity):
            out["integrity"] = self.integrity
        if self.real_name and self.real_name != self.name and _PKG_RE.fullmatch(self.real_name):
            out["registry_name"] = self.real_name
        return out


@dataclass
class DepFailure:
    name: str
    reason: str               # see FAILURE_REASONS
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        """Client-safe row: the validated npm name and the enum reason only. `detail` carries
        lockfile / package.json text (ranges, URLs): repository data, kept for host logs only."""
        name = self.name if _PKG_RE.fullmatch(self.name) else "<invalid>"
        reason = self.reason if self.reason in FAILURE_REASONS or self.reason == "not_declared" else "unknown"
        return {"name": name, "reason": reason}


# Reasons that stop the job with E_DEPENDENCY_UNRESOLVED. `not_declared` is informational: the
# import may still be satisfied by the build (forge auto remappings); the build gate decides.
FAILURE_REASONS = frozenset({
    "not_in_registry", "version_unresolvable", "integrity_mismatch", "integrity_missing",
    "non_registry_source", "registry_unreachable", "download_failed", "bad_tarball",
    "cap_exceeded", "write_refused", "invalid_name",
})


@dataclass
class NpmResolution:
    lockfile: str | None = None
    packages: list[DepPackage] = field(default_factory=list)
    unresolved: list[DepFailure] = field(default_factory=list)
    not_declared: list[str] = field(default_factory=list)
    remappings: list[str] = field(default_factory=list)

    @property
    def fatal(self) -> list[DepFailure]:
        return [f for f in self.unresolved if f.reason in FAILURE_REASONS]

    @property
    def pinned_by(self) -> str | None:
        """Weakest pin among the vendored packages (what the status reports)."""
        order = ("lockfile", "lockfile_version", "registry_range")
        pins = {p.pinned_by for p in self.packages}
        worst = [o for o in order if o in pins]
        return worst[-1] if worst else None

    def summary(self) -> dict[str, Any]:
        return {
            "manager": "npm",
            "lockfile": self.lockfile,
            "pinned_by": self.pinned_by,
            "packages": [p.as_dict() for p in self.packages],
            "unresolved": [f.as_dict() for f in self.unresolved],
            "not_declared": self.not_declared[:20],
            "remappings": self.remappings,
        }


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


def safe_version(version: str | None) -> bool:
    """True for a plain semver string (charset and shape), the only version form sent to a client."""
    return bool(version) and bool(_STRICT_SEMVER_RE.fullmatch(version or ""))


def parse_imports(source: str) -> list[str]:
    """Import paths of one Solidity file (comments removed first)."""
    return _IMPORT_RE.findall(_COMMENT_RE.sub(" ", source))


def _norm(path: str) -> str | None:
    p = posixpath.normpath(path)
    if p.startswith(("../", "/")) or p in ("..", "."):
        return None
    return p


def _parse_remap(remap: str) -> tuple[str, str, str] | None:
    ctx, _, rest = remap.rpartition(":") if ":" in remap.split("=", 1)[0] else ("", "", remap)
    prefix, sep, target = rest.partition("=")
    if not sep or not prefix:
        return None
    return ctx, prefix, target


def package_of(import_path: str) -> str | None:
    """npm package directory an import path names: `@scope/name` or `name`; None if invalid."""
    parts = import_path.split("/")
    if import_path.startswith("@"):
        if len(parts) < 3:
            return None
        name = parts[0] + "/" + parts[1]
    else:
        if len(parts) < 2:
            return None
        name = parts[0]
    return name if _PKG_RE.fullmatch(name) else None


def resolve_import(importer: str, path: str, tree: dict[str, str] | set[str],
                   remappings: list[str], *, node_modules: bool = True,
                   forge_libs: bool = False) -> tuple[str | None, str | None]:
    """Resolve one import like solc + the project tool would.

    Returns (tree_path, npm_path): tree_path when the file is in the tree; otherwise npm_path is
    the path inside node_modules the import needs (None when it is not an npm-shaped import).
    """
    if path.startswith(("./", "../")):
        resolved = _norm(posixpath.join(posixpath.dirname(importer), path))
        return (resolved if resolved in tree else None), None
    best: tuple[str, str] | None = None
    for remap in remappings:
        parsed = _parse_remap(remap)
        if parsed is None:
            continue
        ctx, prefix, target = parsed
        if ctx and not importer.startswith(ctx):
            continue
        if path.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, target)
    if best is not None:
        mapped = _norm(best[1] + path[len(best[0]):])
        if mapped is None:
            return None, None
        if mapped in tree:
            return mapped, None
        if mapped.startswith("node_modules/"):
            return None, mapped[len("node_modules/"):]
        return None, None
    direct = _norm(path)
    if direct is None:
        return None, None
    if direct in tree:
        return direct, None
    if node_modules and ("node_modules/" + direct) in tree:
        return "node_modules/" + direct, None
    if forge_libs:
        # forge auto-remaps lib/<name>/ (src/ or contracts/ inside it) when no remapping is set
        head, _, rest = direct.partition("/")
        for cand in (f"lib/{head}/src/{rest}", f"lib/{head}/{rest}", f"lib/{head}/contracts/{rest}"):
            if cand in tree:
                return cand, None
    return None, direct


def import_closure(start: Iterable[str], tree: dict[str, str], remappings: list[str], *,
                   node_modules: bool = True, forge_libs: bool = False,
                   ) -> tuple[set[str], list[tuple[str, str, str | None]]]:
    """Files reachable from `start` and the imports that did not resolve.

    Returns (visited tree paths, [(importer, import_path, npm_path)]).
    """
    visited: set[str] = set()
    stack = [p for p in start if p in tree]
    missing: list[tuple[str, str, str | None]] = []
    while stack:
        cur = stack.pop()
        if cur in visited:
            continue
        visited.add(cur)
        for imp in parse_imports(tree[cur]):
            hit, npm_path = resolve_import(cur, imp, tree, remappings,
                                           node_modules=node_modules, forge_libs=forge_libs)
            if hit is not None:
                if hit not in visited:
                    stack.append(hit)
            else:
                missing.append((cur, imp, npm_path))
    return visited, missing


# ---------------------------------------------------------------------------
# Semver (npm range syntax: ^ ~ x-ranges, hyphen ranges, comparators, ||)
# ---------------------------------------------------------------------------

Version = tuple[int, int, int, tuple[Any, ...]]


def parse_version(v: str) -> Version | None:
    m = _SEMVER_RE.fullmatch(v.strip())
    if not m:
        return None
    pre: tuple[Any, ...] = ()
    if m.group(4):
        pre = tuple(int(x) if x.isdigit() else x for x in m.group(4).split("."))
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _key(v: Version) -> tuple[Any, ...]:
    # A release sorts after its prereleases; numeric identifiers sort before alphanumeric ones.
    pre = tuple((0, x, "") if isinstance(x, int) else (1, 0, x) for x in v[3])
    return (v[0], v[1], v[2], 1 if not v[3] else 0, pre)


def _partial(s: str) -> tuple[list[int | None], tuple[Any, ...]] | None:
    s = s.strip().lstrip("v=").strip()
    if s in ("", "*", "x", "X"):
        return [None, None, None], ()
    main, _, pre_s = s.partition("-")
    main = main.split("+")[0]
    parts = main.split(".")
    if len(parts) > 3:
        return None
    nums: list[int | None] = []
    for p in parts:
        if p in ("x", "X", "*"):
            nums.append(None)
        elif p.isdigit():
            nums.append(int(p))
        else:
            return None
    while len(nums) < 3:
        nums.append(None)
    # once a component is a wildcard, the rest are too
    for i in range(3):
        if nums[i] is None:
            nums[i + 1:] = [None] * (2 - i)
            break
    pre = tuple(int(x) if x.isdigit() else x for x in pre_s.split(".")) if pre_s else ()
    return nums, pre


_LOW: tuple[Any, ...] = ("0",)   # "-0": the lowest prerelease, so `<X.Y.Z-0` excludes X.Y.Z prereleases


def _bound(nums: list[int | None], pre: tuple[Any, ...] = ()) -> Version:
    return (nums[0] or 0, nums[1] or 0, nums[2] or 0, pre)


def _desugar(token: str) -> list[tuple[str, Version]] | None:
    """One comparator token -> [(op, version)]; [] = any version; None = unparseable."""
    m = re.fullmatch(r"(\^|~>|~|>=|<=|>|<|=)?\s*(.*)", token.strip())
    if not m:
        return None
    op, rest = m.group(1) or "", m.group(2)
    parsed = _partial(rest)
    if parsed is None:
        return None
    nums, pre = parsed
    major, minor, patch = nums
    if major is None:
        return [] if op in ("", "=", ">=", "<=", "^", "~", "~>") else [("<", (0, 0, 0, _LOW))]
    if op in ("", "="):
        if patch is not None:
            return [("=", (major, minor or 0, patch, pre))]
        hi = (major + 1, 0, 0, _LOW) if minor is None else (major, minor + 1, 0, _LOW)
        return [(">=", _bound(nums)), ("<", hi)]
    if op in ("~", "~>"):
        hi = (major + 1, 0, 0, _LOW) if minor is None else (major, minor + 1, 0, _LOW)
        return [(">=", _bound(nums, pre)), ("<", hi)]
    if op == "^":
        if major > 0 or minor is None:
            hi = (major + 1, 0, 0, _LOW)
        elif minor > 0 or patch is None:
            hi = (0, minor + 1, 0, _LOW)
        else:
            hi = (0, 0, patch + 1, _LOW)
        return [(">=", _bound(nums, pre)), ("<", hi)]
    if op == ">=":
        return [(">=", _bound(nums, pre))]
    if op == "<":
        return [("<", _bound(nums, pre or (_LOW if patch is None else ())))]
    if op == ">":
        if patch is not None:
            return [(">", (major, minor or 0, patch, pre))]
        return [(">=", (major + 1, 0, 0, ()) if minor is None else (major, minor + 1, 0, ()))]
    if op == "<=":
        if patch is not None:
            return [("<=", (major, minor or 0, patch, pre))]
        return [("<", (major + 1, 0, 0, _LOW) if minor is None else (major, minor + 1, 0, _LOW))]
    return None


def _parse_range(rng: str) -> list[list[tuple[str, Version]]] | None:
    sets: list[list[tuple[str, Version]]] = []
    for alt in rng.split("||"):
        alt = alt.strip()
        hy = re.fullmatch(r"(\S+)\s+-\s+(\S+)", alt)
        comps: list[tuple[str, Version]] = []
        if hy:
            lo, hi = _desugar(">=" + hy.group(1)), _desugar("<=" + hy.group(2))
            if lo is None or hi is None:
                return None
            comps = lo + hi
        else:
            # "> = 1.2" style spacing: glue operators to their version
            alt = re.sub(r"(\^|~>|~|>=|<=|>|<|=)\s+", r"\1", alt)
            for tok in alt.split():
                d = _desugar(tok)
                if d is None:
                    return None
                comps += d
        sets.append(comps)
    return sets


def satisfies(version: str, rng: str) -> bool:
    v = parse_version(version)
    sets = _parse_range(rng)
    if v is None or sets is None:
        return False
    kv = _key(v)
    for comps in sets:
        ok = True
        for op, bound in comps:
            kb = _key(bound)
            if not ((op == "=" and kv == kb) or (op == ">=" and kv >= kb) or (op == ">" and kv > kb)
                    or (op == "<" and kv < kb) or (op == "<=" and kv <= kb)):
                ok = False
                break
        if not ok:
            continue
        # npm: a prerelease satisfies only when a comparator names the same X.Y.Z with a tag
        if v[3] and not any(b[3] and b[3] != _LOW and b[:3] == v[:3] for _, b in comps):
            continue
        return True
    return False


def max_satisfying(versions: Iterable[str], rng: str) -> str | None:
    best: tuple[tuple[Any, ...], str] | None = None
    for ver in versions:
        pv = parse_version(ver)
        if pv is None or not satisfies(ver, rng):
            continue
        k = _key(pv)
        if best is None or k > best[0]:
            best = (k, ver)
    return best[1] if best else None


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


def sha512_of(integrity: str | None) -> list[bytes]:
    """The sha512 digests of an SRI string (npm `integrity`); other algorithms are ignored."""
    out: list[bytes] = []
    for part in (integrity or "").split():
        algo, _, b64 = part.partition("-")
        if algo != "sha512":
            continue
        try:
            digest = base64.b64decode(b64.split("?")[0], validate=True)
        except (ValueError, TypeError):
            continue
        if len(digest) == 64:
            out.append(digest)
    return out


def verify_integrity(data: bytes, integrity: str | None) -> str:
    """'ok' | 'mismatch' | 'missing' (no usable sha512 in the integrity string)."""
    digests = sha512_of(integrity)
    if not digests:
        return "missing"
    return "ok" if hashlib.sha512(data).digest() in digests else "mismatch"


# ---------------------------------------------------------------------------
# Lockfiles
# ---------------------------------------------------------------------------


@dataclass
class LockEntry:
    name: str                       # node_modules directory name (alias or real name)
    version: str
    integrity: str | None = None
    real_name: str | None = None    # registry name (differs for npm aliases)
    non_registry: bool = False      # git / file / tarball-URL dependency


def _registry_resolved(resolved: Any) -> bool:
    if not isinstance(resolved, str) or not resolved:
        return True       # no resolved field: the registry default
    return resolved.startswith(("https://registry.npmjs.org/", "https://registry.yarnpkg.com/"))


def _add(entries: dict[str, list[LockEntry]], e: LockEntry) -> None:
    if _PKG_RE.fullmatch(e.name):
        entries.setdefault(e.name, []).append(e)


def parse_package_lock(text: str) -> tuple[dict[str, list[LockEntry]], dict[str, str]]:
    """package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3.

    Returns (entries by node_modules name, root versions: name -> version of the top-level copy).
    """
    data = json.loads(text)
    entries: dict[str, list[LockEntry]] = {}
    root: dict[str, str] = {}
    pkgs = data.get("packages") if isinstance(data, dict) else None
    if isinstance(pkgs, dict) and pkgs:
        for key, meta in pkgs.items():
            if not key or not isinstance(meta, dict) or "node_modules/" not in key or meta.get("link"):
                continue
            name = key.rsplit("node_modules/", 1)[1]
            version = meta.get("version")
            if not isinstance(version, str):
                continue
            real = meta.get("name") if isinstance(meta.get("name"), str) else None
            nr = not _registry_resolved(meta.get("resolved")) or parse_version(version) is None
            _add(entries, LockEntry(name, version, meta.get("integrity") if isinstance(meta.get("integrity"), str)
                                    else None, real, nr))
            if key == "node_modules/" + name:
                root[name] = version
        return entries, root

    def walk(deps: Any, top: bool) -> None:
        if not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if not isinstance(meta, dict) or not isinstance(meta.get("version"), str):
                continue
            version = meta["version"]
            real = None
            if version.startswith("npm:"):          # v1 alias: "npm:@scope/name@1.2.3"
                spec = version[4:]
                at = spec.rfind("@")
                real, version = (spec[:at], spec[at + 1:]) if at > 0 else (None, spec)
            nr = not _registry_resolved(meta.get("resolved")) or parse_version(version) is None
            _add(entries, LockEntry(name, version, meta.get("integrity") if isinstance(meta.get("integrity"), str)
                                    else None, real, nr))
            if top:
                root[name] = version
            walk(meta.get("dependencies"), False)

    walk(data.get("dependencies") if isinstance(data, dict) else None, True)
    return entries, root


def _yarn_spec_name(spec: str) -> tuple[str, str]:
    """`name@range` / `@scope/name@npm:range` -> (name, range)."""
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    if at <= 0:
        return spec, ""
    return spec[:at], spec[at + 1:]


def parse_yarn_lock(text: str) -> tuple[dict[str, list[LockEntry]], dict[str, str]]:
    """yarn.lock: classic (v1) and berry (v2+, YAML with `__metadata`)."""
    entries: dict[str, list[LockEntry]] = {}
    if "__metadata:" in text:
        import yaml

        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            return entries, {}
        for key, meta in data.items():
            if key == "__metadata" or not isinstance(meta, dict):
                continue
            version = str(meta.get("version", ""))
            resolution = str(meta.get("resolution", ""))
            # berry `checksum` hashes the zip cache entry, not the npm tarball: not usable here
            real, _ = _yarn_spec_name(resolution) if resolution else (None, "")
            nr = "@npm:" not in resolution
            for spec in str(key).split(","):
                name, _ = _yarn_spec_name(spec)
                _add(entries, LockEntry(name, version, None, real, nr or parse_version(version) is None))
        return entries, {}
    block_names: list[str] = []
    meta: dict[str, str] = {}

    def flush() -> None:
        if block_names and "version" in meta:
            resolved = meta.get("resolved", "")
            nr = not _registry_resolved(resolved.split("#")[0]) or parse_version(meta["version"]) is None
            for spec in block_names:
                name, rng = _yarn_spec_name(spec)
                real = None
                if rng.startswith("npm:"):
                    alias_target = rng[4:]
                    at = alias_target.rfind("@")
                    real = alias_target[:at] if at > 0 else alias_target
                _add(entries, LockEntry(name, meta["version"], meta.get("integrity"), real, nr))

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            flush()
            block_names = [s for s in line.rstrip(":").split(", ") if s]
            meta = {}
        elif line.startswith("  ") and not line.startswith("   "):
            k, _, v = line.strip().partition(" ")
            meta[k] = v.strip().strip('"')
    flush()
    return entries, {}


def parse_pnpm_lock(text: str) -> tuple[dict[str, list[LockEntry]], dict[str, str]]:
    """pnpm-lock.yaml lockfileVersion 5.x, 6.x and 9.x."""
    import yaml

    data = yaml.safe_load(text)
    entries: dict[str, list[LockEntry]] = {}
    root: dict[str, str] = {}
    if not isinstance(data, dict):
        return entries, root
    try:
        lv = float(str(data.get("lockfileVersion", "9")).split(".")[0])
    except ValueError:
        lv = 9.0

    def clean(v: str) -> str:
        return v.split("(")[0].split("_")[0]

    importers = data.get("importers") if isinstance(data.get("importers"), dict) else {}
    root_imp = importers.get(".") if isinstance(importers.get("."), dict) else data
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = root_imp.get(sect) if isinstance(root_imp, dict) else None
        if not isinstance(deps, dict):
            continue
        for name, v in deps.items():
            ver = v.get("version") if isinstance(v, dict) else v
            if isinstance(ver, str):
                root[str(name)] = clean(ver)
    pkgs = data.get("packages") if isinstance(data.get("packages"), dict) else {}
    for key, meta in pkgs.items():
        if not isinstance(meta, dict):
            continue
        k = clean(str(key).lstrip("/")) if lv >= 6 else str(key).lstrip("/").split("(")[0]
        if lv >= 6:
            at = k.rfind("@")
            if at <= 0:
                continue
            name, version = k[:at], k[at + 1:]
        else:
            name, _, version = k.rpartition("/")
            version = version.split("_")[0]
        res = meta.get("resolution") if isinstance(meta.get("resolution"), dict) else {}
        integrity = res.get("integrity") if isinstance(res.get("integrity"), str) else None
        nr = bool(res.get("tarball") or res.get("repo")) and not integrity
        _add(entries, LockEntry(name, version, integrity, None, nr or parse_version(version) is None))
    return entries, root


_LOCKFILES = (
    ("package-lock.json", parse_package_lock),
    ("npm-shrinkwrap.json", parse_package_lock),
    ("yarn.lock", parse_yarn_lock),
    ("pnpm-lock.yaml", parse_pnpm_lock),
)


def read_lockfile(tree: dict[str, str]) -> tuple[str | None, dict[str, list[LockEntry]], dict[str, str]]:
    """First parseable root lockfile -> (file name, entries, root versions)."""
    for fname, parser in _LOCKFILES:
        text = tree.get(fname)
        if not text or len(text) > MAX_LOCKFILE_CHARS:
            continue
        try:
            entries, root = parser(text)
        except Exception as exc:  # noqa: BLE001 - an unparseable lockfile is "no lockfile"
            logger.info("npm_deps: %s unparseable (%s)", fname, type(exc).__name__)
            continue
        return fname, entries, root
    return None, {}, {}


def declared_ranges(package_json: str | None) -> dict[str, str]:
    """dependencies/devDependencies/peerDependencies/optionalDependencies of one package.json."""
    try:
        data = json.loads(package_json or "{}")
    except ValueError:
        return {}
    out: dict[str, str] = {}
    if not isinstance(data, dict):
        return out
    for sect in ("peerDependencies", "optionalDependencies", "devDependencies", "dependencies"):
        deps = data.get(sect)
        if isinstance(deps, dict):
            out.update({str(k): str(v) for k, v in deps.items() if isinstance(v, (str, int, float))})
    return out


def pick_entry(entries: list[LockEntry], root_version: str | None, rng: str | None) -> LockEntry:
    """The lock entry to vendor: the root (hoisted) copy, else one matching the range, else highest."""
    if root_version:
        for e in entries:
            if e.version == root_version:
                return e
    if rng:
        ok = [e for e in entries if satisfies(e.version, rng)]
        if ok:
            entries = ok
    return max(entries, key=lambda e: _key(parse_version(e.version) or (0, 0, 0, ())))


# ---------------------------------------------------------------------------
# Tarball extraction and the fd-safe writer
# ---------------------------------------------------------------------------


class TarballError(Exception):
    """The tarball is unusable (corrupt, over a cap, unsafe member)."""


def _safe_rel(rel: str) -> bool:
    parts = rel.split("/")
    if not rel or len(rel) > 400 or len(parts) > MAX_PATH_DEPTH or rel.startswith("/"):
        return False
    return all(p not in ("", ".", "..") and _SAFE_SEG_RE.fullmatch(p) and not p.startswith("-")
               and p.casefold() != ".git" for p in parts)


def extract_sources(tgz: bytes) -> dict[str, bytes]:
    """`.sol` files and the root package.json of an npm tarball: {package-relative path: bytes}.

    Regular members only (links, devices, dirs skipped); the first path component (npm's
    `package/`) is stripped; any member with an unsafe path is skipped; caps raise TarballError.
    """
    if len(tgz) > MAX_TARBALL_BYTES:
        raise TarballError("tarball_too_large")
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = d.decompress(tgz, MAX_TAR_BYTES + 1)
        if len(raw) > MAX_TAR_BYTES or d.unconsumed_tail:
            raise TarballError("tar_too_large")
    except zlib.error as exc:
        raise TarballError("bad_gzip") from exc
    out: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            for m in tf:
                if not m.isreg():
                    continue
                parts = m.name.lstrip("./").split("/", 1)
                if len(parts) != 2:
                    continue
                rel = parts[1]
                if not (rel.endswith(".sol") or rel == "package.json") or not _safe_rel(rel) or rel in out:
                    continue
                if m.size > MAX_FILE_BYTES:
                    raise TarballError("file_too_large")
                fh = tf.extractfile(m)
                if fh is None:
                    continue
                data = fh.read(MAX_FILE_BYTES + 1)
                total += len(data)
                if len(out) >= MAX_PACKAGE_FILES or total > MAX_PACKAGE_BYTES:
                    raise TarballError("package_cap")
                out[rel] = data
    except tarfile.TarError as exc:
        raise TarballError("bad_tar") from exc
    return out


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_dir(parent_fd: int, name: str, create: bool) -> int:
    if create:
        try:
            os.mkdir(name, 0o755, dir_fd=parent_fd)
        except FileExistsError:
            pass
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError("not a directory")
    return fd


def write_package(src_root: str, pkg: str, files: dict[str, bytes]) -> int:
    """Write files under <src_root>/node_modules/<pkg>/ without following any link.

    The package directory must not exist yet (O_EXCL semantics on the last component). Raises
    OSError when a component is a link, a file, or the package dir exists. Returns files written.
    """
    if not _PKG_RE.fullmatch(pkg):
        raise OSError("invalid package name")
    root_fd = os.open(src_root, _DIR_FLAGS)
    fds = [root_fd]
    try:
        cur = _open_dir(root_fd, "node_modules", create=True)
        fds.append(cur)
        segs = pkg.split("/")
        if len(segs) == 2:
            cur = _open_dir(cur, segs[0], create=True)
            fds.append(cur)
        os.mkdir(segs[-1], 0o755, dir_fd=cur)        # FileExistsError when already present
        pkg_fd = _open_dir(cur, segs[-1], create=False)
        fds.append(pkg_fd)
        written = 0
        for rel, data in sorted(files.items()):
            *dirs, base = rel.split("/")
            dfd = pkg_fd
            opened: list[int] = []
            try:
                for d in dirs:
                    dfd = _open_dir(dfd, d, create=True)
                    opened.append(dfd)
                fd = os.open(base, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
                try:
                    view = memoryview(data)
                    while view:
                        n = os.write(fd, view)
                        view = view[n:]
                finally:
                    os.close(fd)
                written += 1
            finally:
                for o in reversed(opened):
                    os.close(o)
        return written
    finally:
        for fd in reversed(fds):
            os.close(fd)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

# fetch(requests) -> NpmFetchOutcome-like object with .bodies, .status, .transient, .error
Fetcher = Callable[[list[dict]], Any]


def _tarball_url(real_name: str, version: str) -> str:
    base = real_name.rsplit("/", 1)[-1]
    return f"{REGISTRY}{real_name}/-/{base}-{version}.tgz"


def _metadata_url(real_name: str) -> str:
    return REGISTRY + real_name.replace("/", "%2f")


@dataclass
class _Want:
    name: str                       # node_modules dir
    real_name: str
    version: str | None = None      # exact, when known
    integrity: str | None = None    # sha512 to verify, when known
    rng: str | None = None          # range to resolve against metadata
    pinned_by: str = "lockfile"


def resolve_npm_deps(src_root: str, tree: dict[str, str], scope: Iterable[str], remappings: list[str],
                     fetch: Fetcher) -> NpmResolution | None:
    """Vendor the npm packages the scope imports into <src_root>/node_modules/.

    `tree` is the O_NOFOLLOW read of `src_root` ({path: text}); it is updated in place with the
    vendored files. Returns None when no import needs a package (nothing was fetched).
    """
    lockname, lock, lock_root = read_lockfile(tree)
    root_ranges = declared_ranges(tree.get("package.json"))
    res = NpmResolution(lockfile=lockname)
    attempted: set[str] = set()
    total_files = total_bytes = 0
    scope = list(scope)
    needed_any = False
    vendored: dict[str, dict[str, str]] = {}   # package -> its declared ranges (transitive)

    for _round in range(MAX_ROUNDS):
        _visited, missing = import_closure(scope, tree, remappings + res.remappings,
                                           node_modules=True, forge_libs=True)
        wants: dict[str, _Want] = {}
        for importer, _imp, npm_path in missing:
            pkg = package_of(npm_path) if npm_path else None
            if pkg is None or pkg in attempted or pkg in wants:
                continue
            importer_pkg = None
            if importer.startswith("node_modules/"):
                importer_pkg = package_of(importer[len("node_modules/"):])
            rng = root_ranges.get(pkg) or (vendored.get(importer_pkg or "", {}).get(pkg))
            if pkg in lock:
                e = pick_entry(lock[pkg], lock_root.get(pkg), rng)
                real = e.real_name or pkg
                if e.non_registry:
                    res.unresolved.append(DepFailure(pkg, "non_registry_source", e.version[:80]))
                    attempted.add(pkg)
                    continue
                if sha512_of(e.integrity):
                    wants[pkg] = _Want(pkg, real, e.version, e.integrity, None, "lockfile")
                else:
                    wants[pkg] = _Want(pkg, real, e.version, None, None, "lockfile_version")
            elif rng is not None:
                real, r = pkg, rng
                if rng.startswith("npm:"):                    # alias: "npm:@scope/name@^1"
                    real, r = _yarn_spec_name(rng[4:])
                if not _PKG_RE.fullmatch(real) or _parse_range(r or "*") is None:
                    res.unresolved.append(DepFailure(pkg, "non_registry_source", rng[:80]))
                    attempted.add(pkg)
                    continue
                wants[pkg] = _Want(pkg, real, None, None, r or "*", "registry_range")
            else:
                if pkg not in res.not_declared:
                    res.not_declared.append(pkg)
                attempted.add(pkg)
        if not wants:
            break
        needed_any = True
        if len(attempted) + len(wants) > MAX_PACKAGES:
            for w in wants.values():
                res.unresolved.append(DepFailure(w.name, "cap_exceeded", f"more than {MAX_PACKAGES} packages"))
            break
        attempted.update(wants)

        # Phase 1: tarballs with a lockfile sha512 + metadata for everything else (one sandbox run)
        reqs: list[dict] = []
        by_id: dict[str, tuple[str, str]] = {}
        for w in wants.values():
            rid = f"r{len(reqs)}"
            if w.integrity:
                reqs.append({"id": rid, "url": _tarball_url(w.real_name, w.version or ""), "kind": "tarball",
                             "max_bytes": MAX_TARBALL_BYTES})
                by_id[rid] = ("tarball", w.name)
            else:
                reqs.append({"id": rid, "url": _metadata_url(w.real_name), "kind": "metadata",
                             "max_bytes": MAX_METADATA_BYTES})
                by_id[rid] = ("metadata", w.name)
        out1 = _fetch_retry(fetch, reqs)
        tarballs: dict[str, bytes] = {}
        reqs2: list[dict] = []
        by_id2: dict[str, str] = {}
        for rid, (kind, name) in by_id.items():
            w = wants[name]
            body = out1.bodies.get(rid)
            if body is None:
                res.unresolved.append(_fetch_failure(name, out1, rid))
                continue
            if kind == "tarball":
                tarballs[name] = body
                continue
            version, integrity = _from_metadata(body, w)
            if version is None:
                res.unresolved.append(DepFailure(name, "version_unresolvable",
                                                 f"{w.real_name}@{w.version or w.rng}"))
                continue
            if not sha512_of(integrity):
                res.unresolved.append(DepFailure(name, "integrity_missing", f"{w.real_name}@{version}"))
                continue
            w.version, w.integrity = version, integrity
            rid2 = f"r{len(reqs2)}"
            reqs2.append({"id": rid2, "url": _tarball_url(w.real_name, version), "kind": "tarball",
                          "max_bytes": MAX_TARBALL_BYTES})
            by_id2[rid2] = name
        # Phase 2: tarballs pinned through registry metadata
        if reqs2:
            out2 = _fetch_retry(fetch, reqs2)
            for rid, name in by_id2.items():
                body = out2.bodies.get(rid)
                if body is None:
                    res.unresolved.append(_fetch_failure(name, out2, rid))
                else:
                    tarballs[name] = body

        for name, body in sorted(tarballs.items()):
            w = wants[name]
            verdict = verify_integrity(body, w.integrity)
            if verdict != "ok":
                res.unresolved.append(DepFailure(name, "integrity_mismatch" if verdict == "mismatch"
                                                 else "integrity_missing", f"{w.real_name}@{w.version}"))
                continue
            try:
                files = extract_sources(body)
            except TarballError as exc:
                res.unresolved.append(DepFailure(name, "bad_tarball", str(exc)))
                continue
            size = sum(len(b) for b in files.values())
            if total_files + len(files) > MAX_TOTAL_FILES or total_bytes + size > MAX_TOTAL_BYTES:
                res.unresolved.append(DepFailure(name, "cap_exceeded", "total extracted size"))
                continue
            try:
                n = write_package(src_root, name, files)
            except OSError as exc:
                res.unresolved.append(DepFailure(name, "write_refused", type(exc).__name__))
                continue
            total_files += n
            total_bytes += size
            for rel, data in files.items():
                tree[f"node_modules/{name}/{rel}"] = data.decode("utf-8", errors="replace")
            vendored[name] = declared_ranges(tree.get(f"node_modules/{name}/package.json"))
            res.packages.append(DepPackage(name, w.version or "", w.integrity or "", w.pinned_by,
                                           sum(1 for r in files if r.endswith(".sol")), w.real_name))
            # solc needs a remapping for a hardhat-style import unless the repo maps it already
            remap = f"{name}/=node_modules/{name}/"
            if not any((_parse_remap(r) or ("", "", ""))[1].startswith(name.split("/")[0])
                       for r in remappings) and remap not in res.remappings:
                res.remappings.append(remap)

    if not needed_any and not res.unresolved:
        return None if not res.not_declared else res
    res.packages.sort(key=lambda p: p.name)
    return res


def _fetch_retry(fetch: Fetcher, reqs: list[dict]) -> Any:
    out = fetch(reqs)
    if getattr(out, "transient", False):
        logger.info("npm_deps: registry fetch transient (%s), one retry", getattr(out, "error", ""))
        out = fetch(reqs)
    return out


def _fetch_failure(name: str, outcome: Any, rid: str) -> DepFailure:
    if getattr(outcome, "transient", False):
        return DepFailure(name, "registry_unreachable", str(getattr(outcome, "error", ""))[:80])
    status = (getattr(outcome, "status", {}) or {}).get(rid) or str(getattr(outcome, "error", "") or "")
    if status == "not_found":
        return DepFailure(name, "not_in_registry")
    return DepFailure(name, "download_failed", status[:80])


def _from_metadata(body: bytes, want: _Want) -> tuple[str | None, str | None]:
    """(version, dist.integrity) from an abbreviated packument."""
    try:
        doc = json.loads(body)
    except ValueError:
        return None, None
    versions = doc.get("versions") if isinstance(doc, dict) else None
    if not isinstance(versions, dict):
        return None, None
    if want.version:
        version = want.version if want.version in versions else None
    else:
        rng = want.rng or "*"
        tags = doc.get("dist-tags") if isinstance(doc.get("dist-tags"), dict) else {}
        if rng in tags and isinstance(tags[rng], str):     # "latest" and other tags
            version = tags[rng] if tags[rng] in versions else None
        else:
            version = max_satisfying(versions.keys(), rng)
    if version is None:
        return None, None
    meta = versions.get(version) if isinstance(versions.get(version), dict) else {}
    dist = meta.get("dist") if isinstance(meta.get("dist"), dict) else {}
    integrity = dist.get("integrity") if isinstance(dist.get("integrity"), str) else None
    return version, integrity
