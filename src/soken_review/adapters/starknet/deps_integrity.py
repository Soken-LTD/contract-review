"""Scarb cache verification against the pinned lockfile (supervisor side, read-only).

After the deps step (`scarb fetch` on the family egress network) and before the first offline
step, the supervisor checks that what the container fetched into `scarb-cache` is exactly what the
pinned `Scarb.lock` names, so an offline build never runs on an unverified cache (the Move adapter's
fail-closed property, applied to Scarb; design note starknet-scarb-prefetch-design-2026-10-23):

- every lock row with a registry source needs `registry/dl/<ident>/<name>-<version>.tar.zst` as a
  regular file whose sha256 equals the row's `checksum` (`sha256:<hex>`). Scarb's lock checksum is
  the archive checksum (stand, oz-account-v3: both `snforge_*` archives hash to their lock rows);
- every archive under `registry/dl/` and every unpacked dir under `registry/src/` must be a listed
  registry row (something the container fetched that the lock does not name fails the build);
- a lock row whose source carries no checksum (git sources; a registry row without `checksum`)
  cannot be verified from the lock. These are listed as `unverified` and the build proceeds with
  the row named in `build_result.json` and in the trust scan (`deps_unverified:<name>@<version>`),
  which keeps the inputs untrusted (tier A blocked), never silently trusted.

Rows without a `source` are workspace members (in the pinned tree) and need no cache entry. The
registry index (`registry/cache/*.redb`) is Scarb's own cache and is not parsed here. CARGO_HOME
(procedural-macro crates) is verified by cargo itself against the in-tree Cargo.lock on every build.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_NAME_RE = r"[a-z_][a-z0-9_]{0,63}"
_VERSION_RE = r"\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.]{1,40})?"
_ARCHIVE_RE = re.compile(rf"^(?P<name>{_NAME_RE})-(?P<version>{_VERSION_RE})\.tar\.zst$")
_SRC_DIR_RE = re.compile(rf"^(?P<name>{_NAME_RE})-(?P<version>{_VERSION_RE})$")
_CHECKSUM_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024      # the deps step's fsize cap: nothing larger is Scarb's
_IGNORED_SRC_ENTRIES = frozenset({".scarb-ok"})


@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    source: str
    checksum: str | None

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def is_registry(self) -> bool:
        return self.source.startswith("registry+")


@dataclass
class DepsVerification:
    """Outcome of one cache check. `failures` closes the build; `unverified` is flagged, not fatal."""

    verified: list[str] = field(default_factory=list)      # name@version, archive hash equal
    unverified: list[str] = field(default_factory=list)    # name@version with no lock checksum
    failures: list[str] = field(default_factory=list)      # <reason>:<subject>

    @property
    def ok(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, list[str]]:
        return {"verified": sorted(self.verified), "unverified": sorted(self.unverified),
                "failures": sorted(self.failures)}


def parse_lock(lock_text: str) -> list[LockedPackage] | None:
    """External packages of a Scarb.lock (rows with a `source`); None when it does not parse."""
    try:
        rows = tomllib.loads(lock_text).get("package") or []
    except tomllib.TOMLDecodeError:
        return None
    out: list[LockedPackage] = []
    for row in rows:
        if not isinstance(row, dict) or "source" not in row:
            continue
        name, version, source, checksum = row.get("name"), row.get("version"), row.get("source"), row.get("checksum")
        if not isinstance(name, str) or not isinstance(version, str) or not isinstance(source, str):
            return None
        if not re.fullmatch(_NAME_RE, name) or not re.fullmatch(_VERSION_RE, version):
            return None
        out.append(LockedPackage(name, version, source, checksum if isinstance(checksum, str) else None))
    return out


def _sha256_regular_file(path: Path) -> str | None:
    """sha256 of a regular file read through O_NOFOLLOW; None for a symlink, a special file or an
    oversize file (never followed, never partially trusted)."""
    try:
        st = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_ARCHIVE_BYTES:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    h = hashlib.sha256()
    total = 0
    try:
        while chunk := os.read(fd, 1 << 20):
            total += len(chunk)
            if total > _MAX_ARCHIVE_BYTES:
                return None
            h.update(chunk)
    finally:
        os.close(fd)
    return h.hexdigest()


def _subdirs(path: Path) -> list[Path]:
    """Real sub-directories of `path` (symlinks excluded), sorted; empty when absent."""
    try:
        entries = sorted(path.iterdir(), key=lambda p: p.name)
    except OSError:
        return []
    out = []
    for entry in entries:
        try:
            if stat.S_ISDIR(entry.lstat().st_mode):
                out.append(entry)
        except OSError:
            continue
    return out


def verify_registry_cache(lock_text: str | None, cache_dir: Path) -> DepsVerification:
    """Check `cache_dir` (the job's scarb-cache) against the pinned lockfile text.

    Fails closed (a `failures` entry) on: an unparsable or missing lock while the cache holds
    registry packages, a listed registry archive that is missing, not a regular file or whose sha256
    differs from the lock, an archive or unpacked source dir the lock does not list, and a source
    kind this check does not know. Rows without a checksum (git sources) go to `unverified`.
    """
    result = DepsVerification()
    registry = cache_dir / "registry"
    packages = parse_lock(lock_text) if lock_text is not None else None
    if packages is None:
        packages = []
        reason = "lock_missing" if lock_text is None else "lock_unparsable"
        # A cache with registry content and no lock to check it against is unverifiable.
        if any(_subdirs(registry / sub) for sub in ("dl", "src")):
            result.failures.append(f"{reason}:Scarb.lock")

    listed: dict[tuple[str, str], LockedPackage] = {}
    for pkg in packages:
        if (pkg.name, pkg.version) in listed:
            result.failures.append(f"lock_duplicate_row:{pkg.label}")
            continue
        listed[(pkg.name, pkg.version)] = pkg

    # Registry rows: archive present, regular, hash equal to the lock checksum.
    archives: dict[tuple[str, str], Path] = {}
    for ident_dir in _subdirs(registry / "dl"):
        try:
            entries = sorted(ident_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            entries = []
        for entry in entries:
            m = _ARCHIVE_RE.match(entry.name)
            key = (m.group("name"), m.group("version")) if m else None
            if key is None or key not in listed or not listed[key].is_registry:
                result.failures.append(f"unlisted_archive:{ident_dir.name}/{entry.name}")
                continue
            archives[key] = entry
    for ident_dir in _subdirs(registry / "src"):
        try:
            entries = sorted(ident_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            entries = []
        for entry in entries:
            if entry.name in _IGNORED_SRC_ENTRIES:
                continue
            m = _SRC_DIR_RE.match(entry.name)
            key = (m.group("name"), m.group("version")) if m else None
            if key is None or key not in listed or not listed[key].is_registry:
                result.failures.append(f"unlisted_source_dir:{ident_dir.name}/{entry.name}")

    for key, pkg in sorted(listed.items()):
        if pkg.is_registry:
            m = _CHECKSUM_RE.match(pkg.checksum or "")
            if m is None:
                # A registry row Scarb wrote without a checksum: nothing to verify against.
                result.unverified.append(pkg.label)
                continue
            archive = archives.get(key)
            if archive is None:
                result.failures.append(f"archive_missing:{pkg.label}")
                continue
            digest = _sha256_regular_file(archive)
            if digest is None:
                result.failures.append(f"archive_not_regular_file:{pkg.label}")
            elif digest != m.group(1):
                result.failures.append(f"checksum_mismatch:{pkg.label}")
            else:
                result.verified.append(pkg.label)
        elif pkg.source.startswith("git+"):
            # Scarb git rows carry no checksum (the lock pins the rev inside the source string);
            # the checkout under scarb-cache/git/ is not verifiable from the lock.
            result.unverified.append(pkg.label)
        else:
            result.failures.append(f"unknown_source:{pkg.label}")

    result.verified.sort()
    result.unverified.sort()
    result.failures.sort()
    return result
