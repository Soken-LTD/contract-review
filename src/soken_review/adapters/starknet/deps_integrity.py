"""Scarb cache verification against the pinned lockfile (supervisor side, read-only).

After the deps step (`scarb fetch` on the family egress network) and before the first offline
step, the supervisor checks that what the container fetched into `scarb-cache` is exactly what the
pinned `Scarb.lock` names, so an offline build never runs on an unverified cache (the Move adapter's
fail-closed property, applied to Scarb; design note starknet-scarb-prefetch-design-2026-10-23).

What Scarb 2.13.1 itself does (software-mansion/scarb at v2.13.1):
- `scarb/src/core/registry/client/cache.rs` `download_and_verify_with_cache` / `verify_checksum`:
  the downloaded `.tar.zst` is hashed as a whole (`Checksum::digest()` = sha256 over the file bytes)
  against the registry index record's `checksum`; `scarb/src/core/lockfile.rs` writes that same
  record checksum into the lock row (`checksum = "sha256:<hex>"`). So the lock checksum is the
  checksum of `registry/dl/<ident>/<name>-<version>.tar.zst`, and the supervisor hashes the same
  bytes (stand, oz-account-v3: both `snforge_*` archives hash to their lock rows).
- `scarb/src/core/registry/package_source_store.rs` `extract_impl`: extraction into
  `registry/src/<ident>/<name>-<version>/` runs under `protected_run_if_not_ok!`, i.e. it is
  skipped when that dir already holds `.scarb-ok`; otherwise the dir is recreated and the archive
  untarred. Scarb therefore compiles an already-extracted tree without re-reading the archive, so a
  verified archive proves nothing about an extracted tree the deps container also wrote. The build
  step discards `registry/src` after a passing check (`discard_extracted_sources`), and the next
  Scarb run re-extracts from the archives whose bytes were verified.
- `scarb/src/core/lockfile.rs`: `LockVersion` has the single variant `V1 = 1`; `serdex::Lockfile`
  is `version` + a set of `package` rows (`name`, `version`, `source`, `checksum`, `dependencies`).

Rules (every reason is a named `failures` entry; `failures` closes the build with `deps_integrity`):
- the lock must parse as TOML (tomllib only), carry `version = 1`, and every row must be a table
  whose `name`/`version`/`source` are strings in Scarb's grammar; a row with a `source` identifies
  a package as (name, version, source) exactly as written (no case folding, no `-`/`_` or unicode
  normalisation); two rows with the same name and version are rejected (the archive name
  `<name>-<version>.tar.zst` could not tell them apart);
- every registry row (`source` starting with `registry+`) must carry a well-formed checksum and
  its archive must exist under some `registry/dl/<ident>/` as a regular file whose sha256 equals it;
- every entry under `registry/dl/` and `registry/src/` must be the archive or the extracted dir of
  a listed registry row; any symlink at any of these levels, and any entry of an unexpected kind,
  fails closed (Scarb follows the tree it finds there);
- rows with a `git+` source carry no checksum in Scarb's lock (the rev is in the source string) and
  cannot be verified from it: they are listed as `unverified`, named in `build_result.json`
  (`deps_unverified`) and in the trust scan (`deps_unverified:<name>@<version>`), never silent;
- any other source kind fails closed (`unknown_source`).

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
_NAME_FULL = re.compile(rf"^{_NAME_RE}$")
_VERSION_FULL = re.compile(rf"^{_VERSION_RE}$")
_CHECKSUM_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
_SUPPORTED_LOCK_VERSION = 1              # scarb lockfile.rs LockVersion::V1
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024    # the deps step's fsize cap: nothing larger is Scarb's
_MAX_ROWS = 10_000


class LockFormatError(ValueError):
    """The pinned lock cannot be used as a verification oracle; `.reason` is the failure entry."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


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

    @property
    def is_git(self) -> bool:
        return self.source.startswith("git+")

    @property
    def archive_name(self) -> str:
        """`PackageId::tarball_name()`: the lock-derived file name, no separators possible."""
        return _safe_name(f"{self.name}-{self.version}.tar.zst")

    @property
    def source_dir_name(self) -> str:
        """`PackageId::tarball_basename()`: the extracted dir name under `registry/src/<ident>/`."""
        return _safe_name(f"{self.name}-{self.version}")


def _safe_name(name: str) -> str:
    """A single path component built from lock-derived identity: never a separator, `.`/`..`,
    an absolute path or a NUL (the grammar already forbids these; this is the stated invariant)."""
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\0" in name:
        raise LockFormatError(f"lock_row_malformed:{name!r}")
    return name


@dataclass
class DepsVerification:
    """Outcome of one cache check. `failures` closes the build; `unverified` is flagged, not fatal."""

    verified: list[str] = field(default_factory=list)      # name@version, archive hash equal
    unverified: list[str] = field(default_factory=list)    # name@version with no lock checksum (git)
    failures: list[str] = field(default_factory=list)      # <reason>:<subject>

    @property
    def ok(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, list[str]]:
        return {"verified": sorted(self.verified), "unverified": sorted(self.unverified),
                "failures": sorted(self.failures)}


def parse_lock(lock_text: str) -> list[LockedPackage]:
    """External packages of a Scarb.lock (rows with a `source`), tomllib only.

    Raises LockFormatError (`lock_unparsable`, `lock_version_unsupported:<v>`,
    `lock_row_malformed:<n>`, `lock_duplicate_row:<name>@<version>`). Identity is the row's
    `name`, `version` and `source` strings exactly as Scarb wrote them.
    """
    try:
        doc = tomllib.loads(lock_text)
    except tomllib.TOMLDecodeError:
        raise LockFormatError("lock_unparsable:Scarb.lock") from None
    version = doc.get("version")
    if isinstance(version, bool) or version != _SUPPORTED_LOCK_VERSION:
        raise LockFormatError(f"lock_version_unsupported:{version!r}"[:120])
    rows = doc.get("package") or []
    if not isinstance(rows, list) or len(rows) > _MAX_ROWS:
        raise LockFormatError("lock_row_malformed:package")
    out: list[LockedPackage] = []
    seen: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise LockFormatError(f"lock_row_malformed:{index}")
        name, version_s = row.get("name"), row.get("version")
        if not isinstance(name, str) or not _NAME_FULL.match(name):
            raise LockFormatError(f"lock_row_malformed:{index}")
        if not isinstance(version_s, str) or not _VERSION_FULL.match(version_s):
            raise LockFormatError(f"lock_row_malformed:{name}")
        if (name, version_s) in seen:
            raise LockFormatError(f"lock_duplicate_row:{name}@{version_s}")
        seen.add((name, version_s))
        if "source" not in row:
            continue                                     # workspace member: lives in the pinned tree
        source, checksum = row.get("source"), row.get("checksum")
        if not isinstance(source, str) or not source or (checksum is not None and not isinstance(checksum, str)):
            raise LockFormatError(f"lock_row_malformed:{name}@{version_s}")
        out.append(LockedPackage(name, version_s, source, checksum))
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


def _entries(path: Path) -> list[tuple[Path, int]]:
    """(entry, lstat mode) of every child, sorted by name; empty when `path` is absent."""
    try:
        children = sorted(path.iterdir(), key=lambda p: p.name)
    except OSError:
        return []
    out: list[tuple[Path, int]] = []
    for child in children:
        try:
            out.append((child, child.lstat().st_mode))
        except OSError:
            out.append((child, 0))
    return out


def _level_dirs(root: Path, rel: str, failures: list[str]) -> list[Path]:
    """Ident dirs under `registry/<rel>` (`dl` or `src`): the level itself must be a real dir when
    present, and every child a real dir; a symlink or a stray entry fails closed."""
    level = root / "registry" / rel
    try:
        mode = level.lstat().st_mode
    except OSError:
        return []
    if stat.S_ISLNK(mode):
        failures.append(f"symlink_in_cache:{rel}")
        return []
    if not stat.S_ISDIR(mode):
        failures.append(f"unexpected_entry:{rel}")
        return []
    idents: list[Path] = []
    for child, cmode in _entries(level):
        if stat.S_ISLNK(cmode):
            failures.append(f"symlink_in_cache:{rel}/{child.name}")
        elif stat.S_ISDIR(cmode):
            idents.append(child)
        else:
            failures.append(f"unexpected_entry:{rel}/{child.name}")
    return idents


def verify_registry_cache(lock_text: str | None, cache_dir: Path) -> DepsVerification:
    """Check `cache_dir` (the job's scarb-cache) against the pinned lockfile text; see the module
    docstring for the rules. Read-only: nothing under `cache_dir` is modified."""
    result = DepsVerification()
    failures = result.failures
    dl_idents = _level_dirs(cache_dir, "dl", failures)
    src_idents = _level_dirs(cache_dir, "src", failures)
    cache_has_packages = bool(dl_idents or src_idents)

    packages: list[LockedPackage] = []
    if lock_text is None:
        if cache_has_packages:
            failures.append("lock_missing:Scarb.lock")
    else:
        try:
            packages = parse_lock(lock_text)
        except LockFormatError as exc:
            # An unusable lock is fatal whenever the cache holds anything it would have to vouch for.
            if cache_has_packages or not exc.reason.startswith("lock_unparsable"):
                failures.append(exc.reason)
            packages = []

    registry_rows: dict[str, LockedPackage] = {}     # archive name -> row
    source_dirs: dict[str, LockedPackage] = {}       # extracted dir name -> row
    for pkg in packages:
        if pkg.is_registry:
            registry_rows[pkg.archive_name] = pkg
            source_dirs[pkg.source_dir_name] = pkg
        elif pkg.is_git:
            result.unverified.append(pkg.label)
        else:
            failures.append(f"unknown_source:{pkg.label}")

    # Cache -> lock: everything fetched must be a listed registry package, nothing may be a symlink.
    archives: dict[str, Path] = {}
    for ident in dl_idents:
        for entry, mode in _entries(ident):
            rel = f"dl/{ident.name}/{entry.name}"
            if stat.S_ISLNK(mode):
                failures.append(f"symlink_in_cache:{rel}")
            elif entry.name not in registry_rows:
                failures.append(f"unlisted_archive:{ident.name}/{entry.name}")
            elif not stat.S_ISREG(mode):
                failures.append(f"unexpected_entry:{rel}")
            elif entry.name in archives:
                failures.append(f"archive_duplicate:{registry_rows[entry.name].label}")
            else:
                archives[entry.name] = entry
    for ident in src_idents:
        for entry, mode in _entries(ident):
            rel = f"src/{ident.name}/{entry.name}"
            if stat.S_ISLNK(mode):
                failures.append(f"symlink_in_cache:{rel}")
            elif entry.name not in source_dirs:
                failures.append(f"unlisted_source_dir:{ident.name}/{entry.name}")
            elif not stat.S_ISDIR(mode):
                failures.append(f"unexpected_entry:{rel}")

    # Lock -> cache: every registry row has its archive, and the bytes hash to the lock checksum.
    for archive_name, pkg in sorted(registry_rows.items()):
        if pkg.checksum is None:
            failures.append(f"checksum_missing:{pkg.label}")
            continue
        m = _CHECKSUM_RE.match(pkg.checksum)
        if m is None:
            failures.append(f"checksum_unparsable:{pkg.label}")
            continue
        archive = archives.get(archive_name)
        if archive is None:
            failures.append(f"archive_missing:{pkg.label}")
            continue
        digest = _sha256_regular_file(archive)
        if digest is None:
            failures.append(f"archive_not_regular_file:{pkg.label}")
        elif digest != m.group(1):
            failures.append(f"checksum_mismatch:{pkg.label}")
        else:
            result.verified.append(pkg.label)

    result.verified.sort()
    result.unverified.sort()
    result.failures.sort()
    return result


def discard_extracted_sources(cache_dir: Path) -> bool:
    """Remove `registry/src` so the next Scarb run re-extracts every package from its verified
    archive (`package_source_store.rs`: extraction is skipped only while `.scarb-ok` exists in the
    extracted dir; without the dir it is recreated from the `.tar.zst`). Returns True when
    something was removed. Never follows a symlink."""
    import shutil

    src = cache_dir / "registry" / "src"
    try:
        mode = src.lstat().st_mode
    except OSError:
        return False
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        src.unlink()
    else:
        shutil.rmtree(src)
    return True
