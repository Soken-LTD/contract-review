"""Scarb cache and CARGO_HOME verification against the pinned lockfiles (supervisor side).

After the deps step (`scarb fetch` on the family egress network) and before the first offline
step, the supervisor checks that what the container fetched is exactly what the pinned lockfiles
name, so an offline build never runs on an unverified cache (the Move adapter's fail-closed
property, applied to Scarb; design note starknet-scarb-prefetch-design-2026-10-23). Both caches
are written by the sandboxed container: nothing in them is trusted, no symlink in them is ever
followed, and what cannot be verified is either regenerated from verified bytes or fails closed.

What Scarb 2.13.1 itself does (software-mansion/scarb at v2.13.1):
- `scarb/src/core/registry/client/cache.rs` `verify_checksum`: the downloaded `.tar.zst` is hashed
  as a whole (sha256) against the registry index record; `core/lockfile.rs` writes that record
  checksum into the lock row. So `Scarb.lock` `checksum = "sha256:<hex>"` is sha256 of
  `registry/dl/<ident>/<name>-<version>.tar.zst` (stand, oz-account-v3: both `snforge_*` archives).
  Offline, `download_and_verify_with_cache` returns an archive already in `dl/` WITHOUT re-hashing
  it, so the supervisor's hash is the only byte check that runs.
- `scarb/src/core/registry/package_source_store.rs` `extract_impl` and
  `scarb/src/sources/standard_lib.rs` `ensure_loaded`: extraction into `registry/src/<ident>/
  <name>-<version>/` and of the corelib into `registry/std/<version>/` runs under
  `protected_run_if_not_ok!` (`flock.rs` `OK_FILE = ".scarb-ok"`): with the marker present the
  existing tree is used as is; without the dir it is recreated (`fs.recreate()`) from the archive,
  or from the corelib embedded in the Scarb binary. The supervisor discards both after a passing
  check, so the offline run compiles only trees re-extracted from verified bytes or from the
  pinned image.
- `scarb/src/ops/resolve.rs:346`: every resolution calls `resolve.check_checksums(&lockfile)`
  (`core/resolver/resolve.rs`): a resolved package whose record checksum differs from the lock
  row is an error, so the registry index cache (`registry/cache/<ident>.v1.redb`, a private redb
  file this check cannot parse) cannot substitute a record for a locked package without Scarb
  failing; then `write_lockfile` rewrites `Scarb.lock` from the resolution. The supervisor compares
  the tree's lock with the pinned one after the offline `scarb metadata` probe (the resolution
  from the index with no network) and closes the build when they differ.
- `scarb/src/core/lockfile.rs`: `LockVersion` has the single variant `V1 = 1`; rows are `name`,
  `version`, `source`, `checksum`, `dependencies`. Git rows carry no checksum (the rev is in the
  source string). Workspace members have no `source`.

Cargo (procedural macros of in-tree `[cairo-plugin]` packages, CARGO_HOME = `cargo-home/`):
`Cargo.lock` `checksum = "<hex>"` is sha256 of `registry/cache/<index>/<name>-<version>.crate`
(stand: 204 of 204 crates of OZ `packages/macros/Cargo.lock`); `registry/src/<index>/<crate>/` is
the extracted tree with cargo's `.cargo-ok` marker (used as is when present), `registry/index/
<index>/` the sparse-index cache (`config.json`, `.cache/`), `.global-cache` / `.package-cache*`
cargo's own lock and db files. The offline build mounts cargo-home read-write because cargo
extracts crates and writes its locks there, so cargo's own checks are not relied on: every crate
present must hash to a row of an in-tree plugin `Cargo.lock`, the extracted trees are discarded,
and a plugin dir without a `Cargo.lock` cannot be verified while crates are present.

Policy per cache entry (every reason is a `failures` entry; any failure closes the build with
`deps_integrity`): verified (archive / crate bytes against the lock), regenerated (discarded
through directory file descriptors, never following a symlink; Scarb / cargo recreate it from
verified bytes or the image), modelled (name and kind fixed, content a tool-private cache whose
effect is caught by a later check), flagged (`git+` rows: no checksum exists; named in
`build_result.json` and the trust scan as `deps_unverified`), unexpected (anything else:
`unexpected_cache_entry:<path>`). A symlink at any traversed level is `symlink_in_cache:<path>`.
"""

from __future__ import annotations

import hashlib
import json
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
_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")          # `scarbs.xyz-9djtpev4jug5q`
_REDB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.v1\.redb(\.lock)?$")
_CONFIG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.json$")
_STD_DIR_RE = re.compile(r"^v\d{1,6}\.\d{1,6}\.\d{1,6}$")
_CONFIG_KEYS = {"version", "api", "dl", "index", "upload"}

# cargo: crates.io names allow letters of both cases, digits, `-` and `_`; identity is the exact string.
_CRATE_NAME_RE = r"[A-Za-z0-9_-]{1,64}"
_CRATE_VERSION_RE = r"\d{1,6}\.\d{1,6}\.\d{1,6}(?:[-+][0-9A-Za-z.]{1,60})?"
_CRATE_NAME_FULL = re.compile(rf"^{_CRATE_NAME_RE}$")
_CRATE_VERSION_FULL = re.compile(rf"^{_CRATE_VERSION_RE}$")
_CRATE_CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")
_CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
_CARGO_INDEX_DIR_RE = re.compile(r"^index\.crates\.io-[0-9a-f]{16}$")
_CARGO_TOP_FILES = frozenset({".global-cache", ".package-cache", ".package-cache-mutate"})

# Regenerable trees: discarded after a passing check, recreated by the tool from verified bytes.
SCARB_REGENERATED = ("registry/src", "registry/std", "plugins")
CARGO_REGENERATED = ("registry/src",)


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
    """Outcome of one cache check. `failures` closes the build; `unverified` is flagged, not fatal;
    `regenerate` names the trees to discard before the first offline run."""

    verified: list[str] = field(default_factory=list)      # name@version, bytes hash equal
    unverified: list[str] = field(default_factory=list)    # name@version with no lock checksum (git)
    failures: list[str] = field(default_factory=list)      # <reason>:<subject>
    regenerate: list[str] = field(default_factory=list)    # cache-relative trees to discard

    @property
    def ok(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, list[str]]:
        return {"verified": sorted(self.verified), "unverified": sorted(self.unverified),
                "failures": sorted(self.failures), "regenerate": list(self.regenerate)}

    def merge(self, other: DepsVerification, prefix: str) -> None:
        self.verified += [f"{prefix}{x}" for x in other.verified]
        self.unverified += [f"{prefix}{x}" for x in other.unverified]
        self.failures += [f"{prefix}{x}" for x in other.failures]


# --------------------------------------------------------------------------------------------
# Lockfiles
# --------------------------------------------------------------------------------------------

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


def parse_cargo_lock(text: str) -> dict[str, str]:
    """crates.io rows of a Cargo.lock as {`<name>-<version>.crate`: sha256 hex}, tomllib only.

    Rows of other sources (path, git) have no crate file in CARGO_HOME and are skipped; a
    crates.io row without a well-formed checksum, a malformed row or two rows with one crate file
    name and different checksums raise LockFormatError.
    """
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise LockFormatError("cargo_lock_unparsable:Cargo.lock") from None
    rows = doc.get("package") or []
    if not isinstance(rows, list) or len(rows) > _MAX_ROWS:
        raise LockFormatError("cargo_lock_row_malformed:package")
    out: dict[str, str] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise LockFormatError(f"cargo_lock_row_malformed:{index}")
        name, version, source, checksum = row.get("name"), row.get("version"), row.get("source"), row.get("checksum")
        if not isinstance(name, str) or not _CRATE_NAME_FULL.match(name) or not isinstance(version, str) \
                or not _CRATE_VERSION_FULL.match(version):
            raise LockFormatError(f"cargo_lock_row_malformed:{index}")
        if source is None:
            continue                                     # the plugin crate itself (path)
        if source != _CRATES_IO:
            continue                                     # git / other: no crate file; cargo-home git/ is unexpected
        if not isinstance(checksum, str) or not _CRATE_CHECKSUM_RE.match(checksum):
            raise LockFormatError(f"cargo_lock_checksum_missing:{name}@{version}")
        crate = _safe_name(f"{name}-{version}.crate")
        if out.get(crate, checksum) != checksum:
            raise LockFormatError(f"cargo_lock_duplicate_row:{name}@{version}")
        out[crate] = checksum
    return out


# --------------------------------------------------------------------------------------------
# Read-only filesystem helpers (lstat, O_NOFOLLOW)
# --------------------------------------------------------------------------------------------

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


def _mode(path: Path) -> int | None:
    try:
        return path.lstat().st_mode
    except OSError:
        return None


def _real_dir(path: Path, rel: str, failures: list[str]) -> bool:
    """True when `path` is a real directory; a symlink or another kind fails closed; absent is False."""
    mode = _mode(path)
    if mode is None:
        return False
    if stat.S_ISLNK(mode):
        failures.append(f"symlink_in_cache:{rel}")
        return False
    if not stat.S_ISDIR(mode):
        failures.append(f"unexpected_cache_entry:{rel}")
        return False
    return True


def _dir_children(path: Path, rel: str, failures: list[str], *, name_re: re.Pattern[str] | None = None,
                  kind: str = "dir") -> list[Path]:
    """Children of a real dir `path` that are real entries of `kind` (`dir` or `file`) and match
    `name_re`; everything else (symlinks, other kinds, other names) fails closed."""
    out: list[Path] = []
    for child, mode in _entries(path):
        crel = f"{rel}/{child.name}"
        if stat.S_ISLNK(mode):
            failures.append(f"symlink_in_cache:{crel}")
        elif (kind == "dir" and not stat.S_ISDIR(mode)) or (kind == "file" and not stat.S_ISREG(mode)) \
                or (name_re is not None and not name_re.match(child.name)):
            failures.append(f"unexpected_cache_entry:{crel}")
        else:
            out.append(child)
    return out


# --------------------------------------------------------------------------------------------
# Scarb cache
# --------------------------------------------------------------------------------------------

def verify_scarb_cache(lock_text: str | None, cache_dir: Path) -> DepsVerification:
    """Check the job's scarb-cache against the pinned Scarb.lock text; see the module docstring
    for the policy. Read-only: nothing under `cache_dir` is modified."""
    result = DepsVerification(regenerate=list(SCARB_REGENERATED))
    failures = result.failures
    registry = cache_dir / "registry"

    # Top level: `.package-cache.lock` (Scarb's flock file), `registry/`, `git/` (only with git rows),
    # `plugins/` (proc-macro build dir, regenerated). Anything else is unexpected.
    top: dict[str, int] = {child.name: mode for child, mode in _entries(cache_dir)}
    for name, mode in sorted(top.items()):
        if stat.S_ISLNK(mode):
            failures.append(f"symlink_in_cache:{name}")
        elif name == ".package-cache.lock":
            if not stat.S_ISREG(mode):
                failures.append(f"unexpected_cache_entry:{name}")
        elif name in ("registry", "git", "plugins"):
            if not stat.S_ISDIR(mode):
                failures.append(f"unexpected_cache_entry:{name}")
        else:
            failures.append(f"unexpected_cache_entry:{name}")

    dl_idents = src_idents = []
    has_registry = "registry" in top and stat.S_ISDIR(top["registry"]) and not stat.S_ISLNK(top["registry"])
    if has_registry:
        for child, mode in _entries(registry):
            rel = f"registry/{child.name}"
            if stat.S_ISLNK(mode):
                failures.append(f"symlink_in_cache:{rel}")
            elif child.name not in ("dl", "src", "cache", "configs", "std") or not stat.S_ISDIR(mode):
                failures.append(f"unexpected_cache_entry:{rel}")
        if _real_dir(registry / "dl", "registry/dl", failures):
            dl_idents = _dir_children(registry / "dl", "registry/dl", failures, name_re=_IDENT_RE)
        if _real_dir(registry / "src", "registry/src", failures):
            src_idents = _dir_children(registry / "src", "registry/src", failures, name_re=_IDENT_RE)
        # Modelled: the redb index cache (content private to Scarb; a record that disagrees with
        # the lock fails Scarb's own check_checksums and the post-metadata lock comparison).
        if _real_dir(registry / "cache", "registry/cache", failures):
            _dir_children(registry / "cache", "registry/cache", failures, name_re=_REDB_RE, kind="file")
        # Modelled: registry configs, one JSON object per registry with URL templates, read offline
        # only to form cache keys.
        if _real_dir(registry / "configs", "registry/configs", failures):
            for child in _dir_children(registry / "configs", "registry/configs", failures, name_re=re.compile(r"^http$")):
                for cfg in _dir_children(child, "registry/configs/http", failures, name_re=_CONFIG_RE, kind="file"):
                    _check_registry_config(cfg, failures)
        # Regenerated: the corelib Scarb unpacks from its own binary (standard_lib.rs).
        if _real_dir(registry / "std", "registry/std", failures):
            _dir_children(registry / "std", "registry/std", failures, name_re=_STD_DIR_RE)
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
    git_rows = 0
    for pkg in packages:
        if pkg.is_registry:
            registry_rows[pkg.archive_name] = pkg
            source_dirs[pkg.source_dir_name] = pkg
        elif pkg.is_git:
            git_rows += 1
            result.unverified.append(pkg.label)
        else:
            failures.append(f"unknown_source:{pkg.label}")
    # Flagged: git checkouts exist only for git rows (their content is what `deps_unverified` names).
    if "git" in top and not stat.S_ISLNK(top["git"]) and git_rows == 0:
        failures.append("unexpected_cache_entry:git")

    # Cache -> lock: everything fetched must be a listed registry package, nothing may be a symlink.
    archives: dict[str, Path] = {}
    for ident in dl_idents:
        for entry, mode in _entries(ident):
            rel = f"registry/dl/{ident.name}/{entry.name}"
            if stat.S_ISLNK(mode):
                failures.append(f"symlink_in_cache:{rel}")
            elif entry.name not in registry_rows:
                failures.append(f"unlisted_archive:{ident.name}/{entry.name}")
            elif not stat.S_ISREG(mode):
                failures.append(f"unexpected_cache_entry:{rel}")
            elif entry.name in archives:
                failures.append(f"archive_duplicate:{registry_rows[entry.name].label}")
            else:
                archives[entry.name] = entry
    for ident in src_idents:
        for entry, mode in _entries(ident):
            rel = f"registry/src/{ident.name}/{entry.name}"
            if stat.S_ISLNK(mode):
                failures.append(f"symlink_in_cache:{rel}")
            elif entry.name not in source_dirs:
                failures.append(f"unlisted_source_dir:{ident.name}/{entry.name}")
            elif not stat.S_ISDIR(mode):
                failures.append(f"unexpected_cache_entry:{rel}")

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
    result.failures = sorted(set(result.failures))
    return result


def _check_registry_config(path: Path, failures: list[str]) -> None:
    """`registry/configs/http/<ident>.json`: a JSON object of the registry's URL templates."""
    rel = f"registry/configs/http/{path.name}"
    try:
        st = path.lstat()
        if st.st_size > 64 * 1024:
            raise ValueError("oversize")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            doc = json.loads(os.read(fd, 64 * 1024 + 1))
        finally:
            os.close(fd)
    except (OSError, ValueError):
        failures.append(f"config_unparsable:{rel}")
        return
    if not isinstance(doc, dict) or not set(doc) <= _CONFIG_KEYS or not all(
            isinstance(v, str) for k, v in doc.items() if k != "version"):
        failures.append(f"config_unparsable:{rel}")


# --------------------------------------------------------------------------------------------
# CARGO_HOME
# --------------------------------------------------------------------------------------------

def verify_cargo_home(cargo_locks: dict[str, str | None], cargo_home: Path) -> DepsVerification:
    """Check the job's cargo-home against the in-tree plugin Cargo.lock files.

    `cargo_locks` maps each `[cairo-plugin]` package dir to its pinned `Cargo.lock` text (None
    when the dir has none). Every `.crate` present must hash to a row of one of those locks; a crate
    the locks do not name, a mismatch, a lock-less plugin dir while crates are present, a symlink
    or an entry the layout does not model fails closed. A listed crate that is absent is not a
    failure: cargo stops offline on its own, and an absent crate cannot be a substituted one.
    """
    result = DepsVerification(regenerate=list(CARGO_REGENERATED))
    failures = result.failures
    top: dict[str, int] = {child.name: mode for child, mode in _entries(cargo_home)}
    for name, mode in sorted(top.items()):
        if stat.S_ISLNK(mode):
            failures.append(f"symlink_in_cache:{name}")
        elif name in _CARGO_TOP_FILES:
            if not stat.S_ISREG(mode):
                failures.append(f"unexpected_cache_entry:{name}")
        elif name == "registry":
            if not stat.S_ISDIR(mode):
                failures.append(f"unexpected_cache_entry:{name}")
        else:
            failures.append(f"unexpected_cache_entry:{name}")     # git/, bin/, config.toml, ...

    crates: dict[str, Path] = {}
    registry = cargo_home / "registry"
    if "registry" in top and stat.S_ISDIR(top["registry"]) and not stat.S_ISLNK(top["registry"]):
        for child, mode in _entries(registry):
            rel = f"registry/{child.name}"
            if stat.S_ISLNK(mode):
                failures.append(f"symlink_in_cache:{rel}")
            elif child.name == "CACHEDIR.TAG":
                if not stat.S_ISREG(mode):
                    failures.append(f"unexpected_cache_entry:{rel}")
            elif child.name not in ("cache", "index", "src") or not stat.S_ISDIR(mode):
                failures.append(f"unexpected_cache_entry:{rel}")
        if _real_dir(registry / "cache", "registry/cache", failures):
            for idx in _dir_children(registry / "cache", "registry/cache", failures, name_re=_CARGO_INDEX_DIR_RE):
                for crate in _dir_children(idx, f"registry/cache/{idx.name}", failures, kind="file"):
                    if crate.name in crates:
                        failures.append(f"crate_duplicate:{crate.name}")
                    crates[crate.name] = crate
        # Modelled: cargo's sparse-index cache; with a Cargo.lock cargo rejects an index record whose
        # checksum differs from the lock, and the crate bytes are verified here regardless.
        if _real_dir(registry / "index", "registry/index", failures):
            _dir_children(registry / "index", "registry/index", failures, name_re=_CARGO_INDEX_DIR_RE)
        # Regenerated: extracted crates (`.cargo-ok` trees), re-extracted from the verified files.
        if _real_dir(registry / "src", "registry/src", failures):
            _dir_children(registry / "src", "registry/src", failures, name_re=_CARGO_INDEX_DIR_RE)

    listed: dict[str, str] = {}
    for plugin_dir, text in sorted(cargo_locks.items()):
        label = plugin_dir or "."
        if text is None:
            if crates:
                failures.append(f"cargo_lock_missing:{label}")
            continue
        try:
            rows = parse_cargo_lock(text)
        except LockFormatError as exc:
            failures.append(f"{exc.reason}@{label}")
            continue
        for crate, checksum in rows.items():
            if listed.get(crate, checksum) != checksum:
                failures.append(f"cargo_lock_conflict:{crate}")
            listed[crate] = checksum

    for name, path in sorted(crates.items()):
        checksum = listed.get(name)
        if checksum is None:
            failures.append(f"unlisted_crate:{name}")
            continue
        digest = _sha256_regular_file(path)
        if digest is None:
            failures.append(f"crate_not_regular_file:{name}")
        elif digest != checksum:
            failures.append(f"crate_checksum_mismatch:{name}")
        else:
            result.verified.append(name.removesuffix(".crate"))

    result.verified.sort()
    result.failures = sorted(set(result.failures))
    return result


# --------------------------------------------------------------------------------------------
# Discarding regenerable trees through directory file descriptors (never following a symlink)
# --------------------------------------------------------------------------------------------

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _rm_contents(dir_fd: int) -> None:
    """Remove everything below the open directory `dir_fd`: files and symlinks are unlinked by
    name relative to the fd (a link is never resolved), subdirectories are opened O_NOFOLLOW,
    emptied the same way and removed with rmdir."""
    with os.scandir(dir_fd) as it:
        entries = [(e.name, e.is_dir(follow_symlinks=False)) for e in it]
    for name, is_dir in entries:
        if is_dir:
            child = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
            try:
                _rm_contents(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=dir_fd)
        else:
            os.unlink(name, dir_fd=dir_fd)


def discard_regenerable(root: Path, rel: str) -> tuple[bool, str | None]:
    """Remove the regenerable tree `rel` (cache-relative, e.g. `registry/src`) under `root`.

    Every path component is opened with O_DIRECTORY | O_NOFOLLOW relative to the previous
    directory descriptor; the target must be a real directory (a symlink is refused, not removed,
    with `symlink_in_cache:<rel>`; another kind with `unexpected_cache_entry:<rel>`), and nothing is
    re-resolved by path after the check. Returns (removed, failure reason): (True, None) when the
    tree was removed, (False, None) when it was absent, (False, reason) when it was refused.
    """
    parts = rel.split("/")
    if not parts or any(p in ("", ".", "..") for p in parts):
        return False, f"unexpected_cache_entry:{rel}"
    fds: list[int] = []
    try:
        try:
            fds.append(os.open(root, _DIR_FLAGS))
        except OSError:
            return False, None                                      # no cache dir: nothing to discard
        for part in parts[:-1]:
            try:
                fds.append(os.open(part, _DIR_FLAGS, dir_fd=fds[-1]))
            except FileNotFoundError:
                return False, None
            except OSError:                                        # ELOOP (symlink) / ENOTDIR
                return False, f"symlink_in_cache:{rel}"
        parent, leaf = fds[-1], parts[-1]
        try:
            st = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return False, None
        if stat.S_ISLNK(st.st_mode):
            return False, f"symlink_in_cache:{rel}"
        if not stat.S_ISDIR(st.st_mode):
            return False, f"unexpected_cache_entry:{rel}"
        target = os.open(leaf, _DIR_FLAGS, dir_fd=parent)
        try:
            _rm_contents(target)
        finally:
            os.close(target)
        os.rmdir(leaf, dir_fd=parent)
        return True, None
    except OSError as exc:
        return False, f"discard_failed:{rel}:{exc.__class__.__name__}"
    finally:
        for fd in reversed(fds):
            os.close(fd)
