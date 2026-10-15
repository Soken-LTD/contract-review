"""Trust scan for Solana candidates (06 section 3.3.4).

Sets untrusted_inputs = True when the source tree contains patterns that could
forge a tier-A outcome. Fail closed — any Cargo.toml that cannot be parsed is
untrusted. Any binary content at any path is untrusted.

Security properties:
- Git deps require rev = <40-hex>; tag/branch = unpinned (untrusted).
- Path deps outside the tree (absolute or ../): untrusted.
- .cargo/config* and rust-toolchain* matched at any tree depth: untrusted.
- ELF magic (\x7fELF) or non-UTF-8 content at any path: untrusted.
- include_bytes!/include_str! of any non-.rs file: untrusted.
- package.build != build.rs or build.rs present at all: untrusted (06 3.3).
- proc-macro crates present: untrusted (06 3.3).
"""

from __future__ import annotations

import json
import posixpath
import re
import tomllib
from pathlib import Path, PurePosixPath

# ---------------------------------------------------------------------------
# Path-level pattern checks
# ---------------------------------------------------------------------------

# .cargo/config or .cargo/config.toml at any depth
_CARGO_CONFIG_RE = re.compile(r'(?:^|/)\.cargo/config(?:\.toml)?$', re.IGNORECASE)

# rust-toolchain or rust-toolchain.toml at any depth
_RUST_TOOLCHAIN_RE = re.compile(r'(?:^|/)rust-toolchain(?:\.toml)?$', re.IGNORECASE)

# Pre-compiled artifact extensions (belt-and-suspenders; content check is primary)
_ARTIFACT_EXTS = frozenset({".o", ".a", ".so", ".elf"})

# ELF magic bytes
_ELF_MAGIC = b"\x7fELF"

# include_bytes!/include_str! of any non-source file (not .rs, .toml, .md, .txt)
_SAFE_INCLUDE_EXTS = frozenset({".rs", ".toml", ".md", ".txt", ".json", ".yaml", ".yml"})
_INCLUDE_ANY_RE = re.compile(r'include_(?:bytes|str)!\s*\(\s*"([^"]+)"', re.MULTILINE)

# build.rs forbidden directives
_BUILD_RS_FORBIDDEN = re.compile(
    r'cargo:rustc-(?:link|flags|env=RUSTFLAGS)|target/deploy',
    re.MULTILINE,
)

# #[link] attribute
_LINK_ATTR_RE = re.compile(r'#\[link[\s\(]', re.MULTILINE)

# proc-macro crate indicator: [lib] proc-macro = true OR proc_macro = true (Cargo accepts both spellings)
# NOTE: we use structural tomllib parsing in _check_cargo_toml; this regex is a belt-and-suspenders fallback
_PROC_MACRO_RE = re.compile(r'proc[-_]macro\s*=\s*true', re.MULTILINE)

# asm!/global_asm!
_ASM_RE = re.compile(r'\b(?:global_asm|asm)!\s*\(', re.MULTILINE)
_ASM_THRESHOLD = 20

# Valid rev: exactly 40 hex chars
_VALID_REV_RE = re.compile(r'^[0-9a-f]{40}$', re.IGNORECASE)

# Detects non-ASCII characters (unicode lookalikes) in paths/names that should be ASCII-only
_NON_ASCII_RE = re.compile(r'[^\x00-\x7f]')

# Windows-style backslash in a path string
_BACKSLASH_IN_PATH_RE = re.compile(r'\\')


# ---------------------------------------------------------------------------
# Path resolution for Cargo.toml values
# ---------------------------------------------------------------------------

def _resolve_tree_path(crate_dir: str, raw_val: str) -> str | None:
    """Resolve a Cargo.toml path value relative to crate_dir.

    Returns the source-root-relative normalized path when the result stays
    within the source root, or None when it escapes (starts with '..' or '/').

    Security contract: callers must check raw_val for backslash and non-ASCII
    BEFORE calling this function — those bypass categories are not handled here.

    Args:
        crate_dir: source-root-relative directory of the Cargo.toml, e.g.
                   "programs/counter" or "." for a root-level file.
        raw_val:   path string taken from Cargo.toml content.
    """
    if not raw_val:
        return None
    joined = posixpath.join(crate_dir, raw_val)
    normalized = posixpath.normpath(joined)
    # Escape if absolute or has a leading '..' component after normalization
    if normalized.startswith(("/", "..")):
        return None
    return normalized


# ---------------------------------------------------------------------------
# Structural Cargo.toml parsing
# ---------------------------------------------------------------------------

def _dep_table_names() -> list[str]:
    return ["dependencies", "dev-dependencies", "build-dependencies"]


def _extract_dep_tables(parsed: dict) -> list[tuple[str, dict]]:
    """Yield (table_name, dep_dict) for all dependency tables."""
    tables: list[tuple[str, dict]] = []

    for name in _dep_table_names():
        if name in parsed and isinstance(parsed[name], dict):
            tables.append((name, parsed[name]))

    ws = parsed.get("workspace", {})
    if isinstance(ws, dict):
        for name in _dep_table_names():
            if name in ws and isinstance(ws[name], dict):
                tables.append((f"workspace.{name}", ws[name]))

    target_map = parsed.get("target", {})
    if isinstance(target_map, dict):
        for target_name, target_val in target_map.items():
            if not isinstance(target_val, dict):
                continue
            for name in _dep_table_names():
                if name in target_val and isinstance(target_val[name], dict):
                    tables.append((f"target.{target_name}.{name}", target_val[name]))

    return tables


def _check_dep_spec(
    dep_spec: object,
    dep_name: str,
    table_name: str,
    cargo_path: str,
    crate_dir: str = ".",
) -> list[str]:
    reasons: list[str] = []
    if isinstance(dep_spec, str):
        return reasons
    if not isinstance(dep_spec, dict):
        return reasons

    git_url = dep_spec.get("git")
    path_val = dep_spec.get("path")

    if git_url is not None:
        rev = dep_spec.get("rev")
        if rev is None or not _VALID_REV_RE.match(str(rev)):
            reasons.append(
                f"git dep '{dep_name}' in {cargo_path}[{table_name}] "
                f"missing or invalid rev (rev={rev!r}); must be 40-hex"
            )

    if path_val is not None:
        path_str = str(path_val)
        # Character-level checks first (backslash/unicode bypass categories)
        if _BACKSLASH_IN_PATH_RE.search(path_str):
            reasons.append(
                f"backslash in path dep '{dep_name}' in {cargo_path}[{table_name}]: {path_str!r}"
            )
        elif _NON_ASCII_RE.search(path_str):
            reasons.append(
                f"non-ASCII (unicode lookalike?) in path dep '{dep_name}' in {cargo_path}[{table_name}]: {path_str!r}"
            )
        else:
            # Resolve against the crate dir to detect tree escape.
            # This catches absolute paths, leading-'..', and complex traversals
            # (e.g. "valid/../../../outside") regardless of the raw string form.
            resolved = _resolve_tree_path(crate_dir, path_str)
            if resolved is None:
                reasons.append(
                    f"path dep '{dep_name}' in {cargo_path}[{table_name}] "
                    f"escapes source root: {path_str!r}"
                )

    return reasons


def _check_cargo_toml(path: str, content: str, crate_dir: str = ".") -> list[str]:
    """Parse Cargo.toml structurally; fail closed on parse error.

    crate_dir: source-root-relative directory containing this Cargo.toml,
               used to resolve relative path values against the source root.
    """
    reasons: list[str] = []
    try:
        parsed = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        reasons.append(f"Cargo.toml parse error in {path}: {exc}")
        return reasons

    # Check [lib] table: proc-macro AND lib path escape.
    # Cargo accepts both "proc-macro" and "proc_macro" spellings; tomllib keeps
    # them as written so we must check both.
    lib_table = parsed.get("lib", {})
    if isinstance(lib_table, dict):
        # A proc-macro crate in the reviewed tree runs code at compile time and can steer the
        # output: tier A off (build still sandboxed). Both spellings are accepted by Cargo.
        if lib_table.get("proc-macro") or lib_table.get("proc_macro"):
            reasons.append(f"proc-macro crate in {path}")
        # [lib] path can point outside the tree
        lib_path_val = lib_table.get("path")
        if lib_path_val is not None:
            lib_path_str = str(lib_path_val)
            if _BACKSLASH_IN_PATH_RE.search(lib_path_str) or _NON_ASCII_RE.search(lib_path_str):
                reasons.append(
                    f"[lib].path has invalid characters in {path}: {lib_path_str!r}"
                )
            else:
                resolved = _resolve_tree_path(crate_dir, lib_path_str)
                if resolved is None:
                    reasons.append(
                        f"[lib].path escapes source root in {path}: {lib_path_str!r}"
                    )

    # Check package.build.
    # build = "build.rs"  → standard; ok
    # build = "x.rs"     → custom build script; flag
    # build = true        → Cargo auto-detects build.rs; flag (build.rs may exist; file scan catches it)
    # build = false       → build script disabled; ok (not a custom script)
    pkg = parsed.get("package", {})
    if isinstance(pkg, dict):
        build_script = pkg.get("build")
        if build_script is not None:
            if isinstance(build_script, bool):
                if build_script is True:
                    # auto-detect build.rs; treat same as having build.rs present
                    reasons.append(
                        f"package.build = true in {path} (auto-detects build.rs; flagged as build script)"
                    )
                # build = false → disabled, not a custom script; skip
            elif isinstance(build_script, str) and build_script != "build.rs":
                reasons.append(
                    f"non-standard build script '{build_script}' in {path}[package.build]"
                )

    # Check workspace members: resolve each against crate_dir to detect tree escape.
    ws = parsed.get("workspace", {})
    if isinstance(ws, dict):
        members = ws.get("members", [])
        if isinstance(members, list):
            for member_path in members:
                if not isinstance(member_path, str):
                    continue
                if _BACKSLASH_IN_PATH_RE.search(member_path) or _NON_ASCII_RE.search(member_path):
                    reasons.append(
                        f"workspace member has invalid characters in {path}: {member_path!r}"
                    )
                else:
                    resolved = _resolve_tree_path(crate_dir, member_path)
                    if resolved is None:
                        reasons.append(
                            f"workspace member escapes source root in {path}: {member_path!r}"
                        )

    for table_name, dep_table in _extract_dep_tables(parsed):
        for dep_name, dep_spec in dep_table.items():
            reasons.extend(_check_dep_spec(dep_spec, dep_name, table_name, path, crate_dir))

    patch = parsed.get("patch", {})
    if isinstance(patch, dict):
        for registry, deps in patch.items():
            if not isinstance(deps, dict):
                continue
            for dep_name, dep_spec in deps.items():
                reasons.extend(
                    _check_dep_spec(dep_spec, dep_name, f"patch.{registry}", path, crate_dir)
                )

    return reasons


# ---------------------------------------------------------------------------
# Content-level checks
# ---------------------------------------------------------------------------

def _is_binary(content: object) -> bool:
    """Return True if content is binary (bytes with ELF magic, or non-decodable str)."""
    if isinstance(content, bytes):
        return content[:4] == _ELF_MAGIC or _has_null_bytes(content)
    if isinstance(content, str):
        return _ELF_MAGIC in content.encode("latin-1", errors="replace")[:4]
    return False


def _has_null_bytes(data: bytes) -> bool:
    return b"\x00" in data[:1024]


def _check_include_macros(content: str, path: str) -> list[str]:
    """Flag include_bytes!/include_str! of non-source files."""
    reasons: list[str] = []
    for m in _INCLUDE_ANY_RE.finditer(content):
        included_path = m.group(1)
        ext = PurePosixPath(included_path).suffix.lower()
        if ext not in _SAFE_INCLUDE_EXTS:
            reasons.append(
                f"include_bytes!/include_str! of non-source file '{included_path}' in {path}"
            )
    return reasons


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan_candidate_files(
    files: dict[str, str], unread_paths: list[str] | tuple[str, ...] = (),
) -> tuple[bool, list[str]]:
    """Scan a candidate's file dict for patterns that could forge tier A (06 3.3.4).

    unread_paths: files present in the fetched tree that were not read into `files` (objects, ELF,
    `.cargo/config*`; fetch._walk_source_files). Each one is untrusted: the scan never fails open
    because the walker skipped a binary.

    Returns (untrusted: bool, reasons: list[str]).

    Fail closed on any match. Binary content at any path is untrusted.
    Unparseable Cargo.toml is untrusted.
    build.rs present at all is untrusted (06 3.3: build scripts run in sandbox only).

    Path normalization: every path is first normalized via safe_store_path.
    If normalization fails OR norm != raw (path had leading ./, duplicate slashes etc.),
    the path-level checks run on the NORMALIZED path to prevent bypass via path tricks.
    """
    # Import here to avoid circular import at module level
    try:
        from soken_review.adapters.solana.units import safe_store_path as _ssp
    except ImportError:
        _ssp = None  # fallback: no normalization

    reasons: list[str] = [f"committed binary or cargo config not read: {p}" for p in unread_paths]
    crate_asm_counts: dict[str, int] = {}

    for raw_path, content in files.items():
        # Normalize path; reject if safe_store_path returns None OR if the
        # normalised form differs from the raw path (./x, a//b, a/../b).
        # This ensures every rule runs on the canonical path form and no
        # path variant can slip past a rule by using a dirty representation.
        if _ssp is not None:
            norm = _ssp(raw_path)
            if norm is None or norm != raw_path:
                reasons.append(f"unsafe_path:{raw_path}")
                continue
        else:
            norm = raw_path

        # All path-level checks run on normalized path
        path = norm

        # .cargo/config* at any depth
        if _CARGO_CONFIG_RE.search(path):
            reasons.append(f"cargo config file: {path}")

        # rust-toolchain* naming another toolchain (06 3.3.4). The build pins RUSTUP_TOOLCHAIN to the
        # image's toolchain, so the file only matters when it names a different concrete release.
        if _RUST_TOOLCHAIN_RE.search(path) and _names_other_toolchain(content):
            reasons.append(f"rust-toolchain names another toolchain: {path}")

        # Binary content check (ELF magic, null bytes in first 1KB)
        if isinstance(content, bytes):
            if _is_binary(content):
                reasons.append(f"binary/ELF content: {path}")
        elif isinstance(content, str):
            # Check for ELF magic encoded as latin-1 in string (shouldn't happen but be safe)
            raw_start = content[:4].encode("latin-1", errors="replace")
            if raw_start == _ELF_MAGIC:
                reasons.append(f"ELF magic in string content: {path}")

        # Pre-compiled artifact by extension (belt-and-suspenders)
        if PurePosixPath(path).suffix.lower() in _ARTIFACT_EXTS:
            reasons.append(f"pre-compiled artifact by extension: {path}")

        path_name = PurePosixPath(path).name

        # build.rs (06 3.3.4 "tier A cannot be forged"): a substring denylist over Rust is bypassable
        # (strings built at run time), so any non-empty build script removes tier A. The build
        # itself still runs in the sandbox; only provenance becomes not_checkable.
        if path_name.lower() == "build.rs" and not (isinstance(content, str) and _EMPTY_BUILD_RS.match(content)):
            reasons.append(f"build.rs present: {path}")

        # .rs files
        if path.lower().endswith(".rs") and isinstance(content, str):
            reasons.extend(_check_include_macros(content, path))
            if _LINK_ATTR_RE.search(content):
                reasons.append(f"#[link] attribute in: {path}")
            asm_count = len(_ASM_RE.findall(content))
            if asm_count > 0:
                crate_key = _crate_key(path)
                crate_asm_counts[crate_key] = crate_asm_counts.get(crate_key, 0) + asm_count

        # Cargo.toml: structural check, fail closed on parse error.
        # Match case-insensitively (Cargo.TOML, CARGO.toml, cargo.toml all flagged).
        # Pass the crate_dir so path values can be resolved against the source root.
        if path_name.lower() == "cargo.toml" and isinstance(content, str):
            crate_dir = str(PurePosixPath(path).parent)
            reasons.extend(_check_cargo_toml(path, content, crate_dir))

    # asm counts
    for crate_key, count in crate_asm_counts.items():
        if count > _ASM_THRESHOLD:
            reasons.append(f"asm!/global_asm! {count} > {_ASM_THRESHOLD} in crate: {crate_key}")

    return bool(reasons), reasons


_EMPTY_BUILD_RS = re.compile(r"^\s*fn\s+main\s*\(\s*\)\s*\{\s*\}\s*$")
_IMAGE_MAP = Path(__file__).parent / "data" / "image_map.json"
_TOOLCHAIN_KEYS = {"channel", "components", "targets", "profile"}


def _active_toolchains() -> set[str]:
    """Rust releases of the pinned build images ("1.81.0" from "1.81.0-x86_64-...")."""
    images = json.loads(_IMAGE_MAP.read_text())["images"].values()
    return {str(i.get("active_toolchain", "")).split("-")[0] for i in images if i.get("active_toolchain")}


def _names_other_toolchain(content: object) -> bool:
    """True when the file pins a concrete toolchain no image uses, or cannot be read (fail closed)."""
    if not isinstance(content, str):
        return True
    text = content.strip()
    if not text:
        return False
    channel: str | None
    try:
        parsed = tomllib.loads(text)
        table = parsed.get("toolchain") or {}
        if not isinstance(table, dict) or set(parsed) - {"toolchain"} or set(table) - _TOOLCHAIN_KEYS:
            return True  # `path` (custom toolchain dir) or anything rustup reads beyond the known keys
        channel = str(table.get("channel", "")) or None
    except tomllib.TOMLDecodeError:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if len(lines) != 1:
            return True
        channel = lines[0]
    if channel is None or channel in ("stable", "beta", "nightly"):
        return False
    return channel.split("-")[0] not in _active_toolchains()


def _crate_key(path: str) -> str:
    parts = path.split("/")
    if len(parts) >= 3 and parts[0] in ("programs", "contracts", "src"):
        return parts[1] if len(parts) > 2 else "root"
    return parts[0] if parts else "root"
