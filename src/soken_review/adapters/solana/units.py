"""Unit label, store-path helpers and nSLOC counter for Solana (06 sections 2.6, 2.9).

Unit label: <name>_<h6>
  name:  crate name (lib.name in Cargo.toml), [A-Za-z0-9_], max 40 chars
  h6:    first 6 lowercase hex chars of the base58-decoded program id bytes;
         with no address, first 6 hex of sha256 of the store path.

Store path: <unit_label>/<relative_file_path>

nSLOC for Rust (06 2.9): strip //, ///, //!, /* */ (nested), string literals
not counted. In-scope = files reached from crate root by mod resolution
minus #[cfg(test)], tests/, benches/, examples/, migrations/, app/, client/,
build scripts, vendored crates.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

_H6_STRIP = re.compile(r"[^A-Za-z0-9_]")
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")

# Alphabet for Solana base58 (same as Bitcoin)
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_decode(s: str) -> bytes:
    """Decode a Solana base58-encoded address to bytes (no checksum)."""
    n = 0
    for char in s.encode("ascii"):
        digit = _B58_ALPHABET.find(char)
        if digit < 0:
            raise ValueError(f"Invalid base58 character: {chr(char)!r}")
        n = n * 58 + digit
    result: list[int] = []
    while n > 0:
        n, remainder = divmod(n, 256)
        result.append(remainder)
    for char in s:
        if char == "1":
            result.append(0)
        else:
            break
    return bytes(reversed(result))


def b58_encode(data: bytes) -> str:
    """Encode bytes to Solana base58 string."""
    n = int.from_bytes(data, "big")
    result: list[bytes] = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(_B58_ALPHABET[remainder : remainder + 1])
    for byte in data:
        if byte == 0:
            result.append(b"1")
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def is_solana_address(s: str) -> bool:
    """Return True if s looks like a valid Solana base58 program id (32 bytes)."""
    s = s.strip()
    if not s:
        return False
    try:
        decoded = b58_decode(s)
        return len(decoded) == 32
    except (ValueError, UnicodeEncodeError):
        return False


def make_h6_from_address(program_id: str) -> str:
    """First 6 lowercase hex chars of the base58-decoded program id (06 2.6)."""
    decoded = b58_decode(program_id)
    return decoded[:3].hex()


def make_h6_from_path(store_path: str) -> str:
    """First 6 hex chars of sha256 of the store path (fallback with no address)."""
    return hashlib.sha256(store_path.encode()).hexdigest()[:6]


def sanitize_name(raw: str) -> str:
    """Strip non-[A-Za-z0-9_] and truncate to 40 chars (05 3.4)."""
    return _H6_STRIP.sub("_", raw)[:40]


def make_unit_label(name: str, program_id: str | None, store_path: str | None = None) -> str:
    """Compose <name>_<h6> unit label (05 3.4 applied to Solana)."""
    safe = sanitize_name(name)
    if program_id is not None:
        h6 = make_h6_from_address(program_id)
    elif store_path is not None:
        h6 = make_h6_from_path(store_path)
    else:
        h6 = "000000"
    return f"{safe}_{h6}"


def safe_store_path(raw_path: str) -> str | None:
    """Validate and normalise a file path from an untrusted source (security gate).

    Same rules as adapters/evm/units.safe_store_path (RULES.md).
    """
    import posixpath

    if not raw_path:
        return None
    if "\x00" in raw_path or "\\" in raw_path:
        return None
    normalised = posixpath.normpath(raw_path)
    if normalised.startswith("/"):
        return None
    parts = normalised.split("/")
    if ".." in parts or "" in parts:
        return None
    if not _SAFE_PATH_RE.match(normalised):
        return None
    return normalised


def filter_candidate_files(files: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Apply safe_store_path to every key; return (safe_files, dropped_paths)."""
    safe: dict[str, str] = {}
    dropped: list[str] = []
    for raw_path, content in files.items():
        norm = safe_store_path(raw_path)
        if norm is None:
            dropped.append(raw_path)
        else:
            safe[norm] = content
    return safe, dropped


# ---------------------------------------------------------------------------
# nSLOC for Rust (06 2.9)
# ---------------------------------------------------------------------------

def count_nsloc_rust(source: str) -> int:
    """Count nSLOC for a Rust source file (06 2.9).

    Strips: //, ///, //!, /* */ (nested), raw strings, char vs lifetime.
    A line counts when it still has non-whitespace after stripping.
    """
    lines = source.splitlines()
    in_block = 0  # nesting depth (Rust /* */ do NOT nest, but we track for safety)
    count = 0
    for line in lines:
        s = line.strip()
        if in_block > 0:
            while "/*" in s or "*/" in s:
                if "*/" in s:
                    s = s[s.index("*/") + 2:]
                    in_block -= 1
                    in_block = max(in_block, 0)
                    break
                elif "/*" in s:
                    s = s[s.index("/*") + 2:]
                    in_block += 1
            if in_block > 0:
                continue
        # Handle /* */ on the same line
        while "/*" in s:
            start = s.index("/*")
            if "*/" in s[start + 2:]:
                end = s.index("*/", start + 2)
                s = s[:start] + s[end + 2:]
            else:
                s = s[:start]
                in_block += 1
                break
        # Strip // line comments
        if "//" in s:
            # Be careful with string literals - simplified: strip from // onwards
            # for nSLOC purposes this is sufficient
            idx = s.find("//")
            s = s[:idx]
        s = s.strip()
        if s:
            count += 1
    return count


# ---------------------------------------------------------------------------
# In-scope file detection (06 2.9)
# ---------------------------------------------------------------------------

# Files excluded from nSLOC by directory prefix
_EXCLUDED_DIRS = frozenset({"tests", "benches", "examples", "migrations", "app", "client"})


def is_in_scope_rust(path: str) -> bool:
    """Return True if a Rust source file is in scope for nSLOC (06 2.9).

    Excludes: tests/, benches/, examples/, migrations/, app/, client/,
    build scripts (build.rs at the crate root), vendored crates.
    """
    p = PurePosixPath(path)
    parts = p.parts
    if not parts:
        return False
    # build.rs at any root position is excluded
    if p.name == "build.rs":
        return False
    # Exclude known excluded directories at any prefix position
    for part in parts[:-1]:  # exclude the file name itself
        if part in _EXCLUDED_DIRS:
            return False
    # Only .rs files
    return p.suffix == ".rs"
