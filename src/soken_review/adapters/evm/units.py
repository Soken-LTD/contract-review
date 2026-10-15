"""Unit label and store-path helpers, nSLOC counter (05 section 3.4).

unit_label = <name>_<h6>
  name: contract/program/module name, [A-Za-z0-9_], at most 40 chars
  h6:   first 6 lowercase hex chars of the address bytes (EVM: 20-byte addr)
        or, with no address, first 6 hex of sha256 of the entry file store path

Store path: <unit_label>/<relative_file_path>
  A file with the same sha256 in every unit is stored once under shared/<path>.

nSLOC: source lines with comments and blanks removed.
  Lines starting with // or /* ... */ blocks are stripped. Empty lines removed.
  Vendored library files matching lib_hashes.json are counted as "library" (not counted).
"""

from __future__ import annotations

import hashlib
import re

_H6_STRIP = re.compile(r"[^A-Za-z0-9_]")
_COMMENT_LINE = re.compile(r"^\s*(//|/\*|\*)")
_BLANK = re.compile(r"^\s*$")

# Allowlist for verified-source file paths (03 path pattern): printable ASCII,
# no traversal components, no absolute path, no null bytes, no backslash.
# ^[A-Za-z0-9_./-]{1,200}$ applied AFTER posixpath normalisation.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9@_./-]{1,200}$")  # @: npm scopes (@openzeppelin/...)


def make_h6(address: str) -> str:
    """Return the first 6 lowercase hex chars of the 20-byte address (05 3.4).

    address: 0x-prefixed hex string (EVM checksum or lowercase).
    """
    raw = address.lower().lstrip("0x").replace(" ", "")
    # address bytes are the last 40 hex chars (20 bytes)
    if len(raw) >= 40:
        raw = raw[-40:]
    return raw[:6]


def make_h6_from_path(store_path: str) -> str:
    """First 6 hex chars of sha256 of the store path (fallback with no address)."""
    digest = hashlib.sha256(store_path.encode()).hexdigest()
    return digest[:6]


def sanitize_name(raw_name: str) -> str:
    """Strip non-[A-Za-z0-9_] chars, truncate to 40 chars (05 3.4)."""
    cleaned = _H6_STRIP.sub("_", raw_name)
    return cleaned[:40]


def make_unit_label(name: str, address: str | None, store_path: str | None = None) -> str:
    """Compose <name>_<h6> unit label (05 3.4).

    Example: GBLIN_c2181d for Base 0xc2181d975c05c8c724b334bcED0764c0b86B1D53
    """
    safe = sanitize_name(name)
    if address is not None:
        h6 = make_h6(address)
    elif store_path is not None:
        h6 = make_h6_from_path(store_path)
    else:
        h6 = "000000"
    return f"{safe}_{h6}"


def resolve_collision(label: str, existing: set[str]) -> str:
    """Append _2, _3, ... if label already in existing (05 3.4)."""
    if label not in existing:
        return label
    i = 2
    while True:
        candidate = f"{label}_{i}"
        if candidate not in existing:
            return candidate
        i += 1


def store_path(unit_label: str, relative_path: str) -> str:
    """Compose store path: <unit_label>/<relative_path> (05 3.4)."""
    return f"{unit_label}/{relative_path}"


def shared_path(relative_path: str) -> str:
    """Shared file store path for files identical across units."""
    return f"shared/{relative_path}"


def safe_store_path(raw_path: str) -> str | None:
    """Validate and normalise a file path from an untrusted source (security gate).

    Rejects:
      - absolute paths (starting with /)
      - paths containing .. segments (after posixpath normalisation)
      - backslashes (Windows traversal)
      - NUL bytes
      - empty segments (double slashes after normalisation)
      - anything outside ^[A-Za-z0-9@_./-]{1,200}$ after normalisation

    Returns the normalised path string, or None if rejected.
    Dropped paths must be recorded by the caller as a candidate-level warning.
    """
    import posixpath

    if not raw_path:
        return None
    # Reject NUL bytes and backslashes immediately
    if "\x00" in raw_path or "\\" in raw_path:
        return None
    # Normalise (collapses ./, removes trailing /, squashes //)
    normalised = posixpath.normpath(raw_path)
    # After normalisation: reject absolute paths
    if normalised.startswith("/"):
        return None
    # Reject any remaining .. component
    parts = normalised.split("/")
    if ".." in parts:
        return None
    # Reject empty segments (can happen with paths like "a//b")
    if "" in parts:
        return None
    # Allowlist character check
    if not _SAFE_PATH_RE.match(normalised):
        return None
    return normalised


def filter_candidate_files(files: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Apply safe_store_path to every key in a candidate files dict.

    Returns (safe_files, dropped_paths) — dropped_paths is the list of rejected keys
    to record as a candidate-level warning (security gate, never silently dropped).
    """
    safe: dict[str, str] = {}
    dropped: list[str] = []
    for raw_path, content in files.items():
        norm = safe_store_path(raw_path)
        if norm is None:
            dropped.append(raw_path)
        else:
            safe[norm] = content
    return safe, dropped


def count_nsloc(source: str) -> int:
    """Count non-blank, non-comment source lines (05 3.4 nSLOC rule).

    Strips single-line // comments and lines that are part of /* */ block comments.
    Does not parse inline comments (e.g. x = 1; // comment) — full line only.
    """
    lines = source.splitlines()
    in_block = False
    count = 0
    for line in lines:
        stripped = line.strip()
        if in_block:
            if "*/" in stripped:
                in_block = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped[2:]:
                in_block = True
            continue
        if stripped.startswith("//"):
            continue
        if not stripped:
            continue
        count += 1
    return count
