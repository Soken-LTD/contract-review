"""Move family helpers: addresses, store paths, unit labels, nSLOC (plan v4 07 sections 2, 4, 12.4).

Store path rules are the RULES.md sanitizer (same rules as `adapters/evm/units.safe_store_path`):
no absolute path, no `..`, no backslash or NUL, pattern `^[A-Za-z0-9_./-]{1,200}$`.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")
_HEX64_RE = re.compile(r"^0x[0-9a-f]{64}$")
_ADDR_IN_RE = re.compile(r"^(0x)?[0-9a-fA-F]{1,64}$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def normalize_address(value: str) -> str | None:
    """`0x` + 64 lowercase hex, or None. Sui ids and Aptos addresses are 32 bytes (07 12.4)."""
    if not isinstance(value, str) or not _ADDR_IN_RE.match(value.strip()):
        return None
    raw = value.strip().lower().removeprefix("0x")
    return "0x" + raw.rjust(64, "0")


def is_full_address(value: str) -> bool:
    """Input form accepted for a deployed Sui package or Aptos account: `0x` + 64 hex (07 12.4)."""
    return isinstance(value, str) and bool(_HEX64_RE.match(value.strip().lower()))


def short_address(address: str) -> str:
    """Display form used in manifests: `0x1` for framework addresses, full hex otherwise."""
    raw = address.removeprefix("0x").lstrip("0")
    return "0x" + (raw or "0") if len(raw) <= 2 else address


def safe_store_path(path: str) -> str | None:
    """Normalized store-relative path, or None when unsafe (RULES.md untrusted data)."""
    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
        return None
    if path.startswith("/"):
        return None
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    norm = "/".join(parts)
    if not _SAFE_PATH_RE.match(norm):
        return None
    return norm


def write_tree(files: dict[str, str | bytes], dest: Path) -> list[str]:
    """Write files under dest with the sanitizer and resolve() + is_relative_to (RULES.md).
    Returns the skipped raw paths."""
    base = dest.resolve()
    skipped: list[str] = []
    for raw, content in files.items():
        norm = safe_store_path(raw)
        if norm is None:
            skipped.append(raw)
            continue
        target = (dest / norm).resolve()
        if not target.is_relative_to(base):
            skipped.append(raw)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return skipped


def unit_label(name: str, address: str | None) -> str:
    """`<name>_<h6>` (04 2.1 style): h6 from the address bytes, else from the name."""
    clean = re.sub(r"[^A-Za-z0-9_]", "_", name)[:40] or "package"
    seed = address.removeprefix("0x") if address else hashlib.sha256(clean.encode()).hexdigest()
    return f"{clean}_{seed[-6:] if address else seed[:6]}"


def candidate_sha256(files: dict[str, str]) -> str:
    """sha256 over the sorted (path, content sha256) list (base.Candidate.sha256)."""
    parts = [f"{p}:{hashlib.sha256(files[p].encode()).hexdigest()}" for p in sorted(files)]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


# -- nSLOC (07 4) --------------------------------------------------------------

_TEST_ATTR_RE = re.compile(r"#\[\s*(test|test_only)\b[^\]]*\]")


def is_in_scope(path: str, package_dirs: list[str] | tuple[str, ...] = (".",)) -> bool:
    """A `.move` file the compiler builds for one of the package dirs: `<dir>/sources/**` at any
    depth and under any directory name (review finding 2026-10-10: a `sources/tests/x.move` is
    compiled, so it is in scope). Out of scope: the package-root `tests/` dir, other packages and
    `#[test]`/`#[test_only]` items (handled by count_nsloc and the source layer)."""
    if not path.endswith(".move"):
        return False
    for d in package_dirs:
        prefix = "" if d in (".", "") else d.rstrip("/") + "/"
        if path.startswith((prefix + "sources/", prefix + "scripts/")):
            return True
    return False


def declared_modules(text: str) -> set[str]:
    """Module names declared in one source file (comments removed)."""
    return set(re.findall(r"\bmodule\s+(?:[A-Za-z0-9_]+\s*::\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*[{;]",
                          strip_comments(text)))


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments (Move block comments do not nest) and mask literal contents,
    keeping line breaks."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
        elif c == '"':
            # String and byte-string literal contents are masked (spaces, line breaks kept): rule
            # patterns and declarations never match text inside a literal.
            out.append(c)
            i += 1
            while i < n and text[i] != '"':
                step = 2 if text[i] == "\\" and i + 1 < n else 1
                out.extend("\n" if ch == "\n" else " " for ch in text[i:i + step])
                i += step
            if i < n:
                out.append('"')
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_line_ranges(code: str) -> list[tuple[int, int]]:
    """1-based inclusive line ranges of items under #[test] / #[test_only] (comments stripped)."""
    ranges: list[tuple[int, int]] = []
    for m in _TEST_ATTR_RE.finditer(code):
        start_line = code.count("\n", 0, m.start()) + 1
        i = m.end()
        depth, seen_brace = 0, False
        while i < len(code):
            ch = code[i]
            if ch == "{":
                depth += 1
                seen_brace = True
            elif ch == "}":
                depth -= 1
                if seen_brace and depth == 0:
                    break
            elif ch == ";" and not seen_brace:
                break
            i += 1
        ranges.append((start_line, code.count("\n", 0, min(i, len(code))) + 1))
    return ranges


def count_nsloc(text: str) -> int:
    """Lines minus blank and comment-only lines, minus #[test]/#[test_only] items (07 4)."""
    code = strip_comments(text)
    excluded: set[int] = set()
    for a, b in test_line_ranges(code):
        excluded.update(range(a, b + 1))
    return sum(1 for i, line in enumerate(code.splitlines(), 1) if line.strip() and i not in excluded)
