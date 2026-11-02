"""Unit label and store-path helpers for the TON adapter (plan v4 06 section 2.6).

unit_label = <name>_<h6>
  name: contract/file name, [A-Za-z0-9_], at most 40 chars
  h6:   first 6 lowercase hex chars of the raw address account bytes (64-hex string)
        or, with no address, first 6 hex of sha256 of the entry file store path

Store path rule: <unit_label>/<relative_file_path>
Path safety: same allowlist as evm/units.safe_store_path  (RULES.md §3)
"""

from __future__ import annotations

import hashlib
import posixpath
import re

_H6_STRIP = re.compile(r"[^A-Za-z0-9_]")

# Allowlist from RULES.md §3: same as evm/units.safe_store_path
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")


def make_h6(raw_address: str) -> str:
    """First 6 lowercase hex chars of the account-id part of a raw TON address.

    raw_address: '-1:abcdef...' (64-hex account id after the colon)
    Falls back to zeros if the format is unexpected.
    """
    if ":" in raw_address:
        account = raw_address.split(":", 1)[1].lower()
        if len(account) >= 6:
            return account[:6]
    return "000000"


def make_h6_from_path(store_path: str) -> str:
    """First 6 hex chars of sha256 of a store path (fallback when no address)."""
    return hashlib.sha256(store_path.encode()).hexdigest()[:6]


def sanitize_name(raw: str) -> str:
    """Strip non-[A-Za-z0-9_] and truncate to 40 chars."""
    return _H6_STRIP.sub("_", raw)[:40]


def make_unit_label(name: str, raw_address: str | None, store_path: str | None = None) -> str:
    """Compose <name>_<h6> unit label (plan 06 2.6, 05 3.4)."""
    safe = sanitize_name(name)
    if raw_address is not None:
        h6 = make_h6(raw_address)
    elif store_path is not None:
        h6 = make_h6_from_path(store_path)
    else:
        h6 = "000000"
    return f"{safe}_{h6}"


def safe_store_path(raw_path: str) -> str | None:
    """Validate and normalise a file path from an untrusted source (RULES.md §3).

    Rejects absolute paths, .., backslashes, NUL bytes, empty segments,
    anything outside ^[A-Za-z0-9_./-]{1,200}$.
    Returns the normalised path or None.
    """
    if not raw_path:
        return None
    if "\x00" in raw_path or "\\" in raw_path:
        return None
    normalised = posixpath.normpath(raw_path)
    if normalised.startswith("/"):
        return None
    parts = normalised.split("/")
    if ".." in parts:
        return None
    if "" in parts:
        return None
    if not _SAFE_PATH_RE.match(normalised):
        return None
    return normalised


def filter_candidate_files(files: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Apply safe_store_path to every key. Returns (safe_files, dropped_paths)."""
    safe: dict[str, str] = {}
    dropped: list[str] = []
    for raw_path, content in files.items():
        norm = safe_store_path(raw_path)
        if norm is None:
            dropped.append(raw_path)
        else:
            safe[norm] = content
    return safe, dropped


def count_nsloc_ton(source: str, language: str) -> int:
    """Count nSLOC for FunC, Tact, or Tolk (plan 06 2.9).

    FunC: ;; single-line, {- -} nested block comments
    Tact/Tolk: // single-line, /* */ non-nested block comments
    """
    lines = source.splitlines()
    count = 0
    in_block = False
    nest_level = 0

    if language == "func":
        # FunC: {- -} nested block comments, ;; single-line
        for line in lines:
            stripped = line.strip()
            code_on_line = False
            text = stripped
            j = 0
            while j < len(text):
                if not in_block and text[j:j+2] == "{-":
                    in_block = True
                    nest_level = 1
                    j += 2
                    continue
                if in_block:
                    if text[j:j+2] == "{-":
                        nest_level += 1
                        j += 2
                        continue
                    if text[j:j+2] == "-}":
                        nest_level -= 1
                        if nest_level == 0:
                            in_block = False
                        j += 2
                        continue
                    j += 1
                    continue
                # not in block
                if text[j:j+2] == ";;":
                    break  # rest is comment
                code_on_line = True
                j += 1
            if code_on_line and not in_block:
                count += 1
            elif not in_block and text and not text.startswith(";;") and ";;" not in text:
                # line had only non-comment content
                has_code = bool(text.replace(" ", "").replace("\t", ""))
                if has_code and not text.startswith(";;"):
                    # Re-check: after stripping ;; comment
                    before_comment = text.split(";;", 1)[0].strip() if ";;" in text else text
                    if before_comment:
                        count += 1
    else:
        # Tact / Tolk: // single-line, /* */ non-nested
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


# ── standard library files (blind round 5b, 2026-10-31) ───────────────────
# 26 of the 27 multisig v2 leads sat on imports/stdlib.fc, the FunC standard library: asm prototypes
# of TVM instructions and send-mode constants, which the rule pack reads as sends, auth checks and
# gas loops. The file ships with the toolchain, not with the project's logic, so it yields no leads
# and is pinned as a dependency (readable and searchable, out of scope). A file counts only when its
# name (or the verifier manifest's isStdLib flag) says standard library AND its code is asm
# declarations, constants and pure inline helpers (the newer stdlib's slice and builder helpers):
# a function body that sends, reserves, commits or sets code or data, or an `impure` function with
# a body, keeps the file in scope with its leads.
_STDLIB_NAME = re.compile(r"^stdlib[A-Za-z0-9_.-]*\.(fc|func)$", re.IGNORECASE)
_FUNC_LINE_COMMENT = re.compile(r";;[^\n]*")
_SIDE_EFFECT = re.compile(r"\b(send_raw_message|set_code|set_data|accept_message|raw_reserve(?:_extra)?|commit|"
                          r"set_c3|emit_log|send_message|set_lib_code|change_lib)\b")


def _strip_func_comments(text: str) -> str:
    """FunC source without `;;` line comments and (nested) `{- -}` block comments."""
    out: list[str] = []
    depth, i, n = 0, 0, len(text)
    while i < n:
        if text.startswith("{-", i):
            depth += 1
            i += 2
        elif depth and text.startswith("-}", i):
            depth -= 1
            i += 2
        elif depth:
            i += 1
        else:
            j = text.find("{-", i)
            j = n if j < 0 else j
            out.append(text[i:j])
            i = j
    return _FUNC_LINE_COMMENT.sub("", "".join(out))


def _bodies_are_pure(code: str) -> bool:
    """No top-level function body with a side-effect primitive, and no `impure` function with a body."""
    i, n = 0, len(code)
    while True:
        j = code.find("{", i)
        if j < 0:
            return True
        head = code[max(code.rfind(";", 0, j), code.rfind("}", 0, j)) + 1:j]
        depth, k = 0, j
        while k < n:
            if code[k] == "{":
                depth += 1
            elif code[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        if depth != 0 or re.search(r"\bimpure\b", head) or _SIDE_EFFECT.search(code[j:k + 1]):
            return False
        i = k + 1


def is_stdlib_file(path: str, text: str, flagged: bool = False) -> bool:
    """True for the FunC standard library: named stdlib*.fc / .func (or `flagged` by the verifier
    manifest), with asm declarations and only pure function bodies (see above)."""
    if not (flagged or _STDLIB_NAME.match(posixpath.basename(path))):
        return False
    code = re.sub(r'"[^"\n]*"', '""', _strip_func_comments(text))   # asm strings may hold <{ }> blocks
    return "asm" in code and _bodies_are_pure(code)


def stdlib_paths(files: dict[str, str], flagged: list[str] | tuple[str, ...] = ()) -> set[str]:
    """Paths of `files` that are the FunC standard library (is_stdlib_file)."""
    marked = set(flagged)
    return {p for p, t in files.items() if is_stdlib_file(p, t, p in marked)}
