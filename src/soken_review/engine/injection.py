"""Prompt-injection flags J1 to J5 and the V4 echo check (04 section 12). Pure; no I/O beyond the rubric.

scan_file(path, text, tokens) -> list[flag]
    Pin-time detection per file. `tokens` are the file's `map.v1` tokens (comment and literal_str
    kinds feed J1 and J5; identifier tokens feed J4). Flag: `{file, line, rule, detail}`; J1 flags
    also carry `text` (the comment or string, the span V4 compares against).

check_echo(text, j1_flags) -> list[Violation]
    V4: title and body may not contain 6 or more consecutive words of a J1 span (E_INJECTION_ECHO).

server_draft_flags(flags) -> list[flag]
    One server draft per J2 or J4 flag (04 12 "Server drafts"); J1, J3, J5 are report rows only.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .text_gate import Violation, _char_script

_PATTERNS = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "injection_patterns.yaml"
_ECHO_WORDS = 6
_WORD_RE = re.compile(r"[^\W_]+(?:['_][^\W_]+)*", re.UNICODE)
_IDENT_WORD_RE = re.compile(r"[^\W\d]\w*", re.UNICODE)
_J1_TEXT_MAX = 2000


@lru_cache(maxsize=1)
def _cfg() -> dict[str, Any]:
    return yaml.safe_load(_PATTERNS.read_text(encoding="utf-8"))


def _cp(s: str) -> str:
    return chr(int(s.removeprefix("U+"), 16))


@lru_cache(maxsize=1)
def _j1_regexes() -> list[tuple[str, re.Pattern[str]]]:
    cfg = _cfg()["J1"]
    out = []
    for p in cfg.get("phrases") or []:
        body = r"\s+".join(re.escape(w) for w in p.split())
        out.append((p, re.compile(rf"(?i)(?<!\w){body}(?!\w)")))
    for r in cfg.get("regexes") or []:
        out.append((r, re.compile(r, re.IGNORECASE)))
    return out


@lru_cache(maxsize=1)
def _sets() -> tuple[frozenset[str], frozenset[str], dict[str, str], list[re.Pattern[str]]]:
    cfg = _cfg()
    j2 = frozenset(_cp(c) for c in cfg["J2"]["codepoints"])
    j3 = frozenset(_cp(c) for c in cfg["J3"]["codepoints"])
    look = dict(cfg["J4"]["latin_lookalikes"])
    j5 = [re.compile(r) for r in cfg["J5"]["regexes"]]
    return j2, j3, look, j5


_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"})


def is_invisible(c: str) -> bool:
    """Category rule (not a list): controls except LF and tab, format characters (bidi, zero-width,
    tag characters U+E0000 to U+E007F), private use, surrogates, unassigned, line and paragraph
    separators, variation selectors, plus the J2 and J3 lists of injection_patterns.yaml."""
    if c in "\n\t":
        return False
    if c.isascii():
        return not c.isprintable()
    j2, j3, _look, _j5 = _sets()
    if c in j2 or c in j3:
        return True
    cp = ord(c)
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF or 0x180B <= cp <= 0x180F:
        return True
    return unicodedata.category(c) in _INVISIBLE_CATEGORIES


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_file(path: str, text: str, tokens: list[dict[str, Any]],
              ascii_identifiers: frozenset[str] = frozenset()) -> list[dict[str, Any]]:
    """J1 to J5 flags for one pinned file (04 12). Deterministic order: line, rule.

    Lexer mistakes can only add flags, never remove them: J1 and J5 run on the grammar tokens, on
    an independent fallback lexing and on the raw text; J4 takes identifiers from both lexings and
    mixed-script words from the raw text; an unterminated comment or string is a J2 flag (text a
    reader cannot see the end of, the Trojan Source class).
    """
    from ..mapping.lexers import language_for, lex_fallback  # pure; no cycle at import time

    j2, _j3, look, j5 = _sets()
    flags: list[dict[str, Any]] = []

    # J2, J3: character scan over the whole file (code, comments and strings alike)
    for i, ch in enumerate(text):
        if ch in j2:
            flags.append({"file": path, "line": _line_of(text, i), "rule": "J2", "detail": f"U+{ord(ch):04X}"})
        elif is_invisible(ch) and not (i == 0 and ch == "\ufeff"):
            flags.append({"file": path, "line": _line_of(text, i), "rule": "J3", "detail": f"U+{ord(ch):04X}"})

    fb = lex_fallback(language_for(path), text)
    fb_tokens = [t.to_json() for t in fb.tokens]
    for line, what in fb.unterminated:
        flags.append({"file": path, "line": line, "rule": "J2", "detail": f"unterminated_{what}"})

    # J1 and J5 on comment and string tokens of both lexings, then on the raw text
    views = [t for t in tokens if t.get("kind") in ("comment", "literal_str")]
    views += [t for t in fb_tokens if t["kind"] in ("comment", "literal_str")]
    raw_lines = text.split("\n")
    views.append({"kind": "raw", "line": 1, "text": text})
    j1_lines: set[int] = set()
    j5_lines: set[int] = set()
    for tok in views:
        body = tok.get("text") or ""
        # invisible characters removed (catches `ig<ZWSP>nore`) and replaced by a space (catches a
        # U+2028 used as a line break); neither variant adds or removes LF, so line numbers hold
        variants = {unicodedata.normalize("NFKC", "".join(c for c in body if not is_invisible(c))),
                    unicodedata.normalize("NFKC", "".join(" " if is_invisible(c) else c for c in body))}
        for pid, rx in _j1_regexes():
            for folded in sorted(variants):
                for m in rx.finditer(folded):
                    line = tok["line"] + folded.count("\n", 0, m.start())
                    if line in j1_lines:
                        continue
                    j1_lines.add(line)
                    span = raw_lines[line - 1] if tok["kind"] == "raw" and line <= len(raw_lines) else body
                    flags.append({"file": path, "line": line, "rule": "J1", "detail": pid[:80],
                                  "text": span[:_J1_TEXT_MAX]})
        if tok["kind"] in ("comment", "raw"):
            for rx in j5:
                for m in rx.finditer(body):
                    line = tok["line"] + body.count("\n", 0, m.start())
                    if line not in j5_lines:
                        j5_lines.add(line)
                        flags.append({"file": path, "line": line, "rule": "J5", "detail": f"{len(m.group(0))} chars"})

    # J4: identifiers of either lexing plus non-comment words of either view; mixed script anywhere
    candidates: dict[str, int] = {}
    for tok in [*tokens, *fb_tokens]:
        if tok.get("kind") in ("identifier", "type_name", "keyword") and not (tok.get("text") or "").isascii():
            candidates.setdefault(tok["text"], tok["line"])
    for toks in (tokens, fb_tokens):
        for word, line in _code_words(text, toks):
            if not word.isascii():
                candidates.setdefault(word, line)
    for ident, line in sorted(candidates.items(), key=lambda kv: (kv[1], kv[0])):
        reason = _j4_reason(ident, look, ascii_identifiers)
        if reason:
            flags.append({"file": path, "line": line, "rule": "J4", "detail": reason})
    for i, raw in enumerate(raw_lines, start=1):
        for m in _IDENT_WORD_RE.finditer(raw):
            w = m.group(0)
            if not w.isascii() and len({_char_script(c) for c in w if c.isalpha()} - {"Common", "Inherited"}) > 1:
                flags.append({"file": path, "line": i, "rule": "J4", "detail": "mixed_script"})

    flags.sort(key=lambda f: (f["line"], f["rule"], f.get("detail", "")))
    return _dedup(flags)


def escape_invisible(s: str) -> str:
    """Tool output form of a source line: J2 and J3 characters and C0 controls (tab kept) shown as
    `<U+XXXX>` so nothing invisible reaches the session (04 12; 08 `src` class J2 and J3 replacement)."""
    if s.isascii() and s.isprintable():
        return s
    out = []
    for c in s:
        if is_invisible(c) or c == "\n":
            out.append(f"<U+{ord(c):04X}>")
        else:
            out.append(c)
    return "".join(out)


def _code_words(text: str, tokens: list[dict[str, Any]]):
    """Unicode words outside comment and string tokens (catches identifiers a grammar rejected)."""
    lines = text.split("\n")
    masked = [list(l) for l in lines]
    for tok in tokens:
        if tok.get("kind") not in ("comment", "literal_str"):
            continue
        body = tok.get("text") or ""
        row, col = tok["line"] - 1, tok["col"] - 1
        for ch in body:
            if row >= len(masked):
                break
            if ch == "\n":
                row, col = row + 1, 0
                continue
            if col < len(masked[row]):
                masked[row][col] = " "
            col += 1
    for i, chars in enumerate(masked):
        for m in _IDENT_WORD_RE.finditer("".join(chars)):
            yield m.group(0), i + 1


def _j4_reason(ident: str, look: dict[str, str], ascii_identifiers: frozenset[str]) -> str | None:
    scripts = {_char_script(c) for c in ident if c.isalpha()} - {"Common", "Inherited"}
    if len(scripts) > 1:
        return "mixed_script"
    if unicodedata.normalize("NFKC", ident) != ident:
        return "nfkc_changes"
    letters = [c for c in ident if c.isalpha() and not c.isascii()]
    if letters and all(c in look for c in letters):
        return "latin_confusable"
    skeleton = "".join(look.get(c, c) for c in ident)
    if skeleton != ident and skeleton in ascii_identifiers:
        return "confusable_with_identifier"
    return None


def _dedup(flags: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple] = set()
    out = []
    for f in flags:
        key = (f["file"], f["line"], f["rule"], f.get("detail"))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def server_draft_flags(flags: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One server draft per (file, line, rule) for J2 and J4 flags (04 12)."""
    seen: set[tuple[str, int, str]] = set()
    out = []
    for f in flags:
        if f["rule"] not in ("J2", "J4"):
            continue
        key = (f["file"], f["line"], f["rule"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# ── V4 echo (04 12 "Echo V4") ───────────────────────────────────────────────


def _words(s: str) -> list[str]:
    folded = unicodedata.normalize("NFKC", s).lower()
    return _WORD_RE.findall(folded)


def check_echo(text: str, j1_flags: list[dict[str, Any]]) -> list[Violation]:
    """E_INJECTION_ECHO when `text` holds 6 or more consecutive words of a J1 span."""
    words = _words(text)
    if len(words) < _ECHO_WORDS:
        return []
    grams = {tuple(words[i : i + _ECHO_WORDS]) for i in range(len(words) - _ECHO_WORDS + 1)}
    out: list[Violation] = []
    for flag in j1_flags:
        if flag.get("rule") != "J1":
            continue
        span = _words(flag.get("text") or "")
        for i in range(len(span) - _ECHO_WORDS + 1):
            if tuple(span[i : i + _ECHO_WORDS]) in grams:
                out.append(Violation("E_INJECTION_ECHO", "V4", (0, len(text)), f"J1 {flag['file']}:{flag['line']}"))
                break
    return out
