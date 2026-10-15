"""Quote-match (04 section 5.2): pure function with no I/O.

Normalization: NFC (not NFKC), LF, strip leading/trailing horizontal whitespace,
collapse inner whitespace runs, drop empty lines.

Elision "..." is allowed once; more than one elision -> E_QUOTE_ELISION.
Segments match contiguous runs of normalized pinned lines in order;
first segment starts at P[0], last segment ends at P[-1]. Tolerance 0.
"""

from __future__ import annotations

import re
import unicodedata

from .store import PinnedSource

ELISION = "..."

# A quote is trivial when it has fewer than 12 non-whitespace chars,
# or when it consists only of braces, brackets, semicolons, pragmas or imports.
_ONLY_BRACES_RE = re.compile(r"^[\s{}\[\]();,]*$")
_IMPORT_PRAGMA_RE = re.compile(r"^\s*(import\b|pragma\b)", re.IGNORECASE)


class QuoteMatchError(Exception):
    """A quote validation failure (04 5.2). `code` is the errors.yaml code."""

    def __init__(self, code: str, **detail) -> None:
        self.code = code
        self.detail = detail
        super().__init__(code)


# ── normalization (exposed for the text-gate workstream) ────────────────────


def normalize_line(line: str) -> str:
    """NFC, strip leading/trailing horizontal whitespace, collapse inner runs (04 5.2)."""
    line = unicodedata.normalize("NFC", line)
    line = line.strip(" \t")
    line = re.sub(r"[ \t]+", " ", line)
    return line


def normalize_lines(text: str) -> list[str]:
    """Normalize and drop empty lines. Input may have any line endings."""
    lf = text.replace("\r\n", "\n").replace("\r", "\n")
    return [nl for raw in lf.split("\n") if (nl := normalize_line(raw))]


# ── trivial check ───────────────────────────────────────────────────────────


def _is_trivial(lines: list[str]) -> bool:
    """True when the quote carries too little code content (04 5.2)."""
    joined = "".join(lines)
    non_ws = re.sub(r"\s", "", joined)
    if len(non_ws) < 12:
        return True
    # Every line is braces-only OR an import/pragma
    return all(_ONLY_BRACES_RE.match(l) or _IMPORT_PRAGMA_RE.match(l) for l in lines)


# ── segment finder ──────────────────────────────────────────────────────────


def _find_segment(haystack: list[str], needle: list[str], from_pos: int) -> int:
    """Find `needle` as a contiguous sublist of `haystack[from_pos:]`. Returns start index or -1."""
    n = len(needle)
    for i in range(from_pos, len(haystack) - n + 1):
        if haystack[i : i + n] == needle:
            return i
    return -1


# ── public API ───────────────────────────────────────────────────────────────


def quote_match(
    pin: PinnedSource,
    path: str,
    start: int,
    end: int,
    text: str,
) -> None:
    """Verify that `text` matches pinned lines [start, end] per 04 5.2.

    On success returns None. On failure raises QuoteMatchError with the
    appropriate errors.yaml code:
      E_FILE_UNKNOWN     path not in the manifest
      E_RANGE_INVALID    start/end outside the file
      E_QUOTE_TOO_LONG   more than 40 lines
      E_QUOTE_TRIVIAL    no code tokens
      E_QUOTE_ELISION    more than one "..." line
      E_QUOTE_MISMATCH   normalized text does not match
    """
    entry = pin.get_entry(path)
    if entry is None:
        raise QuoteMatchError("E_FILE_UNKNOWN", path=path)

    if end - start + 1 > 40:
        raise QuoteMatchError("E_QUOTE_TOO_LONG")
    if start < 1 or end > entry.lines or start > end:
        raise QuoteMatchError("E_RANGE_INVALID", path=path, lines=entry.lines)

    # Normalized pinned lines (non-empty only)
    raw_pinned = pin.read_lines(path, start, end)
    P = [nl for raw in raw_pinned if (nl := normalize_line(raw))]

    # Parse the quote text into segments split on elision
    lf_text = text.replace("\r\n", "\n").replace("\r", "\n")
    raw_q_lines = lf_text.split("\n")
    q_normalized = [normalize_line(l) for l in raw_q_lines]

    elision_positions = [i for i, l in enumerate(q_normalized) if l == ELISION]
    if len(elision_positions) > 1:
        raise QuoteMatchError("E_QUOTE_ELISION")

    if elision_positions:
        idx = elision_positions[0]
        raw_segs = [q_normalized[:idx], q_normalized[idx + 1 :]]
    else:
        raw_segs = [q_normalized]

    segments = [[l for l in seg if l] for seg in raw_segs]
    segments = [s for s in segments if s]

    Q_flat = [l for seg in segments for l in seg]
    if _is_trivial(Q_flat):
        raise QuoteMatchError("E_QUOTE_TRIVIAL")

    if not segments:
        # Quote is all empty/elision; P must also be empty
        if P:
            raise QuoteMatchError("E_QUOTE_MISMATCH", path=path, start=start, end=end)
        return

    # Match: first segment starts at P[0], last segment ends at P[-1].
    pos = 0
    for seg_idx, segment in enumerate(segments):
        is_first = seg_idx == 0

        if is_first:
            # Must match starting at pos=0
            if len(segment) > len(P):
                raise QuoteMatchError("E_QUOTE_MISMATCH", path=path, start=start, end=end)
            for i, expected in enumerate(segment):
                if P[i] != expected:
                    raise QuoteMatchError(
                        "E_QUOTE_MISMATCH",
                        path=path,
                        start=start,
                        end=end,
                        first_diff_quote=expected,
                        first_diff_pinned=P[i],
                    )
            pos = len(segment)
        else:
            found = _find_segment(P, segment, pos)
            if found == -1:
                raise QuoteMatchError("E_QUOTE_MISMATCH", path=path, start=start, end=end)
            pos = found + len(segment)

    # Last segment must have consumed through P[-1]
    if pos != len(P):
        raise QuoteMatchError("E_QUOTE_MISMATCH", path=path, start=start, end=end)
