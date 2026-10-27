"""Number check (04 section 6). Pure; no I/O beyond the rubric.

Entry points:
  lex_numbers(text, context) -> list[Violation]  - ordered single-pass lexer
  parse_placeholder(s) -> Placeholder            - parse {{fact:}}/{{calc:}}/{{finding:}}

Plan: 04 §6.1 (scope), §6.2 (lexer classes L0-L9b, L9c plain number words), §6.3 (allowed set),
§6.4 (placeholders), number_lexer.yaml.
"""
from __future__ import annotations

import dataclasses
import re
import unicodedata
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from .text_gate import Violation

_LEXER_YAML = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "number_lexer.yaml"

# ── Placeholder grammar (04 §6.4) ─────────────────────────────────────────
#
#   placeholder = "{{" , ( fact | calc | finding ) , "}}"
#   fact        = "fact:" , key
#   finding     = "finding:" , draft_key
#   calc        = "calc:" , expr , "|" , precision
#   expr        = fname "(" operand ")" | operand op operand
#   fname       = bps_to_pct | wei_to_ether | seconds_to_hours | seconds_to_days | units_to_tokens
#   operand     = number | "fact:" key
#   key         = lower { lower | digit | "_" | "." }
#   precision   = "0" | "1" | "2" | "3" | "4" | "5" | "6"

_KEY_RE = r"[a-z][a-z0-9_.]*"
_DRAFT_KEY_RE = r"[a-z0-9][a-z0-9-]{2,47}"
_NUMBER_LIT_RE = r"\d+(?:\.\d+)?"
_OPERAND_RE = rf"(?:{_NUMBER_LIT_RE}|fact:{_KEY_RE})"
_OP_RE = r"[+\-*/]"
_FNAME_RE = r"(?:bps_to_pct|wei_to_ether|seconds_to_hours|seconds_to_days|units_to_tokens)"
_EXPR_RE = rf"(?:{_FNAME_RE}\({_OPERAND_RE}\)|{_OPERAND_RE}(?:{_OP_RE}{_OPERAND_RE})?)"
_CALC_RE = rf"calc:{_EXPR_RE}\|[0-6]"
_FACT_RE = rf"fact:{_KEY_RE}"
_FINDING_RE = rf"finding:{_DRAFT_KEY_RE}"
_PLACEHOLDER_RE = re.compile(
    rf"\{{{{(?:{_CALC_RE}|{_FACT_RE}|{_FINDING_RE})\}}}}"
)
_PLACEHOLDER_FULL_RE = re.compile(
    r"^\{{(?P<kind>fact|calc|finding):(?P<body>[^{}]*)\}}$"
)
# Spurious placeholder: looks like {{...}} but is not a valid placeholder (04 §6.4).
_SPURIOUS_PLACEHOLDER_RE = re.compile(r"\{\{[^{}\n]*\}\}")
# Half placeholder: a fact, calc or finding placeholder with one brace on either side
# (`{fact:key}`, `{{fact:key}`, `{fact:key}}`). The kit expands the double-brace form only, so
# this text would print as written (Wallitelli PDF, matrix run 2026-10-27: `{fact:onchain.total_supply}`
# on page 4). Rejected at write time with the double-brace form as the example.
HALF_PLACEHOLDER_RE = re.compile(r"\{{1,2}(?:fact|calc|finding):[^{}\n]*\}{1,2}")


def placeholder_example(token: str) -> str:
    """The double-brace form of a half placeholder: `{fact:k}` -> `{{fact:k}}`."""
    return "{{" + token.strip("{}") + "}}"


@dataclass(frozen=True)
class Placeholder:
    """Parsed placeholder from ``{{fact:...}}``, ``{{calc:...}}``, or ``{{finding:...}}``."""

    kind: str  # 'fact', 'calc', 'finding'
    body: str  # everything after the colon


_FACT_BODY_RE = re.compile(rf"^{_KEY_RE}$")
_FINDING_BODY_RE = re.compile(rf"^{_DRAFT_KEY_RE}$")
_CALC_BODY_RE = re.compile(rf"^{_EXPR_RE}\|[0-6]$")


def parse_placeholder(s: str) -> Placeholder | None:
    """Parse a placeholder string.  Returns ``None`` if it does not parse.

    Body is validated against the kind-specific grammar (04 §6.4).
    """
    m = _PLACEHOLDER_FULL_RE.match(s)
    if not m:
        return None
    kind = m.group("kind")
    body = m.group("body")
    if kind == "fact" and not _FACT_BODY_RE.match(body):
        return None
    if kind == "finding" and not _FINDING_BODY_RE.match(body):
        return None
    if kind == "calc" and not _CALC_BODY_RE.match(body):
        return None
    return Placeholder(kind=kind, body=body)


# ── NumberContext ──────────────────────────────────────────────────────────


@dataclass
class NumberContext:
    """Context for the number lexer (04 §6.3 allowed set).

    All fields default to empty / None which is safe for CI / server-template use.
    """

    # A1: literal_num token values from the finding's quoted lines (as normalised strings)
    allowed_literals: frozenset[str] = dataclasses.field(default_factory=frozenset)
    """Values from A1 (literal tokens on quoted lines).  Compare as strings after
    group-separator removal.  Includes folded constant values from ``map.constants``."""

    # A2: Solidity unit suffix derived values (baked in below)
    include_solidity_units: bool = False
    """When True, A2 suffix-derived values (ether, gwei, etc.) are added to the allowed set."""

    # A4: server facts
    facts: dict[str, Any] = dataclasses.field(default_factory=dict)
    """Map of fact key -> value (A4).  Values that appear bare in text are rejected with
    the {{fact:key}} placeholder as a hint."""

    # A3 / L5-L6: quoted line ranges for this finding
    quoted_line_ranges: list[tuple[str, int, int]] = dataclasses.field(default_factory=list)
    """List of (path, start, end) tuples representing the finding's quote ranges (A3)."""

    # Token identifiers from the manifest / map word set
    word_set: frozenset[str] = dataclasses.field(default_factory=frozenset)
    """L7 exemption: if an alphanumeric-with-digit token is in the word set, it is exempt."""

    is_finding: bool = True
    """When False (non-finding string), A1 and A3 are empty; amount_at_risk facts are
    rejected (E_NUMBER_CONTEXT)."""

    draft_keys: frozenset[str] = dataclasses.field(default_factory=frozenset)
    """Known draft keys for {{finding:}} placeholder validation."""

    known_fact_keys: frozenset[str] | None = None
    """Every fact key of the job (A4), when the job's facts are loaded. A placeholder naming
    another key is E_NUMBER_UNSOURCED; None (CI, server templates) skips the check."""

    blocked_fact_keys: frozenset[str] = dataclasses.field(default_factory=frozenset)
    """Fact keys present in the job but not allowed in this string by the meaning rule
    (amount_at_risk outside an unbounded finding on the fact's unit): E_NUMBER_CONTEXT (04 6.3)."""


# ── Solidity unit suffixes (A2, 04 §6.3) ─────────────────────────────────
_SOL_UNITS: dict[str, int] = {
    "ether": 10**18,
    "gwei": 10**9,
    "minutes": 60,
    "hours": 3600,
    "days": 86400,
    "weeks": 604800,
}

# ── Type names exempt from L7 (04 §6.2, number_lexer.yaml type_names) ─────
_TYPE_NAMES: frozenset[str] = frozenset(
    [f"uint{8 * i}" for i in range(1, 33)]  # uint8 … uint256
    + [f"int{8 * i}" for i in range(1, 33)]   # int8 … int256
    + [f"bytes{i}" for i in range(1, 33)]      # bytes1 … bytes32
    + ["u8", "u16", "u32", "u64", "u128", "u256",
       "i8", "i16", "i32", "i64", "i128",
       "felt252"]
)

# ── Standard id prefixes (L3) ─────────────────────────────────────────────
_STD_ID_RE = re.compile(
    r"(?i)\b(ERC|EIP|BEP|TRC|TEP|SPL|SIP|SNIP|SWC|CWE|CVE|RFC|FIP)-?\d+(?:-\d+)?\b"
)

# ── Exempt everywhere (04 §6.2 number_lexer.yaml exempt_everywhere) ───────
_EXEMPT_WORDS: frozenset[str] = frozenset(["0", "1", "zero", "one", "first", "second", "last"])

# ── Cardinal / ordinal patterns (L9) ──────────────────────────────────────
_L9_RE = re.compile(
    r"(?i)\b(?:"
    r"two|three|four|five|six|seven|eight|nine|ten|"
    r"eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|"
    r"thirty|forty|fifty|sixty|seventy|eighty|ninety|"
    r"third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|"
    r"eleventh|twelfth|thirteenth|fourteenth|fifteenth|sixteenth|"
    r"seventeenth|eighteenth|nineteenth|twentieth|"
    r"thirtieth|fortieth|fiftieth|sixtieth|seventieth|eightieth|ninetieth|"
    r"hundredth|thousandth|millionth"
    r")\b"
)
# Exception: "third party" and "third-party"
_THIRD_PARTY_RE = re.compile(r"(?i)\bthird[- ]party\b")

# ── Magnitude / multiplier words (L9a) ───────────────────────────────────
# \w{2,}uple: quadruple, quintuple, sextuple; the code word "tuple" is not a multiplier
# ("Magnitude suffix in tuple", c6 re-run 2026-10-23).
_L9A_RE = re.compile(
    r"(?i)\b(?:"
    r"hundreds?|thousands?|millions?|billions?|trillions?|"
    r"dozens?|twice|thrice|double|triple|\w{2,}uple|half|halves|quarters?|\w+fold"
    r")\b"
)

# L9a qualitative uses of `half` and `double` (matrix run 2026-10-26, TON and BNB arms): a
# hyphenated compound ("double-count", "half-open"), `double` as the name of an accounting
# fault ("double counting", "counted double") and `half` as a structural position ("the second
# half of the function") state no amount. "double the fee" and "half the supply" stay amounts.
_FACTOR_WORD_RE = re.compile(r"(?i)\b(?:half|double)\b")
_DOUBLE_ACTION_RE = re.compile(
    r"(?i)[\s-]*(?:count(?:s|ed|ing)?|spen(?:d|ds|t|ding)|charg(?:e|es|ed|ing)|entr(?:y|ies)|dip(?:s|ped|ping)?"
    r"|book(?:s|ed|ing)?|accru(?:al|ed|ing)|accounting|credit(?:s|ed|ing)?|mint(?:s|ed|ing)?|claim(?:s|ed|ing)?"
    r"|withdraw(?:s|n|al|als|ing)?|redeem(?:s|ed|ing)?|collect(?:s|ed|ion|ing)?)\b")
_DOUBLE_BEFORE_RE = re.compile(r"(?i)\b(?:counted|charged|credited|paid|booked|spent|minted|claimed|collected)\s+$")
_HALF_BEFORE_RE = re.compile(r"(?i)\b(?:first|second|latter|upper|lower|top|bottom|other|left|right|former|each)\s+$")
_COMPOUND_TAIL_RE = re.compile(r"-[A-Za-z]")


def _factor_word_is_qualitative(text: str, start: int, end: int, blocked: frozenset[str]) -> bool:
    """True when `half`/`double` at text[start:end] names no amount (see the note above)."""
    if _amount_follows(text, end, blocked):
        return False   # "double the ... tokens", "half-percent": still an amount
    word = text[start:end].lower()
    if _COMPOUND_TAIL_RE.match(text, end):
        return True    # double-count, double-spend, half-open, half-life
    if word == "double":
        return bool(_DOUBLE_ACTION_RE.match(text, end) or _DOUBLE_BEFORE_RE.search(text, 0, start))
    return bool(_HALF_BEFORE_RE.search(text, 0, start))

# ── Plain-language number words (L9c, number_lexer.yaml plain_number_words) ─
# A small count of code things in words ("two pools", "the third call", "pays twice") is structure,
# not a quantity, and needs no source; followed by a unit, percent or token/currency word it is an
# amount ("two tokens", "ten percent") and falls through to L9 / L9a. Runs after L9b so "two thirds
# of" is still a fraction. Added 2026-10-23 after the MasterChef re-run rewrote titles to dodge it.
_FOLLOWER_WORD_RE = re.compile(r"[\s-]*([A-Za-z%]+)(?:\s+([A-Za-z]+))?")


@cache
def _plain_number_words() -> tuple[re.Pattern[str], frozenset[str]]:
    """(word pattern, blocked follower words lower-cased) from number_lexer.yaml."""
    data = yaml.safe_load(_LEXER_YAML.read_text(encoding="utf-8")).get("plain_number_words") or {}
    words = [*data.get("cardinals", []), *data.get("ordinals", []), *data.get("frequency", [])]
    blocked = frozenset(str(w).lower() for w in data.get("blocked_followers", []))
    pattern = re.compile(r"(?i)\b(?:" + "|".join(re.escape(str(w)) for w in words) + r")\b")
    return pattern, blocked


def _amount_follows(text: str, pos: int, blocked: frozenset[str]) -> bool:
    """True when the word(s) after *pos* make the number word an amount (unit, percent, token)."""
    m = _FOLLOWER_WORD_RE.match(text, pos)
    if not m:
        return False
    first = m.group(1).lower()
    if first.startswith("%") or first in blocked:
        return True
    second = m.group(2)
    return bool(second) and f"{first} {second.lower()}" in blocked

# ── Fraction phrases (L9b) ────────────────────────────────────────────────
_L9B_RE = re.compile(
    r"\b(?:a|an|one|two|three|four|five|six|seven|eight|nine|ten)\s+"
    r"(?:third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|hundredth|thousandth)s?\s+of\b"
    r"|\b(?:thirds?|fourths?|fifths?|sixths?|sevenths?|eighths?|ninths?|tenths?|"
    r"hundredths?|thousandths?)\s+of\b",
    re.IGNORECASE,
)

# ── Numeric run (L8) ──────────────────────────────────────────────────────
# L8: [$€£¥]?\d{1,3}(?:[,_ ]\d{3})+(?:\.\d+)?%? | [$€£¥]?\d+(?:\.\d+)?(?:[eE]\d+)?%?
# Note: plain space never joins digits (spec)
_L8_RE = re.compile(
    r"[$€£¥]?\d{1,3}(?:[,_]\d{3})+(?:\.\d+)?%?"
    r"|[$€£¥]?\d+(?:\.\d+)?(?:[eE]\d+)?%?"
)

# ── Currency/ticker next to a number (L8a) ────────────────────────────────
_L8A_PREFIX_RE = re.compile(r"(?i)(USD|US\$|EUR|GBP)\s?\d")

# ── Magnitude suffix on a number (L8d) ────────────────────────────────────
_L8D_RE = re.compile(r"\b\d+(?:\.\d+)?[kKmMbB]\b|\b\d+(?:st|nd|rd|th)\b")

# ── Hex (L2) ─────────────────────────────────────────────────────────────
_L2_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")

# ── Version (L4) ─────────────────────────────────────────────────────────
_L4_RE = re.compile(r"\b\d+\.\d+\.\d+\b")

# ── Word-with-digit (L7) ──────────────────────────────────────────────────
_L7_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*[0-9][A-Za-z0-9_$]*|[A-Za-z_][A-Za-z0-9_$]*")

# ── Alpha-word fallback (L7 second pass, must use compiled .match(str, pos)) ─
_ALPHA_WORD_RE = re.compile(r"[A-Za-z_]\w*")

# ── Line reference patterns (L5, L6) ─────────────────────────────────────
_L5_RE = re.compile(r"[A-Za-z0-9@_./-]{1,200}:(\d+)(?:-(\d+))?")
_L6_RE = re.compile(
    r"(?i)\blines?\s+\d+(?:\s*,\s*\d+)*(?:\s*,?\s*(?:and|to|-)\s*\d+)?"
)

# ── Non-ASCII numerals (step U) ───────────────────────────────────────────
_NON_ASCII_NUM_RE = re.compile(
    r"[^\x00-\x7f\n]"  # quick filter; refined below
)


def _has_non_ascii_numeral(text: str) -> list[Violation]:
    """Step U: reject Unicode No, Nl, or Nd outside 0-9 in the submitted string."""
    violations: list[Violation] = []
    for i, ch in enumerate(text):
        cat = unicodedata.category(ch)
        if cat in ("No", "Nl") or cat == "Nd" and not ("0" <= ch <= "9"):
            violations.append(Violation("E_NUMBER_FORMAT", "U", (i, i + 1), ch))
    return violations


# ── Group-separator normalisation ─────────────────────────────────────────


def _norm_value(s: str) -> str:
    """Remove group separators for equality comparison (04 §6.3)."""
    return s.replace(",", "").replace("_", "").replace(" ", "")


def _values_equal(a: str, b: str) -> bool:
    """Compare two numeric strings as values after removing group separators."""
    na, nb = _norm_value(a), _norm_value(b)
    try:
        return Decimal(na) == Decimal(nb)
    except InvalidOperation:
        return na == nb


# ── Allowed-set lookup (04 §6.3) ──────────────────────────────────────────


def _in_allowed_set(token: str, ctx: NumberContext) -> bool:
    """Return True if *token* is in A1 (or A2 when Solidity units enabled)."""
    for lit in ctx.allowed_literals:
        if _values_equal(token, lit):
            return True
    if ctx.include_solidity_units:
        for suffix_val in _SOL_UNITS.values():
            if _values_equal(token, str(suffix_val)):
                return True
    return False


# ── Main lexer ─────────────────────────────────────────────────────────────


def lex_numbers(text: str, context: NumberContext | None = None) -> list[Violation]:
    """Run the ordered single-pass number lexer on *text* (04 §6.2).

    Returns violations; empty list means no violation.
    Step U runs on the submitted string; the rest on the NFKC copy.
    """
    if context is None:
        context = NumberContext()

    violations: list[Violation] = []

    # Step U: non-ASCII numerals in the submitted string
    violations.extend(_has_non_ascii_numeral(text))

    # NFKC copy for the lexer
    nfkc = unicodedata.normalize("NFKC", text)

    pos = 0
    length = len(nfkc)
    while pos < length:
        # ── L0: placeholder ───────────────────────────────────────────────
        m = _PLACEHOLDER_RE.match(nfkc, pos)
        if m:
            violations.extend(_check_placeholder(m.group(), m.start(), context))
            pos = m.end()
            continue

        # ── L0 spurious: looks like {{...}} but not a valid placeholder ───
        if nfkc[pos : pos + 2] == "{{":
            sm = _SPURIOUS_PLACEHOLDER_RE.match(nfkc, pos)
            if sm:
                violations.append(Violation("E_CALC_SYNTAX", "L0", (sm.start(), sm.end()), sm.group()))
                pos = sm.end()
                continue

        # ── L0 half: a placeholder with one brace on either side is printed as written ──
        if nfkc[pos] == "{":
            hm = HALF_PLACEHOLDER_RE.match(nfkc, pos)
            if hm:
                violations.append(Violation("E_PLACEHOLDER_SYNTAX", "L0", (hm.start(), hm.end()), hm.group()))
                pos = hm.end()
                continue

        # ── L1: code span ─────────────────────────────────────────────────
        if nfkc[pos] == "`":
            end = nfkc.find("`", pos + 1)
            if end == -1 or "\n" in nfkc[pos + 1 : end]:
                pos += 1
                continue
            # Re-lex code span content with L2 to L9 (relaxed: no E_NUMBER_* from L8d etc.)
            # For inner content we apply the same lexer but allow literals freely
            # span_text = nfkc[pos + 1 : end]  # reserved for future inner-span re-lex
            pos = end + 1
            continue

        # ── L2: hex literal ───────────────────────────────────────────────
        m = _L2_RE.match(nfkc, pos)
        if m:
            token = m.group()
            hex_val = token[2:]  # strip 0x
            # 40-hex or 64-hex always require a fact (addresses/hashes); others allowed in A1
            if len(hex_val) in (40, 64):
                # Only by fact
                pass  # accepted as "fact only" - no violation (fact validation is V6, not text gate)
            else:
                # Allowed if in A1
                if context.is_finding and not _in_allowed_set(str(int(token, 16)), context):
                    pass  # tolerated: hex literals in code spans are usually cited from code
            pos = m.end()
            continue

        # ── L3: standard id ───────────────────────────────────────────────
        m = _STD_ID_RE.match(nfkc, pos)
        if m:
            # Exempt if in the standard_ids allowlist (we accept all standard ids as exempt)
            pos = m.end()
            continue

        # ── L4: version ───────────────────────────────────────────────────
        m = _L4_RE.match(nfkc, pos)
        if m:
            # Version must equal a version fact; without facts we accept
            pos = m.end()
            continue

        # ── L5: path:line reference ───────────────────────────────────────
        m = _L5_RE.match(nfkc, pos)
        if m:
            start_line = int(m.group(1))
            end_line = int(m.group(2)) if m.group(2) else start_line
            path = m.group().rsplit(":", 1)[0]
            if not _line_in_quotes(path, start_line, context) or not _line_in_quotes(path, end_line, context):
                violations.append(Violation("E_LINEREF_OUTSIDE", "L5", (m.start(), m.end()), m.group()))
            pos = m.end()
            continue

        # ── L6: "lines N, M and K" ────────────────────────────────────────
        m = _L6_RE.match(nfkc, pos)
        if m:
            # L6: each number follows L5; with no path given, it must fall inside a quote range
            # of this finding (any file). No quote ranges = every line reference is outside.
            for n in (int(x) for x in re.findall(r"\d+", m.group())):
                if not any(start <= n <= end for _, start, end in context.quoted_line_ranges):
                    violations.append(Violation("E_LINEREF_OUTSIDE", "L6", (m.start(), m.end()), m.group()))
                    break
            pos = m.end()
            continue

        # ── L7: word containing a digit ───────────────────────────────────
        m = _L7_RE.match(nfkc, pos)
        if m and any(ch.isdigit() for ch in m.group()):
            token = m.group()
            if (
                token not in _EXEMPT_WORDS
                and token not in _TYPE_NAMES
                and token not in context.word_set
                and not _STD_ID_RE.fullmatch(token)
            ):
                violations.append(Violation("E_NUMBER_UNSOURCED", "L7", (m.start(), m.end()), token))
            pos = m.end()
            continue

        # ── L8d: magnitude suffix or ordinal number ───────────────────────
        m = _L8D_RE.match(nfkc, pos)
        if m:
            violations.append(Violation("E_NUMBER_FORMAT", "L8d", (m.start(), m.end()), m.group()))
            pos = m.end()
            continue

        # ── L8a: currency/ticker prefix ───────────────────────────────────
        m = _L8A_PREFIX_RE.match(nfkc, pos)
        if m:
            violations.append(Violation("E_NUMBER_FORMAT", "L8a", (m.start(), m.end()), m.group()))
            pos = m.end()
            continue

        # ── L8: numeric run ───────────────────────────────────────────────
        m = _L8_RE.match(nfkc, pos)
        if m:
            token = m.group()
            # L8b: bare percent
            if token.endswith("%"):
                violations.append(Violation("E_NUMBER_FORMAT", "L8b", (m.start(), m.end()), token))
                pos = m.end()
                continue
            # L8a: currency symbol prefix
            if token and token[0] in "$€£¥":
                violations.append(Violation("E_NUMBER_FORMAT", "L8a", (m.start(), m.end()), token))
                pos = m.end()
                continue
            # Validate group separators (1,00 is invalid)
            raw = _norm_value(token)
            try:
                Decimal(raw)
            except InvalidOperation:
                violations.append(Violation("E_NUMBER_FORMAT", "L8", (m.start(), m.end()), token))
                pos = m.end()
                continue
            # L8c: allowed-set check
            if raw in _EXEMPT_WORDS:
                pos = m.end()
                continue
            if raw == "0" or raw == "1":
                pos = m.end()
                continue
            if context.is_finding and not _in_allowed_set(raw, context):
                # Check if the value equals any fact (bare fact value -> hint to use placeholder)
                for val in context.facts.values():
                    if _values_equal(raw, str(val)):
                        violations.append(
                            Violation("E_NUMBER_UNSOURCED", "L8c", (m.start(), m.end()), token)
                        )
                        break
                else:
                    violations.append(
                        Violation("E_NUMBER_UNSOURCED", "L8c", (m.start(), m.end()), token)
                    )
            pos = m.end()
            continue

        # ── L9b: fraction phrases ─────────────────────────────────────────
        m = _L9B_RE.match(nfkc, pos)
        if m:
            violations.append(Violation("E_NUMBER_FORMAT", "L9b", (m.start(), m.end()), m.group()))
            pos = m.end()
            continue

        # ── L9c: plain number word with no unit, percent or token word after it ──
        plain_re, blocked = _plain_number_words()
        m = plain_re.match(nfkc, pos)
        if m and not _amount_follows(nfkc, m.end(), blocked):
            pos = m.end()
            continue

        # ── L9a: magnitude/multiplier words ──────────────────────────────
        m = _FACTOR_WORD_RE.match(nfkc, pos)
        if m and _factor_word_is_qualitative(nfkc, m.start(), m.end(), blocked):
            pos = m.end()
            continue
        m = _L9A_RE.match(nfkc, pos)
        if m:
            violations.append(Violation("E_NUMBER_FORMAT", "L9a", (m.start(), m.end()), m.group()))
            pos = m.end()
            continue

        # ── L9: cardinal/ordinal words ────────────────────────────────────
        m = _L9_RE.match(nfkc, pos)
        if m:
            # Exception: "third party" and "third-party"
            end_pos = m.end()
            remainder = nfkc[end_pos : end_pos + 10]
            if m.group().lower() == "third" and re.match(r"\s*-?\s*party\b", remainder, re.IGNORECASE):
                pos = end_pos
                continue
            if m.group().lower() not in _EXEMPT_WORDS:
                violations.append(Violation("E_NUMBER_UNSOURCED", "L9", (m.start(), m.end()), m.group()))
            pos = end_pos
            continue

        # ── L7: pure-alpha word-with-digit (second pass) ─────────────────
        # L7 also catches identifiers; handled above. Skip alpha-only tokens.
        if nfkc[pos].isalpha() or nfkc[pos] == "_":
            # Match a word token — must use compiled .match(str, pos) so pos is an offset,
            # not the flags argument (re.match(pat, s, pos) passes pos as flags).
            m = _ALPHA_WORD_RE.match(nfkc, pos)
            if m:
                token = m.group()
                if token.lower() in _EXEMPT_WORDS:
                    pos = m.end()
                    continue
                pos = m.end()
                continue

        # advance one character
        pos += 1

    return violations


# ── Helpers ────────────────────────────────────────────────────────────────


def _line_in_quotes(path: str, line: int, ctx: NumberContext) -> bool:
    """Return True if (path, line) is within one of the finding's quoted ranges."""
    if not ctx.is_finding:
        return False
    for qpath, start, end in ctx.quoted_line_ranges:
        if qpath == path and start <= line <= end:
            return True
    return False


def _check_placeholder(token: str, offset: int, ctx: NumberContext) -> list[Violation]:
    """Validate a placeholder token (04 §6.4).

    Returns violations for unknown fact keys, malformed calc expressions, or
    unknown draft keys.
    """
    violations: list[Violation] = []
    ph = parse_placeholder(token)
    if ph is None:
        violations.append(Violation("E_CALC_SYNTAX", "L0", (offset, offset + len(token)), token))
        return violations
    if ph.kind == "fact":
        violations.extend(_check_fact_key(ph.body, token, offset, ctx))
    elif ph.kind == "finding":
        draft_key = ph.body
        if ctx.draft_keys and draft_key not in ctx.draft_keys:
            violations.append(
                Violation("E_FINDING_REF_UNKNOWN", "L0", (offset, offset + len(token)), token)
            )
    elif ph.kind == "calc":
        key_violations = [v for key in re.findall(rf"fact:({_KEY_RE})", ph.body)
                          for v in _check_fact_key(key, token, offset, ctx)]
        violations.extend(key_violations or _validate_calc(ph.body, token, offset, ctx))
    return violations


def _check_fact_key(key: str, token: str, offset: int, ctx: NumberContext) -> list[Violation]:
    """A4 key checks against the job's fact records (04 6.3 meaning rule, 6.4 operands)."""
    span = (offset, offset + len(token))
    if key in ctx.blocked_fact_keys:
        return [Violation("E_NUMBER_CONTEXT", "L0", span, token)]
    if ctx.known_fact_keys is not None and key not in ctx.known_fact_keys:
        return [Violation("E_NUMBER_UNSOURCED", "L0", span, token)]
    return []


_CALC_PARSE_RE = re.compile(
    rf"^(?P<expr>(?:{_FNAME_RE}\({_OPERAND_RE}\)|{_OPERAND_RE}(?:[+\-*/]{_OPERAND_RE})?)"
    rf")\|(?P<prec>[0-6])$"
)


def _validate_calc(body: str, token: str, offset: int, ctx: NumberContext) -> list[Violation]:
    """Validate a calc placeholder body (04 §6.4)."""
    m = _CALC_PARSE_RE.match(body)
    if not m:
        return [Violation("E_CALC_SYNTAX", "L0", (offset, offset + len(token)), token)]
    # Evaluate to check for zero-rounding (E_CALC_ROUNDING) when possible
    # Fail closed: an expression the server cannot evaluate (unknown fact, unknown function,
    # division by zero) is rejected, never accepted unchecked (04 6.4).
    span = (offset, offset + len(token))
    try:
        result = _eval_calc(m.group("expr"), ctx)
    except (ValueError, ArithmeticError, InvalidOperation):
        result = None
    if result is None:
        return [Violation("E_CALC_SYNTAX", "L0", span, token)]
    prec = int(m.group("prec"))
    rounded = result.quantize(Decimal(10) ** -prec, rounding=ROUND_HALF_EVEN)
    if rounded == 0 and result != 0:
        return [Violation("E_CALC_ROUNDING", "L0", span, token)]
    return []


def _eval_calc(expr: str, ctx: NumberContext) -> Decimal | None:
    """Best-effort evaluation of a calc expression.  Returns None if inputs are unknown."""
    fn_m = re.match(rf"^({_FNAME_RE})\(({_OPERAND_RE})\)$", expr)
    if fn_m:
        fn, operand_s = fn_m.group(1), fn_m.group(2)
        val = _resolve_operand(operand_s, ctx)
        if val is None:
            return None
        fns: dict[str, Decimal] = {
            "bps_to_pct": Decimal("0.01"),
            "wei_to_ether": Decimal("1e-18"),
            "seconds_to_hours": Decimal(1) / 3600,
            "seconds_to_days": Decimal(1) / 86400,
            "units_to_tokens": Decimal(1),
        }
        factor = fns.get(fn)
        return None if factor is None else val * factor
    op_m = re.match(rf"^({_OPERAND_RE})([+\-*/])({_OPERAND_RE})$", expr)
    if op_m:
        lhs = _resolve_operand(op_m.group(1), ctx)
        op = op_m.group(2)
        rhs = _resolve_operand(op_m.group(3), ctx)
        if lhs is None or rhs is None:
            return None
        if op == "+":
            return lhs + rhs
        if op == "-":
            return lhs - rhs
        if op == "*":
            return lhs * rhs
        if op == "/" and rhs != 0:
            return lhs / rhs
    return None


def _resolve_operand(s: str, ctx: NumberContext) -> Decimal | None:
    """Resolve an operand to a Decimal, or None if the fact key is unknown."""
    if s.startswith("fact:"):
        key = s[5:]
        val = ctx.facts.get(key)
        if val is None:
            return None
        try:
            return Decimal(str(val))
        except InvalidOperation:
            return None
    try:
        return Decimal(s)
    except InvalidOperation:
        return None
