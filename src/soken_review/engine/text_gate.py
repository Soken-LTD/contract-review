"""Text gate (04 section 11). Pure; no I/O.

Entry point: ``check_text(text, scope, context) -> list[Violation]``.

Rules are data-driven from ``contract/rubric/text_gate.yaml``; this module implements
the *kinds* of checks. Scopes: ``model | server | public | subject``.

Plan references: 04 §11.1 (scopes), §11.2 (rules T1-T31, P1-P4), §11.3 (code spans),
§11.4 (render parity). text_gate.yaml, errors.yaml owner part 04.
"""
from __future__ import annotations

import dataclasses
import re
import unicodedata
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

RUBRIC_DIR = Path(__file__).resolve().parents[3] / "contract" / "rubric"
TLDS_FILE = RUBRIC_DIR / "tlds.txt"

# ── Violation ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Violation:
    """One text-gate or number-check violation.

    ``span`` is ``(start, end)`` in character offsets. For step0 violations the span
    is in the *submitted* string; for all other violations it is in the NFKC copy.
    ``match`` is the matched or flagged text.
    """

    code: str  # error code from contract/errors.yaml
    rule_id: str  # T1 … T31, P1 … P4, step0, subject_words
    span: tuple[int, int]
    match: str


# ── CheckContext ───────────────────────────────────────────────────────────


@dataclass
class CheckContext:
    """Caller-supplied context for ``check_text``.

    All fields are optional and default to safe values for CI / server-template use
    (no word-set, no claims, no profile).
    """

    field: str | None = None
    """Field name (title, description, impact, recommendation, attack_steps, notes, …)
    for field-specific rules T21, T22, T23, T24, T30."""

    profile: str | None = None
    """Job profile (``public_review`` or ``owner``).  T30 fires only for public_review."""

    absence_claims: list[dict[str, str]] = dataclasses.field(default_factory=list)
    """Absence-claim list from the finding draft (04 §7.6) for T24 phrase binding.
    Each entry: ``{says, kind, target, scope}``."""

    word_set: frozenset[str] | None = None
    """Token identifiers from the manifest (04 §5.1) for T31 code-call detection.
    If ``None``, T31 raises violations for any call syntax outside a backtick span."""

    competitor_names: list[str] | None = None
    """Competitor name list (01 §4 competitor table) for P2.  Skipped when ``None``."""

    is_list_item: bool = False
    """True when the text is a list-item body (used by T30 list-actor check)."""


# ── YAML loader ────────────────────────────────────────────────────────────


@cache
def _load_gate_yaml() -> dict:
    return yaml.safe_load((RUBRIC_DIR / "text_gate.yaml").read_text())


@cache
def _load_tlds() -> frozenset[str]:
    """Load IANA TLD set from contract/rubric/tlds.txt if present; return empty set."""
    if not TLDS_FILE.exists():
        return frozenset()
    lines = TLDS_FILE.read_text().splitlines()
    return frozenset(ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#"))


# ── Scope → active rule ids ────────────────────────────────────────────────

# text_gate.yaml scopes field:
#   model:   [step0, T1-T31]
#   server:  [step0, T1-T12, T25_brand_soken_dev_only, T28]
#   public:  [T1-T4, T6-T8, T10, T11, T14, T15, T25_brand_soken_dev_only, T27, T28, P1, P2, P3, P4]
#   subject: [subject_words]
#   note:    [step0]
#
# "T25_brand_soken_dev_only" = T25 variant that permits the literal string "soken.dev"

_MODEL_RULES = frozenset(
    ["step0"]
    + [f"T{i}" for i in range(1, 32)]  # T1 … T31
)
_SERVER_RULES = frozenset(
    ["step0"]
    + [f"T{i}" for i in range(1, 13)]  # T1 … T12
    + ["T25_brand_only", "T28"]
)
_PUBLIC_RULES = frozenset(
    [f"T{i}" for i in [1, 2, 3, 4, 6, 7, 8, 10, 11, 14, 15]]
    + ["T25_brand_only", "T27", "T28", "P1", "P2", "P3", "P4"]
)
_SUBJECT_RULES = frozenset(["subject_words"])
# Internal notes (dismissal note, challenge answer note, withdrawal note) go to the audit log,
# never to the report. Only step0 (control characters, bidi controls, foreign scripts) applies:
# the prose rules T1-T31 and the number provenance check are report-text rules and only cost
# the reviewer attempts here ("Number two in note has no source", 2026-10-22).
_NOTE_RULES = frozenset(["step0"])

_SCOPE_RULES: dict[str, frozenset[str]] = {
    "model": _MODEL_RULES,
    "server": _SERVER_RULES,
    "public": _PUBLIC_RULES,
    "subject": _SUBJECT_RULES,
    "note": _NOTE_RULES,
}

# Rules that are EXEMPT inside a valid code span (text_gate.yaml code_span_exempt)
_CODE_SPAN_EXEMPT = frozenset(["T5", "T9", "T12", "T18", "T19", "T20", "T24", "T16"])

# Rules that fire even inside code spans (text_gate.yaml code_span_never_exempt)
_CODE_SPAN_NEVER_EXEMPT = frozenset(
    ["step0", "T4", "T13", "T14", "T15", "T17", "T25", "T25_brand_only", "T26", "T27", "T28", "T29"]
)

# Contraction map (text_gate.yaml contractions field)
_CONTRACTIONS: dict[str, str] = {
    "doesn't": "does not",
    "don't": "do not",
    "isn't": "is not",
    "aren't": "are not",
    "can't": "cannot",
    "won't": "will not",
    "wasn't": "was not",
    "hasn't": "has not",
}

# ── Unicode helpers ────────────────────────────────────────────────────────

# Bidi controls (step0)
_BIDI_CODEPOINTS = frozenset(
    list(range(0x202A, 0x202F))  # U+202A-U+202E
    + list(range(0x2066, 0x206A))  # U+2066-U+2069
    + [0x200E, 0x200F, 0x061C]
)
_SOFT_HYPHEN = 0x00AD

# Unicode scripts considered valid for plain text (step0 script check)
_ALLOWED_SCRIPTS = frozenset(["Latin", "Common", "Inherited"])


def _char_script(ch: str) -> str:
    """Return the Unicode script property name for a single character."""
    # unicodedata does not expose Script directly; use Script_Extensions via regex
    # Fall back to the category-based heuristic used in practice.
    cp = ord(ch)
    try:
        import unicodedata as ud
        name = ud.name(ch, "")
    except (ValueError, UnicodeError):
        name = ""
    # Fast path: ASCII is Latin
    if cp < 128:
        return "Latin"
    cat = unicodedata.category(ch)
    # Common includes punctuation, digits, symbols used across scripts
    if cat in ("Nd", "Po", "Ps", "Pe", "Pi", "Pf", "Pd", "Pc", "No", "Nl",
               "So", "Sm", "Sc", "Sk", "Zs", "Mn", "Mc", "Me"):
        return "Common"
    # For letters, use name prefix as a rough Script proxy.
    # Covers Cyrillic, Greek, Arabic, Hebrew, CJK, etc.
    for script, prefixes in [
        ("Latin", ("LATIN",)),
        ("Cyrillic", ("CYRILLIC",)),
        ("Greek", ("GREEK",)),
        ("Arabic", ("ARABIC",)),
        ("Hebrew", ("HEBREW",)),
        ("CJK", ("CJK", "HANGUL", "HIRAGANA", "KATAKANA")),
        ("Devanagari", ("DEVANAGARI",)),
        ("Thai", ("THAI",)),
        ("Georgian", ("GEORGIAN",)),
        ("Armenian", ("ARMENIAN",)),
    ]:
        if any(name.startswith(p) for p in prefixes):
            return script
    # Inherited (combining marks, ZERO WIDTH JOIN/NON-JOINER, etc.)
    if cat in ("Cf",):
        return "Inherited"
    return "Unknown"


# ── Code-span detection ────────────────────────────────────────────────────

_CODE_SPAN_RE = re.compile(r"`[^`\n]+`")


def _code_span_ranges(text: str) -> list[tuple[int, int]]:
    """Return character ranges of all backtick spans in *text*."""
    return [(m.start(), m.end()) for m in _CODE_SPAN_RE.finditer(text)]


def _in_code_span(pos: int, spans: list[tuple[int, int]]) -> bool:
    """True if character position *pos* falls inside a code span."""
    return any(s <= pos < e for s, e in spans)


def _match_in_code_span(m: re.Match, spans: list[tuple[int, int]]) -> bool:
    return _in_code_span(m.start(), spans)


# ── NFKC + contraction helpers ─────────────────────────────────────────────


def _nfkc_expand(text: str) -> str:
    """NFKC-normalise *text* then expand contractions (text_gate.yaml contractions)."""
    nfkc = unicodedata.normalize("NFKC", text)
    # Expand contractions with word boundaries (case-insensitive)
    for contraction, expansion in _CONTRACTIONS.items():
        nfkc = re.sub(rf"(?i)\b{re.escape(contraction)}\b", expansion, nfkc)
    return nfkc


# ── Phrase-list helper ─────────────────────────────────────────────────────


def _phrase_re(phrases: list[str]) -> re.Pattern:
    """Compile a list of phrases into a single case-insensitive pattern.

    Spaces in phrases match ``\\s+``.  Each phrase is bounded with ``\\b`` at
    word-character boundaries and ``(?<!\\w)``/``(?!\\w)`` at non-word-character
    boundaries (e.g. ``#1`` starts with ``#`` which is not ``\\w``).
    """
    alts = []
    for p in phrases:
        body = r"\s+".join(re.escape(w) for w in p.split())
        start = r"\b" if p[0].isalnum() or p[0] == "_" else r"(?<!\w)"
        end = r"\b" if p[-1].isalnum() or p[-1] == "_" else r"(?!\w)"
        alts.append(start + body + end)
    return re.compile(r"(?i)(?:" + "|".join(alts) + r")")


# ── T4: retired brand domain ───────────────────────────────────────────────
# text_gate.yaml T4: the kit GATE retired brand domain (verified against report-kit GATE 2026-10-09).
_T4_RE = re.compile(
    r"(?i)\bsoken\s*(?:\.|\bdot\b)\s*io\b"
    r"|soken[․܁]io"  # homoglyph variants
)

# ── T10: vanity-count patterns ─────────────────────────────────────────────
# text_gate.yaml T10: the kit GATE vanity counts (verified against report-kit GATE 2026-10-09).
_T10_RE = re.compile(r"\b(890\+|255\+)")

# ── Rule patterns ──────────────────────────────────────────────────────────

_T1_RE = re.compile("—")  # em dash
_T2_RE = re.compile("–")  # en dash
_T3_RE = re.compile("→")  # rightwards arrow

_T5_RE = re.compile(r"(?i)\b(you|your|yours|we|our)\b")
_T6_RE = re.compile(r"(?i)\bconfidential\.\s+shared\b")
_T7_RE = re.compile(r"(?i)\breserved\s+for\b")
_T8_RE = re.compile(r"(?i)\bthe\s+choice\s+is\b")
# T9: case-SENSITIVE per text_gate.yaml "(case-sensitive)" annotation
_T9_RE = re.compile(r"\b(AI|LLM|Claude|GPT|subagent)\b")
# T11: case-SENSITIVE
_T11_RE = re.compile(r"\b(TODO|TBD|DRAFT)\b")
_T12_RE = re.compile(r"\?")

_T13_PHRASES = [
    "critical", "high", "medium", "low", "informational",
    "severe", "catastrophic", "devastating", "serious", "major", "minor",
]
_T13_RE = _phrase_re(_T13_PHRASES)

_T14_PHRASES = [
    "guaranteed", "fully secure", "no vulnerability", "no vulnerabilities",
    "bug-free", "proven exploit", "confirmed exploit", "100% safe",
]
_T14_RE = _phrase_re(_T14_PHRASES)

_T15_RE = re.compile(r"(?i)\baudit(?:s|ed|or|ors)?\b")

# T16: case-SENSITIVE (proper tool/model names)
_T16_RE = re.compile(
    r"\b(Slither|Aderyn|Wake|Semgrep|Radar|Misti|Mythril|Echidna|Medusa|Trident"
    r"|Opus|Sonnet|Haiku)\b"
)

_T17_RE = re.compile(r"(?i)(https?://|www\.|[^\s@]+@[^\s@]+\.[a-zA-Z]{2,})")

_T18_PHRASES = [
    "it is important to note", "it should be noted", "in conclusion",
    "please note", "as an ai", "feel free", "we recommend", "note that",
]
_T18_RE = _phrase_re(_T18_PHRASES)

_T19_RE = re.compile(r"(?i)\b(might|could|may)\s+(potentially|possibly)\b")

_T20_RE = re.compile(r"->|=>|[‐-―]|−")

_T22_RE = re.compile(r"(?i)\b(let's|let\s+us)\b")

# T24: absence / universal phrase classes (04 §11.2, §7.6)
_T24_GUARD = [
    r"\bno (?:check|guard|lock|validation|modifier|protection|restriction|access control)s?\b",
    r"\bno \w+ (?:check|guard|protection|validation|restriction)s?\b",
    r"\black(?:s|ing)?\b",
    r"\b(?:is|are) missing\b",
    r"\bmissing (?:a |an |any )?(?:check|guard|lock|validation|modifier|access control|protection|restriction)s?\b",
    r"\bwithout (?:a |an |any )?(?:check|guard|lock|validation|modifier|access control|protection|restriction|limit|bound|cap)s?\b",
    r"\b(?:unprotected|unguarded|unchecked|unrestricted|unvalidated)\b",
    r"\b(?:does|do) not (?:check|verify|validate|enforce|restrict)\b",
    r"\b(?:is|are) not (?:checked|verified|validated|enforced|restricted|guarded)\b",
    r"\bfails? to (?:check|verify|validate|enforce|restrict|guard|limit|bound)\b",
]
_T24_CALLER = [
    r"\b(?:anyone|anybody|everyone|nobody) can\b",
    r"\bany \w+(?: \w+){0,5} can\b",
    r"\bnothing (?:prevents|stops|blocks)\b",
    r"\b(?:every|all) (?:function|caller|path|entry point)s?\b",
]
_T24_READ = [
    r"\b(?:never|nowhere)\b",
    r"\bnot\b.{0,40}\banywhere\b",
    r"\b(?:is|are) not used\b",
]

_T24_ALL_RE = re.compile(
    r"(?i)(" + "|".join(_T24_GUARD + _T24_CALLER + _T24_READ) + r")"
)

_T25_RE = re.compile(r"(?i)\bsoken\b")
_T25_BRAND_ONLY_RE = re.compile(r"(?i)\bsoken\b(?!\s*\.dev\b)")

_T27_PHRASES = [
    "book a call", "book a demo", "contact us", "contact our",
    "reach out", "hire us", "hire a team", "hire our",
    "engage us", "engage our", "paid review", "paid audit", "paid plan",
    "manual review", "full review", "upgrade to", "pricing", "discount",
    "team of experts",
]
_T27_RE = _phrase_re(_T27_PHRASES)

# T28: counts near a number or magnitude word (within 3 words)
_T28_ANCHOR_RE = re.compile(r"(?i)\b(projects|engagements|clients|reviews|audits)\b")
_T28_NUM_RE = re.compile(
    r"(?i)\b(\d+|hundreds?|thousands?|millions?|billions?|dozens?|several|many|numerous)\b"
)

_T29_RE = re.compile(r"\b[CHMLIF]-\d{2,3}\b|\bLEAD-\d{4}\b")

# T30: exploit sequence (04 §11.2 T30)
_T30_STEP_RE = re.compile(r"(?i)\b(?:step\s*\d|stage\s*\d)\b")
_T30_LIST_ACTOR_RE = re.compile(r"(?i)^(?:the )?(?:attacker|exploiter|malicious (?:user|contract|account))\b")
_T30_ACTOR_RE = re.compile(
    r"(?i)\b(?:attacker|exploiter|malicious (?:user|contract|account)|re-?enter(?:ant)?(?:\s+call)?)\b"
)
_T30_SEQ_RE = re.compile(
    r"(?i)\b(?:then|next|after\s+that|afterwards|finally|again|repeat(?:s|ed|edly)?|loop(?:s|ed)?)\b"
)
_T30_LINEREF_RE = re.compile(r"\bline\s+\d+\b", re.IGNORECASE)

# T31: call syntax (04 §11.2, §11.3 control 2)
_T31_RE = re.compile(
    r"\b[A-Za-z_]\w*\.[A-Za-z_]\w*\s*\("
    r"|\b[a-z]+(?:_[a-z0-9]+)+\s*\("
    r"|\b[a-z]+[A-Z]\w*\s*\("
    r"|\b(?:call|delegatecall|staticcall|transfer|send|invoke|invoke_signed|send_raw_message|transferFrom)\s*\("
)

# P1: superlative/exclusivity words
_P1_PHRASES = ["only", "first", "no other", "best", "unique", "unlike", "better than", "leading", "#1"]
_P1_RE = _phrase_re(_P1_PHRASES)

# P3: score / finance words
_P3_PHRASES = ["score", "scored", "badge", "rating", "rated", "grade", "buy", "sell", "invest", "safe to buy"]
_P3_RE = _phrase_re(_P3_PHRASES)

# P4: endorsement within 5 words of Anthropic/Claude
_P4_ENDORSE_RE = re.compile(r"(?i)\b(?:endorsed|approved|certified|official|partner|recommended|verified)\b")
_P4_BRAND_RE = re.compile(r"(?i)\b(?:Anthropic|Claude)\b")

# subject_words — match as substring (no word boundaries) so compound names like
# "SecureToken" are caught by the "secure" rule (04 §11.1 subject scope).
_SUBJECT_WORDS = ["soken", "audit", "audited", "certified", "verified", "secure", "safe"]
_SUBJECT_RE = re.compile(r"(?i)(?:" + "|".join(re.escape(w) for w in _SUBJECT_WORDS) + r")")

# ── main check_text ────────────────────────────────────────────────────────


def check_text(text: str, scope: str, context: CheckContext | None = None) -> list[Violation]:
    """Run the text gate for *scope* on *text*.

    Returns a list of ``Violation`` objects; an empty list means no violation.
    Raises ``ValueError`` for an unknown scope.

    Plan: 04 §11.1 (one rule file, one function), text_gate.yaml.
    """
    if scope not in _SCOPE_RULES:
        raise ValueError(f"Unknown scope {scope!r}; valid: {sorted(_SCOPE_RULES)}")
    if context is None:
        context = CheckContext()

    active = _SCOPE_RULES[scope]
    violations: list[Violation] = []

    # ── Step 0 (submitted string) ──────────────────────────────────────────
    if "step0" in active:
        violations.extend(_check_step0(text))

    # ── Prepare NFKC copy for the rule checks ──────────────────────────────
    nfkc = _nfkc_expand(text)
    code_spans = _code_span_ranges(nfkc)

    def _add(rule_id: str, m: re.Match, code: str = "E_TEXT_GATE") -> None:
        if rule_id in _CODE_SPAN_EXEMPT and _match_in_code_span(m, code_spans):
            return
        violations.append(Violation(code=code, rule_id=rule_id, span=(m.start(), m.end()), match=m.group()))

    # ── T1: em dash ───────────────────────────────────────────────────────
    if "T1" in active:
        for m in _T1_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T1", (m.start(), m.end()), m.group()))

    # ── T2: en dash ───────────────────────────────────────────────────────
    if "T2" in active:
        for m in _T2_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T2", (m.start(), m.end()), m.group()))

    # ── T3: right arrow ───────────────────────────────────────────────────
    if "T3" in active:
        for m in _T3_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T3", (m.start(), m.end()), m.group()))

    # ── T4: retired brand domain (never exempt from code spans) ──────────
    # DEFECT: exact domain inferred as soken.io; verify against kit GATE at W0
    if "T4" in active:
        for m in _T4_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T4", (m.start(), m.end()), m.group()))

    # ── T5: second person (code_span_exempt) ─────────────────────────────
    if "T5" in active:
        for m in _T5_RE.finditer(nfkc):
            _add("T5", m)

    # ── T6: "Confidential. Shared" ────────────────────────────────────────
    if "T6" in active:
        for m in _T6_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T6", (m.start(), m.end()), m.group()))

    # ── T7: "reserved for" ────────────────────────────────────────────────
    if "T7" in active:
        for m in _T7_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T7", (m.start(), m.end()), m.group()))

    # ── T8: "the choice is" ──────────────────────────────────────────────
    if "T8" in active:
        for m in _T8_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T8", (m.start(), m.end()), m.group()))

    # ── T9: AI words (case-sensitive, code_span_exempt) ─────────────────
    if "T9" in active:
        for m in _T9_RE.finditer(nfkc):
            _add("T9", m)

    # ── T10: vanity counts (never exempt from code spans) ────────────────
    # DEFECT: exact patterns inferred as 890+ and 255+; verify against kit GATE at W0
    if "T10" in active:
        for m in _T10_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T10", (m.start(), m.end()), m.group()))

    # ── T11: TODO/TBD/DRAFT (case-sensitive) ─────────────────────────────
    if "T11" in active:
        for m in _T11_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T11", (m.start(), m.end()), m.group()))

    # ── T12: question mark (code_span_exempt) ────────────────────────────
    if "T12" in active:
        for m in _T12_RE.finditer(nfkc):
            _add("T12", m)

    # ── T13: severity words (never exempt) ───────────────────────────────
    if "T13" in active:
        for m in _T13_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T13", (m.start(), m.end()), m.group()))

    # ── T14: completeness / proof claims (never exempt) ──────────────────
    if "T14" in active:
        for m in _T14_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T14", (m.start(), m.end()), m.group()))

    # ── T15: audit wording (never exempt) ────────────────────────────────
    if "T15" in active:
        for m in _T15_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T15", (m.start(), m.end()), m.group()))

    # ── T16: analyzer / model names (code_span_exempt) ───────────────────
    if "T16" in active:
        for m in _T16_RE.finditer(nfkc):
            _add("T16", m)

    # ── T17: URLs / email (never exempt) ─────────────────────────────────
    if "T17" in active:
        for m in _T17_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T17", (m.start(), m.end()), m.group()))

    # ── T18: filler phrases (code_span_exempt) ───────────────────────────
    if "T18" in active:
        for m in _T18_RE.finditer(nfkc):
            _add("T18", m)

    # ── T19: hedging stack (code_span_exempt) ────────────────────────────
    if "T19" in active:
        for m in _T19_RE.finditer(nfkc):
            _add("T19", m)

    # ── T20: arrows and dash look-alikes (code_span_exempt) ──────────────
    if "T20" in active:
        for m in _T20_RE.finditer(nfkc):
            _add("T20", m)

    # ── T21: title structure (field='title', no code-span exemption) ─────
    if "T21" in active and context.field == "title":
        violations.extend(_check_t21(nfkc))

    # ── T22: "let's / let us" ─────────────────────────────────────────────
    if "T22" in active:
        for m in _T22_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T22", (m.start(), m.end()), m.group()))

    # ── T23: paragraph word count (field-specific) ───────────────────────
    if "T23" in active and context.field not in (None, "title", "recommendation"):
        violations.extend(_check_t23(nfkc))

    # ── T24: absence phrases (model scope, fields: title/description/impact/attack_steps/notes) ──
    _T24_FIELDS = {"title", "description", "impact", "attack_steps", "notes"}
    if "T24" in active and context.field in _T24_FIELDS:
        violations.extend(_check_t24(nfkc, code_spans, context))

    # ── T25 (model scope): \bsoken\b everywhere ───────────────────────────
    if "T25" in active:
        for m in _T25_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T25", (m.start(), m.end()), m.group()))

    # ── T25_brand_only (server/public): soken unless part of soken.dev ───
    if "T25_brand_only" in active:
        for m in _T25_BRAND_ONLY_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T25", (m.start(), m.end()), m.group()))

    # ── T26: bare domain (skip when tlds.txt absent; never exempt) ────────
    if "T26" in active:
        tlds = _load_tlds()
        if tlds:
            violations.extend(_check_t26(nfkc, tlds))

    # ── T27: promotion phrases (never exempt) ────────────────────────────
    if "T27" in active:
        for m in _T27_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T27", (m.start(), m.end()), m.group()))

    # ── T28: counts near numbers (never exempt) ──────────────────────────
    if "T28" in active:
        violations.extend(_check_t28(nfkc))

    # ── T29: raw finding / lead ids (never exempt) ───────────────────────
    if "T29" in active:
        for m in _T29_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "T29", (m.start(), m.end()), m.group()))

    # ── T30: exploit sequence (public_review profile only) ───────────────
    _T30_FIELDS = {"description", "impact"}
    if "T30" in active and context.profile == "public_review" and context.field in _T30_FIELDS:
        violations.extend(_check_t30(nfkc, context))

    # ── T31: call syntax (model scope, code_span_exempt via valid spans) ──
    if "T31" in active:
        violations.extend(_check_t31(nfkc, code_spans, context))

    # ── P1: superlative / exclusivity ────────────────────────────────────
    if "P1" in active:
        for m in _P1_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "P1", (m.start(), m.end()), m.group()))

    # ── P2: competitor names ──────────────────────────────────────────────
    if "P2" in active and context.competitor_names:
        p2_re = _phrase_re(context.competitor_names)
        for m in p2_re.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "P2", (m.start(), m.end()), m.group()))

    # ── P3: score / finance wording ───────────────────────────────────────
    if "P3" in active:
        for m in _P3_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "P3", (m.start(), m.end()), m.group()))

    # ── P4: endorsement words near Anthropic/Claude ───────────────────────
    if "P4" in active:
        violations.extend(_check_p4(nfkc))

    # ── subject_words ─────────────────────────────────────────────────────
    if "subject_words" in active:
        for m in _SUBJECT_RE.finditer(nfkc):
            violations.append(Violation("E_TEXT_GATE", "subject_words", (m.start(), m.end()), m.group()))

    return violations


# ── Rule implementations ───────────────────────────────────────────────────


def _check_step0(text: str) -> list[Violation]:
    """Step 0 on the submitted string (04 §11.1, text_gate.yaml step0).

    Rejects: Cc except LF, any Cf, U+00AD, bidi controls; letters outside
    Latin/Common/Inherited script (outside code spans).
    """
    violations: list[Violation] = []
    # Detect code spans in the original text for script exemption
    orig_spans = _code_span_ranges(text)
    for i, ch in enumerate(text):
        cp = ord(ch)
        cat = unicodedata.category(ch)
        # Cc except LF (0x0A), Cf, U+00AD, bidi controls
        if cat == "Cc" and cp != 0x0A or cat == "Cf" or cp == _SOFT_HYPHEN or cp in _BIDI_CODEPOINTS:
            violations.append(Violation("E_TEXT_CONTROL_CHAR", "step0", (i, i + 1), ch))
        # Script check: letters (category L*) outside valid code spans
        elif cat.startswith("L") and not _in_code_span(i, orig_spans):
            script = _char_script(ch)
            if script not in _ALLOWED_SCRIPTS:
                violations.append(Violation("E_TEXT_SCRIPT", "step0", (i, i + 1), ch))
    return violations


def _check_t21(nfkc: str) -> list[Violation]:
    """T21: title 10-110 chars, one sentence, no trailing period, not only a code span (04 §11.2)."""
    violations: list[Violation] = []
    stripped = nfkc.strip()
    if len(stripped) < 10 or len(stripped) > 110:
        violations.append(Violation("E_TEXT_GATE", "T21", (0, len(nfkc)), nfkc))
        return violations  # further checks meaningless
    if stripped.endswith("."):
        violations.append(Violation("E_TEXT_GATE", "T21", (0, len(nfkc)), nfkc))
    # More than one sentence (contains a sentence-ending `.`, `!` or `?` not at the end)
    sentence_ends = re.findall(r"[.!?]", stripped[:-1])  # exclude last char
    if sentence_ends:
        violations.append(Violation("E_TEXT_GATE", "T21", (0, len(nfkc)), nfkc))
    # Not only a code span
    if re.fullmatch(r"\s*`[^`\n]+`\s*", nfkc):
        violations.append(Violation("E_TEXT_GATE", "T21", (0, len(nfkc)), nfkc))
    return violations


def _check_t23(nfkc: str) -> list[Violation]:
    """T23: paragraph at most 90 words (04 §11.2)."""
    violations: list[Violation] = []
    paragraphs = re.split(r"\n\s*\n", nfkc)
    for para in paragraphs:
        words = para.split()
        if len(words) > 90:
            violations.append(Violation("E_TEXT_GATE", "T23", (0, len(nfkc)), para[:60]))
    return violations


def _check_t24(nfkc: str, code_spans: list[tuple[int, int]], context: CheckContext) -> list[Violation]:
    """T24: absence/universal phrases must be bound to an absence_claims entry (04 §7.6, §11.2).

    Unbound matches produce E_ABSENCE_UNRESOLVED.
    Matches inside code spans are exempt (code_span_exempt).
    """
    violations: list[Violation] = []
    for m in _T24_ALL_RE.finditer(nfkc):
        if _match_in_code_span(m, code_spans):
            continue
        phrase = m.group()
        # Check if the phrase is covered by an absence claim
        bound = False
        for claim in context.absence_claims:
            says = claim.get("says", "")
            # The claim covers a phrase if the match lies inside an occurrence of says
            for cm in re.finditer(re.escape(says), nfkc, re.IGNORECASE):
                if cm.start() <= m.start() and m.end() <= cm.end():
                    bound = True
                    break
            if bound:
                break
        if not bound:
            violations.append(Violation("E_ABSENCE_UNRESOLVED", "T24", (m.start(), m.end()), phrase))
    return violations


def _check_t26(nfkc: str, tlds: frozenset[str]) -> list[Violation]:
    """T26: bare domain against IANA TLD list (04 §11.2, never exempt from code spans)."""
    violations: list[Violation] = []
    tld_alts = "|".join(re.escape(t) for t in sorted(tlds, key=len, reverse=True))
    if not tld_alts:
        return violations
    domain_re = re.compile(
        r"(?i)\b[a-z0-9-]+\s*(?:\.|dot)\s*(?:" + tld_alts + r")\b"
    )
    for m in domain_re.finditer(nfkc):
        # Exempt if it is part of the soken.dev allowlist (control 13 / T25_brand_only allows soken.dev)
        # URLs already caught by T17 which is never-exempt; T26 catches bare domains without protocol.
        violations.append(Violation("E_TEXT_GATE", "T26", (m.start(), m.end()), m.group()))
    return violations


def _check_t28(nfkc: str) -> list[Violation]:
    """T28: count nouns within 3 words of a number or magnitude word (04 §11.2)."""
    violations: list[Violation] = []
    # Tokenize into word tokens; strip trailing punctuation for matching only
    tokens = [(m.group(), m.start(), m.end()) for m in re.finditer(r"\S+", nfkc)]

    def _strip_punct(s: str) -> str:
        return s.rstrip(".,;:!?\"')")

    for idx, (word, start, end) in enumerate(tokens):
        if not re.fullmatch(r"(?i)projects|engagements|clients|reviews|audits", _strip_punct(word)):
            continue
        # Look at tokens within 3 positions on either side
        neighbours = tokens[max(0, idx - 3) : idx] + tokens[idx + 1 : idx + 4]
        for nword, _ns, _ne in neighbours:
            if _T28_NUM_RE.search(nword):
                violations.append(Violation("E_TEXT_GATE", "T28", (start, end), word))
                break
    return violations


def _check_t30(nfkc: str, context: CheckContext) -> list[Violation]:
    """T30: no ordered exploit sequence (04 §11.2 T30, public_review profile only)."""
    violations: list[Violation] = []
    # Condition 1: step marker
    for m in _T30_STEP_RE.finditer(nfkc):
        violations.append(Violation("E_TEXT_GATE", "T30", (m.start(), m.end()), m.group()))
        return violations  # one violation per text is sufficient
    # Condition 2: list item starting with the attacker pattern
    if context.is_list_item and _T30_LIST_ACTOR_RE.match(nfkc.lstrip()):
        violations.append(Violation("E_TEXT_GATE", "T30", (0, len(nfkc)), nfkc[:60]))
        return violations
    # Condition 3: sentence with actor + 2+ sequencing terms or 2+ line refs
    sentences = re.split(r"(?<=[.!?])\s+", nfkc)
    for sent in sentences:
        if not _T30_ACTOR_RE.search(sent):
            continue
        seq_count = len(_T30_SEQ_RE.findall(sent))
        lineref_count = len(_T30_LINEREF_RE.findall(sent))
        if seq_count >= 2 or lineref_count >= 2:
            start = nfkc.find(sent)
            violations.append(Violation("E_TEXT_GATE", "T30", (start, start + len(sent)), sent[:60]))
            return violations
    return violations


def _check_t31(nfkc: str, code_spans: list[tuple[int, int]], context: CheckContext) -> list[Violation]:
    """T31: call syntax outside a valid code span (04 §11.2 control 2, §11.3).

    When word_set is not provided any match outside a backtick span is flagged.
    """
    violations: list[Violation] = []
    for m in _T31_RE.finditer(nfkc):
        if _match_in_code_span(m, code_spans):
            continue
        violations.append(Violation("E_CODESPAN_NOT_IN_SOURCE", "T31", (m.start(), m.end()), m.group()))
    return violations


def _check_p4(nfkc: str) -> list[Violation]:
    """P4: endorsement words within 5 words of Anthropic or Claude (04 §11.1, 02)."""
    violations: list[Violation] = []
    tokens = list(re.finditer(r"\S+", nfkc))
    for idx, m in enumerate(tokens):
        if not _P4_ENDORSE_RE.search(m.group()):
            continue
        window = tokens[max(0, idx - 5) : idx] + tokens[idx + 1 : min(len(tokens), idx + 6)]
        for wm in window:
            if _P4_BRAND_RE.search(wm.group()):
                violations.append(Violation("E_TEXT_GATE", "P4", (m.start(), m.end()), m.group()))
                break
    return violations
