"""Vyper compiler advisories and construct detectors (05 6.2, 15; F30).

Same contract as the solc path (evm/compiler_bugs.py): for the exact recorded Vyper release,
every published GHSA whose vulnerable range may contain it gets a row:

  lead                 a construct detector matched: located lead, category evm.compiler_bug,
                       rule_id compiler.<GHSA id>
  construct_not_found  a detector exists and proved the construct absent (A3)
  not_machine_checked  no detector (A4)

Nothing runs for a pragma-guessed version (A1) or a pre-release.

Rule for every detector: a parse or delimit failure is a hit, never absence.
  - Source is tokenised with Python's `tokenize` (Vyper's lexer is Python's: comments, triple-
    quoted strings). If tokenising fails, every detector reports the whole file (line 1).
  - Decorator facts (@nonreentrant key and function) come from the Vyper compiler's own AST in
    the build output; without that AST, from the tokens; a decorator whose key or function
    cannot be resolved counts as a hit for every lock advisory.
  - A call whose arguments cannot be delimited counts as a hit.
Scanning is linear: one tokenize pass, one parenthesis-matching pass, no regex with nested or
overlapping quantifiers over source text.
"""

from __future__ import annotations

import bisect
import io
import json
import re
import tokenize
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from soken_review.adapters.evm.compiler_bugs import CATEGORY, CompilerBugReport
from soken_review.adapters.vyper.compiler import is_prerelease, short_version

_ADVISORIES_FILE = Path(__file__).parent / "data" / "vyper_advisories.json"
_AST_NODES_FILE = Path(__file__).parent / "data" / "vyper_ast_nodes.json"
KNOWN_AST_TYPES = frozenset(json.loads(_AST_NODES_FILE.read_text())["node_types"])


def _load() -> dict:
    return json.loads(_ADVISORIES_FILE.read_text())


def tool_id() -> str:
    return f"vyper-advisories@{_load()['checked_at']}"


# ---------------------------------------------------------------------------
# Versions and ranges (">= 0.2.15, < 0.3.1", "= 0.1.0b14", "< 0.4.2")
# ---------------------------------------------------------------------------

_VER = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?[-.]?(?:(a|b|rc|beta)\.?(\d+))?")


def vkey(version: str) -> tuple[int, ...] | None:
    m = _VER.fullmatch(short_version(version).strip()[:64])
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    if m.group(4):
        return (major, minor, patch, 0, int(m.group(5) or 0))
    return (major, minor, patch, 1, 0)


def in_range(version: str, spec: str | None) -> bool | None:
    """None when the range or version cannot be parsed (the caller keeps the advisory)."""
    v = vkey(version)
    if v is None or not spec:
        return None
    for part in spec.split(","):
        part = part.strip()
        op = next((o for o in (">=", "<=", ">", "<", "=") if part.startswith(o)), None)
        if op is None:
            return None
        bound = part[len(op):].strip()
        if bound == "0":
            bound = "0.0.0"
        b = vkey(bound)
        if b is None:
            return None
        ok = {">=": v >= b, "<=": v <= b, ">": v > b, "<": v < b, "=": v == b}[op]
        if not ok:
            return False
    return True


# ---------------------------------------------------------------------------
# Source view: comment-free text from tokens, decorator facts from the AST or tokens
# ---------------------------------------------------------------------------

UNRESOLVED = object()  # a key, name or keyword value that could not be resolved
ANY = object()         # needle: keyword present with any value

_POS_KEYS = frozenset({"lineno", "col_offset", "end_lineno", "end_col_offset", "node_id", "src", "pos"})
_LITERALS = frozenset({"NameConstant", "Int", "Str", "Bytes", "Hex", "Decimal", "Constant", "HexBytes"})

# Bounds that keep every detector linear in the file size (attacker-sized input):
MAX_AST_DEPTH = 300      # deeper AST: the file is a hit for every detector (never absence)
MAX_AST_NODES = 2_000_000
_ARG_WINDOW = 400        # text fallback: the first two call arguments are read within this window
_DECORATOR_WINDOW = 200  # tokens between a decorator and its `def`


@dataclass
class Lock:
    line: int
    key: Any       # str, "" for a bare 0.4 decorator, or UNRESOLVED
    function: Any  # str or UNRESOLVED


@dataclass
class CallFact:
    name: str
    line: int
    args: list[dict]
    keywords: dict[str, Any]  # keyword -> AST value node


@dataclass
class SourceView:
    """Facts for one source file, computed once (one tokenize pass or one AST walk).

    ast path:  calls, locks, internal-with-defaults and ternary-bitor lines from the Vyper AST
    text path: comment- and string-blanked text with precomputed indexes (no AST available)
    whole_file_hit: tokenising failed, the AST was too deep or too large: every detector reports
                    line 1 for this file (doubt keeps the advisory in scope)
    """
    text: str | None = None
    locks: list[Lock] = field(default_factory=list)
    has_ast: bool = False
    calls: list[CallFact] = field(default_factory=list)
    internal_default_lines: list[int] = field(default_factory=list)
    ternary_bitor_lines: list[int] = field(default_factory=list)
    balanced: bool = True
    whole_file_hit: bool = False
    hit_reason: str | None = None
    newlines: list[int] = field(default_factory=list)
    pairs: dict[int, int] = field(default_factory=dict)
    eq_positions: list[int] = field(default_factory=list)


def _tokens(src: str) -> list[tokenize.TokenInfo] | None:
    try:
        return list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def _blank(src: str, tokens: list[tokenize.TokenInfo], kinds: tuple[int, ...]) -> str:
    """Source with the given token kinds blanked to spaces (newlines and positions kept). Linear:
    each line is rebuilt once from its spans."""
    lines = src.splitlines(keepends=True)
    spans: dict[int, list[tuple[int, int]]] = {}
    for tok in tokens:
        if tok.type not in kinds:
            continue
        (r0, c0), (r1, c1) = tok.start, tok.end
        for r in range(r0, r1 + 1):
            if r - 1 >= len(lines):
                break
            end = c1 if r == r1 else len(lines[r - 1].rstrip("\r\n"))
            spans.setdefault(r, []).append((c0 if r == r0 else 0, end))
    for r, ss in spans.items():
        line = lines[r - 1]
        chars = list(line)
        for a, b in ss:
            for i in range(a, min(b, len(chars))):
                if chars[i] not in "\r\n":
                    chars[i] = " "
        lines[r - 1] = "".join(chars)
    return "".join(lines)


def code_text(src: str) -> str | None:
    """Source with comments blanked; None if tokenize fails."""
    toks = _tokens(src)
    return None if toks is None else _blank(src, toks, (tokenize.COMMENT,))


def strip_comments(src: str) -> str:
    """Comment-free source; unchanged if tokenize fails."""
    text = code_text(src)
    return src if text is None else text


def _lineno(node: dict) -> int:
    try:
        return max(1, int(node.get("lineno") or 1))
    except (TypeError, ValueError):
        return 1


def _literal(node: Any) -> Any:
    if isinstance(node, dict) and node.get("ast_type") in _LITERALS:
        return node.get("value")
    return UNRESOLVED


def _same(a: Any, b: Any, budget: int = 10_000) -> bool:
    """Structural AST equality ignoring positions; iterative, bounded. Over budget it answers
    True: the caller treats a match as a hit, so doubt keeps the advisory."""
    stack = [(a, b)]
    while stack:
        budget -= 1
        if budget < 0:
            return True
        x, y = stack.pop()
        if isinstance(x, dict) and isinstance(y, dict):
            kx = {k for k in x if k not in _POS_KEYS}
            if kx != {k for k in y if k not in _POS_KEYS}:
                return False
            stack.extend((x[k], y[k]) for k in kx)
        elif isinstance(x, list) and isinstance(y, list):
            if len(x) != len(y):
                return False
            stack.extend(zip(x, y))
        elif x != y:
            return False
    return True


def _is_msg_value(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    if node.get("ast_type") == "Attribute" and node.get("attr") == "value":
        return (node.get("value") or {}).get("id") == "msg"
    if node.get("ast_type") == "Call" and (node.get("func") or {}).get("id") == "len":
        args = node.get("args") or []
        return bool(args) and isinstance(args[0], dict) and args[0].get("attr") == "data" \
            and (args[0].get("value") or {}).get("id") == "msg"
    return False


def _ast_view(ast: dict) -> SourceView:
    """One iterative walk: calls, locks, internal defaults, ternary bit-or. Depth and size capped."""
    view = SourceView(has_ast=True)
    stack: list[tuple[Any, int, int | None]] = [(ast, 0, None)]  # (node, depth, enclosing IfExp line)
    seen = 0
    while stack:
        node, depth, ifexp = stack.pop()
        if isinstance(node, list):
            stack.extend((v, depth, ifexp) for v in node)
            continue
        if not isinstance(node, dict):
            continue
        seen += 1
        if depth > MAX_AST_DEPTH or seen > MAX_AST_NODES:
            return SourceView(has_ast=True, whole_file_hit=True, hit_reason="ast_over_cap")
        kind = node.get("ast_type")
        if kind is not None and kind not in KNOWN_AST_TYPES:
            # a node this code does not know may hold any construct: doubt keeps every advisory
            return SourceView(has_ast=True, whole_file_hit=True, hit_reason=f"unknown_ast_node:{str(kind)[:40]}")
        if kind == "IfExp" and ifexp is None:
            ifexp = _lineno(node)
        elif kind == "Call":
            func = node.get("func") or {}
            name = func.get("id") if func.get("ast_type") == "Name" else func.get("attr")
            if isinstance(name, str):
                kws = {k.get("arg"): k.get("value") for k in node.get("keywords") or [] if isinstance(k, dict)}
                view.calls.append(CallFact(name, _lineno(node), [a for a in node.get("args") or [] if isinstance(a, dict)], kws))
        elif kind == "BinOp" and ifexp is not None and (node.get("op") or {}).get("ast_type") == "BitOr" \
                and (_is_msg_value(node.get("left")) or _is_msg_value(node.get("right"))):
            view.ternary_bitor_lines.append(ifexp)
        elif kind == "FunctionDef":
            name = node.get("name") if isinstance(node.get("name"), str) else UNRESOLVED
            decs = [d for d in node.get("decorator_list") or [] if isinstance(d, dict)]
            # a function not marked @external/@deploy may be internal (0.4 default): doubt = internal
            explicit_external = any(d.get("id") in ("external", "deploy") for d in decs)
            if not explicit_external and ((node.get("args") or {}).get("defaults") or []):
                view.internal_default_lines.append(_lineno(node))
            for dec in decs:
                if dec.get("ast_type") == "Name" and dec.get("id") == "nonreentrant":
                    view.locks.append(Lock(_lineno(dec), "", name))
                elif dec.get("ast_type") == "Call" and (dec.get("func") or {}).get("id") == "nonreentrant":
                    args = dec.get("args") or []
                    val = args[0].get("value") if len(args) == 1 and isinstance(args[0], dict) else None
                    view.locks.append(Lock(_lineno(dec), val if isinstance(val, str) else UNRESOLVED, name))
        stack.extend((v, depth + 1, ifexp) for v in node.values() if isinstance(v, (dict, list)))
    view.ternary_bitor_lines = sorted(set(view.ternary_bitor_lines))
    return view


def _token_locks(tokens: list[tokenize.TokenInfo]) -> list[Lock]:
    """`@ nonreentrant [ ( STRING ) ]` then the next `def NAME`; next-def index precomputed (linear)."""
    toks = [t for t in tokens if t.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT,
                                                 tokenize.INDENT, tokenize.DEDENT)]
    next_def = [-1] * (len(toks) + 1)
    for k in range(len(toks) - 1, -1, -1):
        next_def[k] = k if toks[k].type == tokenize.NAME and toks[k].string == "def" else next_def[k + 1]
    locks: list[Lock] = []
    for i, t in enumerate(toks):
        if not (t.type == tokenize.OP and t.string == "@" and i + 1 < len(toks) and toks[i + 1].string == "nonreentrant"):
            continue
        j = i + 2
        key: Any = ""
        if j < len(toks) and toks[j].string == "(":
            if j + 2 < len(toks) and toks[j + 1].type == tokenize.STRING and toks[j + 2].string == ")":
                lit = toks[j + 1].string
                key = lit[1:-1] if len(lit) >= 2 and lit[:1] in "'\"" and lit[-1:] == lit[:1] else UNRESOLVED
                j += 3
            else:
                key = UNRESOLVED
        fn: Any = UNRESOLVED
        k = next_def[j] if j < len(toks) else -1
        if k != -1 and k - j <= _DECORATOR_WINDOW and k + 1 < len(toks) and toks[k + 1].type == tokenize.NAME:
            fn = toks[k + 1].string
        locks.append(Lock(t.start[0], key, fn))
    return locks


def _text_indexes(view: SourceView) -> None:
    """Newline offsets, matching parentheses and `=` offsets: one pass each."""
    text = view.text or ""
    stack: list[int] = []
    balanced = True
    for i, c in enumerate(text):
        if c == "\n":
            view.newlines.append(i)
        elif c == "(":
            stack.append(i)
        elif c == ")":
            if stack:
                view.pairs[stack.pop()] = i
            else:
                balanced = False
        elif c == "=":
            view.eq_positions.append(i)
    view.balanced = balanced and not stack


def source_view(src: str, ast: Any = None) -> SourceView:
    """AST facts when the compiler AST is present; else text with comments and strings blanked."""
    if isinstance(ast, dict) and "ast_type" in ast:
        return _ast_view(ast)
    toks = _tokens(src)
    if toks is None:
        return SourceView(whole_file_hit=True, hit_reason="tokenize_failed")
    view = SourceView(text=_blank(src, toks, (tokenize.COMMENT, tokenize.STRING)), locks=_token_locks(toks))
    _text_indexes(view)
    return view


# ---------------------------------------------------------------------------
# Text fallback helpers (indexes from SourceView; no rescans)
# ---------------------------------------------------------------------------

def _line(view: SourceView, offset: int) -> int:
    return bisect.bisect_left(view.newlines, offset) + 1


def _text_calls(view: SourceView, name: str) -> list[tuple[int, int, int | None]]:
    """(name offset, open paren, matching close or None) of every `name(`."""
    return [(m.start(), m.end() - 1, view.pairs.get(m.end() - 1))
            for m in re.finditer(rf"\b{re.escape(name)}[ \t]*\(", view.text or "")]


def _first_two_args(text: str, open_paren: int, close: int) -> tuple[str, str] | None:
    """The first two top-level arguments, read within _ARG_WINDOW; None when not delimited there."""
    depth, comma, i = 0, -1, open_paren + 1
    limit = min(close, open_paren + _ARG_WINDOW)
    while i < limit:
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            comma = i
            break
        i += 1
    if comma == -1:
        # whole call read and no top-level comma: a one-argument call, provably not (x, x + N)
        return ("", "") if close <= open_paren + _ARG_WINDOW else None
    first = "".join(text[open_paren + 1 : comma].split())
    second = "".join(text[comma + 1 : min(close, comma + 1 + len(first) + _ARG_WINDOW)].split())
    return first, second


def _has_between(positions: list[int], a: int, b: int) -> bool:
    i = bisect.bisect_right(positions, a)
    return i < len(positions) and positions[i] < b


# ---------------------------------------------------------------------------
# Detectors: SourceView -> hit lines (each linear in the file through the precomputed view)
# ---------------------------------------------------------------------------

def d_nonreentrant_any(v: SourceView) -> list[int]:
    return [lk.line for lk in v.locks]


def d_nonreentrant_shared_key(v: SourceView) -> list[int]:
    by_key: dict[str, set[str]] = {}
    for lk in v.locks:
        if lk.key is not UNRESOLVED and lk.function is not UNRESOLVED:
            by_key.setdefault(lk.key, set()).add(lk.function)
    return [
        lk.line for lk in v.locks
        if lk.key is UNRESOLVED or lk.function is UNRESOLVED or len(by_key.get(lk.key, ())) > 1
    ]


def d_nonreentrant_empty_key(v: SourceView) -> list[int]:
    return [lk.line for lk in v.locks if lk.key is UNRESOLVED or lk.key == ""]


def d_nonreentrant_default(v: SourceView) -> list[int]:
    return [lk.line for lk in v.locks if lk.function is UNRESOLVED or lk.function == "__default__"]


def _call_detector(*names: str) -> Callable[[SourceView], list[int]]:
    def det(v: SourceView) -> list[int]:
        if v.has_ast:
            return sorted(c.line for c in v.calls if c.name in names)
        if not v.balanced:
            return [1]
        return sorted(_line(v, o) for name in names for o, _, _ in _text_calls(v, name))
    det.__name__ = "calls_" + "_".join(names)
    return det


def _raw_call_with(*groups: dict[str, Any]) -> Callable[[SourceView], list[int]]:
    """raw_call with every keyword of one group; a keyword whose value is not a literal may hold
    the needle, so it counts as a match. Text fallback: keyword `name =` occurrences indexed once,
    then a binary search per call (no argument slicing)."""
    def det(v: SourceView) -> list[int]:
        if v.has_ast:
            out = []
            for c in v.calls:
                if c.name != "raw_call":
                    continue
                if any(all(k in c.keywords and (want is ANY or _literal(c.keywords[k]) in (want, UNRESOLVED))
                           for k, want in g.items()) for g in groups):
                    out.append(c.line)
            return out
        if not v.balanced:
            return [1]
        text = v.text or ""
        index = {k: [m.start() for m in re.finditer(rf"\b{re.escape(k)}[ \t]*=", text)]
                 for g in groups for k in g}
        out = []
        for o, op, close in _text_calls(v, "raw_call"):
            # keyword present inside the call; its value is not read in text mode (doubt = match)
            if close is None or any(all(_has_between(index[k], op, close) for k in g) for g in groups):
                out.append(_line(v, o))
        return out
    det.__name__ = "raw_call_with"
    return det


def d_range_start_plus_n(v: SourceView) -> list[int]:
    if v.has_ast:
        out = []
        for c in v.calls:
            if c.name == "range" and len(c.args) >= 2:
                second = c.args[1]
                if second.get("ast_type") == "BinOp" and (second.get("op") or {}).get("ast_type") == "Add" \
                        and _same(second.get("left"), c.args[0]):
                    out.append(c.line)
        return out
    if not v.balanced:
        return [1]
    out = []
    text = v.text or ""
    for o, op, close in _text_calls(v, "range"):
        two = _first_two_args(text, op, close) if close is not None else None
        if two is None or (two[0] and two[1].startswith(two[0] + "+")):
            out.append(_line(v, o))
    return out


def d_internal_default_args(v: SourceView) -> list[int]:
    if v.has_ast:
        return list(v.internal_default_lines)
    if not v.balanced:
        return [1]
    out = []
    text = v.text or ""
    for m in re.finditer(r"@internal\b", text):
        d = text.find("def ", m.end(), m.end() + 2000)
        p = text.find("(", d, d + 200) if d != -1 else -1
        close = v.pairs.get(p) if p != -1 else None
        if close is None or _has_between(v.eq_positions, p, close):
            out.append(_line(v, d if d != -1 else m.start()))
    return out


def d_msg_value_or_in_ternary(v: SourceView) -> list[int]:
    if v.has_ast:
        return list(v.ternary_bitor_lines)
    # text: any msg.value / msg.data line in a file that has both `|` and `if` (a ternary may span
    # lines; the text cannot prove it does not)
    text = v.text or ""
    if "|" not in text or "if" not in text:
        return []
    return [n for n, line in enumerate(text.split("\n"), start=1) if "msg.value" in line or "msg.data" in line]


DETECTORS: dict[str, Callable[[SourceView], list[int]]] = {
    "GHSA-5824-cm3x-3c38": d_nonreentrant_shared_key,   # named locks misallocated, 0.2.15 to 0.3.0 (F30)
    "GHSA-7f92-rr6w-cq64": d_nonreentrant_any,          # storage overwritten by locks
    "GHSA-3hg2-r75x-g69m": d_nonreentrant_empty_key,
    "GHSA-m2v9-w374-5hj9": d_nonreentrant_default,
    "GHSA-f5x6-7qgp-jhf3": _call_detector("ecrecover"),
    "GHSA-vgf2-gvx8-xwc3": _call_detector("ecrecover", "ecadd", "ecmul"),
    "GHSA-x2c2-q32w-4w6m": _raw_call_with({"value": ANY, "is_static_call": True},
                                          {"value": ANY, "is_delegate_call": True}),
    "GHSA-w9g2-3w7p-72g9": _raw_call_with({"max_outsize": 0, "revert_on_failure": False}),
    "GHSA-9x7f-gwxq-6f2c": _call_detector("slice"),
    "GHSA-r56x-j438-vw5m": _call_detector("slice"),
    "GHSA-3vcg-j39x-cwfm": _call_detector("slice"),
    "GHSA-2q8v-3gqq-4f8p": _call_detector("concat"),
    "GHSA-qhr6-mgqr-mchm": _call_detector("concat"),
    "GHSA-6r8q-pfpv-7cgj": d_range_start_plus_n,
    "GHSA-ppx5-q359-pvwj": d_range_start_plus_n,
    "GHSA-ph9x-4vc9-m39g": d_internal_default_args,
    "GHSA-5jrj-52x8-m64h": _call_detector("sqrt"),
    "GHSA-2p94-8669-xg86": _call_detector("sqrt"),
    "GHSA-xchq-w5r3-4wg3": _call_detector("raw_log"),
    "GHSA-3whq-64q2-qfj6": _call_detector("create_from_blueprint"),
    "GHSA-fxg7-4wqg-c8gh": _call_detector("create_from_blueprint"),
    "GHSA-4hwq-4cpm-8vmx": _call_detector("extract32"),
    "GHSA-9p8r-4xp4-gw5w": _call_detector("_abi_decode", "abi_decode"),
    "GHSA-cx2q-hfxr-rj97": _call_detector("_abi_decode", "abi_decode"),
    "GHSA-375m-5fvv-xq23": _call_detector("create_forwarder_to"),
    "GHSA-6j9c-gvcw-74fj": d_msg_value_or_in_ternary,
}


def run_detector(det: Callable[[SourceView], list[int]], view: SourceView | tuple[SourceView, ...]) -> list[int]:
    """Hit lines over every view of a file (AST and text): the union, so a construct either
    parser sees is reported. A view that could not be read (tokenize failed, unknown AST node,
    AST over the depth or size cap) is a hit on line 1: doubt keeps the advisory in scope."""
    views = view if isinstance(view, tuple) else (view,)
    hits: set[int] = set()
    for v in views:
        hits.update([1] if v.whole_file_hit else det(v))
    return sorted(hits)


def file_views(src: str, ast: Any = None) -> tuple[SourceView, ...]:
    """The text view always; the AST view too when the compiler AST is present."""
    text_view = source_view(src)
    if isinstance(ast, dict) and "ast_type" in ast:
        return (source_view(src, ast), text_view)
    if ast is not None:  # present but not a Vyper AST we can read
        return (SourceView(has_ast=True, whole_file_hit=True, hit_reason="ast_unreadable"), text_view)
    return (text_view,)


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def vyper_report(version: str, pinned_by: str | None, std_input: dict, output: dict | None = None) -> CompilerBugReport:
    if not version:
        return CompilerBugReport("not_run", "compiler_version_unknown")
    if (pinned_by or "").startswith("pragma"):
        return CompilerBugReport("not_run", "version_pinned_by_pragma", version)  # A1
    # a version we cannot place (pre-release, unparsed) keeps every advisory in scope as unknown
    version_known = not is_prerelease(version) and vkey(version) is not None
    data = _load()
    tool = tool_id()
    out_sources = (output or {}).get("sources") or {}
    views = {
        key: file_views((v or {}).get("content") or "", (out_sources.get(key) or {}).get("ast"))
        for key, v in (std_input.get("sources") or {}).items()
    }
    report = CompilerBugReport("ok", None, version)
    for adv in data["advisories"]:
        hits = [in_range(version, r.get("vulnerable")) for r in adv.get("ranges") or []] if version_known else [None]
        if not hits:
            hits = [None]  # no range published: cannot prove the version is outside
        if not any(h is not False for h in hits):  # every range proves the version is outside
            continue
        row = {
            "compiler": "vyper", "version": short_version(version), "bug": adv["ghsa_id"],
            "severity": adv.get("severity"), "link": adv.get("url"), "conditions": {},
            "conditions_unknown": (["version"] if not version_known else ["version_range"] if True not in hits else []),
            "rule_id": f"compiler.{adv['ghsa_id']}",
        }
        det = DETECTORS.get(adv["ghsa_id"])
        if det is None:
            row["status"] = "not_machine_checked"
            report.advisories.append(row)
            continue
        found = [(key, line) for key, view in views.items() for line in run_detector(det, view)]
        row["status"] = "lead" if found else "construct_not_found"
        row["detector"] = det.__name__
        bad = {k: sorted({v.hit_reason or "unbalanced_text" for v in vs
                          if v.whole_file_hit or (not v.has_ast and not v.balanced)})
               for k, vs in views.items()}
        bad = {k: r for k, r in bad.items() if r}
        if bad:
            row["unparsed_sources"] = sorted(bad)
            row["unparsed_reasons"] = bad
        for key, line in found:
            report.raw_leads.append({
                "tool": tool, "rule_id": f"compiler.{adv['ghsa_id']}", "severity_raw": adv.get("severity") or "",
                "file": key, "start": line, "end": line, "category": CATEGORY,
            })
        report.advisories.append(row)
    return report
