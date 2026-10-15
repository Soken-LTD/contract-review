"""One lexer per file: grammar parser, else the fallback lexer (04 sections 2.1, 2.2; lexers.yaml).

`lex_file(path, text)` returns tokens (`map.v1` token kinds), spans (functions, modifiers,
handlers; grammar only), declaration lines per identifier (for `references`) and constant
initializers (for `constants[].folded_value`). Pure: no I/O beyond loading `lexers.yaml` once.

Grammar parsers: tree-sitter Solidity and Rust (lexers.yaml `grammar`). A file whose parse tree has
error nodes keeps the grammar tokens with status `partial`; a grammar that cannot load or a parse
that yields no tree goes through the fallback lexer (tokens, no spans).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fractions import Fraction
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import yaml

_LEXERS_YAML = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "lexers.yaml"

TOKEN_KINDS = ("identifier", "keyword", "type_name", "operator", "punct", "literal_num", "literal_str", "comment")


@dataclass(frozen=True)
class Token:
    line: int       # 1-based line of the token start
    col: int        # 1-based character column
    kind: str       # one of TOKEN_KINDS
    text: str

    def to_json(self) -> dict[str, Any]:
        return {"line": self.line, "col": self.col, "kind": self.kind, "text": self.text}


@dataclass(frozen=True)
class Span:
    name: str
    kind: str          # function | modifier | handler
    start: int
    end: int
    unit: str | None   # enclosing contract, library, interface or Rust module (lexical)


@dataclass(frozen=True)
class LexUnit:
    name: str
    kind: str          # contract | interface | library | module
    start: int
    end: int


@dataclass
class LexResult:
    lang: str
    lexer: str                     # grammar | fallback
    status: str                    # ok | partial | failed
    error_class: str | None = None
    tokens: list[Token] = field(default_factory=list)
    spans: list[Span] = field(default_factory=list)
    units: list[LexUnit] = field(default_factory=list)
    decls: dict[str, set[int]] = field(default_factory=dict)
    constants: list[tuple[str, int, list[Token]]] = field(default_factory=list)  # name, line, initializer tokens
    unterminated: list[tuple[int, str]] = field(default_factory=list)  # (line, "comment" | "string"), fallback only


# ── configuration ────────────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def _config() -> dict[str, Any]:
    return yaml.safe_load(_LEXERS_YAML.read_text(encoding="utf-8"))


def language_for(path: str) -> str:
    """Language key by file extension (lexers.yaml `extensions`); `default` when unknown."""
    ext = Path(path).suffix.lower()
    return _config()["extensions"].get(ext, "default")


@cache
def _fallback_cfg(lang: str) -> dict[str, Any]:
    fb = _config()["fallback"]
    cfg = dict(fb["default"])
    cfg.update(fb.get(lang) or {})
    return cfg


@cache
def _grammar(lang: str):
    """tree-sitter Parser for `lang`, or None when the grammar is not listed or cannot load."""
    module = _config()["grammar"].get(lang)
    if not module:
        return None
    try:
        import importlib
        import warnings

        import tree_sitter as ts

        mod = importlib.import_module(module)
        with warnings.catch_warnings():
            # tree-sitter-solidity 1.2.13 hands an int pointer to Language(); deprecated, still supported
            warnings.simplefilter("ignore", DeprecationWarning)
            return ts.Parser(ts.Language(mod.language()))
    except Exception:  # noqa: BLE001  # grammar missing or ABI mismatch: fallback lexer (04 2.2)
        return None


def lex_file(path: str, text: str) -> LexResult:
    """Tokenize one pinned file (LF-normalized text)."""
    lang = language_for(path)
    parser = _grammar(lang)
    if parser is not None:
        result = _lex_grammar(lang, parser, text)
        if result is not None:
            return result
    return lex_fallback(lang, text)


# ── column helper ────────────────────────────────────────────────────────────


class _Lines:
    """Byte point (row, byte column) to 1-based (line, char column)."""

    def __init__(self, text: str) -> None:
        self._lines = text.split("\n")
        self._ascii = text.isascii()

    def col(self, row: int, byte_col: int) -> int:
        if self._ascii or row >= len(self._lines):
            return byte_col + 1
        return len(self._lines[row].encode("utf-8")[:byte_col].decode("utf-8", errors="ignore")) + 1


# ── grammar lexers (tree-sitter) ─────────────────────────────────────────────

_OPERATOR_TEXTS = frozenset(_fallback_cfg("default")["operators"]) | frozenset(
    {"=", "?", ":", "..", "..=", "=>", "->", "@"}
) - frozenset({":"})
_WORD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_SOL_STRING_NODES = frozenset({"string_literal", "hex_string_literal", "unicode_string_literal", "string",
                               "yul_string_literal"})
_SOL_DECL_NODES = frozenset({
    "contract_declaration", "interface_declaration", "library_declaration", "struct_declaration",
    "enum_declaration", "event_definition", "error_declaration", "function_definition", "modifier_definition",
    "state_variable_declaration", "constant_variable_declaration", "user_defined_type_definition",
    "struct_member", "parameter", "event_parameter", "error_parameter", "variable_declaration",
})
_SOL_UNIT_NODES = {"contract_declaration": "contract", "interface_declaration": "interface",
                   "library_declaration": "library"}
_SOL_SPAN_NODES = {"function_definition": "function", "modifier_definition": "modifier",
                   "constructor_definition": "function", "fallback_receive_definition": "function"}

_RUST_STRING_NODES = frozenset({"string_literal", "raw_string_literal", "char_literal"})
_RUST_COMMENT_NODES = frozenset({"line_comment", "block_comment"})
_RUST_DECL_NODES = frozenset({
    "function_item", "function_signature_item", "struct_item", "enum_item", "union_item", "const_item",
    "static_item", "mod_item", "trait_item", "type_item", "field_declaration", "enum_variant",
    "let_declaration", "parameter", "macro_definition",
})


def _lex_grammar(lang: str, parser, text: str) -> LexResult | None:
    try:
        tree = parser.parse(text.encode("utf-8"))
    except Exception:  # noqa: BLE001  # parser failure: fallback lexer (04 2.2)
        return None
    root = tree.root_node
    if root is None:
        return None
    res = LexResult(lang=lang, lexer="grammar", status="partial" if root.has_error else "ok")
    if root.has_error:
        res.error_class = "parse_error"
    lines = _Lines(text)
    if lang == "solidity":
        _SolWalker(res, lines).walk(root)
    elif lang == "rust":
        _RustWalker(res, lines).walk(root)
    else:
        return None
    res.tokens.sort(key=lambda t: (t.line, t.col))
    return res


class _Walker:
    """Shared tree walk: emit tokens, record declarations, spans and units."""

    comment_nodes: frozenset[str] = frozenset({"comment"})
    string_nodes: frozenset[str] = frozenset()
    number_nodes: frozenset[str] = frozenset()
    type_leaf_nodes: frozenset[str] = frozenset()
    identifier_leaf_nodes: frozenset[str] = frozenset({"identifier"})
    decl_nodes: frozenset[str] = frozenset()

    def __init__(self, res: LexResult, lines: _Lines) -> None:
        self.res = res
        self.lines = lines

    def tok(self, node, kind: str, text: str | None = None) -> Token:
        row, bcol = node.start_point
        t = Token(row + 1, self.lines.col(row, bcol), kind, text if text is not None else _text(node))
        self.res.tokens.append(t)
        return t

    def walk(self, node, unit: str | None = None) -> None:
        stack = [(node, unit)]
        while stack:
            n, u = stack.pop()
            u = self.enter(n, u)
            t = n.type
            if t in self.comment_nodes:
                self.tok(n, "comment")
                continue
            if t in self.string_nodes:
                self.tok(n, "literal_str")
                continue
            if t in self.number_nodes:
                self.number(n)
                continue
            if n.child_count == 0:
                self.leaf(n)
                continue
            stack.extend((c, u) for c in reversed(n.children))

    def enter(self, node, unit: str | None) -> str | None:
        if node.type in self.decl_nodes:
            for name_node in self.decl_names(node):
                self.res.decls.setdefault(_text(name_node), set()).add(name_node.start_point[0] + 1)
        return unit

    def decl_names(self, node) -> list:
        n = node.child_by_field_name("name")
        if n is not None and n.type in ("identifier", "type_identifier", "field_identifier"):
            return [n]
        for c in node.children:
            if c.type == "identifier":
                return [c]
        return []

    def number(self, node) -> None:
        self.tok(node, "literal_num")

    def leaf(self, node) -> None:
        t = node.type
        txt = _text(node)
        if not txt.strip():
            return
        if t in self.identifier_leaf_nodes:
            self.tok(node, "identifier", txt)
        elif t in self.type_leaf_nodes or (node.parent is not None and node.parent.type in self.type_leaf_nodes):
            self.tok(node, "type_name", txt)
        elif not node.is_named and _WORD_RE.match(txt):
            self.tok(node, "keyword", txt)
        elif _WORD_RE.match(txt) or any(ch.isalpha() for ch in txt):
            # named leaves such as `self`, `super`, ERROR-node words: identifiers unless keyword-like
            self.tok(node, "keyword" if t in ("self", "super", "crate", "mutable_specifier") else "identifier", txt)
        elif txt in _OPERATOR_TEXTS:
            self.tok(node, "operator", txt)
        else:
            self.tok(node, "punct", txt)


class _SolWalker(_Walker):
    string_nodes = _SOL_STRING_NODES
    number_nodes = frozenset({"number_literal", "hex_number", "decimal_number", "yul_decimal_number",
                              "yul_hex_number", "solidity_version"})
    type_leaf_nodes = frozenset({"primitive_type"})
    identifier_leaf_nodes = frozenset({"identifier", "yul_identifier", "yul_evm_builtin"})
    decl_nodes = _SOL_DECL_NODES

    def enter(self, node, unit):
        unit = super().enter(node, unit)
        t = node.type
        if t in _SOL_UNIT_NODES:
            name = node.child_by_field_name("name") or next((c for c in node.children if c.type == "identifier"), None)
            if name is not None:
                unit = _text(name)
                self.res.units.append(LexUnit(unit, _SOL_UNIT_NODES[t], node.start_point[0] + 1, node.end_point[0] + 1))
        elif t in _SOL_SPAN_NODES:
            self.res.spans.append(Span(self._span_name(node), _SOL_SPAN_NODES[t], node.start_point[0] + 1,
                                       node.end_point[0] + 1, unit))
        elif t in ("state_variable_declaration", "constant_variable_declaration"):
            self._constant(node)
        return unit

    @staticmethod
    def _span_name(node) -> str:
        t = node.type
        if t == "constructor_definition":
            return "constructor"
        if t == "fallback_receive_definition":
            first = node.children[0] if node.children else None
            word = _text(first) if first is not None else "fallback"
            return word if word in ("receive", "fallback") else "fallback"
        name = node.child_by_field_name("name") or next((c for c in node.children if c.type == "identifier"), None)
        return _text(name) if name is not None else "function"

    def _constant(self, node) -> None:
        children = node.children
        if node.type == "state_variable_declaration" and not any(_text(c) == "constant" for c in children
                                                                  if not c.is_named):
            return
        names = self.decl_names(node)
        value = node.child_by_field_name("value")
        if value is None:
            for i, c in enumerate(children):
                if _text(c) == "=" and i + 1 < len(children):
                    value = children[i + 1]
                    break
        if not names or value is None:
            return
        sub = LexResult(lang="solidity", lexer="grammar", status="ok")
        _SolWalker(sub, self.lines).walk(value)
        sub.tokens.sort(key=lambda t: (t.line, t.col))
        self.res.constants.append((_text(names[0]), names[0].start_point[0] + 1, sub.tokens))

    def number(self, node) -> None:
        # `1 ether`: one number_literal with a number_unit child; emit the digits and the unit word.
        unit = next((c for c in node.children if c.type == "number_unit"), None)
        if unit is None:
            self.tok(node, "literal_num", _text(node).strip())
            return
        digits = _text(node)[: unit.start_byte - node.start_byte].strip()
        self.tok(node, "literal_num", digits)
        self.tok(unit, "keyword", _text(unit))


class _RustWalker(_Walker):
    comment_nodes = _RUST_COMMENT_NODES
    string_nodes = _RUST_STRING_NODES
    number_nodes = frozenset({"integer_literal", "float_literal"})
    type_leaf_nodes = frozenset({"primitive_type", "type_identifier"})
    identifier_leaf_nodes = frozenset({"identifier", "field_identifier", "shorthand_field_identifier"})
    decl_nodes = _RUST_DECL_NODES

    def decl_names(self, node) -> list:
        if node.type in ("let_declaration", "parameter"):
            pat = node.child_by_field_name("pattern")
            if pat is None:
                return []
            if pat.type == "identifier":
                return [pat]
            return [c for c in _descendants(pat) if c.type == "identifier"]
        return super().decl_names(node)

    def enter(self, node, unit):
        unit = super().enter(node, unit)
        t = node.type
        if t == "mod_item":
            name = node.child_by_field_name("name")
            if name is not None:
                unit = _text(name)
                self.res.units.append(LexUnit(unit, "module", node.start_point[0] + 1, node.end_point[0] + 1))
        elif t == "impl_item":
            ty = node.child_by_field_name("type")
            if ty is not None:
                unit = _text(ty)
        elif t == "function_item":
            name = node.child_by_field_name("name")
            if name is not None:
                self.res.spans.append(Span(_text(name), "function", node.start_point[0] + 1,
                                           node.end_point[0] + 1, unit))
        elif t in ("const_item", "static_item"):
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and value is not None:
                sub = LexResult(lang="rust", lexer="grammar", status="ok")
                _RustWalker(sub, self.lines).walk(value)
                sub.tokens.sort(key=lambda t: (t.line, t.col))
                self.res.constants.append((_text(name), name.start_point[0] + 1, sub.tokens))
        return unit


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None and node.text is not None else ""


def _descendants(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


# ── fallback lexer (lexers.yaml) ─────────────────────────────────────────────

_DECL_KEYWORDS = frozenset({"def", "fun", "fn", "const", "struct", "event", "contract", "trait", "message",
                            "module", "let", "var", "val", "global", "enum", "interface", "flag", "type", "mod",
                            "impl", "get"})


def lex_fallback(lang: str, text: str) -> LexResult:
    """Fallback lexer: comments, strings, numbers, identifiers, operators (04 2.2). No spans."""
    cfg = _fallback_cfg(lang)
    res = LexResult(lang=lang, lexer="fallback", status="ok")
    keywords = frozenset(cfg.get("keywords") or [])
    type_names = frozenset(cfg.get("type_names") or [])
    ident_re = re.compile(cfg["identifier"])
    num_re = re.compile(cfg["number"])
    ops = sorted(cfg["operators"], key=len, reverse=True)
    line_comments = list(cfg.get("line_comment") or [])
    block_comments = [tuple(b) for b in (cfg.get("block_comment") or [])]
    nested = bool(cfg.get("nested_block_comment"))
    strings = sorted(cfg.get("strings") or [], key=len, reverse=True)
    byte_prefixes = tuple(cfg.get("byte_string_prefixes") or [])
    doc_as_comment = bool(cfg.get("docstring_is_comment"))
    multiline = bool(cfg.get("multiline_strings"))

    n = len(text)
    pos = 0
    line = 1
    line_start = 0

    def emit(start: int, end: int, kind: str, start_line: int, start_col: int) -> None:
        res.tokens.append(Token(start_line, start_col, kind, text[start:end]))

    while pos < n:
        ch = text[pos]
        if ch == "\n":
            line += 1
            pos += 1
            line_start = pos
            continue
        if ch.isspace():
            pos += 1
            continue
        tl, tc = line, pos - line_start + 1
        # line comment
        lc = next((m for m in line_comments if text.startswith(m, pos)), None)
        if lc is not None:
            end = text.find("\n", pos)
            end = n if end < 0 else end
            emit(pos, end, "comment", tl, tc)
            pos = end
            continue
        # block comment
        bc = next((b for b in block_comments if text.startswith(b[0], pos)), None)
        if bc is not None:
            opener, closer = bc
            depth, i = 1, pos + len(opener)
            while i < n and depth:
                if nested and text.startswith(opener, i):
                    depth += 1
                    i += len(opener)
                elif text.startswith(closer, i):
                    depth -= 1
                    i += len(closer)
                else:
                    i += 1
            if depth:
                res.unterminated.append((tl, "comment"))
            line, line_start = _advance(text, pos, i, line, line_start)
            emit(pos, i, "comment", tl, tc)
            pos = i
            continue
        # strings (with optional byte prefix: b"..", x"..")
        prefix = 0
        if byte_prefixes and ch in byte_prefixes and pos + 1 < n and text[pos + 1] in ('"', "'"):
            prefix = 1
        delim = next((d for d in strings if text.startswith(d, pos + prefix)), None)
        if delim is not None:
            i = pos + prefix + len(delim)
            closed = False
            while i < n:
                if text[i] == "\\" and len(delim) == 1:
                    i += 2
                    continue
                if text.startswith(delim, i):
                    i += len(delim)
                    closed = True
                    break
                if len(delim) == 1 and text[i] == "\n" and not multiline:
                    break  # unterminated single-line string ends at the line end
                i += 1
            i = min(i, n)
            if not closed:
                res.unterminated.append((tl, "string"))
            line, line_start = _advance(text, pos, i, line, line_start)
            kind = "comment" if (doc_as_comment and len(delim) == 3) else "literal_str"
            emit(pos, i, kind, tl, tc)
            pos = i
            continue
        m = num_re.match(text, pos)
        if m and m.end() > pos and ch.isdigit():
            emit(pos, m.end(), "literal_num", tl, tc)
            pos = m.end()
            continue
        m = ident_re.match(text, pos)
        if m and m.end() > pos:
            word = m.group(0)
            kind = "keyword" if word in keywords else ("type_name" if word in type_names else "identifier")
            emit(pos, m.end(), kind, tl, tc)
            pos = m.end()
            continue
        op = next((o for o in ops if text.startswith(o, pos)), None)
        if op is not None:
            emit(pos, pos + len(op), "operator", tl, tc)
            pos += len(op)
            continue
        emit(pos, pos + 1, "punct", tl, tc)
        pos += 1

    _fallback_decls_and_constants(res, lang)
    return res


def _advance(text: str, start: int, end: int, line: int, line_start: int) -> tuple[int, int]:
    nl = text.count("\n", start, end)
    if nl:
        line += nl
        line_start = text.rfind("\n", start, end) + 1
    return line, line_start


def _fallback_decls_and_constants(res: LexResult, lang: str) -> None:
    """Declarations after a declaring keyword; constants `const X ... = expr` and Vyper `X: constant(T) = expr`."""
    code = [t for t in res.tokens if t.kind not in ("comment", "literal_str")]
    for i, t in enumerate(code):
        if t.kind == "keyword" and t.text in _DECL_KEYWORDS:
            name = next((c for c in code[i + 1 : i + 4] if c.kind == "identifier"), None)
            if name is not None:
                res.decls.setdefault(name.text, set()).add(name.line)
        if t.kind == "identifier" and t.col == 1 and i + 1 < len(code) and code[i + 1].text == ":" \
                and code[i + 1].line == t.line and lang == "vyper":
            res.decls.setdefault(t.text, set()).add(t.line)
    for i, t in enumerate(code):
        name: Token | None = None
        if t.kind == "keyword" and t.text == "const":
            j = i + 1
            while j < len(code) and code[j].text != "=" and code[j].line == t.line:
                if code[j].kind == "identifier":
                    name = code[j]
                j += 1
        elif lang == "vyper" and t.kind == "identifier" and i + 2 < len(code) and code[i + 1].text == ":" \
                and code[i + 2].text == "constant":
            name = t
            j = i + 3
            while j < len(code) and code[j].text != "=" and code[j].line == t.line:
                j += 1
        else:
            continue
        if name is None or j >= len(code) or code[j].text != "=":
            continue
        expr: list[Token] = []
        k = j + 1
        while k < len(code) and code[k].text != ";" and code[k].line == name.line:
            expr.append(code[k])
            k += 1
        if expr:
            res.constants.append((name.text, name.line, expr))


# ── constant folding (04 2.1 `folded_value`) ─────────────────────────────────

_UNIT_FACTORS = {"wei": 1, "gwei": 10**9, "szabo": 10**12, "finney": 10**15, "ether": 10**18,
                 "seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800, "years": 31536000}
_UNIT_NAMES = {"wei": "wei", "gwei": "wei", "szabo": "wei", "finney": "wei", "ether": "wei",
               "seconds": "seconds", "minutes": "seconds", "hours": "seconds", "days": "seconds",
               "weeks": "seconds", "years": "seconds"}
_RUST_SUFFIX_RE = re.compile(r"(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|u256|felt252)$")
_MAX_BITS = 512


class _FoldError(Exception):
    pass


def fold_constant(tokens: list[Token]) -> tuple[int, str | None] | None:
    """Fold a literal initializer (`1_000`, `10**18`, `1 ether`, `(2 * 3) << 4`) to an integer.

    Returns (value, unit) where unit is `wei` or `seconds` when a Solidity unit suffix appears, or
    None when the expression is not a literal expression or does not fold to an integer.
    """
    toks = [t for t in tokens if t.kind != "comment"]
    if not toks:
        return None
    parser = _Folder(toks)
    try:
        value = parser.expr()
        if parser.pos != len(toks):
            return None
    except (_FoldError, ZeroDivisionError, ValueError, OverflowError):
        return None
    if value.denominator != 1:
        return None
    v = int(value)
    if v.bit_length() > _MAX_BITS:
        return None
    return v, parser.unit


class _Folder:
    def __init__(self, toks: list[Token]) -> None:
        self.toks = toks
        self.pos = 0
        self.unit: str | None = None

    def peek(self) -> str | None:
        return self.toks[self.pos].text if self.pos < len(self.toks) else None

    def take(self) -> Token:
        if self.pos >= len(self.toks):
            raise _FoldError("eof")
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def expr(self) -> Fraction:
        return self.shift()

    def shift(self) -> Fraction:
        v = self.add()
        while self.peek() in ("<<", ">>"):
            op = self.take().text
            r = self.add()
            if v.denominator != 1 or r.denominator != 1 or r < 0 or r > _MAX_BITS:
                raise _FoldError("shift")
            v = Fraction(int(v) << int(r)) if op == "<<" else Fraction(int(v) >> int(r))
        return v

    def add(self) -> Fraction:
        v = self.mul()
        while self.peek() in ("+", "-"):
            op = self.take().text
            r = self.mul()
            v = v + r if op == "+" else v - r
        return v

    def mul(self) -> Fraction:
        v = self.power()
        while self.peek() in ("*", "/", "%"):
            op = self.take().text
            r = self.power()
            if op == "*":
                v = v * r
            elif op == "/":
                v = v / r
            else:
                if v.denominator != 1 or r.denominator != 1:
                    raise _FoldError("mod")
                v = Fraction(int(v) % int(r))
        self._check(v)
        return v

    def power(self) -> Fraction:
        base = self.unary()
        if self.peek() == "**":
            self.take()
            exp = self.power()
            if exp.denominator != 1 or exp < 0 or exp > _MAX_BITS:
                raise _FoldError("pow")
            if base.denominator == 1 and abs(int(base)).bit_length() * int(exp) > _MAX_BITS * 2:
                raise _FoldError("pow-size")
            base = base ** int(exp)
            self._check(base)
        return base

    def unary(self) -> Fraction:
        if self.peek() == "-":
            self.take()
            return -self.unary()
        if self.peek() == "(":
            self.take()
            v = self.expr()
            if self.take().text != ")":
                raise _FoldError("paren")
            return self.suffix(v)
        t = self.take()
        if t.kind != "literal_num":
            raise _FoldError("not literal")
        return self.suffix(_parse_number(t.text))

    def suffix(self, v: Fraction) -> Fraction:
        word = self.peek()
        if word in _UNIT_FACTORS and self.toks[self.pos].kind in ("keyword", "identifier"):
            self.take()
            self.unit = _UNIT_NAMES[word]
            return v * _UNIT_FACTORS[word]
        return v

    @staticmethod
    def _check(v: Fraction) -> None:
        if abs(v.numerator).bit_length() > _MAX_BITS * 2:
            raise _FoldError("size")


def _parse_number(raw: str) -> Fraction:
    s = raw.replace("_", "")
    s = _RUST_SUFFIX_RE.sub("", s) if not s.lower().startswith("0x") else s
    if s.lower().startswith("0x"):
        return Fraction(int(s, 16))
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?", s)
    if not m:
        raise _FoldError("number")
    whole, frac, exp = m.group(1), m.group(2) or "", int(m.group(3) or 0)
    if abs(exp) > _MAX_BITS:
        raise _FoldError("exp")
    v = Fraction(int(whole + frac), 10 ** len(frac))
    return v * (Fraction(10) ** exp)
