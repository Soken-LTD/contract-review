"""Parsed spans and semantic layer of `map.v1` for TON sources: Tact, FunC, Tolk (04 sections 2.1, 13).

There is no compiler AST for TON (the Tact, FunC and Tolk compilers emit no AST we keep, and the
exact compiler is often missing from the image: matrix run 2026-10-25, Forton). The map is parsed
from the fallback lexer's tokens instead: units (Tact contracts and traits, one module per FunC or
Tolk file), handlers and functions with their line spans, state fields, message sends, sender
guards, state writes and reads, internal call edges, roles and category candidates.

`ton_spans(lang, tokens)` gives the lexical layer (spans, units, parse status) for one file;
`build_semantic_ton(lex)` the `semantic` object plus the span ids per (path, start line), in the
same shape as `semantic_evm.build_semantic`. Pure. Names pass the identifier grammar (`safe_name`),
so free text from code (receiver comment strings included) never enters the map.

Parse limits (stated, not hidden): a guard reached through an internal function is followed three
calls deep inside the parsed files; stdlib traits (Ownable, Deployable) are not in the source, so
`self.requireOwner()` is recognised by name as an owner check.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

TON_LANGS = frozenset({"tact", "func", "tolk"})

logger = logging.getLogger(__name__)

# Work limits (security review 2026-10-26: the parse runs on untrusted source in the worker).
# Brackets are matched once per token list (stack pass) and range questions are prefix sums, so
# the parse is linear; these caps bound the constant. A file over the cap keeps the lexical
# layer only (`partial`); a job over the total, the function cap or the time budget gets no
# parsed semantic layer. The budget is cooperative and sits inside the map step's lease.
_MAX_FILE_TOKENS = 60_000
_MAX_TOTAL_TOKENS = 400_000
_MAX_FUNCTIONS = 4_000
_PARSE_BUDGET_S = 30.0
_ROLE_WINDOW = 64        # tokens of a guard condition searched for the compared `self.<x>`
_MAX_REACH = 256         # functions one handler may inherit features from (call graph, depth 3)
_MAX_SITES = 256         # call sites, writes and reads recorded per function (and per guard list)

_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,63}$")
_MAX_DEPTH = 3

# Builtins by effect. Tact names first, then FunC, then Tolk spellings.
_SEND_FNS = frozenset({
    "send", "message", "deploy", "cashback", "sendRawMessage", "nativeSendMessage",
    "nativeSendMessageReturnForwardFee", "send_raw_message", "createMessage",
})
_SELF_SEND_FNS = frozenset({"reply", "forward", "notify"})
_THROW_FNS = frozenset({
    "require", "throwUnless", "throwIf", "nativeThrowUnless", "nativeThrowIf",
    "throw_unless", "throw_if", "throw_arg_unless", "throw_arg_if", "assert",
})
_OWNER_CHECK_FNS = frozenset({"requireOwner"})
_RESERVE_FNS = frozenset({"nativeReserve", "raw_reserve", "reserveToncoinsOnBalance", "reserve"})
_RANDOM_FNS = frozenset({"random", "randomInt", "nativeRandom", "nativeRandomize", "nativeRandomizeLt",
                         "getSeed", "rand", "randomize", "randomize_lt", "random.uint256", "random.range"})
_TIME_FNS = frozenset({"now", "blockchain.now"})
_SIGNATURE_FNS = frozenset({"checkSignature", "checkDataSignature", "check_signature",
                            "check_data_signature", "isSignatureValid", "isSliceSignatureValid"})
_CODE_FNS = frozenset({"setCode", "nativeSetCode", "set_code", "setCodePostponed"})
_ACCEPT_FNS = frozenset({"acceptMessage", "accept_message"})
_STORE_WRITE_FNS = frozenset({"set_data", "setContractData", "setData"})
_STORE_READ_FNS = frozenset({"get_data", "getContractData", "getData"})
_MAP_WRITE_METHODS = frozenset({"set", "del", "replace", "replaceGet", "deleteGet", "addIfNotExists",
                                "append", "save"})
_ASSIGN_OPS = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>=", "||=", "&&="})
_LOOP_WORDS = frozenset({"while", "repeat", "do", "foreach", "until"})
_ARITH_OPS = frozenset({"*", "/", "%", "<<", ">>", "*=", "/=", "%=", "<<=", ">>="})
# send(...) mode flags by name and by numeric value
_MODE_NAMES = {"SendRemainingBalance": "send_mode_drain", "SendRemainingValue": "excess_return",
               "SendIgnoreErrors": "ignore_errors", "SendDestroyIfZero": "destroy",
               "SEND_MODE_CARRY_ALL_BALANCE": "send_mode_drain", "SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE":
               "excess_return", "SEND_MODE_IGNORE_ERRORS": "ignore_errors", "SEND_MODE_DESTROY": "destroy"}
_MODE_BITS = {128: "send_mode_drain", 64: "excess_return", 2: "ignore_errors", 32: "destroy"}
_JETTON_RE = re.compile(r"jetton|tokentransfer|tokenburn|tokennotification|internaltransfer", re.IGNORECASE)

# category -> features an entry handler must have (04 13); no row: no candidates from the map.
_CATEGORY_FEATURES: dict[str, tuple[str, ...]] = {
    "ton.sender_auth": ("writes_state",),
    "ton.external_accept_early": ("external",),
    "ton.bounce_handling": ("send",),
    "ton.send_mode_drain": ("send_mode_drain",),
    "ton.send_mode_reserve": ("reserve",),
    "ton.account_destroy": ("destroy",),
    "ton.bounce_body": ("bounced",),
    "ton.unrecoverable_send": ("ignore_errors",),
    "ton.excess_return": ("excess_return",),
    "ton.send_order": ("send", "writes_state"),
    "ton.unbounded_loop": ("loop",),
    "ton.signature_binding": ("signature",),
    "ton.upgrade_migration": ("code_update",),
    "ton.signed_integer": ("arithmetic",),
    "ton.storage_persistence": ("writes_state",),
    "ton.replay": ("external",),
    "ton.async_race": ("send", "writes_state"),
    "ton.code_update": ("code_update",),
    "ton.arithmetic": ("arithmetic",),
    "ton.gas_storage": ("map_write",),
    "ton.randomness": ("randomness",),
    "ton.address_parsing": ("has_params",),
    "ton.jetton_standard": ("jetton",),
    "ton.business_logic": ("writes_state",),
    "ton.economic": ("value_flow",),
    "ton.best_practice": (),
}


def safe_name(name: str) -> str:
    if _IDENT_RE.match(name):
        return name
    return "id_" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]


@dataclass
class TonFn:
    unit: str | None          # unit name (Tact contract/trait, FunC/Tolk module); None = Tact global
    name: str                 # span name (receive, bounced, init, function name)
    sig: str                  # receive(SetupJoinPrice), withdraw(Int), ...
    kind: str                 # receiver | bounced | external | init | getter | internal
    start: int
    end: int
    body: list[Any] = field(default_factory=list)       # code tokens between the braces
    params: list[Any] = field(default_factory=list)     # tokens between the parentheses
    modifiers: list[str] = field(default_factory=list)


@dataclass
class TonUnit:
    name: str
    kind: str                 # contract | trait | module
    start: int
    end: int
    bases: list[str] = field(default_factory=list)
    fields: list[tuple[str, int]] = field(default_factory=list)   # (name, line)


@dataclass
class TonParse:
    lang: str
    status: str               # ok | partial
    units: list[TonUnit] = field(default_factory=list)
    fns: list[TonFn] = field(default_factory=list)
    globals_: list[tuple[str, int]] = field(default_factory=list)


_PAIRS = {"(": ")", "{": "}", "[": "]"}
_CLOSERS = {v: k for k, v in _PAIRS.items()}
_THROWISH = frozenset({"throw", "nativeThrow"})
_MODE_FEATS = ("send_mode_drain", "excess_return", "ignore_errors", "destroy")
_NEXT_TEXTS = ("{", ";", "fun", "receive", "init", "get")


class _Overflow(Exception):
    """A work limit was hit; the caller keeps the lexical layer."""


class _Toks(list):
    """Code tokens with bracket pairs and prefix sums, built in one pass (O(n)).

    pairs/rpairs: open index <-> close index for (), {}, [] (one stack per bracket kind; an
    unbalanced bracket has no entry). pre[name][k]: count of flagged tokens in toks[:k], so
    "does toks[lo:hi] mention sender / a throw / a send mode" is O(1).
    """

    def __init__(self, tokens: list[Any]) -> None:
        super().__init__(tokens)
        self._next: dict[str, list[int | None]] = {}
        self.pairs: dict[int, int] = {}
        self.rpairs: dict[int, int] = {}
        stacks: dict[str, list[int]] = {o: [] for o in _PAIRS}
        names = ("sender", "throw", *_MODE_FEATS)
        self.pre: dict[str, list[int]] = {k: [0] * (len(tokens) + 1) for k in names}
        for k, t in enumerate(tokens):
            if t.kind in ("punct", "operator"):
                if t.text in _PAIRS:
                    stacks[t.text].append(k)
                elif t.text in _CLOSERS and stacks[_CLOSERS[t.text]]:
                    o = stacks[_CLOSERS[t.text]].pop()
                    self.pairs[o] = k
                    self.rpairs[k] = o
            nxt = tokens[k + 1].text if k + 1 < len(tokens) else ""
            prev = tokens[k - 1].text if k > 0 else ""
            flags = set()
            low = t.text.lower()
            if (t.text == "sender" and nxt == "(") or (t.kind == "identifier" and (
                    "sender" in low or low.startswith("equal_slice"))):
                flags.add("sender")
            if t.text in _THROWISH or t.text in _THROW_FNS:
                flags.add("throw")
            if t.text in _MODE_NAMES:
                flags.add(_MODE_NAMES[t.text])
            elif t.kind == "literal_num" and prev in ("mode", ":", ",", "|", "+"):
                try:
                    v = int(t.text.replace("_", ""), 0)
                except ValueError:
                    v = 0
                flags.update(feat for bit, feat in _MODE_BITS.items() if v & bit)
            for name, arr in self.pre.items():
                arr[k + 1] = arr[k] + (1 if name in flags else 0)

    def next(self, texts: tuple[str, ...], lo: int, hi: int) -> int | None:
        """First index in [lo, hi) whose text is in `texts` (each from _NEXT_TEXTS). O(len(texts))."""
        if not self._next:
            self._build_next()
        best = None
        for text in texts:
            j = self._next[text][lo] if 0 <= lo < len(self) else None
            if j is not None and j < hi and (best is None or j < best):
                best = j
        return best

    def _build_next(self) -> None:
        n = len(self)
        for text in _NEXT_TEXTS:
            arr: list[int | None] = [None] * (n + 1)
            for k in range(n - 1, -1, -1):
                arr[k] = k if self[k].text == text else arr[k + 1]
            self._next[text] = arr

    def any(self, name: str, lo: int, hi: int) -> bool:
        arr = self.pre[name]
        lo, hi = max(0, lo), min(len(self), hi)
        return hi > lo and arr[hi] - arr[lo] > 0

    def sub(self, lo: int, hi: int) -> _Toks:
        return _Toks(self[lo:hi])


def _code(tokens: list[Any]) -> _Toks:
    code = [t for t in tokens if t.kind != "comment"]
    if len(code) > _MAX_FILE_TOKENS:
        raise _Overflow("file_tokens")
    return _Toks(code)


def _match(toks: _Toks, i: int | None, open_: str, close: str) -> int | None:
    """Index of the token closing toks[i] (== open_), or None when unbalanced. O(1)."""
    if i is None or i >= len(toks) or toks[i].text != open_:
        return None
    j = toks.pairs.get(i)
    return j if j is not None and toks[j].text == close else None


def _types_of(params: list[Any]) -> list[str]:
    """Tact/Tolk `name: Type` -> Type; FunC `type name` -> type. Generic args are dropped."""
    out: list[str] = []
    groups: list[list[Any]] = [[]]
    depth = 0
    for t in params:
        if t.text in ("<", "(", "[") and t.kind in ("punct", "operator"):
            depth += 1
        elif t.text in (">", ")", "]") and t.kind in ("punct", "operator"):
            depth -= 1
        if t.text == "," and depth == 0:
            groups.append([])
            continue
        groups[-1].append(t)
    for g in groups:
        if not g:
            continue
        colon = next((k for k, t in enumerate(g) if t.text == ":"), None)
        if colon is not None:
            typ = next((t.text for t in g[colon + 1:] if t.kind in ("identifier", "type_name")
                        and t.text not in ("bounced", "as")), "")
        else:
            typ = next((t.text for t in g if t.kind in ("identifier", "type_name", "keyword")), "")
        out.append(re.sub(r"[^A-Za-z0-9_]", "", typ)[:64] or "_")
    return out


# ── per-language structure ──────────────────────────────────────────────────


class _Broken(Exception):
    """A header or body bracket that does not close: the file keeps its lexical layer only.

    Parsing on after a broken contract would read its members as free functions and attach
    their guards to the wrong place (security review 2026-10-26)."""


def _parse_tact(toks: _Toks) -> TonParse:
    res = TonParse(lang="tact", status="ok")
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t.text in ("contract", "trait") and t.kind == "keyword" and i + 1 < n and toks[i + 1].kind == "identifier":
            brace = toks.next(("{", ";"), i + 2, n)
            if brace is None or toks[brace].text != "{":
                raise _Broken(f"{t.text} header at line {t.line}")
            end = _match(toks, brace, "{", "}")
            if end is None:
                raise _Broken(f"{t.text} body at line {t.line}")
            bases = [x.text for x in toks[i + 2:brace] if x.kind == "identifier"]
            unit = TonUnit(toks[i + 1].text, t.text, t.line, toks[end].line, bases=bases)
            res.units.append(unit)
            _tact_members(toks, brace + 1, end, unit, res)
            i = end + 1
            continue
        if t.text in ("message", "struct") and t.kind == "keyword":
            brace = toks.next(("{", ";"), i + 1, n)
            if brace is not None and toks[brace].text == "{":
                end = _match(toks, brace, "{", "}")
                if end is None:
                    raise _Broken(f"{t.text} at line {t.line}")
                i = end + 1
                continue
        if t.text == "fun" and t.kind == "keyword":
            fn, nxt = _tact_fun(toks, i, None, _decl_start(toks, i).line, "internal", n)
            if fn is not None:
                res.fns.append(fn)
            i = nxt
            continue
        i += 1
    return res


_TACT_PREFIX = frozenset({"extends", "mutates", "inline", "virtual", "override", "abstract", "native", "asm",
                          "get"})


def _decl_start(toks: list[Any], i: int) -> Any:
    j = i
    while j > 0 and i - j < 8 and toks[j - 1].text in _TACT_PREFIX:
        j -= 1
    return toks[j]


def _tact_fun(toks: _Toks, i: int, unit: str | None, start_line: int, kind: str,
              hi: int) -> tuple[TonFn | None, int]:
    """`fun name(params) [: Ret] { body }` at toks[i] == fun, inside [i, hi). Returns (fn, next index)."""
    if i + 2 >= hi or toks[i + 1].kind != "identifier" or toks[i + 2].text != "(":
        return None, i + 1
    name = toks[i + 1].text
    close = _match(toks, i + 2, "(", ")")
    if close is None or close >= hi:
        raise _Broken(f"fun {safe_name(name)} parameters at line {toks[i].line}")
    k = toks.next(("{", ";", "fun", "receive", "init", "get"), close + 1, hi)
    if k is None:
        raise _Broken(f"fun {safe_name(name)} has no body or ';' at line {toks[i].line}")
    if toks[k].text != "{":
        return None, k + 1 if toks[k].text == ";" else k                 # abstract / native: no body
    end = _match(toks, k, "{", "}")
    if end is None or end >= hi:
        raise _Broken(f"fun {safe_name(name)} body at line {toks[i].line}")
    params = toks[i + 3:close]
    mods = [x.text for x in toks[max(0, i - 4):i] if x.text in _TACT_PREFIX]
    sig = f"{safe_name(name)}({','.join(_types_of(params))})"
    return TonFn(unit, safe_name(name), sig, kind, start_line, toks[end].line, toks.sub(k + 1, end), params,
                 mods), end + 1


def _tact_members(toks: _Toks, lo: int, hi: int, unit: TonUnit, res: TonParse) -> None:
    i = lo
    while i < hi:
        t = toks[i]
        if t.text in ("receive", "bounced", "external", "init") and i + 1 < hi and toks[i + 1].text == "(":
            close = _match(toks, i + 1, "(", ")")
            if close is None or close + 1 >= hi or toks[close + 1].text != "{":
                raise _Broken(f"{t.text} at line {t.line}")
            brace = close + 1
            end = _match(toks, brace, "{", "}")
            if end is None or end >= hi:
                raise _Broken(f"{t.text} body at line {t.line}")
            params = toks[i + 2:close]
            kind = {"receive": "receiver", "bounced": "bounced", "external": "external", "init": "init"}[t.text]
            if t.text == "init":
                sig = f"init({','.join(_types_of(params))})"
            elif not params:
                sig = f"{t.text}()"
            elif params[0].kind == "literal_str":
                sig = f"{t.text}(text_{safe_name(params[0].text.strip(chr(34)))})"
            else:
                sig = f"{t.text}({','.join(_types_of(params))})"
            res.fns.append(TonFn(unit.name, t.text, sig, kind, t.line, toks[end].line, toks.sub(brace + 1, end),
                                 params))
            i = end + 1
            continue
        if t.text == "get" and t.kind == "keyword":
            j = i + 1
            if j < hi and toks[j].text == "(":                       # get(0x1234) fun x()
                close = _match(toks, j, "(", ")")
                if close is None or close >= hi:
                    raise _Broken(f"get at line {t.line}")
                j = close + 1
            if j < hi and toks[j].text == "fun":
                fn, nxt = _tact_fun(toks, j, unit.name, t.line, "getter", hi)
                if fn is not None:
                    res.fns.append(fn)
                i = nxt
                continue
        if t.text == "fun" and t.kind == "keyword":
            fn, nxt = _tact_fun(toks, i, unit.name, _decl_start(toks, i).line, "internal", hi)
            if fn is not None:
                res.fns.append(fn)
            i = nxt
            continue
        if t.text == "const" and t.kind == "keyword" or (
                t.kind == "identifier" and i + 1 < hi and toks[i + 1].text == ":"
                and (i == lo or toks[i - 1].text in (";", "{", "}"))):
            semi = toks.next((";",), i, hi)
            if semi is None:
                raise _Broken(f"declaration without ';' at line {t.line}")
            if t.text != "const":
                unit.fields.append((t.text, t.line))
            i = semi + 1
            continue
        i += 1


_FUNC_SPECIFIERS = frozenset({"impure", "inline", "inline_ref", "method_id"})


def _parse_func(toks: _Toks) -> TonParse:
    """FunC: `[forall ->] ret name(params) [specifiers] { ... }` at brace depth 0; `global T x;`."""
    res = TonParse(lang="func", status="ok")
    i, n, decl_start = 0, len(toks), 0
    while i < n:
        t = toks[i]
        if t.text == "global" and t.kind == "keyword":
            semi = toks.next((";",), i, n)
            if semi is None:
                raise _Broken(f"global without ';' at line {t.line}")
            names = [x for x in toks[i + 1:semi] if x.kind == "identifier"]
            for x in names[1::2] or names[-1:]:
                res.globals_.append((x.text, x.line))
            i = decl_start = semi + 1
            continue
        if t.text == ";":
            i = decl_start = i + 1
            continue
        if t.text == "{":
            end = _match(toks, i, "{", "}")
            if end is None:
                raise _Broken(f"block at line {t.line}")
            k = i - 1
            mods: list[str] = []
            while k > decl_start and i - k < 16 and (
                    toks[k].text in _FUNC_SPECIFIERS or toks[k].kind == "literal_num"
                    or toks[k].text in ("(", ")") and toks[k - 1].text == "method_id"
                    or toks[k].text == ")" and k >= 2 and toks[k - 2].text == "method_id"):
                if toks[k].text in _FUNC_SPECIFIERS:
                    mods.append(toks[k].text)
                k -= 1
            if toks[k].text == ")":
                opn = toks.rpairs.get(k)
                if opn is not None and opn - 1 >= decl_start and toks[opn - 1].kind == "identifier":
                    name = toks[opn - 1].text.lstrip(".~")
                    params = toks[opn + 1:k]
                    if name in ("recv_internal", "main"):
                        kind = "receiver"
                    elif name == "recv_external":
                        kind = "external"
                    elif "method_id" in mods:
                        kind = "getter"
                    else:
                        kind = "internal"
                    sig = f"{safe_name(name)}({','.join(_types_of_func(params))})"
                    res.fns.append(TonFn(None, safe_name(name), sig, kind, toks[decl_start].line, toks[end].line,
                                         toks.sub(i + 1, end), params, mods))
            i = decl_start = end + 1
            continue
        i += 1
    return res


def _types_of_func(params: list[Any]) -> list[str]:
    out, cur = [], []
    for t in [*params, None]:
        if t is None or t.text == ",":
            if cur:
                typ = cur[0].text if len(cur) > 1 else "_"
                out.append(re.sub(r"[^A-Za-z0-9_]", "", typ)[:64] or "_")
            cur = []
        else:
            cur.append(t)
    return out


_TOLK_ENTRY = {"onInternalMessage": "receiver", "recv_internal": "receiver", "main": "receiver",
               "onExternalMessage": "external", "recv_external": "external", "onBouncedMessage": "bounced"}


def _parse_tolk(toks: _Toks) -> TonParse:
    """Tolk: `[get] fun [Recv.]name(params) [: Ret] { ... }`, `get name()`, `global x: T;`."""
    res = TonParse(lang="tolk", status="ok")
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t.text == "global" and t.kind == "keyword" and i + 1 < n and toks[i + 1].kind == "identifier":
            res.globals_.append((toks[i + 1].text, toks[i + 1].line))
        if t.text in ("struct",) and t.kind == "keyword":
            brace = toks.next(("{", ";"), i + 1, n)
            if brace is not None and toks[brace].text == "{":
                end = _match(toks, brace, "{", "}")
                if end is None:
                    raise _Broken(f"struct at line {t.line}")
                i = end + 1
                continue
        getter = t.text == "get" and t.kind == "keyword"
        if t.text == "fun" or getter:
            j = i + 1
            if getter and j < n and toks[j].text == "fun":
                j += 1
            recv = None
            if j + 2 < n and toks[j + 1].text == "." and toks[j + 2].kind == "identifier":
                recv, j = toks[j].text, j + 2
            if j + 1 < n and toks[j].kind == "identifier" and toks[j + 1].text == "(":
                close = _match(toks, j + 1, "(", ")")
                brace = toks.next(("{", ";"), close, n) if close is not None else None
                if close is None or brace is None:
                    raise _Broken(f"fun at line {t.line}")
                if toks[brace].text == "{":
                    end = _match(toks, brace, "{", "}")
                    if end is None:
                        raise _Broken(f"fun body at line {t.line}")
                    name = toks[j].text if recv is None else f"{recv}_{toks[j].text}"
                    kind = "getter" if getter else _TOLK_ENTRY.get(toks[j].text, "internal")
                    params = toks[j + 2:close]
                    sig = f"{safe_name(name)}({','.join(_types_of(params))})"
                    res.fns.append(TonFn(None, safe_name(name), sig, kind, t.line, toks[end].line,
                                         toks.sub(brace + 1, end), params))
                    i = end + 1
                    continue
                i = brace + 1
                continue
        i += 1
    return res


def parse_ton(lang: str, tokens: list[Any], path: str) -> TonParse:
    try:
        toks = _code(tokens)
    except _Overflow:
        logger.info("ton parse: %s over %d tokens, lexical layer only", path, _MAX_FILE_TOKENS)
        return TonParse(lang=lang, status="partial")
    try:
        parsed = {"tact": _parse_tact, "func": _parse_func, "tolk": _parse_tolk}[lang](toks)
    except _Broken as exc:
        logger.info("ton parse: %s: unclosed %s, lexical layer only", path, exc)
        return TonParse(lang=lang, status="partial")
    if lang in ("func", "tolk"):
        stem = safe_name(re.sub(r"[^A-Za-z0-9_]", "_", PurePosixPath(path).stem) or "module")
        last = max((t.line for t in toks), default=1)
        if parsed.fns or parsed.globals_:
            parsed.units.append(TonUnit(stem, "module", 1, last, fields=list(parsed.globals_)))
        for fn in parsed.fns:
            fn.unit = stem
    return parsed


def ton_spans(lang: str, tokens: list[Any], path: str) -> tuple[list[tuple[str, str, int, int, str | None]],
                                                               list[tuple[str, str, int, int]], str]:
    """Lexical layer for one TON file: ([(name, kind, start, end, unit)], [(unit, kind, start, end)], status)."""
    parsed = parse_ton(lang, tokens, path)
    spans = [(fn.name, "handler" if fn.kind in ("receiver", "bounced", "external") else "function",
              fn.start, fn.end, fn.unit) for fn in parsed.fns]
    units = [(u.name, "contract" if u.kind == "contract" else "module", u.start, u.end) for u in parsed.units]
    return spans, units, parsed.status


# ── semantic layer ──────────────────────────────────────────────────────────


@dataclass
class _Info:
    fn: TonFn
    path: str
    span_id: str
    unit_id: str
    guards: list[tuple[str, str]] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)
    writes: list[dict] = field(default_factory=list)
    reads: list[dict] = field(default_factory=list)
    features: set[str] = field(default_factory=set)
    internal: list[tuple[str, str]] = field(default_factory=list)      # (callee name, path:line)
    roles: set[str] = field(default_factory=set)
    callees: dict[str, list[_Info]] = field(default_factory=dict)       # name -> resolvable functions


def build_semantic_ton(files: dict[str, tuple[str, list[Any]]], categories: list[str],
                       budget_s: float = _PARSE_BUDGET_S,
                       ) -> tuple[dict, dict[tuple[str, int], tuple[str, str]]] | None:
    """files: path -> (lang, lexer tokens). Returns (semantic, {(path, start): (span id, unit id)}) or None.

    None also when a work limit is hit (total tokens, function count, time budget): the map then
    keeps its lexical layer, which is what it had before the parse existed."""
    if sum(len(toks) for lang, toks in files.values() if lang in TON_LANGS) > _MAX_TOTAL_TOKENS:
        logger.info("ton parse: job over %d tokens, lexical layer only", _MAX_TOTAL_TOKENS)
        return None
    try:
        return _build_semantic_ton(files, categories, time.monotonic() + budget_s)
    except _Overflow as exc:
        logger.info("ton parse: %s, lexical layer only", exc)
        return None


def _check(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise _Overflow("time budget")


def _build_semantic_ton(files: dict[str, tuple[str, list[Any]]], categories: list[str], deadline: float
                        ) -> tuple[dict, dict[tuple[str, int], tuple[str, str]]] | None:
    parses = {p: parse_ton(lang, toks, p) for p, (lang, toks) in sorted(files.items()) if lang in TON_LANGS}
    if not any(pp.fns for pp in parses.values()):
        return None
    if sum(len(pp.fns) for pp in parses.values()) > _MAX_FUNCTIONS:
        raise _Overflow(f"over {_MAX_FUNCTIONS} functions")
    _check(deadline)
    units_out: list[dict] = []
    state_vars: list[dict] = []
    fields_by_unit: dict[str, set[str]] = {}
    unit_ids: dict[str, str] = {}
    bases_of: dict[str, list[str]] = {}
    for path, pp in parses.items():
        for u in pp.units:
            uid = f"{path}:{safe_name(u.name)}"
            unit_ids.setdefault(u.name, uid)
            bases_of[u.name] = [b for b in u.bases if _IDENT_RE.match(b)]
            if u.kind != "trait":
                units_out.append({"id": uid, "name": safe_name(u.name),
                                  "kind": "contract" if u.kind == "contract" else "module",
                                  "file": path, "start": u.start, "end": u.end})
            for fname, line in u.fields:
                if _IDENT_RE.match(fname):
                    fields_by_unit.setdefault(u.name, set()).add(fname)
                    state_vars.append({"id": f"{uid}.{fname}", "unit": uid, "name": fname,
                                       "decl_ref": f"{path}:{line}"})
    # a contract sees the fields and functions of its local traits
    def lineage(unit: str | None) -> list[str]:
        if unit is None:
            return []
        out, todo = [], [unit]
        while todo:
            u = todo.pop(0)
            if u not in out:
                out.append(u)
                todo.extend(bases_of.get(u, []))
        return out

    infos: list[_Info] = []
    for path, pp in parses.items():
        for fn in pp.fns:
            owner = safe_name(fn.unit) if fn.unit else None
            span_id = f"{owner}.{fn.sig}" if owner else fn.sig
            unit_id = unit_ids.get(fn.unit or "", f"{path}:global")
            infos.append(_Info(fn, path, span_id, unit_id))
    by_name: dict[str, list[_Info]] = {}
    for inf in infos:
        if inf.fn.kind in ("internal", "getter"):
            by_name.setdefault(inf.fn.name, []).append(inf)
    lang_of = {path: pp.lang for path, pp in parses.items()}
    scopes: dict[str | None, tuple[set[str], dict[str, list[_Info]]]] = {}
    for inf in infos:
        _check(deadline)
        if inf.fn.unit not in scopes:
            # Call edges resolve inside the caller's contract and its local traits, or to free
            # functions (Tact globals; FunC/Tolk share one namespace across included files): two
            # contracts with a same-named helper never borrow each other's guards. One scope per
            # unit, not per function.
            family = lineage(inf.fn.unit)
            visible: set[str] = set()
            for u in family:
                visible |= fields_by_unit.get(u, set())
            fam = set(family)
            callable_ = {name: [c for c in cands if c.fn.unit is None or lang_of[c.path] != "tact" or c.fn.unit in fam]
                         for name, cands in by_name.items()}
            scopes[inf.fn.unit] = (visible, {k: v for k, v in callable_.items() if v})
        visible, inf.callees = scopes[inf.fn.unit]
        _analyze_body(inf, visible, inf.callees)
        _cap_sites(inf)
    _propagate_guards(infos, deadline)

    span_out: dict[tuple[str, int], tuple[str, str]] = {}
    functions = []
    seen: set[str] = set()
    for inf in sorted(infos, key=lambda x: (x.path, x.fn.start)):
        sid = inf.span_id if inf.span_id not in seen else f"{inf.span_id}@{inf.path}:{inf.fn.start}"
        seen.add(sid)
        inf.span_id = sid
        span_out[(inf.path, inf.fn.start)] = (sid, inf.unit_id)
        functions.append({
            "span": sid,
            "visibility": {"receiver": "receive", "bounced": "bounced", "external": "external", "init": "init",
                           "getter": "get", "internal": "internal"}[inf.fn.kind],
            "is_entry": inf.fn.kind in ("receiver", "bounced", "external"),
            "modifiers": [m for m in inf.fn.modifiers if _IDENT_RE.match(m)],
            "guards": [{"class": c, "line": line} for c, line in _dedup(inf.guards)[:_MAX_SITES]],
            "calls": inf.calls,
            "writes": inf.writes,
            "reads": inf.reads,
        })
    entries = [inf for inf in infos if inf.fn.kind in ("receiver", "bounced", "external")]
    semantic = {
        "units": units_out,
        "functions": functions,
        "state_vars": state_vars,
        "category_to_functions": _categories(entries, categories),
        "roles": _roles(entries),
        "upgrade_surface": [{"unit": inf.unit_id, "mechanism": "set_code", "authority_fact_key": "onchain.owner"}
                            for inf in _dedup_units(entries) if "code_update" in inf.features],
        "chain_extras": {"ton": {"parsed_from": "source", "units": {
            unit_ids[name]: {"bases": [safe_name(name), *[safe_name(b) for b in bases_of.get(name, [])]]}
            for name in unit_ids}}},
    }
    return semantic, span_out


def _dedup(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    out, seen = [], set()
    for p in pairs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _dedup_units(infos: list[_Info]) -> list[_Info]:
    out, seen = [], set()
    for inf in infos:
        if inf.unit_id not in seen and "code_update" in inf.features:
            seen.add(inf.unit_id)
            out.append(inf)
    return out


def _args(body: _Toks, open_idx: int) -> tuple[int, int]:
    """[lo, hi) of the tokens between the parentheses opened at open_idx; empty when unbalanced."""
    close = _match(body, open_idx, "(", ")")
    if close is None:
        return open_idx + 1, open_idx + 1
    return open_idx + 1, close


def _mode_features(body: _Toks, lo: int, hi: int) -> set[str]:
    return {feat for feat in _MODE_FEATS if body.any(feat, lo, hi)}


def _role_from(body: _Toks, lo: int, hi: int) -> tuple[str | None, bool]:
    """The `self.<x>` (or called address function) a sender check compares with, and computed-ness."""
    hi = min(hi, lo + _ROLE_WINDOW)
    for k in range(lo, hi):
        if body[k].text == "self" and k + 2 < hi and body[k + 1].text == ".":
            name = body[k + 2].text
            computed = k + 3 < hi and body[k + 3].text in ("(", ".")
            if _IDENT_RE.match(name):
                return name, computed
    return None, False


def _analyze_body(inf: _Info, fields: set[str], by_name: dict[str, list[_Info]]) -> None:
    body = inf.fn.body if isinstance(inf.fn.body, _Toks) else _Toks(inf.fn.body)
    path = inf.path
    if inf.fn.kind == "external":
        inf.features.add("external")
    if inf.fn.kind == "bounced":
        inf.features.add("bounced")
    if inf.fn.params and inf.fn.kind in ("receiver", "external"):
        inf.features.add("has_params")
    if inf.fn.sig and _JETTON_RE.search(inf.fn.sig):
        inf.features.add("jetton")
    n = len(body)
    for i, t in enumerate(body):
        line = f"{path}:{t.line}"
        nxt = body[i + 1].text if i + 1 < n else ""
        prev = body[i - 1].text if i > 0 else ""
        if t.text in _LOOP_WORDS and t.kind == "keyword":
            inf.features.add("loop")
        elif t.kind == "operator" and t.text in _ARITH_OPS:
            inf.features.add("arithmetic")
        if t.text == "self" and nxt == "." and i + 2 < n:
            member = body[i + 2]
            after = body[i + 3].text if i + 3 < n else ""
            mname = member.text
            if after == "(":
                if mname in _OWNER_CHECK_FNS:
                    inf.guards.append(("caller_check", line))
                    inf.roles.add("owner")
                elif mname in _SELF_SEND_FNS:
                    inf.calls.append({"kind": "message", "target": mname, "line": line, "value_bearing": True})
                    inf.features.update({"send", "value_flow"})
                elif mname in by_name:
                    inf.calls.append({"kind": "internal", "target": mname, "line": line})
                    inf.internal.append((mname, line))
            elif mname in fields:
                if after in _ASSIGN_OPS:
                    inf.writes.append({"var": mname, "line": line})
                    inf.features.add("writes_state")
                elif after == "." and i + 5 < n and body[i + 4].text in _MAP_WRITE_METHODS and body[i + 5].text == "(":
                    inf.writes.append({"var": mname, "line": line})
                    inf.features.update({"writes_state", "map_write"})
                else:
                    inf.reads.append({"var": mname, "line": line})
            continue
        if t.kind not in ("identifier", "keyword") or nxt != "(" or prev == ".":
            if prev == "." and nxt == "(" and t.text == "send":                     # Tolk msg.send(mode)
                lo, hi = _args(body, i + 1)
                inf.calls.append({"kind": "message", "target": "send", "line": line, "value_bearing": True})
                inf.features.update({"send", "value_flow"} | _mode_features(body, lo, hi))
            continue
        name = t.text.lstrip(".~")
        if name in _SEND_FNS:
            lo, hi = _args(body, i + 1)
            inf.calls.append({"kind": "message", "target": name, "line": line, "value_bearing": True})
            inf.features.update({"send", "value_flow"} | _mode_features(body, lo, hi))
        elif name in _THROW_FNS:
            lo, hi = _args(body, i + 1)
            if body.any("sender", lo, hi):
                inf.guards.append(("caller_check", line))
                role, _computed = _role_from(body, lo, hi)
                inf.roles.add(role or "inline_sender_check")
        elif name in _OWNER_CHECK_FNS:
            inf.guards.append(("caller_check", line))
            inf.roles.add("owner")
        elif name in _RESERVE_FNS:
            inf.features.add("reserve")
        elif name in _RANDOM_FNS:
            inf.features.add("randomness")
        elif name in _TIME_FNS:
            inf.features.add("timestamp")
        elif name in _SIGNATURE_FNS:
            inf.features.add("signature")
        elif name in _CODE_FNS:
            inf.features.add("code_update")
        elif name in _ACCEPT_FNS:
            inf.features.add("accept")
        elif name in _STORE_WRITE_FNS:
            inf.writes.append({"var": "storage", "line": line})
            inf.features.add("writes_state")
        elif name in _STORE_READ_FNS:
            inf.reads.append({"var": "storage", "line": line})
        elif name == "if":
            lo, close = _args(body, i + 1)
            if close > lo and body.any("sender", lo, close) and close + 1 < n and body[close + 1].text == "{":
                blk_end = _match(body, close + 1, "{", "}") or n
                if body.any("throw", close + 2, blk_end):
                    inf.guards.append(("caller_check", line))
                    role, _computed = _role_from(body, lo, close)
                    inf.roles.add(role or "inline_sender_check")
        elif name in by_name:
            inf.calls.append({"kind": "internal", "target": name, "line": line})
            inf.internal.append((name, line))


def _propagate_guards(infos: list[_Info], deadline: float) -> None:
    """A guard (or a send, write or feature) reached through an internal function counts on the caller.

    Bounded: callee names are deduplicated per function, at most _MAX_REACH functions are visited
    per handler, and the deadline is checked inside the walk."""
    own = {id(inf): (list(inf.guards), set(inf.features), set(inf.roles)) for inf in infos}
    for inf in infos:
        frontier = [inf]
        seen = {id(inf)}
        for _ in range(_MAX_DEPTH):
            nxt = []
            for cur in frontier:
                for callee_name in dict.fromkeys(name for name, _line in cur.internal):
                    for callee in cur.callees.get(callee_name, []):
                        if id(callee) in seen:
                            continue
                        if len(seen) >= _MAX_REACH:
                            break
                        _check(deadline)
                        seen.add(id(callee))
                        guards, feats, roles = own[id(callee)]
                        inf.guards.extend(guards)
                        inf.features |= feats - {"external", "bounced", "has_params"}
                        inf.roles |= roles
                        nxt.append(callee)
            frontier = nxt


def _cap_sites(inf: _Info) -> None:
    """Keep the first _MAX_SITES call sites, writes, reads and guards of a function; the internal
    edge list keeps one entry per callee name (the propagation needs names, not every site)."""
    inf.calls = inf.calls[:_MAX_SITES]
    inf.writes = inf.writes[:_MAX_SITES]
    inf.reads = inf.reads[:_MAX_SITES]
    inf.guards = inf.guards[:_MAX_SITES]
    first: dict[str, tuple[str, str]] = {}
    for name, line in inf.internal:
        first.setdefault(name, (name, line))
    inf.internal = list(first.values())[:_MAX_SITES]


def _categories(entries: list[_Info], categories: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for cat in categories:
        need = _CATEGORY_FEATURES.get(cat)
        if need is None:
            out[cat] = []
            continue
        out[cat] = sorted({inf.span_id for inf in entries if all(x in inf.features for x in need)})
    return out


def _roles(entries: list[_Info]) -> list[dict]:
    gated: dict[str, set[str]] = {}
    for inf in entries:
        if not any(c == "caller_check" for c, _ in inf.guards):
            continue
        for r in inf.roles or {"inline_sender_check"}:
            gated.setdefault(safe_name(r), set()).add(inf.span_id)
    return [{"name": r, "holder_kind": "unknown", "gated_functions": sorted(v)} for r, v in sorted(gated.items())]
