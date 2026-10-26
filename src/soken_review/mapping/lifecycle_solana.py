"""Account-authority signals for Anchor programs from the pinned Rust source (feat/lifecycle-invariant-pass).

Works on source text, so it runs when the program build fails (the 2026-10-25 blind run produced
zero leads on an Anchor repo because every Solana detector ran only after a successful build).

The class it points at: an instruction requires a token account whose owner, authority or frozen
state is controlled by a party that does not sign the instruction. A classic SPL Token account
holder can reassign the account owner (SetAuthority AccountOwner), close an empty account, or the
mint can freeze it; the instruction's constraint then fails for every caller, and a counterparty
can no longer settle, claim or recover. Token-2022 associated token accounts carry the immutable
owner extension, so an account whose token program is Token-2022 only is skipped.

Signals (ids in `contract/rubric/invariants.yaml`):
  LC-SOL-AUTH  a `TokenAccount` field constrained by `associated_token::authority = X`,
               `token::authority = X` or `constraint = <field>.owner == X`, where X is not a
               signer of the instruction and not a program-derived account of the same struct.
  LC-SOL-PIN   a `TokenAccount` field pinned to a stored key (`address = state.key`, or a
               `has_one` on another account naming it) whose authority is not constrained to a
               signer: the user who owns it can close it, the mint can freeze it.

Parsing is lexical and conservative: comments and string literals are blanked before matching,
`#[derive(Accounts)]` structs are cut by brace matching, attributes and fields by bracket depth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_DERIVE_RE = re.compile(r"#\s*\[\s*derive\s*\(([^)]*)\)\s*\]")
_STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)")
_CTX_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(\s*(?:mut\s+)?\w+\s*:\s*Context\s*<\s*(?:'\w+\s*,\s*)*"
                     r"([A-Za-z_][A-Za-z0-9_]*)")
_TOKEN_PROGRAM_RE = re.compile(r"\b(associated_token|token)\s*::\s*token_program\s*=\s*([A-Za-z_]\w*)")
_ADDRESS_RE = re.compile(r"\baddress\s*=\s*([A-Za-z_][\w.]*)")
_HAS_ONE_RE = re.compile(r"\bhas_one\s*=\s*([A-Za-z_]\w*)")


@dataclass
class _Field:
    name: str
    type: str
    attrs: str
    line: int           # first line of the field's attributes
    end: int            # line of the field declaration


@dataclass
class _Struct:
    name: str
    path: str
    start: int
    end: int
    fields: dict[str, _Field] = field(default_factory=dict)


def _blank_comments_strings(text: str) -> str:
    """Comments and string literals replaced by spaces (line breaks kept), so offsets and lines
    stay valid and no free text reaches the matchers."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _match_close(text: str, i: int, open_c: str, close_c: str) -> int:
    depth = 0
    for j in range(i, len(text)):
        if text[j] == open_c:
            depth += 1
        elif text[j] == close_c:
            depth -= 1
            if depth == 0:
                return j
    return -1


def _line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _parse_structs(path: str, text: str) -> list[_Struct]:
    clean = _blank_comments_strings(text)
    out: list[_Struct] = []
    for m in _DERIVE_RE.finditer(clean):
        if "Accounts" not in re.split(r"[\s,]+", m.group(1)):
            continue
        sm = _STRUCT_RE.search(clean, m.end())
        if sm is None or clean[m.end():sm.start()].count(";"):
            continue
        brace = clean.find("{", sm.end())
        if brace < 0:
            continue
        close = _match_close(clean, brace, "{", "}")
        if close < 0:
            continue
        st = _Struct(name=sm.group(1), path=path, start=_line_at(clean, m.start()), end=_line_at(clean, close))
        body_start = brace + 1
        i = body_start
        attrs: list[str] = []
        attr_line = None
        while i < close:
            ch = clean[i]
            if ch.isspace() or ch == ",":
                i += 1
                continue
            if ch == "#":
                lb = clean.find("[", i)
                rb = _match_close(clean, lb, "[", "]") if lb >= 0 else -1
                if rb < 0:
                    break
                attrs.append(clean[lb + 1:rb])
                attr_line = attr_line or _line_at(clean, i)
                i = rb + 1
                continue
            # field: [pub[(crate)]] name: Type, (type may hold <...> with commas)
            colon = clean.find(":", i)
            if colon < 0 or colon > close:
                break
            head = clean[i:colon].strip()
            name = head.split()[-1] if head.split() else ""
            j, depth = colon + 1, 0
            while j < close:
                cj = clean[j]
                if cj in "<([":
                    depth += 1
                elif cj in ">)]":
                    depth -= 1
                elif cj == "," and depth <= 0:
                    break
                j += 1
            ftype = " ".join(clean[colon + 1:j].split())
            if re.fullmatch(r"[A-Za-z_]\w*", name):
                st.fields[name] = _Field(name=name, type=ftype, attrs=" ".join(" ".join(attrs).split()),
                                         line=attr_line or _line_at(clean, i), end=_line_at(clean, colon))
            attrs, attr_line = [], None
            i = j + 1
        out.append(st)
    return out


_AUTH_AT_RE = re.compile(r"\b(?:associated_token|token)\s*::\s*authority\s*=\s*")
_OWNER_AT_RE = re.compile(r"constraint\s*=\s*([A-Za-z_]\w*)\s*\.\s*owner\s*==\s*")
# a program data account (state the program owns): it can be a token authority only as a PDA the
# program signs for, never a party that can call SetAuthority on its own
_STATE_ACCOUNT_RE = re.compile(r"\b(?:AccountLoader|Account|InterfaceAccount)\s*<\s*'\w+\s*,\s*([A-Za-z_][\w:]*)\s*>")
_TOKEN_STATE = frozenset({"TokenAccount", "Mint"})
_EXTERNAL_RE = re.compile(r"\b(?:UncheckedAccount|SystemAccount|AccountInfo)\b")


def _expr_at(attrs: str, pos: int) -> str:
    """The attribute expression starting at `pos`, up to a top-level `,` or `@` (Anchor error)."""
    depth, j = 0, pos
    while j < len(attrs):
        c = attrs[j]
        if c in "([{<":
            depth += 1
        elif c in ")]}>":
            if depth == 0:
                break
            depth -= 1
        elif c in ",@" and depth == 0:
            break
        j += 1
    return attrs[pos:j].strip()


def _segments(expr: str) -> list[str]:
    """`escrow.load()?.recipient.key()` -> [escrow, recipient]; `&lender` -> [lender]."""
    e = re.sub(r"\s+", "", expr).lstrip("&*")
    e = re.sub(r"\.(key|load|load_mut|as_ref|to_account_info)\(\)\??", "", e)
    e = e.replace("?", "").replace("()", "")
    return [seg for seg in e.split(".") if seg]


def _root_key(expr: str) -> str:
    """`loan.lender.key()` -> `lender`; `lender` -> `lender`; `ctx.accounts.x` -> `x`."""
    segs = _segments(expr)
    return segs[-1] if segs else ""


def _authority_kind(st: _Struct, expr: str) -> str | None:
    """`stored` (a party key kept in program state), `external` (an account the instruction does
    not control), or None when the authority is a signer, a PDA or a program data account."""
    segs = _segments(expr)
    if not segs or not re.fullmatch(r"[A-Za-z_]\w*", segs[-1]):
        return None
    key = segs[-1]
    if _is_signer(st, key) or _is_pda(st, key) or key in ("program", "crate", "ID", "id"):
        return None
    f = st.fields.get(key)
    if f is not None:
        sm = _STATE_ACCOUNT_RE.search(f.type)
        if sm and sm.group(1).split("::")[-1] not in _TOKEN_STATE:
            return None
    if len(segs) > 1:
        return "stored"
    if f is not None and _EXTERNAL_RE.search(f.type):
        return "external"
    return None


def _is_signer(st: _Struct, key: str) -> bool:
    f = st.fields.get(key)
    if f is not None and re.search(r"\bSigner\s*<", f.type):
        return True
    return f is not None and re.search(r"\bsigner\b", f.attrs) is not None


def _is_pda(st: _Struct, key: str) -> bool:
    f = st.fields.get(key)
    return f is not None and re.search(r"\bseeds\s*=", f.attrs) is not None


def _token2022_only(st: _Struct, f: _Field, cfg: dict[str, Any]) -> bool:
    m = _TOKEN_PROGRAM_RE.search(f.attrs)
    prog = st.fields.get(m.group(2)) if m else st.fields.get("token_program")
    if prog is None:
        return False
    return re.search(cfg["token2022_only_programs"], f"{prog.type}") is not None


def solana_signals(files: dict[str, str], cfg: dict[str, Any]) -> list[dict[str, Any]]:
    dep_re = re.compile(cfg["dependency_paths"])
    tok_re = re.compile(cfg["token_account_types"])
    structs: list[_Struct] = []
    handlers: dict[str, set[str]] = {}
    for path, text in sorted(files.items()):
        if not path.endswith(".rs") or dep_re.search(path):
            continue
        structs.extend(_parse_structs(path, text))
        for m in _CTX_RE.finditer(_blank_comments_strings(text)):
            handlers.setdefault(m.group(2), set()).add(m.group(1))
    out: list[dict[str, Any]] = []
    for st in structs:
        signers = {n for n in st.fields if _is_signer(st, n)}
        ix = ", ".join(sorted(handlers.get(st.name, set()))[:3]) or st.name
        pinned_by_has_one = {m.group(1) for f in st.fields.values() for m in _HAS_ONE_RE.finditer(f.attrs)}
        for f in st.fields.values():
            if not tok_re.search(f.type) or re.search(r"\bseeds\s*=", f.attrs):
                continue
            if _token2022_only(st, f, cfg):
                continue
            authority = None
            m = _AUTH_AT_RE.search(f.attrs)
            if m:
                authority = _expr_at(f.attrs, m.end())
            else:
                mo = _OWNER_AT_RE.search(f.attrs)
                if mo and mo.group(1) == f.name:
                    authority = _expr_at(f.attrs, mo.end())
            if authority:
                kind = _authority_kind(st, authority)
                if kind is None:
                    continue
                key = _root_key(authority)
                out.append({
                    "signal": "LC-SOL-AUTH", "file": st.path, "start": f.line, "end": f.end, "strong": True,
                    # a counterparty key stored in program state is the strongest form
                    "score": 90 if kind == "stored" else 85,
                    "params": {"ix": ix, "account": f.name, "authority": " ".join(authority.split())},
                    "names": sorted({f.name, key, *handlers.get(st.name, set())}),
                })
                continue
            pin = None
            ma = _ADDRESS_RE.search(f.attrs)
            if ma and "." in ma.group(1):
                pin = ma.group(1)
            elif f.name in pinned_by_has_one:
                pin = f"has_one {f.name}"
            if pin is not None and signers:
                out.append({
                    "signal": "LC-SOL-PIN", "file": st.path, "start": f.line, "end": f.end, "strong": False,
                    "score": 40,
                    "params": {"ix": ix, "account": f.name, "pin": pin},
                    "names": sorted({f.name, *handlers.get(st.name, set())}),
                })
    return out


def account_names(files: dict[str, str], cfg: dict[str, Any]) -> set[str]:
    """Accounts-struct and field names of in-scope Rust files (protocol type detection input)."""
    dep_re = re.compile(cfg["dependency_paths"])
    names: set[str] = set()
    for path, text in files.items():
        if not path.endswith(".rs") or dep_re.search(path):
            continue
        for st in _parse_structs(path, text):
            names.add(st.name)
            names.update(st.fields)
    return names
