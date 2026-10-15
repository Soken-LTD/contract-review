"""Cairo source layer (07 5.1): functions, their kind and exact line ranges.

07 names tree-sitter-cairo; no maintained Python wheel of that grammar exists, so this module
is a small brace-matching splitter over comment- and string-blanked text (W0 finding). It gives
the `path:line` ranges leads quote; detection precision rests on the rule fixtures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Function:
    name: str
    kind: str                 # external | view | l1_handler | constructor | internal
    start: int                # 1-based line of `fn`
    end: int                  # 1-based line of the closing brace
    params: str
    body: str                 # blanked body text (comments and strings removed)
    body_start: int           # line of the opening brace
    attributes: list[str] = field(default_factory=list)


@dataclass
class CairoFile:
    path: str
    text: str
    blank: str                # same length and lines as text; comments and strings are spaces
    functions: list[Function]
    storage_structs: list[tuple[int, int, str]]    # (start, end, body) of #[storage] structs

    def line_of(self, offset: int) -> int:
        return self.blank.count("\n", 0, offset) + 1


def blank_comments_strings(text: str) -> str:
    """Replace `//` comments, "..." strings and '...' short strings by spaces, keeping newlines."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c in "\"'":
            q = c
            out[i] = " "
            i += 1
            while i < n and text[i] != q and text[i] != "\n":
                if text[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    i += 1
                out[i] = " "
                i += 1
            if i < n and text[i] == q:
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _match(blank: str, open_idx: int, open_c: str, close_c: str) -> int:
    depth = 0
    for j in range(open_idx, len(blank)):
        if blank[j] == open_c:
            depth += 1
        elif blank[j] == close_c:
            depth -= 1
            if depth == 0:
                return j
    return len(blank) - 1


_FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{]*>)?\s*\(")
_IMPL_RE = re.compile(r"\bimpl\s+[A-Za-z_][A-Za-z0-9_]*[^{;]*\{")
_ATTR_RE = re.compile(r"#\[[^\]]*\]")
_STORAGE_RE = re.compile(r"#\[storage\]\s*(?:pub\s+)?struct\s+\w+\s*\{")


_TRAIL_ATTR_RE = re.compile(r"#\[[^\[\]]*\]\s*$")
_TRAIL_MOD_RE = re.compile(r"(?:\bpub(?:\([a-z]+\))?|\bunsafe|\bextern)\s*$")


def attrs_before(blank: str, idx: int) -> list[str]:
    """Attributes that apply to the item starting at `idx`.

    Only text made of whitespace, visibility keywords and other attributes may sit between an
    attribute and the item; anything else (`#[cfg(test)] mod a; mod b;`) stops the scan, so an
    attribute is never attributed to a later sibling.
    """
    head = blank[:idx]
    attrs: list[str] = []
    while True:
        stripped = head.rstrip()
        m = _TRAIL_MOD_RE.search(stripped)
        if m and m.group(0).strip():
            head = stripped[:m.start()]
            continue
        m = _TRAIL_ATTR_RE.search(stripped)
        if not m:
            break
        attrs.insert(0, m.group(0).strip().replace(" ", ""))
        head = stripped[:m.start()]
    return attrs


_attrs_before = attrs_before


def parse(path: str, text: str) -> CairoFile:
    blank = blank_comments_strings(text)
    impls: list[tuple[int, int, list[str]]] = []
    for m in _IMPL_RE.finditer(blank):
        open_idx = m.end() - 1
        impls.append((m.start(), _match(blank, open_idx, "{", "}"), _attrs_before(blank, m.start())))
    cf = CairoFile(path, text, blank, [], [])
    for m in _STORAGE_RE.finditer(blank):
        close = _match(blank, m.end() - 1, "{", "}")
        cf.storage_structs.append((cf.line_of(m.start()), cf.line_of(close), blank[m.end():close]))
    for m in _FN_RE.finditer(blank):
        paren = m.end() - 1
        pclose = _match(blank, paren, "(", ")")
        brace = blank.find("{", pclose)
        semi = blank.find(";", pclose)
        if brace == -1 or (semi != -1 and semi < brace):
            continue          # trait declaration without a body
        close = _match(blank, brace, "{", "}")
        attrs = _attrs_before(blank, m.start())
        impl_attrs = next((a for s, e, a in impls if s < m.start() < e), None)
        params = blank[paren + 1:pclose]
        kind = "internal"
        if "#[l1_handler]" in attrs:
            kind = "l1_handler"
        elif "#[constructor]" in attrs:
            kind = "constructor"
        elif any(a.startswith("#[external(") for a in attrs) or (
            impl_attrs is not None
            and any(a.startswith(("#[abi(embed_v0)]", "#[embeddable_as(")) for a in impl_attrs)
        ):
            kind = "view" if re.search(r"\bself\s*:\s*@", params) else "external"
        cf.functions.append(Function(
            name=m.group(1), kind=kind, start=cf.line_of(m.start()), end=cf.line_of(close),
            params=params, body=blank[brace:close + 1], body_start=cf.line_of(brace), attributes=attrs,
        ))
    return cf


def line_hits(fn: Function, pattern: re.Pattern[str]) -> list[int]:
    """1-based file lines inside the function body that match `pattern`."""
    hits: list[int] = []
    for i, line in enumerate(fn.body.split("\n")):
        if pattern.search(line):
            hits.append(fn.body_start + i)
    return hits


# Matches:  #[substorage(v0)]
#               field_name: ModPath::Storage,
# Groups: (field_name, mod_path_without_Storage)
_SUBSTORAGE_RE = re.compile(
    r"#\[substorage\(v0\)\]\s*(?:pub\s+)?(\w+)\s*:\s*([\w:]+)::Storage\b"
)


def extract_components(files: list[CairoFile]) -> list[dict]:
    """07 10 chain_extras `components[]`: each #[substorage(v0)] field in any storage struct.

    Returns [{"path": "ModPath", "storage_name": "field_name"}, ...] in source order.
    Duplicates (same path+name from multiple files) are deduplicated; order is first occurrence.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for cf in files:
        for _s, _e, body in cf.storage_structs:
            for m in _SUBSTORAGE_RE.finditer(body):
                storage_name = m.group(1)
                path = m.group(2)
                key = (path, storage_name)
                if key not in seen:
                    seen.add(key)
                    out.append({"path": path, "storage_name": storage_name})
    return out
