"""Move source layer (plan v4 07 section 5.1): exact `path:line` ranges for modules, functions
and structs, so every lead points at quotable lines (E2).

Plan 07 names tree-sitter grammars; this is a lexical scanner over comment-stripped text with
brace matching (no grammar dependency). It finds what the rules need: module headers (block and
Move 2024 file-level forms), function declarations with visibility, `entry`, attributes and body
range, and struct declarations with abilities. A file it cannot balance is reported `partial`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from soken_review.adapters.move.units import strip_comments

_MODULE_RE = re.compile(r"\bmodule\s+(?:([A-Za-z0-9_]+)\s*::\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*([{;])")
_FUN_RE = re.compile(
    r"(?P<attrs>(?:#\[[^\]]*\]\s*)*)"
    r"(?P<vis>public\s*\(\s*(?:package|friend)\s*\)\s*|public\s+|friend\s+)?"
    r"(?P<entry>entry\s+)?(?P<native>native\s+)?(?:inline\s+)?(?:entry\s+)?fun\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_STRUCT_RE = re.compile(
    r"(?:public\s+)?struct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{]*>)?\s*(?:has\s+(?P<pre>[a-z,\s]+?))?\s*[{(;]"
)
_HAS_POST_RE = re.compile(r"^\s*has\s+([a-z,\s]+?)\s*;")


@dataclass
class FnSpan:
    module: str
    name: str
    file: str
    start: int
    end: int
    body_start: int                 # line of the opening brace (== start for native/no body)
    visibility: str                 # public | friend | private
    entry: bool
    attributes: list[str] = field(default_factory=list)
    body: str = ""                  # comment-stripped body text (rules read it)
    signature: str = ""             # comment-stripped text from `fun` to the body


@dataclass
class StructSpan:
    module: str
    name: str
    file: str
    start: int
    end: int
    abilities: list[str]
    body: str = ""


@dataclass
class SourceIndex:
    functions: list[FnSpan] = field(default_factory=list)
    structs: list[StructSpan] = field(default_factory=list)
    modules: dict[str, tuple[str, int, int]] = field(default_factory=dict)   # name -> (file, start, end)
    files: dict[str, str] = field(default_factory=dict)                     # path -> ok | partial
    code: dict[str, str] = field(default_factory=dict)                      # path -> stripped text

    def fns(self, module: str, name: str) -> list[FnSpan]:
        """Every in-scope span for module::name. More than one (same module name declared twice,
        or a duplicated function) is ambiguous: callers use all of them, never pick the first."""
        return [f for f in self.functions if f.module == module and f.name == name]


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _match_brace(code: str, open_pos: int) -> int | None:
    depth = 0
    for i in range(open_pos, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _module_regions(code: str) -> list[tuple[str, int, int]]:
    regions = []
    for m in _MODULE_RE.finditer(code):
        if m.group(3) == "{":
            end = _match_brace(code, m.end() - 1)
            if end is None:
                continue
            regions.append((m.group(2), m.start(), end))
        else:                                   # Move 2024 `module a::b;` covers the rest of the file
            regions.append((m.group(2), m.start(), len(code)))
    return regions


def index_sources(files: dict[str, str], in_scope) -> SourceIndex:
    """Scan every in-scope `.move` file."""
    idx = SourceIndex()
    for path in sorted(files):
        if not in_scope(path):
            continue
        code = strip_comments(files[path])
        idx.code[path] = code
        status = "ok"
        regions = _module_regions(code)
        if not regions:
            status = "partial"
        for mod, mstart, mend in regions:
            idx.modules.setdefault(mod, (path, _line(code, mstart), _line(code, mend)))
            region = code[mstart:mend]
            for fm in _FUN_RE.finditer(region):
                abs_start = mstart + fm.start() + (len(fm.group("attrs")) if fm.group("attrs") else 0)
                # skip leading whitespace that the attrs group may have left
                while abs_start < len(code) and code[abs_start].isspace():
                    abs_start += 1
                after = mstart + fm.end()
                brace = code.find("{", after)
                semi = code.find(";", after)
                vis_raw = (fm.group("vis") or "").replace(" ", "")
                vis = "public" if vis_raw == "public" else ("friend" if vis_raw else "private")
                attrs = re.findall(r"#\[([^\]]*)\]", fm.group("attrs") or "")
                if fm.group("native") or (semi != -1 and (brace == -1 or semi < brace)):
                    end_pos, body, body_line = semi, "", _line(code, abs_start)
                    sig = code[after:semi] if semi != -1 else ""
                else:
                    close = _match_brace(code, brace)
                    if close is None:
                        status = "partial"
                        continue
                    end_pos, body, body_line = close, code[brace + 1:close], _line(code, brace)
                    sig = code[after:brace]
                idx.functions.append(FnSpan(
                    module=mod, name=fm.group("name"), file=path, start=_line(code, abs_start),
                    end=_line(code, end_pos), body_start=body_line, visibility=vis,
                    entry=bool(fm.group("entry")) or "entry" in (fm.group(0) or "").split("fun")[0],
                    attributes=[a.strip() for a in attrs], body=body, signature=sig,
                ))
            for sm in _STRUCT_RE.finditer(region):
                abs_start = mstart + sm.start()
                term = code[mstart + sm.end() - 1]
                abilities = sm.group("pre") or ""
                if term == "{":
                    close = _match_brace(code, mstart + sm.end() - 1)
                    if close is None:
                        status = "partial"
                        continue
                    post = _HAS_POST_RE.match(code[close + 1:close + 80])
                    if post:
                        abilities += "," + post.group(1)
                    end_pos, body = close, code[mstart + sm.end():close]
                else:
                    end_pos, body = mstart + sm.end() - 1, ""
                idx.structs.append(StructSpan(
                    module=mod, name=sm.group("name"), file=path, start=_line(code, abs_start),
                    end=_line(code, end_pos), body=body,
                    abilities=sorted({a.strip() for a in abilities.split(",") if a.strip()}),
                ))
        idx.files[path] = status
    seen: dict[tuple[str, str], list[FnSpan]] = {}
    for f in idx.functions:
        seen.setdefault((f.module, f.name), []).append(f)
    for spans in seen.values():
        if len(spans) > 1:
            for f in spans:
                idx.files[f.file] = "partial"
    return idx
