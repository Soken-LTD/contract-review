"""soken-cairo-rules engine (07 5.1 to 5.3, 8.3): YAML rules over class facts and the source layer.

Regexes run through RE2 (linear time) because the source is untrusted input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import re2  # type: ignore[import-untyped]
import yaml

from soken_review.adapters.starknet.felt import selector
from soken_review.adapters.starknet.sierra import ClassFacts
from soken_review.adapters.starknet.source import CairoFile, Function

RULES_PATH = Path(__file__).parent / "cairo_rules.yaml"
TOOL = "soken-cairo-rules"


@dataclass
class Hit:
    rule_id: str
    category: str
    raw: str
    file: str
    start: int
    end: int
    unit: str | None = None


def load_rules() -> dict[str, Any]:
    return yaml.safe_load(RULES_PATH.read_text())


def facts_hold(preds: list[str], facts: ClassFacts | None) -> bool:
    """All fact predicates hold; unknown facts (None or incomplete) never suppress a source match."""
    if facts is None or not facts.complete:
        return True
    for p in preds:
        kind, _, arg = p.partition(":")
        if kind == "libfunc":
            ok = arg in facts.libfuncs
        elif kind == "reachable":
            etype, _, lib = arg.partition(":")
            ok = lib in facts.reachable.get(etype, frozenset())
        elif kind == "entry":
            ok = arg in facts.entry_types
        elif kind == "selector":
            ok = any(selector(n) in facts.felt_consts for n in arg.split("|"))
        else:
            raise ValueError(f"unknown fact predicate {p!r}")
        if not ok:
            return False
    return True


def _kind_ok(fn: Function, kinds: list[str]) -> bool:
    return "any" in kinds or fn.kind in kinds


def _body_has(fn: Function, pattern: str) -> bool:
    return re2.search(pattern, fn.body) is not None


def _lines(fn: Function, pattern: str) -> list[int]:
    rx = re2.compile(pattern)
    return [fn.body_start + i for i, line in enumerate(fn.body.split("\n")) if rx.search(line)]


# ---------------------------------------------------------------------------------- custom checks

def _felt_arithmetic(rule: dict, files: list[CairoFile]) -> list[tuple[CairoFile, Function, int]]:
    out = []
    for cf in files:
        felt_members = set()
        for _s, _e, body in cf.storage_structs:
            for m in re2.finditer(r"\b(\w+)\s*:\s*felt252\b", body):
                felt_members.add(m.group(1))
        for fn in cf.functions:
            if not _kind_ok(fn, rule.get("fn_kinds", ["any"])) or ".write(" not in fn.body:
                continue
            params = [m.group(1) for m in re2.finditer(r"\b(\w+)\s*:\s*felt252\b", fn.params)]
            names = params + [f"self.{m}.read()" for m in felt_members]
            if not names:
                continue
            alt = "|".join(re.escape(n) for n in names)
            pat = rf"(^|[^\w.])({alt})\s*[-+*]\s*\w|\w\s*[-+*]\s*({alt})($|[^\w(])"
            for line in _lines(fn, pat):
                out.append((cf, fn, line))
    return out


def _deploy_from_zero_literal(rule: dict, files: list[CairoFile]) -> list[tuple[CairoFile, Function, int]]:
    out = []
    for cf in files:
        for fn in cf.functions:
            for m in re2.finditer(r"\bdeploy_syscall\s*\(", fn.body):
                close = fn.body.find(";", m.end())
                call = fn.body[m.end(): close if close != -1 else len(fn.body)]
                if re2.search(r",\s*true\s*\)\s*(\.|\?|$)", call.strip()) or re2.search(r",\s*true\s*\)", call):
                    out.append((cf, fn, fn.body_start + fn.body.count("\n", 0, m.start())))
    return out


def _camel_only_token_calls(rule: dict, files: list[CairoFile]) -> list[tuple[CairoFile, Function, int]]:
    blob = "\n".join(cf.blank for cf in files)
    if re2.search(r"\.(transfer_from|balance_of)\s*\(", blob):
        return []
    out = []
    for cf in files:
        for fn in cf.functions:
            for line in _lines(fn, r"\.(transferFrom|balanceOf)\s*\("):
                out.append((cf, fn, line))
    return out


def _storage_collision(rule: dict, files: list[CairoFile]) -> list[tuple[CairoFile, Function | None, int]]:
    """Contract storage whose own members or substorage components declare the same name (U-11)."""
    comp_members: dict[str, set[str]] = {}
    for cf in files:
        for m in re2.finditer(r"#\[starknet::component\]\s*(?:pub\s+)?mod\s+(\w+)\s*\{", cf.blank):
            start = m.end()
            members = set()
            for s_line, _e, body in cf.storage_structs:
                if cf.line_of(start) <= s_line:
                    members = {x.group(1) for x in re2.finditer(r"(?:^|\n)\s*(?:pub\s+)?(\w+)\s*:", body)}
                    break
            comp_members[m.group(1)] = members
    out = []
    for cf in files:
        for s_line, _e, body in cf.storage_structs:
            subs = re2.findall(r"#\[substorage\(v0\)\]\s*(?:pub\s+)?\w+\s*:\s*([\w:]+)::Storage", body)
            if not subs:
                continue
            own = set()
            for line in body.split("\n"):
                m = re2.match(r"\s*(?:pub\s+)?(\w+)\s*:\s*([\w:<>, ]+)", line)
                if m and not m.group(2).strip().endswith("::Storage"):
                    own.add(m.group(1))
            seen: dict[str, int] = {}
            for name in own:
                seen[name] = seen.get(name, 0) + 1
            for path in subs:
                for name in comp_members.get(path.split("::")[-1], set()):
                    seen[name] = seen.get(name, 0) + 1
            if any(v > 1 for v in seen.values()):
                out.append((cf, None, s_line))
    return out


_CUSTOM = {
    "felt_arithmetic": _felt_arithmetic,
    "deploy_from_zero_literal": _deploy_from_zero_literal,
    "camel_only_token_calls": _camel_only_token_calls,
    "storage_collision": _storage_collision,
}


def run_rules(files: list[CairoFile], facts: ClassFacts | None, rules: dict[str, Any] | None = None) -> list[Hit]:
    rules = rules or load_rules()
    hits: list[Hit] = []
    for rule in rules["rules"]:
        if not facts_hold(rule.get("facts") or [], facts):
            continue
        found: list[tuple[CairoFile, Function | None, int]] = []
        if rule.get("custom"):
            found = _CUSTOM[rule["custom"]](rule, files)
        else:
            for cf in files:
                for fn in cf.functions:
                    if not _kind_ok(fn, rule.get("fn_kinds", ["any"])):
                        continue
                    if any(not _body_has(fn, r) for r in rule.get("require", [])):
                        continue
                    if any(_body_has(fn, r) for r in rule.get("negative", [])):
                        continue
                    if rule.get("match"):
                        found += [(cf, fn, ln) for ln in _lines(fn, rule["match"])]
                    elif rule.get("fn_match") and re2.search(rule["fn_match"], fn.name):
                        found.append((cf, fn, fn.start))
        for cf, fn, line in found:
            hits.append(Hit(rule["id"], rule["category"], rule["raw"], cf.path, line, line,
                            unit=f"{cf.path}:{fn.name}" if fn else None))
    return hits
