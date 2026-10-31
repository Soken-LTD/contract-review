"""Job artifacts the validators read: map, tokens, facts, injection flags (04 sections 2.1, 6.3, 7.5, 12).

Pure (10 T1: V0 to V12 callable as `validate(call, artifacts)` without I/O). The tools layer loads
an `Artifacts` value from the job store; every function here only reads it.

  word_set(a)                         word set of 5.1: identifier and type_name tokens plus map names
  a1_literals(a, quotes)              A1 and A2 inputs of 6.3 for a finding's quoted lines
  number_context(a, quotes, ...)      NumberContext with facts filtered by the 6.3 meaning rule
  references(a, name, files)          2.1 `references` of an identifier, declaration lines excluded
  entry_functions_for(a, path, line)  7.5 entry functions whose call graph reaches the line
  flags_in(a, path, start, end)       J1 to J5 flags of a range (03 4.4 `flags`)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .numbers import NumberContext

_SOL_UNIT_WORDS = frozenset({"wei", "gwei", "szabo", "finney", "ether", "seconds", "minutes", "hours", "days",
                             "weeks", "years"})
_MAX_CALL_DEPTH = 8


@dataclass(frozen=True)
class Artifacts:
    map: dict[str, Any] | None = None
    map_status: str | None = None
    tokens: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    facts: list[dict[str, Any]] | None = None
    flags: list[dict[str, Any]] = field(default_factory=list)

    @property
    def semantic(self) -> dict[str, Any] | None:
        return (self.map or {}).get("semantic")


def word_set(a: Artifacts) -> frozenset[str]:
    words: set[str] = set()
    for toks in a.tokens.values():
        words.update(t["text"] for t in toks if t.get("kind") in ("identifier", "type_name"))
    m = a.map or {}
    words.update(s["name"] for s in m.get("spans") or [])
    words.update(c["name"] for c in m.get("constants") or [])
    sem = m.get("semantic") or {}
    words.update(u["name"] for u in sem.get("units") or [])
    words.update(v["name"] for v in sem.get("state_vars") or [])
    return frozenset(words)


def _quoted_lines(quotes: list[dict[str, Any]]) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for q in quotes:
        out.setdefault(q["file"], set()).update(range(int(q["start"]), int(q["end"]) + 1))
    return out


def a1_literals(a: Artifacts, quotes: list[dict[str, Any]]) -> tuple[frozenset[str], bool]:
    """(A1 values, A2 applies): literal_num tokens on quoted lines (comments and strings excluded by
    token kind) plus `constants.folded_value` of identifiers on those lines; A2 when a Solidity unit
    suffix sits on a quoted line."""
    lines = _quoted_lines(quotes)
    consts = {c["name"]: c["folded_value"] for c in (a.map or {}).get("constants") or []}
    decl_literals: dict[str, set[str]] | None = None
    values: set[str] = set()
    units = False
    for path, ls in lines.items():
        for t in a.tokens.get(path, []):
            if t["line"] not in ls:
                continue
            kind = t.get("kind")
            if kind == "literal_num":
                values.add(t["text"].strip())
            elif kind == "identifier" and t["text"] in consts:
                values.add(consts[t["text"]])
                values.update(_scaled_percents(consts[t["text"]]))
            elif kind in ("keyword", "identifier") and t["text"] in _SOL_UNIT_WORDS:
                units = True
            if kind == "identifier":
                # A named constant used on a quoted line: the literals of its own initializer are
                # code values too (r5 2026-10-31: `MAX_LIQUIDATION_PENALTY_X32 = uint32(Q32 / 10)`
                # quoted at its use site, "10 percent" was rejected as unsourced).
                if decl_literals is None:
                    decl_literals = _constant_initializer_literals(a)
                values.update(decl_literals.get(t["text"], ()))
    return frozenset(values), units


_CONST_KEYWORDS = frozenset({"constant", "immutable", "const"})
# Fixed-point scales a constant is commonly expressed in; a folded value over one of them, times
# a hundred, is the percent a reviewer writes ("Q32 / 10" is "10 percent").
_PERCENT_SCALES = (10_000, 10**18, 2**32, 2**64, 2**96, 2**128)


def _scaled_percents(folded: str) -> set[str]:
    from decimal import Decimal, InvalidOperation
    try:
        v = Decimal(folded)
    except InvalidOperation:
        return set()
    out: set[str] = set()
    for scale in _PERCENT_SCALES:
        if v <= 0 or v > scale * 10:
            continue
        pct = (v * 100 / Decimal(scale)).quantize(Decimal("0.01"))
        exact = v * 100 / Decimal(scale)
        # within a rounding step of the integer-division initializer (Q32 / 10 floors)
        if pct > 0 and abs(exact - pct) * Decimal(scale) <= 100:
            out.add(format(pct.normalize(), "f"))
    return out


def _constant_initializer_literals(a: Artifacts) -> dict[str, set[str]]:
    """name -> literal_num texts of its initializer, for `constant` / `immutable` / `const`
    declarations in the stored token streams (declaration up to the closing `;`)."""
    out: dict[str, set[str]] = {}
    for toks in a.tokens.values():
        i, n = 0, len(toks)
        while i < n:
            t = toks[i]
            if t.get("kind") == "keyword" and t["text"] in _CONST_KEYWORDS:
                j = i + 1
                name = None
                while j < n and j < i + 8 and toks[j]["text"] not in ("=", ";"):
                    if toks[j].get("kind") == "identifier":
                        name = toks[j]["text"]
                    j += 1
                if name and j < n and toks[j]["text"] == "=":
                    k = j + 1
                    lits: set[str] = set()
                    while k < n and k < j + 64 and toks[k]["text"] != ";":
                        if toks[k].get("kind") == "literal_num":
                            lits.add(toks[k]["text"].strip())
                        k += 1
                    if lits:
                        out.setdefault(name, set()).update(lits)
                    i = k
                    continue
            i += 1
    return out


def fact_meaning_filter(a: Artifacts, *, is_finding: bool, component: str | None,
                        magnitude: str | None) -> tuple[dict[str, str], frozenset[str]]:
    """(allowed facts key->value, blocked keys) under the 04 6.3 meaning rule."""
    allowed: dict[str, str] = {}
    blocked: set[str] = set()
    for f in a.facts or []:
        if "amount_at_risk" in (f.get("tags") or []):
            ok = is_finding and magnitude == "unbounded" and f.get("unit_id") is not None \
                and f.get("unit_id") == component
            if not ok:
                blocked.add(f["key"])
                continue
        allowed[f["key"]] = f["value"]
    return allowed, frozenset(blocked)


def number_context(a: Artifacts, quotes: list[dict[str, Any]], *, is_finding: bool = True,
                   component: str | None = None, magnitude: str | None = None,
                   draft_keys: frozenset[str] = frozenset()) -> NumberContext:
    """NumberContext for one model string of a finding (or a non-finding string)."""
    literals, units = a1_literals(a, quotes) if is_finding else (frozenset(), False)
    allowed, blocked = fact_meaning_filter(a, is_finding=is_finding, component=component, magnitude=magnitude)
    return NumberContext(
        allowed_literals=literals,
        include_solidity_units=units,
        facts=allowed,
        quoted_line_ranges=[(q["file"], int(q["start"]), int(q["end"])) for q in quotes] if is_finding else [],
        word_set=word_set(a),
        is_finding=is_finding,
        draft_keys=draft_keys,
        known_fact_keys=frozenset(f["key"] for f in a.facts) if a.facts is not None else None,
        blocked_fact_keys=blocked,
    )


def references(a: Artifacts, name: str, files: set[str] | None = None) -> list[str]:
    refs = ((a.map or {}).get("references") or {}).get(name) or []
    if files is None:
        return list(refs)
    return [r for r in refs if r.rpartition(":")[0] in files]


def span_at(a: Artifacts, path: str, line: int) -> dict[str, Any] | None:
    """Innermost span of the map holding path:line."""
    best = None
    for s in (a.map or {}).get("spans") or []:
        inside = s["file"] == path and s["start"] <= line <= s["end"]
        if inside and (best is None or (s["end"] - s["start"]) < (best["end"] - best["start"])):
            best = s
    return best


def entry_functions_for(a: Artifacts, path: str, line: int) -> list[str] | None:
    """Span ids of the entry functions whose call graph reaches the span holding path:line (7.5).

    None without a semantic layer (7.5: `map_unavailable`); a line on a state-variable declaration
    resolves to the entry functions that write that variable.
    """
    sem = a.semantic
    if sem is None:
        return None
    spans = {s["id"]: s for s in (a.map or {}).get("spans") or []}
    by_name: dict[str, list[str]] = {}
    for s in spans.values():
        by_name.setdefault(s["name"], []).append(s["id"])
    funcs = {f["span"]: f for f in sem.get("functions") or []}
    ref = f"{path}:{line}"
    var = next((v for v in sem.get("state_vars") or [] if v.get("decl_ref") == ref), None)
    if var is not None:
        return sorted(f["span"] for f in funcs.values() if f["is_entry"]
                      and any(w["var"] == var["name"] for w in f.get("writes") or []))
    target = span_at(a, path, line)
    if target is None:
        return []
    out = []
    for f in funcs.values():
        if not f["is_entry"]:
            continue
        seen = {f["span"]}
        frontier = [f["span"]]
        depth = 0
        hit = f["span"] == target["id"]
        while frontier and not hit and depth < _MAX_CALL_DEPTH:
            nxt = []
            for sid in frontier:
                for call in (funcs.get(sid) or {}).get("calls") or []:
                    if call.get("kind") != "internal":
                        continue
                    for cand in by_name.get(call["target"], []):
                        if cand == target["id"]:
                            hit = True
                        if cand not in seen:
                            seen.add(cand)
                            nxt.append(cand)
            frontier = nxt
            depth += 1
        # modifiers of the entry function execute on its path too
        if not hit and target.get("kind") == "modifier" and target["name"] in (f.get("modifiers") or []):
            hit = True
        if hit:
            out.append(f["span"])
    return sorted(out)


def flags_in(a: Artifacts, path: str, start: int, end: int) -> list[dict[str, Any]]:
    return [f for f in a.flags if f["file"] == path and start <= f["line"] <= end]


def j1_flags(a: Artifacts) -> list[dict[str, Any]]:
    return [f for f in a.flags if f["rule"] == "J1"]
