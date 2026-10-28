"""Gate policy (never-worse, CEO direction 2026-10-27 section A): which rejections block a write.

The classification is reference data in ``contract/rubric/gate_policy.yaml``; this module only reads
it. Three classes:

* ``blocking``: evidence integrity or publication safety. The call is refused, as before.
* ``advisory``: the call succeeds; the item becomes a warning in the result and is stored.
* ``rewrite``: the call succeeds; the server rewrote the matched text for publication before storing
  it (``rewrite_text``) and the warning names the old and the new text.

A code or rule missing from the file is blocking (fail closed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import yaml

RUBRIC_DIR = Path(__file__).resolve().parents[3] / "contract" / "rubric"
POLICY_FILE = RUBRIC_DIR / "gate_policy.yaml"

BLOCKING = "blocking"
ADVISORY = "advisory"
REWRITE = "rewrite"
_CLASSES = frozenset({BLOCKING, ADVISORY, REWRITE})

# Warnings returned per call; the rest are counted in `warnings_more`.
MAX_WARNINGS = 20


@dataclass(frozen=True)
class Disposition:
    cls: str
    why: str


@cache
def _policy() -> dict[str, Any]:
    doc = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8")) or {}
    for code, row in (doc.get("codes") or {}).items():
        if row.get("class") not in _CLASSES:
            raise ValueError(f"gate_policy.yaml: {code} has class {row.get('class')!r}")
        for rid, sub in (row.get("rules") or {}).items():
            if sub.get("class") not in _CLASSES:
                raise ValueError(f"gate_policy.yaml: {code}.{rid} has class {sub.get('class')!r}")
    return doc


def codes() -> dict[str, dict[str, Any]]:
    """The code rows of the policy (for tests and the guide)."""
    return dict(_policy().get("codes") or {})


def disposition(code: str, rule: str | None = None) -> Disposition:
    """Class and rationale of one rejection, by error code and (optionally) rule id."""
    row = (_policy().get("codes") or {}).get(code)
    if row is None:
        return Disposition(_policy().get("default_class", BLOCKING), "not classified: fail closed")
    if rule:
        # A rule id is classified by its own row only: an unlisted rule is never advisory by
        # inheritance from its code (fail closed; security review 2026-10-27).
        sub = (row.get("rules") or {}).get(rule)
        if sub is None:
            return Disposition(_policy().get("default_class", BLOCKING), f"rule {rule} not classified: fail closed")
        return Disposition(sub["class"], str(sub.get("why", "")))
    return Disposition(row["class"], str(row.get("why", "")))


def is_classified(code: str, rule: str | None = None) -> bool:
    """True when the policy has an explicit row for this code (and rule id, when one is given)."""
    row = (_policy().get("codes") or {}).get(code)
    if row is None:
        return False
    return rule is None or rule in (row.get("rules") or {})


def is_exempt(code: str, rule: str | None, field: str | None) -> bool:
    """True when the rule does not apply to this prose field at all (e.g. T13 in severity_reason)."""
    if not rule or not field:
        return False
    row = (_policy().get("codes") or {}).get(code) or {}
    sub = (row.get("rules") or {}).get(rule) or {}
    return field in (sub.get("exempt_fields") or row.get("exempt_fields") or [])


def is_blocking(code: str, rule: str | None = None) -> bool:
    return disposition(code, rule).cls == BLOCKING


def finalize_check(check_id: str) -> dict[str, Any]:
    """Row of one finalize check (F1..F9): class, kind (the coverage note key) and rationale."""
    row = (_policy().get("finalize_checks") or {}).get(check_id)
    if row is None:
        return {"class": BLOCKING, "why": "not classified: fail closed"}
    return dict(row)


def finalize_check_blocks(check_id: str) -> bool:
    return finalize_check(check_id).get("class") == BLOCKING


def warning(envelope: dict[str, Any], *, code: str, rule: str | None, field: str | None = None,
            match: str | None = None, suggest: str | None = None, cls: str | None = None) -> dict[str, Any]:
    """One warning object (schema `$defs/warning`) from a rejection envelope."""
    d = disposition(code, rule)
    out: dict[str, Any] = {
        "code": code,
        "class": cls or (ADVISORY if d.cls == BLOCKING else d.cls),
        "what": str(envelope.get("what", ""))[:300],
        "suggest": str(suggest if suggest is not None else envelope.get("fix", ""))[:300],
    }
    if rule:
        out["rule"] = str(rule)[:40]
    f = field if field is not None else envelope.get("field")
    if f:
        out["field"] = str(f)[:80]
    if match:
        out["match"] = str(match)[:120]
    return out


# ── Rewrites ──────────────────────────────────────────────────────────────────

_PROTECTED_RE = re.compile(r"`[^`\n]+`|\{\{[^{}]*\}\}")


@cache
def _rewrites() -> list[tuple[str, str | None, re.Pattern[str], str, bool]]:
    out = []
    for row in _policy().get("rewrites") or []:
        flags = re.IGNORECASE if row.get("case") == "preserve" else 0
        out.append((str(row["rule"]), row.get("field"), re.compile(str(row["pattern"]), flags),
                    str(row.get("replace", "")), row.get("case") == "preserve"))
    return out


def _apply(pattern: re.Pattern[str], replace: str, preserve: bool, text: str) -> tuple[str, list[str]]:
    hits: list[str] = []

    def sub(m: re.Match[str]) -> str:
        hits.append(m.group())
        if preserve and m.group()[:1].isupper():
            return replace[:1].upper() + replace[1:]
        return replace

    return pattern.sub(sub, text), hits


def rewrite_text(text: str, field: str | None = None) -> tuple[str, list[dict[str, str]]]:
    """Apply the publication rewrites outside code spans and placeholders.

    Returns (new text, [{rule, match, replace}]) with one entry per rule that changed the text.
    Idempotent: rewriting the output again changes nothing.
    """
    if not text:
        return text, []
    applied: list[dict[str, str]] = []
    for rule, only_field, pattern, replace, preserve in _rewrites():
        if only_field and only_field != field:
            continue
        parts: list[str] = []
        pos = 0
        hits: list[str] = []
        for m in _PROTECTED_RE.finditer(text):
            chunk, h = _apply(pattern, replace, preserve, text[pos:m.start()])
            parts.extend([chunk, m.group()])
            hits.extend(h)
            pos = m.end()
        chunk, h = _apply(pattern, replace, preserve, text[pos:])
        parts.append(chunk)
        hits.extend(h)
        new = "".join(parts)
        if new != text:
            applied.append({"rule": rule, "match": ", ".join(dict.fromkeys(hits))[:120], "replace": replace or "(removed)"})
            text = new
    return text, applied


def rewrite_blocks(blocks: Any, field: str) -> tuple[Any, list[dict[str, str]]]:
    """rewrite_text over model blocks ({p}, {ul}, {table}) of one field, returning new blocks."""
    if not isinstance(blocks, list):
        return blocks, []
    out: list[Any] = []
    applied: list[dict[str, str]] = []

    def one(s: Any) -> Any:
        if not isinstance(s, str):
            return s
        new, a = rewrite_text(s, field)
        applied.extend(a)
        return new

    for b in blocks:
        if not isinstance(b, dict):
            out.append(b)
            continue
        nb = dict(b)
        for key in ("p", "risk_note", "note", "reason"):
            if key in nb:
                nb[key] = one(nb[key])
        if isinstance(nb.get("ul"), list):
            nb["ul"] = [one(x) for x in nb["ul"]]
        tbl = nb.get("table")
        if isinstance(tbl, dict):
            nt = dict(tbl)
            if isinstance(nt.get("head"), list):
                nt["head"] = [one(x) for x in nt["head"]]
            if isinstance(nt.get("rows"), list):
                nt["rows"] = [[one(c) for c in row] if isinstance(row, list) else row for row in nt["rows"]]
            nb["table"] = nt
        out.append(nb)
    return out, applied


def rewrite_finding(args: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Copy of a submit_finding argument dict with every prose field rewritten for publication."""
    out = dict(args)
    applied: list[dict[str, str]] = []

    def tag(items: list[dict[str, str]], field: str) -> None:
        applied.extend({**a, "field": field} for a in items)

    if isinstance(out.get("title"), str):
        out["title"], a = rewrite_text(out["title"], "title")
        tag(a, "title")
    body = out.get("body")
    if isinstance(body, dict):
        nb = dict(body)
        for section in ("description", "impact", "recommendation", "notes"):
            if section in nb:
                nb[section], a = rewrite_blocks(nb[section], section)
                tag(a, section)
        out["body"] = nb
    if isinstance(out.get("attack_steps"), list):
        steps = []
        for s in out["attack_steps"]:
            if isinstance(s, dict) and isinstance(s.get("text"), str):
                text, a = rewrite_text(s["text"], "attack_steps")
                tag(a, "attack_steps")
                s = {**s, "text": text}
            steps.append(s)
        out["attack_steps"] = steps
    for key in ("notes", "severity_reason"):
        if isinstance(out.get(key), str):
            out[key], a = rewrite_text(out[key], key)
            tag(a, key)
    return out, applied


def rewrite_warnings(applied: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Warning objects for the rewrites rewrite_finding / rewrite_blocks applied."""
    out = []
    for a in applied:
        d = disposition("E_TEXT_GATE", a["rule"])
        w: dict[str, Any] = {
            "code": "E_TEXT_GATE", "class": REWRITE, "rule": a["rule"],
            "match": a["match"],
            "what": f"Rule {a['rule']} matched {a['match']!r}; the server printed {a['replace']!r} instead.",
            "suggest": d.why[:300],
        }
        if a.get("field"):
            w["field"] = a["field"]
        out.append(w)
    return out


def policy_lines() -> list[str]:
    """One line per classified code and rule for review_get_guide (challenge_rules)."""
    lines = []
    for code, row in codes().items():
        lines.append(f"{code}: {row['class']}. {row.get('why', '')}")
        for rid, sub in (row.get("rules") or {}).items():
            lines.append(f"  {code} {rid}: {sub['class']}. {sub.get('why', '')}")
    return lines
