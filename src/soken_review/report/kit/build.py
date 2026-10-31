"""Report kit, automated type (08 sections 1 and 2). Pure: data in, HTML out, no network.

`build(report, out_dir, mode=, compact_evidence=)` validates `report.automated.schema.json`,
runs `check_strings()` on the placeholder form (08 1.5), applies `project()` (08 2.4, the only
place placeholders expand) and writes `print.html` or `screen.html`.
Every call uses its own `BuildContext` (08 1.1 item 2), so print, screen, print in one process
give identical bytes. The manual kit stays in the soken-offsec skill (08 1.1: manual unchanged).
"""

from __future__ import annotations

import base64
import copy
import html as _html
import json
import math
import re
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from functools import cache
from pathlib import Path
from typing import Any

KIT = Path(__file__).resolve().parent
REPO = KIT.parents[3]
SCHEMA_PATH = REPO / "contract" / "report.automated.schema.json"

SEVS = ["Critical", "High", "Medium", "Low", "Informational"]
SEV_PREFIX = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}
SEVCOL = {"Critical": "#d9536b", "High": "#e07a4a", "Medium": "#c2922f", "Low": "#6fa3cc", "Informational": "#8397b4"}
SURF, INK, MUTE, GRID = "#0d1728", "#cdd9ea", "#8397b4", "#26374f"
# Declared-vs-observed status chips (context ingestion spec 7): matches green, differs amber,
# not_checkable grey; same chip markup and style as the severity chips.
STATUS_COL = {"matches": "#199e70", "differs": "#c2922f", "not_checkable": "#8397b4"}
MAX_CONTEXT_KEEP_ROWS = 12
SERIES = ["#3987e5", "#199e70"]  # kit palette, validated on SURF (kit REPORT-STANDARD)
CSP = ("default-src 'none'; img-src data:; font-src data:; style-src 'unsafe-inline'; "
       "script-src 'unsafe-inline'")  # print.html: paged.js is inline; never leaves the sandbox
# screen.html is published on the soken.dev origin: no script at all. The hosted route adds the same
# policy as an HTTP header (K5).
CSP_SCREEN = ("default-src 'none'; img-src data:; font-src data:; style-src 'unsafe-inline'; script-src 'none'; "
              "base-uri 'none'; form-action 'none'")
SITE = "https://soken.dev/"
WIDTH_RE = re.compile(r"^(\d{1,2}%)?$")
# 04 E8: bidi controls and zero-width characters shown as a visible token in source text.
HIDDEN_RANGES = [(0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069), (0x061C, 0x061C),
                 (0xFEFF, 0xFEFF), (0x00AD, 0x00AD)]
HIDDEN_RE = re.compile("[" + "".join(f"{chr(a)}-{chr(z)}" for a, z in HIDDEN_RANGES) + "]")
PLACEHOLDER_RE = re.compile(r"\{\{(fact|calc|finding):([^{}]*)\}\}")
# Anything that looks like a placeholder, in any brace form: the late check fails the render on a
# form `expand()` does not substitute instead of printing it (Wallitelli PDF, matrix run 2026-10-27:
# `{fact:onchain.total_supply}` and `{fact:compiler.version}` printed on page 4).
PLACEHOLDER_ANY_RE = re.compile(r"\{{1,2}(?:fact|calc|finding):[^{}\n]*\}{1,2}")
MAX_COMPONENT_ROWS, MAX_FILE_ROWS = 12, 15
# Pagination (kit CSS contract): a table or a heading-plus-table block is kept on one page
# (break-inside:avoid) only when it is short enough to always fit: at most MAX_KEEP_ROWS rows and
# about MAX_KEEP_LINES text lines (a narrow cell wraps at about KEEP_CHARS_PER_LINE characters; an
# A4 page of the kit holds about 70 lines). Anything longer breaks between rows with the header
# row repeated. Live cases 2026-10-27: a 37-lead table and a 34-row scope table in keep blocks.
MAX_KEEP_ROWS, MAX_KEEP_LINES, KEEP_CHARS_PER_LINE = 12, 36, 40
_TAG_RE = re.compile(r"<[^>]+>")
_ROW_RE = re.compile(r"<tr[ >].*?</tr>", re.DOTALL)


class BuildError(Exception):
    """08 render detail code (contract/errors.yaml `E_RENDER_FAILED` detail), detail, json path."""

    def __init__(self, code: str, detail: str = "", path: str = "", rule: str = "") -> None:
        super().__init__(f"{code}: {detail} {path}".strip())
        self.code, self.detail, self.path, self.rule = code, detail, path, rule


@dataclass
class BuildResult:
    html_path: Path
    mode: str
    figures: int
    sections: int
    uses_mono: bool
    out_name: str
    profile: str


@dataclass
class BuildContext:
    """Per-call counters and state (08 1.1 item 2)."""

    texts: dict[str, Any]
    mode: str
    profile: str
    compact: bool
    fig_n: int = 0
    sec_n: int = 0
    uses_mono: bool = False
    sec_numbers: dict[str, int] = field(default_factory=dict)


# ------------------------------------------------------------------ data files
@cache
def kit_texts() -> dict[str, Any]:
    return json.loads((KIT / "text" / "automated.json").read_text(encoding="utf-8"))


@cache
def schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _b64(name: str) -> str:
    return base64.b64encode((KIT / name).read_bytes()).decode()


# ------------------------------------------------------------------ escaping (08 1.2, 1.5)
def esc(s: Any) -> str:
    return _html.escape(str(s), quote=True)


def show_hidden(s: str) -> str:
    return HIDDEN_RE.sub(lambda m: f"[U+{ord(m.group()):04X}]", s)


def esc_src(s: str, ctx: BuildContext, kind: str = "span") -> str:
    """Source-derived text: hidden characters as tokens, escaped, never through inl()."""
    body = esc(show_hidden(str(s)))
    if kind == "svg":
        return body
    ctx.uses_mono = True
    return f'<span class="src mono">{body}</span>'


def inl(s: str, ctx: BuildContext) -> str:
    """Model text: escape first, then backtick code spans and bold."""
    out = esc(s)
    if "`" in out:
        ctx.uses_mono = True
    out = re.sub(r"`([^`]+)`", r'<span class="mono">\1</span>', out)
    return re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", out)


def ref_text(r: dict[str, Any]) -> str:
    return f'{r["path"]}:{r["start"]}' + (f'-{r["end"]}' if r["end"] != r["start"] else "")


# ------------------------------------------------------------------ field classes (08 1.5)
def _resolve(node: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in node:
        node = schema()["$defs"][node["$ref"].split("/")[-1]]
    return node


def _valid(node: dict[str, Any], value: Any) -> bool:
    from jsonschema import Draft202012Validator

    wrapped = {"$defs": schema()["$defs"], **node}
    return Draft202012Validator(wrapped).is_valid(value)


def iter_strings(value: Any, node: dict[str, Any] | None = None, path: str = "$"):
    """Yield (path, class, string) for every string in a report, class from `x-text-class`.

    A string without a class that is not a closed enum or const is a schema error (CI text-class).
    """
    node = _resolve(node if node is not None else schema())
    for key in ("oneOf", "anyOf"):
        if key in node:
            branch = next((b for b in node[key] if _valid(b, value)), None)
            if branch is None:
                raise BuildError("schema", f"no {key} branch matches", path)
            yield from iter_strings(value, branch, path)
            return
    if isinstance(value, str):
        cls = node.get("x-text-class")
        if cls is None and "enum" not in node and "const" not in node:
            raise BuildError("schema", "string without x-text-class", path)
        if cls is not None:
            yield path, cls, value
    elif isinstance(value, dict):
        props = node.get("properties", {})
        extra = node.get("additionalProperties")
        for k, v in value.items():
            sub = props.get(k) if k in props else (extra if isinstance(extra, dict) else None)
            if sub is not None:
                yield from iter_strings(v, sub, f"{path}.{k}")
    elif isinstance(value, list):
        prefix = node.get("prefixItems", [])
        for i, v in enumerate(value):
            sub = prefix[i] if i < len(prefix) else node.get("items")
            if isinstance(sub, dict):
                yield from iter_strings(v, sub, f"{path}[{i}]")


# Rules that need submit-time context absent from report.json: T24 binds to absence claims,
# T31 to the manifest word set, T29 is the typed-id rule (assembly writes {{finding}} ids as final
# ids). All three ran at submit (04 11); the build re-runs every other rule (late_gate).
# Canonical definition lives in text_gate.LATE_GATE_SKIP; imported here so callers can use either.
from soken_review.engine.text_gate import LATE_GATE_SKIP

# Kit keys whose fixed text names the company or the audit boundary on purpose (08 1.4: disclaimer,
# authorship box and footer are the AI and scope disclosure). Matches outside these stay errors.
KIT_EXEMPT: dict[str, set[str]] = {"footer_line": {"T15"}, "disclaimer": {"T15"}, "authorship_box": {"P1"},
                                   "reasoning_only": {"P1"}}


def _field_of(path: str) -> str | None:
    for name in ("title", "description", "impact", "recommendation", "attack_steps", "notes"):
        if f".{name}" in path:
            return name
    return None


def gate_kit_text(key: str, text: str) -> list[tuple[str, str]]:
    """04 public scope on one kit text, with the KIT_EXEMPT keys and the company name allowed."""
    from soken_review.engine.text_gate import check_text

    hits = []
    for v in check_text(text, "public"):
        if v.rule_id in KIT_EXEMPT.get(key, set()):
            continue
        if v.rule_id == "T25" and text[v.span[0]:v.span[0] + 9] == "SOKEN LTD":
            continue
        hits.append((v.rule_id, v.match))
    return hits


def malformed_placeholder(text: str) -> str | None:
    """The first placeholder-like token of a model string that `expand()` would not substitute: a
    half form (`{fact:k}`, `{{fact:k}`) or a double-brace form whose body does not parse (04 6.4).
    None when every placeholder is well formed."""
    from soken_review.engine.numbers import parse_placeholder

    for m in PLACEHOLDER_ANY_RE.finditer(text):
        tok = m.group()
        if not (tok.startswith("{{") and tok.endswith("}}")) or parse_placeholder(tok) is None:
            return tok
    return None


def _walk_strings(obj: Any, path: str = "$"):
    """(path, string) for every string of a plain JSON object, schema-free."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}")


def assert_expanded(projected: dict[str, Any]) -> None:
    """The late check after projection: no placeholder form may survive into the HTML. A leftover
    is a projection fault (the string classes above decide who fixes it), never printed."""
    for path, text in _walk_strings(projected):
        m = PLACEHOLDER_ANY_RE.search(text)
        if m:
            raise BuildError("schema", f"placeholder not expanded {m.group()!r}", path)


_PATH_TOKEN_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]")


def apply_publication_rewrites(report: dict[str, Any]) -> list[str]:
    """Rewrite model-class strings for publication in place (contract/rubric/gate_policy.yaml rewrites:
    dashes, arrows, audit words; never inside code spans or placeholders). Text written since the gate
    policy was introduced is already rewritten at write time; this covers older stored text, so the
    PDF prints the rewritten form instead of failing the render. Returns the paths it changed."""
    from soken_review.engine import gate_policy

    changed: list[str] = []
    for path, cls, text in list(iter_strings(report)):
        if cls != "model" or not text:
            continue
        new, applied = gate_policy.rewrite_text(text, _field_of(path))
        if not applied:
            continue
        toks = [m.group(1) if m.group(1) is not None else int(m.group(2)) for m in _PATH_TOKEN_RE.finditer(path[1:])]
        node: Any = report
        for t in toks[:-1]:
            node = node[t]
        node[toks[-1]] = new
        changed.append(path)
    return changed


def check_strings(report: dict[str, Any]) -> None:
    """08 1.5: 04 gate by field class on data, never on HTML. A hit is `late_gate`.

    Model-class text: calls ``check_model_field`` (full model scope) then filters
    ``LATE_GATE_SKIP`` (T24, T29, T31).  Those three rules need submit-time context
    (absence_claims, word_set, manifest ids) that is absent from the assembled
    report.json; they are enforced at write time and at ``review_finalize``'s
    pre-freeze gate.  The render builder is the **only** caller that applies
    ``LATE_GATE_SKIP`` (04 §11.4 render parity).
    """
    from soken_review.engine.text_gate import check_model_field, check_text

    apply_publication_rewrites(report)
    profile = report["meta"]["profile"]
    for path, cls, text in iter_strings(report):
        if cls == "src" or not text:
            continue
        if cls == "model":
            bad = malformed_placeholder(text)
            if bad:
                # A placeholder the projection will not expand is the reviewer's text to fix: the
                # render fails as a late gate (rule L0) and never prints the token.
                raise BuildError("late_gate", f"L0 {bad!r}", path, rule="L0")
            # Blocking rules only (contract/rubric/gate_policy.yaml): advisory wording rules were
            # warnings when the text was written and never fail the render.
            from soken_review.engine import gate_policy

            field = _field_of(path)
            hits = [
                v for v in check_model_field(text, field=field, profile=profile, is_list_item=".ul[" in path)
                if v.rule_id not in LATE_GATE_SKIP and gate_policy.is_blocking(v.code, v.rule_id)
                and not gate_policy.is_exempt(v.code, v.rule_id, field)
            ]
        elif cls == "server":
            hits = check_text(text, "server")
            if path == "$.meta.subject":
                hits += check_text(text, "subject")
            hits = [v for v in hits if not (v.rule_id == "T25" and "SOKEN LTD" in text)]
        else:  # kit
            hits = [type("V", (), {"rule_id": r, "match": m}) for r, m in gate_kit_text(path.rsplit(".", 1)[-1], text)]
        if hits:
            # path and rule travel as structured fields (result.json) so the supervisor classifies the
            # failure on them, never on the truncated free-text detail.
            raise BuildError("late_gate", f"{hits[0].rule_id} {hits[0].match!r}", path, rule=str(hits[0].rule_id))


def validate(report: dict[str, Any]) -> None:
    from jsonschema import Draft202012Validator

    err = next(iter(sorted(Draft202012Validator(schema()).iter_errors(report), key=lambda e: list(e.path))), None)
    if err is not None:
        raise BuildError("schema", err.message[:200], "$." + ".".join(str(p) for p in err.absolute_path))


# ------------------------------------------------------------------ projection (08 2.4, 04 4.1)
_FNAMES = {
    "bps_to_pct": lambda d: d / Decimal(100),
    "wei_to_ether": lambda d: d / Decimal(10) ** 18,
    "seconds_to_hours": lambda d: d / Decimal(3600),
    "seconds_to_days": lambda d: d / Decimal(86400),
}
_CALC_RE = re.compile(r"^(?:(?P<fn>[a-z_]+)\((?P<arg>[^()]+)\)|(?P<a>[^+\-*/]+)(?:(?P<op>[+\-*/])(?P<b>.+))?)\|(?P<p>[0-6])$")


def _operand(s: str, facts: dict[str, Any]) -> tuple[Decimal, list[str]]:
    if s.startswith("fact:"):
        key = s[5:]
        try:
            return Decimal(facts[key]["value"].replace(",", "")), [key]
        except (KeyError, InvalidOperation) as exc:
            raise BuildError("schema", f"calc operand {s} unresolved") from exc
    return Decimal(s), []


def eval_calc(body: str, facts: dict[str, Any]) -> tuple[str, list[str]]:
    """Value of a `{{calc:...}}` placeholder (04 6.4 grammar) and the fact keys it uses."""
    m = _CALC_RE.match(body)
    if not m:
        raise BuildError("schema", f"calc grammar {body!r}")
    if m["fn"]:
        if m["fn"] not in _FNAMES:
            raise BuildError("schema", f"calc function {m['fn']} not supported by the kit")
        d, keys = _operand(m["arg"], facts)
        val = _FNAMES[m["fn"]](d)
    else:
        a, keys = _operand(m["a"], facts)
        val = a
        if m["op"]:
            b, kb = _operand(m["b"], facts)
            keys += kb
            if m["op"] == "/" and b == 0:
                raise BuildError("schema", "calc division by zero")
            val = {"+": a + b, "-": a - b, "*": a * b, "/": a / b if b else a}[m["op"]]
    q = Decimal(1).scaleb(-int(m["p"]))
    return f"{val.quantize(q, rounding=ROUND_HALF_EVEN):,}", keys


def expand(text: str, facts: dict[str, Any]) -> str:
    """Placeholders expanded to their server values. Every profile prints every value as is (CEO
    2026-10-28: findings are never hidden, amount_at_risk facts included)."""
    seen: set[str] = set()

    def sub(m: re.Match) -> str:
        kind, body = m.group(1), m.group(2)
        if kind == "fact":
            f = facts.get(body)
            if f is None:
                raise BuildError("schema", f"fact {body} not in facts")
            # chain text prints as a quoted literal; the network and block of chain facts print once per
            # string (several values read at one block share one label)
            value = f'"{f["value"]}"' if f.get("literal") else f["value"]
            out = value + (f" {f['unit']}" if f.get("unit") else "")
            if f.get("at") and f["at"] not in seen:
                seen.add(f["at"])
                out += f" ({f['at']})"
            return out
        if kind == "calc":
            return eval_calc(body, facts)[0]
        raise BuildError("schema", f"unexpanded finding placeholder {body}")

    return PLACEHOLDER_RE.sub(sub, text)


def _project_blocks(blocks: list[dict[str, Any]], exp) -> list[dict[str, Any]]:
    """Model blocks through `expand`: paragraphs, list items and string table cells."""
    out: list[dict[str, Any]] = []
    for b in blocks:
        if "p" in b:
            out.append({**b, "p": exp(b["p"])})
        elif "ul" in b:
            out.append({**b, "ul": [exp(x) for x in b["ul"]]})
        elif "table" in b:
            t = b["table"]
            rows = [[exp(c) if isinstance(c, str) else c for c in row] for row in t.get("rows", [])]
            out.append({**b, "table": {**t, "rows": rows}})
        else:
            out.append(b)
    return out


def project(report: dict[str, Any], profile: str | None = None) -> dict[str, Any]:
    """The only projection (08 2.4): expands placeholders in every model string.

    Every finding prints as is under every profile and requester role (CEO 2026-10-28): title,
    severity, location, description, impact, recommendation, code quotes, amount-at-risk values and
    Figures used rows. The attack step list prints for the owner profile only (`card()`).
    """
    profile = profile or report["meta"]["profile"]
    facts = report["facts"]
    out = copy.deepcopy(report)
    out["meta"]["profile"] = profile

    def prose(s: str) -> str:
        return expand(s, facts)

    for f in out["findings"]:
        f["title"] = prose(f["title"])
        for key in ("description", "impact", "recommendation"):
            if key in f:
                f[key] = _project_blocks(f[key], prose)
        if f.get("attack_steps"):
            f["attack_steps"] = [{**s, "text": prose(s["text"])} for s in f["attack_steps"]]
    roles = out["roles"]
    roles["rows"] = [{**r, "risk_note": prose(r["risk_note"])} if "risk_note" in r else r for r in roles["rows"]]
    roles["notes"] = _project_blocks(roles["notes"], prose)
    if "context" in out:  # context_notes blocks expand like roles notes (same gates, same projection)
        out["context"]["notes"] = _project_blocks(out["context"]["notes"], prose)
    cov = out["review_coverage"]
    cov["areas"] = [{**a, "note": prose(a["note"])} if "note" in a else a for a in cov["areas"]]
    out["scope"]["out_of_scope"] = [{**r, "reason": prose(r["reason"])} for r in out["scope"]["out_of_scope"]]
    return out


def counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """03 4.15: Open and Not verified as fixed cards by severity; Fixed cards not counted."""
    return {s: sum(1 for f in findings if f["severity"] == s and f.get("status") != "Fixed") for s in SEVS}


MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
          "November", "December"]


def build_date_text(d: Any) -> str:
    """Schema `date_text`: `10 October 2026`."""
    return f"{d.day} {MONTHS[d.month - 1]} {d.year}"


def out_name(meta: dict[str, Any], profile: str, subject_ascii: str) -> str:
    """08 2.4: server-built ASCII name, `[A-Za-z0-9_-]`, max 80 with the extension."""
    if profile == "owner":
        stem = re.sub(r"[^A-Za-z0-9]+", "_", subject_ascii).strip("_")[:36] or "Subject"
        iso = meta["date_iso"]
        return f"Soken_{stem}_Automated_Review_{iso}.pdf"
    return f"Automated_Review_{meta['report_id_short']}.pdf"


# ------------------------------------------------------------------ cells and tables
def chip(sev: str) -> str:
    c = SEVCOL[sev]
    return f'<span class="sev" style="color:{c}"><i style="background:{c}"></i>{esc(sev)}</span>'


def ev_chip(level: str, ctx: BuildContext) -> str:
    return f'<span class="ev">{esc(ctx.texts["evidence_chips"][level])}</span>'


def status_chip(status: str, ctx: BuildContext) -> str:
    """Comparison status chip, kit chip style (`.sev`) with the STATUS_COL colour and kit label."""
    c = STATUS_COL[status]
    return f'<span class="sev st-{esc(status)}" style="color:{c}"><i style="background:{c}"></i>{esc(ctx.texts["context"]["status_chips"][status])}</span>'


def addr_html(a: str, ctx: BuildContext, short: bool = False, addr_url: str | None = None) -> str:
    lab = a[:8] + "..." + a[-6:] if short and len(a) > 20 else a
    if addr_url:
        href = esc(addr_url.replace("{a}", a))
        ctx.uses_mono = True
        return f'<a class="mono lnk src" href="{href}">{esc(show_hidden(lab))}</a>'
    return esc_src(lab, ctx)


def cell(v: Any, cls: str, ctx: BuildContext, meta: dict[str, Any]) -> str:
    if isinstance(v, bool):
        return esc("Yes" if v else "No")
    if isinstance(v, int):
        return f"{v:,}"
    if isinstance(v, dict):
        if "addr" in v:
            return addr_html(v["addr"], ctx, addr_url=meta.get("addr_url"))
        if "sev" in v:
            return chip(v["sev"])
        if "code" in v:
            return esc_src(ref_text(v["code"]), ctx)
        if "src" in v:
            return esc_src(v["src"], ctx)
        if "fact" in v:
            return esc(v["value"] + (f" {v['unit']}" if v.get("unit") else ""))
        raise BuildError("schema", f"unknown cell {sorted(v)}")
    return inl(v, ctx) if cls == "model" else esc(v)


def row_lines(row_html: str) -> int:
    """Estimated text lines of one `<tr>`: the tallest cell, counting `<br>` and wrapped text."""
    lines = 1
    for c in re.split(r"<td[^>]*>", row_html)[1:]:
        text = _TAG_RE.sub("", c)
        lines = max(lines, c.count("<br>") + 1, math.ceil(len(text) / KEEP_CHARS_PER_LINE))
    return lines


def short_table(rows_html: str) -> bool:
    """True when a table body is short enough to be kept on one page (see MAX_KEEP_ROWS)."""
    rows = _ROW_RE.findall(rows_html)
    return len(rows) <= MAX_KEEP_ROWS and sum(row_lines(r) for r in rows) <= MAX_KEEP_LINES


def tbl(head_cells: str, rows_html: str, *, name: str, keep: bool | None = None, cls: str = "") -> str:
    """One kit table: `<thead>` (repeated on every continuation page by the paged.js handler in
    `build()`), `<tbody>`, `data-block` naming the block in render failure details (structure only,
    never report text), and `keep` (break-inside:avoid) when the table is short enough to fit a page."""
    k = short_table(rows_html) if keep is None else keep
    classes = " ".join(c for c in (cls, "keep" if k else "") if c)
    attrs = (f' class="{classes}"' if classes else "") + f' data-block="{name}"'
    return f"<table{attrs}><thead><tr>{head_cells}</tr></thead><tbody>{rows_html}</tbody></table>"


def titled(heading_html: str, table_html: str) -> str:
    """Heading plus table: one keep block when the table is short (the heading is never left alone at
    a page bottom); a long table follows its heading (`h3{break-after:avoid}`, `h3 + *{break-before:
    avoid}`) and breaks between its rows."""
    if 'class="keep' in table_html.split(">", 1)[0]:
        return f'<div class="keep">{heading_html}{table_html}</div>'
    return f"{heading_html}{table_html}"


def section(key: str, inner: str) -> str:
    """`<section data-section=key>`: the key names the section in render failure details."""
    return f'<section data-section="{key}">{inner}</section>'


def table(t: dict[str, Any], cls: str, ctx: BuildContext, meta: dict[str, Any], keep: bool | None = None,
          name: str = "table") -> str:
    nums = set(t.get("num", []))
    widths = t.get("widths", [])
    for w in widths:
        if not WIDTH_RE.match(w):
            raise BuildError("table_attr", f"width {w!r}")
    head = "".join(
        f'<th{" class=num" if i in nums else ""}{f" style=width:{widths[i]}" if i < len(widths) and widths[i] else ""}>'
        f"{inl(h, ctx) if cls == 'model' else esc(h)}</th>" for i, h in enumerate(t["head"]))
    body = "".join(
        "<tr>" + "".join(f'<td{" class=num" if i in nums else ""}>{cell(v, cls, ctx, meta)}</td>'
                         for i, v in enumerate(r)) + "</tr>" for r in t["rows"])
    return tbl(head, body, name=name, keep=keep)


def blocks(items: list[dict[str, Any]], ctx: BuildContext, meta: dict[str, Any]) -> str:
    out = ""
    for b in items:
        if "p" in b:
            out += f"<p>{inl(b['p'], ctx)}</p>"
        elif "ul" in b:
            out += "<ul>" + "".join(f"<li>{inl(x, ctx)}</li>" for x in b["ul"]) + "</ul>"
        elif "table" in b:
            out += table(b["table"], "model", ctx, meta)
        else:
            raise BuildError("schema", f"unknown block {sorted(b)}")
    return out


def server_blocks(items: list[dict[str, Any]], ctx: BuildContext, meta: dict[str, Any]) -> str:
    return "".join(f"<p>{esc(b['p'])}</p>" if "p" in b else table(b["table"], "server", ctx, meta) for b in items)


# ------------------------------------------------------------------ charts (kit, with caps)
def nice_max(v: float) -> float:
    if v <= 0:
        return 1
    e = 10 ** math.floor(math.log10(v))
    for k in (1, 2, 2.5, 5, 10):
        if k * e >= v:
            return k * e
    return 10 * e


def bar_path(x: float, y: float, w: float, h: float) -> str:
    if w <= 0:
        return ""
    r = min(4, w, h / 2)
    return (f"M{x:.1f},{y:.1f}h{w - r:.1f}a{r},{r} 0 0 1 {r},{r}v{h - 2 * r:.1f}"
            f"a{r},{r} 0 0 1 -{r},{r}h-{w - r:.1f}z")


def legend(names: list[str], colors: list[str], x: float, y: float) -> str:
    out, cx = "", x
    for n, c in zip(names, colors, strict=True):
        out += (f'<rect x="{cx}" y="{y - 8}" width="9" height="9" rx="2" fill="{c}"/>'
                f'<text x="{cx + 14}" y="{y}" font-size="10" fill="{INK}">{esc(n)}</text>')
        cx += 14 + len(n) * 5.7 + 18
    return out


def _svg_label(s: str, n: int) -> str:
    s = show_hidden(s)
    return esc(s if len(s) <= n else s[: n - 3] + "...")


def hbar(rows: list[tuple[str, int]], unit: str = "") -> str:
    """Horizontal bars, max 15 rows plus a computed Other row (08 1.1 item 5)."""
    if len(rows) > MAX_FILE_ROWS:
        rows = rows[: MAX_FILE_ROWS - 1] + [("Other", sum(v for _, v in rows[MAX_FILE_ROWS - 1:]))]
    W, LW, RW = 720, 230, 86
    PW, RH, BH, top = W - LW - RW, 16, 12, 6
    vmax = nice_max(max([v for _, v in rows] + [1]))
    H = top + len(rows) * RH + 22
    p = [f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Gilroy,sans-serif">']
    for k in range(5):
        x = LW + PW * k / 4
        p.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{H - 20}" stroke="{GRID}" stroke-width="1"/>')
        p.append(f'<text x="{x:.1f}" y="{H - 6}" font-size="9.5" fill="{MUTE}" text-anchor="middle">'
                 f"{vmax * k / 4:,.0f}{unit}</text>")
    for i, (label, v) in enumerate(rows):
        y = top + i * RH + 2
        p.append(f'<text x="{LW - 10}" y="{y + BH - 1.5}" font-size="10" fill="{INK}" text-anchor="end">'
                 f"{_svg_label(label, 38)}</text>")
        w = PW * v / vmax
        p.append(f'<path d="{bar_path(LW, y, w, BH)}" fill="{SERIES[0]}"/>')
        p.append(f'<text x="{LW + w + 6:.1f}" y="{y + BH - 1.5}" font-size="9.5" fill="{INK}">{v:,}</text>')
    p.append("</svg>")
    return "".join(p)


def stacked(rows: list[tuple[str, dict[str, int]]]) -> str:
    """Findings by component, max 12 rows plus Other; empty data gives no chart (08 1.1 item 5)."""
    rows = [r for r in rows if sum(r[1].values())]
    if not rows:
        return ""
    if len(rows) > MAX_COMPONENT_ROWS:
        other: dict[str, int] = {}
        for _, seg in rows[MAX_COMPONENT_ROWS - 1:]:
            for s, n in seg.items():
                other[s] = other.get(s, 0) + n
        rows = rows[: MAX_COMPONENT_ROWS - 1] + [("Other", other)]
    W, LW, RW = 720, 200, 60
    PW, RH, BH, top = W - LW - RW, 24, 12, 26
    vmax = max(sum(seg.values()) for _, seg in rows)
    H = top + len(rows) * RH + 22
    present = [s for s in SEVS if any(seg.get(s) for _, seg in rows)]
    p = [f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Gilroy,sans-serif">',
         legend(present, [SEVCOL[s] for s in present], LW, 12)]
    step = max(1, math.ceil(vmax / 10))
    for k in range(0, vmax + 1, step):
        x = LW + PW * k / vmax
        p.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{H - 20}" stroke="{GRID}" stroke-width="1"/>')
        p.append(f'<text x="{x:.1f}" y="{H - 6}" font-size="9.5" fill="{MUTE}" text-anchor="middle">{k}</text>')
    for i, (label, seg) in enumerate(rows):
        y = top + i * RH + 6
        p.append(f'<text x="{LW - 10}" y="{y + BH - 1.5}" font-size="10.5" fill="{INK}" text-anchor="end">'
                 f"{_svg_label(label, 32)}</text>")
        x = LW
        parts = [(s, seg[s]) for s in SEVS if seg.get(s)]
        for k, (s, n) in enumerate(parts):
            w = PW * n / vmax - (2 if k < len(parts) - 1 else 0)
            d = bar_path(x, y, w, BH) if k == len(parts) - 1 else f"M{x:.1f},{y}h{w:.1f}v{BH}h-{w:.1f}z"
            p.append(f'<path d="{d}" fill="{SEVCOL[s]}"/>')
            x += PW * n / vmax
        p.append(f'<text x="{x + 6:.1f}" y="{y + BH - 1.5}" font-size="9.5" fill="{INK}">{sum(seg.values())}</text>')
    p.append("</svg>")
    return "".join(p)


def diagram(a: dict[str, Any]) -> str:
    """Kit grid diagram; every node must sit inside the grid (08 1.2), else `diagram_fit`."""
    W, cols, rows = 720, a["cols"], a["rows"]
    CW, RH, BH = W / cols, a.get("row_height", 92), 44
    H = (rows - 1) * RH + BH + 34
    box: dict[str, tuple[float, float, float, float]] = {}
    for n in a["nodes"]:
        span = n.get("span", 1)
        if not (0 <= n["col"] and n["col"] + span <= cols and 0 <= n["row"] < rows):
            raise BuildError("diagram_fit", f"node {n['id']} outside the grid")
        w = CW * span - 22
        if max(len(n["label"]) * 6.2, len(n.get("sub", "")) * 4.7) > w - 8:
            raise BuildError("diagram_fit", f"label of node {n['id']}")
        box[n["id"]] = ((n["col"] + span / 2) * CW, n["row"] * RH + BH / 2 + 4, w, BH)
    p = [f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Gilroy,sans-serif">',
         ('<defs><marker id="ah" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" '
          f'orient="auto-start-reverse"><path d="M0,0.5L7.5,4L0,7.5z" fill="{MUTE}"/></marker></defs>')]
    for e in a["edges"]:
        if e["a"] not in box or e["b"] not in box:
            raise BuildError("diagram_fit", f"edge {e['a']}-{e['b']} to an unknown node")
        (ax, ay, aw, ah), (bx, by, bw, bh) = box[e["a"]], box[e["b"]]
        ln = math.hypot(bx - ax, by - ay) or 1
        ux, uy = (bx - ax) / ln, (by - ay) / ln

        def edge_t(w: float, h: float, ux: float = ux, uy: float = uy) -> float:
            return min((w / 2) / abs(ux) if ux else 1e9, (h / 2) / abs(uy) if uy else 1e9) + 3

        t1, t2 = edge_t(aw, ah), edge_t(bw, bh)
        x1, y1, x2, y2 = ax + ux * t1, ay + uy * t1, bx - ux * t2, by - uy * t2
        start = ' marker-start="url(#ah)"' if e.get("both") else ""
        p.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{MUTE}" '
                 f'stroke-width="1.2" marker-end="url(#ah)"{start}/>')
        if e.get("label"):
            f = e.get("lpos", 0.5)
            lx, ly = x1 + (x2 - x1) * f, y1 + (y2 - y1) * f
            tw = len(e["label"]) * 5.0 + 8
            if tw * abs(ux) + 14 * abs(uy) > math.hypot(x2 - x1, y2 - y1) - 10:
                raise BuildError("diagram_fit", f"label of edge {e['a']}-{e['b']}")
            p.append(f'<rect x="{lx - tw / 2:.1f}" y="{ly - 7:.1f}" width="{tw:.1f}" height="14" rx="3" fill="{SURF}"/>')
            p.append(f'<text class="src" x="{lx:.1f}" y="{ly + 3.2:.1f}" font-size="9" fill="{MUTE}" '
                     f'text-anchor="middle">{esc(show_hidden(e["label"]))}</text>')
    style = {"scope": f'fill="#132238" stroke="{SERIES[0]}" stroke-width="1.4"',
             "ext": f'fill="{SURF}" stroke="#4a5d7a" stroke-width="1.2" stroke-dasharray="4 3"',
             "actor": f'fill="#17273f" stroke="{MUTE}" stroke-width="1.2"'}
    for n in a["nodes"]:
        cx, cy, w, h = box[n["id"]]
        rx = 22 if n["kind"] == "actor" else 5
        p.append(f'<rect x="{cx - w / 2:.1f}" y="{cy - h / 2:.1f}" width="{w:.1f}" height="{h}" rx="{rx}" '
                 f'{style[n["kind"]]}/>')
        ty = cy + 4 if not n.get("sub") else cy - 2
        p.append(f'<text class="src" x="{cx:.1f}" y="{ty:.1f}" font-size="11" font-weight="700" fill="#fff" '
                 f'text-anchor="middle">{esc(show_hidden(n["label"]))}</text>')
        if n.get("sub"):
            p.append(f'<text x="{cx:.1f}" y="{cy + 12:.1f}" font-size="8.8" fill="{MUTE}" text-anchor="middle">'
                     f'{esc(n["sub"])}</text>')
    lx, ly = 4, H - 8
    for lab, kind in (("In scope", "scope"), ("Third party", "ext"), ("Actor", "actor")):
        p.append(f'<rect x="{lx}" y="{ly - 9}" width="18" height="10" rx="{5 if kind == "actor" else 2}" {style[kind]}/>')
        p.append(f'<text x="{lx + 24}" y="{ly}" font-size="9.5" fill="{INK}">{lab}</text>')
        lx += 24 + len(lab) * 5.6 + 20
    p.append("</svg>")
    return "".join(p)


def figure(title: str, svg: str, ctx: BuildContext) -> str:
    if not svg:
        return ""
    ctx.fig_n += 1
    return f'<figure class="fig"><div class="figtitle">Figure {ctx.fig_n}. {esc(title)}</div>{svg}</figure>'


# ------------------------------------------------------------------ sections
def h2(key: str, ctx: BuildContext) -> str:
    ctx.sec_n += 1
    ctx.sec_numbers[key] = ctx.sec_n
    return f'<h2><span class="snum grad">{ctx.sec_n:02d}</span>{esc(ctx.texts["section_titles"][key])}</h2>'


def code_block(cb: dict[str, Any], ctx: BuildContext) -> str:
    ctx.uses_mono = True
    ref = cb["code"]["ref"]
    lines = "".join(f'<span class="cl"><span class="ln">{n}</span>{esc(show_hidden(t))}</span>'
                    for n, t in cb["code"]["lines"])
    keep = " keep" if len(cb["code"]["lines"]) <= 15 else ""
    return (f'<div class="codegrp{keep}"><div class="codehead src mono">{esc(show_hidden(ref_text(ref)))}</div>'
            f'<pre class="code src{keep}">{lines}</pre></div>')


def figures_table(figs: list[dict[str, Any]], ctx: BuildContext, meta: dict[str, Any]) -> str:
    if not figs:
        return ""
    rows = []
    for g in figs:
        srcs = "<br>".join(
            esc_src(ref_text(op["source"]["line"]), ctx) if "line" in op["source"]
            else esc(f'{op["source"]["fact"]}, {op["source"]["method"]} at {op["source"]["block_or_slot"]:,}')
            for op in g["operands"])
        rows.append(f"<tr><td>{esc(g['figure'])}</td><td>{esc(g.get('expression', ''))}</td><td>{srcs}</td></tr>")
    return (f'<div class="fl">{esc(ctx.texts["figures_title"])}</div>'
            + tbl('<th style="width:24%">Figure</th><th style="width:30%">Expression</th><th>Sources</th>',
                  "".join(rows), name="figures"))


def fork_test_block(ft: dict[str, Any], ctx: BuildContext) -> str:
    """The fork verification line of a card (review_verify_on_fork) and, for the owner profile only,
    the test source as code (the same visibility rule as attack steps)."""
    t, lab = ctx.texts, ctx.texts["labels"]
    key = "fork_verified_line" if ft.get("kind") == "verified" else "fork_exercised_line"
    head, _, _ = t[key].partition("{tests}")
    line = esc(head.format(network=ft["network"], block=f'{int(ft["block"]):,}'))
    names = ", ".join(esc_src(n, ctx) for n in ft["tests"])
    out = f'<div class="fl">{esc(lab["fork_test"])}</div><p>{line}{names}</p>'
    if ctx.profile == "owner" and ft.get("source"):
        ctx.uses_mono = True
        lines = "".join(f'<span class="cl"><span class="ln">{n}</span>{esc(show_hidden(x))}</span>'
                        for n, x in enumerate(ft["source"].splitlines()[:400], 1))
        out += (f'<div class="codegrp"><div class="codehead src mono">{esc(show_hidden(ft["test_path"]))}</div>'
                f'<pre class="code src">{lines}</pre></div>')
    elif ft.get("source"):
        out += f'<p class="nofind">{esc(t["fork_test_owner_only"])}</p>'
    return out


def card(f: dict[str, Any], ctx: BuildContext, meta: dict[str, Any], has_status: bool) -> str:
    t, lab = ctx.texts, ctx.texts["labels"]
    chips = f'<span class="chips">{chip(f["severity"])}{ev_chip(f["evidence_level"], ctx)}</span>'
    cols = [["Component", esc_src(f["component"], ctx), "20%"], ["Location", esc_src(ref_text(f["location"]), ctx), ""],
            ["Category", esc(f["category"]), "22%"]]
    if has_status:
        cols.append(["Status", esc(f.get("status", "")), "14%"])
    meta_row = tbl("".join(f'<th{f" style=width:{c[2]}" if c[2] else ""}>{c[0]}</th>' for c in cols),
                   "<tr>" + "".join(f"<td>{c[1]}</td>" for c in cols) + "</tr>", name="finding_meta", keep=True)
    head = f'<div class="fh"><span class="fid">{esc(f["id"])} {inl(f["title"], ctx)}</span>{chips}</div>'
    body = ""
    if f.get("calibration"):
        # The matrix outcome beside the reviewer's severity (thin server, 2026-10-31); server text.
        cal = f["calibration"]
        body += f'<p class="nofind">{esc(lab["calibration"])}: {esc(cal["severity"])} ({esc(cal["rule"])})</p>'
    fixed = f.get("status") == "Fixed"
    if not fixed:
        body += f'<div class="fl">{esc(lab["description"])}</div>{blocks(f.get("description", []), ctx, meta)}'
        body += f'<div class="fl">{esc(lab["impact"])}</div>{blocks(f.get("impact", []), ctx, meta)}'
        # The step list prints for the owner profile only (security review 2026-10-28, pending the CEO's
        # call): public copies keep title, location, quotes, mechanism and impact, and name the sequence.
        if f.get("attack_steps") and ctx.profile == "owner":
            body += f'<div class="fl">{esc(lab["attack_steps"])}</div><ol>' + "".join(
                f'<li>{inl(s["text"], ctx)} {esc_src(ref_text(s["ref"]), ctx)}</li>' for s in f["attack_steps"]) + "</ol>"
        elif f.get("attack_steps"):
            body += f'<div class="fl">{esc(lab["attack_steps"])}</div><p class="nofind">{esc(t["attack_steps_owner_only"])}</p>'
        body += f'<div class="fl">{esc(lab["recommendation"])}</div>{blocks(f.get("recommendation", []), ctx, meta)}'
    ev = f["evidence"]
    body += f'<div class="fl">{esc(lab["evidence"])}</div>'
    if fixed:
        body += f'<p class="nofind">{esc(t["carried_lines"]["fixed"])}</p>'
    if ev.get("compact") or (ctx.compact and f["severity"] in ("Low", "Informational")):
        body += f'<p class="nofind">{esc(t["evidence_compact"])}</p>'
    else:
        body += "".join(code_block(cb, ctx) for cb in ev["code"])
    if ev.get("further"):
        body += (f'<p><b>{esc(t["evidence_further"])}</b>: '
                 + ", ".join(esc_src(ref_text(r), ctx) for r in ev["further"]) + "</p>")
    body += figures_table(ev.get("figures", []), ctx, meta)
    body += f'<div class="fl">{esc(lab["severity_basis"])}</div>' + table(ev["basis"], "server", ctx, meta, name="basis")
    if ev.get("challenge"):
        body += f'<div class="fl">{esc(lab["challenge"])}</div>' + table(ev["challenge"], "server", ctx, meta, name="challenge")
    if ev.get("lead") and f["evidence_level"] in ("analyzer_and_reasoning", "test_verified"):
        body += "<p>" + esc(lab["analyzer_lead"].format(analyzer=ev["lead"]["analyzer"], rule_id="")).rstrip() + " " \
            + esc_src(ev["lead"]["rule_id"], ctx) + "</p>"
    if ev.get("fork_test"):
        body += fork_test_block(ev["fork_test"], ctx)
    if f.get("documented_intent"):
        line = t["documented_intent_line"].split("{path_lines}")[0]
        body += f"<p>{esc(line)}{esc_src(ref_text(f['documented_intent']), ctx)}</p>"
    if f.get("tier_c_line"):
        body += f'<p class="nofind">{esc(t["tier_c_card_line"])}</p>'
    if f.get("no_map_line"):
        body += f'<p class="nofind">{esc(t["no_map_card_line"])}</p>'
    if f.get("status") == "Not verified as fixed":
        body += f'<p class="nofind">{esc(t["carried_lines"]["not_verified"])}</p>'
    return f'<div class="finding" id="{esc(f["id"])}" data-block="finding"><div class="keep">{head}{meta_row}</div>{body}</div>'


def _counts_line(c: dict[str, int]) -> str:
    return ", ".join(f"{c[s]} {s}" for s in SEVS)


def _sub_table(title: str, head: str, rows: list[str], name: str) -> str:
    """h3 plus table (see `titled`): short tables share one keep block with their heading; long
    tables break between rows with the header row repeated."""
    return titled(f"<h3>{esc(title)}</h3>", tbl(head, "".join(rows), name=name))


def context_section(r: dict[str, Any], ctx: BuildContext, meta: dict[str, Any]) -> str:
    """"Project context" (context ingestion spec 7): documents table, declared-vs-observed table with
    status chips, reviewer notes. No documents: one kit line in the `.emptynote` card, never an
    empty table. Document fields are SRC text (escaped, hidden characters shown, never gated)."""
    t = ctx.texts["context"]
    c = r.get("context") or {"documents": [], "comparison": [], "notes": []}
    docs, rows, notes = c["documents"], c["comparison"], c["notes"]
    if not docs:
        body = f'<div class="emptynote"><p class="nofind">{esc(t["empty_line"])}</p></div>'
        return section("context", f'{h2("context", ctx)}{body}{blocks(notes, ctx, meta)}')
    dh = t["documents_head"]
    head = (f'<th style="width:13%">{esc(dh["kind"])}</th><th>{esc(dh["title"])}</th><th style="width:22%">{esc(dh["host"])}</th>'
            f'<th style="width:13%">{esc(dh["retrieved"])}</th><th style="width:12%">{esc(dh["sha256"])}</th>'
            f'<th style="width:12%">{esc(dh["status"])}</th>')
    drows = []
    for d in docs:
        host = esc_src(d["host"], ctx) if d["host"] else f'<span class="nofind">{esc(t["inline_host"])}</span>'
        sha = esc_src(d["sha256_short"], ctx) if d["sha256_short"] else ""
        drows.append(f'<tr><td class="nw">{esc(t["kind_labels"][d["kind"]])}</td><td>{esc_src(d["title"], ctx) if d["title"] else ""}</td>'
                     f'<td>{host}</td><td>{esc(d["retrieved"])}</td><td>{sha}</td><td class="nw">{esc(t["doc_status"][d["status"]])}</td></tr>')
    body = _sub_table(t["documents_title"], head, drows, "context_documents")
    if rows:
        ch = t["comparison_head"]
        head = (f'<th style="width:18%">{esc(ch["claim"])}</th><th>{esc(ch["declared"])}</th><th style="width:15%">{esc(ch["declared_source"])}</th>'
                f'<th>{esc(ch["observed"])}</th><th style="width:15%">{esc(ch["observed_source"])}</th><th style="width:12%">{esc(ch["status"])}</th>')
        crows = []
        for x in rows:
            crows.append(f'<tr><td>{esc(x["claim"])}</td><td>{esc_src(x["declared"], ctx) if x["declared"] else ""}</td>'
                         f'<td>{esc_src(x["declared_source"], ctx) if x["declared_source"] else esc(t["no_source"])}</td>'
                         f'<td>{esc_src(x["observed"], ctx) if x["observed"] else ""}</td>'
                         f'<td>{esc_src(x["observed_source"], ctx) if x["observed_source"] else esc(t["no_source"])}</td>'
                         f'<td>{status_chip(x["status"], ctx)}</td></tr>')
        body += _sub_table(t["comparison_title"], head, crows, "context_comparison")
    else:
        body += f'<p class="nofind">{esc(t["no_comparison_line"])}</p>'
    if notes:
        body += f'<h3>{esc(t["notes_title"])}</h3>' + blocks(notes, ctx, meta)
    return section("context", f'{h2("context", ctx)}{body}')


def render_body(r: dict[str, Any], ctx: BuildContext) -> str:
    t, m = ctx.texts, r["meta"]
    prov = m["provenance"]
    F = r["findings"]
    c = counts(F)
    has_status = any("status" in f for f in F)
    no_high = c["Critical"] == 0 and c["High"] == 0
    tiles = "".join(
        f'<div class="tile"><div class="n" style="color:{SEVCOL[s] if c[s] else "#5b6f8f"}">{c[s]}</div>'
        f'<div class="l"><i style="background:{SEVCOL[s]}"></i>{s}</div></div>' for s in SEVS)
    authbox = f'<div class="authbox">{esc(t["authorship_box"])}</div>'
    banner = (f'<div class="banner">{esc(t["public_review_banner"])}</div>' if m["profile"] == "public_review" else "")
    tierc = (f'<div class="banner tierc">{esc(t["tier_c_warning"].format(address=prov.get("address", ""), noun=m["deployed_noun"]))}</div>'
             if prov["tier"] == "C" else "")
    if prov.get("implementation") and prov.get("proxy_verified") is False:
        # the address is a proxy whose own code is not verified (security review 2026-10-31)
        tierc += (f'<div class="banner tierc" data-block="proxy_unverified">'
                  f'{esc(t["proxy_unverified_warning"].format(address=prov.get("address", "")))}</div>')
    # A failed build is stated on the cover and in the summary in the same sentence (meta.build_failure,
    # server text), not only in the per-card "Checked without a contract map" line.
    if m.get("build_failure"):
        tierc += f'<div class="banner tierc" data-block="build_failure">{esc(m["build_failure"])}</div>'
    nohigh = f'<p class="nofind">{esc(t["no_high_line"])}</p>' if no_high else ""
    files = r["scope"]["files"]
    nsloc = sum(f["nsloc"] for f in files)
    src_parts = []
    if prov.get("repo"):
        src_parts.append(esc_src(prov["repo"], ctx) + (f", {esc_src(prov['commit'], ctx)}" if prov.get("commit") else ""))
    if prov.get("address"):
        addr = addr_html(prov["address"], ctx, addr_url=m.get("addr_url"))
        # a proxy: the address the client named holds the state, the implementation is the code
        src_parts.append(f"Proxy {addr}" if prov.get("implementation") else addr)
    if prov.get("implementation"):
        src_parts.append(f'Implementation {addr_html(prov["implementation"], ctx, addr_url=m.get("addr_url"))}')
    src_parts.append(f'{esc(m["source_id_label"])} {esc_src(prov["code_hash"] if prov.get("code_hash") else prov["source_hash"], ctx)}')
    if prov.get("source_attribution"):
        src_parts.append(esc(prov["source_attribution"]))
    grid = [("Generated by", esc(t["generated_by"])), ("Subject", esc(m["subject"])),
            ("Chain and network", esc(m["network"])), ("Provenance", esc(prov["label"])),
            ("Source", "<br>".join(src_parts)), ("Scope", f"{len(files):,} file{"s" if len(files) != 1 else ""}, {nsloc:,} source lines"),
            ("Findings", esc(_counts_line(c))), ("Date", esc(m["date"]))]
    if prov.get("related"):
        # one line per related contract pinned in the same job (source.related)
        status_text = t["related_status"]
        lines = [f'{esc_src(r["name"], ctx)} {addr_html(r["address"], ctx, short=True, addr_url=m.get("addr_url"))}, '
                 f'{esc(status_text.get(r["status"], r["status"]))}' for r in prov["related"]]
        grid.insert(5, ("Related contracts", "<br>".join(lines)))
    if prov["tier"] == "A":
        ua = prov.get("upgrade_authority")
        if ua is None or ua == "NotChecked":
            grid.append(("Upgrade authority", esc(t["upgrade_authority_not_checked"])))
        else:
            grid.append(("Upgrade authority", addr_html(ua["addr"], ctx, addr_url=m.get("addr_url")) if isinstance(ua, dict) else esc(ua)))
    metagrid = "".join(f'<div class="c"><div class="k">{k}</div><div class="v">{v}</div></div>' for k, v in grid)
    cover = f"""
<div class="cover">
  <div><div class="top"><div class="logo">{WORDMARK()}</div><div class="badge">{esc(t["badge"])}</div></div>
  <hr class="rule" style="margin-top:22px;"></div>
  <div>
    <div class="sub">{esc(m["kind"])}</div>
    <h1>{esc(m["subject"])}</h1>
    <p class="prov {prov["tier"].lower()}">{esc(prov["label"])}</p>
    {tierc}{banner}
    <div class="tiles" style="margin-top:16px;">{tiles}</div>
    {nohigh}
    {authbox}
    <p class="req">{esc(t["requested_by_line"].format(label=m["requested_by"]["label"]))}</p>
  </div>
  <div><div class="metagrid">{metagrid}</div></div>
</div>"""

    # Summary
    kpis = "".join(f'<div class="kpi"><div class="n">{esc(f"{k["value"]:,}" if isinstance(k["value"], int) else k["value"])}</div>'
                   f'<div class="l">{esc(k["label"])}</div></div>' for k in r["summary"]["kpis"])
    # Seven tiles (the `documents` KPI) lay out 4 + 3 instead of leaving one tile alone on a row.
    kpis_cls = "kpis wide" if len(r["summary"]["kpis"]) > 6 else "kpis"
    comp_order: list[str] = []
    for f in F:
        if f["component"] not in comp_order:
            comp_order.append(f["component"])
    comp_rows = sorted(((cname, {s: sum(1 for f in F if f["component"] == cname and f["severity"] == s
                                        and f.get("status") != "Fixed") for s in SEVS}) for cname in comp_order),
                       key=lambda x: -sum(x[1].values()))
    rows = ""
    for f in F:
        title = inl(f["title"], ctx)
        rows += (f'<tr><td class="id">{esc(f["id"])}</td><td>{chip(f["severity"])}</td><td>{ev_chip(f["evidence_level"], ctx)}</td>'
                 f'<td>{esc_src(f["component"], ctx)}</td><td>{title}</td>'
                 + (f'<td>{esc(f.get("status", ""))}</td>' if has_status else "") + "</tr>")
    ftable = (tbl(f'<th style="width:8%">Id</th><th style="width:14%">Severity</th><th style="width:16%">Evidence</th>'
                  f'<th style="width:17%">Component</th><th>Title</th>{"<th style=width:11%>Status</th>" if has_status else ""}',
                  rows, name="findings_summary")
              if F else f'<p class="nofind">{esc(t["empty_findings"])}</p>')
    dl = r["summary"].get("dismissed_leads")
    dl_html = ""
    if dl and no_high and dl["rows"]:
        labels = t["dismissal_reasons"]
        drows = "".join(f'<tr><td>{esc_src(x["detector"], ctx)}</td><td>{chip(x["severity_class"])}</td>'
                        f'<td>{esc_src(ref_text(x["location"]), ctx)}</td><td>{esc(labels[x["reason"]])}</td></tr>'
                        for x in dl["rows"])
        more = (f'<p class="nofind">and {dl["remainder"]:,} more, counted in Review coverage</p>' if dl["remainder"] else "")
        dl_html = titled(f'<h3>{esc(t["dismissed_leads_title"])}</h3>',
                         tbl(f'<th style="width:26%">Detector</th><th style="width:14%">Severity class</th>'
                             f'<th style="width:32%">Location</th><th>{esc(t["dismissed_leads_reason_header"])}</th>',
                             drows, name="dismissed_leads")) + more
    summary = section("summary", f'{h2("summary", ctx)}{authbox}{tierc}{nohigh}<div class="{kpis_cls}">{kpis}</div>'
                      f'{figure("Findings by component", stacked(comp_rows), ctx)}{ftable}{dl_html}')

    # Scope
    head = r["scope"]["head"]
    srows = "".join(f'<tr><td>{esc_src(f["name"], ctx)}</td><td>{esc_src(f["file"], ctx)}</td><td class="num">{f["nsloc"]:,}</td>'
                    f'<td>{addr_html(f["addr"], ctx, short=True, addr_url=m.get("addr_url")) if f.get("addr") else ""}</td></tr>'
                    for f in files)
    scope_tab = tbl(f'<th style="width:19%">{esc(head[0])}</th><th>{esc(head[1])}</th><th class="num" style="width:9%">'
                    f'{esc(head[2])}</th><th style="width:20%">{esc(head[3])}</th>',
                    f'{srows}<tr><td colspan="2"><b>Total</b></td><td class="num"><b>{nsloc:,}</b></td><td></td></tr>',
                    name="scope", cls="scope")
    size_rows = sorted(((f["file"].rsplit("/", 1)[-1], f["nsloc"]) for f in files), key=lambda x: -x[1])
    oos = r["scope"]["out_of_scope"]
    oos_html = ""
    if oos:
        orows = "".join(f'<tr><td>{esc_src(o["path"], ctx)}</td><td>{inl(o["reason"], ctx) if o["by"] == "model" else esc(o["reason"])}</td></tr>'
                        for o in oos)
        oos_html = titled("<h3>Out of scope</h3>", tbl('<th style="width:45%">Item</th><th>Reason</th>', orows, name="out_of_scope"))
    scope = section("scope", f'{h2("scope", ctx)}{scope_tab}'
                    f'{figure("Size of the code in scope, source lines without comments and blank lines", hbar(size_rows), ctx)}'
                    f"{oos_html}")

    # Project context (right after Scope; context ingestion spec 7)
    context = context_section(r, ctx, m)

    # Architecture and roles
    arch = r["architecture"]
    if [n["id"] for n in arch["nodes"]] == ["no_map"]:
        arch_html = f'<div class="emptynote"><p class="nofind">{esc(t["no_map_line"])}</p></div>'
    else:
        arch_html = figure(arch["title"], diagram(arch), ctx)
        roles = r["roles"]
        if roles["rows"]:
            rrows = ""
            for x in roles["rows"]:
                holder = (addr_html(x["holder"]["addr"], ctx, addr_url=m.get("addr_url")) if isinstance(x["holder"], dict)
                          else esc(x["holder"]))
                fns = ", ".join(esc_src(g, ctx) for g in x["gated_functions"][:12])
                rrows += (f'<tr><td>{esc_src(x["role"], ctx)}</td><td>{holder}</td><td>{esc(x["type"])}</td><td>{fns}</td>'
                          f'<td>{inl(x.get("risk_note", ""), ctx)}</td></tr>')
            arch_html += titled("<h3>Privileged roles</h3>",
                                tbl('<th style="width:15%">Role</th><th style="width:20%">Holder</th><th style="width:11%">Type</th>'
                                    '<th>Gated functions</th><th style="width:26%">Risk note</th>', rrows, name="roles"))
        related = roles.get("related_contracts", [])
        if related:
            rrel = ""
            for x in related:
                rrel += (f'<tr><td>{esc(x["label"])}</td><td>{esc(x["address"])}</td>'
                         f'<td>{esc(x["kind"])}</td><td>{esc(x["verified"])}</td>'
                         f'<td>{esc(x.get("note", ""))}</td></tr>')
            arch_html += titled("<h3>Related contracts</h3>",
                                tbl('<th style="width:20%">Label</th><th style="width:16%">Address</th><th style="width:11%">Kind</th>'
                                    '<th style="width:12%">Verified</th><th>Notes</th>', rrel, name="related_contracts"))
        arch_html += blocks(roles["notes"], ctx, m) + figures_table(roles.get("figures", []), ctx, m)
    architecture = section("architecture", f'{h2("architecture", ctx)}{arch_html}')

    # Method. The heading and its method table are wrapped together in one keep-together block: the
    # method table is a short fixed set of steps, so paged.js can always place the pair on a page, and
    # the wrapper stops the heading being left alone at a page bottom when its table would start on the
    # next page (break-after:avoid on the heading alone is honored inconsistently when the next block
    # is a table; the x86 render reproduced the orphan, the Mac render did not). The severity scale is
    # already a keep block of its own.
    mrows = "".join(f'<tr><td>{esc(x["step"])}</td><td>{esc(x["detail"])}</td></tr>' for x in r["method"])
    srows2 = "".join(f'<tr><td>{chip(x["severity"])}</td><td>{esc(x["text"])}</td></tr>' for x in r["severity_scale"])
    method = section("method", f'<div class="keep">{h2("method", ctx)}'
                     + tbl('<th style="width:24%">Step</th><th>Detail</th>', mrows, name="method", keep=True) + "</div>"
                     + '<div class="keep"><h3>Severity scale</h3>'
                     + tbl('<th style="width:21%">Severity</th><th>Meaning</th>', srows2, name="severity_scale", keep=True) + "</div>")

    # Findings
    cards = ""
    for s in SEVS:
        fs = [f for f in F if f["severity"] == s]
        if fs:
            cards += f"<h3>{s}</h3>" + "".join(card(f, ctx, m, has_status) for f in fs)
    findings = section("findings", f'{h2("findings", ctx)}{cards or "<p class=nofind>" + esc(t["empty_findings"]) + "</p>"}')

    verification = ""
    if prov["tier"] in ("A", "C") and r.get("verification"):
        verification = section("verification", f'{h2("verification", ctx)}{server_blocks(r["verification"], ctx, m)}')

    # Review coverage
    cov = r["review_coverage"]
    arows = ""
    for a in cov["areas"]:
        res = ", ".join(a["result"]) if isinstance(a["result"], list) else a["result"]
        ret = a["code_returned"] + (f' ({a["units_returned"]} of {a["units_total"]})' if a["code_returned"] == "Partly" else "")
        note = f'<br><span class="nofind">{inl(a["note"], ctx)}</span>' if a.get("note") else ""
        arows += f'<tr><td>{esc(a["area"])}</td><td>{esc(ret)}</td><td>{esc(res)}{note}</td></tr>'
    # Rule tiers (learning-loop P1): a lower-priority column and one sentence only when a tier moved a lead.
    tiers_cov = cov.get("rule_tiers")
    lp_head = f'<th class="num">{esc(t["lower_priority_header"])}</th>' if tiers_cov else ""
    lrows = "".join(f'<tr><td>{esc(x["analyzer"])}</td><td>{esc(x["version"])}</td><td class="num">{x["leads"]:,}</td>'
                    f'<td class="num">{x["promoted"]:,}</td><td class="num">{x["dismissed"]:,}</td>'
                    + (f'<td class="num">{x.get("lower_priority", 0):,}</td>' if tiers_cov else "") + '</tr>'
                    for x in cov["leads"])
    tiers_note = (f'<p class="nofind">{esc(t["rule_tiers_note"].format(n=f"{tiers_cov["lower_priority"]:,}", version=tiers_cov["version"]))}</p>'
                  if tiers_cov else "")
    cov_html = (tbl('<th style="width:40%">Area</th><th style="width:22%">Code returned</th><th>Result</th>', arows, name="coverage_areas")
                + nohigh + titled("<h3>Analyzer leads</h3>",
                                  tbl('<th>Analyzer</th><th>Version</th><th class="num">Leads</th><th class="num">Promoted</th>'
                                      '<th class="num">Dismissed</th>' + lp_head, lrows, name="analyzer_leads")) + tiers_note)
    if cov["withdrawn"]:
        wrows = "".join(
            f'<tr><td>{esc(w["candidate"])}</td><td>{esc(w["category"])}</td>'
            f'<td>{esc(t["withdrawn_by"][w["withdrawn_by"]].format(item_id=w.get("item_id", "")))}</td>'
            f'<td>{esc_src(ref_text(w["lines"]), ctx)}</td></tr>' for w in cov["withdrawn"])
        cov_html += titled("<h3>Withdrawn candidates</h3>",
                           tbl('<th style="width:12%">Candidate</th><th>Category</th><th>Withdrawn by</th><th>Lines</th>', wrows,
                               name="withdrawn"))
    if cov.get("invariant_walks"):
        iw = t["invariant_walks"]
        vrows = "".join(
            f'<tr><td>{esc(x["walk_id"])} {esc(x["title"])}</td><td>{esc(iw["verdict"][x["verdict"]])}</td>'
            f'<td>{"<br>".join(esc_src(ref_text(ln), ctx) for ln in x["lines"])}</td>'
            f'<td>{esc(x.get("finding", ""))}</td></tr>' for x in cov["invariant_walks"])
        head = iw["head"]
        cov_html += titled(f'<h3>{esc(iw["heading"])}</h3>',
                           tbl(f'<th style="width:38%">{esc(head["walk"])}</th><th style="width:14%">{esc(head["verdict"])}</th>'
                               f'<th>{esc(head["code"])}</th><th style="width:10%">{esc(head["finding"])}</th>', vrows,
                               name="invariant_walks"))
    if cov.get("not_taken"):
        cn = t["coverage_note"]
        nrows = "".join("<li>" + esc(cn["lines"][x["kind"]].format(count=format(x["count"], ","))) + "</li>"
                        for x in cov["not_taken"] if x["kind"] in cn["lines"])
        if nrows:
            cov_html += titled(f'<h3>{esc(cn["heading"])}</h3>', f'<ul class="nofind">{nrows}</ul>')
    if cov["injection_flags"]:
        irows = "".join(f'<tr><td>{esc_src(x["file"], ctx)}</td><td class="num">{x["line"]:,}</td></tr>' for x in cov["injection_flags"])
        cov_html += titled("<h3>Instruction-like comments</h3>",
                           tbl('<th>File</th><th class="num" style="width:12%">Line</th>', irows, name="injection_flags"))
    # No forced page break before the coverage section: the 2026-10-15 break (a workaround for the
    # areas table spilling into overflow columns) left a near-empty page whenever the section before
    # it ended with a short spill (TON job 2026-10-27, empty_page page 15). Tables now break between
    # rows with the header repeated (kit CSS contract), so the section flows like every other one.
    coverage = section("coverage", f'{h2("coverage", ctx)}{cov_html}')

    # Bug 2 fix (2026-10-25): removed class="keep" from disclaimer.  A server-owned section must
    # never overflow a page; keep prevents paged.js from splitting across pages, causing
    # layout_overflow on long disclaimer text (job_8ZSAGKD2S7RA8T0YD9NZWHKBJ6 incident).
    disclaimer = section("disclaimer", f'{h2("disclaimer", ctx)}<p class="disc">{esc(t["disclaimer"].format(date=m["date"]))}</p>'
                         f'<p class="disc">{esc(t["responsible_disclosure"])}</p>')
    return cover + summary + scope + context + architecture + method + findings + verification + coverage + disclaimer


@cache
def _wordmark() -> str:
    return (KIT / "wordmark.svg").read_text(encoding="utf-8")


def WORDMARK() -> str:
    return _wordmark()


def _css(ctx: BuildContext) -> str:
    css = (KIT / "report.css").read_text(encoding="utf-8")
    css = css.replace("__GR__", _b64("fonts/Gilroy-Regular.woff2")).replace("__GB__", _b64("fonts/Gilroy-Bold.woff2"))
    if ctx.uses_mono:
        css += ("@font-face{font-family:'JetBrains Mono';font-weight:400;font-style:normal;"
                f"src:url(data:font/woff2;base64,{_b64('fonts/JetBrainsMono-Regular.woff2')}) format('woff2');}}")
    css += (KIT / "report.automated.css").read_text(encoding="utf-8")
    if ctx.mode == "screen":
        css += (KIT / "screen.css").read_text(encoding="utf-8")
    return css


def build(report: dict[str, Any], out_dir: Path | str, *, mode: str = "print",
          compact_evidence: bool = False) -> BuildResult:
    """08 1.2: validate, check strings on the placeholder form, project, write HTML. Pure."""
    if mode not in ("print", "screen"):
        raise ValueError(mode)
    if report.get("meta", {}).get("report_type") != "automated":
        raise BuildError("schema", "report_type is not automated", "$.meta.report_type")
    validate(report)
    check_strings(report)
    texts = kit_texts()
    projected = project(report)
    assert_expanded(projected)
    ctx = BuildContext(texts=texts, mode=mode, profile=projected["meta"]["profile"], compact=compact_evidence)
    body = render_body(projected, ctx)
    m = projected["meta"]
    subject = m["subject"]
    run_title = f'{m["kind"]} / {subject[:40]}'
    run = ""
    if mode == "print":
        line = texts["footer_public_review"] if ctx.profile == "public_review" else texts["footer_line"]
        ref = texts["labels"]["disclaimer_ref"].format(n=f'{ctx.sec_numbers["disclaimer"]:02d}')
        foot = (f'<div class="runfoot">{esc(line)} {esc(ref)}<br>{esc(texts["labels"]["company_line"])}<br>'
                f'<a href="{SITE}">soken.dev</a></div>')
        run = f'<div class="runlogo">{WORDMARK()}</div><div class="runtitle">{esc(run_title)}</div>{foot}'
    css = _css(ctx)
    # paged.js measures the page while it lays it out, so every kit font must be loaded before it
    # starts: a row measured in a fallback font and reflowed in JetBrains Mono after the fact changes
    # height, and the last row of a page fragment lands in a paged.js overflow column (x86
    # chrome-headless-shell, Solana Scope table 2026-10-27: no console warning, rows measured
    # two lines, rendered three). PagedConfig.before is awaited by the polyfill before preview().
    fonts_wait = ("<script>window.PagedConfig={before:()=>Promise.all(["
                  "document.fonts.load(\"400 10pt 'Gilroy'\"),document.fonts.load(\"700 10pt 'Gilroy'\"),"
                  "document.fonts.load(\"400 8pt 'JetBrains Mono'\")].map((p)=>p.catch(()=>null)))"
                  ".then(()=>document.fonts.ready)};</script>")
    script = (fonts_wait + f"<script>{(KIT / 'pagedjs.js').read_text(encoding='utf-8')}</script>"
              f"<script>{(KIT / 'paged_handlers.js').read_text(encoding='utf-8')}</script>") if mode == "print" else ""
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
           f'<meta http-equiv="Content-Security-Policy" content="{CSP if mode == "print" else CSP_SCREEN}">'
           f'<meta name="viewport" content="width=device-width, initial-scale=1">'
           f"<title>{esc(texts['badge'])}: {esc(subject)}</title><style>{css}</style></head>"
           f'<body class="{mode} {ctx.profile}">{run}{body}{script}</body></html>')
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / ("print.html" if mode == "print" else "screen.html")
    path.write_text(doc, encoding="utf-8")
    return BuildResult(html_path=path, mode=mode, figures=ctx.fig_n, sections=ctx.sec_n, uses_mono=ctx.uses_mono,
                       out_name=m["out_name"], profile=ctx.profile)


def main(argv: list[str] | None = None) -> int:
    """CLI: `python -m soken_review.report.kit.build <report.json> <out_dir> [print|screen] [--compact]`."""
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    compact = "--compact" in args
    args = [a for a in args if a != "--compact"]
    report = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    try:
        res = build(report, args[1], mode=args[2] if len(args) > 2 else "print", compact_evidence=compact)
    except BuildError as err:
        print(json.dumps({"code": err.code, "detail": err.detail, "path": err.path}))
        return 2
    print(json.dumps({"code": "ok", "html": str(res.html_path), "figures": res.figures, "uses_mono": res.uses_mono}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
