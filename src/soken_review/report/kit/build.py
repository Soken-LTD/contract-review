"""Report kit, automated type (08 sections 1 and 2). Pure: data in, HTML out, no network.

`build(report, out_dir, mode=, compact_evidence=)` validates `report.automated.schema.json`,
runs `check_strings()` on the placeholder form (08 1.5), applies `project()` (08 2.4, the only
place placeholders expand and withholding happens) and writes `print.html` or `screen.html`.
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
SERIES = ["#3987e5", "#199e70"]  # kit palette, validated on SURF (kit REPORT-STANDARD)
WITHHELD = ("Critical", "High")
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
MAX_COMPONENT_ROWS, MAX_FILE_ROWS = 12, 15


class BuildError(Exception):
    """08 render detail code (contract/errors.yaml `E_RENDER_FAILED` detail), detail, json path."""

    def __init__(self, code: str, detail: str = "", path: str = "") -> None:
        super().__init__(f"{code}: {detail} {path}".strip())
        self.code, self.detail, self.path = code, detail, path


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
LATE_GATE_SKIP = {"T24", "T29", "T31"}
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


def check_strings(report: dict[str, Any]) -> None:
    """08 1.5: 04 gate by field class on data, never on HTML. A hit is `late_gate`."""
    from soken_review.engine.text_gate import CheckContext, check_text

    profile = report["meta"]["profile"]
    for path, cls, text in iter_strings(report):
        if cls == "src" or not text:
            continue
        if cls == "model":
            ctx = CheckContext(field=_field_of(path), profile=profile, is_list_item=".ul[" in path)
            hits = [v for v in check_text(text, "model", ctx) if v.rule_id not in LATE_GATE_SKIP]
        elif cls == "server":
            hits = check_text(text, "server")
            if path == "$.meta.subject":
                hits += check_text(text, "subject")
            hits = [v for v in hits if not (v.rule_id == "T25" and "SOKEN LTD" in text)]
        else:  # kit
            hits = [type("V", (), {"rule_id": r, "match": m}) for r, m in gate_kit_text(path.rsplit(".", 1)[-1], text)]
        if hits:
            raise BuildError("late_gate", f"{hits[0].rule_id} {hits[0].match!r}", path)


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


def _risky(keys: list[str], facts: dict[str, Any]) -> bool:
    return any(facts.get(k, {}).get("amount_at_risk") for k in keys)


def expand(text: str, facts: dict[str, Any], profile: str, withheld_value: str) -> str:
    def sub(m: re.Match) -> str:
        kind, body = m.group(1), m.group(2)
        if kind == "fact":
            f = facts.get(body)
            if f is None:
                raise BuildError("schema", f"fact {body} not in facts")
            if profile == "public_review" and f["amount_at_risk"]:
                return withheld_value
            return f["value"] + (f" {f['unit']}" if f.get("unit") else "")
        if kind == "calc":
            value, keys = eval_calc(body, facts)
            return withheld_value if profile == "public_review" and _risky(keys, facts) else value
        raise BuildError("schema", f"unexpanded finding placeholder {body}")

    return PLACEHOLDER_RE.sub(sub, text)


def _map_strings(obj: Any, fn) -> Any:
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_map_strings(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: _map_strings(v, fn) for k, v in obj.items()}
    return obj


def _figure_risky(fig: dict[str, Any], facts: dict[str, Any]) -> bool:
    return any("fact" in op["source"] and facts.get(op["source"]["fact"], {}).get("amount_at_risk")
               for op in fig["operands"])


def is_withheld(f: dict[str, Any], profile: str) -> bool:
    return profile == "public_review" and f["severity"] in WITHHELD


def project(report: dict[str, Any], profile: str | None = None) -> dict[str, Any]:
    """The only projection (08 2.4): expands placeholders, applies 04 4.1 effects 2 to 4.

    Withheld High and Critical findings keep only server fields (id, severity, category,
    component, evidence level, status) plus `withheld: true`; attack steps are dropped for
    every finding under `public_review`; amount-at-risk facts print `withheld_value` and their
    Figures used rows are dropped.
    """
    texts = kit_texts()
    profile = profile or report["meta"]["profile"]
    facts = report["facts"]
    out = copy.deepcopy(report)
    out["meta"]["profile"] = profile
    wv = texts["withheld_value"]

    def exp(s: str) -> str:
        return expand(s, facts, profile, wv)

    findings = []
    for f in out["findings"]:
        if is_withheld(f, profile):
            keep = {k: f[k] for k in ("id", "severity", "evidence_level", "category", "component", "status")
                    if k in f}
            keep["withheld"] = True
            findings.append(keep)
            continue
        if profile == "public_review":
            f.pop("attack_steps", None)
        for key in ("title", "description", "impact", "recommendation", "attack_steps"):
            if key in f:
                f[key] = _map_strings(f[key], exp)
        figs = f["evidence"].get("figures")
        if figs is not None and profile == "public_review":
            f["evidence"]["figures"] = [g for g in figs if not _figure_risky(g, facts)]
        findings.append(f)
    out["findings"] = findings
    roles = out["roles"]
    roles["rows"] = [{**r, "risk_note": exp(r["risk_note"])} if "risk_note" in r else r for r in roles["rows"]]
    roles["notes"] = _map_strings(roles["notes"], exp)
    if "figures" in roles and profile == "public_review":
        roles["figures"] = [g for g in roles["figures"] if not _figure_risky(g, facts)]
    cov = out["review_coverage"]
    cov["areas"] = [{**a, "note": exp(a["note"])} if "note" in a else a for a in cov["areas"]]
    out["scope"]["out_of_scope"] = [{**r, "reason": exp(r["reason"])} for r in out["scope"]["out_of_scope"]]
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


def table(t: dict[str, Any], cls: str, ctx: BuildContext, meta: dict[str, Any], keep: bool | None = None) -> str:
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
    k = keep if keep is not None else len(t["rows"]) <= 12
    return f'<table{" class=keep" if k else ""}><tr>{head}</tr>{body}</table>'


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
    lines = "".join(f'<span class="ln">{n}</span>{esc(show_hidden(t))}\n' for n, t in cb["code"]["lines"])
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
    return (f'<div class="fl">{esc(ctx.texts["figures_title"])}</div><table class="keep"><tr><th style="width:24%">'
            f'Figure</th><th style="width:30%">Expression</th><th>Sources</th></tr>{"".join(rows)}</table>')


def card(f: dict[str, Any], ctx: BuildContext, meta: dict[str, Any], has_status: bool) -> str:
    t, lab = ctx.texts, ctx.texts["labels"]
    chips = f'<span class="chips">{chip(f["severity"])}{ev_chip(f["evidence_level"], ctx)}</span>'
    if f.get("withheld"):
        cols = [["Component", esc_src(f["component"], ctx)], ["Category", esc(f["category"])]]
        if has_status:
            cols.append(["Status", esc(f.get("status", ""))])
        meta_row = ("<table class=keep><tr>" + "".join(f"<th>{c[0]}</th>" for c in cols) + "</tr><tr>"
                    + "".join(f"<td>{c[1]}</td>" for c in cols) + "</tr></table>")
        return (f'<div class="finding keep withheld"><div class="fh"><span class="fid">{esc(f["id"])} '
                f'{esc(f["category"])}</span>{chips}</div>{meta_row}<p class="nofind">{esc(t["withheld_line"])}</p></div>')
    cols = [["Component", esc_src(f["component"], ctx), "20%"], ["Location", esc_src(ref_text(f["location"]), ctx), ""],
            ["Category", esc(f["category"]), "22%"]]
    if has_status:
        cols.append(["Status", esc(f.get("status", "")), "14%"])
    meta_row = ("<table class=keep><tr>" + "".join(f'<th{f" style=width:{c[2]}" if c[2] else ""}>{c[0]}</th>' for c in cols)
                + "</tr><tr>" + "".join(f"<td>{c[1]}</td>" for c in cols) + "</tr></table>")
    head = f'<div class="fh"><span class="fid">{esc(f["id"])} {inl(f["title"], ctx)}</span>{chips}</div>'
    body = ""
    fixed = f.get("status") == "Fixed"
    if not fixed:
        body += f'<div class="fl">{esc(lab["description"])}</div>{blocks(f.get("description", []), ctx, meta)}'
        body += f'<div class="fl">{esc(lab["impact"])}</div>{blocks(f.get("impact", []), ctx, meta)}'
        if f.get("attack_steps") and ctx.profile == "owner":
            body += f'<div class="fl">{esc(lab["attack_steps"])}</div><ol>' + "".join(
                f'<li>{inl(s["text"], ctx)} {esc_src(ref_text(s["ref"]), ctx)}</li>' for s in f["attack_steps"]) + "</ol>"
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
    body += f'<div class="fl">{esc(lab["severity_basis"])}</div>' + table(ev["basis"], "server", ctx, meta)
    if ev.get("challenge"):
        body += f'<div class="fl">{esc(lab["challenge"])}</div>' + table(ev["challenge"], "server", ctx, meta)
    if f["evidence_level"] == "analyzer_and_reasoning" and ev.get("lead"):
        body += "<p>" + esc(lab["analyzer_lead"].format(analyzer=ev["lead"]["analyzer"], rule_id="")).rstrip() + " " \
            + esc_src(ev["lead"]["rule_id"], ctx) + "</p>"
    if f.get("documented_intent"):
        line = t["documented_intent_line"].split("{path_lines}")[0]
        body += f"<p>{esc(line)}{esc_src(ref_text(f['documented_intent']), ctx)}</p>"
    if f.get("tier_c_line"):
        body += f'<p class="nofind">{esc(t["tier_c_card_line"])}</p>'
    if f.get("no_map_line"):
        body += f'<p class="nofind">{esc(t["no_map_card_line"])}</p>'
    if f.get("status") == "Not verified as fixed":
        body += f'<p class="nofind">{esc(t["carried_lines"]["not_verified"])}</p>'
    return f'<div class="finding"><div class="keep">{head}{meta_row}</div>{body}</div>'


def _counts_line(c: dict[str, int]) -> str:
    return ", ".join(f"{c[s]} {s}" for s in SEVS)


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
    nohigh = f'<p class="nofind">{esc(t["no_high_line"])}</p>' if no_high else ""
    files = r["scope"]["files"]
    nsloc = sum(f["nsloc"] for f in files)
    src_parts = []
    if prov.get("repo"):
        src_parts.append(esc_src(prov["repo"], ctx) + (f", {esc_src(prov['commit'], ctx)}" if prov.get("commit") else ""))
    if prov.get("address"):
        src_parts.append(addr_html(prov["address"], ctx, addr_url=m.get("addr_url")))
    src_parts.append(f'{esc(m["source_id_label"])} {esc_src(prov["code_hash"] if prov.get("code_hash") else prov["source_hash"], ctx)}')
    if prov.get("source_attribution"):
        src_parts.append(esc(prov["source_attribution"]))
    grid = [("Generated by", esc(t["generated_by"])), ("Subject", esc(m["subject"])),
            ("Chain and network", esc(m["network"])), ("Provenance", esc(prov["label"])),
            ("Source", "<br>".join(src_parts)), ("Scope", f"{len(files):,} file{"s" if len(files) != 1 else ""}, {nsloc:,} source lines"),
            ("Findings", esc(_counts_line(c))), ("Date", esc(m["date"]))]
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
    comp_order: list[str] = []
    for f in F:
        if f["component"] not in comp_order:
            comp_order.append(f["component"])
    comp_rows = sorted(((cname, {s: sum(1 for f in F if f["component"] == cname and f["severity"] == s
                                        and f.get("status") != "Fixed") for s in SEVS}) for cname in comp_order),
                       key=lambda x: -sum(x[1].values()))
    rows = ""
    for f in F:
        title = (f'{esc(f["category"])}<br><span class="nofind">{esc(t["withheld_line"])}</span>' if f.get("withheld")
                 else inl(f["title"], ctx))
        rows += (f'<tr><td class="id">{esc(f["id"])}</td><td>{chip(f["severity"])}</td><td>{ev_chip(f["evidence_level"], ctx)}</td>'
                 f'<td>{esc_src(f["component"], ctx)}</td><td>{title}</td>'
                 + (f'<td>{esc(f.get("status", ""))}</td>' if has_status else "") + "</tr>")
    ftable = (f'<table><tr><th style="width:8%">Id</th><th style="width:14%">Severity</th><th style="width:16%">Evidence</th>'
              f'<th style="width:17%">Component</th><th>Title</th>{"<th style=width:11%>Status</th>" if has_status else ""}</tr>{rows}</table>'
              if F else f'<p class="nofind">{esc(t["empty_findings"])}</p>')
    dl = r["summary"].get("dismissed_leads")
    dl_html = ""
    if dl and no_high and dl["rows"]:
        drows = "".join(f'<tr><td>{esc_src(x["detector"], ctx)}</td><td>{chip(x["severity_class"])}</td>'
                        f'<td>{esc_src(ref_text(x["location"]), ctx)}</td></tr>' for x in dl["rows"])
        more = (f'<p class="nofind">and {dl["remainder"]:,} more, counted in Review coverage</p>' if dl["remainder"] else "")
        dl_html = (f'<div class="keep"><h3>{esc(t["dismissed_leads_title"])}</h3><table><tr><th style="width:30%">Detector</th>'
                   f'<th style="width:18%">Severity class</th><th>Location</th></tr>{drows}</table></div>{more}')
    summary = (f'<section>{h2("summary", ctx)}{authbox}{tierc}{nohigh}<div class="kpis">{kpis}</div>'
               f'{figure("Findings by component", stacked(comp_rows), ctx)}{ftable}{dl_html}</section>')

    # Scope
    head = r["scope"]["head"]
    srows = "".join(f'<tr><td>{esc_src(f["name"], ctx)}</td><td>{esc_src(f["file"], ctx)}</td><td class="num">{f["nsloc"]:,}</td>'
                    f'<td>{addr_html(f["addr"], ctx, short=True, addr_url=m.get("addr_url")) if f.get("addr") else ""}</td></tr>'
                    for f in files)
    scope_tab = (f'<table><tr><th style="width:19%">{esc(head[0])}</th><th>{esc(head[1])}</th><th class="num" style="width:9%">'
                 f'{esc(head[2])}</th><th style="width:20%">{esc(head[3])}</th></tr>{srows}'
                 f'<tr><td colspan="2"><b>Total</b></td><td class="num"><b>{nsloc:,}</b></td><td></td></tr></table>')
    size_rows = sorted(((f["file"].rsplit("/", 1)[-1], f["nsloc"]) for f in files), key=lambda x: -x[1])
    oos = r["scope"]["out_of_scope"]
    oos_html = ""
    if oos:
        orows = "".join(f'<tr><td>{esc_src(o["path"], ctx)}</td><td>{inl(o["reason"], ctx) if o["by"] == "model" else esc(o["reason"])}</td></tr>'
                        for o in oos)
        oos_html = f'<div class="keep"><h3>Out of scope</h3><table><tr><th style="width:45%">Item</th><th>Reason</th></tr>{orows}</table></div>'
    scope = (f'<section>{h2("scope", ctx)}{scope_tab}'
             f'{figure("Size of the code in scope, source lines without comments and blank lines", hbar(size_rows), ctx)}'
             f"{oos_html}</section>")

    # Architecture and roles
    arch = r["architecture"]
    if [n["id"] for n in arch["nodes"]] == ["no_map"]:
        arch_html = f'<p class="nofind">{esc(t["no_map_line"])}</p>'
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
            arch_html += (f'<h3>Privileged roles</h3><table><tr><th style="width:15%">Role</th><th style="width:20%">Holder</th>'
                          f'<th style="width:11%">Type</th><th>Gated functions</th><th style="width:26%">Risk note</th></tr>{rrows}</table>')
        arch_html += blocks(roles["notes"], ctx, m) + figures_table(roles.get("figures", []), ctx, m)
    architecture = f'<section>{h2("architecture", ctx)}{arch_html}</section>'

    # Method
    mrows = "".join(f'<tr><td>{esc(x["step"])}</td><td>{esc(x["detail"])}</td></tr>' for x in r["method"])
    srows2 = "".join(f'<tr><td>{chip(x["severity"])}</td><td>{esc(x["text"])}</td></tr>' for x in r["severity_scale"])
    method = (f'<section>{h2("method", ctx)}<table><tr><th style="width:24%">Step</th><th>Detail</th></tr>{mrows}</table>'
              f'<div class="keep"><h3>Severity scale</h3><table><tr><th style="width:21%">Severity</th><th>Meaning</th></tr>'
              f"{srows2}</table></div></section>")

    # Findings
    cards = ""
    for s in SEVS:
        fs = [f for f in F if f["severity"] == s]
        if fs:
            cards += f"<h3>{s}</h3>" + "".join(card(f, ctx, m, has_status) for f in fs)
    findings = f'<section>{h2("findings", ctx)}{cards or "<p class=nofind>" + esc(t["empty_findings"]) + "</p>"}</section>'

    verification = ""
    if prov["tier"] in ("A", "C") and r.get("verification"):
        verification = f'<section>{h2("verification", ctx)}{server_blocks(r["verification"], ctx, m)}</section>'

    # Review coverage
    cov = r["review_coverage"]
    arows = ""
    for a in cov["areas"]:
        res = ", ".join(a["result"]) if isinstance(a["result"], list) else a["result"]
        ret = a["code_returned"] + (f' ({a["units_returned"]} of {a["units_total"]})' if a["code_returned"] == "Partly" else "")
        note = f'<br><span class="nofind">{inl(a["note"], ctx)}</span>' if a.get("note") else ""
        arows += f'<tr><td>{esc(a["area"])}</td><td>{esc(ret)}</td><td>{esc(res)}{note}</td></tr>'
    lrows = "".join(f'<tr><td>{esc(x["analyzer"])}</td><td>{esc(x["version"])}</td><td class="num">{x["leads"]:,}</td>'
                    f'<td class="num">{x["promoted"]:,}</td><td class="num">{x["dismissed"]:,}</td></tr>' for x in cov["leads"])
    cov_html = (f'<table><tr><th style="width:40%">Area</th><th style="width:22%">Code returned</th><th>Result</th></tr>{arows}</table>'
                f'{nohigh}<div class="keep"><h3>Analyzer leads</h3><table><tr><th>Analyzer</th><th>Version</th><th class="num">Leads</th>'
                f'<th class="num">Promoted</th><th class="num">Dismissed</th></tr>{lrows}</table></div>')
    if cov["withdrawn"]:
        wrows = "".join(
            f'<tr><td>{esc(w["candidate"])}</td><td>{esc(w["category"])}</td>'
            f'<td>{esc(t["withdrawn_by"][w["withdrawn_by"]].format(item_id=w.get("item_id", "")))}</td>'
            f'<td>{esc_src(ref_text(w["lines"]), ctx)}</td></tr>' for w in cov["withdrawn"])
        cov_html += (f'<div class="keep"><h3>Withdrawn candidates</h3><table><tr><th style="width:12%">Candidate</th><th>Category</th>'
                     f'<th>Withdrawn by</th><th>Lines</th></tr>{wrows}</table></div>')
    if cov["injection_flags"]:
        irows = "".join(f'<tr><td>{esc_src(x["file"], ctx)}</td><td class="num">{x["line"]:,}</td></tr>' for x in cov["injection_flags"])
        cov_html += (f'<div class="keep"><h3>Instruction-like comments</h3><table><tr><th>File</th><th class="num" style="width:12%">'
                     f"Line</th></tr>{irows}</table></div>")
    coverage = f'<section>{h2("coverage", ctx)}{cov_html}</section>'

    disclaimer = (f'<section class="keep">{h2("disclaimer", ctx)}<p class="disc">{esc(t["disclaimer"].format(date=m["date"]))}</p>'
                  f'<p class="disc">{esc(t["responsible_disclosure"])}</p></section>')
    return cover + summary + scope + architecture + method + findings + verification + coverage + disclaimer


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
    script = f"<script>{(KIT / 'pagedjs.js').read_text(encoding='utf-8')}</script>" if mode == "print" else ""
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
