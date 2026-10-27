"""Pagination contract of the kit (report.css tables, build.tbl/titled/section, paged_handlers.js).

Live cases 2026-10-27: TON job PF27 (tier A) failed `empty_page` on page 15 because the verification
section spilled two short blocks onto a page that the forced page break before the coverage section
then left 10 percent full; Solana job F6FZ failed `layout_overflow` on page 2 in its 32-row Scope
table. The general rules under test: every table is thead + tbody, a long table breaks between rows
with its header row repeated on every continuation page, `keep` (break-inside:avoid) is set only on
blocks short enough to fit a page, no section forces a page break, and the render gate's failure
detail names the blocks around the problem by structure only (never by report text).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from soken_review.report.kit import build as kb
from soken_review.report.kit.build import KIT, MAX_KEEP_ROWS, build, short_table, tbl, titled

from .fixtures import CODE, finding, report

CHROME = os.environ.get("CHROME_BIN")
needs_chrome = pytest.mark.skipif(
    not (CHROME and Path(CHROME).exists() and shutil.which("pdftotext") and shutil.which("node")),
    reason="needs CHROME_BIN, node and poppler (render-e2e runs these with the CI Chrome)")



def long_path(i: int) -> str:
    """A 120-character Rust module path (the live Solana scope rows were 76 characters)."""
    stem = f"programs/vesting/src/instructions/escrow_instructions/nested/deeper/cancel_vesting_escrow_{i:02d}_padding_"
    return stem + "x" * (120 - len(stem) - 3) + ".rs"


def _ref(start: int, path: str = "src/Vault.sol") -> dict:
    return {"path": path, "start": start, "end": start + 2}


def long_report() -> dict:
    """A report that exercises every long table: 60 scope rows with 120-character paths, 40 out of
    scope rows, 30 roles, 10 dismissed leads (schema cap), 60 coverage areas, 20 withdrawn
    candidates, 20 invariant walks of 4 refs each, 30 instruction-like comments, 7 findings with
    40-line quotes and a 60-row model table, and the architecture diagram."""
    r = report(severities=["Medium"] * 3 + ["Low"] * 4, with_map=True)
    fs = []
    for i, sev in enumerate(["Medium"] * 3 + ["Low"] * 4):
        f = finding(i % 3 + 1, sev, code_lines=40, level=["analyzer_and_reasoning", "reasoning_challenged", "reasoning_only"][i % 3])
        f["evidence"]["code"][0]["code"]["lines"] = [[100 + n, CODE[n % len(CODE)] + " // " + "x" * 60] for n in range(40)]
        fs.append(f)
    fs[0]["description"].append({"table": {"head": ["Call", "State written", "Amount"], "num": [2],
                                           "rows": [[f"`path_{k}`", "after the external call", k * 1000] for k in range(60)]}})
    r["findings"] = fs
    files = [{"name": f"unit_{i:02d}_with_a_long_rust_module_name", "file": long_path(i), "nsloc": 10 + i} for i in range(60)]
    assert all(len(f["file"]) == 120 for f in files)
    r["scope"]["files"] = files
    r["scope"]["out_of_scope"] = [{"path": f"tests/fixtures/case_{i:02d}.rs", "reason": "Test file", "by": "server"} for i in range(40)]
    r["roles"]["rows"] = [{"role": f"role_{i}", "holder": "Unknown", "type": "Unknown",
                           "gated_functions": [f"fn_{i}_{k}" for k in range(12)]} for i in range(30)]
    r["summary"]["dismissed_leads"] = {"rows": [{"detector": f"detector-{i}", "severity_class": "Medium", "location": _ref(10 + i),
                                                 "reason": "fp_guarded"} for i in range(10)], "remainder": 27}
    cov = r["review_coverage"]
    cov["areas"] = [{"area_id": f"evm.area_{i}", "area": f"Checklist area {i} with a longer label", "code_returned": "Yes",
                     "result": "No finding submitted"} for i in range(60)]
    cov["withdrawn"] = [{"candidate": f"F-{i:02d}", "category": "Reentrancy", "withdrawn_by": "challenge", "item_id": "R1", "condition": "State written before the call",
                         "lines": _ref(20 + i)} for i in range(1, 21)]
    cov["invariant_walks"] = [{"walk_id": f"IW-EVM-{i}", "title": f"Invariant walk {i} over the vault balance", "verdict": "holds",
                               "lines": [_ref(30 + i + k) for k in range(4)]} for i in range(1, 21)]
    cov["injection_flags"] = [{"file": f"src/module_{i}.sol", "line": 7 + i} for i in range(30)]
    cov["leads"] = [{"analyzer": f"analyzer-{i}", "version": "1.0", "leads": 12, "promoted": 1, "dismissed": 0} for i in range(5)]
    return r


# ---------------------------------------------------------------- markup contract (no browser)

def test_every_table_has_thead_tbody_and_a_block_name(tmp_path):
    html = build(long_report(), tmp_path, mode="print").html_path.read_text(encoding="utf-8").split("<script>")[0]
    tables = re.findall(r"<table[^>]*>", html)
    assert len(tables) >= 20
    assert all(re.search(r'data-block="[a-z_]+"', t) for t in tables)
    assert html.count("<table") == html.count("<thead><tr>") == html.count("</thead><tbody>")
    assert "<tr><th" not in html.replace("<thead><tr><th", "")  # every header row sits in a thead
    for key in ("summary", "scope", "context", "architecture", "method", "findings", "coverage", "disclaimer"):
        assert f'<section data-section="{key}">' in html
    assert 'class="brk"' not in html


def test_long_tables_are_not_kept_and_short_ones_are(tmp_path):
    html = build(long_report(), tmp_path, mode="print").html_path.read_text(encoding="utf-8")
    for name in ("scope", "out_of_scope", "roles", "coverage_areas", "withdrawn", "invariant_walks", "injection_flags"):
        m = re.search(rf'<table([^>]*) data-block="{name}">', html)
        assert m and "keep" not in m.group(1), name
        # a long table's heading is not wrapped in a keep block with it
        before = html[:m.start()]
        h3 = before.rfind("<h3>")
        if h3 >= 0 and "<table" not in before[h3:]:  # the heading right before this table
            assert not before[:h3].endswith('<div class="keep">'), name
    for name in ("method", "severity_scale", "analyzer_leads", "finding_meta", "basis"):
        assert re.search(rf'<table class="keep" data-block="{name}">', html), name
    # the 60-row model table inside the first finding breaks too
    assert re.search(r'<table data-block="table"><thead><tr><th>Call</th>', html)


def test_scope_rows_keep_full_paths_in_a_fixed_layout(tmp_path):
    html = build(long_report(), tmp_path, mode="print").html_path.read_text(encoding="utf-8")
    assert '<table class="scope" data-block="scope">' in html
    assert html.count(long_path(7)) == 1  # the whole path prints; wrapping is the CSS's job
    assert "table.scope{table-layout:fixed;}" in html


def test_keep_estimate_counts_rows_and_wrapped_lines():
    row = "<tr><td>a</td><td>b</td></tr>"
    assert short_table(row * MAX_KEEP_ROWS) and not short_table(row * (MAX_KEEP_ROWS + 1))
    tall = "<tr><td>" + "x" * 600 + "</td></tr>"  # 600 characters wrap to 15 lines in a narrow cell
    assert short_table(tall * 2) and not short_table(tall * 3)
    brs = "<tr><td>" + "<br>".join(["ref"] * 10) + "</td></tr>"
    assert not short_table(brs * 4)
    t = tbl("<th>A</th>", row, name="x")
    assert t.startswith('<table class="keep" data-block="x"><thead><tr><th>A</th></tr></thead><tbody>')
    assert titled("<h3>T</h3>", t).startswith('<div class="keep"><h3>T</h3>')
    assert titled("<h3>T</h3>", tbl("<th>A</th>", row * 20, name="x")) == "<h3>T</h3>" + tbl("<th>A</th>", row * 20, name="x")


def test_print_html_registers_the_table_head_handler(tmp_path):
    html = build(report(1), tmp_path, mode="print").html_path.read_text(encoding="utf-8")
    assert "Paged.registerHandlers(RepeatTableHead)" in html
    screen = build(report(1), tmp_path / "s", mode="screen").html_path.read_text(encoding="utf-8")
    assert "<script" not in screen


# ---------------------------------------------------------------- rendered (CHROME_BIN)

def _render(tmp_path: Path, r: dict, compact: bool = False) -> tuple[dict, Path]:
    from soken_review.report.kit import render_job

    (tmp_path / "in").mkdir(parents=True)
    (tmp_path / "in" / "report.json").write_text(json.dumps(r), encoding="utf-8")
    return render_job.run(tmp_path, compact=compact), tmp_path / "out" / "report.pdf"


def _page_texts(pdf: Path) -> list[str]:
    n = int(re.search(r"^Pages:\s+(\d+)", subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True, check=True).stdout,
                      re.MULTILINE).group(1))
    return [subprocess.run(["pdftotext", "-f", str(p), "-l", str(p), "-layout", str(pdf), "-"], capture_output=True, text=True,
                           check=True).stdout for p in range(1, n + 1)]


@needs_chrome
def test_long_synthetic_report_renders_with_repeated_headers(tmp_path):
    res, pdf = _render(tmp_path, long_report())
    assert res["code"] == "ok", res
    assert not (tmp_path / "out" / "layout.json").exists()
    pages = _page_texts(pdf)
    assert 12 <= len(pages) <= 60
    # the Scope table spans pages and every continuation page starts with its header row
    scope_pages = [i for i, t in enumerate(pages) if "unit_" in t and "padding_xxxx" in t]
    assert len(scope_pages) >= 2
    for i in scope_pages[1:]:
        assert re.search(r"UNIT\s+FILE\s+NSLOC\s+ADDRESS", pages[i]), f"page {i + 1} lacks the repeated header"
    # the coverage areas table (60 rows) spans pages with its header repeated as well
    area_pages = [i for i, t in enumerate(pages) if "Checklist area" in t]
    assert len(area_pages) >= 2 and all(re.search(r"AREA\s+CODE RETURNED\s+RESULT", pages[i]) for i in area_pages)
    # every page is more than a tenth full (the render gate) and nothing overflows (the gate again)
    assert res["pages"] == len(pages)


@needs_chrome
def test_live_ton_and_solana_reports_render(tmp_path):
    """The two 2026-10-27 live failures, assembled from the stand's rows: empty_page (TON, page 15 at
    10 percent) and layout_overflow (Solana, Scope table) must both render."""
    live = Path(__file__).parent / "live"
    for name in ("ton_forton", "solana_fvm8"):
        r = json.loads((live / f"{name}.report.json").read_text(encoding="utf-8"))
        res, pdf = _render(tmp_path / name, r)
        assert res["code"] == "ok", (name, res)
        texts = _page_texts(pdf)
        assert "Review coverage" in "".join(texts)


def _render_html(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    css = "\n".join(ln for ln in (KIT / "report.css").read_text(encoding="utf-8").splitlines() if not ln.startswith("@font-face"))
    html = (f'<!doctype html><html><head><meta charset="utf-8"><style>@page{{size:A4;margin:20mm}}{css}</style></head>'
            f'<body>{body}<script>{(KIT / "pagedjs.js").read_text(encoding="utf-8")}</script>'
            f'<script>{(KIT / "paged_handlers.js").read_text(encoding="utf-8")}</script></body></html>')
    (tmp_path / "out").mkdir(exist_ok=True)
    page = tmp_path / "page.html"
    page.write_text(html, encoding="utf-8")
    return subprocess.run(["node", str(KIT / "render.mjs"), str(tmp_path), str(page), str(tmp_path / "out" / "r.pdf")],
                          capture_output=True, text=True, timeout=110, check=False)


@needs_chrome
def test_empty_page_detail_names_blocks_by_structure_only(tmp_path):
    secret = "CLIENTTEXT7731"
    body = (f'<section data-section="verification"><table data-block="verification"><thead><tr><th>{secret} head</th></tr></thead>'
            f'<tbody><tr><td>{secret} cell</td></tr></tbody></table></section>'
            f'<section data-section="coverage" class="brk"><h2>{secret} heading</h2><p>{secret} body</p></section>'
            f'<section data-section="disclaimer" class="brk"><p>{secret} end</p></section>')
    proc = _render_html(tmp_path, body)
    assert proc.returncode == 12, proc.stderr
    detail = proc.stderr
    assert "empty_page" in detail and '"page":1' in detail
    assert secret not in detail and "head" not in detail and "heading" not in detail
    assert '"sec":"verification"' in detail and '"blk":"verification"' in detail and '"sec":"coverage"' in detail
    # the text record for a developer stays in out/, which the supervisor never reads
    layout = json.loads((tmp_path / "out" / "layout.json").read_text(encoding="utf-8"))
    assert layout["pages"][0]["page"] == 1 and secret in json.dumps(layout["pages"]) and "check" in layout


@needs_chrome
def test_overflow_detail_names_the_innermost_element_without_text(tmp_path):
    secret = "CLIENTTEXT9912"
    body = (f'<section data-section="scope"><table class="scope" data-block="scope"><thead><tr><th>h</th></tr></thead><tbody>'
            f'<tr><td><span class="src mono" style="white-space:nowrap;display:inline-block;width:400mm">{secret}</span></td></tr>'
            f'</tbody></table></section>')
    proc = _render_html(tmp_path, body)
    assert proc.returncode == 11, proc.stderr
    assert "layout_overflow" in proc.stderr and '"excess_px":' in proc.stderr
    assert secret not in proc.stderr
    assert re.search(r'"el":\{"tag":"(SPAN|TD|TH)","cls":"[a-z ]*","sec":"scope","blk":"scope"\}', proc.stderr)
    assert '"in":{"tag":"TABLE","cls":"scope","sec":"scope","blk":"scope"}' in proc.stderr


def test_kit_texts_unchanged_by_pagination_work():
    # the pagination work is markup and CSS only: no kit text was added for it
    assert "pagination" not in json.dumps(kb.kit_texts()).lower()
