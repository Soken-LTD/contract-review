"""Project context section of the automated report (context ingestion spec 7): kit, schema, assembly
builder and the two coupling points to the context-core modules (store, compare)."""

from __future__ import annotations

import re
import sys
import types
from datetime import date
from pathlib import Path

import pytest

from soken_review.report import assemble as asm
from soken_review.report.kit import build as kb
from soken_review.report.kit.build import BuildError, build, iter_strings, project

from .fixtures import (
    CONTEXT_NOTES,
    context_comparison_json,
    context_facts_json,
    context_manifest,
    report,
)


def _html(r, tmp_path, mode="print") -> str:
    return build(r, tmp_path / mode, mode=mode).html_path.read_text(encoding="utf-8")


def _section(html: str, title: str) -> str:
    """Body of the section whose h2 text is `title` (up to the next section)."""
    m = re.search(rf'<section>(<h2><span class="snum grad">\d\d</span>{re.escape(title)}</h2>.*?)</section>', html, re.DOTALL)
    assert m, f"section {title!r} missing"
    return m.group(1)


# ------------------------------------------------------------------ kit
def test_context_section_sits_after_scope_with_both_tables(tmp_path):
    html = _html(report(3), tmp_path)
    titles = re.findall(r'<h2><span class="snum grad">\d\d</span>([^<]+)</h2>', html)
    assert titles[:4] == ["Summary", "Scope", "Project context", "Architecture and privileged roles"]
    sec = _section(html, "Project context")
    t = kb.kit_texts()["context"]
    assert sec.count("<table>") == 2
    assert t["documents_title"] in sec and t["comparison_title"] in sec and t["notes_title"] in sec
    # 4 document rows: three retrieved, one failed; kind labels from the kit; failed row has no digest
    assert sec.count(f'<td class="nw">{t["doc_status"]["ok"]}</td>') == 3
    assert sec.count(f'<td class="nw">{t["doc_status"]["failed"]}</td>') == 1
    for kind in ("whitepaper", "website", "docs", "terms"):  # kind and status cells never break mid-word
        assert f'<td class="nw">{t["kind_labels"][kind]}</td>' in sec
    # both sub-tables share a keep block with their h3 (header never orphaned at a page bottom)
    assert sec.count('<div class="keep"><h3>') == 2
    assert t["empty_line"] not in sec and t["no_comparison_line"] not in sec


def test_context_status_chips_use_kit_chip_style_and_colours(tmp_path):
    sec = _section(_html(report(1), tmp_path), "Project context")
    chips = re.findall(r'<span class="sev st-([a-z_]+)" style="color:(#[0-9a-f]{6})"><i style="background:(#[0-9a-f]{6})"></i>([^<]+)</span>', sec)
    assert sorted(c[0] for c in chips) == ["differs", "differs", "matches", "matches", "not_checkable"]
    labels = kb.kit_texts()["context"]["status_chips"]
    for status, color, bg, label in chips:
        assert color == bg == kb.STATUS_COL[status] and label == labels[status]
    assert kb.STATUS_COL == {"matches": "#199e70", "differs": "#c2922f", "not_checkable": "#8397b4"}


def test_context_document_text_is_src_class_escaped_never_gated(tmp_path):
    r = report(1)
    d = r["context"]["documents"][0]
    d["title"] = "Whitepaper </td><script>x()</script> manual audit" + chr(0x202E)
    d["host"] = "evil.example</td><img src=x onerror=alert(1)>"
    r["context"]["comparison"][0]["declared"] = "<b>declared</b> SOKEN LTD guaranteed"
    html = _html(r, tmp_path)  # must not raise late_gate: document text is SRC
    sec = _section(html, "Project context")
    assert "<script>x()" not in sec and "<img src=x" not in sec and "<b>declared</b>" not in sec
    assert "&lt;script&gt;x()&lt;/script&gt;" in sec and "[U+202E]" in sec and "&lt;img src=x" in sec
    classes = {cls for path, cls, _ in iter_strings(r) if path.startswith("$.context.documents")}
    assert classes == {"src", "server"}  # title/host src; retrieved/sha256 server


def test_context_long_title_and_host_render_in_cells(tmp_path):
    sec = _section(_html(report(1), tmp_path), "Project context")
    assert "very-long-subdomain-for-the-documentation-portal.docs.example-protocol.finance" in sec
    assert "integration notes for the version two deployment" in sec
    assert "td .src.mono{display:inline;overflow-wrap:anywhere" in _html(report(1), tmp_path / "css")


def test_context_notes_expand_context_facts(tmp_path):
    r = report(1)
    p = project(r)
    note = p["context"]["notes"][0]["p"]
    assert "{{fact:" not in note and "1,000,000,000 tokens" in note and "0.3 percent" in note and "25 bps" in note
    sec = _section(_html(r, tmp_path), "Project context")
    assert "1,000,000,000 tokens" in sec and '<span class="mono">renounced</span>' in sec
    # context facts are not amount_at_risk: they print under public_review too
    assert "(withheld)" not in sec


def test_context_empty_state_prints_one_line_in_emptynote(tmp_path):
    r = report(2, context="empty")
    html = _html(r, tmp_path)
    sec = _section(html, "Project context")
    t = kb.kit_texts()["context"]
    assert f'<div class="emptynote"><p class="nofind">{t["empty_line"]}</p></div>' in sec
    assert "<table" not in sec and "<h3>" not in sec
    assert [k["key"] for k in r["summary"]["kpis"]] == ["files", "nsloc", "leads", "promoted", "areas_returned", "deployed_code"]
    assert 'class="kpis"' in html and "kpis wide" not in html


def test_context_documents_without_rows_prints_no_comparison_line(tmp_path):
    r = report(1)
    r["context"]["comparison"] = []
    r["context"]["notes"] = []
    sec = _section(_html(r, tmp_path), "Project context")
    assert kb.kit_texts()["context"]["no_comparison_line"] in sec
    assert sec.count("<table>") == 1 and kb.kit_texts()["context"]["notes_title"] not in sec


def test_documents_kpi_tile_and_wide_grid(tmp_path):
    r = report(1)
    kpis = r["summary"]["kpis"]
    assert kpis[-1] == {"key": "documents", "value": 3, "label": kb.kit_texts()["kpi_labels"]["documents"]}
    html = _html(r, tmp_path)
    assert '<div class="kpis wide">' in html and html.count('<div class="kpi">') == 7
    assert ".kpis.wide{grid-template-columns:repeat(4,1fr);}" in html


def test_context_missing_from_report_renders_empty_state(tmp_path):
    """Reports stored before this section (no `context` key) still render: the key is optional."""
    r = report(1, context="empty")
    del r["context"]
    assert kb.kit_texts()["context"]["empty_line"] in _html(r, tmp_path)


@pytest.mark.parametrize("mutate", [
    lambda c: c.update(extra=1),
    lambda c: c["comparison"][0].update(status="unknown"),
    lambda c: c["documents"][0].update(kind="forum"),
    lambda c: c["documents"][0].update(sha256_short="xyz"),
    lambda c: c["notes"].extend([{"p": "x"}] * 9),
    lambda c: c.pop("notes"),
])
def test_context_schema_is_closed(tmp_path, mutate):
    r = report(1)
    mutate(r["context"])
    with pytest.raises(BuildError) as e:
        build(r, tmp_path)
    assert e.value.code == "schema" and e.value.path.startswith("$.context")


def test_context_kit_texts_pass_the_public_gate():
    t = kb.kit_texts()["context"]
    assert kb.gate_kit_text("empty_line", t["empty_line"]) == []
    assert kb.gate_kit_text("comparison_title", t["comparison_title"]) == []
    assert kb.kit_texts()["section_titles"]["context"] == "Project context"


# ------------------------------------------------------------------ assembly builders
def test_context_documents_rows_from_manifest():
    rows = asm.context_documents(context_manifest()["entries"], date(2026, 10, 23))
    assert [r["kind"] for r in rows] == ["whitepaper", "website", "docs", "terms"]
    wp, site, docs, terms = rows
    assert wp["host"] == "cdn.example-protocol.finance"  # final_url wins over url
    assert wp["retrieved"] == "22 October 2026" and re.fullmatch(r"[0-9a-f]{12}", wp["sha256_short"])
    assert site["host"] == "www.example-protocol.finance" and site["status"] == "ok"
    assert docs["host"].startswith("very-long-subdomain") and len(docs["title"]) <= 200
    assert terms == {"kind": "terms", "title": "", "host": "example-protocol.finance", "retrieved": "22 October 2026",
                     "sha256_short": "", "status": "failed"}


def test_context_documents_tolerate_odd_entries():
    rows = asm.context_documents([{"kind": "forum", "url": None, "title": "a\x00b\tc", "fetched_at": "not a date",
                                   "sha256_raw": "ZZZ", "status": "ok"}] * 20, date(2026, 1, 2))
    assert len(rows) == 12
    assert rows[0] == {"kind": "other", "title": "a b c", "host": "", "retrieved": "2 January 2026", "sha256_short": "", "status": "ok"}


def test_context_rows_shape_and_rejections():
    rows = asm.context_rows(context_comparison_json())
    assert [r["status"] for r in rows] == ["matches", "matches", "differs", "differs", "not_checkable"]
    assert rows[4]["observed"] == "" and rows[4]["observed_source"] == ""
    with pytest.raises(asm.AssemblyError):
        asm.context_rows([{"claim": "x", "status": "maybe"}])
    with pytest.raises(asm.AssemblyError):
        asm.context_rows([{"claim": "", "status": "matches"}])
    assert asm.context_rows([{"claim": "c", "declared": ["a", "b"], "status": "matches"}])[0]["declared"] == "a, b"


def test_context_facts_keep_context_keys_that_pass_the_server_gate():
    facts = context_facts_json() + [
        {"key": "context.docs.admin_claims_3", "value": "owner can pause, SOKEN LTD guarantees nothing", "unit": None, "tags": ["context"]},
        {"key": "context.bad key", "value": "1", "unit": None, "tags": []},
    ]
    out = asm.context_facts(facts)
    assert set(out) == {f["key"] for f in context_facts_json() if f["key"].startswith("context.")}
    assert out["context.whitepaper.total_supply"] == {"value": "1,000,000,000", "unit": "tokens", "amount_at_risk": False}
    assert out["context.whitepaper.decimals"]["value"] == "18" and out["context.docs.fee_pct_1"]["unit"] == "bps"
    assert "onchain.total_supply" not in out


def test_context_notes_accept_list_or_notes_object():
    assert asm.context_notes(None) == []
    assert asm.context_notes(CONTEXT_NOTES) == CONTEXT_NOTES
    assert asm.context_notes({"notes": [{"p": "x"}] * 10}) == [{"p": "x"}] * 8


# ------------------------------------------------------------------ coupling points (spec 4 and 6)
def test_coupling_absent_modules_give_empty_section(tmp_path, monkeypatch):
    """The core branch ships soken_review.context; without it the section is the empty state."""
    for name in ("soken_review.context", "soken_review.context.store", "soken_review.context.compare"):
        monkeypatch.setitem(sys.modules, name, None)  # None in sys.modules makes import raise ImportError
    assert asm.context_store(tmp_path, "job_x") is None
    assert asm.context_compare([], None, {}) == []
    sec = asm.context_section(tmp_path, "job_x", {}, {}, date(2026, 10, 23))
    assert sec == {"documents": [], "comparison": [], "notes": [], "facts": {}}


def _fake_context_modules(monkeypatch, manifest, rows, seen: dict):
    pkg = types.ModuleType("soken_review.context")
    store = types.ModuleType("soken_review.context.store")
    compare = types.ModuleType("soken_review.context.compare")

    class ContextStore:
        def __init__(self, m):
            self._m = m

        @classmethod
        def load(cls, pin_root, job_id):
            seen["load"] = (Path(pin_root), job_id)
            if manifest is None:
                raise FileNotFoundError(job_id)
            return cls(manifest)

        def manifest(self):
            return self._m

    def compare_fn(facts, map_doc, job):
        seen["compare"] = (facts, map_doc, job)
        return rows

    store.ContextStore = ContextStore
    compare.compare = compare_fn
    for name, mod in (("soken_review.context", pkg), ("soken_review.context.store", store), ("soken_review.context.compare", compare)):
        monkeypatch.setitem(sys.modules, name, mod)


def test_coupling_store_and_compare_are_called_with_the_spec_signatures(tmp_path, monkeypatch):
    import json

    seen: dict = {}
    _fake_context_modules(monkeypatch, context_manifest(), context_comparison_json(), seen)
    (tmp_path / "job_1").mkdir()
    (tmp_path / "job_1" / "facts.json").write_text(json.dumps(context_facts_json()))
    job = {"job_id": "job_1", "chain_id": 8453, "address": "0xc2181d975c05c8c724b334bcED0764c0b86B1D53"}
    sec = asm.context_section(tmp_path, "job_1", job, {"context_notes": CONTEXT_NOTES}, date(2026, 10, 23))
    assert seen["load"] == (tmp_path, "job_1")
    facts, map_doc, job_seen = seen["compare"]
    assert [f["key"] for f in facts] == [f["key"] for f in context_facts_json()]  # whole facts.json, not only context.*
    assert map_doc is None and job_seen is job  # no map on disk for this job
    assert len(sec["documents"]) == 4 and len(sec["comparison"]) == 5 and sec["notes"] == CONTEXT_NOTES
    assert "context.whitepaper.total_supply" in sec["facts"]
    # the report built from it validates and renders
    r = report(1)
    r["context"] = {k: v for k, v in sec.items() if k != "facts"}
    build(r, tmp_path / "out")


def test_coupling_store_without_manifest_is_the_empty_state(tmp_path, monkeypatch):
    seen: dict = {}
    _fake_context_modules(monkeypatch, None, [{"claim": "never", "status": "matches"}], seen)
    sec = asm.context_section(tmp_path, "job_2", {}, {}, date(2026, 10, 23))
    assert sec["documents"] == [] and sec["comparison"] == [] and "compare" not in seen
