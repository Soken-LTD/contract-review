"""Report kit, automated type (08 sections 1, 2, 7)."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from soken_review.report.kit import build as kb
from soken_review.report.kit.build import BuildError, build, check_strings, counts, eval_calc, iter_strings, project

from .fixtures import HIGH_TITLE, finding, report, with_profile


def _html(r, tmp_path, mode="print", **kw) -> str:
    return build(r, tmp_path / mode, mode=mode, **kw).html_path.read_text(encoding="utf-8")


def test_fixture_builds_and_every_string_has_a_class(tmp_path):
    r = report(12)
    classes = {cls for _, cls, _ in iter_strings(r)}
    assert classes <= {"model", "server", "kit", "src"}
    assert "model" in classes and "src" in classes
    assert "Figure 1." in _html(r, tmp_path)


def test_reentrancy_print_screen_print_identical(tmp_path):
    r = report(5)
    a = build(r, tmp_path / "a", mode="print").html_path.read_bytes()
    build(r, tmp_path / "b", mode="screen")
    c = build(r, tmp_path / "c", mode="print").html_path.read_bytes()
    assert a == c
    assert a.count(b"Figure 1.") == 1


def test_public_review_withholds_high_and_critical(tmp_path):
    r = report(severities=["Critical", "High", "Medium", "Low"])
    r["findings"][1]["title"] = HIGH_TITLE
    html = _html(r, tmp_path)
    screen = _html(r, tmp_path, "screen")
    for doc in (html, screen):
        assert HIGH_TITLE not in doc
        assert "Call <span class=\"mono\">withdraw</span> from a contract" not in doc  # attack steps
        assert kb.kit_texts()["withheld_line"] in doc
        assert kb.kit_texts()["public_review_banner"] in doc
    # Medium card is shown, its amount-at-risk fact is withheld and its figure row dropped
    assert "Balance written after the external call in withdraw path 1" in html
    assert "1,250 ETH" not in html and "(withheld)" in html
    assert kb.kit_texts()["footer_public_review"] in html


def test_owner_profile_shows_everything(tmp_path):
    r = with_profile(report(severities=["Critical", "High", "Medium"]), "owner")
    r["findings"][1]["title"] = HIGH_TITLE
    html = _html(r, tmp_path)
    assert HIGH_TITLE in html
    assert "Attack steps" in html
    assert "1,250 ETH" in html
    assert kb.kit_texts()["public_review_banner"] not in html
    assert kb.kit_texts()["footer_line"] in html


def test_project_keeps_only_server_fields_for_withheld():
    p = project(report(severities=["High", "Low"]))
    h = p["findings"][0]
    assert h["withheld"] and set(h) <= {"id", "severity", "evidence_level", "category", "component", "status", "withheld"}


def test_hostile_text_is_escaped(tmp_path):
    r = report(severities=["Medium"])
    f = r["findings"][0]
    f["title"] = "Title with <script>alert(1)</script> and </style><img src=x onerror=alert(2)>"
    f["evidence"]["code"][0]["code"]["lines"][0][1] = "</pre><style>body{display:none}</style>" + chr(0x202E) + "x"
    f["component"] = "Vault<script>"
    try:
        html = _html(r, tmp_path)
    except BuildError as err:  # the late gate may reject the model text; it must never reach HTML raw
        assert err.code == "late_gate"
        return
    assert "<script>alert" not in html and "<img src=x" not in html and "</style><img" not in html
    assert "&lt;script&gt;alert(1)" in html
    assert "&lt;/pre&gt;&lt;style&gt;" in html and "[U+202E]" in html
    assert "Vault&lt;script&gt;" in html


def test_hostile_src_text_never_gated_but_escaped(tmp_path):
    r = report(severities=["Low"])
    r["scope"]["files"][0]["name"] = "Vault</td><script>x()</script>"
    html = _html(r, tmp_path)
    assert "<script>x()" not in html and "Vault&lt;/td&gt;&lt;script&gt;" in html


def test_screen_has_no_script_and_strict_csp(tmp_path):
    html = _html(report(3), tmp_path, "screen")
    assert "<script" not in html
    assert "script-src 'none'" in html
    assert "https://soken.dev/" not in html  # no footer, no promotion on the screen page


def test_print_has_exactly_one_site_link(tmp_path):
    html = _html(report(3), tmp_path)
    assert html.count('href="https://soken.dev/"') == 1
    body = html.split("<script>")[0]
    assert body.count("http://") == body.count("http://www.w3.org/2000/svg")


def test_late_gate_on_model_em_dash(tmp_path):
    r = report(severities=["Low"])
    r["findings"][0]["impact"] = [{"p": "Funds move " + chr(0x2014) + " twice."}]
    with pytest.raises(BuildError) as e:
        build(r, tmp_path)
    assert e.value.code == "late_gate" and "impact" in e.value.path


def test_schema_error(tmp_path):
    r = report(1)
    r["meta"]["profile"] = "restricted"
    with pytest.raises(BuildError) as e:
        build(r, tmp_path)
    assert e.value.code == "schema"


def test_table_attr_rejects_width(tmp_path):
    r = report(severities=["Low"])
    r["findings"][0]["description"].append({"table": {"head": ["a"], "rows": [["b"]], "widths": ["10%;color:red"]}})
    with pytest.raises(BuildError) as e:
        build(r, tmp_path)
    assert e.value.code in ("schema", "table_attr")


def test_diagram_fit(tmp_path):
    r = report(1, with_map=True)
    assert "Units in scope" in _html(r, tmp_path)
    r["architecture"]["nodes"][0]["col"] = 3.5
    with pytest.raises(BuildError) as e:
        build(r, tmp_path / "x")
    assert e.value.code == "diagram_fit"


def test_counts_exclude_fixed():
    fs = [finding(1, "High"), {**finding(1, "Medium"), "status": "Fixed"}, {**finding(1, "Low"), "status": "Not verified as fixed"}]
    assert counts(fs) == {"Critical": 0, "High": 1, "Medium": 0, "Low": 1, "Informational": 0}


def test_eval_calc():
    facts = {"fee.bps": {"value": "250", "unit": None, "amount_at_risk": False}}
    assert eval_calc("bps_to_pct(fact:fee.bps)|2", facts) == ("2.50", ["fee.bps"])
    assert eval_calc("10*4|0", facts) == ("40", [])


def test_no_high_line_and_empty_findings(tmp_path):
    r = report(0, severities=[])
    r["review_coverage"]["areas"][0]["result"] = "No finding submitted"
    html = _html(r, tmp_path)
    assert kb.kit_texts()["no_high_line"] in html and kb.kit_texts()["empty_findings"] in html


def test_no_map_line(tmp_path):
    assert kb.kit_texts()["no_map_line"] in _html(report(1), tmp_path)


def test_kit_texts_pass_public_scope_with_named_exemptions():
    def walk(o, k=""):
        if isinstance(o, dict):
            for a, b in o.items():
                yield from walk(b, a)
        else:
            yield k, o
    bad = [(k, kb.gate_kit_text(k, v)) for k, v in walk(kb.kit_texts()) if kb.gate_kit_text(k, v)]
    assert bad == []
    assert "closing_line" not in kb.kit_texts()


def test_kit_text_exemption_is_narrow():
    assert kb.gate_kit_text("badge", "A manual audit")  # T15 outside the exempt keys
    assert kb.gate_kit_text("disclaimer", "Soken team")  # T25 only for "SOKEN LTD"


def test_sixty_findings_and_long_lines_build(tmp_path):
    r = report(60)
    for f in r["findings"]:
        f["evidence"]["code"][0]["code"]["lines"][0][1] = "x" * 1500
    html = _html(r, tmp_path, compact_evidence=True)
    assert html.count('class="finding') == 60


def test_cli_reports_build_error(tmp_path):
    r = report(1)
    r["meta"]["report_type"] = "manual"
    p = tmp_path / "r.json"
    p.write_text(json.dumps(r))
    assert kb.main([str(p), str(tmp_path / "o")]) == 2


CHROME = os.environ.get("CHROME_BIN")


@pytest.mark.skipif(not (CHROME and Path(CHROME).exists() and shutil.which("pdftotext") and shutil.which("node")),
                    reason="needs CHROME_BIN, node and poppler (render job runs in the soken-render image in CI)")
def test_render_job_pdf_escapes_and_withholds(tmp_path):
    from soken_review.report.kit import render_job

    r = report(severities=["High", "Medium", "Low", "Informational"])
    r["findings"][0]["title"] = HIGH_TITLE
    r["findings"][1]["evidence"]["code"][0]["code"]["lines"][0][1] = "</pre><style>*{}</style><script>x()</script>"
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "report.json").write_text(json.dumps(r))
    res = render_job.run(tmp_path, compact=False)
    assert res["code"] == "ok", res
    text = subprocess.run(["pdftotext", str(tmp_path / "out" / "report.pdf"), "-"], capture_output=True, text=True,
                          check=True).stdout
    assert "drain the vault" not in text
    assert "</pre><style>*{}</style><script>x()</script>" in text.replace("\n", "")
    assert res["fonts"] == ["Gilroy-Bold", "Gilroy-Regular", "JetBrainsMono-Regular"]


def test_deepcopy_not_mutated():
    r = report(3)
    before = copy.deepcopy(r)
    project(r)
    check_strings(r)
    assert r == before
