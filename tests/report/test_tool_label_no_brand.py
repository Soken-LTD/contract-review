"""Server pass names print without the brand prefix: the method line is server text and gate T25
(`\\bsoken\\b`) failed the whole render on "soken-lifecycle 1: 10 leads" (blind run 2026-10-26)."""

from __future__ import annotations

from soken_review.engine.text_gate import check_text


def test_lifecycle_tool_line_passes_server_gate():
    name = "soken-lifecycle".removeprefix("soken-")
    line = f"{name} 1: 10 leads, slither 0.10.4: 42 leads."
    assert check_text(line, "server") == []
    assert any(v.rule_id == "T25" for v in check_text("soken-lifecycle 1: 10 leads", "server"))


def test_pass_label_strips_prefix_in_tool_and_rule_id():
    from soken_review.report.assemble import pass_label

    assert pass_label("soken-lifecycle@1") == "lifecycle 1"
    assert pass_label("soken-lifecycle:STALE_ON_EMPTY", 80) == "lifecycle:STALE_ON_EMPTY"
    assert pass_label("slither@0.10.4") == "slither 0.10.4"
    for s in ("soken-lifecycle@1", "soken-lifecycle:STALE"):
        assert check_text(pass_label(s, 80), "server") == []
