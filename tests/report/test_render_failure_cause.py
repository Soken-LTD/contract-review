"""Who can fix a render failure (render.failure_cause): only a late gate on model-class text is the
reviewer's; everything else is the server's and must not spend the reviewer's reset budget."""

from __future__ import annotations

import pytest

from soken_review.report.render import (
    MAX_RENDER_RESETS,
    failure_cause,
    finalize_reopens,
    render_failure_client_caused,
)

REPORT = {"meta": {"subject": "Token"}, "findings": [{"title": "Reentrancy in withdraw"}],
          "method": [{"step": "Static analysis", "detail": "slither 0.11"}]}


def test_late_gate_on_model_text_is_the_reviewers():
    assert failure_cause("late_gate", "T27 'pricing' $.findings[0].title", REPORT) == {
        "cause": "model", "path": "$.findings[0].title"}


@pytest.mark.parametrize("path", ["$.method[0].detail", "$.meta.subject", "$.method[0].step"])
def test_late_gate_on_server_or_kit_text_is_the_servers(path):
    out = failure_cause("late_gate", f"T25 'soken' {path}", REPORT)
    assert out == {"cause": "server", "path": path}


def test_late_gate_with_an_unresolvable_path_is_the_servers():
    assert failure_cause("late_gate", "T25 'soken' $.nowhere[9].x", REPORT)["cause"] == "server"
    assert failure_cause("late_gate", "T25 'soken'", REPORT) == {"cause": "server"}
    assert failure_cause("late_gate", "T27 'pricing' $.findings[0].title", None) == {"cause": "server"}


@pytest.mark.parametrize("code", ["internal", "schema", "empty_page", "layout_overflow", "table_attr",
                                  "diagram_fit", "timeout", "page_limit", "fonts", "banner", "size_limit"])
def test_every_other_code_is_the_servers(code):
    assert failure_cause(code, "$.findings[0].title", REPORT) == {"cause": "server"}


def test_client_caused_needs_the_recorded_model_cause():
    assert render_failure_client_caused({"detail": "late_gate", "cause": "model"}) is True
    assert render_failure_client_caused({"detail": "late_gate", "cause": "server"}) is False
    assert render_failure_client_caused({"detail": "late_gate"}) is False  # stored before the cause existed
    assert render_failure_client_caused({"detail": "internal", "cause": "model"}) is False
    assert render_failure_client_caused(None) is False


def test_finalize_reopens_matches_the_reset_budget():
    model = {"detail": "late_gate", "cause": "model"}
    assert finalize_reopens({"error_detail": model, "render_resets": MAX_RENDER_RESETS - 1}) is True
    assert finalize_reopens({"error_detail": model, "render_resets": MAX_RENDER_RESETS}) is False
    server = {"detail": "empty_page", "cause": "server"}
    assert finalize_reopens({"error_detail": server, "render_resets": MAX_RENDER_RESETS + 2}) is True
