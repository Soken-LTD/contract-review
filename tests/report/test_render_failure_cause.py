"""Who can fix a render failure (render.failure_cause): a late gate is the reviewer's unless its
structured path resolves to server, kit or src text; everything else is the server's. Fail closed:
no path or an unresolvable path means the reviewer's (security review PR #83)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.report.render import (
    MAX_RENDER_RESETS,
    MAX_TOTAL_REOPENS,
    failure_cause,
    finalize_reopens,
    read_result,
    render_failure_client_caused,
)

REPORT = {"meta": {"subject": "Token"}, "findings": [{"title": "Reentrancy in withdraw"}],
          "method": [{"step": "Static analysis", "detail": "slither 0.11"}]}


def test_late_gate_on_model_text_is_the_reviewers():
    assert failure_cause("late_gate", "$.findings[0].title", REPORT) == {"cause": "model", "path": "$.findings[0].title"}


@pytest.mark.parametrize("path", ["$.method[0].detail", "$.meta.subject", "$.method[0].step"])
def test_late_gate_on_server_or_kit_text_is_the_servers(path):
    assert failure_cause("late_gate", path, REPORT) == {"cause": "server", "path": path}


@pytest.mark.parametrize("path", [None, "", "$.nowhere[9].x", "T25 'soken' $.method[0].detail", "method[0].detail"])
def test_late_gate_without_a_resolvable_structured_path_fails_closed(path):
    """A missing, malformed or unresolvable path never gives a free reset."""
    assert failure_cause("late_gate", path, REPORT)["cause"] == "model"


def test_late_gate_without_the_report_fails_closed():
    assert failure_cause("late_gate", "$.method[0].detail", None) == {"cause": "model", "path": "$.method[0].detail"}


@pytest.mark.parametrize("code", ["internal", "schema", "empty_page", "layout_overflow", "table_attr",
                                  "diagram_fit", "timeout", "page_limit", "fonts", "banner", "size_limit"])
def test_every_other_code_is_the_servers(code):
    assert failure_cause(code, None, REPORT) == {"cause": "server"}


def test_client_caused_unless_recorded_as_the_servers():
    assert render_failure_client_caused({"detail": "late_gate", "cause": "model"}) is True
    assert render_failure_client_caused({"detail": "late_gate"}) is True  # stored without a cause: fail closed
    assert render_failure_client_caused({"detail": "late_gate", "cause": "server"}) is False
    assert render_failure_client_caused({"detail": "internal", "cause": "model"}) is False
    assert render_failure_client_caused(None) is False


def test_finalize_reopens_matches_both_budgets():
    model = {"detail": "late_gate", "cause": "model"}
    assert finalize_reopens({"error_detail": model, "render_resets": MAX_RENDER_RESETS - 1}) is True
    assert finalize_reopens({"error_detail": model, "render_resets": MAX_RENDER_RESETS}) is False
    server = {"detail": "empty_page", "cause": "server"}
    assert finalize_reopens({"error_detail": server, "render_resets": MAX_RENDER_RESETS + 2}) is True
    assert finalize_reopens({"error_detail": server, "render_reopens": MAX_TOTAL_REOPENS}) is False


def _result(tmp_path: Path, **extra) -> dict:
    (tmp_path / "result.json").write_text(json.dumps({"code": "late_gate", "detail": "T25 'soken' $.method[0].detail", **extra}))
    return read_result(tmp_path)


def test_read_result_keeps_a_well_formed_structured_path_and_rule(tmp_path):
    res = _result(tmp_path, path="$.method[0].detail", rule="T25")
    assert res["path"] == "$.method[0].detail" and res["rule"] == "T25"


@pytest.mark.parametrize("bad", [{"path": "method[0]"}, {"path": "$." + "x" * 300}, {"path": 7}, {}, {"rule": "x y"}])
def test_read_result_drops_a_malformed_structured_field(tmp_path, bad):
    res = _result(tmp_path, **bad)
    assert res["path"] in ("", "$.method[0].detail") and res["rule"] in ("", "T25")
    if "path" in bad:
        assert res["path"] == ""
    if "rule" in bad:
        assert res["rule"] == ""
