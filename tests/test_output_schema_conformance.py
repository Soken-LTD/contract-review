"""Structured results must match the tool's outputSchema (Claude Code 2.1.309 drops them otherwise).

The suite-wide guard lives in tests/conftest.py; these tests pin the live failures of 2026-10-31
(review_report links on mcp.soken.dev, review_dismiss_lead rejected[] items, review_challenge
scope.source) and the server's runtime safety net.
"""

from __future__ import annotations

import logging

import pytest

from soken_review import server as srv
from soken_review.contract import bundle_tools
from soken_review.server import SokenServer, output_violations
from soken_review.tools import report

JOB = "job_" + "A" * 26
RID = "abcdefghijklmnopqrstuvwxyz"


@pytest.mark.parametrize("site", ["https://soken.dev", "https://mcp.soken.dev"])
@pytest.mark.parametrize("profile", ["public_review", "private"])
def test_report_links_match_the_schema_on_every_configured_host(monkeypatch, site, profile):
    monkeypatch.setattr(report, "SITE", site)
    body = {"accepted": True, "report_id": RID, **report.links(RID, profile, 1, now=2_000_000_000)}
    assert output_violations("review_report", body) == []
    assert report.require_report_site() == site


@pytest.mark.parametrize("site", ["https://evil.example", "http://soken.dev", "https://mcp.soken.dev/",
                                  "https://staging.soken.dev"])
def test_a_report_site_the_schema_rejects_fails_at_boot(monkeypatch, site):
    monkeypatch.setattr(report, "SITE", site)
    with pytest.raises(RuntimeError, match="SOKEN_REPORT_SITE"):
        report.require_report_site()


def test_dismiss_rejected_item_is_lead_id_plus_errors():
    err = {"code": "E_FINDING_NOT_FOUND", "what": "w", "fix": "f"}
    ok = {"accepted": True, "dismissed": [], "already": [], "high_medium_open": 0,
          "rejected": [{"lead_id": "LEAD-0001", "errors": [err]}]}
    assert output_violations("review_dismiss_lead", ok) == []
    bare = {**ok, "rejected": [err]}
    assert output_violations("review_dismiss_lead", bare)


def test_challenge_scope_source_is_declared():
    scope = {t["name"]: t for t in bundle_tools()}["review_challenge"]["outputSchema"]["properties"]["items"][
        "items"]["properties"]["scope"]
    assert scope["properties"]["source"]["enum"] == ["semantic", "lexical", "not_covered"]


def test_violations_name_paths_not_values():
    secret = "do-not-log-this-value"
    bad = output_violations("review_report", {"accepted": True, "url": f"https://{secret}/r/x"})
    assert bad == ["url: pattern"]
    assert all(secret not in v for v in bad)


@pytest.mark.output_schema_violation_expected
@pytest.mark.anyio
async def test_runtime_net_logs_a_mismatch_and_keeps_the_result(monkeypatch, caplog):
    async def broken(_args):
        return {"accepted": True, "url": "https://example.invalid/r/x"}

    monkeypatch.setitem(srv.HANDLERS, "review_report", broken)
    with caplog.at_level(logging.ERROR, logger="soken_review.server"):
        res = await SokenServer().call_tool("review_report", {"job_id": JOB})
    assert res.structured_content == {"accepted": True, "url": "https://example.invalid/r/x"}
    logged = [r.getMessage() for r in caplog.records if r.name == "soken_review.server"]
    assert any("review_report" in m and "url: pattern" in m for m in logged), logged
    assert all("example.invalid" not in m for m in logged)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_the_suite_guard_wraps_every_control_tool_handler():
    control = {t["name"] for t in bundle_tools() if "outputSchema" in t}
    assert control <= set(srv.HANDLERS)
    assert all(getattr(srv.HANDLERS[n], "_schema_guarded", False) for n in control)
    assert getattr(SokenServer.call_tool, "_schema_guarded", False)
