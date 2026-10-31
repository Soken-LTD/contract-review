"""Stale client tool lists (blind round 5, 2026-10-31): every MCP arm ran on a list from 2026-10-23/24.

Server levers (version, instructions, tools/list freshness), the per-job notice, and the routes that
make the newest capabilities reachable through fields an old list already has."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp import Client
from mcp.types import CallToolResult, TextContent
from starlette.testclient import TestClient

from soken_review import client_refresh
from soken_review.contract import schema_version
from soken_review.server import SokenServer, _finish, create_app, server_version
from soken_review.tools.context import MemoryJobContext
from soken_review.tools.set_section import route_walk_rows
from soken_review.tools.submit import lift_severity_line

JOB = "job_" + "0" * 25 + "A"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def pin_ctx(tmp_path: Path):
    client_refresh.set_context(MemoryJobContext(tmp_path))
    yield tmp_path
    client_refresh.set_context(None)


# ── what an old list lacks ────────────────────────────────────────────────


def test_missing_names_the_round5_gaps():
    m = client_refresh.missing()
    assert {"review_chain_read", "review_chain_roles", "review_chain_balances"} <= set(m["tools"])
    assert "review_submit_finding.severity_reason" in m["fields"]
    assert "review_set_section.invariant_walks" in m["fields"]
    assert "review_get_guide.topic invariants" in m["values"]
    assert "review_set_section.section invariant_walks" in m["values"]


def test_baseline_is_a_released_list_and_older_than_now():
    base = client_refresh.baseline()
    assert base["rev"] and base["date"] == "2026-10-23" and len(base["tools"]) == 18
    assert "review_chain_read" not in base["tools"]


def test_notice_is_plain_and_actionable():
    for certain in (True, False):
        text = client_refresh.notice(certain)
        assert "—" not in text and "–" not in text
        assert "remove this connector and add it again" in text and "start a new chat" in text
        assert "/mcp" in text and "reload the tool list" in text
        assert "review_chain_read" in text and "severity_reason" in text
        assert schema_version() in text
        assert len(text) < 1300
    assert client_refresh.notice(True).startswith("Your tool list predates the current schema")
    assert client_refresh.notice(False).startswith("Your tool list may be older")


# ── per-job decision ──────────────────────────────────────────────────────


def test_decide_notices_until_a_new_tool_is_called(pin_ctx):
    start = client_refresh.decide("review_start", {}, {"accepted": True, "job_id": JOB}, False)
    assert start and "review_chain_read" in start
    assert client_refresh.decide("review_status", {"job_id": JOB}, {"state": "ready"}, False)
    assert client_refresh.decide("review_status", {"job_id": JOB}, {"state": "ready"}, False) is None   # once
    assert client_refresh.decide("review_read_code", {"job_id": JOB}, "text", False) is None
    sev = {"accepted": False, "errors": [{"code": "E_SEVERITY_CONFIRM"}]}
    assert client_refresh.decide("review_submit_finding", {"job_id": JOB}, sev, False)
    assert client_refresh.decide("review_chain_read", {"job_id": JOB}, {"accepted": True}, False) is None
    assert client_refresh.load_state(JOB)["fresh"] is True
    assert client_refresh.decide("review_finalize", {"job_id": JOB}, {"accepted": True}, False) is None


def test_decide_caps_the_likely_notice(pin_ctx):
    shown = [client_refresh.decide("review_finalize", {"job_id": JOB}, {}, False) for _ in range(8)]
    assert sum(1 for s in shown if s) == 4


def test_certain_signal_always_speaks_and_no_state_means_no_guess():
    client_refresh.set_context(None)
    assert client_refresh.decide("review_start", {}, {"job_id": JOB}, False) is None
    assert client_refresh.decide("review_leads", {"job_id": JOB}, "x", True).startswith("Your tool list predates")


def test_finish_attaches_client_notice_to_structured_and_text(pin_ctx):
    res = CallToolResult(content=[TextContent(type="text", text=json.dumps({"accepted": True, "job_id": JOB}))],
                         structured_content={"accepted": True, "job_id": JOB})
    out = _finish("review_start", {}, res, False)
    assert out.structured_content["client_notice"].startswith("Your tool list may be older")
    assert "schema_hint" not in out.structured_content
    text = _finish("review_leads", {"job_id": JOB}, CallToolResult(content=[TextContent(type="text", text="end")]), True)
    lines = text.content[-1].text.splitlines()
    assert lines[0] == "end" and lines[1].startswith("client_notice ") and lines[2].startswith("schema_hint ")


# ── server levers ─────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_initialize_carries_version_and_instructions():
    async with Client(SokenServer()) as client:
        version, instructions = client.server_info.version, client.instructions
    assert version == server_version() and schema_version() in version
    assert "review_chain_read" in instructions and "/mcp" in instructions


def test_tools_list_is_marked_immediately_stale_on_the_modern_wire():
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {}}
    h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
         "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"}
    with TestClient(create_app(), base_url="http://127.0.0.1:8000") as c:
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}}, headers=h)
    body = r.json()["result"]
    assert body["ttlMs"] == 0 and body["cacheScope"] == "public"
    assert body["_meta"]["io.modelcontextprotocol/serverInfo"]["version"] == server_version()


def test_request_log_line_names_method_tool_and_client():
    from soken_review.http import describe_request

    line = describe_request({"method": "tools/call", "params": {"name": "review_status", "arguments": {"job_id": JOB}}},
                            "2025-11-25", "Claude-User")
    assert line == "mcp_request method=tools/call tool=review_status proto=2025-11-25 ua=Claude-User"
    init = describe_request({"method": "initialize", "params": {"protocolVersion": "2025-06-18",
                                                                "clientInfo": {"name": "claude-ai", "version": "0.1.0"}}},
                            None, None)
    assert "client=claude-ai/0.1.0" in init and "proto=2025-06-18" in init and JOB not in line


# ── capabilities through fields an old list has ───────────────────────────


def _finding(blocks: list[dict]) -> dict:
    return {"job_id": JOB, "draft_key": "f-001", "title": "A long enough title",
            "body": {"description": [{"p": "What happens."}], "impact": blocks, "recommendation": [{"p": "Fix it."}]}}


def test_severity_line_fills_claim_and_reason():
    args, lifted = lift_severity_line(_finding([{"p": "Funds stay locked."},
                                                {"p": "Severity: Medium. Reason: The manager can unfreeze withdrawals, but"
                                                      " only after users wait for a manual action."}]))
    assert args["claimed_severity"] == "Medium"
    assert args["severity_reason"].startswith("The manager can unfreeze")
    assert args["body"]["impact"] == [{"p": "Funds stay locked."}]
    assert lifted["field"] == "body.impact[1]"


def test_severity_line_never_overrides_explicit_arguments_and_keeps_a_lone_block():
    explicit = {**_finding([{"p": "Severity: Low. Reason: twenty characters or more here."}]),
                "claimed_severity": "High", "severity_reason": "explicit reason that is long enough"}
    assert lift_severity_line(explicit) == (explicit, None)
    args, lifted = lift_severity_line(_finding([{"p": "Severity reason: the balance is zero today, so nothing moves."}]))
    assert args["severity_reason"].startswith("the balance is zero") and "claimed_severity" not in args
    assert len(args["body"]["impact"]) == 1 and "stays in the body" in lifted["note"]
    plain = _finding([{"p": "Severity of the issue depends on the oracle."}])
    assert lift_severity_line(plain) == (plain, None)


def test_coverage_rows_with_walk_ids_become_walk_answers():
    args = {"job_id": JOB, "section": "coverage", "coverage": {"rows": [
        {"area_id": "IW-AMM-1", "reason": "nr_holds",
         "note": "Reserves are synced after every swap; refs src/Pool.sol:10-40, src/Pool.sol:60-80."},
        {"area_id": "IW-VS-2", "reason": "nr_violated", "note": "Price snapshot survives burn, draft f-001, src/V.sol:5-9."},
        {"area_id": "AC", "reason": "nr_no_admin", "note": "No admin functions exist in scope."}]}}
    out, ids = route_walk_rows(args)
    assert ids == ["IW-AMM-1", "IW-VS-2"]
    rows = out["invariant_walks"]["rows"]
    assert rows[0] == {"walk_id": "IW-AMM-1", "outcome": "holds", "refs": ["src/Pool.sol:10-40", "src/Pool.sol:60-80"],
                       "note": args["coverage"]["rows"][0]["note"]}
    assert rows[1]["outcome"] == "violated" and rows[1]["draft_key"] == "f-001"
    assert out["coverage"]["rows"] == [args["coverage"]["rows"][2]] and out["section"] == "coverage"
    only, _ = route_walk_rows({"job_id": JOB, "section": "coverage", "coverage": {"rows": args["coverage"]["rows"][:1]}})
    assert "coverage" not in only and only["section"] == "invariant_walks"
    assert route_walk_rows({"job_id": JOB, "section": "coverage", "coverage": {"rows": args["coverage"]["rows"][2:]}})[1] == []


@pytest.mark.anyio
async def test_checklist_with_job_carries_the_walks(monkeypatch):
    from soken_review.tools import guide

    monkeypatch.setattr(guide, "_job_has_walks", lambda job_id: True)
    monkeypatch.setattr(guide, "_job_chain", lambda job_id: "evm")
    text = await guide._get_guide({"topic": "checklist", "job_id": JOB})
    assert "topic checklist" in text and "topic invariants" in text
    plain = await guide._get_guide({"topic": "checklist"})
    assert "topic invariants" not in plain
