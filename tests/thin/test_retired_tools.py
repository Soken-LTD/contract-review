"""The five retired tools (thin server design 2026-11-03, section 1): unlisted, still answered, and the answer
validates against every outputSchema any client could have cached (every git revision of tools.v1.json)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from mcp import Client

import soken_review.tools  # noqa: F401
from soken_review.contract import CONTRACT_DIR, bundle_retired_tools, bundle_tools, retired_tool_names
from soken_review.server import SokenServer, output_violations
from soken_review.tools import retired

ASYNC = pytest.mark.asyncio(loop_scope="session")
REPO = Path(__file__).resolve().parents[2]
RETIRED = {"review_leads", "review_dismiss_lead", "review_challenge", "review_answer_challenge", "review_set_section"}
CONTROL = RETIRED - {"review_leads"}
JOB = "job_" + "0" * 26


def _history() -> list[dict]:
    """Every committed revision of contract/mcp/tools.v1.json (empty when git history is unavailable)."""
    try:
        revs = subprocess.run(["git", "-C", str(REPO), "log", "--format=%H", "--", "contract/mcp/tools.v1.json"],
                              capture_output=True, text=True, check=True, timeout=60).stdout.split()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    docs = []
    for rev in revs:
        out = subprocess.run(["git", "-C", str(REPO), "show", f"{rev}:contract/mcp/tools.v1.json"],
                             capture_output=True, text=True, check=False, timeout=60)
        if out.returncode == 0:
            docs.append(json.loads(out.stdout))
    return docs


def _schemas_of(doc: dict, name: str) -> list[dict]:
    """The tool's outputSchema in one revision, with local $refs resolvable through the revision's $defs."""
    tools = [t for t in [*doc.get("tools", []), *doc.get("retired", [])] if t["name"] == name]
    return [{"$defs": doc.get("$defs", {}), **t["outputSchema"]} for t in tools if "outputSchema" in t]


def _strip_external_refs(node):
    """Rubric file refs ($ref to ../rubric/...) cannot be resolved from a bare revision: replace them by `{}`;
    the root shape (required, additionalProperties, the client_notice type) is what decides here."""
    if isinstance(node, list):
        return [_strip_external_refs(x) for x in node]
    if isinstance(node, dict):
        if isinstance(node.get("$ref"), str) and not node["$ref"].startswith("#"):
            return {}
        return {k: _strip_external_refs(v) for k, v in node.items()}
    return node


def test_contract_moves_exactly_the_five_tools():
    assert retired_tool_names() == RETIRED
    served = {t["name"] for t in bundle_tools()}
    assert len(served) == 18 and not served & RETIRED
    assert {t["name"] for t in bundle_retired_tools()} == RETIRED


def test_retired_answer_validates_against_every_historical_output_schema():
    history = _history()
    if not history:
        pytest.skip("git history unavailable")
    checked = 0
    for name in sorted(CONTROL):
        body = retired.answer(name, {})
        assert body == {"accepted": True, "client_notice": retired.notice(name)}
        for doc in history:
            for schema in _schemas_of(doc, name):
                schema = _strip_external_refs(schema)
                errors = list(Draft202012Validator(schema).iter_errors(body))
                assert not errors, (name, [e.message for e in errors][:3])
                assert set(schema.get("required", [])) <= {"accepted"}
                checked += 1
    assert checked >= 4 * 10, checked   # dozens of cached revisions, at least ten per tool


def test_notices_come_from_the_contract_data():
    import yaml

    data = yaml.safe_load((CONTRACT_DIR / "mcp" / "client_refresh.yaml").read_text(encoding="utf-8"))
    for name in RETIRED:
        assert retired.notice(name) == " ".join(data["retired_notices"][name].split())
    assert "Nothing to triage" in retired.notice("review_leads")


@ASYNC
async def test_server_lists_18_tools_and_answers_retired_calls_of_any_shape():
    server = SokenServer()
    listed = {t.name for t in await server.list_tools()}
    assert len(listed) == 18 and not listed & RETIRED
    async with Client(server) as c:
        leads = await c.call_tool("review_leads", {"job_id": JOB, "status": "all", "page_size": 100})
        assert not leads.is_error and "Analyzer leads are retired" in leads.content[0].text
        # old shapes, made-up shapes and no arguments at all: never E_INVALID_ARGUMENT
        for name, args in [
            ("review_dismiss_lead", {"job_id": JOB, "items": [{"lead_id": "LEAD-0001", "reason": "fp_guarded"}]}),
            ("review_challenge", {"job_id": JOB, "draft_key": "x-001"}),
            ("review_answer_challenge", {"job_id": JOB, "draft_key": "x-001", "revision": 0, "answers": "[]"}),
            ("review_set_section", {"job_id": JOB, "section": "invariant_walks", "invariant_walks": "{\"rows\": []}"}),
            ("review_set_section", {"no": "such", "field": 1}),
            ("review_challenge", {}),
        ]:
            res = await c.call_tool(name, args)
            assert not res.is_error, (name, res.content[0].text)
            body = res.structured_content
            assert body["accepted"] is True and body["client_notice"] == retired.notice(name)
            assert output_violations(name, body) == []
            assert json.loads(res.content[0].text) == body


@ASYNC
async def test_retired_call_writes_nothing_and_is_no_fresh_list_signal(monkeypatch):
    from soken_review import client_refresh

    calls = []

    async def spy(*a, **k):
        calls.append(a)

    monkeypatch.setattr(client_refresh, "decide", spy)
    async with Client(SokenServer()) as c:
        await c.call_tool("review_dismiss_lead", {"job_id": JOB, "items": []})
    assert calls == []


def test_legacy_flag_serves_the_retired_tools(monkeypatch):
    monkeypatch.setenv("SOKEN_FLOW", "legacy")
    server = SokenServer()
    assert RETIRED <= set(server.contract) and server.retired == {}
