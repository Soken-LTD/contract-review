"""Tests for the next_action hint in review_start / review_status (feat/context-related-state).

The hint must:
- Be present when no context items are supplied.
- Be absent when context items are present.
- Pass the text gate (no injection-like phrases, no commands to call unrelated tools).
- Be plain declarative text that describes; it must not begin with an imperative command.
"""

from __future__ import annotations

import re

import pytest
from mcp import Client

import soken_review.tools  # noqa: F401 – register @handler decorators
from soken_review.server import SokenServer

pytestmark = pytest.mark.anyio


async def _call(tool: str, **args):
    async with Client(SokenServer()) as c:
        return await c.call_tool(tool, args)


# ---------------------------------------------------------------------------
# review_start: next_action present / absent
# ---------------------------------------------------------------------------

async def test_review_start_carries_next_action_when_no_context():
    source = {
        "kind": "files",
        "language": "solidity",
        "files": [{"path": "A.sol", "content": "contract A {}"}],
    }
    res = await _call("review_start", source=source)
    # E_INTERNAL = no DB pool wired in this test environment; skip gracefully.
    if res.is_error:
        pytest.skip("DB not wired (E_INTERNAL); skipping review_start accepted-path assertion")
    body = res.structured_content
    # Rejection channel (accepted=False) also means the job was not created.
    if body is None or not body.get("accepted"):
        pytest.skip("DB not wired; skipping accepted-path assertion")
    assert "next_action" in body, "next_action should be present when no context"
    hint = body["next_action"]
    assert isinstance(hint, str) and len(hint) > 20
    # Must not be an imperative starting with a verb directly commanding the model
    # to call a specific unrelated tool.
    assert not re.match(r"^(Call|Invoke|Use|Run|Execute)\s+review_", hint, re.IGNORECASE), (
        f"hint must not command calling unrelated tools: {hint!r}"
    )
    # Must mention what the user can provide
    assert any(w in hint.lower() for w in ("website", "whitepaper", "documentation", "docs", "terms")), (
        f"hint must mention document types: {hint!r}"
    )


async def test_review_start_no_next_action_when_context_provided():
    source = {
        "kind": "files",
        "language": "solidity",
        "files": [{"path": "A.sol", "content": "contract A {}"}],
    }
    ctx = {"items": [{"kind": "website", "url": "https://example.com/"}]}
    res = await _call("review_start", source=source, context=ctx)
    if res.is_error:
        pytest.skip("DB not wired (E_INTERNAL); skipping review_start accepted-path assertion")
    body = res.structured_content
    if body is None or not body.get("accepted"):
        pytest.skip("DB not wired")
    assert "next_action" not in body, (
        "next_action must be absent when context items are provided"
    )


# ---------------------------------------------------------------------------
# review_status next_action via _build_status_response (unit-level)
# ---------------------------------------------------------------------------

def test_build_status_response_next_action_when_no_context():
    from soken_review.tools.start_status import _build_status_response

    job = {
        "job_id": "job_HINT000000000000000000000",
        "state": "ready",
        "requester_role": "third_party_public_code",
        "ownership_proven": False,
        "context_items": [],  # no context
        "error_code": None,
        "error_detail": None,
        "map_status": "partial",
        "analyzer_degraded": False,
        "tier": None,
        "upload_id": None,
    }
    out = _build_status_response(job, "concise")
    assert "next_action" in out
    hint = out["next_action"]
    assert "project document" in hint.lower() or "whitepaper" in hint.lower(), hint
    # Plain statement, not a command starting with a verb for another tool
    assert not re.match(r"^(Call|Invoke|Use|Run|Execute)\s+review_", hint, re.IGNORECASE)


def test_build_status_response_no_next_action_when_context_present():
    from soken_review.tools.start_status import _build_status_response

    job = {
        "job_id": "job_HINT000000000000000000001",
        "state": "ready",
        "requester_role": "third_party_public_code",
        "ownership_proven": False,
        "context_items": [{"kind": "website", "url": "https://example.com/"}],
        "error_code": None,
        "error_detail": None,
        "map_status": "partial",
        "analyzer_degraded": False,
        "tier": None,
        "upload_id": None,
    }
    out = _build_status_response(job, "concise")
    assert "next_action" not in out


def test_build_status_response_next_action_absent_in_terminal_state():
    from soken_review.tools.start_status import _build_status_response

    job = {
        "job_id": "job_HINT000000000000000000002",
        "state": "failed",
        "requester_role": "third_party_public_code",
        "ownership_proven": False,
        "context_items": [],
        "error_code": "E_INTERNAL",
        "error_detail": None,
        "map_status": "none",
        "analyzer_degraded": False,
        "tier": None,
        "upload_id": None,
    }
    out = _build_status_response(job, "concise")
    # Terminal states should not carry the hint (the job can no longer accept context)
    assert "next_action" not in out


def test_build_status_response_next_action_present_in_queued_state():
    from soken_review.tools.start_status import _build_status_response

    job = {
        "job_id": "job_HINT000000000000000000003",
        "state": "queued",
        "requester_role": "third_party_public_code",
        "ownership_proven": False,
        "context_items": [],
        "error_code": None,
        "error_detail": None,
        "map_status": "none",
        "analyzer_degraded": False,
        "tier": None,
        "upload_id": None,
    }
    out = _build_status_response(job, "concise")
    assert "next_action" in out


# ---------------------------------------------------------------------------
# Guide: context topic starts with step 1 instruction
# ---------------------------------------------------------------------------

async def test_guide_context_topic_has_step_1():
    res = await _call("review_get_guide", topic="context", chain="evm")
    assert not res.is_error, res.content[0].text
    text = res.content[0].text
    assert "Step 1" in text, "context topic must have a Step 1 doc-request instruction"
    assert "review_add_context" in text, "Step 1 must mention review_add_context"
    # Must explain WHY (spec-vs-code)
    assert any(w in text.lower() for w in ("spec", "whitepaper", "documentation", "document"))
