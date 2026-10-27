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
import pytest_asyncio
from mcp import Client

import soken_review.tools  # noqa: F401 – register @handler decorators
from soken_review.server import SokenServer
from soken_review.tools.start_status import set_pool

from ._client import task_scoped_client

ASYNC = pytest.mark.asyncio(loop_scope="session")   # the db_pool loop (tests/conftest.py)


async def _call(tool: str, **args):
    async with Client(SokenServer()) as c:
        return await c.call_tool(tool, args)


# ---------------------------------------------------------------------------
# DB-wired client fixture (same pattern as test_status_tails.py)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(loop_scope="session")
async def wired_client(db_pool):
    """MCP client with a live DB pool injected via set_pool."""
    set_pool(db_pool)
    try:
        async with task_scoped_client() as c:
            yield c
    finally:
        set_pool(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# review_start: next_action present / absent
# ---------------------------------------------------------------------------

@ASYNC
async def test_review_start_carries_next_action_when_no_context(wired_client):
    source = {
        "kind": "files",
        "language": "solidity",
        "files": [{"path": "A.sol", "content": "contract A {}"}],
    }
    res = await wired_client.call_tool("review_start", {"source": source})
    assert not res.is_error, getattr(res.content[0], "text", repr(res))
    body = res.structured_content
    assert body is not None and body.get("accepted"), f"Expected accepted job; got: {body!r}"
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


@ASYNC
async def test_review_start_no_next_action_when_context_provided(wired_client):
    source = {
        "kind": "files",
        "language": "solidity",
        "files": [{"path": "A.sol", "content": "contract A {}"}],
    }
    ctx = {"items": [{"kind": "website", "url": "https://example.com/"}]}
    res = await wired_client.call_tool("review_start", {"source": source, "context": ctx})
    assert not res.is_error, getattr(res.content[0], "text", repr(res))
    body = res.structured_content
    assert body is not None and body.get("accepted"), f"Expected accepted job; got: {body!r}"
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

@ASYNC
async def test_guide_context_topic_has_step_1():
    res = await _call("review_get_guide", topic="context", chain="evm")
    assert not res.is_error, res.content[0].text
    text = res.content[0].text
    assert "Step 1" in text, "context topic must have a Step 1 doc-request instruction"
    assert "review_add_context" in text, "Step 1 must mention review_add_context"
    # Must explain WHY (spec-vs-code)
    assert any(w in text.lower() for w in ("spec", "whitepaper", "documentation", "document"))


def test_documents_hint_says_exactly_how_to_silence_it():
    """Held-out run 2026-10-27: the hint repeated on every status until the arm guessed the
    section shape; it now names the tool, the section and the notes shape."""
    from soken_review.tools.start_status import NO_DOCUMENTS_HINT, _build_status_response

    assert "review_set_section" in NO_DOCUMENTS_HINT and '"context_notes"' in NO_DOCUMENTS_HINT
    assert '{"notes": [{"p":' in NO_DOCUMENTS_HINT and "review_add_context" in NO_DOCUMENTS_HINT
    assert not re.match(r"^(Call|Invoke|Use|Run|Execute)\s+review_", NO_DOCUMENTS_HINT, re.IGNORECASE)
    assert "—" not in NO_DOCUMENTS_HINT
    job = {"job_id": "job_HINT000000000000000000009", "state": "ready", "requester_role": "third_party_public_code",
           "ownership_proven": False, "context_items": [], "error_code": None, "error_detail": None,
           "map_status": "partial", "analyzer_degraded": False, "tier": None, "upload_id": None}
    assert _build_status_response(job, "concise")["next_action"] == NO_DOCUMENTS_HINT
    assert "next_action" not in _build_status_response(job, "concise", context_notes_recorded=True)
