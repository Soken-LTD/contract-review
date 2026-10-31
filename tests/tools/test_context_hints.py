"""The documents note and the default guide on review_start (thin server, CEO decision 2026-10-31).

Round 5: every MCP arm saw the no-documents hint on every review_status call until it guessed how to
silence it. Now the note rides once on review_start (only when no documents were supplied), review_status
never carries it, and its text lives in contract/rubric/guide.yaml. review_start also returns the default
guide, so the default path needs no review_get_guide call.
"""

from __future__ import annotations

import re

import pytest
import pytest_asyncio
from mcp import Client

import soken_review.tools  # noqa: F401 – register @handler decorators
from soken_review.server import SokenServer
from soken_review.tools.start_status import _build_status_response, documents_note, set_pool

from ._client import task_scoped_client

ASYNC = pytest.mark.asyncio(loop_scope="session")   # the db_pool loop (tests/conftest.py)

_FILES = {"kind": "files", "language": "solidity", "files": [{"path": "A.sol", "content": "contract A {}"}]}


async def _call(tool: str, **args):
    async with Client(SokenServer()) as c:
        return await c.call_tool(tool, args)


@pytest_asyncio.fixture(loop_scope="session")
async def wired_client(db_pool):
    set_pool(db_pool)
    try:
        async with task_scoped_client() as c:
            yield c
    finally:
        set_pool(None)  # type: ignore[arg-type]


@ASYNC
async def test_review_start_carries_the_note_and_the_guide_when_no_context(wired_client):
    res = await wired_client.call_tool("review_start", {"source": _FILES})
    assert not res.is_error, getattr(res.content[0], "text", repr(res))
    body = res.structured_content
    assert body is not None and body.get("accepted"), body
    assert "next_action" not in body
    note = body["documents_note"]
    assert note == documents_note() and "Optional" in note and "review_add_context" in note
    assert not re.match(r"^(Call|Invoke|Use|Run|Execute)\s+review_", note, re.IGNORECASE)
    guide = body["guide"]
    assert guide.startswith("Default path.") and "claimed_severity" in guide and "evm.access_control" in guide


@ASYNC
async def test_review_start_has_no_note_when_context_provided(wired_client):
    ctx = {"items": [{"kind": "website", "url": "https://example.com/"}]}
    res = await wired_client.call_tool("review_start", {"source": _FILES, "context": ctx})
    assert not res.is_error, getattr(res.content[0], "text", repr(res))
    body = res.structured_content
    assert body.get("accepted") and "documents_note" not in body and "guide" in body


@pytest.mark.parametrize("state", ["queued", "analyzing", "ready", "failed"])
def test_review_status_never_carries_a_documents_hint(state):
    job = {"job_id": "job_HINT000000000000000000000", "state": state, "requester_role": "third_party_public_code",
           "ownership_proven": False, "context_items": [], "error_code": None, "error_detail": None,
           "map_status": "partial", "analyzer_degraded": False, "tier": None, "upload_id": None}
    out = _build_status_response(job, "concise")
    assert "next_action" not in out and "documents_note" not in out


@ASYNC
async def test_guide_context_topic_is_optional_and_names_the_tool():
    res = await _call("review_get_guide", topic="context", chain="evm")
    assert not res.is_error, res.content[0].text
    text = res.content[0].text
    assert "Optional" in text and "review_add_context" in text and "whitepaper" in text
    assert "Step 1" not in text


def test_documents_note_is_data_and_plain_english():
    note = documents_note()
    assert "—" not in note and "–" not in note and "?" not in note
