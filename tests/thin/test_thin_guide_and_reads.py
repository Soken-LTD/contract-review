"""Thin guide (design section 2) and reads from the moment the source is pinned (section 4)."""

from __future__ import annotations

import pytest
from mcp import Client

import soken_review.tools  # noqa: F401
from soken_review.pinning.store import PinnedSource
from soken_review.server import SokenServer
from soken_review.tools import read as read_mod
from soken_review.tools.context import MemoryJobContext
from soken_review.tools.guide import _texts, start_text, thin_text

ASYNC = pytest.mark.asyncio(loop_scope="session")
JOB = "job_" + "C" * 26


def test_thin_guide_is_one_block_under_budget():
    t = thin_text()
    assert len(t) < int(_texts()["thin"]["budget_chars"]) == 900
    assert start_text("ton") == t
    for word in ("matrix", "review_challenge", "review_set_section", "review_leads", "category"):
        assert word not in t


@ASYNC
@pytest.mark.parametrize("topic", ["start", "checklist", "categories", "severity_inputs", "challenge_rules",
                                   "context", "invariants", "chain"])
async def test_every_topic_answers_the_how_to(topic):
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_get_guide", {"topic": topic})
    text = r.content[0].text
    assert not r.is_error and thin_text() in text
    assert (f"Topic {topic} is retired" in text) == (topic != "start")


@ASYNC
async def test_several_topics_in_one_call():
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_get_guide", {"topics": ["checklist", "invariants"]})
    text = r.content[0].text
    assert text.count(thin_text()) == 1 and "Topic checklist is retired" in text and "Topic invariants" in text


@ASYNC
@pytest.mark.parametrize("state", ["fetching", "building", "analyzing"])
async def test_code_is_readable_once_pinned(tmp_path, state):
    ctx = MemoryJobContext(tmp_path)
    ctx.set_state(JOB, state)
    read_mod.set_context(ctx)
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_read_code", {"job_id": JOB, "path": "src/A.sol", "start_line": 1, "end_line": 2})
        assert "E_JOB_NOT_READY" in r.content[0].text    # no pin yet
        PinnedSource.from_files({"src/A.sol": b"uint256 constant A = 1;\nuint256 constant B = 2;\n"}).persist(tmp_path, JOB)
        r = await c.call_tool("review_read_code", {"job_id": JOB, "path": "src/A.sol", "start_line": 1, "end_line": 2})
        s = await c.call_tool("review_search_code", {"job_id": JOB, "pattern": "constant B"})
    assert not r.is_error and "uint256 constant B = 2;" in r.content[0].text and "flags pending" in r.content[0].text
    assert not s.is_error and "src/A.sol" in s.content[0].text, s.content[0].text
    assert read_mod.source_pinned(tmp_path, JOB)


@ASYNC
async def test_queued_job_is_not_readable_even_with_a_stray_pin(tmp_path):
    ctx = MemoryJobContext(tmp_path)
    ctx.set_state(JOB, "queued")
    read_mod.set_context(ctx)
    PinnedSource.from_files({"src/A.sol": b"x\n"}).persist(tmp_path, JOB)
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_read_code", {"job_id": JOB, "path": "src/A.sol", "start_line": 1, "end_line": 1})
    assert "E_JOB_NOT_READY" in r.content[0].text
