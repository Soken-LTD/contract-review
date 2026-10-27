"""review_get_guide (03 4.3): every topic answers, first line is the header, content is rubric data.

Until 2026-10-22 the tool had no handler and every call raised NotImplementedError through the MCP
layer; a web session then guessed matrix enums and burned its submit attempts.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

import soken_review.tools  # noqa: F401

from ._client import task_scoped_client

ASYNC = pytest.mark.asyncio(loop_scope="session")   # one loop for fixture and test (tests/tools/_client.py)


@pytest_asyncio.fixture(loop_scope="session")
async def client():
    async with task_scoped_client() as c:
        yield c


async def _guide(client, **args) -> str:
    result = await client.call_tool("review_get_guide", args)
    assert not result.is_error, result.content[0].text
    return result.content[0].text


@pytest.mark.parametrize("topic", ["checklist", "categories", "severity_inputs", "challenge_rules", "context"])
@ASYNC
async def test_every_topic_answers_with_header(client, topic):
    text = await _guide(client, topic=topic)
    first = text.splitlines()[0]
    assert first == f"guide_version v0 topic {topic} chain evm"
    assert 200 < len(text) <= 12_000


@ASYNC
async def test_categories_follow_chain_family(client):
    evm = await _guide(client, topic="categories", chain="evm")
    assert "evm.access_control" in evm and "solana." not in evm
    sol = await _guide(client, topic="categories", chain="solana")
    assert "solana." in sol and "evm.access_control" not in sol
    assert sol.splitlines()[0].endswith("chain solana")


@ASYNC
async def test_severity_inputs_list_exact_enum_values(client):
    text = await _guide(client, topic="severity_inputs")
    # the values a client must send; the ones the web session guessed wrong are not there
    for value in ("privileged_role", "privileged_role_unprotected", "theft_of_funds", "permanent_freeze",
                  "incorrect_accounting_no_fund_effect", "self_recovering", "admin_reversible"):
        assert value in text
    for guessed in ("governance", "accounting_error", "freeze_of_funds"):
        assert guessed not in text
    assert "K4" in text and "reasoning_challenged" in text and "analyzer_and_reasoning" in text


@ASYNC
async def test_checklist_renders_family_items(client):
    text = await _guide(client, topic="checklist", chain="starknet")
    assert text.splitlines()[0].endswith("chain starknet")
    assert "cairo." in text and "kill" in text


@ASYNC
async def test_challenge_rules_name_answer_values(client):
    text = await _guide(client, topic="challenge_rules")
    for value in ("present", "absent", "not_applicable", "review_dismiss_lead", "F2"):
        assert value in text


@ASYNC
async def test_context_topic_describes_the_documents_surface(client):
    # Context ingestion spec 8: what the tool ingests, role context quotes, {{fact:context.*}} sources,
    # and context_notes as the only free-text place.
    text = await _guide(client, topic="context")
    for value in ("review_add_context", "whitepaper", "privacy", "context/", "role context", "fact:context.",
                  "context_notes", "E_CONTEXT_FETCH", "12 documents"):
        assert value in text, value
    rules = await _guide(client, topic="challenge_rules")
    assert "role context" in rules


@ASYNC
async def test_severity_inputs_show_the_double_brace_placeholder_form(client):
    """The guide once showed `{fact:<key>}`; the Wallitelli reviewer copied it and the PDF printed it raw."""
    text = await _guide(client, topic="severity_inputs")
    assert "{{fact:<key>}}" in text and "{{calc:<expr>|<precision>}}" in text
    assert "({fact:<key>}" not in text
