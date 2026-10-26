"""Golden calls through the SDK client (03 section 11): the live list equals the contract."""

import json

import pytest
from mcp import Client

from soken_review.contract import bundle_tools
from soken_review.server import SokenServer

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_tools_list_equals_contract():
    contract = {t["name"]: t for t in bundle_tools()}
    async with Client(SokenServer()) as client:
        listed = (await client.list_tools()).tools
    assert [t.name for t in listed] == list(contract)
    for tool in listed:
        c = contract[tool.name]
        assert tool.input_schema == c["inputSchema"]
        assert tool.output_schema == c.get("outputSchema")
        assert tool.description == c["description"]
        assert tool.annotations.read_only_hint == c["annotations"]["readOnlyHint"]
        assert tool.annotations.destructive_hint == c["annotations"]["destructiveHint"]


async def test_invalid_argument_is_catalogued_error():
    async with Client(SokenServer()) as client:
        result = await client.call_tool("review_status", {"job_id": "nope"})
    assert result.is_error
    body = json.loads(result.content[0].text)
    assert body["accepted"] is False
    assert body["errors"][0]["code"] == "E_INVALID_ARGUMENT"
    assert body["errors"][0]["field"] == "job_id"


async def test_rejection_channel_is_not_an_error_result():
    from soken_review.errors import ReviewError
    from soken_review.server import _error_result

    result = _error_result(ReviewError("E_CHAIN_ID_REQUIRED"))
    assert not result.is_error
    assert result.structured_content["accepted"] is False


def _first_error(schema, instance):
    from jsonschema import Draft202012Validator
    return next(iter(Draft202012Validator(schema).iter_errors(instance)))


def test_violation_hint_names_missing_required_field():
    # A missing required field used to report field "(root)" with an empty example, so a caller
    # could not tell WHAT to add (the review_get_guide 'topic' failure the web session hit).
    from soken_review.server import _violation_hint
    schema = {"type": "object", "properties": {"topic": {"type": "string"}}, "required": ["topic"]}
    field, example = _violation_hint(_first_error(schema, {}))
    assert field == "topic"
    assert example == "add the required field 'topic'"


def test_violation_hint_names_unexpected_field():
    # The review_dismiss_lead 'reason'/'lead_id' failure: additionalProperties must name the extra
    # field and list the allowed ones so the caller can switch to the right shape.
    from soken_review.server import _violation_hint
    schema = {"type": "object", "properties": {"job_id": {}, "items": {}}, "additionalProperties": False}
    field, example = _violation_hint(_first_error(schema, {"job_id": "j", "reason": "r"}))
    assert field == "reason"
    assert "remove the unexpected field 'reason'" in example
    assert "items" in example  # allowed fields listed


async def test_get_guide_missing_topic_names_the_field():
    # End to end through the client: the exact call the web session made (no topic) now returns an
    # actionable envelope naming 'topic', instead of an opaque "(root) breaks rule required".
    async with Client(SokenServer()) as client:
        result = await client.call_tool("review_get_guide", {"job_id": "job_" + "A" * 26})  # valid id: only topic is missing
    assert result.is_error
    body = json.loads(result.content[0].text)
    assert body["errors"][0]["code"] == "E_INVALID_ARGUMENT"
    assert body["errors"][0]["field"] == "topic"
    assert "topic" in body["errors"][0]["fix"]
