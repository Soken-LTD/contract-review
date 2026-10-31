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


async def test_get_guide_without_topic_returns_the_default_guide():
    # Thin server (2026-10-31): the exact call the web session made (no topic) returns topic start, the
    # short default path, instead of an error.
    async with Client(SokenServer()) as client:
        result = await client.call_tool("review_get_guide", {"job_id": "job_" + "A" * 26})
    assert not result.is_error
    text = result.content[0].text
    assert text.splitlines()[0].startswith("guide_version v0 topic start")
    assert "review_submit_finding" in text and "claimed_severity" in text


def test_json_string_is_parsed_for_object_and_array_properties():
    """A client with a stale tool list sends an unknown-typed object as a string (blind run 2026-10-26,
    `invariant_walks`). The server parses it before validation; other strings stay untouched."""
    from soken_review.server import _parse_json_strings

    schema = {"properties": {"job_id": {"type": "string"}, "invariant_walks": {"type": "object"},
                             "ranges": {"type": "array"}, "maybe": {"type": ["object", "null"]}}}
    args = {"job_id": "job_X", "invariant_walks": '{"rows": [{"walk_id": "w1"}]}', "ranges": "[1, 2]",
            "maybe": "{}"}
    out = _parse_json_strings(schema, args)
    assert out["invariant_walks"] == {"rows": [{"walk_id": "w1"}]}
    assert out["ranges"] == [1, 2] and out["maybe"] == {}
    assert out["job_id"] == "job_X"
    assert args["invariant_walks"].startswith("{")  # input not mutated


def test_json_string_of_wrong_type_or_not_json_is_left_alone():
    from soken_review.server import _parse_json_strings

    schema = {"properties": {"obj": {"type": "object"}, "txt": {"type": "string"}, "arr": {"type": "array"}}}
    args = {"obj": "[1]", "txt": '{"a": 1}', "arr": "{not json"}
    assert _parse_json_strings(schema, args) is args


async def test_set_section_accepts_section_object_sent_as_string():
    """End to end through the SDK: the string form must reach the handler as an object (so the error,
    if any, is the handler's, not E_INVALID_ARGUMENT from the schema validator)."""
    async with Client(SokenServer()) as client:
        result = await client.call_tool("review_set_section", {
            "job_id": "job_00000000000000000000000000",
            "section": "invariant_walks",
            "invariant_walks": '{"rows": [{"walk_id": "W1", "outcome": "holds", "refs": []}]}',
        })
    body = json.loads(result.content[0].text)
    err = body["errors"][0]
    assert not (err["code"] == "E_INVALID_ARGUMENT" and err.get("field") == "invariant_walks"), body


def test_schema_version_is_the_hash_of_the_shipped_tool_list():
    """review_start and review_status return it; a client compares it with the list it loaded."""
    import hashlib
    import re

    from soken_review.contract import TOOLS_FILE, schema_version

    v = schema_version()
    assert re.fullmatch(r"[0-9a-f]{12}", v)
    assert v == hashlib.sha256(TOOLS_FILE.read_bytes()).hexdigest()[:12]
    props = {t["name"]: t["outputSchema"]["properties"] for t in bundle_tools() if "outputSchema" in t}
    assert props["review_start"]["schema_version"]["pattern"] == props["review_status"]["schema_version"]["pattern"]


async def test_stale_client_shape_gets_a_reload_hint_once_per_result():
    """A JSON-string object is the one visible sign of a tool list loaded before a deploy (PR #77):
    the result carries a one-line hint naming the served schema_version; a native object does not."""
    from soken_review.contract import schema_version

    args = {"job_id": "job_00000000000000000000000000", "section": "invariant_walks"}
    rows = {"rows": [{"walk_id": "W1", "outcome": "holds", "refs": []}]}
    async with Client(SokenServer()) as client:
        stale = await client.call_tool("review_set_section", {**args, "invariant_walks": json.dumps(rows)})
        fresh = await client.call_tool("review_set_section", {**args, "invariant_walks": rows})
    stale_body = json.loads(stale.content[0].text)
    assert stale_body["schema_hint"].startswith("Your tool list predates the current schema")
    assert schema_version() in stale_body["schema_hint"] and "reload" in stale_body["schema_hint"].lower()
    if stale.structured_content is not None:
        assert stale.structured_content["schema_hint"] == stale_body["schema_hint"]
    assert "schema_hint" not in json.loads(fresh.content[0].text)
    assert stale_body["errors"][0]["code"] == json.loads(fresh.content[0].text)["errors"][0]["code"]


async def test_stale_shape_hint_rides_a_rejection_result_too():
    """Channel `rejection` (accepted false, structured): the hint sits beside the errors."""
    from soken_review.contract import schema_version

    async with Client(SokenServer()) as client:
        res = await client.call_tool("review_submit_finding", {
            "job_id": "job_00000000000000000000000000", "draft_key": "d-1", "category": "evm.other",
            "title": "t", "quotes": "[]", "matrix": "{}", "body": "{}"})
    body = json.loads(res.content[0].text)
    assert body["accepted"] is False and schema_version() in body["schema_hint"]
    if res.structured_content is not None:
        assert res.structured_content["schema_hint"] == body["schema_hint"]


def test_text_result_gets_the_hint_as_a_last_line():
    from mcp.types import CallToolResult, TextContent

    from soken_review.server import _with_schema_hint

    res = _with_schema_hint(CallToolResult(content=[TextContent(type="text", text="leads open 0 of 0\nend")]))
    lines = res.content[0].text.splitlines()
    assert lines[:2] == ["leads open 0 of 0", "end"] and lines[2].startswith("schema_hint Your tool list predates")


def test_stale_schema_hint_tells_a_claude_ai_user_how_to_refresh():
    """JUDGEMENT 2026-10-27 E2: the stale list was the client's cache; the hint must say what to do."""
    from soken_review.server import _stale_schema_hint

    hint = _stale_schema_hint()
    assert hint.startswith("Your tool list predates the current schema")
    assert "remove this connector" in hint and "add it again" in hint
    assert "reload the tool list" in hint
