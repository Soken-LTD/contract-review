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
