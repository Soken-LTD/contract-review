"""Long-poll cap (MetaDAO blind run 2026-10-31: a fifteen-minute Solana build cost 25 status calls).

The wait is 55 s for review_status and review_start: under the 60 s default request timeout of the
MCP TypeScript SDK, above the old 45 s. The schema and the handler agree."""

from __future__ import annotations

from soken_review.contract import bundle_tools
from soken_review.tools import start_status


def test_schema_and_handler_share_the_55_second_cap():
    tools = {t["name"]: t for t in bundle_tools()}
    assert start_status._MAX_WAIT == 55
    for name in ("review_status", "review_start"):
        assert tools[name]["inputSchema"]["properties"]["wait_seconds"]["maximum"] == 55, name
