"""Live: review_start -> ready -> review_leads for real Sui and Aptos packages (plan v4 07, 09 3.1).

Skips unless SOKEN_DATABASE_URL and SOKEN_MOVE_E2E=1 are set (needs docker images
SOKEN_IMAGE_APTOS_BUILD / SOKEN_IMAGE_SUI_BUILD / SOKEN_IMAGE_GIT_FETCH and network). Select
targets with SOKEN_MOVE_E2E_CHAINS=aptos,sui.
"""

from __future__ import annotations

import os

import pytest

from tests.integration.test_e2e_evm import (  # noqa: F401
    _mcp_call,
    _poll_status,
    mcp_client,
    pg_pool,
    pin_root,
    running_supervisor,
)

pytestmark = pytest.mark.skipif(
    not (os.environ.get("SOKEN_DATABASE_URL") and os.environ.get("SOKEN_MOVE_E2E") == "1"),
    reason="SOKEN_DATABASE_URL and SOKEN_MOVE_E2E=1 not set (live Move e2e)",
)

TARGETS = {
    "aptos": "0xc7efb4076dbe143cbcd98cfaaa929ecfc8f299203dfff63b95ccb6bfe19850fa",   # PancakeSwap
    "sui": "0xbb97fa5af2504cc944a8df78dcb5c8b72c3673ca4ba8e4969a98188bf745ee54",     # @mvr/core v3
}
CHAINS = [c for c in os.environ.get("SOKEN_MOVE_E2E_CHAINS", "aptos,sui").split(",") if c in TARGETS]


@pytest.mark.asyncio
@pytest.mark.timeout(1800)
@pytest.mark.parametrize("chain", CHAINS)
async def test_move_package_to_ready_with_leads(chain, running_supervisor, mcp_client) -> None:  # noqa: F811
    start = await _mcp_call(mcp_client, "review_start",
                            source={"kind": "deployed", "chain": chain, "address": TARGETS[chain]})
    assert start.get("accepted") is not False, start
    job_id = start["job_id"]
    status = await _poll_status(mcp_client, job_id, timeout=1700.0)
    print(f"\n{chain} {job_id} status: {status}")
    assert status["state"] == "ready", status
    # map_status='failed' means the build step failed; analyze never ran → leads are meaningless.
    assert status.get("map_status") != "failed", (
        f"map_status=failed — build failed so analysis never ran; "
        f"analyzer_degraded={status.get('analyzer_degraded')}"
    )
    # analyzer_degraded means all analyzers errored or were skipped — no facts produced.
    assert not status.get("analyzer_degraded"), (
        f"all analyzers degraded — no facts produced: {status}"
    )
    leads = await _mcp_call(mcp_client, "review_leads", job_id=job_id)
    assert not leads.get("is_error"), leads
    assert "LEAD-0001" in leads["text"], leads["text"][:400]
    print(f"{chain} leads:", "\n".join(leads["text"].splitlines()[:4]))


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_move_address_without_package_is_insufficient_source(running_supervisor, mcp_client) -> None:  # noqa: F811
    start = await _mcp_call(mcp_client, "review_start", source={
        "kind": "deployed", "chain": "aptos",
        "address": "0x00000000000000000000000000000000000000000000000000000000000000ab"})
    status = await _poll_status(mcp_client, start["job_id"], timeout=280.0)
    assert status["state"] == "insufficient_source", status
