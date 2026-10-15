"""chain_state 1 on-chain facts (03 3.1; 04 1.3): reads go through the RPC pool's public API."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from soken_review.mapping import facts


def _rpc(balance: str = "0x3e8") -> AsyncMock:
    rpc = AsyncMock(spec=["get_balance", "eth_call"])
    rpc.get_balance = AsyncMock(return_value=balance)
    rpc.eth_call = AsyncMock(return_value="0x" + "0" * 64)
    return rpc


@pytest.mark.asyncio
async def test_balance_fact_is_read_with_get_balance_at_the_pinned_block():
    rpc = _rpc()
    out = await facts.onchain_facts(rpc, "0xabc", 777, None, "u1")
    rpc.get_balance.assert_awaited_once_with("0xabc", 777)
    bal = next(f for f in out if f["key"] == "onchain.balance")
    assert bal["value"] == "1000" and bal["unit"] == "wei" and bal["unit_id"] == "u1"
    assert "777" in bal["source"]


@pytest.mark.asyncio
async def test_failed_balance_read_is_no_fact():
    rpc = _rpc()
    rpc.get_balance = AsyncMock(side_effect=RuntimeError("down"))
    out = await facts.onchain_facts(rpc, "0xabc", 1, None, None)
    assert not [f for f in out if f["key"] == "onchain.balance"]
