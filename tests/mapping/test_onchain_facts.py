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


# ─── privileged holders from getters beyond owner() (road-to-prod item 9) ─────────────────────

GOV = "0x" + "ab" * 20


def _map(*names: str) -> dict:
    spans = [{"id": f"s{i}", "name": n} for i, n in enumerate(names)]
    return {"spans": spans, "semantic": {"functions": [{"span": s["id"], "is_entry": True} for s in spans],
                                         "state_vars": []}}


@pytest.mark.asyncio
async def test_governance_getter_is_read_only_when_the_unit_exposes_it():
    rpc = AsyncMock(spec=["get_balance", "eth_call", "get_storage_at", "get_code"])
    rpc.get_balance = AsyncMock(return_value="0x0")
    rpc.get_storage_at = AsyncMock(return_value="0x" + "0" * 64)
    rpc.get_code = AsyncMock(return_value="0x")

    async def call(address, data, block=None):
        return "0x" + "0" * 24 + GOV[2:] if data == facts.getter_selector("governance") else "0x" + "0" * 64

    rpc.eth_call = AsyncMock(side_effect=call)
    out = await facts.onchain_facts(rpc, "0xabc", 5, _map("governance", "setFee"), "u1")
    gov = next(f for f in out if f["key"] == "onchain.governance")
    assert gov["value"] == GOV and gov["source"] == "eth_call governance() at block 5"
    assert next(f for f in out if f["key"] == "onchain.governance.holder_kind")["value"] == "eoa"
    called = {c.args[1] for c in rpc.eth_call.await_args_list}
    assert facts.getter_selector("guardian") not in called           # not exposed by the unit: never read


@pytest.mark.asyncio
async def test_getter_word_that_is_not_an_address_is_no_fact():
    rpc = AsyncMock(spec=["get_balance", "eth_call", "get_storage_at", "get_code"])
    rpc.get_balance = AsyncMock(return_value="0x0")
    rpc.get_storage_at = AsyncMock(return_value="0x" + "0" * 64)
    rpc.eth_call = AsyncMock(return_value="0x" + "f" * 64)                 # a uint, not an address
    out = await facts.onchain_facts(rpc, "0xabc", 5, _map("minter"), "u1")
    assert not [f for f in out if f["key"].startswith("onchain.minter")]


def test_getter_selectors_and_keys_follow_the_abi_and_the_key_grammar():
    assert facts.getter_selector("owner") == "0x8da5cb5b"
    assert facts.getter_selector("admin") == "0xf851a440"
    assert facts.getter_selector("pendingOwner") == "0xe30c3978"
    assert facts.holder_fact_key("pendingOwner") == "onchain.pending_owner"
    for g in facts.HOLDER_GETTERS:
        facts.fact(facts.holder_fact_key(g), "0x" + "1" * 40, source="t")   # key grammar accepts every getter
