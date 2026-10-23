"""Holder facts for the roles table `type` column (08 2.2): `eth_getCode` on every holder address found
at the pinned block, kind probes for Safe and timelock; fail-closed on every RPC error (04 1.3)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from soken_review.mapping import facts

OWNER = "0x1111111111111111111111111111111111111111"
ADMIN = "0x2222222222222222222222222222222222222222"
WORD = "0x" + "0" * 64
ONE = "0x" + "1".rjust(64, "0")
OWNERS_ARRAY = "0x" + "20".rjust(64, "0") + "1".rjust(64, "0") + OWNER[2:].rjust(64, "0")


def _word(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


def _rpc(*, code: dict[str, str], calls: dict[str, str] | None = None, admin: str | None = None) -> AsyncMock:
    """owner() returns OWNER; `code` maps address -> eth_getCode; `calls` maps selector -> eth_call answer."""
    rpc = AsyncMock(spec=["get_balance", "eth_call", "get_storage_at", "get_code"])
    rpc.get_balance = AsyncMock(return_value="0x0")
    rpc.get_storage_at = AsyncMock(side_effect=lambda a, slot, block: _word(admin) if admin and slot == facts._EIP1967_ADMIN
                                   else WORD)

    async def eth_call(to: str, data: str, block: int | None = None) -> str:
        if data == facts._SEL["owner"]:
            return _word(OWNER)
        if to in code and data in (calls or {}):
            return calls[data]
        return "0x"

    rpc.eth_call = AsyncMock(side_effect=eth_call)
    rpc.get_code = AsyncMock(side_effect=lambda a, block=None: code.get(a, "0x"))
    return rpc


MAP = {"semantic": {"functions": [], "state_vars": [{"name": "owner"}]}, "spans": []}


def _by_key(out: list[dict]) -> dict[str, dict]:
    return {f["key"]: f for f in out}


@pytest.mark.asyncio
async def test_eoa_owner_gets_code_size_zero_and_kind_eoa():
    rpc = _rpc(code={})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 777, MAP, "u1"))
    rpc.get_code.assert_awaited_once_with(OWNER, block=777)
    assert out["onchain.owner.holder_code_size"]["value"] == "0"
    assert out["onchain.owner.holder_code_size"]["unit"] == "bytes"
    assert out["onchain.owner.holder_is_contract"]["value"] == "false"
    assert out["onchain.owner.holder_kind"]["value"] == "eoa"
    assert out["onchain.owner.holder_kind"]["source"] == "eth_getCode at block 777"
    assert out["onchain.owner.holder_kind"]["unit_id"] == "u1"
    assert not [k for k in out if k.startswith("onchain.admin.")]   # no admin slot, no admin facts


@pytest.mark.asyncio
async def test_plain_contract_owner_when_no_probe_answers():
    rpc = _rpc(code={OWNER: "0x6080604052"})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_code_size"]["value"] == "5"
    assert out["onchain.owner.holder_is_contract"]["value"] == "true"
    assert out["onchain.owner.holder_kind"]["value"] == "contract"


@pytest.mark.asyncio
async def test_safe_owner_is_multisig_when_threshold_and_owners_answer():
    rpc = _rpc(code={OWNER: "0x60"}, calls={facts._PROBE["getThreshold"]: ONE, facts._PROBE["getOwners"]: OWNERS_ARRAY})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_kind"]["value"] == "multisig"


@pytest.mark.asyncio
async def test_zero_threshold_is_not_a_multisig():
    rpc = _rpc(code={OWNER: "0x60"}, calls={facts._PROBE["getThreshold"]: WORD, facts._PROBE["getOwners"]: OWNERS_ARRAY})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_kind"]["value"] == "contract"


@pytest.mark.asyncio
async def test_timelock_owner_when_get_min_delay_answers():
    rpc = _rpc(code={OWNER: "0x60"}, calls={facts._PROBE["getMinDelay"]: "0x" + "15180".rjust(64, "0")})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_kind"]["value"] == "timelock"


@pytest.mark.asyncio
async def test_admin_slot_holder_gets_its_own_facts():
    rpc = _rpc(code={ADMIN: "0x60"}, admin=ADMIN)
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 5, MAP, None))
    assert out["onchain.eip1967.admin"]["value"] == ADMIN
    assert out["onchain.admin.holder_is_contract"]["value"] == "true"
    assert out["onchain.admin.holder_kind"]["value"] == "contract"
    assert out["onchain.owner.holder_kind"]["value"] == "eoa"


@pytest.mark.asyncio
async def test_failed_get_code_yields_no_holder_fact_not_a_false():
    rpc = _rpc(code={})
    rpc.get_code = AsyncMock(side_effect=RuntimeError("rpc down"))
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert "onchain.owner" in out
    assert not [k for k in out if ".holder_" in k]


@pytest.mark.asyncio
async def test_rpc_without_get_code_yields_no_holder_fact():
    rpc = AsyncMock(spec=["get_balance", "eth_call", "get_storage_at"])
    rpc.get_balance = AsyncMock(return_value="0x0")
    rpc.get_storage_at = AsyncMock(return_value=WORD)
    rpc.eth_call = AsyncMock(return_value=_word(OWNER))
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert "onchain.owner" in out and not [k for k in out if ".holder_" in k]


@pytest.mark.asyncio
async def test_failed_probe_is_the_generic_contract_kind():
    rpc = _rpc(code={OWNER: "0x60"})
    rpc.eth_call = AsyncMock(side_effect=lambda to, data, block=None: _word(OWNER) if data == facts._SEL["owner"]
                             else (_ for _ in ()).throw(RuntimeError("revert")))
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_kind"]["value"] == "contract"
    assert out["onchain.owner.holder_is_contract"]["value"] == "true"


@pytest.mark.asyncio
async def test_renounced_owner_has_no_holder_facts():
    rpc = _rpc(code={})
    rpc.eth_call = AsyncMock(return_value=WORD)   # owner() == address(0)
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner"]["value"] == "0x" + "0" * 40
    assert not [k for k in out if ".holder_" in k]
