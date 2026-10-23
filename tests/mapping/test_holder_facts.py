"""Holder facts for the roles table `type` column (08 2.2): `eth_getCode` on every holder address found
at the pinned block, Safe recognised by its singleton in storage slot 0; fail-closed on every RPC error (04 1.3)."""

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
    slot0 = {k: v for k, v in (calls or {}).items() if k.startswith("slot0:")}

    def storage(a: str, slot: str, block=None) -> str:
        if admin and slot == facts._EIP1967_ADMIN:
            return _word(admin)
        if int(slot, 16) == 0 and f"slot0:{a}" in slot0:
            return slot0[f"slot0:{a}"]
        return WORD

    rpc.get_storage_at = AsyncMock(side_effect=storage)

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


SAFE_SINGLETON = "0xd9db270c1b5e3bd161e8c8503c55ceabee709552"   # GnosisSafe 1.3.0 canonical
SAFE_PROXY_CODE = "0x608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea2646970667358221220d1429297349653a4918076d650332de1a1068c5f3e07c5c82360c277770b955264736f6c63430007060033"   # live GnosisSafeProxy 1.3.0 runtime (0x849D5231...)


@pytest.mark.asyncio
async def test_safe_proxy_owner_is_multisig_by_singleton_in_slot_zero():
    rpc = _rpc(code={OWNER: SAFE_PROXY_CODE}, calls={f"slot0:{OWNER}": _word(SAFE_SINGLETON)})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_kind"]["value"] == "multisig"
    assert out["onchain.owner.holder_singleton"]["value"] == SAFE_SINGLETON
    assert "slot 0" in out["onchain.owner.holder_singleton"]["source"]


@pytest.mark.asyncio
async def test_getter_probes_do_not_make_a_multisig():
    """A contract answering getThreshold()/getOwners()/getMinDelay() is still `contract`: getters
    are attacker-controlled, the singleton slot against the published Safe list is not."""
    rpc = _rpc(code={OWNER: "0x60"}, calls={"0xe75235b8": ONE, "0xa0e67e2b": OWNERS_ARRAY,
                                             "0xf27a0c92": "0x" + "15180".rjust(64, "0")})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_kind"]["value"] == "contract"
    assert "onchain.owner.holder_singleton" not in out


@pytest.mark.asyncio
async def test_unknown_singleton_in_slot_zero_is_a_plain_contract():
    rpc = _rpc(code={OWNER: SAFE_PROXY_CODE}, calls={f"slot0:{OWNER}": _word("0x" + "ab" * 20)})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_kind"]["value"] == "contract"


@pytest.mark.asyncio
async def test_singleton_in_slot_zero_without_the_proxy_code_is_a_plain_contract():
    """Storing a Safe singleton address in slot 0 is not enough: the holder must run the Safe
    proxy code (review 2026-10-23)."""
    rpc = _rpc(code={OWNER: "0x60"}, calls={f"slot0:{OWNER}": _word(SAFE_SINGLETON)})
    out = _by_key(await facts.onchain_facts(rpc, "0xdead", 1, MAP, None))
    assert out["onchain.owner.holder_kind"]["value"] == "contract"
    assert "onchain.owner.holder_singleton" not in out


def test_safe_proxy_code_recogniser_prefix_and_metadata_variants():
    code = bytes.fromhex(SAFE_PROXY_CODE[2:])
    assert facts.is_safe_proxy_code(code)
    other_metadata = code[: code.index(0xFE) + 1] + b"\xa2\x64ipfs" + b"\x00" * 30   # 1.4.1 / 1.1.1 differ only here
    assert facts.is_safe_proxy_code(other_metadata)
    assert not facts.is_safe_proxy_code(code[: code.index(0xFE) - 5])   # functional code cut short
    assert not facts.is_safe_proxy_code(b"\x60" + code)              # prefixed
    assert not facts.is_safe_proxy_code(code + b"\x00" * 300)        # too long


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
async def test_failed_storage_read_is_the_generic_contract_kind():
    rpc = _rpc(code={OWNER: "0x60"})
    rpc.get_storage_at = AsyncMock(side_effect=RuntimeError("timeout"))
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
