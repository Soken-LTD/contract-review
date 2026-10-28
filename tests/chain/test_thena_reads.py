"""Thena round 4 (matrix 2026-10-27 r4, T3 and T5) reproduced through the chain reads, on BSC
answers recorded from the free pool on 2026-10-28 (tests/fixtures/chain/thena_bsc.json).

Hand check of the recorded values (block 130,229,517):
  supply()            = 335,304,456.968 THE  (335304456968324627407175342 / 1e18)
  THE.balanceOf(veTHE) = 150,473,875.547 THE  (150473875546894119406360255 / 1e18)
  ratio 2.228; supply() also exceeds THE.totalSupply() = 299,457,998.711 THE, which a correct
  lock total never can. getPastTotalSupply(block time minus 86,400 s) reverts Panic(0x11).
The r4 judgement read 335,281,333 and 150,470,429 a day earlier; both moved by under 0.01%.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.chain import reads
from soken_review.chain.endpoints import Health
from soken_review.chain.proxy import ChainProxy

from .replay import Replay

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "chain"
VE = "0xfBBF371C9B0B994EebFcC977CEf603F7f31c070D"
THE = "0xf4c8e32eadec4bfe97e0f595add0f4450a863a11"
META = json.loads((FIX / "thena_bsc.meta.json").read_text())


def _job() -> reads.ChainJob:
    return reads.ChainJob("job_x", "evm", 56, "BNB Smart Chain Mainnet", None, VE)


@pytest.fixture(autouse=True)
def _fresh_health():
    Health.reset()
    yield
    Health.reset()


@pytest.mark.asyncio
async def test_thena_supply_double_count_and_past_supply_revert_as_facts():
    replay = Replay(FIX / "thena_bsc.json")
    async with ChainProxy(transport=replay, pace=False) as px:
        at = await reads.evm_resolve(px, _job(), "latest")
        assert at.block == META["block"]
        out = reads.Out(job=_job(), at=at)
        await reads.evm_read(px, out, [
            {"alias": "ve", "address": VE, "kind": "call", "fn": "supply()", "returns": "uint256"},
            {"alias": "ve", "address": VE, "kind": "call", "fn": "token()", "returns": "address"},
            {"alias": "ve", "address": VE, "kind": "call", "fn": "getPastTotalSupply(uint256)",
             "args": [META["past_ts"]], "returns": "uint256"}])
        bal = reads.Out(job=_job(), at=at)
        await reads.evm_balances(px, bal, THE, "the", [{"alias": "ve", "address": VE}])
    assert not replay.missing, replay.missing
    facts = {f["key"]: f for f in out.facts + bal.facts}
    supply = int(facts["chain.ve.supply"]["value"])
    held = int(facts["chain.the.balance.ve"]["value"])
    assert supply == 335304456968324627407175342
    assert held == 150473875546894119406360255
    assert supply > int(facts["chain.the.total_supply"]["value"]) > held
    assert round(supply / held, 2) == 2.23
    assert facts["chain.ve.token"]["value"] == THE
    assert facts["chain.ve.get_past_total_supply.reverted"]["value"] == "true"
    assert facts["chain.ve.get_past_total_supply.revert_reason"]["value"] == "Panic(0x11): arithmetic underflow or overflow"
    for f in facts.values():
        assert f["block"] == META["block"] and f["chain_id"] == 56 and f["network"] == "BNB Smart Chain Mainnet"
        assert f"block {META['block']:,}" in f["source"]
        assert f["origin"] == "chain_tool"
    assert facts["chain.the.symbol"]["class"] == "chain_text"


@pytest.mark.asyncio
async def test_thena_roles_team_is_a_three_of_five_safe():
    replay = Replay(FIX / "thena_bsc.json")
    async with ChainProxy(transport=replay, pace=False) as px:
        at = await reads.evm_resolve(px, _job(), "latest")
        out = reads.Out(job=_job(), at=at)
        roles = await reads.evm_roles(px, out, VE, "ve", ["team", "voter", "artProxy"])
    facts = {f["key"]: f["value"] for f in out.facts}
    assert facts["chain.ve.team"] == "0x46f99291eedf25fd5c6ae56bbfd6679d0ea3630b"
    assert facts["chain.ve.team.holder_kind"] == "safe"
    assert (facts["chain.ve.team.safe_threshold"], facts["chain.ve.team.safe_owners"]) == ("3", "5")
    assert facts["chain.ve.deployer"] == "0x993ae2b514677c7ac52baecd8871d2b362a9d693"
    assert roles["deployment"]["creation_block"] == "24435328"
    assert not roles["proxy"]


@pytest.mark.asyncio
async def test_pool_falls_back_when_a_host_has_no_state():
    """The first host answers 'missing trie node' for an old block, the next serves it, and the
    first host is skipped for that depth afterwards (health memory)."""
    import httpx

    from soken_review.chain.endpoints import Endpoint

    hits: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        hits.append(request.url.host)
        body = json.loads(request.content)
        if body["method"] == "eth_blockNumber":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": hex(1_000_000)})
        if request.url.host == "head.example":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "missing trie node"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x05"})

    eps = [Endpoint("https://head.example", keyed=False, depth="unknown"),
           Endpoint("https://deep.example", keyed=False, depth="unknown")]
    async with ChainProxy(transport=httpx.MockTransport(handler), endpoint_list=lambda f, c: eps, pace=False) as px:
        px.depth_hint = 50_000
        assert await px.evm(1, "eth_getBalance", ["0x" + "0" * 40, hex(950_000)]) == "0x05"
        hits.clear()
        assert await px.evm(1, "eth_getBalance", ["0x" + "1" * 40, hex(950_000)]) == "0x05"
    assert hits == ["deep.example"]


@pytest.mark.asyncio
async def test_every_host_failing_is_said_plainly():
    import httpx

    from soken_review.chain.endpoints import Endpoint
    from soken_review.chain.proxy import ChainUnavailable

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={})

    eps = [Endpoint("https://a.example", keyed=False), Endpoint("https://b.example", keyed=False)]
    async with ChainProxy(transport=httpx.MockTransport(handler), endpoint_list=lambda f, c: eps, pace=False) as px:
        with pytest.raises(ChainUnavailable) as exc:
            await px.evm(1, "eth_blockNumber", [])
    assert exc.value.reason == "rate_limited"
    assert exc.value.hosts == ["https://a.example", "https://b.example"]
