"""Keyed chain hosts (thin server design section 6): keyed first, 401/403 cools the key down for an hour and the
free pool answers, and a key value never appears in a repr, a result, a fact or a log line."""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from soken_review.chain import endpoints as ep_mod
from soken_review.chain.endpoints import AUTH_COOLDOWN_S, Health, capability, endpoints, install_key_filter, keyed
from soken_review.chain.proxy import ChainProxy

ASYNC = pytest.mark.asyncio(loop_scope="session")
KEYS = {
    "SOKEN_KEY_NODEREAL": "nrKEYVALUE0000000000001", "SOKEN_KEY_DRPC": "drKEYVALUE0000000000002",
    "SOKEN_KEY_INFURA": "inKEYVALUE0000000000003", "SOKEN_KEY_ALCHEMY": "alKEYVALUE0000000000004",
    "SOKEN_KEY_HELIUS": "heKEYVALUE0000000000005", "SOKEN_KEY_TRONGRID": "trKEYVALUE0000000000006",
    "SOKEN_KEY_TONCENTER": "toKEYVALUE0000000000007",
}


@pytest.fixture
def keys(monkeypatch):
    for k, v in KEYS.items():
        monkeypatch.setenv(k, v)
    Health.reset()
    yield KEYS
    Health.reset()


def _blob(obj) -> str:
    return json.dumps(obj, default=str) + repr(obj) + str(obj)


def test_keyed_first_on_every_family(keys):
    bsc = endpoints("evm", 56)
    assert [e.provider for e in bsc[:2]] == ["nodereal", "drpc"] and all(e.keyed for e in bsc[:2])
    assert any(not e.keyed for e in bsc)   # the free pool follows
    eth = [e.provider for e in endpoints("evm", 1) if e.provider]
    assert eth == ["drpc", "infura", "alchemy"]
    assert [e.keyed for e in endpoints("solana")] == [True, False]
    assert [e.keyed for e in endpoints("tron")] == [True, False]
    assert [e.keyed for e in endpoints("ton")] == [True, False]   # a refused key falls back to keyless toncenter
    assert dict(endpoints("tron")[0].headers) == {"TRON-PRO-API-KEY": KEYS["SOKEN_KEY_TRONGRID"]}
    assert keyed("evm", 999_999) == []


def test_disabled_providers_are_never_used(keys, monkeypatch):
    monkeypatch.setenv("SOKEN_KEY_TONAPI", "tapiKEYVALUE000000000")
    monkeypatch.setenv("SOKEN_KEY_QUICKNODE", "qnKEYVALUE00000000000")
    assert not any(e.provider in ("tonapi", "quicknode", "chainstack") for fam in ("ton", "evm")
                   for e in endpoints(fam, 1))


def test_no_key_in_repr_host_or_capability(keys):
    for fam, cid in (("evm", 1), ("evm", 56), ("solana", None), ("tron", None), ("ton", None)):
        eps = endpoints(fam, cid)
        text = _blob([repr(e) for e in eps]) + _blob([e.host for e in eps]) + _blob(capability(fam, cid).as_dict())
        text += _blob([e.health_key for e in eps])
        for v in KEYS.values():
            assert v not in text, (fam, v)


def test_supervisor_pool_is_the_chain_tool_pool(keys, monkeypatch):
    from soken_review.worker.supervisor import _rpc_urls

    monkeypatch.delenv("SOKEN_RPC_56", raising=False)
    urls = _rpc_urls(56)
    assert urls[0].startswith("https://bsc-mainnet.nodereal.io/v1/") and len(urls) > 2


def _transport(seen: list[str]):
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if "nodereal" in request.url.host or "drpc" in request.url.host:
            return httpx.Response(403, content=b"")        # geo-blocked or revoked key: empty-body 403
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x10"})
    return httpx.MockTransport(handle)


@ASYNC
async def test_auth_failure_cools_the_key_down_and_the_free_pool_answers(keys, caplog):
    install_key_filter()
    seen: list[str] = []
    caplog.set_level(logging.DEBUG)
    async with ChainProxy(pace=False, transport=_transport(seen)) as proxy:
        res = await proxy.evm(56, "eth_blockNumber", [])
        assert res == "0x10"
        first = list(seen)
        assert "nodereal" in first[0]
        keyed_eps = [e for e in endpoints("evm", 56) if e.keyed]
        for e in keyed_eps:
            assert Health.cool_until[e.health_key] - __import__("time").monotonic() > AUTH_COOLDOWN_S - 60
        seen.clear()
        await proxy.evm(56, "eth_chainId", [])
        assert "nodereal" not in seen[0] and "drpc.live" not in seen[0]   # cooled keys go last
        meter = _blob(proxy.meter.__dict__)
    logging.getLogger("soken_review.test").warning("probe %s", endpoints("evm", 56)[0].url)
    logs = caplog.text + "".join(r.getMessage() for r in caplog.records)
    for v in KEYS.values():
        assert v not in logs and v not in meter
    assert "***" in logs


def test_log_filter_masks_any_loaded_key(keys, caplog):
    install_key_filter()
    caplog.set_level(logging.INFO)
    logging.getLogger("soken_review.anything").info("url=%s", "https://x/" + KEYS["SOKEN_KEY_INFURA"])
    assert KEYS["SOKEN_KEY_INFURA"] not in caplog.text and "***" in caplog.text
    assert ep_mod.mask_keys(KEYS["SOKEN_KEY_HELIUS"]) == "***"
