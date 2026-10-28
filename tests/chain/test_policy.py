"""The proxy refuses every send and broadcast family, before anything goes upstream (design 3.3)."""

from __future__ import annotations

import json

import httpx
import pytest

from soken_review.chain import policy
from soken_review.chain.proxy import ChainProxy, asgi_app

EVM_SENDS = policy.EVM_DENIED_EXAMPLES
TRON_SENDS = policy.TRON_DENIED_EXAMPLES
SOL_SENDS = policy.SOLANA_DENIED_EXAMPLES
TON_SENDS = policy.TON_DENIED_EXAMPLES


@pytest.mark.parametrize("method", EVM_SENDS)
def test_evm_send_family_denied(method):
    with pytest.raises(policy.ProxyDenied) as exc:
        policy.check_evm(method, ["0x00"])
    assert exc.value.code == -32601


def test_evm_allowlist_never_holds_a_send():
    for m in policy.EVM_ALLOWED:
        assert not any(w in m.lower() for w in ("send", "sign", "personal", "wallet", "admin", "miner", "anvil", "evm_"))


@pytest.mark.parametrize("method", ["eth_call", "eth_getBalance", "eth_getStorageAt", "eth_blockNumber", "eth_getCode"])
def test_evm_reads_allowed(method):
    params = {"eth_call": [{"to": "0x" + "1" * 40, "data": "0x"}, "0x10"], "eth_getStorageAt": ["0x" + "1" * 40, "0x0", "0x10"],
              "eth_blockNumber": []}.get(method, ["0x" + "1" * 40, "0x10"])
    policy.check_evm(method, params)


def test_batch_with_one_send_is_refused_whole():
    batch = [{"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
             {"jsonrpc": "2.0", "id": 2, "method": "eth_sendRawTransaction", "params": ["0x02"]}]
    with pytest.raises(policy.ProxyDenied):
        policy.check_evm_payload(batch)


def test_block_pin_refuses_later_blocks_and_tags():
    good = [{"to": "0x" + "1" * 40, "data": "0x"}, hex(100)]
    policy.check_evm("eth_call", good, max_block=100)
    for tag in (hex(101), "latest", "pending", {"blockHash": "0x" + "0" * 64}):
        with pytest.raises(policy.ProxyDenied):
            policy.check_evm("eth_call", [good[0], tag], max_block=100)


def test_get_logs_needs_address_and_bounded_range():
    with pytest.raises(policy.ProxyDenied):
        policy.check_evm("eth_getLogs", [{"fromBlock": "0x1", "toBlock": "0x2"}])
    with pytest.raises(policy.ProxyDenied):
        policy.check_evm("eth_getLogs", [{"address": "0x" + "1" * 40, "fromBlock": "0x0", "toBlock": hex(policy.MAX_LOG_RANGE + 1)}])
    policy.check_evm("eth_getLogs", [{"address": "0x" + "1" * 40, "fromBlock": "0x0", "toBlock": hex(1000)}])


@pytest.mark.parametrize("path", TRON_SENDS)
def test_tron_broadcast_family_denied(path):
    with pytest.raises(policy.ProxyDenied):
        policy.check_tron(path, "POST", {})


def test_tron_jsonrpc_send_denied_and_reads_allowed():
    with pytest.raises(policy.ProxyDenied):
        policy.check_tron("/jsonrpc", "POST", {"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": []})
    policy.check_tron("/jsonrpc", "POST", {"jsonrpc": "2.0", "id": 1, "method": "eth_getStorageAt", "params": []})
    policy.check_tron("/wallet/triggerconstantcontract", "POST", {})
    with pytest.raises(policy.ProxyDenied):
        policy.check_tron("/wallet/triggerconstantcontract", "GET")


@pytest.mark.parametrize("method", SOL_SENDS)
def test_solana_send_family_denied(method):
    with pytest.raises(policy.ProxyDenied):
        policy.check_solana(method, [])


@pytest.mark.parametrize("method", TON_SENDS)
def test_ton_send_family_denied_direct_and_through_jsonrpc(method):
    with pytest.raises(policy.ProxyDenied):
        policy.check_ton(method, {})
    with pytest.raises(policy.ProxyDenied):
        policy.check_ton("jsonRPC", {"method": method, "params": {}})


def test_sourcify_only_the_fixed_deployment_path():
    policy.check_sourcify(f"/server/v2/contract/1/0x{'a' * 40}?fields=deployment")
    for p in ("/server/v2/verify/1/0x" + "a" * 40, "/server/v2/contract/1/0xa?fields=all"):
        with pytest.raises(policy.ProxyDenied):
            policy.check_sourcify(p)


class _Count(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.calls = 0

    async def handle_async_request(self, request):
        self.calls += 1
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x1"})


@pytest.mark.asyncio
async def test_proxy_methods_never_send_denied_requests_upstream():
    t = _Count()
    async with ChainProxy(transport=t) as px:
        for m in EVM_SENDS:
            with pytest.raises(policy.ProxyDenied):
                await px.evm(1, m, ["0x02"])
        for p in TRON_SENDS:
            with pytest.raises(policy.ProxyDenied):
                await px.tron(p, {})
        for m in SOL_SENDS:
            with pytest.raises(policy.ProxyDenied):
                await px.solana(m, [])
        for m in TON_SENDS:
            with pytest.raises(policy.ProxyDenied):
                await px.ton(m, {})
    assert t.calls == 0


@pytest.mark.asyncio
async def test_http_proxy_answers_minus_32601_for_every_send():
    t = _Count()
    app = asgi_app(1, max_block=100, proxy_factory=lambda: ChainProxy(transport=t))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://rpc-proxy") as client:
        for m in EVM_SENDS:
            r = await client.post("/", json={"jsonrpc": "2.0", "id": 7, "method": m, "params": ["0x02"]})
            assert r.json()["error"]["code"] == -32601, m
        r = await client.post("/", json=[{"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
                                         {"jsonrpc": "2.0", "id": 2, "method": "eth_sendRawTransaction", "params": ["0x"]}])
        assert r.json()["error"]["code"] == -32601
        r = await client.post("/", content=json.dumps({"jsonrpc": "2.0", "id": 3, "method": "eth_call",
                                                       "params": [{"to": "0x" + "1" * 40}, "latest"]}))
        assert r.json()["error"]["code"] == -32601   # latest is after the pinned block 100
    assert t.calls == 0
