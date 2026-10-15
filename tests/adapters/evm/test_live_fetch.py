"""Live integration tests for EVM source fetch (05 section 4.2).

These tests hit the real Sourcify v2 API and require network access.
They are skipped by default; run with:
  uv run pytest -m live tests/adapters/evm/test_live_fetch.py -v

Live contracts tested (05 17 E-DEPLOY):
  GBLIN     Base 8453  0xc2181d975c05c8c724b334bcED0764c0b86B1D53  (own fixture E-OWN)
  USDC      ETH  1     0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48  (ZeppelinOS proxy, F11)
  WETH9     ETH  1     0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
  USDT      ETH  1     0xdAC17F958D2ee523a2206206994597C13D831ec7
  Uniswap V2 Factory ETH 1  0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6F
"""

from __future__ import annotations

import asyncio

import pytest

from soken_review.adapters.evm.fetch import fetch_source
from soken_review.adapters.evm.proxy import detect_proxy, read_proxy_slots
from soken_review.adapters.evm.registry import get_chain
from soken_review.adapters.evm.rpc import RpcClient


@pytest.mark.live
def test_gblin_base_sourcify():
    """GBLIN on Base chain 8453 must be found on Sourcify (E-OWN, F8)."""
    candidates = asyncio.run(
        fetch_source(
            chain_id=8453,
            address="0xc2181d975c05c8c724b334bcED0764c0b86B1D53",
            runtime_bytecode="0x",
        )
    )
    assert len(candidates) >= 1
    sourcify_cands = [c for c in candidates if c.provider == "sourcify"]
    assert len(sourcify_cands) >= 1
    cand = sourcify_cands[0]
    assert cand.sourcify_match in ("exact_match", "match")
    assert cand.compiler is not None
    assert "0.8.37" in cand.compiler.version
    assert len(cand.files) >= 1


@pytest.mark.live
def test_usdc_sourcify():
    """USDC on Ethereum must be found on Sourcify."""
    candidates = asyncio.run(
        fetch_source(
            chain_id=1,
            address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            runtime_bytecode="0x",
        )
    )
    assert len(candidates) >= 1
    assert any(c.provider == "sourcify" for c in candidates)


@pytest.mark.live
def test_weth9_sourcify():
    """WETH9 on Ethereum must be found on Sourcify."""
    candidates = asyncio.run(
        fetch_source(
            chain_id=1,
            address="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            runtime_bytecode="0x",
        )
    )
    assert len(candidates) >= 1


@pytest.mark.live
def test_usdc_proxy_detection():
    """USDC proxy slots: ZeppelinOS pattern (F11, F39).

    Uses public Ethereum RPC to read storage slots at latest block.
    Tries all configured RPCs in order; skips if all are unavailable.
    """
    chain = get_chain(1)
    assert chain is not None

    async def _run() -> None:
        last_exc: Exception | None = None
        for rpc_entry in chain.rpc:
            rpc = RpcClient(rpc_entry.url)
            try:
                block = await rpc.block_number()
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue
            assert block > 20_000_000  # sanity check
            code = await rpc.get_code("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
            slots = await read_proxy_slots(rpc, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
            result = detect_proxy(code, slots)
            # USDC is ZeppelinOS proxy (F11) — implementation slot holds the FiatTokenV2 address
            assert result.pattern == 5
            assert result.pattern_name == "zeppelinos"
            assert result.implementation is not None
            # Admin is 0x807a96288A1A408dBC13DE2b1d087d10356395d2 (F39)
            assert result.admin is not None
            assert "807a96288" in result.admin.lower()
            return  # success
        pytest.skip(f"all Ethereum RPCs unavailable: {last_exc}")

    asyncio.run(_run())


@pytest.mark.live
def test_uniswap_v2_factory_sourcify():
    """Uniswap V2 Factory on Ethereum is in Sourcify (UV5-30 E-DEPLOY set)."""
    candidates = asyncio.run(
        fetch_source(
            chain_id=1,
            address="0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6F",
            runtime_bytecode="0x",
        )
    )
    assert len(candidates) >= 1
