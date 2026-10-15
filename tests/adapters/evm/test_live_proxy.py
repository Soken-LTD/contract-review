"""Live proxy patterns 6 (Safe) and 7 (EIP-2535 diamond) on mainnet (05 section 5, UV5-07).

    uv run pytest -m live tests/adapters/evm/test_live_proxy.py -v

Cases (E-DEPLOY "Safe" and "diamond" rows):
  Safe 1.1.1  ETH  0xF529d79e96358d47455451dDC2a2a60BB0CE9e46
  Safe 1.3.0  ETH  0xac1ee53F3C590A78e9E322066a30C6c0E237E45a, Base 0xE840141570f3C1dd23fD6718A6dec9f33EE80cf7
  Safe 1.4.1  ETH  0xC3F92E082bcCBC51470b05312dfdB9304Ad11873, Base 0xC0c894CbDeE763D2bCC1616eFE89d64662938F82
  Diamond     ETH and Base  0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE (LI.FI)
  Negatives   USDC (pattern 5), WETH9 (not a proxy)
"""

from __future__ import annotations

import asyncio

import pytest

from soken_review.adapters.evm.proxy import (
    detect_proxy,
    read_proxy_authority,
    read_proxy_calls,
    read_proxy_slots,
)
from soken_review.adapters.evm.registry import get_chain
from soken_review.adapters.evm.rpc import RpcClient

# The registry RPCs first; publicnode as a read-only fallback (09 allowlist row pending).
_FALLBACK = {1: "https://ethereum-rpc.publicnode.com", 8453: "https://base-rpc.publicnode.com"}


async def _detect(chain_id: int, address: str):
    chain = get_chain(chain_id)
    assert chain is not None
    urls = [r.url for r in chain.rpc] + [_FALLBACK[chain_id]]
    last: Exception | None = None
    for url in urls:
        try:
            rpc = RpcClient(url, block=await RpcClient(url).block_number())
            code = await rpc.get_code(address)
            result = detect_proxy(code, await read_proxy_slots(rpc, address), await read_proxy_calls(rpc, address))
            return result, await read_proxy_authority(rpc, address, result)
        except Exception as exc:  # noqa: BLE001
            last = exc
    pytest.skip(f"all RPCs for chain {chain_id} unavailable: {last}")


@pytest.mark.live
@pytest.mark.parametrize(
    ("chain_id", "address", "version"),
    [
        (1, "0xF529d79e96358d47455451dDC2a2a60BB0CE9e46", "1.1.1"),
        (1, "0xac1ee53F3C590A78e9E322066a30C6c0E237E45a", "1.3.0"),
        (1, "0xC3F92E082bcCBC51470b05312dfdB9304Ad11873", "1.4.1"),
        (8453, "0xE840141570f3C1dd23fD6718A6dec9f33EE80cf7", "1.3.0"),
        (8453, "0xC0c894CbDeE763D2bCC1616eFE89d64662938F82", "1.4.1"),
    ],
)
def test_safe_proxy_live(chain_id: int, address: str, version: str):
    result, auth = asyncio.run(_detect(chain_id, address))
    assert result.pattern == 6
    assert result.extra["safe_version"] == version
    assert result.implementation is not None  # singleton from slot 0
    assert auth.get("owners"), auth
    assert 1 <= auth["threshold"] <= len(auth["owners"])
    assert isinstance(auth["modules"], list)


@pytest.mark.live
def test_uninitialized_safe_live():
    """A Safe proxy whose setup() never ran: pattern 6, threshold 0, initialized False, owners unread."""
    result, auth = asyncio.run(_detect(8453, "0x9779c9C849F47a746eB777Acb7Df7bF73A54ecDc"))
    assert result.pattern == 6
    assert auth["threshold"] == 0 and auth["initialized"] is False
    assert auth["owners"] is None and auth["errors"]


@pytest.mark.live
@pytest.mark.parametrize("chain_id", [1, 8453])
def test_lifi_diamond_live(chain_id: int):
    result, auth = asyncio.run(_detect(chain_id, "0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE"))
    assert result.pattern == 7
    assert len(result.extra["facets"]) >= 5
    assert result.extra["diamond_cut_present"] is True
    assert auth["owner"] and auth["owner"] != "0x" + "0" * 40


@pytest.mark.live
@pytest.mark.parametrize(
    ("address", "pattern"),
    [("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 5), ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", None)],
)
def test_non_safe_non_diamond_live(address: str, pattern: int | None):
    result, _ = asyncio.run(_detect(1, address))
    assert result.pattern == pattern
