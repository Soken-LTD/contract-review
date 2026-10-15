"""Minimal JSON-RPC client for EVM chains (05 section 3).

Implements eth_getCode, eth_getStorageAt, eth_call, eth_blockNumber.
All reads are pinned to a specific block per 05 12.5 (chain_state 0 pin).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(30.0)
_MAX_RETRIES = 3
_RETRY_BACKOFF = (1.0, 2.0, 4.0)

# Sentinel for "read at latest" during chain_state 0 probe.
BLOCK_LATEST = "latest"


class RpcError(Exception):
    """JSON-RPC error response."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.rpc_message = message


class RpcClient:
    """Single-endpoint async JSON-RPC client pinned to a block (05 3).

    All methods accept an optional `block` override; if omitted the client
    uses the block set at construction time (or BLOCK_LATEST).
    """

    def __init__(self, url: str, block: int | str = BLOCK_LATEST) -> None:
        self._url = url
        self._block = block
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _block_tag(self, block: int | str | None) -> str:
        b = block if block is not None else self._block
        if isinstance(b, int):
            return hex(b)
        return b

    async def _call(self, method: str, params: list[Any]) -> Any:
        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method, "params": params}
        last_exc: Exception | None = None
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            for attempt, backoff in enumerate(_RETRY_BACKOFF):
                try:
                    resp = await client.post(self._url, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    if "error" in data:
                        err = data["error"]
                        raise RpcError(err.get("code", -1), err.get("message", "unknown"))
                    return data["result"]
                except RpcError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    if attempt < len(_RETRY_BACKOFF) - 1:
                        logger.debug("RPC %s attempt %d failed: %s; retry in %.1fs", method, attempt + 1, exc, backoff)
                        await asyncio.sleep(backoff)
        raise RuntimeError(f"RPC {method} failed after {_MAX_RETRIES} retries") from last_exc

    async def block_number(self) -> int:
        """eth_blockNumber — returns the latest block number."""
        result = await self._call("eth_blockNumber", [])
        return int(result, 16)

    async def get_code(self, address: str, block: int | str | None = None) -> str:
        """eth_getCode at the pinned block. Returns 0x-prefixed hex string."""
        return await self._call("eth_getCode", [address, self._block_tag(block)])

    async def get_storage_at(self, address: str, slot: str, block: int | str | None = None) -> str:
        """eth_getStorageAt at the pinned block. slot is 0x-prefixed 32-byte hex."""
        return await self._call("eth_getStorageAt", [address, slot, self._block_tag(block)])

    async def eth_call(
        self,
        to: str,
        data: str,
        block: int | str | None = None,
        state_override: dict[str, Any] | None = None,
    ) -> str:
        """eth_call at the pinned block. Returns 0x-prefixed hex output.

        state_override maps address -> {balance, nonce, code, stateDiff, state}.
        """
        params: list[Any] = [{"to": to, "data": data}, self._block_tag(block)]
        if state_override is not None:
            params.append(state_override)
        return await self._call("eth_call", params)
