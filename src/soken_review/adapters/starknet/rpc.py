"""Starknet JSON-RPC reads for chain_state (07 3, 8.1). Supervisor only.

Methods: starknet_blockNumber, starknet_getClassHashAt, starknet_getClass, all pinned to one block.
Endpoints (07 3, live 2026-10-07): publicnode, Cartridge. `SOKEN_STARKNET_RPC` overrides (09 keyed
endpoint). Licence rows are in compliance/providers.yaml (U-09): pending rows warn in development
and refuse with SOKEN_ENFORCE_LICENCES=1.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINTS = (
    "https://starknet-rpc.publicnode.com",
    "https://api.cartridge.gg/x/starknet/mainnet",
)
_TIMEOUT = httpx.Timeout(60.0)
_BACKOFF = (1.0, 2.0, 4.0)
_PROVIDERS = Path(__file__).resolve().parents[4] / "compliance" / "providers.yaml"

# Starknet RPC error codes (spec): 20 contract not found, 28 class hash not found, 24 block not found.
CONTRACT_NOT_FOUND = 20
CLASS_HASH_NOT_FOUND = 28


class StarknetRpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"starknet rpc error {code}: {message}")
        self.code = code


def licence_check(url: str) -> str | None:
    """Return a warning when the host's provider row is not cleared; raise when enforcing."""
    host = urlparse(url).hostname or ""
    try:
        rows = yaml.safe_load(_PROVIDERS.read_text()) or []
    except OSError:
        rows = []
    row = next((r for r in rows if host in (r.get("hosts") or [])), None)
    if row and row.get("clearance") == "cleared":
        return None
    msg = f"licence: starknet RPC host {host} is {row.get('clearance') if row else 'not listed'} (07 U-09)"
    if os.environ.get("SOKEN_ENFORCE_LICENCES") == "1":
        raise PermissionError(msg)
    logger.warning(msg)
    return msg


def endpoint() -> str:
    return os.environ.get("SOKEN_STARKNET_RPC") or DEFAULT_ENDPOINTS[0]


class StarknetRpc:
    """Async client; `block` is a block number once pinned, "latest" only for the pin read."""

    def __init__(self, url: str | None = None, block: int | str = "latest", *, check_licence: bool = True) -> None:
        self.url = url or endpoint()
        self.block = block
        self.licence_warning = licence_check(self.url) if check_licence else None
        self._id = 0

    def _block_id(self) -> Any:
        return {"block_number": self.block} if isinstance(self.block, int) else self.block

    async def _call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        last: Exception | None = None
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers={"user-agent": "soken-review/1"}) as client:
            for backoff in _BACKOFF:
                try:
                    resp = await client.post(self.url, json=payload)
                    if resp.status_code in (429, 502, 503, 504):
                        raise httpx.HTTPStatusError("transient", request=resp.request, response=resp)
                    resp.raise_for_status()
                    data = resp.json()
                except (httpx.TransportError, httpx.HTTPStatusError, ValueError) as exc:
                    last = exc
                    await asyncio.sleep(backoff)
                    continue
                if "error" in data:
                    err = data["error"]
                    raise StarknetRpcError(int(err.get("code", -1)), str(err.get("message", "")))
                return data["result"]
        raise ConnectionError(f"starknet rpc {method} failed: {last}")

    async def block_number(self) -> int:
        return int(await self._call("starknet_blockNumber", []))

    async def class_hash_at(self, address: str) -> str:
        return await self._call("starknet_getClassHashAt", [self._block_id(), address])

    async def get_class(self, class_hash: str) -> dict[str, Any]:
        return await self._call("starknet_getClass", [self._block_id(), class_hash])
