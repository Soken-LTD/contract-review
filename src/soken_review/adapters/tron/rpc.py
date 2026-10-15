"""TronGrid HTTP client (05 sections 4.2 TRON, 12.5, F25, F26, F41).

TronGrid native API:
  POST /wallet/getcontract        - creation bytecode + contract metadata (F25)
  POST /wallet/getcontractinfo    - runtimecode (F25)
  GET  /wallet/getchainparameters - chain parameters #13, #60, etc. (F41)

JSON-RPC (at /jsonrpc):
  eth_getCode, eth_getStorageAt, eth_call at 'latest' only (F26)

Window logic (12.5):
  TronGrid serves only 'latest', so every read batch runs twice.
  When all values match, record block_window = [first_block_batch1, last_block_batch2].
  On mismatch: up to 3 retries, then not_checkable(state_changed_during_read).

Rate limiting: limits.yaml outbound.trongrid (R4, default 2 req/s).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import httpx

from soken_review.adapters.tron.address import to_wire_hex

logger = logging.getLogger(__name__)

TRONGRID_BASE = "https://api.trongrid.io"
TRONGRID_JSONRPC = f"{TRONGRID_BASE}/jsonrpc"

_TIMEOUT = httpx.Timeout(30.0)
_MAX_RETRIES = 3
_RETRY_BACKOFF = (1.0, 2.0, 4.0)
_RATE_PER_S = 2.0  # outbound.trongrid (R4, limits.yaml)

# Optional API key — production uses TRON_GRID_API_KEY env var
_TRONGRID_API_KEY = os.environ.get("TRON_GRID_API_KEY", "")


class TronGridError(Exception):
    """TronGrid API error."""


class _RateLimiter:
    """Simple token-bucket rate limiter, 2 req/s (R4)."""

    def __init__(self, per_s: float = _RATE_PER_S) -> None:
        self._per_s = per_s
        self._last: float = 0.0

    async def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        gap = 1.0 / self._per_s
        if elapsed < gap:
            await asyncio.sleep(gap - elapsed)
        self._last = time.monotonic()


_rate = _RateLimiter()


def _headers() -> dict[str, str]:
    h: dict[str, str] = {"Accept": "application/json"}
    if _TRONGRID_API_KEY:
        h["TRON-PRO-API-KEY"] = _TRONGRID_API_KEY
    return h


async def _post(client: httpx.AsyncClient, url: str, body: dict) -> dict:
    """POST with retries and rate-limiting (R4)."""
    last_exc: Exception | None = None
    for attempt, backoff in enumerate(_RETRY_BACKOFF):
        try:
            await _rate.wait()
            resp = await client.post(url, json=body, headers=_headers())
            if resp.status_code == 429:
                logger.warning("TronGrid 429 rate limit; waiting %ss", backoff * 4)
                await asyncio.sleep(backoff * 4)
                continue
            resp.raise_for_status()
            data = resp.json()
            if "Error" in data:
                raise TronGridError(f"TronGrid error: {data['Error']}")
            return data
        except TronGridError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < len(_RETRY_BACKOFF) - 1:
                await asyncio.sleep(backoff)
    raise TronGridError(f"TronGrid POST {url} failed after {_MAX_RETRIES} retries") from last_exc


async def _get(client: httpx.AsyncClient, url: str) -> dict:
    """GET with retries and rate-limiting (R4)."""
    last_exc: Exception | None = None
    for attempt, backoff in enumerate(_RETRY_BACKOFF):
        try:
            await _rate.wait()
            resp = await client.get(url, headers=_headers())
            if resp.status_code == 429:
                await asyncio.sleep(backoff * 4)
                continue
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < len(_RETRY_BACKOFF) - 1:
                await asyncio.sleep(backoff)
    raise TronGridError(f"TronGrid GET {url} failed after {_MAX_RETRIES} retries") from last_exc


async def _jsonrpc(client: httpx.AsyncClient, method: str, params: list) -> Any:
    """JSON-RPC call via TronGrid /jsonrpc (F26, latest only)."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last_exc: Exception | None = None
    for attempt, backoff in enumerate(_RETRY_BACKOFF):
        try:
            await _rate.wait()
            resp = await client.post(TRONGRID_JSONRPC, json=payload, headers=_headers())
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                err = data["error"]
                raise TronGridError(f"JSON-RPC error {err.get('code')}: {err.get('message')}")
            return data.get("result")
        except TronGridError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < len(_RETRY_BACKOFF) - 1:
                await asyncio.sleep(backoff)
    raise TronGridError(f"TronGrid jsonrpc {method} failed") from last_exc


class TronGridClient:
    """Async TronGrid client (05 4.2, 12.5, F25, F26, F41).

    All native API calls accept the 20-byte internal hex address; this client
    converts to the 0x41-prefixed 21-byte wire format transparently.
    """

    def __init__(self, base_url: str = TRONGRID_BASE) -> None:
        self._base = base_url.rstrip("/")

    def _wire(self, internal_hex: str) -> str:
        """Convert 20-byte internal hex to 21-byte wire hex (0x41-prefixed)."""
        return to_wire_hex(internal_hex)

    async def get_contract(self, internal_hex: str) -> dict:
        """POST /wallet/getcontract — creation bytecode + metadata (F25).

        Returns: bytecode, origin_address, consume_user_resource_percent, origin_energy_limit
        """
        url = f"{self._base}/wallet/getcontract"
        body = {"value": self._wire(internal_hex), "visible": False}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            return await _post(client, url, body)

    async def get_contract_info(self, internal_hex: str) -> dict:
        """POST /wallet/getcontractinfo — runtimecode (F25).

        Returns: runtimecode (hex), plus abi, energy/resource settings
        """
        url = f"{self._base}/wallet/getcontractinfo"
        body = {"value": self._wire(internal_hex), "visible": False}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            return await _post(client, url, body)

    async def get_chain_parameters(self) -> list[dict]:
        """GET /wallet/getchainparameters — returns list of {key, value} (F41).

        Key index #13 = getMaxCpuTimeOfOneTx (default 80).
        Key index #60 = getAllowTvmCompatibleEvm (may be absent; absent means 0).
        """
        url = f"{self._base}/wallet/getchainparameters"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            data = await _get(client, url)
        return data.get("chainParameter", [])

    async def eth_block_number(self) -> int:
        """JSON-RPC eth_blockNumber (latest only, F26)."""
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            result = await _jsonrpc(client, "eth_blockNumber", [])
        if result is None:
            raise TronGridError("eth_blockNumber returned null")
        return int(result, 16)

    async def eth_get_code(self, address_hex: str) -> str:
        """JSON-RPC eth_getCode at latest (F26). address_hex: 0x-prefixed 20-byte hex."""
        # TronGrid JSON-RPC uses 0x + 40-char hex or 0x41-prefixed (42-char hex)
        # Use the internal 20-byte hex with 0x prefix
        addr = "0x" + address_hex.lower().lstrip("0x")
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            result = await _jsonrpc(client, "eth_getCode", [addr, "latest"])
        return result or "0x"


# ---------------------------------------------------------------------------
# Window logic (05 12.5)
# ---------------------------------------------------------------------------

_WINDOW_MAX_RETRIES = 3


async def read_with_window(
    reads_fn: Any,  # async callable returning dict[str, Any]
    client: TronGridClient,
) -> tuple[dict[str, Any], tuple[int, int]]:
    """Run reads_fn twice; return (values, (first_block, last_block)) when stable.

    Per 12.5: every TRON read batch runs twice; when all values match, record
    block_window = [first block of batch 1, last block of batch 2].
    On mismatch: up to 3 retries, then raise TronGridWindowError.
    """
    for attempt in range(_WINDOW_MAX_RETRIES):
        block_before = await client.eth_block_number()
        values1: dict[str, Any] = await reads_fn()
        # Capture a block number between the two reads so the window spans
        # [first_block_batch1 .. last_block_batch2] per plan 12.5.
        await client.eth_block_number()
        values2: dict[str, Any] = await reads_fn()
        block_after = await client.eth_block_number()

        # All values must match
        if values1.keys() == values2.keys() and all(values1[k] == values2[k] for k in values1):
            return values1, (block_before, block_after)

        logger.warning(
            "TRON window mismatch on attempt %d/%d; keys differ: %s",
            attempt + 1,
            _WINDOW_MAX_RETRIES,
            {k for k in (values1.keys() | values2.keys()) if values1.get(k) != values2.get(k)},
        )
        if attempt < _WINDOW_MAX_RETRIES - 1:
            await asyncio.sleep(2 ** attempt)

    raise TronGridWindowError("state_changed_during_read")


class TronGridWindowError(TronGridError):
    """TRON window retries exhausted (12.5 not_checkable state_changed_during_read)."""
