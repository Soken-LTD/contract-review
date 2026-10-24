"""Minimal JSON-RPC client for EVM chains (05 section 3).

Implements eth_getCode, eth_getStorageAt, eth_call, eth_blockNumber.
All reads are pinned to a specific block per 05 12.5 (chain_state 0 pin).

RpcClientPool: tries each listed endpoint in order; on a transient failure it moves to
the next.  Transient failures are: connection errors, timeouts, and HTTP responses with
status codes in ``_TRANSIENT_HTTP`` (403, 429, 5xx).  Non-transient HTTP errors (e.g.
400) are re-raised immediately.

Security (09 3.5): endpoints may carry an API key in the URL path, query string, or
userinfo (QuickNode: ``https://<name>.quiknode.pro/<KEY>/``; some providers use
``https://user:KEY@host``).  Keys must NEVER appear in logs, exception messages, or
provenance.  ``_redact(url)`` returns only ``scheme://host[:port]`` — no path, no query,
no fragment, no userinfo.  Raw ``Exception`` text is suppressed (httpx embeds the URL
in its repr); only the exception type and HTTP status code appear in log lines.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(30.0)
_MAX_RETRIES = 3
_RETRY_BACKOFF = (1.0, 2.0, 4.0)

# Sentinel for "read at latest" during chain_state 0 probe.
BLOCK_LATEST = "latest"

# HTTP status codes that are transient: failover to the next endpoint (09 3.6).
# 403 = rate-limited / IP-blocked; 429 = explicit rate limit; 5xx = server-side errors.
_TRANSIENT_HTTP = frozenset({403, 429, 500, 502, 503, 504, 525})


def _redact(url: str) -> str:
    """Return ``scheme://host[:port]`` — strip path, query, fragment, and userinfo.

    Handles all key-embedding styles:
      - path:     ``https://host/<KEY>/``      → ``https://host``
      - query:    ``https://host/?apiKey=KEY`` → ``https://host``
      - userinfo: ``https://user:KEY@host``    → ``https://host``

    Returns ``"<url>"`` if parsing fails.
    """
    try:
        p = urlparse(url)
        host = p.hostname or ""      # never includes userinfo or port
        port = p.port
        netloc = f"{host}:{port}" if port else host
        return f"{p.scheme}://{netloc}" if netloc else "<url>"
    except Exception:  # noqa: BLE001
        return "<url>"


class RpcError(Exception):
    """JSON-RPC error response."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.rpc_message = message


class _RpcHttpError(RuntimeError):
    """Non-transient HTTP error from a single RPC endpoint.

    Raised by ``RpcClient._call`` instead of re-raising ``httpx.HTTPStatusError``
    because httpx embeds the endpoint URL (with any API key) in its exception
    message.  Only the status code is kept — never the URL.

    ``RpcClientPool._try_call`` catches this to suppress failover (a 400 Bad
    Request from one endpoint will be 400 on every endpoint; no point rotating).
    """

    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


class RpcAllEndpointsFailed(Exception):
    """All endpoints in the pool failed — caller should treat this as a transient error.

    Only redacted hosts are stored; raw URLs are never embedded in the message.
    ``last_exc_type`` and ``last_status_code`` give enough context for debugging.
    """

    def __init__(self, redacted_hosts: list[str], last_exc: Exception) -> None:
        super().__init__(f"All {len(redacted_hosts)} RPC endpoint(s) failed: {redacted_hosts!r}")
        self.redacted_hosts = redacted_hosts
        # Store only the exception class name and HTTP status (if any); never the message.
        response = getattr(last_exc, "response", None)
        self.last_exc_type = type(last_exc).__name__
        self.last_status_code: int | None = getattr(response, "status_code", None)


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
        last_status: int | None = None
        host = _redact(self._url)
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            for attempt, backoff in enumerate(_RETRY_BACKOFF):
                try:
                    resp = await client.post(self._url, json=payload)
                    status = resp.status_code
                    if status in _TRANSIENT_HTTP:
                        # Transient HTTP — retry within this endpoint, then let the pool failover.
                        # Store only status code; never store the httpx exception (it embeds the URL).
                        last_status = status
                        last_exc = httpx.HTTPStatusError(
                            f"HTTP {status}", request=resp.request, response=resp
                        )
                        if attempt < len(_RETRY_BACKOFF) - 1:
                            logger.debug("RPC %s attempt %d from %s: HTTP %s; retry in %.1fs",
                                         method, attempt + 1, host, status, backoff)
                            await asyncio.sleep(backoff)
                        continue
                    if status >= 400:
                        # Non-transient HTTP: raise URL-free _RpcHttpError so _try_call can
                        # distinguish "don't failover" from network errors (which should failover).
                        # httpx.HTTPStatusError embeds the endpoint URL in its message, which
                        # would expose API keys in logs when logger.exception is called.
                        raise _RpcHttpError(status)
                    data = resp.json()
                    if "error" in data:
                        err = data["error"]
                        raise RpcError(err.get("code", -1), err.get("message", "unknown"))
                    return data["result"]
                except (RpcError, _RpcHttpError):
                    raise
                except Exception as exc:  # noqa: BLE001  (connect/timeout/etc.)
                    last_exc = exc
                    if attempt < len(_RETRY_BACKOFF) - 1:
                        logger.debug("RPC %s attempt %d from %s: %s; retry in %.1fs",
                                     method, attempt + 1, host, type(exc).__name__, backoff)
                        await asyncio.sleep(backoff)
        # Raise with only the redacted host and status/type info — never chain the raw exception
        # (httpx embeds the endpoint URL with any API key in its repr/str).
        detail = f" HTTP {last_status}" if last_status else (
            f" {type(last_exc).__name__}" if last_exc else ""
        )
        raise RuntimeError(f"RPC {method} from {host} failed after {_MAX_RETRIES} retries{detail}")

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

    async def get_balance(self, address: str, block: int | str | None = None) -> str:
        """eth_getBalance at the pinned block. Returns 0x-prefixed hex wei."""
        return await self._call("eth_getBalance", [address, self._block_tag(block)])

    async def eth_call(
        self,
        to: str,
        data: str,
        block: int | str | None = None,
        state_override: dict[str, Any] | None = None,
        gas: int | None = None,
    ) -> str:
        """eth_call at the pinned block. Returns 0x-prefixed hex output.

        state_override maps address -> {balance, nonce, code, stateDiff, state}.
        gas caps the execution gas (prevents a hostile contract consuming unbounded node resources).
        """
        tx: dict[str, Any] = {"to": to, "data": data}
        if gas is not None:
            tx["gas"] = hex(gas)
        params: list[Any] = [tx, self._block_tag(block)]
        if state_override is not None:
            params.append(state_override)
        return await self._call("eth_call", params)

    async def eth_call_probe(
        self,
        to: str,
        data: str,
        block: int | str | None = None,
        *,
        gas: int = 2_000_000,
        timeout_s: float = 5.0,
        max_response_hex_chars: int = 4096,
        min_response_bytes: int = 32,
    ) -> str | None:
        """Single-attempt eth_call for informational state probes.

        Unlike ``eth_call`` this never retries: probes are best-effort — a timeout or error
        simply means we skip that fact, not that we should stall the analysis pipeline for
        up to 3×30 s.

        Returns the 0x-prefixed hex output, or ``None`` on any error / oversized / short
        response (caller treats None as "unknown").

        Args:
            gas:                    Execution gas cap (default 2 000 000) — prevents a
                                    hostile getter from consuming unbounded node resources.
            timeout_s:              Per-call wall-clock timeout (default 5 s).
            max_response_hex_chars: Reject hex responses longer than this (default 4096 chars,
                                    ~ 2 KiB decoded) — guards against oversized blobs.
            min_response_bytes:     Require at least this many decoded bytes before we try to
                                    ABI-decode (default 32 = one uint256 slot).
        """
        tx: dict[str, Any] = {"to": to, "data": data, "gas": hex(gas)}
        params: list[Any] = [tx, self._block_tag(block)]
        payload = {"jsonrpc": "2.0", "method": "eth_call", "params": params, "id": 1}
        host = _redact(self._url)
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                resp = await client.post(self._url, json=payload)
                if resp.status_code >= 400:
                    logger.debug("probe: HTTP %d from %s", resp.status_code, host)
                    return None
                data_resp = resp.json()
                if "error" in data_resp:
                    logger.debug("probe: RPC error from %s: %s", host, str(data_resp["error"])[:80])
                    return None
                result: str = data_resp.get("result") or ""
                if not isinstance(result, str) or not result.startswith("0x"):
                    return None
                hex_body = result[2:]
                if len(hex_body) > max_response_hex_chars:
                    logger.debug("probe: response %d hex chars > cap %d, rejected", len(hex_body), max_response_hex_chars)
                    return None
                decoded_len = len(hex_body) // 2
                if decoded_len < min_response_bytes:
                    logger.debug("probe: response %d bytes < min %d, rejected", decoded_len, min_response_bytes)
                    return None
                return result
        except Exception as exc:  # noqa: BLE001
            logger.debug("probe: %s from %s: %s", "eth_call", host, type(exc).__name__)
            return None


# ---------------------------------------------------------------------------
# Multi-endpoint pool with failover (05 4.1, 09 3.6)
# ---------------------------------------------------------------------------


class RpcClientPool:
    """Try each enabled endpoint in order; fail over on transient errors.

    Transient failures: connection errors, timeouts, and HTTP responses with status
    codes in ``_TRANSIENT_HTTP`` (403, 429, 5xx).  Non-transient HTTP errors are
    re-raised without failover.

    Security: raw URLs are NEVER logged, stored in exceptions or written to provenance.
    Only the redacted host (``scheme://host[:port]``) appears in any user-facing output.
    ``answered_by`` stores the redacted host of the endpoint that responded.

    Usage::

        pool = RpcClientPool([
            "https://a.quiknode.pro/SECRET/",
            "https://b:KEY@host.rpc.io/",
        ])
        block = await pool.block_number()
        print(pool.answered_by)   # "https://a.quiknode.pro" — key and path stripped
    """

    def __init__(self, urls: list[str], block: int | str = BLOCK_LATEST) -> None:
        if not urls:
            raise ValueError("RpcClientPool requires at least one URL")
        self._urls = urls
        self._block = block
        self.answered_by: str | None = None   # redacted host set on first successful call

    def _clients(self) -> list[RpcClient]:
        return [RpcClient(url, self._block) for url in self._urls]

    async def _try_call(self, method: str, fn_name: str, *args: Any) -> Any:
        """Try each endpoint in order; return first success or raise RpcAllEndpointsFailed."""
        last_exc: Exception | None = None
        redacted_hosts: list[str] = []
        for client in self._clients():
            host = _redact(client._url)
            redacted_hosts.append(host)
            try:
                result = await getattr(client, fn_name)(*args)
                self.answered_by = host
                logger.debug("RpcClientPool: %s answered by %s", method, host)
                return result
            except RpcError:
                raise  # JSON-RPC protocol errors are deterministic; don't failover
            except _RpcHttpError:
                raise  # Non-transient HTTP (e.g. 400): same error on every endpoint; don't failover.
                       # _RpcHttpError carries only the status code — no URL leak.
            except Exception as exc:  # noqa: BLE001  (connect / timeout / network errors)
                # Transient HTTP exhausted (_call → RuntimeError) or network error → try next endpoint.
                # Log only the exception type, never the message (httpx may include the URL in it).
                logger.warning("RpcClientPool: %s %s for %s; trying next endpoint",
                               host, type(exc).__name__, method)
                last_exc = exc
        raise RpcAllEndpointsFailed(
            redacted_hosts, last_exc or RuntimeError("no endpoints tried")
        )

    async def block_number(self) -> int:
        return await self._try_call("eth_blockNumber", "block_number")

    async def get_code(self, address: str, block: int | str | None = None) -> str:
        return await self._try_call("eth_getCode", "get_code", address, block)

    async def get_storage_at(self, address: str, slot: str, block: int | str | None = None) -> str:
        return await self._try_call("eth_getStorageAt", "get_storage_at", address, slot, block)

    async def get_balance(self, address: str, block: int | str | None = None) -> str:
        return await self._try_call("eth_getBalance", "get_balance", address, block)

    async def eth_call(
        self,
        to: str,
        data: str,
        block: int | str | None = None,
        state_override: dict[str, Any] | None = None,
    ) -> str:
        return await self._try_call("eth_call", "eth_call", to, data, block, state_override)

    async def eth_call_probe(self, to: str, data: str, block: int | str | None = None, **limits: Any) -> str | None:
        """Best-effort probe: each endpoint once with the probe limits of RpcClient.eth_call_probe
        (gas cap, timeout, response size bounds); the first usable answer wins, else None."""
        for client in self._clients():
            result = await client.eth_call_probe(to, data, block, **limits)
            if result is not None:
                self.answered_by = _redact(client._url)
                return result
        return None

    def with_block(self, block: int | str) -> RpcClientPool:
        """Return a new pool pinned to *block* (shares the same URL list)."""
        return RpcClientPool(self._urls, block=block)
