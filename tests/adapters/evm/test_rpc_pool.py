"""Unit tests for RpcClientPool: failover, URL redaction, and _TRANSIENT_HTTP (05 3, 09 3.6).

Security invariant: API keys embedded in the URL path, query string, or userinfo MUST
NOT appear in log output, exception messages, or the ``answered_by`` provenance field.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from soken_review.adapters.evm.rpc import (
    _TRANSIENT_HTTP,
    RpcAllEndpointsFailed,
    RpcClientPool,
    RpcError,
    _redact,
    _RpcHttpError,
)

# ---------------------------------------------------------------------------
# _redact
# ---------------------------------------------------------------------------

class TestRedact:
    def test_strips_path(self):
        assert _redact("https://host.rpc.io/SECRET") == "https://host.rpc.io"

    def test_strips_query(self):
        assert _redact("https://host.rpc.io/?apiKey=SECRET") == "https://host.rpc.io"

    def test_strips_userinfo(self):
        # user:KEY@host pattern used by some providers
        assert _redact("https://user:SECRET@host.rpc.io/") == "https://host.rpc.io"

    def test_strips_path_and_query_and_userinfo(self):
        url = "https://u:SECRET@a.quiknode.pro/KEY?extra=SECRET"
        result = _redact(url)
        assert "SECRET" not in result
        assert "KEY" not in result
        assert result == "https://a.quiknode.pro"

    def test_keeps_port(self):
        assert _redact("https://host.rpc.io:8545/KEY") == "https://host.rpc.io:8545"

    def test_invalid_returns_placeholder(self):
        assert _redact("") == "<url>"


# ---------------------------------------------------------------------------
# _TRANSIENT_HTTP membership
# ---------------------------------------------------------------------------

class TestTransientHttp:
    def test_403_is_transient(self):
        assert 403 in _TRANSIENT_HTTP

    def test_429_is_transient(self):
        assert 429 in _TRANSIENT_HTTP

    def test_500_is_transient(self):
        assert 500 in _TRANSIENT_HTTP

    def test_525_is_transient(self):
        assert 525 in _TRANSIENT_HTTP

    def test_400_is_not_transient(self):
        assert 400 not in _TRANSIENT_HTTP

    def test_404_is_not_transient(self):
        assert 404 not in _TRANSIENT_HTTP


# ---------------------------------------------------------------------------
# Helpers to build fake HTTP responses
# ---------------------------------------------------------------------------

def _ok_response(block_hex: str = "0x1234") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"jsonrpc": "2.0", "id": 1, "result": block_hex})
    return resp


def _status_response(status: int) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    req = MagicMock()

    def _raise():
        if status >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {status}", request=req, response=resp
            )
    resp.raise_for_status = _raise
    resp.json = MagicMock(return_value={})
    return resp


# ---------------------------------------------------------------------------
# RpcClientPool failover
# ---------------------------------------------------------------------------

class TestRpcClientPoolFailover:
    @pytest.mark.asyncio
    async def test_first_endpoint_answers(self):
        """Pool returns result from the first endpoint when it succeeds."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _ok_response("0xABC")
            pool = RpcClientPool(["https://host1.rpc/", "https://host2.rpc/"])
            result = await pool.block_number()
        assert result == 0xABC
        assert pool.answered_by == "https://host1.rpc"   # redacted

    @pytest.mark.asyncio
    async def test_failover_on_403(self):
        """403 from the first endpoint triggers failover to the second.

        Mocks at RpcClient method level (not httpx) to bypass the per-endpoint
        retry loop inside RpcClient._call, which would retry before giving up.
        """
        dead_resp = MagicMock()
        dead_resp.status_code = 403
        dead_exc = httpx.HTTPStatusError("HTTP 403", request=MagicMock(), response=dead_resp)

        dead_client = AsyncMock()
        dead_client._url = "https://dead.rpc/SECRET"
        dead_client.block_number = AsyncMock(side_effect=dead_exc)

        live_client = AsyncMock()
        live_client._url = "https://live.rpc/"
        live_client.block_number = AsyncMock(return_value=0x100)

        pool = RpcClientPool(["https://dead.rpc/SECRET", "https://live.rpc/"])
        pool._clients = MagicMock(return_value=[dead_client, live_client])

        result = await pool.block_number()
        assert result == 0x100
        assert pool.answered_by == "https://live.rpc"

    @pytest.mark.asyncio
    async def test_failover_on_connect_error(self):
        """Connection error on first endpoint triggers failover to the second."""
        dead_client = AsyncMock()
        dead_client._url = "https://dead.rpc/KEY"
        dead_client.block_number = AsyncMock(side_effect=httpx.ConnectError("refused"))

        live_client = AsyncMock()
        live_client._url = "https://live.rpc/"
        live_client.block_number = AsyncMock(return_value=0x200)

        pool = RpcClientPool(["https://dead.rpc/KEY", "https://live.rpc/"])
        pool._clients = MagicMock(return_value=[dead_client, live_client])

        result = await pool.block_number()
        assert result == 0x200
        assert pool.answered_by == "https://live.rpc"

    @pytest.mark.asyncio
    async def test_all_endpoints_fail_raises(self):
        """RpcAllEndpointsFailed is raised when all endpoints fail."""
        resp_a = MagicMock()
        resp_a.status_code = 403
        exc_a = httpx.HTTPStatusError("HTTP 403", request=MagicMock(), response=resp_a)

        resp_b = MagicMock()
        resp_b.status_code = 403
        exc_b = httpx.HTTPStatusError("HTTP 403", request=MagicMock(), response=resp_b)

        client_a = AsyncMock()
        client_a._url = "https://a.rpc/KEY"
        client_a.block_number = AsyncMock(side_effect=exc_a)

        client_b = AsyncMock()
        client_b._url = "https://b.rpc/"
        client_b.block_number = AsyncMock(side_effect=exc_b)

        pool = RpcClientPool(["https://a.rpc/KEY", "https://b.rpc/"])
        pool._clients = MagicMock(return_value=[client_a, client_b])

        with pytest.raises(RpcAllEndpointsFailed) as exc_info:
            await pool.block_number()

        exc = exc_info.value
        # Exception message must not contain raw key paths
        assert "KEY" not in str(exc)
        assert exc.last_status_code == 403

    @pytest.mark.asyncio
    async def test_non_transient_http_not_failed_over(self):
        """400 Bad Request (_RpcHttpError) is NOT failed over — second endpoint never tried."""
        client_a = AsyncMock()
        client_a._url = "https://a.rpc/"
        client_a.block_number = AsyncMock(side_effect=_RpcHttpError(400))

        client_b = AsyncMock()
        client_b._url = "https://b.rpc/"
        client_b.block_number = AsyncMock(return_value=0x1)  # should never be called

        pool = RpcClientPool(["https://a.rpc/", "https://b.rpc/"])
        pool._clients = MagicMock(return_value=[client_a, client_b])

        with pytest.raises(_RpcHttpError):
            await pool.block_number()

        # Second client must not have been called — no failover on non-transient
        client_b.block_number.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_rpc_error_not_failed_over(self):
        """A JSON-RPC error (200 OK + error field) is NOT failed over."""
        async def _post(url, **kw):
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            resp.json = MagicMock(return_value={
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32000, "message": "method not found"},
            })
            return resp

        with patch("httpx.AsyncClient.post", side_effect=_post):
            pool = RpcClientPool(["https://a.rpc/", "https://b.rpc/"])
            with pytest.raises(RpcError):
                await pool.block_number()


# ---------------------------------------------------------------------------
# URL redaction security: keys must not appear in logs, exceptions, or provenance
# ---------------------------------------------------------------------------

class TestUrlRedactionSecurity:
    SECRET = "TOP_SECRET_KEY_12345"

    @pytest.mark.asyncio
    async def test_key_in_path_not_in_answered_by(self):
        """API key in URL path must not appear in answered_by."""
        url_with_key = f"https://host.quiknode.pro/{self.SECRET}/"
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_ok_response("0x1")):
            pool = RpcClientPool([url_with_key])
            await pool.block_number()
        assert self.SECRET not in (pool.answered_by or "")

    @pytest.mark.asyncio
    async def test_key_in_query_not_in_answered_by(self):
        """API key in query string must not appear in answered_by."""
        url_with_key = f"https://host.rpc.io/?apiKey={self.SECRET}"
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_ok_response("0x1")):
            pool = RpcClientPool([url_with_key])
            await pool.block_number()
        assert self.SECRET not in (pool.answered_by or "")

    @pytest.mark.asyncio
    async def test_key_in_userinfo_not_in_answered_by(self):
        """API key in userinfo must not appear in answered_by."""
        url_with_key = f"https://user:{self.SECRET}@host.rpc.io/"
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_ok_response("0x1")):
            pool = RpcClientPool([url_with_key])
            await pool.block_number()
        assert self.SECRET not in (pool.answered_by or "")

    @pytest.mark.asyncio
    async def test_key_not_in_exception_when_all_fail(self, caplog):
        """Key in URL must not appear in exception message or log output when all endpoints fail."""
        url_with_key = f"https://user:{self.SECRET}@host.rpc.io/{self.SECRET}?k={self.SECRET}"

        async def _post(url, **kw):
            return _status_response(403)

        with caplog.at_level(logging.WARNING, logger="soken_review.adapters.evm.rpc"), \
             patch("httpx.AsyncClient.post", side_effect=_post):
            pool = RpcClientPool([url_with_key])
            with pytest.raises(RpcAllEndpointsFailed) as exc_info:
                await pool.block_number()

        exc_str = str(exc_info.value)
        log_text = caplog.text

        assert self.SECRET not in exc_str, f"Key found in exception: {exc_str!r}"
        assert self.SECRET not in log_text, f"Key found in log: {log_text!r}"

    @pytest.mark.asyncio
    async def test_key_not_in_log_on_failover(self, caplog):
        """Key in URL must not appear in log output during failover."""
        dead_url = f"https://dead.rpc.io/{self.SECRET}/"
        live_url = "https://live.rpc.io/"

        call_count = [0]

        async def _post(url, **kw):
            call_count[0] += 1
            if "dead" in url:
                return _status_response(403)
            return _ok_response("0x1")

        with caplog.at_level(logging.WARNING, logger="soken_review.adapters.evm.rpc"), \
             patch("httpx.AsyncClient.post", side_effect=_post):
            pool = RpcClientPool([dead_url, live_url])
            await pool.block_number()

        assert self.SECRET not in caplog.text, f"Key found in log: {caplog.text!r}"

    @pytest.mark.asyncio
    async def test_key_not_in_exception_chain(self):
        """API key must not appear in the exception's __cause__ or __context__ chain.

        httpx.HTTPStatusError embeds the endpoint URL (with key) in its message.
        The RpcClient._call must not chain from that exception so the key never
        reaches a traceback printed by logger.exception.
        """
        url_with_key = f"https://host.quiknode.pro/{self.SECRET}/"

        async def _post(url, **kw):
            return _status_response(403)

        with patch("httpx.AsyncClient.post", side_effect=_post):
            pool = RpcClientPool([url_with_key])
            with pytest.raises(RpcAllEndpointsFailed) as exc_info:
                await pool.block_number()

        exc = exc_info.value
        # Walk the full exception chain (cause + context on every node)
        seen: set[int] = set()
        node: BaseException | None = exc
        while node is not None and id(node) not in seen:
            seen.add(id(node))
            exc_text = str(node) + repr(node)
            assert self.SECRET not in exc_text, (
                f"Key found in exception chain node {type(node).__name__}: {exc_text!r}"
            )
            node = node.__cause__ or node.__context__
