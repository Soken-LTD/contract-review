"""The chain proxy: the single choke point for every chain read (chain access design 3.3, 2.2).

Each request is checked by `policy` before anything is sent (default deny; every send and
broadcast family is refused), answered from the cache when it can be, else sent to the
endpoints of `endpoints` in order (keyed first, keyless last) with failover, per-host pacing and
a per-call meter. Endpoint URLs are never returned or logged; only the redacted host is.

`asgi_app(...)` exposes the same checks as an HTTP JSON-RPC endpoint (EVM) for a sandboxed
consumer such as the fork simulation of a later phase; it holds the provider keys, the consumer
never does.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar, Self

import httpx

from . import policy
from .endpoints import Endpoint, Health, endpoints, ordered

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(15.0)
MAX_RESPONSE_BYTES = 512 * 1024
_TRANSIENT_HTTP = frozenset({403, 408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 530})
# EVM error text of a node that pruned the state of the requested block (geth, erigon, publicnode).
SOURCIFY = "https://sourcify.dev"
_NO_STATE = ("missing trie node", "header not found", "archive", "pruned", "state is not available",
             "state histories haven't been fully indexed", "unknown block", "historical state")
_RATE_HINTS = ("rate limit", "too many requests", "upgrade to paid", "limit exceeded", "capacity")


class ChainUnavailable(Exception):
    """No endpoint answered. `reason` is one of `archive` (no endpoint holds the state of that
    block), `rate_limited`, `upstream`; `hosts` are redacted."""

    def __init__(self, reason: str, hosts: list[str], detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}"[:200])
        self.reason = reason
        self.hosts = hosts
        self.detail = detail[:200]


class RpcFailure(Exception):
    """A deterministic JSON-RPC error (the same on every endpoint), for example an eth_call revert
    (`data` carries the revert bytes as hex)."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"{code}: {message}"[:200])
        self.code = code
        self.message = message[:200]
        self.data = data


class Meter:
    """Upstream calls and bytes of one tool call; over the cap the proxy stops (E_CHAIN_BUDGET path)."""

    def __init__(self, max_calls: int = 400, max_bytes: int = 8 * 1024 * 1024) -> None:
        self.calls = 0
        self.cached = 0
        self.bytes = 0
        self.failed_upstream = 0
        self.max_calls = max_calls
        self.max_bytes = max_bytes
        self.answered_by: set[str] = set()

    def charge(self, n_bytes: int) -> None:
        self.calls += 1
        self.bytes += n_bytes
        if self.calls > self.max_calls or self.bytes > self.max_bytes:
            raise ChainUnavailable("budget", [], "per-call upstream cap reached")


CacheGet = Callable[[str], Awaitable[Any | None]]
CachePut = Callable[[str, Any, bool, str, bool], Awaitable[None]]   # key, value, durable, operator, trusted


class _Pace:
    _last: ClassVar[dict[str, float]] = {}
    _locks: ClassVar[dict[str, asyncio.Lock]] = {}   # bounded by hosts x loops of the process

    @classmethod
    async def wait(cls, host: str, per_s: float) -> None:
        # one lock per event loop and host: an asyncio.Lock is bound to the loop that first waits on it
        lock = cls._locks.setdefault(f"{id(asyncio.get_running_loop())}:{host}", asyncio.Lock())
        async with lock:
            gap = 1.0 / max(per_s, 0.1)
            now = time.monotonic()
            delay = cls._last.get(host, 0.0) + gap - now
            if delay > 0:
                await asyncio.sleep(delay)
            cls._last[host] = time.monotonic()


def cache_key(family: str, chain: str | int | None, method: str, params: Any) -> str:
    blob = json.dumps([family, str(chain), method, params], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


class ChainProxy:
    """One instance per tool call (its meter is that call's)."""

    def __init__(self, *, meter: Meter | None = None, cache_get: CacheGet | None = None,
                 cache_put: CachePut | None = None, transport: httpx.AsyncBaseTransport | None = None,
                 endpoint_list: Callable[[str, int | None], list[Endpoint]] = endpoints, pace: bool = True) -> None:
        self.meter = meter or Meter()
        self._cache_get = cache_get
        self._cache_put = cache_put
        self._transport = transport
        self._endpoints = endpoint_list
        self._pace = pace   # off only for recorded-answer tests; every live call is paced per host
        self._client: httpx.AsyncClient | None = None
        self.depth_hint: int | None = None   # blocks behind the head of the call's resolved block

    async def __aenter__(self) -> Self:
        self._client = httpx.AsyncClient(timeout=_TIMEOUT, transport=self._transport,
                                         headers={"User-Agent": "contract-review/1"})
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── cache ──────────────────────────────────────────────────────────────

    async def _cached(self, key: str) -> Any | None:
        if self._cache_get is None:
            return None
        try:
            hit = await self._cache_get(key)
        except Exception as exc:  # noqa: BLE001  # a cache fault is a miss, never a failed read
            logger.info("chain cache get failed: %s", type(exc).__name__)
            return None
        if hit is not None:
            self.meter.cached += 1
        return hit

    async def _store(self, key: str, value: Any, durable: bool, ep: Endpoint) -> None:
        """`durable` asks for the shared cache; the cache shares an answer only when two different
        operators of the curated pool agreed on it or the host is operator-configured (keyed), else
        it stays per job. An unknown host passes no operator and never counts."""
        if self._cache_put is None:
            return
        try:
            await self._cache_put(key, value, durable, ep.operator or "", ep.keyed)
        except Exception as exc:  # noqa: BLE001
            logger.info("chain cache put failed: %s", type(exc).__name__)

    # ── transport ──────────────────────────────────────────────────────────

    async def _send(self, ep: Endpoint, method: str, url: str, body: Any | None) -> tuple[int, Any]:
        """One request. The body is streamed: a Content-Length over MAX_RESPONSE_BYTES is refused
        before reading, and reading stops at the cap; the meter is charged with the bytes read."""
        assert self._client is not None, "use ChainProxy as an async context manager"
        if self._pace:
            await _Pace.wait(ep.host, ep.per_s)
        headers = dict(ep.headers)
        kwargs: dict[str, Any] = {"headers": headers} if method == "GET" else {"headers": headers, "json": body}
        async with self._client.stream(method, url, **kwargs) as resp:
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                self.meter.charge(0)
                raise ChainUnavailable("upstream", [ep.host], "response over the size cap")
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    self.meter.charge(size)
                    raise ChainUnavailable("upstream", [ep.host], "response over the size cap")
                chunks.append(chunk)
            status = resp.status_code
        self.meter.charge(size)
        if status >= 400:
            return status, None
        try:
            return status, json.loads(b"".join(chunks))
        except ValueError:
            return 599, None

    async def _failover(self, family: str, chain: int | None, path: str, http: str, body: Any,
                        classify: Callable[[Any], tuple[str, Any]], depth: int | None = None) -> tuple[Any, Endpoint]:
        """Try the pool in `ordered` order; `classify(json)` returns ("ok", result) |
        ("fail", RpcFailure) | ("no_state", detail) | ("retry", detail). Host health is updated."""
        eps = ordered(self._endpoints(family, chain), depth)
        if not eps:
            raise ChainUnavailable("upstream", [], "no endpoint configured")
        reasons: list[str] = []
        hosts: list[str] = []
        for ep in eps:
            hosts.append(ep.host)
            url = ep.url.rstrip("/") + path if path else ep.url
            try:
                status, data = await self._send(ep, http, url, body)
            except ChainUnavailable as exc:
                if exc.reason == "budget":
                    raise
                reasons.append(exc.reason)
                Health.fail(ep.host, exc.reason)
                continue
            except (httpx.HTTPError, OSError) as exc:
                logger.info("chain %s %s: %s", family, ep.host, type(exc).__name__)
                self.meter.failed_upstream += 1
                reasons.append("upstream")
                Health.fail(ep.host, "upstream")
                continue
            if status >= 400 or data is None:
                self.meter.failed_upstream += 1
                why = "rate_limited" if status == 429 else "upstream"
                reasons.append(why)
                Health.fail(ep.host, why)
                continue
            kind, val = classify(data)
            if kind == "ok":
                self.meter.answered_by.add(ep.host)
                Health.ok(ep.host)
                return val, ep
            if kind == "fail":
                Health.ok(ep.host)
                raise val
            if kind == "no_state":
                Health.no_state(ep.host, depth)
                reasons.append("archive")
                continue
            self.meter.failed_upstream += 1
            why = "rate_limited" if any(h in str(val).lower() for h in _RATE_HINTS) else "upstream"
            reasons.append(why)
            Health.fail(ep.host, why)
        reason = "archive" if "archive" in reasons else "rate_limited" if "rate_limited" in reasons else "upstream"
        raise ChainUnavailable(reason, hosts, ", ".join(sorted(set(reasons))))

    # ── EVM ────────────────────────────────────────────────────────────────

    async def evm(self, chain_id: int, method: str, params: list[Any], *, max_block: int | None = None,
                  durable: bool = False, depth: int | None = None) -> Any:
        """One JSON-RPC read. `durable` marks the answer as immutable (a call at a final block);
        `depth` (blocks behind the head) lets the pool try hosts that hold that state first."""
        policy.check_evm(method, params, max_block=max_block)
        key = cache_key("evm", chain_id, method, params)
        hit = await self._cached(key)
        if hit is not None:
            return hit["r"]

        def classify(data: Any) -> tuple[str, Any]:
            if not isinstance(data, dict):
                return "retry", "not an object"
            if "error" in data:
                err = data["error"] if isinstance(data["error"], dict) else {"message": str(data["error"])}
                msg = str(err.get("message", ""))
                if any(s in msg.lower() for s in _NO_STATE):
                    return "no_state", msg
                if any(h in msg.lower() for h in _RATE_HINTS) or err.get("code") in (-32005, 429, 15):
                    return "retry", msg
                if method in ("eth_call", "eth_estimateGas") and (err.get("code") == 3 or "revert" in msg.lower()):
                    return "fail", RpcFailure(int(err.get("code") or 3), msg, err.get("data"))
                if err.get("code") in (-32602, -32600):
                    return "fail", RpcFailure(int(err["code"]), msg)
                return "retry", msg
            return "ok", data.get("result")

        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        result, ep = await self._failover("evm", chain_id, "", "POST", payload, classify,
                                          depth if depth is not None else self.depth_hint)
        if result is not None:
            await self._store(key, {"r": result}, durable, ep)
        return result

    # ── TRON ───────────────────────────────────────────────────────────────

    async def tron(self, path: str, body: Any | None = None, *, http: str = "POST") -> Any:
        policy.check_tron(path, http, body)

        def classify(data: Any) -> tuple[str, Any]:
            if isinstance(data, dict) and "Error" in data:
                return "retry", str(data["Error"])[:200]
            if path == "/jsonrpc" and isinstance(data, dict):
                if "error" in data:
                    err = data["error"] if isinstance(data["error"], dict) else {}
                    return "fail", RpcFailure(int(err.get("code") or -1), str(err.get("message", ""))[:200], err.get("data"))
                return "ok", data.get("result")
            return "ok", data

        result, _ep = await self._failover("tron", None, path, http, body, classify)
        return result

    # ── Solana ─────────────────────────────────────────────────────────────

    async def solana(self, method: str, params: list[Any]) -> Any:
        policy.check_solana(method, params)

        def classify(data: Any) -> tuple[str, Any]:
            if not isinstance(data, dict):
                return "retry", "not an object"
            if "error" in data:
                err = data["error"] if isinstance(data["error"], dict) else {}
                if err.get("code") in (-32602, -32600):
                    return "fail", RpcFailure(int(err["code"]), str(err.get("message", "")))
                return "retry", str(err.get("message", ""))
            return "ok", data.get("result")

        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        result, _ep = await self._failover("solana", None, "", "POST", payload, classify)
        return result

    # ── TON (toncenter v2) ─────────────────────────────────────────────────

    async def ton(self, method: str, body: dict[str, Any] | None = None, *, http: str = "POST",
                  durable: bool = False) -> Any:
        policy.check_ton(method, body)
        key = cache_key("ton", None, method, body)
        hit = await self._cached(key)
        if hit is not None:
            return hit["r"]

        def classify(data: Any) -> tuple[str, Any]:
            if not isinstance(data, dict):
                return "retry", "not an object"
            if not data.get("ok"):
                msg = str(data.get("error", ""))
                if data.get("code") in (400, 404, 422):
                    return "fail", RpcFailure(int(data.get("code")), msg)
                return "retry", msg
            return "ok", data.get("result")

        if http == "GET":
            from urllib.parse import urlencode

            path = f"/{method}" + (f"?{urlencode(body)}" if body else "")
            result, ep = await self._failover("ton", None, path, "GET", None, classify)
        else:
            result, ep = await self._failover("ton", None, f"/{method}", "POST", body or {}, classify)
        if result is not None:
            await self._store(key, {"r": result}, durable, ep)
        return result


    # ── Sourcify ───────────────────────────────────────────────────────────

    async def sourcify_deployment(self, chain_id: int, address: str) -> dict[str, Any] | None:
        """Sourcify's deployment record (deployer, creation tx and block) of a verified contract, or None."""
        path = f"/server/v2/contract/{int(chain_id)}/{address}?fields=deployment"
        policy.check_sourcify(path)
        key = cache_key("sourcify", chain_id, "deployment", address.lower())
        hit = await self._cached(key)
        if hit is not None:
            return hit["r"]
        ep = Endpoint(SOURCIFY, keyed=False, per_s=2.0)
        try:
            status, data = await self._send(ep, "GET", SOURCIFY + path, None)
        except (httpx.HTTPError, OSError):
            return None
        if status >= 400 or not isinstance(data, dict):
            return None
        dep = data.get("deployment") if isinstance(data.get("deployment"), dict) else None
        await self._store(key, {"r": dep}, True, ep)
        return dep


def asgi_app(chain_id: int, *, max_block: int | None = None, proxy_factory: Callable[[], ChainProxy] = ChainProxy):
    """HTTP JSON-RPC endpoint (EVM) with the proxy policy. A denied method answers -32601 and nothing
    goes upstream; a batch with one denied element is refused whole."""

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if len(body) > 1024 * 1024:
                break
            if not msg.get("more_body"):
                break
        status, out, payload = 200, None, None
        try:
            payload = json.loads(body) if scope.get("method") == "POST" else None
            if payload is None:
                raise policy.ProxyDenied("evm", str(scope.get("method")), "POST a JSON-RPC request")
            policy.check_evm_payload(payload, max_block=max_block)
            items = payload if isinstance(payload, list) else [payload]
            answers = []
            async with proxy_factory() as px:
                for item in items:
                    try:
                        r = await px.evm(chain_id, item["method"], item.get("params") or [], max_block=max_block)
                        answers.append({"jsonrpc": "2.0", "id": item.get("id"), "result": r})
                    except RpcFailure as exc:
                        answers.append({"jsonrpc": "2.0", "id": item.get("id"),
                                        "error": {"code": exc.code, "message": exc.message, "data": exc.data}})
                    except ChainUnavailable as exc:
                        answers.append({"jsonrpc": "2.0", "id": item.get("id"),
                                        "error": {"code": -32005, "message": f"unavailable: {exc.reason}"}})
            out = answers if isinstance(payload, list) else answers[0]
        except policy.ProxyDenied as exc:
            out = exc.rpc_error(payload.get("id") if isinstance(payload, dict) else None)
        except ValueError:
            status, out = 400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        data = json.dumps(out).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
        await send({"type": "http.response.body", "body": data})

    return app
