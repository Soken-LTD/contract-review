"""The chain endpoint of one fork run (review_verify_on_fork; chain access design 1.7 and 3.3).

`fork_app(...)` wraps `proxy.asgi_app` for a single run: the forge container reaches it only through
the chainsim relay, so this is the one route from a reviewer's test to a chain. On top of the proxy
policy (default deny; every send, sign, broadcast, txpool, anvil, hardhat and evm_* method answers
-32601 and nothing goes upstream) it adds:

- a per-run token in the path (`/<token>`); any other path answers 404 and reaches nothing;
- the block pin: `latest`, `pending`, `safe` and `finalized` become the fork block, and any block above
  it is refused by the policy bound (`max_block`), so a test can never read past its stated fork;
- one meter for the whole run (calls and bytes that reached an upstream), over the cap -32005;
- counters (`stats`) for the result: requests, denied requests and the denied method names.

`serve(...)` runs the app with uvicorn on a Unix socket for the duration of the run.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import policy
from .proxy import ChainProxy, Meter, asgi_app

logger = logging.getLogger(__name__)

_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
_PIN_TAGS = frozenset({"latest", "pending", "safe", "finalized"})
_MAX_BODY = 1024 * 1024


@dataclass
class ForkStats:
    requests: int = 0
    denied: int = 0
    denied_methods: list[str] = field(default_factory=list)
    bad_path: int = 0
    addresses: set[str] = field(default_factory=set)   # accounts the run read (code, balance, storage, calls)

    def note(self, items: list[Any]) -> None:
        for i in items:
            if not isinstance(i, dict) or not isinstance(i.get("params"), list) or not i["params"]:
                continue
            first = i["params"][0]
            addr = first.get("to") if isinstance(first, dict) else first
            if isinstance(addr, str) and _ADDR.match(addr) and len(self.addresses) < 500:
                self.addresses.add(addr.lower())

    def as_dict(self, meter: Meter) -> dict[str, Any]:
        return {"requests": self.requests, "upstream_calls": meter.calls, "cached": meter.cached,
                "bytes": meter.bytes, "denied": self.denied, "denied_methods": sorted(set(self.denied_methods))[:10],
                "bad_path": self.bad_path, "addresses": sorted(self.addresses)[:200]}


def pin_tags(item: Any, block: int, fork_hash: str | None = None) -> Any:
    """A request with its block tag words, and an EIP-1898 tag naming the fork block's own hash
    (forge pins its reads that way), replaced by the fork block (hex); other fields untouched. Any
    other hash stays as sent and the policy bound refuses it."""
    if not isinstance(item, dict):
        return item
    method, params = item.get("method"), item.get("params")
    idx = policy._EVM_BLOCK_ARG.get(method) if isinstance(method, str) else None
    if idx is None or not isinstance(params, list):
        return item
    params = list(params)
    if len(params) <= idx:
        params += [None] * (idx + 1 - len(params))
        params[idx] = hex(block)
    else:
        tag = params[idx]
        is_word = isinstance(tag, str) and tag in _PIN_TAGS
        is_fork_hash = (isinstance(tag, dict) and fork_hash is not None
                        and str(tag.get("blockHash", "")).lower() == fork_hash)
        if is_word or is_fork_hash:
            params[idx] = hex(block)
    return {**item, "params": params}


def _wants_hash(items: list[Any]) -> bool:
    return any(isinstance(i, dict) and isinstance(i.get("params"), list)
               and any(isinstance(p, dict) and "blockHash" in p for p in i["params"]) for i in items)


def fork_app(chain_id: int, block: int, token: str, meter: Meter, stats: ForkStats,
             proxy_factory: Callable[[], ChainProxy] | None = None) -> Any:
    """ASGI app of one run. `proxy_factory` defaults to a ChainProxy charged to `meter`."""
    factory = proxy_factory or (lambda: ChainProxy(meter=meter))
    inner = asgi_app(chain_id, max_block=block, proxy_factory=factory)
    fork_hash: list[str | None] = [None]

    async def known_hash() -> str | None:
        """The fork block's hash, read once through the proxy (a read at the fork block itself)."""
        if fork_hash[0] is None:
            try:
                async with factory() as px:
                    head = await px.evm(chain_id, "eth_getBlockByNumber", [hex(block), False], max_block=block)
                h = (head or {}).get("hash") if isinstance(head, dict) else None
                fork_hash[0] = str(h).lower() if isinstance(h, str) else None
            except Exception as exc:  # noqa: BLE001  # no hash: a blockHash read stays refused, never widened
                logger.info("fork block hash unavailable: %s", type(exc).__name__)
        return fork_hash[0]

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        stats.requests += 1
        if scope.get("path") != f"/{token}":
            stats.bad_path += 1
            await _send_json(send, 404, {"jsonrpc": "2.0", "id": None, "error": {"code": -32601, "message": "not found"}})
            return
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if len(body) > _MAX_BODY or not msg.get("more_body"):
                break
        try:
            payload = json.loads(body)
        except ValueError:
            payload = None
        if payload is not None:
            items = payload if isinstance(payload, list) else [payload]
            fh = await known_hash() if _wants_hash(items) else fork_hash[0]
            pinned = [pin_tags(i, block, fh) for i in items]
            try:
                policy.check_evm_payload(pinned, max_block=block)
                stats.note(pinned)
            except policy.ProxyDenied as exc:
                stats.denied += 1
                stats.denied_methods.append(exc.method[:60])
            body = json.dumps(pinned if isinstance(payload, list) else pinned[0]).encode()
        sent = False

        async def replay() -> dict[str, Any]:
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await inner(scope, replay, send)

    return app


async def _send_json(send: Any, status: int, obj: Any) -> None:
    data = json.dumps(obj).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
    await send({"type": "http.response.body", "body": data})


@contextlib.asynccontextmanager
async def serve(app: Any, socket_path: Path) -> AsyncIterator[Path]:
    """Serve `app` on a Unix socket until the block exits. The socket is world-connectable (the relay
    runs as the sandbox uid) inside a per-run directory the supervisor removes afterwards."""
    import uvicorn

    with contextlib.suppress(FileNotFoundError):
        socket_path.unlink()
    config = uvicorn.Config(app, uds=str(socket_path), log_level="warning", lifespan="off",
                            access_log=False, timeout_keep_alive=30)
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]  # the worker owns signals
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started or task.done():
            break
        await asyncio.sleep(0.05)
    if task.done():
        task.result()
        raise RuntimeError("fork rpc server did not start")
    os.chmod(socket_path, 0o666)
    try:
        yield socket_path
    finally:
        server.should_exit = True
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, timeout=10)
        with contextlib.suppress(FileNotFoundError):
            socket_path.unlink()
