"""Record and replay transport for chain tool tests: answers keyed by (path, JSON-RPC method,
params), never by request id or endpoint host, so a replay is independent of pool order."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx


def request_key(request: httpx.Request) -> str:
    body: Any = None
    if request.content:
        try:
            body = json.loads(request.content)
        except ValueError:
            body = request.content.decode(errors="replace")
    if isinstance(body, dict) and "jsonrpc" in body:
        body = {"method": body.get("method"), "params": body.get("params")}
    path = request.url.path if request.url.host not in ("sourcify.dev",) else request.url.path + "?" + request.url.query.decode()
    if request.url.host == "toncenter.com" and request.method == "GET":
        path = request.url.path + "?" + request.url.query.decode()
    return json.dumps([request.method, path if request.url.host in ("sourcify.dev", "toncenter.com", "api.trongrid.io") else "",
                       body], sort_keys=True)


class Recorder(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self._inner = httpx.AsyncHTTPTransport()
        self.rows: dict[str, Any] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        resp = await self._inner.handle_async_request(request)
        raw = await resp.aread()
        if resp.status_code == 200:
            try:
                self.rows[request_key(request)] = json.loads(raw)
            except ValueError:
                pass
        return httpx.Response(resp.status_code, content=raw, headers={"content-type": "application/json"})

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.rows, indent=1, sort_keys=True) + "\n", encoding="utf-8")


class Replay(httpx.AsyncBaseTransport):
    """Answers from a recorded file; an unknown request is a 599 (a test that needs it fails loudly)."""

    def __init__(self, path: Path | dict[str, Any]) -> None:
        self.rows = json.loads(path.read_text(encoding="utf-8")) if isinstance(path, Path) else dict(path)
        self.seen: list[str] = []
        self.missing: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = request_key(request)
        self.seen.append(key)
        if key not in self.rows:
            self.missing.append(key)
            return httpx.Response(599, content=b"{}")
        body = self.rows[key]
        if isinstance(body, dict) and "jsonrpc" in body:
            try:
                body = {**body, "id": json.loads(request.content).get("id")}
            except ValueError:
                pass
        return httpx.Response(200, json=body)
