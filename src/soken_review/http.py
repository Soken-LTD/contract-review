"""HTTP rules of 03 section 11 that the SDK does not enforce on its own.

Measured against MCP Python SDK 2.3.0 (2026-10-09): GET opens an SSE stream (03: 405), a
2025-era request after `initialize` without `MCP-Protocol-Version` is served (03: 400 -32020),
and `2025-03-26` is served (03: not served). The 2026-07-28 leg is left to the SDK.
"""

from __future__ import annotations

import json
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from .quota import CLIENT_IP

MODERN = "2026-07-28"
HANDSHAKE_ERA = ("2025-11-25", "2025-06-18")
SUPPORTED = (MODERN, *HANDSHAKE_ERA)
HEADER_MISMATCH = -32020
UNSUPPORTED_VERSION = -32022
BODY_TOO_LARGE = -32600
# Largest legitimate request: review_start with 20 inline files of 60 000 chars (200 000 total,
# limits.yaml inline) JSON-escaped, or 12 context items of 60 000 chars. 2 MiB covers both with
# margin; the body is buffered before schema validation, so the cap is the memory bound per call.
MAX_BODY_BYTES = 2 * 1024 * 1024


class _TooLarge(Exception):
    pass


class ProtocolRules:
    def __init__(self, app: ASGIApp, path: str = "/mcp") -> None:
        self.app = app
        self.path = path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"].rstrip("/") != self.path:
            await self.app(scope, receive, send)
            return
        if scope["method"] != "POST":
            await _respond(send, 405, None, headers=[(b"allow", b"POST")])
            return
        # Client address for the daily report quota (quota.py). nginx sets X-Real-IP; uvicorn binds
        # 127.0.0.1, so the header is ours. Without it a non-loopback peer is the client; a loopback
        # peer is the proxy itself and must not become one shared key for every caller.
        peer = (scope.get("client") or (None, None))[0]
        real = (_header(scope, b"x-real-ip") or "").strip()
        CLIENT_IP.set(real or (peer if peer and peer not in ("127.0.0.1", "::1") else None))

        declared = _header(scope, b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            await _respond(send, 413, _rpc_error(None, BODY_TOO_LARGE, f"Request body over {MAX_BODY_BYTES} bytes"))
            return
        try:
            body, receive = await _buffer(receive)
        except _TooLarge:
            await _respond(send, 413, _rpc_error(None, BODY_TOO_LARGE, f"Request body over {MAX_BODY_BYTES} bytes"))
            return
        version = _header(scope, b"mcp-protocol-version")
        message = _parse(body)

        if version is None:
            if message is not None and (message.get("method") == "initialize" or _is_modern(message)):
                await self.app(scope, receive, send)
                return
            await _respond(send, 400, _rpc_error(message, HEADER_MISMATCH, "MCP-Protocol-Version header is required"))
            return
        if version not in SUPPORTED:
            await _respond(
                send,
                400,
                _rpc_error(message, UNSUPPORTED_VERSION, f"Unsupported protocol version {version}", {"supported": list(SUPPORTED)}),
            )
            return
        await self.app(scope, receive, send)


def _is_modern(message: dict[str, Any]) -> bool:
    meta = (message.get("params") or {}).get("_meta") or {}
    return "io.modelcontextprotocol/protocolVersion" in meta


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope["headers"]:
        if key == name:
            return value.decode("latin-1")
    return None


def _parse(body: bytes) -> dict[str, Any] | None:
    try:
        message = json.loads(body)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


def _rpc_error(message: dict[str, Any] | None, code: int, text: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": text}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": (message or {}).get("id"), "error": error}


async def _buffer(receive: Receive) -> tuple[bytes, Receive]:
    chunks = []
    total = 0
    while True:
        event = await receive()
        chunk = event.get("body", b"")
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise _TooLarge
        chunks.append(chunk)
        if not event.get("more_body"):
            break
    body = b"".join(chunks)
    sent = False

    async def replay() -> Any:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return body, replay


async def _respond(send: Send, status: int, payload: dict[str, Any] | None, headers: list | None = None) -> None:
    body = json.dumps(payload).encode() if payload is not None else b""
    head = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": head + (headers or [])})
    await send({"type": "http.response.body", "body": body})
