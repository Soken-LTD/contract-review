"""MCP server for mcp.soken.dev (03): the contract is the tool list, handlers fill results.

`tools/list` returns the bundled contract unchanged (03 section 13 "Snapshot"). Arguments are
validated against the bundled input schema before a handler runs; a failure is the
`E_INVALID_ARGUMENT` error result. Control tools (those with an `outputSchema`) return
`structuredContent` plus the same JSON minified as the text block; bulk read tools return text.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from typing import Any

from jsonschema import Draft202012Validator
from mcp.server import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from mcp.types import Tool as MCPTool

from .contract import Release, bundle_tools, load_release
from .errors import ReviewError
from .http import ProtocolRules

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any] | str]]

HANDLERS: dict[str, Handler] = {}


def handler(name: str) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        HANDLERS[name] = fn
        return fn

    return register


class SokenServer(MCPServer):
    def __init__(self, release: Release | None = None) -> None:
        super().__init__(name="soken-contract-review", title="Soken Contract Review")
        self.contract = {tool["name"]: tool for tool in bundle_tools(release or load_release())}
        self.validators = {
            name: Draft202012Validator(tool["inputSchema"]) for name, tool in self.contract.items()
        }

    async def list_tools(self) -> list[MCPTool]:
        return [
            MCPTool(
                name=tool["name"],
                title=tool["title"],
                description=tool["description"],
                input_schema=tool["inputSchema"],
                output_schema=tool.get("outputSchema"),
                annotations=ToolAnnotations(**_snake(tool["annotations"])),
                _meta=tool.get("_meta"),
            )
            for tool in self.contract.values()
        ]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], context: Context | None = None
    ) -> CallToolResult:
        tool = self.contract.get(name)
        if tool is None:
            return _error_result(ReviewError("E_INVALID_ARGUMENT", field="name", rule="known tool", value80=name[:80]))
        violation = next(iter(sorted(self.validators[name].iter_errors(arguments), key=lambda e: e.path)), None)
        if violation is not None:
            field = ".".join(str(p) for p in violation.absolute_path) or "(root)"
            return _error_result(
                ReviewError(
                    "E_INVALID_ARGUMENT",
                    field=field,
                    rule=violation.validator,
                    value80=json.dumps(violation.instance, ensure_ascii=False)[:80],
                )
            )
        fn = HANDLERS.get(name)
        if fn is None:
            raise NotImplementedError(f"{name} handler lands in W1 to W4 (part 03)")
        try:
            result = await fn(arguments)
        except ReviewError as err:
            return _error_result(err, structured="outputSchema" in tool)
        if "outputSchema" in tool:
            if not isinstance(result, dict):
                raise TypeError(f"{name} is a control tool and must return an object")
            text = json.dumps(result, separators=(",", ":"), ensure_ascii=False)
            return CallToolResult(content=[TextContent(type="text", text=text)], structured_content=result)
        return CallToolResult(content=[TextContent(type="text", text=str(result))])


def _error_result(err: ReviewError, structured: bool = True) -> CallToolResult:
    """03 7.1: channel `error` is an isError result; channel `rejection` is a normal result with
    `accepted: false` in structuredContent, so it does not count toward the directory error rate."""
    body = {"accepted": False, "errors": [err.envelope()]}
    text = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    if err.channel == "rejection":
        if not structured:  # bulk read tools have no outputSchema: text only (03 1)
            return CallToolResult(content=[TextContent(type="text", text=text)])
        return CallToolResult(content=[TextContent(type="text", text=text)], structured_content=body)
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


def _snake(annotations: dict[str, Any]) -> dict[str, Any]:
    names = {
        "title": "title",
        "readOnlyHint": "read_only_hint",
        "destructiveHint": "destructive_hint",
        "idempotentHint": "idempotent_hint",
        "openWorldHint": "open_world_hint",
    }
    return {names[k]: v for k, v in annotations.items()}


def create_app():
    """Stateless Streamable HTTP with JSON responses (D-SDK, 03 section 11)."""
    hosts = os.environ.get("SOKEN_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*").split(",")
    security = TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts)
    app = SokenServer().streamable_http_app(stateless_http=True, json_response=True, transport_security=security)
    return ProtocolRules(app)
