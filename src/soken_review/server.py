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

from .contract import Release, bundle_tools, load_release, schema_version
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
        parsed = _parse_json_strings(tool["inputSchema"], arguments)
        stale_client = parsed is not arguments   # an object or array reached us as a JSON string
        arguments = parsed
        violation = next(iter(sorted(self.validators[name].iter_errors(arguments), key=lambda e: e.path)), None)
        if violation is not None:
            field, example = _violation_hint(violation)
            res = _error_result(
                ReviewError(
                    "E_INVALID_ARGUMENT",
                    field=field,
                    rule=violation.validator,
                    value80=json.dumps(violation.instance, ensure_ascii=False)[:80],
                    example=example,
                )
            )
            return _with_schema_hint(res) if stale_client else res
        fn = HANDLERS.get(name)
        if fn is None:
            raise NotImplementedError(f"{name} handler lands in W1 to W4 (part 03)")
        try:
            result = await fn(arguments)
        except ReviewError as err:
            res = _error_result(err, structured="outputSchema" in tool)
            return _with_schema_hint(res) if stale_client else res
        if "outputSchema" in tool:
            if not isinstance(result, dict):
                raise TypeError(f"{name} is a control tool and must return an object")
            text = json.dumps(result, separators=(",", ":"), ensure_ascii=False)
            res = CallToolResult(content=[TextContent(type="text", text=text)], structured_content=result)
        else:
            res = CallToolResult(content=[TextContent(type="text", text=str(result))])
        return _with_schema_hint(res) if stale_client else res


def _stale_schema_hint() -> str:
    """One line for a client whose tool list predates the served schema. The JSON-string shape is
    the one signal the server can see (03 section 13: the list is a snapshot the client caches)."""
    return (f"Your tool list predates the current schema (schema_version {schema_version()}). Reload the"
            " tool list to see the current fields, sections and guide topics.")


def _with_schema_hint(res: CallToolResult) -> CallToolResult:
    """Add `schema_hint` to a result (structured object, or a last line of a text result). Additive:
    no output schema closes its root object, so the key passes every client-side check."""
    hint = _stale_schema_hint()
    content = list(res.content)
    body: Any = res.structured_content
    if body is None and content and isinstance(content[-1], TextContent) and content[-1].text[:1] == "{":
        try:
            body = json.loads(content[-1].text)   # an error envelope (channel `error`): JSON text, no structured
        except ValueError:
            body = None
    if isinstance(body, dict):
        body = {**body, "schema_hint": hint}
        text = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        structured = body if res.structured_content is not None else None
        return CallToolResult(content=[TextContent(type="text", text=text)], structured_content=structured,
                              is_error=res.is_error)
    if content and isinstance(content[-1], TextContent):
        content[-1] = TextContent(type="text", text=content[-1].text + "\nschema_hint " + hint)
    return CallToolResult(content=content, structured_content=res.structured_content, is_error=res.is_error)


def _parse_json_strings(schema: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    """Accept an object or array argument that arrived as a JSON string.

    A client that loaded the tool list before a schema change (claude.ai caches it per connector) has
    no type for a property added since, and its proxy serialises the value as a string. Blind run
    2026-10-26: `invariant_walks` reached the server as a string and finalize check F9 could never
    close. Only top-level properties the schema declares as object or array are parsed, and only when
    the parsed value has that type; everything else is left for the validator to report."""
    props = schema.get("properties") or {}
    out = None
    for key, raw in arguments.items():
        if not isinstance(raw, str) or len(raw) > 262_144:
            continue
        declared = (props.get(key) or {}).get("type")
        kinds = set(declared) if isinstance(declared, list) else {declared}
        want = tuple(t for t, k in ((dict, "object"), (list, "array")) if k in kinds)
        if not want or raw[:1] not in "{[":
            continue
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if isinstance(value, want):
            out = dict(arguments) if out is None else out
            out[key] = value
    return out if out is not None else arguments


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


def _violation_hint(violation: Any) -> tuple[str, str]:
    """Turn a jsonschema error into (field, example) that name the exact problem, so a caller can
    self-correct (03 7.1). `required` and `additionalProperties` attach at the parent object, so
    `absolute_path` is empty and the bare field would read "(root)"; derive the specific property
    instead, and give a concrete example for the common keyword failures."""
    path = ".".join(str(p) for p in violation.absolute_path)
    rule = violation.validator
    inst = violation.instance if isinstance(violation.instance, dict) else {}
    if rule == "required":
        missing = [k for k in (violation.validator_value or []) if k not in inst]
        f = missing[0] if missing else (path or "(root)")
        return f, f"add the required field '{f}'"
    if rule == "additionalProperties":
        allowed = sorted((violation.schema.get("properties") or {}).keys())
        extra = [k for k in inst if k not in set(allowed)]
        f = extra[0] if extra else (path or "(root)")
        return f, f"remove the unexpected field '{f}'; allowed fields: {allowed}"
    field = path or "(root)"
    if rule == "enum":
        return field, f"one of {violation.validator_value}"
    if rule == "pattern":
        return field, f"a string matching {violation.validator_value!r}"
    if rule == "type":
        return field, f"a value of type {violation.validator_value}"
    if rule in ("minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems"):
        return field, f"{rule} is {violation.validator_value}"
    return field, ""


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
