"""Load the part 03 wire contract and bundle it into self-contained tool schemas.

`contract/mcp/tools.v1.json` is the source. Every `$ref` (local `#/$defs/...` and the
04 rubric files) is inlined, the angle-bracket enums are filled from the release config,
and the root `allOf` of the finding wrapper is dropped (03 section 1; the V0 check
enforces those branches with the full schema).
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIR = REPO_ROOT / "contract"
TOOLS_FILE = CONTRACT_DIR / "mcp" / "tools.v1.json"
ERRORS_FILE = CONTRACT_DIR / "errors.yaml"
RELEASE_FILE = REPO_ROOT / "config" / "release.yaml"

SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

# Placeholder prefixes in tools.v1.json mapped to release config keys.
_GENERATED = {
    "<generated: released chain keys": "chains",
    "<generated: released adapters": "languages",
    "<generated from the 09 package cache": "dependencies",
}


@dataclass(frozen=True)
class Release:
    chains: tuple[str, ...]
    languages: tuple[str, ...]
    dependencies: tuple[str, ...]


def load_release(path: Path = RELEASE_FILE) -> Release:
    data = yaml.safe_load(path.read_text())
    return Release(
        chains=tuple(data["chains"]),
        languages=tuple(data["languages"]),
        dependencies=tuple(data.get("dependencies") or ()),
    )


@cache
def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _resolve_pointer(doc: dict[str, Any], pointer: str) -> Any:
    node: Any = doc
    for part in pointer.lstrip("/").split("/"):
        if part:
            node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def _inline(node: Any, base: Path, depth: int = 0) -> Any:
    if depth > 64:
        raise ValueError(f"$ref nesting too deep under {base}")
    if isinstance(node, list):
        return [_inline(item, base, depth) for item in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        ref = node["$ref"]
        file_part, _, pointer = ref.partition("#")
        target_file = (base.parent / file_part).resolve() if file_part else base
        target = _resolve_pointer(_load_json(target_file), pointer)
        siblings = {k: v for k, v in node.items() if k != "$ref"}
        resolved = _inline(copy.deepcopy(target), target_file, depth + 1)
        if isinstance(resolved, dict):
            resolved = {k: v for k, v in resolved.items() if k not in ("$schema", "$id", "$defs")}
            resolved.update(_inline(siblings, base, depth))
        return resolved
    return {k: _inline(v, base, depth) for k, v in node.items() if k != "$defs"}


def _fill_generated(node: Any, release: Release) -> Any:
    if isinstance(node, list):
        return [_fill_generated(item, release) for item in node]
    if not isinstance(node, dict):
        return node
    out = {k: _fill_generated(v, release) for k, v in node.items()}
    enum = out.get("enum")
    if isinstance(enum, list) and len(enum) == 1 and isinstance(enum[0], str):
        for prefix, key in _GENERATED.items():
            if enum[0].startswith(prefix):
                out["enum"] = list(getattr(release, key))
    return out


def _drop_empty_enum_arrays(node: Any) -> Any:
    """An array whose item enum is empty accepts no item: express it as maxItems 0."""
    if isinstance(node, list):
        return [_drop_empty_enum_arrays(item) for item in node]
    if not isinstance(node, dict):
        return node
    out = {k: _drop_empty_enum_arrays(v) for k, v in node.items()}
    items = out.get("items")
    if out.get("type") == "array" and isinstance(items, dict) and items.get("enum") == []:
        out["items"] = {k: v for k, v in items.items() if k != "enum"}
        out["maxItems"] = 0
    return out


def bundle_tools(release: Release | None = None) -> list[dict[str, Any]]:
    """Return the 17 tool definitions with self-contained input and output schemas."""
    release = release or load_release()
    source = _load_json(TOOLS_FILE)
    tools = []
    for tool in source["tools"]:
        bundled = copy.deepcopy(tool)
        for key in ("inputSchema", "outputSchema"):
            if key not in bundled:
                continue
            schema = _inline(bundled[key], TOOLS_FILE)
            schema = _drop_empty_enum_arrays(_fill_generated(schema, release))
            if key == "inputSchema":
                _drop_root_combinators(schema)
            bundled[key] = schema
        tools.append(bundled)
    return tools


def _drop_root_combinators(schema: dict[str, Any]) -> None:
    """03 section 1: no combinator at a root; nested ones stay, the server V0 check covers them."""
    for key in ("allOf", "anyOf", "oneOf"):
        schema.pop(key, None)


def load_errors() -> dict[str, dict[str, str]]:
    data = yaml.safe_load(ERRORS_FILE.read_text())
    return {row["code"]: row for row in data["codes"]}
