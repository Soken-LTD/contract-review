"""Stock lint output parsing (plan v4 07 sections 5.3, 6.3, 7.3).

Both CLIs print codespan diagnostics as text (U-03: no JSON diagnostics flag was found in
`sui move build --help` / `aptos move lint --help` at the pinned versions, so the plan's fixed
regex fallback is used). The compiler reports every lint as a warning, so its level is ignored
(07 5.3); the lint name decides category and raw value through `adapters/<chain>/lint_map.yaml`.

  Sui:   warning[Lint W99000]: possible owned object share
            ┌─ ./sources/a.move:10:9
  Aptos: warning: [lint] <message>
            ┌─ pkg/P/sources/a.move:309:29
            = ... `#[lint::skip(unnecessary_cast)]`
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

# sui_mode/linters/mod.rs at mainnet-v1.81.1: codes are positional (W99000 + index), append-only.
SUI_LINTS = [
    "share_owned", "self_transfer", "custom_state_change", "coin_field", "freeze_wrapped",
    "collection_equality", "public_random", "missing_key", "freezing_capability",
    "prefer_mut_tx_context", "public_entry", "uncallable_function", "unused_object_with_fields",
]
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_SUI_HEAD = re.compile(r"^warning\[Lint W99(\d{3})\]:\s*(.*)$")
_APTOS_HEAD = re.compile(r"^warning:\s*\[lint\]\s*(.*)$")
_LOC = re.compile(r"^\s*┌─\s+(\S+?):(\d+):(\d+)\s*$")
_SPAN_LINE = re.compile(r"^\s*(\d+)\s*│")
_APTOS_NAME = re.compile(r"lint::skip\(([a-z0-9_]+)\)")
_GUTTER = re.compile(r"^\s*│")
_NOTE_LINE = re.compile(r"^\s*=\s")          # the compiler's own note lines; never a source snippet


def load_lint_map(path: Path) -> dict[str, dict[str, str]]:
    data = yaml.safe_load(path.read_text())
    return {name: {"category": row["category"], "raw": row["raw"]} for name, row in data["lints"].items()}


def parse(chain: str, text: str) -> list[dict[str, Any]]:
    """[{lint, file (as printed), start, end, message}] in output order."""
    out: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for raw_line in _ANSI.sub("", text).splitlines():
        line = raw_line.rstrip()
        head = _SUI_HEAD.match(line) if chain == "sui" else _APTOS_HEAD.match(line)
        if head:
            if cur:
                out.append(cur)
            if chain == "sui":
                idx = int(head.group(1))
                name = SUI_LINTS[idx] if idx < len(SUI_LINTS) else f"W99{head.group(1)}"
                cur = {"lint": name, "message": head.group(2), "file": None, "start": None, "end": None}
            else:
                cur = {"lint": None, "message": head.group(1), "file": None, "start": None, "end": None}
            continue
        if line.startswith(("warning", "error")) and cur:
            out.append(cur)
            cur = None
            continue
        if cur is None:
            continue
        loc = _LOC.match(line)
        if loc and cur["file"] is None:
            cur["file"], cur["start"] = loc.group(1), int(loc.group(2))
            cur["end"] = cur["start"]
            continue
        span = _SPAN_LINE.match(line)
        if span:
            # Echoed source line: it may contain any text (e.g. a fake `lint::skip(..)` in a
            # comment), so nothing but its line number is read from it.
            if cur["start"] is not None:
                cur["end"] = max(cur["end"], int(span.group(1)))
            continue
        if _GUTTER.match(line):                  # marker/continuation lines of a snippet
            continue
        if chain == "aptos" and cur["lint"] is None and _NOTE_LINE.match(line):
            name = _APTOS_NAME.search(line)
            if name:
                cur["lint"] = name.group(1)
    if cur:
        out.append(cur)
    for d in out:
        if d["lint"] is None:                    # no clean note line: kept, never dropped
            d["lint"] = "unknown"
    return out


def to_raw(chain: str, diags: list[dict[str, Any]], lint_map: dict[str, dict[str, str]], tool: str,
           path_map) -> tuple[list[dict[str, Any]], list[str], int]:
    """Raw lead items; unmapped lints go to `move.best_practice` raw `info` (07 5.3).
    path_map(printed path) -> pin store path or None (diagnostics outside the unit are dropped)."""
    items, unmapped, unlocated = [], [], 0
    for d in diags:
        if not d["file"] or not d["start"]:
            unlocated += 1                       # counted: the caller marks the run degraded
            continue
        row = lint_map.get(d["lint"])
        if row is None:
            unmapped.append(d["lint"])
            row = {"category": "move.best_practice", "raw": "info"}
        file = path_map(d["file"])
        if file is None:
            continue
        items.append({"tool": tool, "rule_id": f"{tool.split('@')[0]}:{d['lint']}", "severity_raw": row["raw"],
                      "category": row["category"], "file": file, "start": d["start"], "end": d["end"]})
    return items, sorted(set(unmapped)), unlocated
