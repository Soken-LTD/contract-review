"""One plain sentence per analyzer that did not run fully (review_status `analyzer_note`, report).

Every degraded or not_run analyzer state carries a reason (MetaDAO blind run 2026-10-31:
`analyzer_degraded: true` with no reason; the cause, cargo-audit without its RustSec snapshot, was
only in the worker's static_map.json). The families write static_map.json in different shapes;
`reasons_of` reads them all: `degraded_reasons` ("tool:code"), `tools` {name: {status, reason}},
`not_run` [names], a top-level `status: not_run` with `reason`, the EVM `aderyn: not_run` key and the
TON `analyzer: not_run` key. A structured `cause` (closed class + reviewed file + line, e.g. the
first solc error of the Slither compilation) follows the sentence as fixed text. Texts: contract/rubric/analyzer_reasons.yaml.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

import yaml

_TEXTS = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "analyzer_reasons.yaml"
_TOOL_NAMES = {"cargo_audit": "cargo-audit", "soken_solana_rules": "soken-solana-rules"}


@cache
def _texts() -> dict[str, Any]:
    return yaml.safe_load(_TEXTS.read_text(encoding="utf-8")) or {}


def reasons_of(static_map: dict[str, Any] | None) -> list[tuple[str, str]]:
    """(tool, reason code) pairs of everything that did not run fully; codes keep only the first
    segment of `code:detail` (no host paths)."""
    sm = static_map if isinstance(static_map, dict) else {}
    out: dict[str, str] = {}

    def add(tool: str, code: str | None) -> None:
        tool = str(tool).split("@", 1)[0].strip() or "analyzer"
        code = str(code or "").split(":", 1)[0].strip() or "not_run"
        if tool not in out or out[tool] == "not_run":
            out[tool] = code

    for row in sm.get("degraded_reasons") or []:
        tool, _, code = str(row).partition(":")
        add(tool, code)
    for name, st in (sm.get("tools") or {}).items():
        if isinstance(st, dict) and st.get("status") not in (None, "ok"):
            add(name, st.get("reason"))
    for name in sm.get("not_run") or []:
        add(str(name), None)
    if sm.get("status") == "not_run":
        add(str(sm.get("tool") or "slither"), sm.get("reason") or "no_output")
    if sm.get("aderyn") == "not_run":
        add("aderyn", "not_available")
    if sm.get("analyzer") == "not_run":
        add("misti", "not_run")
    return sorted(out.items())


_CAUSE_FILE = re.compile(r"^[A-Za-z0-9_@+\-][A-Za-z0-9_@+./\-]{0,199}\.(?:sol|vy)$")


def causes_of(static_map: dict[str, Any] | None) -> dict[str, str]:
    """{tool: cause text} of the not-run analyzers that recorded a structured `cause`.

    The text is built only from contract/rubric/analyzer_reasons.yaml `causes` (closed set of
    classes) plus a reviewed file path and a line number; nothing the analyzer printed (solc
    messages quote the client's identifiers and literals) is ever relayed. An unknown class, a
    malformed path or a non-integer line is dropped."""
    sm = static_map if isinstance(static_map, dict) else {}
    t = _texts()
    texts = t.get("causes") or {}
    out: dict[str, str] = {}

    def add(tool: str, cause: Any) -> None:
        if not isinstance(cause, dict) or not isinstance(cause.get("class"), str):
            return
        text = texts.get(cause["class"])
        if not isinstance(text, str):
            return
        path, line = cause.get("file"), cause.get("line")
        if isinstance(path, str) and _CAUSE_FILE.match(path) and ".." not in path.split("/") \
                and isinstance(line, int) and not isinstance(line, bool) and 0 < line < 10_000_000:
            text = t["cause_location"].format(cause=text, file=path, line=line)
        out[str(tool).split("@", 1)[0].strip() or "analyzer"] = text

    if sm.get("status") == "not_run":
        add(str(sm.get("tool") or "slither"), sm.get("cause"))
    for name, st in (sm.get("tools") or {}).items():
        if isinstance(st, dict) and st.get("status") not in (None, "ok"):
            add(name, st.get("cause"))
    return out


def note_from(static_map: dict[str, Any] | None, build: dict[str, Any] | None = None) -> str:
    """The sentence(s) for a degraded job; never empty (an unrecorded cause says so)."""
    t = _texts()
    words = t.get("reasons") or {}
    parts = []
    b = build if isinstance(build, dict) else {}
    causes = causes_of(static_map)
    for tool, code in reasons_of(static_map):
        if code.startswith("build_") and code != "build_failed":
            reason = t["build_prefix"].format(detail=code.removeprefix("build_").replace("_", " "))
        else:
            reason = words.get(code) or code.replace("_", " ")
        parts.append(t["sentence"].format(tool=_TOOL_NAMES.get(tool, tool), reason=reason))
        if causes.get(tool):
            parts.append(t["cause_sentence"].format(cause=causes[tool]))
    if not parts and b.get("status") not in (None, "ok"):
        parts.append(t["sentence"].format(tool="The analyzers", reason=words["build_failed"]))
    return " ".join(parts) if parts else str(t["unknown"])


def job_analyzer_note(pin_root: Path, job_id: str) -> str:
    """The note of a job from its work directory (<pin_root>/../work/<job_id>)."""
    work = Path(pin_root).parent / "work" / job_id

    def load(name: str) -> dict[str, Any] | None:
        try:
            data = json.loads((work / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    sm = load("static_map.json")
    if sm is None:
        sm = (load("map.json") or {}).get("static")   # Starknet keeps it inside map.json
    return note_from(sm, load("build_result.json"))
