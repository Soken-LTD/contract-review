"""Stale client tool lists: what an old list lacks, and the notice that tells the model how to refresh.

Clients cache tools/list (claude.ai per connector). In the 2026-10-31 blind round 5 every MCP arm ran
on a list from 2026-10-23/24: review_chain_read, severity_reason, invariant_walks and the invariants
topic never reached the model. The server cannot read the client's list, so it uses two signals:

- certain: an object or array argument arrived as a JSON string (server._parse_json_strings);
- likely: a job on which no tool added since the baseline (contract/mcp/client_baseline.json) was
  ever called. Calling one of them proves the list is fresh and silences the notice for the job.

The missing tools, arguments and values are the diff of the served bundle against the baseline, so
the notice never goes stale itself. Texts live in contract/mcp/client_refresh.yaml. Per-job state is
a small file in the job's pin directory (deleted with the job).
"""

from __future__ import annotations

import json
import logging
import os
import re
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from .contract import CONTRACT_DIR, bundle_tools, schema_version

logger = logging.getLogger(__name__)

BASELINE_FILE = CONTRACT_DIR / "mcp" / "client_baseline.json"
TEXTS_FILE = CONTRACT_DIR / "mcp" / "client_refresh.yaml"
STATE_FILE = "client_shape.json"
_JOB_RE = re.compile(r"^job_[0-9A-HJKMNP-TV-Z]{26}$")
_LIST_CAP = 6

_ctx: Any | None = None


def set_context(ctx: Any) -> None:
    global _ctx
    _ctx = ctx


def fingerprint(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """{tool: {props: [...], enums: {prop: [values]}}} of bundled tool definitions (top level only)."""
    out: dict[str, dict[str, Any]] = {}
    for tool in tools:
        props = (tool.get("inputSchema") or {}).get("properties") or {}
        enums = {k: sorted(map(str, v["enum"])) for k, v in props.items()
                 if isinstance(v, dict) and isinstance(v.get("enum"), list)}
        out[tool["name"]] = {"props": sorted(props), "enums": enums}
    return out


@cache
def baseline() -> dict[str, Any]:
    try:
        return json.loads(BASELINE_FILE.read_text())
    except (OSError, ValueError):
        return {"rev": "", "date": "", "tools": {}}


@cache
def texts() -> dict[str, Any]:
    return yaml.safe_load(TEXTS_FILE.read_text(encoding="utf-8")) or {}


@cache
def missing() -> dict[str, list[str]]:
    """What a client holding the baseline list cannot see in the served bundle."""
    base = baseline().get("tools") or {}
    now = fingerprint(bundle_tools())
    tools = [n for n in now if n not in base]
    fields: list[str] = []
    values: list[str] = []
    for name, cur in now.items():
        old = base.get(name)
        if old is None:
            continue
        fields += [f"{name}.{p}" for p in cur["props"] if p not in set(old["props"])]
        for prop, vals in cur["enums"].items():
            had = set((old.get("enums") or {}).get(prop) or [])
            if prop in old["props"] and had:
                values += [f"{name}.{prop} {v}" for v in vals if v not in had]
    return {"tools": tools, "fields": fields, "values": values}


def added_tools() -> frozenset[str]:
    return frozenset(missing()["tools"])


def _join(items: list[str], cap: int = _LIST_CAP) -> str:
    if not items:
        return "none"
    shown = items[:cap]
    more = len(items) - len(shown)
    return ", ".join(shown) + (f" and {more} more" if more > 0 else "")


def _probe() -> str:
    names = [n for n in texts().get("probe_tools") or [] if n in added_tools()] or list(added_tools())[:3]
    return _join(names) if names else "review_status"


def notice(certain: bool) -> str:
    """The plain notice: lead, what is missing, how to refresh, what works now."""
    t = texts()
    m = missing()
    prio = [str(x) for x in t.get("priority") or []]
    rest = [*m["fields"], *(v for v in m["values"] if v.split(" ", 1)[0] not in m["fields"])]
    ordered = [x for x in prio if x in rest] + [x for x in rest if x not in prio]
    cap = int(t.get("max_listed") or _LIST_CAP)
    fill = {"schema_version": schema_version(), "baseline_date": baseline().get("date") or "an earlier date",
            "probe": _probe(), "tools": _join(m["tools"]), "fields": _join(ordered, cap)}
    parts = [t["lead_certain" if certain else "lead_likely"]]
    if any(m.values()):
        parts.append(t["missing"])
    parts += [t["refresh"], t["works_now"]]
    return " ".join(" ".join(p.split()) for p in parts).format(**fill)


def instructions() -> str:
    tools = bundle_tools()
    text = " ".join(str(texts().get("instructions") or "").split())
    return text.format(tool_count=len(tools), schema_version=schema_version(), probe=_probe())


# ── per-job state ──────────────────────────────────────────────────────────


def _state_path(job_id: str) -> Path | None:
    if _ctx is None or not _JOB_RE.match(job_id or ""):
        return None
    try:
        return Path(_ctx.get_pin_root()) / job_id / STATE_FILE
    except Exception:  # noqa: BLE001  # no pin root wired: no per-job state
        return None


def load_state(job_id: str) -> dict[str, Any]:
    p = _state_path(job_id)
    if p is None or not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(job_id: str, state: dict[str, Any]) -> None:
    p = _state_path(job_id)
    if p is None:
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(state, sort_keys=True))
        tmp.replace(p)
    except OSError as exc:  # the notice is advisory; a full disk must not fail a tool call
        logger.warning("client shape write failed for %s: %s", job_id[-8:], type(exc).__name__)


def _codes(body: Any) -> set[str]:
    if not isinstance(body, dict):
        return set()
    rows = [*(body.get("errors") or []), *(body.get("warnings") or [])]
    return {str(r.get("code")) for r in rows if isinstance(r, dict) and r.get("code")}


def decide(tool: str, arguments: dict[str, Any], body: Any, certain: bool) -> str | None:
    """The notice to attach to this result, or None. Records per-job freshness and the notice count."""
    if certain:
        return notice(True)
    job_id = str(arguments.get("job_id") or (body.get("job_id") if isinstance(body, dict) else "") or "")
    if not job_id or _state_path(job_id) is None:
        return None   # without per-job state the notice could not be capped: only the certain signal speaks
    state = load_state(job_id)
    if tool in added_tools():
        if not state.get("fresh"):
            state["fresh"] = True
            _save_state(job_id, state)
        return None
    if state.get("fresh"):
        return None
    t = texts()
    if int(state.get("notices") or 0) >= int(t.get("max_notices_per_job") or 4):
        return None
    if tool == "review_status" and state.get("status_noticed"):
        hit = bool(_codes(body) & set(t.get("notice_codes") or []))
    else:
        hit = tool in set(t.get("notice_tools") or []) or bool(_codes(body) & set(t.get("notice_codes") or []))
    if not hit:
        return None
    state["notices"] = int(state.get("notices") or 0) + 1
    if tool == "review_status":
        state["status_noticed"] = True
    _save_state(job_id, state)
    return notice(False)
