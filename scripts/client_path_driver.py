"""Client-path regression driver: the MCP tools over HTTP, called the way a client session calls them.

The two blind matrix runs (2026-10-25, 2026-10-26) found every PDF blocked by a server fault that the
unit suite never saw: review_set_section shapes, sections stored as lists and assembled as dicts,
report.facts narrower than the fact set the finding gate validated, a brand word inside a detector
name tripping the late gate, deployment.json missing for a TON tier A, a Solana tier never recorded,
render resets burned by server failures, empty_page and layout_overflow on real reports. This module
drives one fixture job end to end through the public tools only (review_start, review_status,
review_contract_map, review_leads, review_facts, review_read_code, review_get_guide,
review_submit_finding, review_challenge, review_answer_challenge, review_dismiss_lead,
review_set_section, review_finalize, review_report) and checks the outcome a client would see,
plus the PDF bytes the report store holds for the signed link.

Every target states its expectations (`TargetSpec`); `run_target` returns a `TargetResult` with
one row per check. Upstream outages (explorer, verifier, RPC, GitHub) turn a target into
`skipped: upstream` only when the named upstream probe fails at that moment; a server error never
skips. Used by scripts/client_path_e2e.py and .github/workflows/client-path-e2e.yml.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from soken_review.server import output_violations

_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25"}
_TERMINAL = frozenset({"ready", "insufficient_source", "failed", "expired", "deleted"})
# Job outcomes that can come from an upstream (explorer, verifier, RPC, repo host) being down. Any
# other terminal error is the server's. Even these only skip when the upstream probe fails too.
_UPSTREAM_CODES = frozenset({"E_SOURCE_NOT_FOUND", "E_REPO_UNREACHABLE", "E_CHAIN_PAUSED", "E_INSUFFICIENT_SOURCE",
                             "E_CAPACITY", "E_COMMIT_NOT_FOUND"})
_READ_WINDOW = 400          # review_read_code window (03 4.4)
_READ_BATCH = 8             # ranges per review_read_code call
_DISMISS_BATCH = 50         # items per review_dismiss_lead call
_WALK_ROWS = 20             # rows per invariant_walks call
_NAV_NOTE = ("Detector pattern matched, but the flagged lines were read in their function and the behaviour "
             "is the intended design at this location, so the lead records no weakness.")
_WALK_NOTE = ("Traced the focus functions and the anchor lines of this walk in full; the stated relation holds "
              "along every path that was read.")
_ANSWER_NOTE = "The scope ranges were read in full and the condition does not appear in them."
_PRESENT_NOTE = "The quoted lines inside the scope show the condition the item asks about."


class ClientPathError(Exception):
    """A server-side failure on the client path (never turns into a skip)."""


class UpstreamDown(Exception):
    """The job stopped on an upstream outcome and the upstream probe confirms the outage."""


# ── MCP over HTTP ───────────────────────────────────────────────────────────


class McpClient:
    """JSON-RPC tools/call over the Streamable HTTP endpoint. Control tools answer JSON objects; the
    bulk read tools answer the line format (03), returned as {"text": ...}."""

    def __init__(self, base_url: str, *, timeout: float = 120.0, log: Path | None = None) -> None:
        self.base = base_url.rstrip("/")
        self.http = httpx.Client(base_url=self.base, timeout=timeout)
        self.calls = 0
        self.log = log
        self._id = 0
        self._lock = threading.Lock()

    def call(self, tool: str, **arguments: Any) -> dict[str, Any]:
        with self._lock:
            self._id += 1
            rpc_id = self._id
        payload = {"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
                   "params": {"name": tool, "arguments": arguments}}
        last: Exception | None = None
        for attempt in range(4):
            try:
                r = self.http.post("/mcp", json=payload, headers=_HEADERS)
                if r.status_code >= 500:
                    raise ClientPathError(f"{tool}: HTTP {r.status_code} {r.text[:300]}")
                r.raise_for_status()
                data = r.json()
                break
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:   # the stack may still be warming up
                last = exc
                time.sleep(1.5 * (attempt + 1))
        else:
            raise ClientPathError(f"{tool}: transport failed: {last}")
        self.calls += 1
        if "error" in data:
            raise ClientPathError(f"{tool}: JSON-RPC error {json.dumps(data['error'])[:400]}")
        result = data.get("result") or {}
        content = result.get("content") or []
        text = content[0]["text"] if content and content[0].get("type") == "text" else ""
        if self.log is not None:
            with self.log.open("a", encoding="utf-8") as fh:
                fh.write(f"\n### {tool} {json.dumps(arguments)[:1500]}\n{text[:6000]}\n")
        if result.get("isError"):
            try:
                env = json.loads(text)
            except ValueError:
                env = {"code": "E_UNKNOWN", "what": text[:300]}
            raise ToolError(tool, env)
        # Claude Code drops a structured result that breaks the tool's outputSchema (2026-10-31: every
        # review_report lost its PDF link), so the client path must fail on it too.
        bad = output_violations(tool, result.get("structuredContent"))
        if bad:
            raise ClientPathError(f"{tool}: structured result breaks its outputSchema: {'; '.join(bad[:10])}")
        if text.startswith("{"):
            return json.loads(text)
        return {"text": text}


class ToolError(ClientPathError):
    """isError true: the error envelope of contract/errors.yaml."""

    def __init__(self, tool: str, envelope: dict[str, Any]) -> None:
        self.tool, self.envelope = tool, envelope
        self.code = str(envelope.get("code") or "E_UNKNOWN")
        super().__init__(f"{tool}: {self.code} {envelope.get('what', '')} {envelope.get('fix', '')}"[:500])


# ── Target specification and result ───────────────────────────────────────


@dataclass
class FindingSpec:
    """One finding the driver files: the quoted function is located in the pinned file by `locate`."""
    file_hint: str                 # substring of the pinned path to quote from
    locate: str                    # text of the line that opens the quoted block
    category: str
    title: str
    description: str               # may hold {fact} which is replaced by {{fact:<key>}} of a real fact
    impact: str
    recommendation: str
    matrix: dict[str, str]
    expect_severity: str


@dataclass
class TargetSpec:
    name: str
    start: dict[str, Any]          # review_start arguments
    probe_url: str                 # upstream the job depends on; a failing probe turns an upstream stop into a skip
    chain: str                     # meta.chain of the report
    network: str                   # meta.network of the report
    tiers: tuple[str, ...]         # accepted provenance tiers
    finding: FindingSpec | None = None
    stale_walks: bool = False      # send invariant_walks as a JSON string (stale client schema, PR #77)
    expect_dependencies: bool = False
    expect_lead_tool: str | None = None    # a tool label that must raise at least one lead (e.g. slither)
    expect_out_of_scope: tuple[str, ...] = ()  # path fragments that must not be in-scope units
    expect_guarded_entry: tuple[str, str] | None = None  # (unit name fragment, entry name) with a caller_check
    min_pages: int = 4
    ready_timeout_s: float = 1200.0
    render_timeout_s: float = 600.0
    address_in_cover: str | None = None
    chain_read: dict[str, Any] | None = None   # review_chain_read step: {items, cite}; the finding cites `cite`
    fork_test: dict[str, Any] | None = None    # review_verify_on_fork step: {content, test}; bound to the finding
    # the start address is a proxy: one job reviews the implementation, reads state at the proxy,
    # pins the proxy source as related `proxy`, and the cover names both (matrix run 2026-10-31, Venus)
    expect_proxy: bool = False
    expect_facts: tuple[str, ...] = ()        # fact keys the job must hold (read at the start address)
    expect_library_ref: str | None = None      # TON: a library hash the report's verification table names


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    gap: bool = False     # a known server gap: recorded and printed, does not fail the target


@dataclass
class TargetResult:
    name: str
    status: str = "fail"           # pass | fail | skipped: upstream
    job_id: str | None = None
    checks: list[Check] = field(default_factory=list)
    pdf: str | None = None
    pages: int | None = None
    calls: int = 0
    seconds: float = 0.0
    error: str | None = None

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(Check(name, bool(ok), detail[:400]))

    def gap(self, name: str, ok: bool, detail: str = "") -> None:
        """A check for behaviour the blind runs asked for and main does not have yet (KNOWN_GAPS): its
        failure is printed as GAP and listed in the result, and stops failing the run once it passes."""
        self.checks.append(Check(name, bool(ok), detail[:400], gap=True))

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and not c.gap]

    @property
    def gaps(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.gap]


# ── Parsing the line formats ───────────────────────────────────────────────

_LEAD_RE = re.compile(r"^(LEAD-\d{4}) (\w+) (\S+) (\w+) (\S+?):(\d+)-(\d+)(?: prev \S+)? (\S+) \[([^\]]*)\]")
_WALK_RE = re.compile(r"^(IW-[A-Z]{2,4}-\d{1,2}) ")
_RANGE_RE = re.compile(r"^([A-Za-z0-9_./-]{1,200}):(\d{1,6})-(\d{1,6})$")
_LINE_RE = re.compile(r"^(\d+)\| (.*)$")
_UNIT_RE = re.compile(r"^unit (\S+) (\S+) (\S+?):(\d+)-(\d+)$")


def parse_leads(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        m = _LEAD_RE.match(line)
        if m:
            out.append({"id": m.group(1), "state": m.group(2), "category": m.group(3), "severity": m.group(4),
                        "path": m.group(5), "start": int(m.group(6)), "end": int(m.group(7)), "rule": m.group(8),
                        "tools": m.group(9).split("+")})
    return out


def parse_walks(text: str) -> list[dict[str, Any]]:
    """Walk rows of review_get_guide topic invariants: id, focus ranges, anchor refs."""
    walks: list[dict[str, Any]] = []
    for line in text.splitlines():
        m = _WALK_RE.match(line)
        if m:
            walks.append({"id": m.group(1), "focus": [], "anchors": []})
        elif walks and line.startswith("  focus: "):
            for part in line[len("  focus: "):].split(", "):
                rng = part.rsplit(" ", 1)[-1]
                if _RANGE_RE.match(rng):
                    walks[-1]["focus"].append(rng)
        elif walks and line.startswith("  anchors: "):
            for part in line[len("  anchors: "):].split(", "):
                ref = part.rsplit(" ", 1)[-1]
                path, _, ln = ref.rpartition(":")
                if path and ln.isdigit():
                    walks[-1]["anchors"].append(f"{path}:{ln}-{ln}")
    return walks


def parse_units(text: str) -> list[dict[str, Any]]:
    units = []
    for line in text.splitlines():
        m = _UNIT_RE.match(line)
        if m:
            units.append({"id": m.group(1), "kind": m.group(2), "file": m.group(3), "start": int(m.group(4)),
                          "end": int(m.group(5))})
    return units


_META_RE = re.compile(r"^(\S+) sha256:[0-9a-f]+ lines (\d+)-(\d+) of (\d+)")


def parse_read(text: str, totals: dict[str, int] | None = None) -> dict[str, dict[int, str]]:
    """{path: {lineno: text}} from one or several read blocks; `totals` collects the file line counts."""
    out: dict[str, dict[int, str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("Untrusted source data, "):
            current = line.split(", ", 2)[1].removeprefix("file ").removeprefix("project document ")
            current = current.split(", lines ")[0]
            out.setdefault(current, {})
            continue
        mm = _META_RE.match(line)
        if mm and totals is not None:
            totals[mm.group(1)] = int(mm.group(4))
            continue
        m = _LINE_RE.match(line)
        if m and current is not None:
            out[current][int(m.group(1))] = m.group(2)
    return out


def split_range(ref: str) -> list[tuple[str, int, int]]:
    m = _RANGE_RE.match(ref)
    if not m:
        raise ClientPathError(f"not a range ref: {ref!r}")
    path, start, end = m.group(1), int(m.group(2)), int(m.group(3))
    return [(path, s, min(s + _READ_WINDOW - 1, end)) for s in range(start, end + 1, _READ_WINDOW)]


# ── The flow ───────────────────────────────────────────────────────────────


class Session:
    """One reviewer session on one job."""

    def __init__(self, client: McpClient, job_id: str, res: TargetResult) -> None:
        self.c, self.job_id, self.res = client, job_id, res
        self.reads: dict[str, dict[int, str]] = {}
        self.totals: dict[str, int] = {}

    def read(self, refs: list[str]) -> None:
        """Read every ref in full (400-line windows, 8 per call) and keep the numbered lines."""
        windows = [w for ref in refs for w in split_range(ref)]
        for i in range(0, len(windows), _READ_BATCH):
            batch = windows[i:i + _READ_BATCH]
            out = self.c.call("review_read_code", job_id=self.job_id,
                              ranges=[{"path": p, "start_line": s, "end_line": e} for p, s, e in batch])
            for path, lines in parse_read(out["text"], self.totals).items():
                self.reads.setdefault(path, {}).update(lines)

    def read_file(self, path: str) -> dict[int, str]:
        """The whole pinned file, window by window."""
        self.read([f"{path}:1-{_READ_WINDOW}"])
        total = self.totals.get(path, 0)
        if total > _READ_WINDOW:
            self.read([f"{path}:{_READ_WINDOW + 1}-{total}"])
        return self.reads.get(path) or {}

    def quote(self, path: str, start: int, end: int) -> dict[str, Any]:
        lines = self.reads.get(path) or {}
        missing = [n for n in range(start, end + 1) if n not in lines]
        if missing:
            self.read([f"{path}:{start}-{end}"])
            lines = self.reads.get(path) or {}
        text = "\n".join(lines.get(n, "") for n in range(start, end + 1))
        return {"file": path, "start": start, "end": end, "text": text, "role": "location"}

    def facts(self) -> list[tuple[str, str]]:
        out = self.c.call("review_facts", job_id=self.job_id, page_size=200)
        rows = []
        for line in out["text"].splitlines()[1:]:
            if line in ("end",) or line.startswith("next_cursor"):
                continue
            parts = line.split(" ", 2)
            if len(parts) >= 2:
                rows.append((parts[0], parts[1]))
        return rows


def _status(client: McpClient, job_id: str, fmt: str = "concise") -> dict[str, Any]:
    return client.call("review_status", job_id=job_id, response_format=fmt)


def wait_ready(client: McpClient, job_id: str, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    status = _status(client, job_id)
    while status.get("state") not in _TERMINAL and time.monotonic() < deadline:
        status = client.call("review_status", job_id=job_id, wait_seconds=45, wait_for="settled")
    if status.get("state") not in _TERMINAL:
        raise ClientPathError(f"job {job_id} still {status.get('state')} after {timeout_s:.0f}s")
    return status


def probe(url: str) -> tuple[bool, str]:
    """True when the upstream answers something other than a 5xx/429 or a transport failure."""
    try:
        r = httpx.get(url, timeout=20, follow_redirects=True, headers={"User-Agent": "soken-client-path-e2e"})
    except httpx.HTTPError as exc:
        return False, f"{type(exc).__name__}: {exc}"[:200]
    return (r.status_code < 500 and r.status_code != 429), f"HTTP {r.status_code}"


def locate_block(lines: dict[int, str], opener: str) -> tuple[int, int]:
    """Lines of the block that opens at the line holding `opener` and closes at the first line whose
    stripped text is a single closing brace at the opener's indentation."""
    start = next((n for n in sorted(lines) if opener in lines[n]), None)
    if start is None:
        raise ClientPathError(f"could not locate {opener!r} in the pinned file")
    indent = len(lines[start]) - len(lines[start].lstrip())
    for n in range(start + 1, max(lines) + 1):
        text = lines.get(n, "")
        if text.strip() == "}" and len(text) - len(text.lstrip()) == indent:
            return start, n
    return start, min(start + 12, max(lines))


def chain_read_step(sess: Session, spec: dict[str, Any]) -> str | None:
    """review_chain_read at the pinned block (latest when the free pool cannot serve it, recorded as a
    gap); returns the fact key the finding cites, None when no free source answered."""
    cite = spec["cite"]
    out = sess.c.call("review_chain_read", job_id=sess.job_id, block="pinned", items=spec["items"])
    item = (out.get("items") or [{}])[0] if out.get("accepted") else {}
    pinned_ok = bool(item.get("ok")) and cite in (out.get("fact_keys") or [])
    sess.res.gap("review_chain_read served the pinned block from the free pool", pinned_ok,
                 json.dumps({"block": out.get("block"), "item": item, "errors": out.get("errors")})[:380])
    if not pinned_ok:
        out = sess.c.call("review_chain_read", job_id=sess.job_id, block="latest", items=spec["items"])
        item = (out.get("items") or [{}])[0] if out.get("accepted") else {}
    block = (out.get("block") or {}).get("resolved")
    ok = bool(out.get("accepted")) and bool(item.get("ok")) and cite in (out.get("fact_keys") or []) \
        and isinstance(block, int)
    sess.res.check("review_chain_read returned the fact with its block", ok,
                   json.dumps({"block": out.get("block"), "value": item.get("value"), "budget": out.get("budget"),
                               "capability": (out.get("capability") or {}).get("history"),
                               "errors": out.get("errors")})[:380])
    if not ok:
        return None
    sess.res.check("chain value is a positive integer", str(item.get("value", "")).isdigit() and int(item["value"]) > 0,
                   str(item.get("value")))
    listed = {k for k, _ in sess.facts()}
    sess.res.check("review_facts lists the chain fact", cite in listed, f"{len(listed)} facts")
    spec["_block"] = block
    return cite


def verify_on_fork_step(sess: Session, spec: dict[str, Any], draft_key: str, timeout_s: float = 600.0) -> bool:
    """review_verify_on_fork with a small assertion test, bound to the filed finding; polls the run to
    its end. A run the free pool could not serve is a gap (upstream), any other non-pass a failure.
    Returns True when the run passed (the report check then looks for the verified line)."""
    out = sess.c.call("review_verify_on_fork", job_id=sess.job_id, draft_key=draft_key, wait_seconds=45,
                      test={"path": "test/Verify.t.sol", "content": spec["content"]})
    sess.res.check("review_verify_on_fork queued the run", bool(out.get("accepted")) and bool(out.get("run_id")),
                   json.dumps({k: out.get(k) for k in ("status", "run_id", "chain", "errors")})[:380])
    if not out.get("accepted"):
        return False
    deadline = time.monotonic() + timeout_s
    while out.get("status") in ("queued", "running") and time.monotonic() < deadline:
        out = sess.c.call("review_verify_on_fork", job_id=sess.job_id, run_id=out["run_id"], wait_seconds=45)
    status, reason = out.get("status"), out.get("reason")
    detail = json.dumps({"status": status, "reason": reason, "tests": out.get("tests"), "rpc": out.get("rpc"),
                         "diagnostics": out.get("diagnostics"), "wall_s": out.get("wall_s")})[:380]
    if status == "error" and reason == "chain_unavailable":
        sess.res.gap("the free pool served the fork at the pinned block", False, detail)
        return False
    sess.res.check("the fork test passed on a local fork through the read-only proxy", status == "passed", detail)
    if status != "passed":
        return False
    rpc = out.get("rpc") or {}
    sess.res.check("the run read chain state through the proxy", int(rpc.get("upstream_calls") or 0) > 0
                   and int(rpc.get("bad_path") or 0) == 0, json.dumps(rpc)[:300])
    ev = out.get("evidence") or {}
    block = (out.get("chain") or {}).get("block")
    sess.res.check("a passing run raises the finding to test_verified with the report line",
                   ev.get("level") == "test_verified" and f"at block {block:,}" in str(ev.get("report_line")),
                   json.dumps(ev)[:300])
    spec["_block"], spec["_line"] = block, ev.get("report_line")
    return True


def submit_finding(sess: Session, spec: FindingSpec, units: list[dict[str, Any]],
                   prefer_key: str | None = None) -> dict[str, Any]:
    path = next((u["file"] for u in units if spec.file_hint in u["file"]), None)
    if path is None:
        raise ClientPathError(f"no in-scope unit matches {spec.file_hint!r}: {[u['file'] for u in units]}")
    lines = sess.read_file(path)
    start, end = locate_block(lines, spec.locate)
    quote = sess.quote(path, start, end)
    facts = sess.facts()
    keys = [k for k, _ in facts]
    key = prefer_key if prefer_key in keys else next(
        (k for pref in ("chain.chain_id", "chain.", "deploy.", "source.") for k in keys if k.startswith(pref)),
        keys[0] if keys else None)
    sess.res.check("facts listed", key is not None, f"{len(facts)} facts, placeholder key {key}")
    description = spec.description.replace("{fact}", f"{{{{fact:{key}}}}}" if key else "")
    args = {
        "job_id": sess.job_id, "draft_key": "client-path-f01", "category": spec.category,
        "quotes": [quote], "matrix": spec.matrix, "lead_ids": [], "title": spec.title,
        "claimed_severity": spec.expect_severity,
        "body": {"description": [{"p": description}], "impact": [{"p": spec.impact}],
                 "recommendation": [{"p": spec.recommendation}]},
    }
    out = sess.c.call("review_submit_finding", **args)
    if not out.get("accepted"):
        raise ClientPathError(f"review_submit_finding rejected: {json.dumps(out.get('errors'))[:800]}")
    sess.res.check("finding accepted", True, f"{out.get('finding_no')} computed {out.get('computed_severity')} "
                   f"rule {out.get('severity_rule')} set_by {out.get('severity_set_by')}")
    sess.res.check("the reviewer's severity is the printed severity, the matrix a calibration",
                   out.get("computed_severity") == spec.expect_severity and out.get("severity_set_by") == "reviewer"
                   and "calibration" in out and "E_SEVERITY_CONFIRM" not in json.dumps(out.get("warnings") or []),
                   json.dumps({k: out.get(k) for k in ("computed_severity", "severity_set_by", "calibration")})[:300])
    sess.res.check("severity payload carries severity_rule/severity_set_by/severity_reason",
                   all(k in out for k in ("severity_rule", "severity_set_by", "severity_reason")),
                   json.dumps({k: out.get(k) for k in ("severity_rule", "severity_set_by", "severity_reason",
                                                       "caps_applied")})[:300])
    out["_quote"] = quote
    return out


def answer_challenge(sess: Session, draft_key: str, quote: dict[str, Any]) -> dict[str, Any]:
    """Read every scope range, answer absent; items whose auto check says present get the location
    quote as evidence; at most four rounds."""
    ch = sess.c.call("review_challenge", job_id=sess.job_id, draft_key=draft_key)
    if not ch.get("accepted"):
        raise ClientPathError(f"review_challenge rejected: {json.dumps(ch.get('errors'))[:600]}")
    items = ch["items"]
    sess.res.check("challenge items returned", bool(items), f"{len(items)} items, revision {ch.get('revision')}")
    present: set[str] = set()
    for _round in range(4):
        answers = []
        for it in items:
            ranges = list((it.get("scope") or {}).get("ranges") or [])
            if ranges:
                sess.read(ranges)
            if it["id"] in present:
                answers.append({"item_id": it["id"], "value": "present", "quotes": [quote], "note": _PRESENT_NOTE})
            else:
                row: dict[str, Any] = {"item_id": it["id"], "value": "absent", "note": _ANSWER_NOTE}
                if ranges:
                    row["refs"] = ranges[:16]
                answers.append(row)
        out = sess.c.call("review_answer_challenge", job_id=sess.job_id, draft_key=draft_key,
                          revision=ch["revision"], answers=answers)
        if out.get("accepted"):
            sess.res.check("challenge answered", True, f"verdict {out.get('verdict')} severity {out.get('severity')} "
                           f"rule {out.get('severity_rule')} set_by {out.get('severity_set_by')}")
            return out
        errors = out.get("errors") or []
        flipped = False
        for e in errors:
            if e.get("code") == "E_CHALLENGE_CONTRADICTS_AUTO":
                # The envelope names the auto check ("<auto_id>=present"), not the item: flip every item
                # bound to that auto check, as a reviewer would after reading the scope.
                auto = str(e.get("auto") or "")
                m = re.search(r"([A-Za-z0-9_.-]+)=present", auto or json.dumps(e))
                auto_id = m.group(1) if m else None
                for it in items:
                    if it.get("auto") and (auto_id is None or it["auto"] == auto_id) and it["id"] not in present:
                        present.add(it["id"])
                        flipped = True
        if not flipped:
            raise ClientPathError(f"review_answer_challenge rejected: {json.dumps(errors)[:900]}")
    raise ClientPathError("challenge not accepted after four rounds")


def close_leads(sess: Session, leads: list[dict[str, Any]]) -> None:
    open_hm = [l for l in leads if l["state"] == "open" and l["severity"] in ("high", "medium")]
    if not open_hm:
        sess.res.check("no open High/Medium leads to close", True)
        return
    rejected: list[str] = []
    still_open = None
    for i in range(0, len(open_hm), _DISMISS_BATCH):
        batch = open_hm[i:i + _DISMISS_BATCH]
        out = sess.c.call("review_dismiss_lead", job_id=sess.job_id,
                          items=[{"lead_id": l["id"], "reason": "not_a_vulnerability", "note": _NAV_NOTE} for l in batch])
        for row in out.get("rejected") or []:
            rejected.append(json.dumps(row)[:200])
        if not out.get("accepted"):
            rejected.append(json.dumps(out.get("errors"))[:300])
        still_open = out.get("high_medium_open", still_open)
    sess.res.check(f"dismissed {len(open_hm)} open High/Medium leads", not rejected and not still_open,
                   f"high_medium_open after: {still_open}; rejected: " + "; ".join(rejected)[:400])


def set_sections(sess: Session, spec: TargetSpec, draft_key: str | None) -> None:
    jid = sess.job_id
    out = sess.c.call("review_set_section", job_id=jid, section="roles_notes", roles_notes={"rows": [
        {"role": "privileged key", "risk_note": "Privileged setters are held by a single key that acts at once."}]})
    sess.res.check("section roles_notes accepted", bool(out.get("accepted")), json.dumps(out.get("errors"))[:300])
    out = sess.c.call("review_set_section", job_id=jid, section="out_of_scope_reasons", out_of_scope_reasons={"rows": [
        {"item_id": "X-001", "reason": "Vendored library code, reviewed only where an in-scope unit calls into it."}]})
    sess.res.check("section out_of_scope_reasons accepted", bool(out.get("accepted")), json.dumps(out.get("errors"))[:300])
    # Coverage N/A rows exist for evm.reentrancy / nr_no_external_call only (checklists na: lists); the
    # predicate is the server's, so a confirmed-false predicate is a correct refusal, not a fault.
    if spec.chain in ("evm", "tron"):
        out = sess.c.call("review_set_section", job_id=jid, section="coverage", coverage={"rows": [
            {"area_id": "evm.reentrancy", "reason": "nr_no_external_call",
             "note": "The in-scope units make no external call, so reentrancy has no entry."}]})
        codes = {e.get("code") for e in (out.get("errors") or [])}
        ok = bool(out.get("accepted")) or codes <= {"E_COVERAGE_NA_UNCONFIRMED"}
        sess.res.check("section coverage accepted or refused by predicate only", ok,
                       "accepted" if out.get("accepted") else json.dumps(out.get("errors"))[:300])
    else:
        sess.res.check("section coverage", True, f"no N/A reasons exist for family {spec.chain}; not sent")
    guide = sess.c.call("review_get_guide", topics=["invariants"], job_id=jid)
    walks = parse_walks(guide["text"])
    if not walks:
        sess.res.check("section invariant_walks", True, "job has no invariant walks")
        return
    rows = []
    for w in walks:
        refs = (w["focus"] + w["anchors"])[:16]
        if refs:
            sess.read(refs)
            rows.append({"walk_id": w["id"], "outcome": "holds", "refs": refs, "note": _WALK_NOTE})
        else:
            rows.append({"walk_id": w["id"], "outcome": "not_applicable", "note": _WALK_NOTE})
    for i in range(0, len(rows), _WALK_ROWS):
        payload: Any = {"rows": rows[i:i + _WALK_ROWS]}
        if spec.stale_walks:
            payload = json.dumps(payload)   # stale client schema: object sent as a JSON string (PR #77)
        out = sess.c.call("review_set_section", job_id=jid, section="invariant_walks", invariant_walks=payload)
        label = "section invariant_walks accepted" + (" (sent as JSON string)" if spec.stale_walks else "")
        sess.res.check(label, bool(out.get("accepted")),
                       f"{len(walks)} walks, open after call: {out.get('walks_open')}" if out.get("accepted")
                       else json.dumps(out.get("errors"))[:400])


def finalize_and_render(sess: Session, spec: TargetSpec) -> dict[str, Any]:
    fin = sess.c.call("review_finalize", job_id=sess.job_id)
    if not fin.get("accepted"):
        st = _status(sess.c, sess.job_id, "detailed")
        raise ClientPathError(f"review_finalize rejected: {json.dumps(fin.get('errors'))[:500]} "
                              f"checks {json.dumps(st.get('finalize_checks'))[:400]}")
    sess.res.check("finalize accepted", True, f"state {fin.get('state')} final_ids {fin.get('final_ids')}")
    deadline = time.monotonic() + spec.render_timeout_s
    rep = sess.c.call("review_report", job_id=sess.job_id, wait_seconds=45)
    while rep.get("status") == "render_pending" and time.monotonic() < deadline:
        rep = sess.c.call("review_report", job_id=sess.job_id, wait_seconds=45)
    if rep.get("status") != "ready":
        st = _status(sess.c, sess.job_id, "detailed")
        err = st.get("error") or {}
        raise ClientPathError(f"report {rep.get('status')} code {rep.get('code')}: {json.dumps(err)[:600]}")
    return rep


def pdf_pages(data: bytes) -> int:
    from io import BytesIO

    from pdfminer.pdfpage import PDFPage

    return sum(1 for _ in PDFPage.get_pages(BytesIO(data)))


def find_report_files(store_root: Path, report_id: str) -> tuple[Path | None, Path | None]:
    base = store_root / "reports" / report_id
    pdfs = sorted(base.glob("*/report.pdf")) if base.exists() else []
    if not pdfs:
        return None, None
    return pdfs[-1], pdfs[-1].with_name("report.json")


def check_report(sess: Session, spec: TargetSpec, rep: dict[str, Any], store_root: Path, out_dir: Path) -> None:
    res = sess.res
    res.check("review_report ready with links", bool(rep.get("pdf_url")) and bool(rep.get("url")),
              f"report_id {rep.get('report_id')} pages {rep.get('pages')} counts {rep.get('counts')}")
    res.check("cover chain", rep.get("chain") == spec.chain, f"{rep.get('chain')!r} expected {spec.chain!r}")
    res.check("cover network", rep.get("network") == spec.network, f"{rep.get('network')!r} expected {spec.network!r}")
    tier = (rep.get("provenance") or {}).get("tier")
    res.check("cover provenance tier", tier in spec.tiers, f"tier {tier!r} label {(rep.get('provenance') or {}).get('label')!r}")
    pdf_path, json_path = find_report_files(store_root, str(rep.get("report_id")))
    if pdf_path is None:
        res.check("PDF bytes in the report store", False, f"no reports/{rep.get('report_id')}/*/report.pdf under {store_root}")
        return
    data = pdf_path.read_bytes()
    res.check("PDF bytes in the report store", data.startswith(b"%PDF-"), f"{len(data)} bytes at {pdf_path}")
    pages = pdf_pages(data)
    res.pages = pages
    res.check(f"page count > {spec.min_pages - 1}", pages >= spec.min_pages, f"{pages} pages (review_report says {rep.get('pages')})")
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f"{spec.name}-{rep.get('report_id')}.pdf"
    dest.write_bytes(data)
    res.pdf = str(dest)
    if json_path and json_path.exists():
        report = json.loads(json_path.read_text(encoding="utf-8"))
        meta = report.get("meta") or {}
        prov = meta.get("provenance") or {}
        (out_dir / f"{spec.name}-report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
        if spec.expect_library_ref:
            # multisig v2: the order code is a masterchain library the code names by hash
            text = json.dumps(report.get("verification") or [], ensure_ascii=False)
            res.check("verification names the library reference", spec.expect_library_ref in text
                      and "Library reference" in text, f"library {spec.expect_library_ref[:12]}")
        res.check("report.json cover matches review_report", meta.get("chain") == rep.get("chain")
                  and meta.get("network") == rep.get("network") and prov.get("tier") == tier,
                  f"meta chain {meta.get('chain')} network {meta.get('network')} tier {prov.get('tier')} label {prov.get('label')!r}")
        if spec.address_in_cover:
            addr = str(prov.get("address") or "")
            res.check("cover provenance line names the start address", addr.lower() == spec.address_in_cover.lower(),
                      f"provenance.address {addr!r}")
        impl = getattr(spec, "_implementation", "")
        if spec.expect_proxy:
            res.check("cover names the implementation beside the proxy",
                      bool(impl) and str(prov.get("implementation") or "").lower() == impl.lower(),
                      f"provenance.implementation {prov.get('implementation')!r} pattern {prov.get('proxy_pattern')!r}")
        raw_facts = report.get("facts") or {}
        facts = set(raw_facts) if isinstance(raw_facts, dict) else {str(f.get("key")) for f in raw_facts}
        res.check("report.facts carries the fact set, not context.* only",
                  bool(facts) and any(not k.startswith("context.") for k in facts),
                  f"{len(facts)} fact keys, first {sorted(facts)[:4]}")
        if spec.chain_read and spec.chain_read.get("_block"):
            key, block = spec.chain_read["cite"], spec.chain_read["_block"]
            rec = (raw_facts or {}).get(key) if isinstance(raw_facts, dict) else None
            res.check("report prints the chain fact with its network and block",
                      bool(rec) and f"block {block:,}" in str(rec.get("at")), json.dumps(rec)[:200])
            figs = [op["source"] for f in report.get("findings") or [] for g in (f.get("evidence") or {}).get("figures") or []
                    for op in g.get("operands") or [] if "fact" in op.get("source", {})]
            res.check("finding Figures used row names the chain read and its block",
                      any(src.get("fact") == key and src.get("block_or_slot") == block for src in figs), json.dumps(figs)[:300])
        if spec.fork_test and spec.fork_test.get("_block"):
            verified = [f for f in report.get("findings") or [] if f.get("evidence_level") == "test_verified"]
            ft = ((verified[0].get("evidence") or {}).get("fork_test") or {}) if verified else {}
            res.check("report.json prints the finding as verified on the fork at its block",
                      bool(verified) and ft.get("block") == spec.fork_test["_block"] and bool(ft.get("tests")),
                      json.dumps(ft)[:300] if ft else f"levels {[f.get('evidence_level') for f in report.get('findings') or []]}")
        if spec.finding:
            sevs = [f.get("severity") for f in report.get("findings") or []]
            res.check(f"a {spec.finding.expect_severity} finding is printed", spec.finding.expect_severity in sevs,
                      f"printed severities {sevs}")
            for f in report.get("findings") or []:
                blob = json.dumps(f)
                res.check("printed finding carries its severity basis (rule, set by, reason)",
                          '"Set by"' in blob and '"Rule"' in blob, blob[:200])
                break


def check_proxy_job(sess: Session, spec: TargetSpec, status: dict[str, Any]) -> None:
    """One job for a proxy: the implementation is the reviewed code, the state facts come from the
    proxy (a job on the implementation read owner 0x0 there), the proxy source is pinned beside it."""
    res = sess.res
    start_addr = str(spec.start["source"]["address"]).lower()
    proxy = status.get("proxy") or {}
    impl = str(proxy.get("implementation") or "")
    res.check("status names the proxy and its implementation",
              str(proxy.get("proxy") or "").lower() == start_addr and impl.startswith("0x") and impl.lower() != start_addr,
              json.dumps(proxy)[:300])
    spec._implementation = impl  # type: ignore[attr-defined]  # read by check_report
    res.check("proxy runtime verified (its own Sourcify match on this chain)", proxy.get("verified") is True,
              str(proxy.get("note") or proxy.get("verified")))
    related = status.get("related") or []
    res.check("proxy source pinned as related `proxy`",
              any(r.get("role") == "proxy" and r.get("status") == "pinned" for r in related), json.dumps(related)[:300])
    facts = dict(sess.facts())
    res.check("deploy.address is the proxy", facts.get("deploy.address", "").lower() == start_addr,
              f"deploy.address {facts.get('deploy.address')!r}")
    res.check("deploy.proxy.implementation recorded", facts.get("deploy.proxy.implementation", "").lower() == impl.lower(),
              f"deploy.proxy.implementation {facts.get('deploy.proxy.implementation')!r}")
    for key in spec.expect_facts:
        val = facts.get(key, "")
        res.check(f"{key} read at the proxy (non-zero)", bool(val) and int(val, 16) != 0 if val.startswith("0x") else bool(val),
                  f"{key} {val!r}")
    if "onchain.eip1967.implementation" in facts:
        res.check("the implementation slot read at the proxy is the reviewed implementation",
                  facts["onchain.eip1967.implementation"].lower() == impl.lower(), facts["onchain.eip1967.implementation"])


def run_target(spec: TargetSpec, base_url: str, store_root: Path, out_dir: Path) -> TargetResult:
    res = TargetResult(name=spec.name)
    t0 = time.monotonic()
    out_dir.mkdir(parents=True, exist_ok=True)
    client = McpClient(base_url, log=out_dir / f"{spec.name}.calls.log")
    try:
        start = client.call("review_start", **spec.start, wait_seconds=45)
        res.job_id = start.get("job_id")
        res.check("review_start returned job_id", bool(res.job_id), json.dumps(start)[:300])
        # thin server (2026-10-31): the default guide rides on review_start, no guide call needed
        res.check("review_start carries the default guide", "review_submit_finding" in str(start.get("guide") or ""),
                  str(start.get("guide") or "")[:120])
        status = wait_ready(client, res.job_id, spec.ready_timeout_s)
        state = status.get("state")
        if state != "ready":
            code = (status.get("error") or {}).get("code") or ""
            detail = json.dumps(status.get("error"))[:500]
            if state == "insufficient_source" or code in _UPSTREAM_CODES:
                ok, why = probe(spec.probe_url)
                if not ok:
                    raise UpstreamDown(f"job {state} {code}; upstream probe {spec.probe_url} failed: {why}")
                raise ClientPathError(f"job {state} {code} while the upstream answers ({why}): {detail}")
            raise ClientPathError(f"job {state}: {detail}")
        if spec.start["source"].get("kind") == "deployed":
            res.check("review_status carries chain_state for the deployment", "chain_state" in status,
                      json.dumps(status.get("chain_state"))[:300])
        prov = status.get("provenance") or {}
        res.check("job ready", True, f"tier {prov.get('tier')} map_status {status.get('map_status')} "
                  f"analyzer_degraded {status.get('analyzer_degraded')}")
        res.check("tier recorded (not null)", prov.get("tier") is not None, f"tier {prov.get('tier')!r}")
        res.check("tier in expected set", prov.get("tier") in spec.tiers, f"tier {prov.get('tier')!r} expected {spec.tiers}")
        if spec.expect_dependencies:
            det = _status(client, res.job_id, "detailed")
            deps = det.get("dependencies") or {}
            res.check("npm dependencies resolved", int(deps.get("count") or 0) > 0,
                      f"manager {deps.get('manager')} count {deps.get('count')} pinned_by {deps.get('pinned_by')} "
                      f"packages {[p.get('name') for p in deps.get('packages') or []][:5]}")
        sess = Session(client, res.job_id, res)
        if spec.expect_proxy:
            check_proxy_job(sess, spec, status)
        cmap = client.call("review_contract_map", job_id=res.job_id, page_size=30, response_format="detailed")
        units = parse_units(cmap["text"])
        head = cmap["text"].splitlines()[0]
        res.check("contract map returned (partial or full)", head.startswith("contract map") and bool(units), head[:200])
        # Apyee blind run 2026-10-26 friction 3 and 11, closed by PR #84: contracts/mocks and test contracts
        # are scope_excluded in repo mode, and an OpenZeppelin onlyOwner modifier in lib/ is followed to its
        # caller check. Both are regression checks now.
        for frag in spec.expect_out_of_scope:
            hit = sorted({u["file"] for u in units if frag in u["file"]})
            res.check(f"{frag} units are out of scope", not hit, f"in-scope units matching: {hit[:4]}")
        if spec.expect_guarded_entry:
            unit_frag, entry = spec.expect_guarded_entry
            block = cmap["text"]
            m = re.search(rf"^  entry \S*{re.escape(unit_frag)}\S*\.{re.escape(entry)}\([^\n]*\n    guards: ([^\n]*)",
                          block, re.MULTILINE)
            guards = m.group(1) if m else "(entry not listed)"
            res.check(f"{entry} credited with a caller_check guard", "caller_check" in guards, guards[:200])
        leads_out = client.call("review_leads", job_id=res.job_id, status="all", page_size=100)
        leads = parse_leads(leads_out["text"])
        res.check("leads > 0", len(leads) > 0, leads_out["text"].splitlines()[0][:200])
        if spec.expect_lead_tool:
            tools = {t for l in leads for t in l["tools"]}
            res.check(f"{spec.expect_lead_tool} leads > 0", spec.expect_lead_tool in tools, f"tools {sorted(tools)}")
        draft_key = None
        cite = chain_read_step(sess, spec.chain_read) if spec.chain_read else None
        if spec.finding:
            sub = submit_finding(sess, spec.finding, units, prefer_key=cite)
            draft_key = sub["draft_key"]
            if sub.get("status") == "needs_challenge":
                answer_challenge(sess, draft_key, sub["_quote"])
            else:
                res.check("challenge", True, f"draft status {sub.get('status')}, no challenge due")
            if spec.fork_test:
                verify_on_fork_step(sess, spec.fork_test, draft_key)
        close_leads(sess, leads)
        set_sections(sess, spec, draft_key)
        rep = finalize_and_render(sess, spec)
        check_report(sess, spec, rep, store_root, out_dir)
        res.status = "pass" if not res.failed else "fail"
    except UpstreamDown as exc:
        res.status = "skipped: upstream"
        res.error = str(exc)
    except ClientPathError as exc:
        res.status = "fail"
        res.error = str(exc)
    except Exception as exc:  # noqa: BLE001  # a driver fault is still a failed target, never a skip
        res.status = "fail"
        res.error = f"{type(exc).__name__}: {exc}"
    res.calls = client.calls
    res.seconds = time.monotonic() - t0
    (out_dir / f"{spec.name}.result.json").write_text(json.dumps({
        "name": res.name, "status": res.status, "job_id": res.job_id, "pdf": res.pdf, "pages": res.pages,
        "calls": res.calls, "seconds": round(res.seconds, 1), "error": res.error,
        "checks": [c.__dict__ for c in res.checks]}, indent=1), encoding="utf-8")
    return res


# ── Fixture targets ────────────────────────────────────────────────────────

WETH9 = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
EIGEN_STETH = "0x93c4b944D05dfe6df7645A86cd2206016c51564D"
FORTON = "EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ"
CRS = "TRegosVaS1o3DHG85nnW8xYzczPm3xL76K"
TON_MULTISIG = "EQBabkaz2T0_ZoRDzaMqZheJIDeRCJgwxMlsQ1GigwsjQlP-"
TON_ORDER_LIB = "6305a8061c856c2ccf05dcb0df5815c71475870567cab5f049e340bcf59251f3"
APYEE_COMMIT = "ffc81631af65010c8afe66e1bee09f94d2d1ea79"
LOCKER_COMMIT = "4f400beb3a7b912888fba214d8553f5368eab18c"
LOCKER_PROGRAM = "Fvm8Z25vd1Yauj6GB4jsrW7jJyUdNYGeDCWYqcuTtDek"
HIPO_COMMIT = "91291c5bfc5da61467d065c6ccd121f0308490e4"
PUMP_COMMIT = "768ef58478724bf6b464c9f0952e3e5a3b2a2613"

WETH9_FINDING = FindingSpec(
    file_hint="WETH9", locate="function withdraw(", category="evm.dos",
    title="Withdraw pushes ether with transfer so a contract holder with a heavier receive path is locked out",
    description=("The withdraw function burns the caller balance and then sends the ether through transfer, which "
                 "forwards a fixed small gas stipend. A holder that is a contract with a receive path heavier than "
                 "that stipend sees the send revert on each call and keeps a token balance it can only move by "
                 "transferring the token to another account. Wrapped ether outstanding on chain: {fact}."),
    impact=("The affected holder keeps the wrapped balance but the ether behind it stays in the contract until "
            "the token is moved elsewhere, which adds a dependency on a second account and delays access."),
    recommendation=("Send the ether with a call that forwards the remaining gas and checks the result, "
                    "or offer a withdrawal variant that takes a recipient address."),
    matrix={"impact_class": "griefing_with_victim_loss", "magnitude": "unbounded", "trigger": "anyone",
            "precondition": "none", "reversibility": "irreversible"},
    expect_severity="Medium",
)

# review_verify_on_fork on the WETH9 target: deposit then balanceOf equals the deposit, on a local fork at
# the pinned block. WETH9 is solc 0.4, so the test talks to the deployed contract through an interface.
WETH9_FORK_TEST = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

interface IWETH9 {
    function deposit() external payable;
    function balanceOf(address) external view returns (uint256);
}

contract WethDepositTest is Test {
    IWETH9 constant WETH = IWETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function test_depositCreditsTheCaller() public {
        vm.deal(address(this), 1 ether);
        uint256 before = WETH.balanceOf(address(this));
        WETH.deposit{value: 1 ether}();
        assertEq(WETH.balanceOf(address(this)), before + 1 ether, "balance after deposit");
    }
}
"""

TARGETS: dict[str, TargetSpec] = {
    "evm": TargetSpec(
        name="evm", start={"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": WETH9}},
        probe_url=f"https://sourcify.dev/server/v2/contract/1/{WETH9}",
        chain="evm", network="Ethereum Mainnet (1)", tiers=("A", "B"), finding=WETH9_FINDING, stale_walks=True,
        address_in_cover=WETH9, ready_timeout_s=900, fork_test={"content": WETH9_FORK_TEST},
        chain_read={"cite": "chain.weth.total_supply",
                    "items": [{"alias": "weth", "address": WETH9, "kind": "call", "fn": "totalSupply()",
                               "returns": "uint256", "unit": "wei", "field": "total_supply"}]}),
    "evm-proxy": TargetSpec(
        # Venus blind run 2026-10-31: a proxy address gave a review of the proxy source only, and a
        # second job on the implementation read owner 0x0. The EigenLayer stETH strategy is an
        # EIP-1967 transparent proxy with a StrategyBase implementation, both Sourcify-verified with
        # relative source paths: one job, one PDF, the EIP-1967 slots read at the proxy. (USDC is a
        # ZeppelinOS-slot proxy and is followed too, but its implementation's Sourcify sources carry
        # absolute paths that the fetch path filter drops, so it cannot build today.)
        name="evm-proxy", start={"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": EIGEN_STETH}},
        probe_url=f"https://sourcify.dev/server/v2/contract/1/{EIGEN_STETH}",
        chain="evm", network="Ethereum Mainnet (1)", tiers=("A", "B"), address_in_cover=EIGEN_STETH, ready_timeout_s=900,
        expect_proxy=True, expect_facts=("onchain.eip1967.implementation", "onchain.eip1967.admin")),
    "evm-repo": TargetSpec(
        name="evm-repo",
        start={"source": {"kind": "repo", "repo_url": "https://github.com/apyee-finance/apyee-protocol",
                          "commit": APYEE_COMMIT}},
        probe_url="https://api.github.com/repos/apyee-finance/apyee-protocol/commits/" + APYEE_COMMIT,
        chain="evm", network="No deployment given; source review only", tiers=("B", "C"), expect_dependencies=True, expect_lead_tool="slither",
        expect_out_of_scope=("contracts/mocks/",), expect_guarded_entry=("Vault", "setFeeRate"), ready_timeout_s=1200),
    "solana": TargetSpec(
        name="solana",
        start={"source": {"kind": "repo", "repo_url": "https://github.com/fraserbrownirl/agent-loans",
                          "commit": LOCKER_COMMIT, "subdir": "programs/locker",
                          "deployment": {"chain": "solana", "address": LOCKER_PROGRAM}}},
        probe_url="https://api.github.com/repos/fraserbrownirl/agent-loans/commits/" + LOCKER_COMMIT,
        chain="solana", network="Solana mainnet", tiers=("A", "B", "C"), ready_timeout_s=1500),
    "ton": TargetSpec(
        name="ton", start={"source": {"kind": "deployed", "chain": "ton", "address": FORTON}},
        probe_url="https://toncenter.com/api/v2/getAddressInformation?address=" + FORTON,
        chain="ton", network="TON mainnet", tiers=("A",), stale_walks=True, address_in_cover=FORTON, ready_timeout_s=900),
    "ton-multisig": TargetSpec(
        # Matrix r5 2026-10-31: multisig v2, verified as FunC 0.4.4. Its auto/order_code.func builds a
        # library reference cell (the order code is a masterchain library), its types.func holds a
        # 2**256 - 1 mask, the manifest names funcVersion and a command-line file order, and only the
        # 0.4.4-newops.1 build assembles its stdlib. Each stopped the job in insufficient_source; now
        # the library is read from the chain by hash and the rebuild matches: tier A.
        name="ton-multisig", start={"source": {"kind": "deployed", "chain": "ton", "address": TON_MULTISIG}},
        probe_url="https://toncenter.com/api/v2/getAddressInformation?address=" + TON_MULTISIG,
        chain="ton", network="TON mainnet", tiers=("A",), address_in_cover=TON_MULTISIG,
        expect_library_ref=TON_ORDER_LIB, ready_timeout_s=900),
    "ton-repo": TargetSpec(
        # Hipo blind run 2026-10-27: a public TON FunC Blueprint repository, started by a third party
        # with repo and commit only (no chain, no deployment), ended insufficient_source on every
        # variant. The family is detected from the tree; the job must reach ready with a TON map and
        # leads, and render.
        name="ton-repo",
        start={"source": {"kind": "repo", "repo_url": "https://github.com/HipoFinance/contract", "commit": HIPO_COMMIT}},
        probe_url="https://api.github.com/repos/HipoFinance/contract/commits/" + HIPO_COMMIT,
        chain="ton", network="No deployment given; source review only", tiers=("B",), ready_timeout_s=900),
    "solana-repo": TargetSpec(
        # Pump Science blind run 2026-10-27: an Anchor workspace (Anchor.toml at the root, the program
        # in programs/pump-science), started with repo, commit and subdir only, ended
        # E_SOURCE_NOT_FOUND / no_manifest twice; it worked only with the declare_id! id as a
        # deployment, and the cover then said "Solana mainnet" for a localnet id. Repo only here.
        name="solana-repo",
        start={"source": {"kind": "repo", "repo_url": "https://github.com/code-423n4/2025-01-pump-science",
                          "commit": PUMP_COMMIT, "subdir": "programs/pump-science"}},
        probe_url="https://api.github.com/repos/code-423n4/2025-01-pump-science/commits/" + PUMP_COMMIT,
        chain="solana", network="No deployment given; source review only", tiers=("B",), ready_timeout_s=1800),
    "tron": TargetSpec(
        # chain_id is omitted as the matrix session did: with it, review_start answers E_CHAIN_DISABLED
        # (TRON is `enabled: false` in chains.json and the RPC gate reads chain_id), without it the TRON
        # adapter path runs. A client following the schema ("chain_id required when chain is evm") sends none.
        name="tron", start={"source": {"kind": "deployed", "chain": "tron", "address": CRS}},
        probe_url="https://apilist.tronscanapi.com/api/contract?contract=" + CRS,
        chain="tron", network="TRON Mainnet (728126428)", tiers=("A", "B"), address_in_cover=CRS, ready_timeout_s=900),
}
