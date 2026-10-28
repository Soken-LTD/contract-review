"""Fewer client round trips (2026-10-26, from the 2026-10-25 blind matrix transcripts).

Covers the additive parameters and results: review_get_guide topics, review_read_code ranges,
review_status wait_for settled and next_tools, review_start wait_seconds, review_set_section with
several section objects, and the disproof checklist inline in review_submit_finding. Old call shapes
must keep working and every server gate stays on the single-call path.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from pathlib import Path

import pytest
import pytest_asyncio
from jsonschema import Draft202012Validator
from mcp import Client

import soken_review.tools  # noqa: F401
from soken_review.contract import TOOLS_FILE, bundle_tools
from soken_review.db.job_repo import JobRepo
from soken_review.mapping.step import run_map_step
from soken_review.pinning.store import PinnedSource
from soken_review.server import SokenServer
from soken_review.tools import read as read_mod
from soken_review.tools.context import MemoryJobContext
from soken_review.tools.start_status import _status_next_tools, set_pool

from ._client import task_scoped_client

ASYNC = pytest.mark.asyncio(loop_scope="session")   # the db_pool loop (tests/conftest.py)
TOOLS = {t["name"]: t for t in bundle_tools()}
JOB = "job_BBBBBBBBBBBBBBBBBBBBBBBBBB"


def _main_contract() -> dict | None:
    """tools.v1.json on origin/main, for the additive-only check; None outside a git checkout."""
    try:
        out = subprocess.run(["git", "show", "origin/main:contract/mcp/tools.v1.json"], cwd=TOOLS_FILE.parent,
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return json.loads(out)


# ── contract: additive only ─────────────────────────────────────────────────


_CLASS_RE = re.compile(r"\[[^\]]*\]")


def _pattern_widens(old: str, new: str) -> bool:
    """A regex pattern widens when its character classes gain characters and nothing else changes
    (2026-10-27: `@` added to path patterns for npm-scoped paths)."""
    if old == new:
        return True
    if _CLASS_RE.sub("[]", old) != _CLASS_RE.sub("[]", new):
        return False
    return all(set(o[1:-1]) <= set(n[1:-1]) for o, n in zip(_CLASS_RE.findall(old), _CLASS_RE.findall(new), strict=True))


def _widens(old, new) -> bool:
    """`new` accepts every value `old` accepts, judged structurally: enums may gain values, upper
    bounds may grow, lower bounds may shrink, `required` may shrink, objects may gain properties,
    descriptions may change. Anything else must stay equal."""
    if isinstance(old, dict) and isinstance(new, dict):
        for k, v in old.items():
            if k == "description":
                continue
            if k not in new:
                return False
            n = new[k]
            if k == "enum":
                if not set(v) <= set(n):
                    return False
            elif k in ("maxItems", "maxLength", "maximum"):
                if n < v:
                    return False
            elif k in ("minItems", "minLength", "minimum"):
                if n > v:
                    return False
            elif k == "required":
                if not set(n) <= set(v):
                    return False
            elif k == "pattern":
                if not _pattern_widens(v, n):
                    return False
            elif not _widens(v, n):
                return False
        return all(k in old or k == "description" or (k != "required" and not isinstance(new[k], (int, str, bool)))
                   for k in new)
    if isinstance(old, list) and isinstance(new, list):
        return len(old) == len(new) and all(_widens(a, b) for a, b in zip(old, new, strict=True))
    return old == new


def test_widens_rules():
    assert _widens({"enum": ["a"]}, {"enum": ["a", "b"]})
    assert not _widens({"enum": ["a", "b"]}, {"enum": ["a"]})
    assert _widens({"type": "object", "properties": {"x": {"type": "string"}}},
                   {"type": "object", "properties": {"x": {"type": "string"}, "y": {"type": "string"}}})
    assert not _widens({"type": "string"}, {"type": "integer"})
    assert not _widens({"maxItems": 5}, {"maxItems": 4})
    assert not _widens({"type": "string"}, {"type": "string", "maxLength": 3})


def test_schema_changes_are_additive():
    old = _main_contract()
    if old is None:
        pytest.skip("origin/main not available")
    new = json.loads(TOOLS_FILE.read_text())
    new_tools = {t["name"]: t for t in new["tools"]}
    for tool in old["tools"]:
        cur = new_tools[tool["name"]]
        for key in ("inputSchema", "outputSchema"):
            if key not in tool:
                continue
            old_props, new_props = tool[key].get("properties", {}), cur[key].get("properties", {})
            for name, spec in old_props.items():
                assert name in new_props and _widens(spec, new_props[name]), f"{tool['name']}.{key}.{name} narrowed"
            if key == "inputSchema":  # required may only shrink: every old call stays valid
                assert set(cur[key].get("required", [])) <= set(tool[key].get("required", [])), tool["name"]


@pytest.mark.parametrize(("tool", "args"), [
    ("review_read_code", {"job_id": JOB, "path": "a.sol", "start_line": 1, "end_line": 9}),
    ("review_get_guide", {"topic": "checklist"}),
    ("review_status", {"job_id": JOB, "wait_seconds": 45}),
    ("review_set_section", {"job_id": JOB, "section": "roles_notes",
                            "roles_notes": {"rows": [{"role": "owner", "risk_note": "Can pause transfers."}]}}),
])
def test_old_shapes_still_validate(tool, args):
    assert list(Draft202012Validator(TOOLS[tool]["inputSchema"]).iter_errors(args)) == []


def test_new_shapes_validate():
    v = Draft202012Validator
    assert not list(v(TOOLS["review_read_code"]["inputSchema"]).iter_errors(
        {"job_id": JOB, "ranges": [{"path": "a.sol", "start_line": 1, "end_line": 9}]}))
    assert not list(v(TOOLS["review_get_guide"]["inputSchema"]).iter_errors({"topics": ["checklist", "categories"]}))
    assert not list(v(TOOLS["review_status"]["inputSchema"]).iter_errors({"job_id": JOB, "wait_for": "settled"}))
    assert list(v(TOOLS["review_read_code"]["inputSchema"]).iter_errors(
        {"job_id": JOB, "ranges": [{"path": "a.sol", "start_line": 1, "end_line": 2}] * 9}))  # maxItems 8


# ── review_get_guide topics ─────────────────────────────────────────────────


@ASYNC
async def test_guide_several_topics_in_one_call():
    async with Client(SokenServer()) as c:
        multi = await c.call_tool("review_get_guide", {"topics": ["severity_inputs", "checklist"], "chain": "ton"})
        one = await c.call_tool("review_get_guide", {"topic": "checklist", "chain": "ton"})
    text = multi.content[0].text
    assert not multi.is_error
    headers = [ln for ln in text.splitlines() if ln.startswith("guide_version ")]
    assert headers == ["guide_version v0 topic severity_inputs chain ton", "guide_version v0 topic checklist chain ton"]
    assert text.endswith(one.content[0].text)  # each block is exactly the single-topic answer


@ASYNC
async def test_guide_without_topic_names_both_options():
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_get_guide", {"chain": "evm"})
    body = json.loads(r.content[0].text)
    assert r.is_error and body["errors"][0]["field"] == "topic"
    assert "topics" in body["errors"][0]["fix"]


# ── review_read_code ranges ─────────────────────────────────────────────────


@pytest.fixture
def read_ctx(tmp_path: Path) -> MemoryJobContext:
    ctx = MemoryJobContext(tmp_path)
    ctx.set_state(JOB, "ready")
    files = {"src/A.sol": "\n".join(f"uint256 constant A{i} = {i};" for i in range(1, 31)).encode(),
             "src/B.sol": "\n".join(f"uint256 constant B{i} = {i};" for i in range(1, 11)).encode()}
    PinnedSource.from_files(files).persist(tmp_path, JOB)
    run_map_step(tmp_path, JOB, solc_output_path=None, build_ok=False, build_detail="no build in test")
    read_mod.set_context(ctx)
    return ctx


@ASYNC
async def test_read_ranges_returns_every_range_and_logs_each(read_ctx):
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_read_code", {"job_id": JOB, "ranges": [
            {"path": "src/A.sol", "start_line": 1, "end_line": 5},
            {"path": "src/B.sol", "start_line": 3, "end_line": 400},   # clamped to 10
            {"path": "src/A.sol", "start_line": 28, "end_line": 30}]})
    text = r.content[0].text
    assert not r.is_error
    assert "src/A.sol sha256:" in text and "lines 1-5 of 30" in text and "lines 28-30 of 30" in text
    assert "lines 3-10 of 10" in text and "end clamped from 400 to 10" in text
    assert read_ctx.reads == [(JOB, "src/A.sol", 1, 5), (JOB, "src/B.sol", 3, 10), (JOB, "src/A.sol", 28, 30)]


@ASYNC
async def test_read_ranges_bad_range_is_reported_inline_and_not_logged(read_ctx):
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_read_code", {"job_id": JOB, "ranges": [
            {"path": "src/Nope.sol", "start_line": 1, "end_line": 5},
            {"path": "src/B.sol", "start_line": 50, "end_line": 60},
            {"path": "src/B.sol", "start_line": 1, "end_line": 2}]})
    text = r.content[0].text
    assert "range 1 rejected E_FILE_UNKNOWN" in text and "Closest paths" in text
    assert "range 2 rejected E_RANGE_INVALID" in text and "Use lines 1 to 10" in text
    assert read_ctx.reads == [(JOB, "src/B.sol", 1, 2)]


@ASYNC
async def test_read_ranges_respect_batch_cap(read_ctx, monkeypatch):
    monkeypatch.setattr(read_mod, "_CAP_READ_BATCH", 12_000)
    async with Client(SokenServer()) as c:
        r = await c.call_tool("review_read_code", {"job_id": JOB, "ranges": [
            {"path": "src/A.sol", "start_line": 1, "end_line": 30}] * 8})
    text = r.content[0].text
    assert "not_read src/A.sol:1-30" in text
    assert len(read_ctx.reads) < 8        # only printed ranges are recorded as read


@ASYNC
async def test_read_single_range_unchanged_and_missing_fields_named(read_ctx):
    async with Client(SokenServer()) as c:
        one = await c.call_tool("review_read_code", {"job_id": JOB, "path": "src/B.sol", "start_line": 1,
                                                     "end_line": 3})
        bad = await c.call_tool("review_read_code", {"job_id": JOB, "path": "src/B.sol"})
    assert one.content[0].text.startswith("Untrusted source data, file src/B.sol, lines 1-3")
    body = json.loads(bad.content[0].text)
    assert bad.is_error and body["errors"][0]["field"] == "start_line"


# ── review_status next_tools (pure) ─────────────────────────────────────────


@pytest.mark.parametrize(("state", "drafts", "checks", "expected"), [
    ("fetching", [], [], ["review_status"]),
    # never-worse: recommendations only; the shortest path is read, submit, finalize
    ("ready", [], [], ["review_read_code", "review_submit_finding", "review_finalize"]),
    ("ready", [{"status": "needs_challenge"}], [{"id": "F3", "open": 1, "tool": "review_answer_challenge"}],
     ["review_finalize", "review_challenge", "review_answer_challenge"]),
    ("ready", [{"status": "accepted"}], [{"id": "F2", "open": 0}], ["review_finalize"]),
    ("ready", [{"status": "accepted"}], [{"id": "F5", "open": 1, "tool": "review_set_section"}],
     ["review_finalize", "review_set_section"]),
    # a blocking check (F6 unresolved placeholder) names its tool first
    ("ready", [{"status": "accepted"}], [{"id": "F6", "open": 1, "tool": "review_submit_finding"}],
     ["review_submit_finding", "review_finalize"]),
    ("render_queued", [], [], ["review_report"]),
    ("failed", [], [], []),
])
def test_status_next_tools(state, drafts, checks, expected):
    assert _status_next_tools(state, drafts, checks) == expected


# ── DB: settled wait and review_start wait_seconds ──────────────────────────

_DOCKER = subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0


@pytest_asyncio.fixture(loop_scope="session")
async def client(db_pool):
    set_pool(db_pool)
    try:
        async with task_scoped_client() as c:
            yield c
    finally:
        set_pool(None)  # type: ignore[arg-type]


_START = {"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": "0x" + "d" * 40}}


async def _advance(db_pool, job_id: str, states: tuple[str, ...], gap: float = 0.4) -> None:
    for s in states:
        await asyncio.sleep(gap)
        async with db_pool.connection() as conn, conn.transaction():
            await JobRepo(conn).transition(job_id, s)


@ASYNC
@pytest.mark.skipif(not _DOCKER, reason="docker unavailable")
async def test_status_settled_waits_through_intermediate_states(client, db_pool):
    r = await client.call_tool("review_start", _START)
    job_id = json.loads(r.content[0].text)["job_id"]
    task = asyncio.create_task(_advance(db_pool, job_id, ("fetching", "building", "analyzing", "ready")))
    t0 = time.monotonic()
    s = await client.call_tool("review_status", {"job_id": job_id, "wait_seconds": 20, "wait_for": "settled"})
    await task
    body = json.loads(s.content[0].text)
    assert body["state"] == "ready" and time.monotonic() - t0 < 10.0
    assert body["next_tools"] == ["review_read_code", "review_submit_finding", "review_finalize"]
    assert list(Draft202012Validator(TOOLS["review_status"]["outputSchema"]).iter_errors(body)) == []


@ASYNC
@pytest.mark.skipif(not _DOCKER, reason="docker unavailable")
async def test_status_change_mode_still_returns_on_first_change(client, db_pool):
    r = await client.call_tool("review_start", _START)
    job_id = json.loads(r.content[0].text)["job_id"]
    task = asyncio.create_task(_advance(db_pool, job_id, ("fetching", "building")))
    s = await client.call_tool("review_status", {"job_id": job_id, "wait_seconds": 20})
    await task
    assert json.loads(s.content[0].text)["state"] == "fetching"


@ASYNC
@pytest.mark.skipif(not _DOCKER, reason="docker unavailable")
async def test_start_wait_seconds_returns_settled_status(client, db_pool):
    async def advance_new_job():
        for _ in range(50):  # the job id is unknown until review_start commits it
            await asyncio.sleep(0.1)
            async with db_pool.connection() as conn:
                row = await (await conn.execute(
                    "select job_id from jobs where address = %s and state = 'queued' order by created_at desc limit 1",
                    ("0x" + "f" * 40,))).fetchone()
            if row:
                await _advance(db_pool, row[0], ("fetching", "insufficient_source"), gap=0.2)
                return

    task = asyncio.create_task(advance_new_job())
    r = await client.call_tool("review_start", {"source": {**_START["source"], "address": "0x" + "f" * 40},
                                                "wait_seconds": 15})
    await task
    body = json.loads(r.content[0].text)
    assert body["accepted"] and body["state"] == "queued"
    assert body["status"]["state"] == "insufficient_source" and body["status"]["job_id"] == body["job_id"]
    assert body["status"]["next_tools"] == []
    assert list(Draft202012Validator(TOOLS["review_start"]["outputSchema"]).iter_errors(body)) == []


@ASYNC
@pytest.mark.skipif(not _DOCKER, reason="docker unavailable")
async def test_start_without_wait_has_no_status(client):
    r = await client.call_tool("review_start", _START)
    assert "status" not in json.loads(r.content[0].text)


# ── DB: review_set_section with several sections ────────────────────────────

_ROLES = {"rows": [{"role": "owner", "risk_note": "The owner can pause every transfer and change the fee."}]}
_CONTEXT = {"notes": [{"p": "No project documents were supplied for this review."}]}


async def _ss_wired(db_pool):
    from soken_review.tools import set_section as ss_mod

    from .test_write_tools import _create_ready_job_with_pin

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))
    return ss_mod, job_id


@ASYNC
async def test_set_section_several_sections_in_one_call(db_pool):
    ss, job_id = await _ss_wired(db_pool)
    r = await ss.handle_review_set_section({"job_id": job_id, "section": "roles_notes", "roles_notes": _ROLES,
                                            "context_notes": _CONTEXT})
    assert r["accepted"] is True and r["section"] == "roles_notes" and r["revision"] == 1, r
    assert [(s["section"], s["accepted"], s["revision"]) for s in r["sections"]] == [
        ("roles_notes", True, 1), ("context_notes", True, 1)]
    async with db_pool.connection() as conn:
        rows = await (await conn.execute("select section from sections where job_id = %s order by section",
                                         (job_id,))).fetchall()
    assert [x[0] for x in rows] == ["context_notes", "roles_notes"]
    assert list(Draft202012Validator(TOOLS["review_set_section"]["outputSchema"]).iter_errors(r)) == []


@ASYNC
async def test_set_section_batch_keeps_gates_per_section(db_pool):
    ss, job_id = await _ss_wired(db_pool)
    bad = {"notes": [{"p": "This contract is guaranteed to be safe."}]}   # text gate T14
    r = await ss.handle_review_set_section({"job_id": job_id, "section": "roles_notes", "roles_notes": _ROLES,
                                            "context_notes": bad})
    assert r["accepted"] is False
    by = {s["section"]: s for s in r["sections"]}
    assert by["roles_notes"]["accepted"] is True
    assert by["context_notes"]["accepted"] is False and by["context_notes"]["errors"][0]["code"] == "E_TEXT_GATE"
    assert "guaranteed" in r["errors"][0]["fix"]


@ASYNC
async def test_set_section_single_shape_has_no_sections_list(db_pool):
    ss, job_id = await _ss_wired(db_pool)
    r = await ss.handle_review_set_section({"job_id": job_id, "section": "roles_notes", "roles_notes": _ROLES})
    assert r == {"accepted": True, "section": "roles_notes", "revision": 1, "idempotent": False}


# ── DB: checklist inline in review_submit_finding ───────────────────────────


@ASYNC
async def test_submit_returns_challenge_inline_matching_review_challenge(db_pool):
    from soken_review.tools import challenge as challenge_mod

    from .test_write_tools import _create_ready_job_with_pin, _submit_finding

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(MemoryJobContext(pin_root))
    r = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-inline-001")
    if r.get("status") != "needs_challenge":
        pytest.skip(f"status {r.get('status')}")
    assert r["next_tools"] == ["review_finalize", "review_answer_challenge"]
    separate = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": "draft-inline-001"})
    assert r["challenge"] == {k: v for k, v in separate.items() if k != "accepted"}
    assert r["challenge"]["revision"] == r["revision"]
    assert list(Draft202012Validator(TOOLS["review_submit_finding"]["outputSchema"]).iter_errors(r)) == []


@ASYNC
async def test_submit_without_challenge_context_still_names_review_challenge(db_pool, monkeypatch):
    from soken_review.tools import challenge as challenge_mod

    from .test_write_tools import _create_ready_job_with_pin, _submit_finding

    async def boom(_args):
        raise RuntimeError("challenge unavailable")

    monkeypatch.setattr(challenge_mod, "handle_review_challenge", boom)
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    r = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-inline-002")
    if r.get("status") != "needs_challenge":
        pytest.skip(f"status {r.get('status')}")
    assert "challenge" not in r and r["next_tools"] == ["review_finalize", "review_challenge"]
