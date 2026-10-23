"""Project context through the tools (context ingestion spec 2026-10-23, sections 2 to 5, 8).

Non-DB: `context/` paths in review_read_code and review_search_code, context facts in
review_facts, quote routing. DB (Docker Postgres or SOKEN_TEST_PG_DSN): review_add_context
state gates, idempotency, the cap, URL rejection and the step at `ready`; review_start with
`context`; review_status `context` counts; a finding quoting a document with role `context`.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from mcp import Client

import soken_review.tools  # noqa: F401
from soken_review.context import facts as cf
from soken_review.context.store import HEADER_LINES, ContextStore
from soken_review.mapping.step import run_map_step
from soken_review.pinning.quote_match import QuoteMatchError, quote_match
from soken_review.pinning.store import PinnedSource
from soken_review.server import SokenServer
from soken_review.tools.context import MemoryJobContext
from soken_review.tools.read import set_context
from tests.context.conftest import FIXTURES, doc

from .test_submit_finalize import _VALID_SUBMISSION, VAULT_SOL, _create_ready_job_with_pin, _insert_lead

ASYNC = pytest.mark.asyncio(loop_scope="session")

JOB_ID = "job_CTXT0000000000000000000000"
WP_URL = "https://sample.example/wp.md"


@pytest.fixture
def ctx(tmp_path: Path) -> MemoryJobContext:
    c = MemoryJobContext(tmp_path)
    c.set_state(JOB_ID, "ready")
    PinnedSource.from_files({"src/Vault.sol": VAULT_SOL.encode()}).persist(tmp_path, JOB_ID)
    run_map_step(tmp_path, JOB_ID, solc_output_path=None, build_ok=False, build_detail="no build in test")
    store = ContextStore.load(tmp_path, JOB_ID)
    store.add([doc("whitepaper", WP_URL, (FIXTURES / "whitepaper.md").read_text(), title="Sample Token Whitepaper"),
               doc("docs", "https://docs.sample.example/", "", status="failed", error="timeout")])
    cf.write_context_facts(tmp_path, JOB_ID, cf.context_facts(store, {"job_id": JOB_ID, "chain_id": 1,
                                                                        "address": "0xc2edad668740f1aa35e4d8f227fb8e17dca888cd"}))
    set_context(c)
    return c


async def _call(tool: str, **args):
    async with Client(SokenServer()) as client:
        res = await client.call_tool(tool, args)
    return res


# ── read, search, facts (no DB) ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_read_code_serves_a_context_document_with_its_header(ctx: MemoryJobContext) -> None:
    res = await _call("review_read_code", job_id=JOB_ID, path="context/whitepaper-1.md", start_line=1, end_line=8)
    assert not res.is_error, res.content[0].text
    text = res.content[0].text
    assert text.startswith("Untrusted source data, project document context/whitepaper-1.md, lines 1-8")
    assert "1| # Sample Token Whitepaper" in text and f"2| source: {WP_URL}" in text and "5| kind: whitepaper" in text
    assert f"{HEADER_LINES + 1}| # Sample Token Whitepaper" in text
    assert "flags none" in text
    assert ctx.reads[-1] == (JOB_ID, "context/whitepaper-1.md", 1, 8)       # same job_reads log


@pytest.mark.asyncio
async def test_read_code_unknown_context_path_names_closest_document(ctx: MemoryJobContext) -> None:
    res = await _call("review_read_code", job_id=JOB_ID, path="context/whitepaper-2.md", start_line=1, end_line=2)
    body = json.loads(res.content[0].text)
    assert body["errors"][0]["code"] == "E_FILE_UNKNOWN" and "context/whitepaper-1.md" in json.dumps(body["errors"][0])
    res = await _call("review_read_code", job_id=JOB_ID, path="context/docs-1.md", start_line=1, end_line=2)
    assert json.loads(res.content[0].text)["errors"][0]["code"] == "E_FILE_UNKNOWN"   # failed documents do not read


@pytest.mark.asyncio
async def test_read_code_range_and_detailed_on_context(ctx: MemoryJobContext) -> None:
    res = await _call("review_read_code", job_id=JOB_ID, path="context/whitepaper-1.md", start_line=1, end_line=999)
    assert json.loads(res.content[0].text)["errors"][0]["code"] == "E_RANGE_INVALID"
    res = await _call("review_read_code", job_id=JOB_ID, path="context/whitepaper-1.md", start_line=7, end_line=9,
                      response_format="detailed")
    assert not res.is_error and "map markers" not in res.content[0].text


@pytest.mark.asyncio
async def test_search_code_covers_documents_after_code(ctx: MemoryJobContext) -> None:
    res = await _call("review_search_code", job_id=JOB_ID, pattern="renounced", mode="literal")
    text = res.content[0].text
    assert "context/whitepaper-1.md:" in text and "src/Vault.sol" not in text
    res = await _call("review_search_code", job_id=JOB_ID, pattern="withdraw|renounced", mode="regex", context_lines=1)
    lines = res.content[0].text.splitlines()
    code_idx = next(i for i, ln in enumerate(lines) if "src/Vault.sol" in ln)
    ctx_idx = next(i for i, ln in enumerate(lines) if "context/whitepaper-1.md" in ln)
    assert code_idx < ctx_idx                          # code paths first, documents after
    res = await _call("review_search_code", job_id=JOB_ID, pattern="a", mode="literal", path_glob="context/*", max_hits=3)
    text = res.content[0].text
    assert "src/Vault.sol" not in text and "context/whitepaper-1.md:" in text


@pytest.mark.asyncio
async def test_facts_lists_context_records(ctx: MemoryJobContext) -> None:
    res = await _call("review_facts", job_id=JOB_ID, filter="context.")
    text = res.content[0].text
    assert "context.whitepaper.total_supply 1000000000 tokens context/whitepaper-1.md:" in text
    assert "context.whitepaper.admin_claims renounced - context/whitepaper-1.md:" in text
    assert "context.whitepaper.mentions_reviewed_address true" in text
    res = await _call("review_facts", job_id=JOB_ID, filter="source.")
    assert "source.files 1" in res.content[0].text and "context." not in res.content[0].text


@pytest.mark.asyncio
async def test_contract_map_ignores_documents(ctx: MemoryJobContext) -> None:
    res = await _call("review_contract_map", job_id=JOB_ID)
    assert "context/" not in res.content[0].text


def test_quote_match_routes_context_paths(ctx: MemoryJobContext, tmp_path: Path) -> None:
    pin = PinnedSource.load(tmp_path, JOB_ID)
    store = ContextStore.load(tmp_path, JOB_ID)
    header = f"# Sample Token Whitepaper\nsource: {WP_URL}"
    quote_match(pin, "context/whitepaper-1.md", 1, 2, header, context=store)      # a provenance quote
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(pin, "context/whitepaper-1.md", 1, 2, header)                 # no store: unknown
    assert exc.value.code == "E_FILE_UNKNOWN"
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(pin, "context/whitepaper-1.md", 1, 2, "# Other title\nsource: x", context=store)
    assert exc.value.code == "E_QUOTE_MISMATCH"
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(pin, "context/docs-1.md", 1, 1, "anything at all here", context=store)
    assert exc.value.code == "E_FILE_UNKNOWN"
    quote_match(pin, "src/Vault.sol", 5, 5, "function withdraw(uint256 a) external {", context=store)


# ── review_add_context, review_start, review_status (DB) ─────────────────────

def _wire(db_pool):
    from soken_review.tools import context_tool, start_status, submit

    context_tool.set_pool(db_pool)
    start_status.set_pool(db_pool)
    submit.set_pool(db_pool)
    return db_pool


async def _ready_job(db_pool) -> tuple[str, Path]:
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    run_map_step(pin_root, job_id, solc_output_path=None, build_ok=False, build_detail="no build in test")
    from soken_review.tools import context_tool, submit

    mem = MemoryJobContext(pin_root)
    mem.set_state(job_id, "ready")
    context_tool.set_context(mem)
    submit.set_context(mem)
    set_context(mem)
    return job_id, pin_root


async def _steps(db_pool, job_id: str) -> list[dict]:
    from soken_review.db.job_repo import JobRepo

    async with db_pool.connection() as conn:
        return await JobRepo(conn).get_steps(job_id)


@ASYNC
async def test_add_context_queues_a_step_at_ready_and_is_idempotent(db_pool) -> None:
    wired = _wire(db_pool)
    job_id, pin_root = await _ready_job(wired)
    items = [{"kind": "website", "url": "https://www.sushi.com/"}, {"kind": "docs", "url": "https://docs.sushi.com"},
             {"kind": "whitepaper", "path": "wp.md", "content": "# WP\n\nTotal supply of 10 tokens."}]
    res = await _call("review_add_context", job_id=job_id, items=items)
    assert not res.is_error, res.content[0].text
    body = res.structured_content
    assert body["accepted"] is True and body["job_id"] == job_id and body["poll_after_s"] >= 1
    assert [r["status"] for r in body["items"]] == ["queued", "queued", "queued"]
    assert body["items"][1]["url"] == "https://docs.sushi.com/"           # normalised: path added
    assert body["context"] == {"requested": 3, "done": 0, "failed": 0}
    steps = await _steps(wired, job_id)
    ctx_steps = [s for s in steps if s["step"] == "context"]
    assert len(ctx_steps) == 1 and ctx_steps[0]["container"] is True and ctx_steps[0]["status"] == "queued"
    # the same URLs again: no new request record, no second queued step
    res = await _call("review_add_context", job_id=job_id, items=items[:2])
    assert res.structured_content["context"]["requested"] == 3
    assert len([s for s in await _steps(wired, job_id) if s["step"] == "context"]) == 1
    # once the worker stored a document, the item reports `exists` with its path
    store = ContextStore.load(pin_root, job_id)
    store.add([doc("website", "https://www.sushi.com/", "Sushi site", title="Sushi")])
    res = await _call("review_add_context", job_id=job_id, items=[items[0]])
    row = res.structured_content["items"][0]
    assert row["status"] == "exists" and row["path"] == "context/website-1.md"
    assert res.structured_content["context"] == {"requested": 3, "done": 1, "failed": 0}
    # a failed document is queued again and carries E_CONTEXT_FETCH
    store.add([doc("docs", "https://docs.sushi.com/", "", status="failed", error="unreachable")])
    res = await _call("review_add_context", job_id=job_id, items=[items[1]])
    row = res.structured_content["items"][0]
    assert row["status"] == "queued" and row["error"]["code"] == "E_CONTEXT_FETCH" and "unreachable" in row["error"]["what"]
    # review_status reports the counts
    res = await _call("review_status", job_id=job_id)
    assert res.structured_content["context"] == {"requested": 3, "done": 1, "failed": 1}


@ASYNC
async def test_add_context_rejections(db_pool) -> None:
    wired = _wire(db_pool)
    job_id, _ = await _ready_job(wired)
    res = await _call("review_add_context", job_id=job_id, items=[{"kind": "docs", "url": "https://10.0.0.1/x"}])
    body = res.structured_content
    assert res.is_error is False and body["accepted"] is False and body["errors"][0]["code"] == "E_CONTEXT_URL"
    res = await _call("review_add_context", job_id=job_id, items=[{"kind": "docs", "url": "http://a.example/"}])
    assert json.loads(res.content[0].text)["errors"][0]["code"] == "E_INVALID_ARGUMENT"   # schema: https only
    res = await _call("review_add_context", job_id=job_id, items=[{"kind": "docs"}])
    assert json.loads(res.content[0].text)["errors"][0]["code"] == "E_INVALID_ARGUMENT"
    res = await _call("review_add_context", job_id=job_id, items=[{"kind": "docs", "path": "a.md", "content": "x",
                                                                      "url": "https://a.example/"}])
    assert json.loads(res.content[0].text)["errors"][0]["code"] == "E_INVALID_ARGUMENT"
    # the cap: 8 per call, 12 per job
    first = [{"kind": "other", "url": f"https://o.example/{i}"} for i in range(8)]
    assert (await _call("review_add_context", job_id=job_id, items=first)).structured_content["accepted"]
    more = [{"kind": "other", "url": f"https://o.example/{i}"} for i in range(8, 13)]
    body = (await _call("review_add_context", job_id=job_id, items=more)).structured_content
    assert body["accepted"] is False and body["errors"][0]["code"] == "E_CONTEXT_LIMIT"
    assert "12" in body["errors"][0]["what"]
    body = (await _call("review_add_context", job_id=job_id, items=more[:4])).structured_content
    assert body["accepted"] and body["context"]["requested"] == 12
    res = await _call("review_add_context", job_id="job_" + "0" * 26, items=first[:1])
    assert res.is_error and json.loads(res.content[0].text)["errors"][0]["code"] == "E_JOB_NOT_FOUND"


@ASYNC
async def test_add_context_state_gates(db_pool) -> None:
    wired = _wire(db_pool)
    job_id, _ = await _ready_job(wired)
    item = [{"kind": "docs", "url": "https://docs.example.org/"}]
    for state, code in (("finalized", "E_JOB_FROZEN"), ("failed", "E_JOB_TERMINAL")):
        async with wired.connection() as conn:
            await conn.execute("update jobs set state = %s where job_id = %s", (state, job_id))
        body = (await _call("review_add_context", job_id=job_id, items=item)).structured_content
        assert body["accepted"] is False and body["errors"][0]["code"] == code, state
    async with wired.connection() as conn:
        await conn.execute("update jobs set state = 'building' where job_id = %s", (job_id,))
    body = (await _call("review_add_context", job_id=job_id, items=item)).structured_content
    assert body["accepted"] is True and body["items"][0]["status"] == "queued"
    assert not [s for s in await _steps(wired, job_id) if s["step"] == "context"]   # queued at ready by the worker
    async with wired.connection() as conn:
        await conn.execute("update jobs set state = 'expired' where job_id = %s", (job_id,))
    res = await _call("review_add_context", job_id=job_id, items=item)
    assert res.is_error and json.loads(res.content[0].text)["errors"][0]["code"] == "E_JOB_EXPIRED"


@ASYNC
async def test_review_start_takes_context(db_pool) -> None:
    from soken_review.tools.start_status import FakeRepoProbe, set_repo_probe

    wired = _wire(db_pool)
    set_repo_probe(FakeRepoProbe())
    source = {"kind": "files", "language": "solidity", "files": [{"path": "A.sol", "content": "contract A {}"}]}
    ctx_arg = {"items": [{"kind": "website", "url": "https://www.sushi.com"},
                         {"kind": "terms", "path": "terms.md", "content": "# Terms\n\nKYC applies."}]}
    res = await _call("review_start", source=source, context=ctx_arg)
    body = res.structured_content
    assert body["accepted"] is True, body
    assert body["context"] == {"requested": 2, "done": 0, "failed": 0}
    async with wired.connection() as conn:
        row = await (await conn.execute("select context_items from jobs where job_id = %s", (body["job_id"],))).fetchone()
    items = row[0]
    assert [i["kind"] for i in items] == ["website", "terms"]
    assert items[0]["url"] == "https://www.sushi.com/" and items[1]["sha256"] and items[1]["content"].startswith("# Terms")
    res = await _call("review_start", source=source, context={"items": [{"kind": "app", "url": "https://user:pw@x.example/"}]})
    body = res.structured_content
    assert body["accepted"] is False and body["errors"][0]["code"] == "E_CONTEXT_URL"
    res = await _call("review_start", source=source)
    assert "context" not in res.structured_content


@ASYNC
async def test_finding_quotes_a_document_with_role_context(db_pool) -> None:
    from soken_review.tools import submit as submit_mod

    wired = _wire(db_pool)
    job_id, pin_root = await _ready_job(wired)
    store = ContextStore.load(pin_root, job_id)
    store.add([doc("whitepaper", WP_URL, (FIXTURES / "whitepaper.md").read_text(), title="Sample Token Whitepaper")])
    lines = store.read_all("context/whitepaper-1.md")
    n = next(i for i, ln in enumerate(lines, start=1) if "has been renounced" in ln)
    args = json.loads(json.dumps(_VALID_SUBMISSION))
    args["job_id"] = job_id
    args["quotes"].append({"file": "context/whitepaper-1.md", "start": n, "end": n, "role": "context", "text": lines[n - 1]})
    result = await submit_mod.handle_review_submit_finding(args)
    assert result["accepted"] is True, result
    async with wired.connection() as conn:
        rows = await (await conn.execute(
            "select role, path from finding_quote_ranges where job_id = %s and draft_key = %s order by ord",
            (job_id, args["draft_key"]))).fetchall()
    assert ("context", "context/whitepaper-1.md") in rows and ("location", "src/Vault.sol") in rows
    # a location quote may not cite a document, and a mismatching context quote is refused
    bad = json.loads(json.dumps(_VALID_SUBMISSION))
    bad["job_id"], bad["draft_key"] = job_id, "draft-ctx-bad"
    bad["quotes"] = [{"file": "context/whitepaper-1.md", "start": n, "end": n, "role": "location", "text": lines[n - 1]}]
    result = await submit_mod.handle_review_submit_finding(bad)
    assert result["accepted"] is False
    assert any(e["code"] == "E_INVALID_ARGUMENT" and e.get("field") == "quotes.role" for e in result["errors"])
    bad["draft_key"] = "draft-ctx-bad2"
    bad["quotes"] = [{"file": "context/whitepaper-1.md", "start": n, "end": n, "role": "context", "text": "not the line at all"}]
    result = await submit_mod.handle_review_submit_finding(bad)
    assert result["accepted"] is False and any(e["code"] == "E_QUOTE_MISMATCH" for e in result["errors"])


# ── security review 2026-10-23: race on the cap, scope parity, principal gates ─────────────────

@ASYNC
async def test_concurrent_add_context_cannot_pass_the_cap(db_pool) -> None:
    """Two calls racing at the cap: the row lock serialises them, exactly one lands, 12 stay 12."""
    wired = _wire(db_pool)
    job_id, _ = await _ready_job(wired)
    base = [{"kind": "other", "url": f"https://o.example/{i}"} for i in range(11)]
    assert (await _call("review_add_context", job_id=job_id, items=base[:8])).structured_content["accepted"]
    assert (await _call("review_add_context", job_id=job_id, items=base[8:])).structured_content["accepted"]
    a = _call("review_add_context", job_id=job_id, items=[{"kind": "docs", "url": "https://race.example/a"}])
    b = _call("review_add_context", job_id=job_id, items=[{"kind": "docs", "url": "https://race.example/b"}])
    ra, rb = await asyncio.gather(a, b)
    bodies = [ra.structured_content, rb.structured_content]
    accepted = [x for x in bodies if x["accepted"]]
    rejected = [x for x in bodies if not x["accepted"]]
    assert len(accepted) == 1 and len(rejected) == 1
    assert rejected[0]["errors"][0]["code"] == "E_CONTEXT_LIMIT"
    async with wired.connection() as conn:
        row = await (await conn.execute("select context_items from jobs where job_id = %s", (job_id,))).fetchone()
    assert len(row[0]) == 12
    # the same URL twice at once: one row, both calls accepted (idempotent), requested stays 12
    c = _call("review_add_context", job_id=job_id, items=[{"kind": "docs", "url": "https://o.example/0"}])
    d = _call("review_add_context", job_id=job_id, items=[{"kind": "docs", "url": "https://o.example/0"}])
    rc, rd = await asyncio.gather(c, d)
    assert rc.structured_content["accepted"] and rd.structured_content["accepted"]
    assert rc.structured_content["context"]["requested"] == 12
    # the row checks of migration 009 refuse what the handler refuses (belt and braces)
    import psycopg
    async with wired.connection() as conn:
        for bad in ('[{"url": "https://x.example/"}, {"url": "https://x.example/"}]',
                    json.dumps([{"url": f"https://x.example/{i}"} for i in range(13)])):
            with pytest.raises(psycopg.errors.CheckViolation):
                async with conn.transaction():
                    await conn.execute("update jobs set context_items = %s::jsonb where job_id = %s", (bad, job_id))


@ASYNC
async def test_dismiss_quotes_may_not_cite_a_document(db_pool) -> None:
    from soken_review.tools import dismiss as dismiss_mod

    wired = _wire(db_pool)
    job_id, pin_root = await _ready_job(wired)
    store = ContextStore.load(pin_root, job_id)
    store.add([doc("whitepaper", WP_URL, (FIXTURES / "whitepaper.md").read_text(), title="Sample Token Whitepaper")])
    lines = store.read_all("context/whitepaper-1.md")
    n = next(i for i, ln in enumerate(lines, start=1) if "total supply of" in ln)   # a prose line, not a heading
    line = lines[n - 1]
    await _insert_lead(wired, job_id, "LEAD-0701")
    dismiss_mod.set_pool(wired)
    dismiss_mod.set_context(MemoryJobContext(pin_root))
    note = "The detector pattern does not apply here because the call target is the trusted router only."
    for reason in ("not_a_vulnerability", "fp_guarded"):
        res = await dismiss_mod.handle_review_dismiss_lead({"job_id": job_id, "items": [
            {"lead_id": "LEAD-0701", "reason": reason, "note": note,
             "quotes": [{"file": "context/whitepaper-1.md", "start": n, "end": n, "text": line}]}]})
        assert res["accepted"] is True and res["dismissed"] == [] and len(res["rejected"]) == 1, reason
        codes = {e["code"] for e in res["rejected"][0]["errors"]}
        assert codes & {"E_FILE_UNKNOWN", "E_DISMISS_UNCHECKABLE"}, (reason, codes)


@ASYNC
async def test_kill_item_present_with_a_document_quote_is_scope_rejected(db_pool) -> None:
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod

    wired = _wire(db_pool)
    job_id, pin_root = await _ready_job(wired)
    store = ContextStore.load(pin_root, job_id)
    store.add([doc("whitepaper", WP_URL, (FIXTURES / "whitepaper.md").read_text(), title="Sample Token Whitepaper")])
    lines = store.read_all("context/whitepaper-1.md")
    challenge_mod.set_pool(wired)
    challenge_mod.set_context(MemoryJobContext(pin_root))
    args = json.loads(json.dumps(_VALID_SUBMISSION))
    args["job_id"], args["draft_key"] = job_id, "draft-ctx-kill"
    submitted = await submit_mod.handle_review_submit_finding(args)
    assert submitted["accepted"] is True, submitted
    if submitted.get("status") != "needs_challenge":
        pytest.skip(f"finding did not reach needs_challenge ({submitted.get('computed_severity')})")
    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": "draft-ctx-kill"})
    assert ch["accepted"] is True
    kill = [i for i in ch["items"] if i["kind"] == "kill"]
    if not kill:
        pytest.skip("no kill item for this category")
    async with wired.connection() as conn, conn.transaction():
        await conn.execute("insert into job_reads (job_id, path, start_line, end_line) values (%s, %s, 1, 9)",
                           (job_id, "src/Vault.sol"))
    n = HEADER_LINES + 2
    answers = []
    for item in ch["items"]:
        if item["id"] == kill[0]["id"]:
            answers.append({"item_id": item["id"], "value": "present",
                            "quotes": [{"file": "context/whitepaper-1.md", "start": n, "end": n, "text": lines[n - 1]}],
                            "note": "The whitepaper states the condition in plain words on this line."})
        else:
            refs = item["scope"].get("ranges") or ["src/Vault.sol:1-9"]
            answers.append({"item_id": item["id"], "value": "absent", "refs": refs,
                            "note": "No evidence of this condition found in the reviewed scope."})
    res = await challenge_mod.handle_review_answer_challenge({"job_id": job_id, "draft_key": "draft-ctx-kill",
                                                               "revision": ch["revision"], "answers": answers})
    assert res["accepted"] is False, res
    scope_errs = [e for e in res["errors"] if e["code"] == "E_CHALLENGE_SCOPE"]
    assert scope_errs and any("context/" in json.dumps(e) for e in scope_errs)
    async with wired.connection() as conn:
        row = await (await conn.execute("select status from finding_drafts where job_id = %s and draft_key = %s",
                                        (job_id, "draft-ctx-kill"))).fetchone()
    assert row[0] == "needs_challenge"                     # nothing was withdrawn by a document quote


@pytest.mark.asyncio
async def test_context_reads_take_the_same_job_gates_as_code(ctx: MemoryJobContext) -> None:
    # Another principal's job id (unknown here) and a job that is not readable yet: the same
    # E_JOB_NOT_FOUND / E_JOB_NOT_READY as for code paths, before any store access.
    foreign = "job_" + "F" * 26
    res = await _call("review_read_code", job_id=foreign, path="context/whitepaper-1.md", start_line=1, end_line=2)
    assert json.loads(res.content[0].text)["errors"][0]["code"] == "E_JOB_NOT_FOUND"
    res = await _call("review_search_code", job_id=foreign, pattern="renounced", path_glob="context/*")
    assert json.loads(res.content[0].text)["errors"][0]["code"] == "E_JOB_NOT_FOUND"
    ctx.set_state(JOB_ID, "analyzing")
    res = await _call("review_read_code", job_id=JOB_ID, path="context/whitepaper-1.md", start_line=1, end_line=2)
    assert json.loads(res.content[0].text)["errors"][0]["code"] == "E_JOB_NOT_READY"
    assert not any(r[1].startswith("context/") for r in ctx.reads)
