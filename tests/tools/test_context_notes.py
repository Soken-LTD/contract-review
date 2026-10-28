"""review_set_section(section="context_notes") (context ingestion spec 6, 7): model blocks under the
roles_notes gates (text gate scope model, number check), at most 8 blocks, revisions kept."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from psycopg.rows import dict_row

from soken_review.contract import bundle_tools

from .test_write_tools import _create_ready_job_with_pin

ASYNC = pytest.mark.asyncio(loop_scope="session")
NOTES = [
    {"p": "The whitepaper declares a fixed supply and describes ownership as renounced."},
    {"ul": ["The documentation names an owner multisig that can pause the vault.",
            "The website lists the reviewed vault address on Base."]},
    {"table": {"head": ["Source", "Fee"], "rows": [["whitepaper", "{{fact:context.whitepaper.fee_pct_1}}"],
                                                    ["docs", "{{fact:context.docs.fee_pct_1}}"]]}},
]


async def _wired(db_pool):
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))
    return ss_mod, job_id


async def _stored(db_pool, job_id):
    async with db_pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("select revision, content from sections where job_id = %s and section = 'context_notes' "
                          "order by revision", (job_id,))
        return await cur.fetchall()


@ASYNC
async def test_context_notes_accepted_stored_and_revisioned(db_pool):
    ss, job_id = await _wired(db_pool)
    r1 = await ss.handle_review_set_section({"job_id": job_id, "section": "context_notes", "content": NOTES})
    assert r1 == {"accepted": True, "section": "context_notes", "revision": 1, "idempotent": False}, r1
    r2 = await ss.handle_review_set_section({"job_id": job_id, "section": "context_notes", "content": NOTES})
    assert r2["accepted"] and r2["revision"] == 1 and r2["idempotent"]
    r3 = await ss.handle_review_set_section({"job_id": job_id, "section": "context_notes",
                                             "content": [{"p": "The terms page could not be retrieved."}]})
    assert r3["accepted"] and r3["revision"] == 2
    rows = await _stored(db_pool, job_id)
    assert [r["revision"] for r in rows] == [1, 2] and rows[0]["content"] == NOTES


@ASYNC
async def test_context_notes_contract_shape_accepted(db_pool):
    """The tools.v1 shape `{section: context_notes, context_notes: {notes: [...]}}` reaches the handler
    as-is through the server (no `content` key)."""
    ss, job_id = await _wired(db_pool)
    args = {"job_id": job_id, "section": "context_notes", "context_notes": {"notes": NOTES}}
    schema = {t["name"]: t for t in bundle_tools()}["review_set_section"]["inputSchema"]
    assert list(Draft202012Validator(schema).iter_errors(args)) == []
    r = await ss.handle_review_set_section(args)
    assert r["accepted"] and r["revision"] == 1
    assert (await _stored(db_pool, job_id))[0]["content"] == NOTES


@ASYNC
@pytest.mark.parametrize("content,detail", [
    ([{"p": "x"}] * 9, "at most 8 blocks"),
    ([{"p": "x", "ul": ["y"]}], "one of {p}, {ul}, {table}"),
    ([{"quote": "x"}], "one of {p}, {ul}, {table}"),
    ([{"p": ""}], "1..900"),
    ([{"ul": []}], "1..8 strings"),
    ([{"table": {"head": ["a"]}}], "{head, rows} only"),
    ([{"table": {"head": [], "rows": [["a"]]}}], "table.head"),
    ([{"table": {"head": ["a"], "rows": [["a"] * 7]}}], "table.rows"),
    ("not a list", "must be an array"),
    ([], "at least one row"),
])
async def test_context_notes_shape_rejected(db_pool, content, detail):
    ss, job_id = await _wired(db_pool)
    r = await ss.handle_review_set_section({"job_id": job_id, "section": "context_notes", "content": content})
    assert r["accepted"] is False
    assert r["errors"][0]["code"] == "E_SECTION_INVALID"
    assert detail in json.dumps(r["errors"][0]), r["errors"][0]


@ASYNC
async def test_context_notes_text_gate_and_number_gate(db_pool):
    ss, job_id = await _wired(db_pool)
    em = await ss.handle_review_set_section({"job_id": job_id, "section": "context_notes",
                                             "content": [{"ul": ["Supply is fixed " + chr(0x2014) + " per the whitepaper."]}]})
    # never-worse: the em dash is rewritten for publication (T1) and stored with a warning
    assert em["accepted"] is True and em["warnings"][0]["class"] == "rewrite", em
    num = await ss.handle_review_set_section({"job_id": job_id, "section": "context_notes",
                                              "content": [{"table": {"head": ["Fee"], "rows": [["The whitepaper says 25 bps"]]}}]})
    # an unsourced digit is still blocking (evidence integrity)
    assert num["accepted"] is False and num["errors"][0]["code"].startswith("E_NUMBER")
    stored = await _stored(db_pool, job_id)
    assert len(stored) == 1 and chr(0x2014) not in json.dumps(stored, ensure_ascii=False)


@ASYNC
async def test_context_notes_frozen_job_rejected(db_pool):
    ss, job_id = await _wired(db_pool)
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set state = 'finalized' where job_id = %s", (job_id,))
    r = await ss.handle_review_set_section({"job_id": job_id, "section": "context_notes", "content": NOTES})
    assert r == {"accepted": False, "errors": [r["errors"][0]]} and r["errors"][0]["code"] == "E_JOB_FROZEN"


def test_contract_lists_context_notes():
    tool = {t["name"]: t for t in bundle_tools()}["review_set_section"]
    assert "context_notes" in tool["inputSchema"]["properties"]["section"]["enum"]
    assert "context_notes" in tool["outputSchema"]["properties"]["section"]["enum"]
    notes = tool["inputSchema"]["properties"]["context_notes"]["properties"]["notes"]
    assert notes["maxItems"] == 8 and notes["minItems"] == 1 and "oneOf" in notes["items"]
