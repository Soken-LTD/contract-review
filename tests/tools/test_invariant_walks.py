"""Invariant-walk answers (tools/walks.py), review_set_section(section=invariant_walks) and the
finalize check F9 (feat/lifecycle-invariant-pass)."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from soken_review.contract import bundle_tools
from soken_review.tools.walks import merge_rows, open_walks, validate_row

from .test_write_tools import _create_ready_job_with_pin

ASYNC = pytest.mark.asyncio(loop_scope="session")

WALK = {"id": "IW-VS-1", "type": "vault_shares", "title": "Supply returns to zero",
        "focus": [{"range": "src/Vault.sol:5-8", "name": "withdraw"}, {"range": "src/Vault.sol:20-30", "name": "deposit"}],
        "anchors": [{"lead_id": "LEAD-0003", "ref": "src/Vault.sol:22"}]}
FREE = {"id": "IW-VS-4", "type": "vault_shares", "title": "Rounding at the boundaries", "focus": [], "anchors": []}
LC = {"walks": [WALK, FREE]}
READS = {"src/Vault.sol": [(1, 9), (18, 31)]}
NOTE = "The snapshot is cleared when the last share burns, so the next deposit prices at par."
OK = {"walk_id": "IW-VS-1", "outcome": "holds", "refs": ["src/Vault.sol:5-8", "src/Vault.sol:20-30"], "note": NOTE}


@pytest.mark.parametrize("row,detail", [
    (OK, None),
    ({**OK, "refs": ["src/Vault.sol:5-8", "src/Vault.sol:20-40"]}, "was not read in full"),
    ({**OK, "refs": ["src/Vault.sol:5-8"]}, "overlap 1 focus functions, at least 2"),
    ({**OK, "refs": ["src/Vault.sol:5-8", "src/Vault.sol:24-30"]}, "do not contain anchor LEAD-0003"),
    ({**OK, "outcome": "not_applicable"}, "not accepted for a walk with anchors"),
    ({**OK, "note": "too short"}, "note must be"),
    ({**OK, "outcome": "maybe"}, "outcome must be"),
    ({**OK, "refs": ["Vault.sol"]}, "is not path:start-end"),
    ({**OK, "outcome": "violated"}, "violated needs draft_key"),
    ({**OK, "outcome": "violated", "draft_key": "d-far"}, "has no location quote inside the refs"),
    ({**OK, "outcome": "violated", "draft_key": "d-near"}, None),
    ({**OK, "outcome": "violated", "draft_key": "d-gone"}, "violated needs draft_key"),
])
def test_validate_row(row, detail):
    drafts = {"d-near": {"status": "accepted", "locations": [("src/Vault.sol", 22, 23)]},
              "d-far": {"status": "accepted", "locations": [("src/Other.sol", 1, 2)]},
              "d-gone": {"status": "withdrawn", "locations": [("src/Vault.sol", 22, 23)]}}
    got = validate_row(row, WALK, READS, drafts)
    assert (got is None) if detail is None else (detail in (got or "")), got


def test_unknown_walk_and_free_walk():
    assert "not a walk of this job" in validate_row({"walk_id": "IW-XX-1"}, None, READS, {})
    na = {"walk_id": "IW-VS-4", "outcome": "not_applicable", "note": NOTE}
    assert validate_row(na, FREE, READS, {}) is None
    # a walk without focus spans needs refs that were read, nothing more
    assert validate_row({**na, "outcome": "holds", "refs": ["src/Vault.sol:1-3"]}, FREE, READS, {}) is None


def test_merge_and_open():
    first = merge_rows(None, [OK])
    assert open_walks(LC, first, {}) == ["IW-VS-4"]
    both = merge_rows(first, [{"walk_id": "IW-VS-4", "outcome": "not_applicable", "note": NOTE}])
    assert open_walks(LC, both, {}) == []
    violated = merge_rows(both, [{**OK, "outcome": "violated", "draft_key": "d1"}])
    assert len(violated) == 2
    assert open_walks(LC, violated, {"d1": {"status": "accepted"}}) == []
    assert open_walks(LC, violated, {"d1": {"status": "withdrawn"}}) == ["IW-VS-1"]


def test_contract_shape():
    tool = {t["name"]: t for t in bundle_tools()}["review_set_section"]
    args = {"job_id": "job_" + "a" * 26, "section": "invariant_walks", "invariant_walks": {"rows": [OK]}}
    errs = list(Draft202012Validator(tool["inputSchema"]).iter_errors(args))
    assert errs == [] or all("job_id" in str(e.path) or "pattern" in e.message for e in errs), errs
    assert "invariant_walks" in tool["outputSchema"]["properties"]["section"]["enum"]
    guide = {t["name"]: t for t in bundle_tools()}["review_get_guide"]
    assert "invariants" in guide["inputSchema"]["properties"]["topic"]["enum"]
    status = {t["name"]: t for t in bundle_tools()}["review_status"]
    ids = status["outputSchema"]["properties"]["finalize_checks"]["items"]["properties"]["id"]["enum"]
    assert {"F7", "F9"} <= set(ids)


# ── database-backed: set_section and F9 ─────────────────────────────────────────


async def _wired(db_pool):
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    (pin_root / job_id / "map").mkdir(parents=True, exist_ok=True)
    walk = {**WALK, "focus": [{"range": "src/Vault.sol:5-8", "name": "withdraw"}],
            "anchors": [{"lead_id": "LEAD-0001", "ref": "src/Vault.sol:6"}]}
    (pin_root / job_id / "map" / "lifecycle.json").write_text(json.dumps({"walks": [walk, FREE], "signals": []}))
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))
    fin_mod.set_pool(db_pool)
    fin_mod.set_context(MemoryJobContext(pin_root))
    return ss_mod, job_id


async def _f9(db_pool, job_id):
    from soken_review.tools.finalize import compute_finalize_checks

    async with db_pool.connection() as conn:
        checks = await compute_finalize_checks(conn, job_id)
    return next(c for c in checks if c["id"] == "F9")


@ASYNC
async def test_set_section_walks_and_f9(db_pool):
    ss, job_id = await _wired(db_pool)
    f9 = await _f9(db_pool, job_id)
    assert f9["open"] == 2 and f9["section"] == "invariant_walks" and "IW-VS-1" in f9["reason"]

    row = {"walk_id": "IW-VS-1", "outcome": "holds", "refs": ["src/Vault.sol:5-8"], "note": NOTE}
    unread = await ss.handle_review_set_section({"job_id": job_id, "section": "invariant_walks",
                                                 "invariant_walks": {"rows": [row]}})
    assert unread["accepted"] is False and "not read in full" in json.dumps(unread["errors"][0])

    async with db_pool.connection() as conn:
        await conn.execute("insert into job_reads (job_id, path, start_line, end_line) values (%s, 'src/Vault.sol', 1, 9)",
                           (job_id,))
    r1 = await ss.handle_review_set_section({"job_id": job_id, "section": "invariant_walks",
                                             "invariant_walks": {"rows": [row]}})
    assert r1["accepted"] and r1["walks_open"] == ["IW-VS-4"], r1
    assert (await _f9(db_pool, job_id))["open"] == 1

    na = {"walk_id": "IW-VS-4", "outcome": "not_applicable", "note": NOTE}
    r2 = await ss.handle_review_set_section({"job_id": job_id, "section": "invariant_walks",
                                             "invariant_walks": {"rows": [na]}})
    assert r2["accepted"] and r2["revision"] == 2 and r2["walks_open"] == []
    assert (await _f9(db_pool, job_id))["open"] == 0


@ASYNC
async def test_set_section_walks_without_lifecycle(db_pool):
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))
    fin_mod.set_pool(db_pool)
    fin_mod.set_context(MemoryJobContext(pin_root))
    r = await ss_mod.handle_review_set_section({"job_id": job_id, "section": "invariant_walks",
                                                "invariant_walks": {"rows": [OK]}})
    assert r["accepted"] is False and "no invariant walks" in json.dumps(r["errors"][0])
    assert (await _f9(db_pool, job_id))["open"] == 0


@ASYNC
async def test_batch_call_carries_invariant_walks(db_pool):
    """The batch form (one call, several section objects) runs invariant_walks through the same
    checks as a single call and reports walks_open next to sections."""
    ss, job_id = await _wired(db_pool)
    row = {"walk_id": "IW-VS-1", "outcome": "holds", "refs": ["src/Vault.sol:5-8"], "note": NOTE}
    args = {"job_id": job_id, "section": "context_notes",
            "context_notes": {"notes": [{"p": "The whitepaper describes a single vault."}]},
            "invariant_walks": {"rows": [row]}}
    schema = {t["name"]: t for t in bundle_tools()}["review_set_section"]["inputSchema"]
    assert list(Draft202012Validator(schema).iter_errors(args)) == []
    unread = await ss.handle_review_set_section(args)
    by = {r["section"]: r for r in unread["sections"]}
    assert unread["accepted"] is False and by["context_notes"]["accepted"] and not by["invariant_walks"]["accepted"]
    assert "not read in full" in json.dumps(by["invariant_walks"]["errors"])
    async with db_pool.connection() as conn:
        await conn.execute("insert into job_reads (job_id, path, start_line, end_line) values (%s, 'src/Vault.sol', 1, 9)",
                           (job_id,))
    ok = await ss.handle_review_set_section(args)
    assert ok["accepted"] and ok["walks_open"] == ["IW-VS-4"]
    assert [r["section"] for r in ok["sections"]] == ["context_notes", "invariant_walks"]
    assert (await _f9(db_pool, job_id))["open"] == 1


def test_guide_topics_include_invariants():
    import asyncio

    from soken_review.tools.guide import _get_guide

    text = asyncio.run(_get_guide({"topics": ["severity_inputs", "invariants"]}))
    assert "topic severity_inputs" in text and "topic invariants" in text and "IW-VS-1" in text
    guide = {t["name"]: t for t in bundle_tools()}["review_get_guide"]
    assert "invariants" in guide["inputSchema"]["properties"]["topics"]["items"]["enum"]
    assert "invariants" in guide["description"]
