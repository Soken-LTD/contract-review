"""review_verify_on_fork through the handler and the worker step on Postgres (design 1.7, P4 EVM).

The container run itself is replaced by a recorded result (tests/sandbox/test_fork_verify.py covers
the endpoint, the caps and the output reader; the client-path e2e runs the real image). Checks: a
call queues one run and one verify_fork step and leaves the job as it was; the limits; the worker
claims one fork step at a time; a run result never changes the job, even when the run crashes; a
passing run bound to a draft is reported as test_verified with the report line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest_asyncio

import soken_review.tools  # noqa: F401
from soken_review.db.job_repo import JobRepo
from soken_review.sandbox import fork_verify as fv
from soken_review.tools import verify_fork as vf_mod
from soken_review.tools.context import MemoryJobContext

from .test_submit_finalize import _create_ready_job_with_pin

ASYNC = pytest.mark.asyncio(loop_scope="session")
WETH9 = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
BLOCK = 26_311_087
TEST = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import {Test} from "forge-std/Test.sol";
import "pinned/src/Vault.sol";
contract VerifyTest is Test { function test_depositCredits() public { assertTrue(true); } }
"""


@pytest.fixture(autouse=True)
def _limits(monkeypatch):
    fv.fork_limits.cache_clear()
    monkeypatch.setattr(vf_mod, "_POLL_S", 0.05)
    monkeypatch.setattr("soken_review.sandbox.profile.locked_image", lambda name: "img@sha256:" + "a" * 64)
    yield
    fv.fork_limits.cache_clear()


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def _no_fork_steps_left(db_pool):
    """Queued fork steps of this module never reach another module's claim."""
    yield
    async with db_pool.connection() as conn:
        await conn.execute("update job_steps set status = 'cancelled', cancel_reason = 'budget' "
                           "where step = 'verify_fork' and status = 'queued'")
        await conn.execute("update job_steps set status = 'done' where step = 'verify_fork' and status = 'running'")


async def _job(db_pool, chain_id: int | None = 1) -> tuple[str, Path]:
    jid, pin_root = await _create_ready_job_with_pin(db_pool)
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set chain_id = %s, address = %s where job_id = %s", (chain_id, WETH9, jid))
    work = pin_root.parent / "work" / jid
    work.mkdir(parents=True, exist_ok=True)
    (work / "chain_state.json").write_text(json.dumps({"chain_id": chain_id, "address": WETH9, "block": BLOCK}))
    vf_mod.set_pool(db_pool)
    vf_mod.set_context(MemoryJobContext(pin_root))
    from soken_review.tools import chain as chain_mod

    chain_mod.set_pool(db_pool)
    chain_mod.set_context(MemoryJobContext(pin_root))
    return jid, pin_root


async def _draft(db_pool, jid: str, key: str = "d-weth") -> str:
    async with db_pool.connection() as conn:
        await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status, current_revision,
            severity, evidence_level) values (%s, %s, 1, 'model', 'accepted', 1, 'Medium', 'reasoning_only')""", (jid, key))
    return key


async def _rows(db_pool, sql: str, *params):
    async with db_pool.connection() as conn:
        return await (await conn.execute(sql, params)).fetchall()


@ASYNC
async def test_call_queues_one_run_and_one_step_and_leaves_the_job(db_pool):
    jid, _ = await _job(db_pool)
    key = await _draft(db_pool, jid)
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "draft_key": key,
                                              "wait_seconds": 0})
    assert res["accepted"] is True, res
    assert res["status"] == "queued" and res["run_id"].startswith("fork-")
    assert res["chain"] == {"family": "evm", "chain_id": 1, "network": res["chain"]["network"], "block": BLOCK}
    assert "poll" in res
    steps = await _rows(db_pool, "select step, status, units, ram_mb from job_steps where job_id = %s", jid)
    assert steps == [("verify_fork", "queued", 1, 1536)]
    runs = await _rows(db_pool, "select status, block, draft_key, test_path, test_source from fork_runs where job_id = %s", jid)
    assert runs == [("queued", BLOCK, key, fv.DEFAULT_TEST_PATH, TEST)]
    state = await _rows(db_pool, "select state from jobs where job_id = %s", jid)
    assert state == [("ready",)]
    # one pending run per job
    again = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "wait_seconds": 0})
    assert again["accepted"] is False and again["errors"][0]["code"] == "E_FORK_LIMIT"


@ASYNC
async def test_rejections_never_queue_anything(db_pool):
    from soken_review.errors import ReviewError

    jid, _ = await _job(db_pool)
    bad = TEST.replace('import "pinned/src/Vault.sol";', 'import "../../etc/x.sol";')
    with pytest.raises(ReviewError) as exc:
        await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": bad}, "wait_seconds": 0})
    assert exc.value.code == "E_INVALID_ARGUMENT" and exc.value.fields["field"] == "test.content"
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "draft_key": "nope",
                                              "wait_seconds": 0})
    assert res["errors"][0]["code"] == "E_FINDING_NOT_FOUND"
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set state = 'finalized' where job_id = %s", (jid,))
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "wait_seconds": 0})
    assert res["accepted"] is False and res["errors"][0]["code"] == "E_JOB_FROZEN"
    assert await _rows(db_pool, "select 1 from fork_runs where job_id = %s", jid) == []
    assert await _rows(db_pool, "select 1 from job_steps where job_id = %s", jid) == []


@ASYNC
async def test_non_evm_job_and_unpinned_image_are_rejections(db_pool, monkeypatch):
    jid, _ = await _job(db_pool)
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set chain = 'tron', chain_id = null where job_id = %s", (jid,))
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "wait_seconds": 0})
    assert res["errors"][0]["code"] == "E_CHAIN_UNSUPPORTED"
    jid2, _ = await _job(db_pool)
    monkeypatch.setattr("soken_review.sandbox.profile.locked_image", lambda name: None)
    res = await vf_mod.handle_verify_on_fork({"job_id": jid2, "test": {"content": TEST}, "wait_seconds": 0})
    assert res["errors"][0]["code"] == "E_FORK_UNAVAILABLE"


@ASYNC
async def test_runs_per_job_cap(db_pool, monkeypatch):
    jid, _ = await _job(db_pool)
    monkeypatch.setitem(fv.fork_limits(), "runs_per_job", 1)
    first = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "wait_seconds": 0})
    async with db_pool.connection() as conn:
        await conn.execute("update fork_runs set status = 'failed' where run_id = %s", (first["run_id"],))
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "wait_seconds": 0})
    assert res["errors"][0]["code"] == "E_FORK_LIMIT" and "1 of 1" in res["errors"][0]["what"]


async def _claim(db_pool):
    async with db_pool.connection() as conn:
        return await JobRepo(conn).claim_step(host="t", free_units=8, lease_secs=60, free_ram_mb=16384,
                                              max_units_idle=8, max_ram_idle=16384, render=False)


@ASYNC
async def test_worker_claims_one_fork_step_at_a_time(db_pool):
    async with db_pool.connection() as conn:   # other tests' queued rows stay out of this claim
        await conn.execute("update job_steps set status = 'cancelled', cancel_reason = 'budget' where status = 'queued'")
        await conn.execute("update job_steps set status = 'done' where step = 'verify_fork' and status = 'running'")
    a, _ = await _job(db_pool)
    ra = await vf_mod.handle_verify_on_fork({"job_id": a, "test": {"content": TEST}, "wait_seconds": 0})
    b, _ = await _job(db_pool)   # each job has its own pin root; the handler context follows it
    rb = await vf_mod.handle_verify_on_fork({"job_id": b, "test": {"content": TEST}, "wait_seconds": 0})
    first = await _claim(db_pool)
    assert first is not None and first["step"] == "verify_fork"
    assert await _claim(db_pool) is None          # the second fork waits while one runs
    async with db_pool.connection() as conn:
        await JobRepo(conn).complete_step(first["id"], "done")
    second = await _claim(db_pool)
    assert second is not None and second["step"] == "verify_fork" and second["id"] != first["id"]
    assert {first["job_id"], second["job_id"]} == {a, b}
    async with db_pool.connection() as conn:
        await JobRepo(conn).complete_step(second["id"], "done")
    assert ra["run_id"] != rb["run_id"]


@ASYNC
async def test_worker_step_records_the_result_and_a_crash_never_fails_the_job(db_pool, monkeypatch):
    async with db_pool.connection() as conn:
        await conn.execute("update job_steps set status = 'cancelled', cancel_reason = 'budget' where status = 'queued'")
        await conn.execute("update job_steps set status = 'done' where step = 'verify_fork' and status = 'running'")
    jid, pin_root = await _job(db_pool)
    key = await _draft(db_pool, jid)
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "draft_key": key,
                                              "wait_seconds": 0})
    passed = {"status": "passed", "wall_s": 9.5, "rpc": {"requests": 30, "upstream_calls": 28, "denied": 1,
                                                          "denied_methods": ["anvil_nodeInfo"],
                                                          "addresses": [WETH9.lower()]},
              "tests": [{"name": "VerifyTest.test_depositCredits()", "status": "passed", "gas": 253747, "events": 2}]}

    async def fake_execute(run, root, **kw):
        assert run["block"] == BLOCK and run["test_source"] == TEST
        return passed

    monkeypatch.setattr(fv, "execute", fake_execute)
    step = await _claim(db_pool)
    await fv.run_step(db_pool, pin_root, step)
    polled = await vf_mod.handle_verify_on_fork({"job_id": jid, "run_id": res["run_id"], "wait_seconds": 0})
    assert polled["status"] == "passed" and polled["matches_expectation"] is True
    assert polled["evidence"]["level"] == "test_verified"
    assert polled["evidence"]["report_line"].startswith(f"Verified by a test on a local fork of {polled['chain']['network']} "
                                                        f"at block {BLOCK:,}: VerifyTest.test_depositCredits()")
    assert "untrusted_text_note" in polled
    st = await _rows(db_pool, "select status, provenance->>'status' from job_steps where id = %s", step["id"])
    assert st == [("done", "passed")]

    # a second run whose execution raises: run error, step done, job untouched
    async def boom(run, root, **kw):
        raise RuntimeError("docker went away")

    monkeypatch.setattr(fv, "execute", boom)
    res2 = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "wait_seconds": 0})
    step2 = await _claim(db_pool)
    await fv.run_step(db_pool, pin_root, step2)
    polled2 = await vf_mod.handle_verify_on_fork({"job_id": jid, "run_id": res2["run_id"], "wait_seconds": 0})
    assert polled2["status"] == "error" and polled2["reason"] == "internal"
    assert "evidence" not in polled2
    assert await _rows(db_pool, "select state from jobs where job_id = %s", jid) == [("ready",)]
    assert await _rows(db_pool, "select status from job_steps where id = %s", step2["id"]) == [("done",)]


@ASYNC
async def test_poll_waits_for_the_result(db_pool):
    import asyncio

    jid, _ = await _job(db_pool)
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "wait_seconds": 0})

    async def finish():
        await asyncio.sleep(0.2)
        async with db_pool.connection() as conn:
            await conn.execute("update fork_runs set status = 'failed', result = %s where run_id = %s",
                               (json.dumps({"status": "failed", "tests": [{"name": "VerifyTest.test_x()", "status": "failed",
                                                                            "reason": {"value": "boom", "class": "chain_text"}}]}),
                                res["run_id"]))

    task = asyncio.create_task(finish())
    polled = await vf_mod.handle_verify_on_fork({"job_id": jid, "run_id": res["run_id"], "wait_seconds": 5})
    await task
    assert polled["status"] == "failed" and polled["matches_expectation"] is False
    assert polled["tests"][0]["reason"]["class"] == "chain_text"


# ── security review 2026-10-31: what a run may raise, and finalize ─────────


async def _passed_run(db_pool, jid: str, key: str, *, revision: int = 1, expect: str = "pass",
                      addresses: list[str] | None = None, source: str = TEST, finished: str = "now() - interval '1 minute'") -> str:
    import secrets

    run_id = "fork-" + secrets.token_hex(6)
    result = {"status": "passed", "rpc": {"addresses": addresses or []},
              "tests": [{"name": "VerifyTest.test_depositCredits()", "status": "passed", "gas": 1}]}
    async with db_pool.connection() as conn:
        await conn.execute(f"""insert into fork_runs (run_id, job_id, draft_key, draft_revision, status, chain_id, network,
              block, test_path, test_sha256, test_source, expect, result, finished_at)
              values (%s, %s, %s, %s, 'passed', 1, 'Ethereum Mainnet', %s, 'test/Verify.t.sol', %s, %s, %s, %s, {finished})""",
                           (run_id, jid, key, revision, BLOCK, "d" * 64, source, expect, json.dumps(result)))
    return run_id


async def _verified(db_pool, jid: str) -> dict:
    from soken_review.engine.fork_evidence import verified_runs

    async with db_pool.connection() as conn:
        return await verified_runs(conn, jid)


async def _poll(jid: str, run_id: str) -> dict:
    return await vf_mod.handle_verify_on_fork({"job_id": jid, "run_id": run_id, "wait_seconds": 0})


@ASYNC
async def test_a_revised_draft_loses_the_mark_until_a_new_run_passes(db_pool):
    jid, _ = await _job(db_pool)
    key = await _draft(db_pool, jid)
    old = await _passed_run(db_pool, jid, key, revision=1, addresses=[WETH9.lower()])
    assert set(await _verified(db_pool, jid)) == {key}
    async with db_pool.connection() as conn:
        await conn.execute("update finding_drafts set current_revision = 2 where job_id = %s and draft_key = %s", (jid, key))
    assert await _verified(db_pool, jid) == {}
    polled = await _poll(jid, old)
    assert polled["evidence"]["level"] == "unchanged" and "revised" in polled["evidence"]["why"]
    new = await _passed_run(db_pool, jid, key, revision=2, addresses=[WETH9.lower()])
    assert (await _verified(db_pool, jid))[key]["run_id"] == new


@ASYNC
async def test_queued_runs_store_the_current_revision(db_pool):
    jid, _ = await _job(db_pool)
    key = await _draft(db_pool, jid)
    async with db_pool.connection() as conn:
        await conn.execute("update finding_drafts set current_revision = 3 where job_id = %s and draft_key = %s", (jid, key))
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "draft_key": key, "wait_seconds": 0})
    assert await _rows(db_pool, "select draft_revision from fork_runs where run_id = %s", res["run_id"]) == [(3,)]


@ASYNC
async def test_expect_fail_and_unexercised_runs_do_not_raise(db_pool):
    jid, _ = await _job(db_pool)
    key = await _draft(db_pool, jid)
    fail_claim = await _passed_run(db_pool, jid, key, expect="fail", addresses=[WETH9.lower()])
    other = await _passed_run(db_pool, jid, key, addresses=["0x" + "9" * 40])     # read another contract only
    assert await _verified(db_pool, jid) == {}
    assert "expect fail" in (await _poll(jid, fail_claim))["evidence"]["why"]
    assert "deployment address" in (await _poll(jid, other))["evidence"]["why"]


@ASYNC
async def test_importing_a_cited_pinned_file_counts_as_exercised(db_pool):
    jid, _ = await _job(db_pool)
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set address = null where job_id = %s", (jid,))   # a repository review
    key = await _draft(db_pool, jid)
    run = await _passed_run(db_pool, jid, key)          # TEST imports pinned/src/Vault.sol, nothing read
    assert await _verified(db_pool, jid) == {}           # the finding quotes no file yet
    async with db_pool.connection() as conn:
        await conn.execute("""insert into finding_revisions (job_id, draft_key, revision, content, content_hash, category,
            category_family, impact_class, computed_severity, severity_rule)
            values (%s, %s, 1, '{}', 'h', 'evm.dos', 'evm', 'griefing_with_victim_loss', 'Medium', 'r')""", (jid, key))
        await conn.execute("insert into finding_quote_ranges values (%s, %s, 1, 0, 'location', 'src/Vault.sol', 1, 3)",
                           (jid, key))
    assert (await _verified(db_pool, jid))[key]["run_id"] == run


@ASYNC
async def test_runs_that_end_after_finalize_do_not_count(db_pool):
    jid, _ = await _job(db_pool)
    key = await _draft(db_pool, jid)
    await _passed_run(db_pool, jid, key, addresses=[WETH9.lower()], finished="now() + interval '1 hour'")
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set state = 'finalized', finalized_at = now() where job_id = %s", (jid,))
    assert await _verified(db_pool, jid) == {}


@ASYNC
async def test_finalize_refuses_while_a_fork_run_is_pending(db_pool):
    from soken_review.tools import finalize as fin_mod

    jid, pin_root = await _job(db_pool)
    fin_mod.set_pool(db_pool)
    fin_mod.set_context(MemoryJobContext(pin_root))
    res = await vf_mod.handle_verify_on_fork({"job_id": jid, "test": {"content": TEST}, "wait_seconds": 0})
    out = await fin_mod.handle_review_finalize({"job_id": jid})
    assert out["accepted"] is False and out["errors"][0]["code"] == "E_FORK_PENDING"
    assert res["run_id"] in out["errors"][0]["what"]
    assert await _rows(db_pool, "select state from jobs where job_id = %s", jid) == [("ready",)]
    async with db_pool.connection() as conn:   # an ended run (any status) never blocks finalize
        await conn.execute("update fork_runs set status = 'error' where run_id = %s", (res["run_id"],))
    out = await fin_mod.handle_review_finalize({"job_id": jid})
    assert not any(e["code"] == "E_FORK_PENDING" for e in out.get("errors") or [])
    async with db_pool.connection() as conn:   # its render row never reaches another module's claim
        await conn.execute("update job_steps set status = 'cancelled', cancel_reason = 'budget' "
                           "where job_id = %s and status = 'queued'", (jid,))


def test_test_verified_alone_never_passes_k8():
    """The raise is printed only: finalize passes the base level. Even if a caller passed
    test_verified, K8 still caps an otherwise Critical finding at High."""
    from soken_review.engine.severity import SeverityContext, compute_severity

    matrix = {"impact_class": "theft_of_funds", "magnitude": "unbounded", "trigger": "anyone",
              "precondition": "none", "reversibility": "irreversible"}
    r = compute_severity(matrix, "finalize", SeverityContext(phase="finalize", evidence_level="test_verified",
                                                              has_attack_steps=True, open_downgrade_item=False))
    assert "K8" in r.caps_applied and r.severity == "High"


def test_evidence_fails_closed_on_mixed_results_and_unfinished_runs():
    from datetime import UTC, datetime, timedelta

    from soken_review.engine.fork_evidence import why_not

    fin = datetime(2026, 10, 31, 8, 0, tzinfo=UTC)
    base = {"draft_key": "d", "status": "passed", "expect": "pass", "draft_revision": 1, "test_source": TEST,
            "finished_at": fin - timedelta(minutes=5),
            "result": {"rpc": {"addresses": [WETH9.lower()]},
                       "tests": [{"name": "A.test_a()", "status": "passed"}]}}
    assert why_not(base, 1, WETH9, set(), fin) is None
    mixed = {**base, "result": {**base["result"], "tests": [{"name": "A.test_a()", "status": "passed"},
                                                             {"name": "A.test_b()", "status": "failed"}]}}
    assert "every test" in why_not(mixed, 1, WETH9, set(), fin)
    skipped = {**base, "result": {**base["result"], "tests": [{"name": "A.test_a()", "status": "passed"},
                                                               {"name": "A.test_c()", "status": "skipped"}]}}
    assert "every test" in why_not(skipped, 1, WETH9, set(), fin)
    empty = {**base, "result": {**base["result"], "tests": []}}
    assert "every test" in why_not(empty, 1, WETH9, set(), fin)
    unfinished = {**base, "finished_at": None}
    assert "finalized" in why_not(unfinished, 1, WETH9, set(), fin)
    late = {**base, "finished_at": fin + timedelta(seconds=1)}
    assert "finalized" in why_not(late, 1, WETH9, set(), fin)
    assert why_not(unfinished, 1, WETH9, set(), None) is None     # not finalized yet: the run's own status decides
