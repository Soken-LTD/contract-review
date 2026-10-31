"""The one-time chain snapshot behind review_facts and review_status (client_refresh, blind round 5).

A client whose tool list predates review_chain_read gets the deployment's holders, proxy slots,
paused flag and native balance as chain.target.* facts without calling a new tool."""

from __future__ import annotations

import json

import pytest

from soken_review.mapping.facts import load_facts
from soken_review.tools import chain as chain_mod
from soken_review.tools import read as read_mod
from soken_review.tools.context import MemoryJobContext

from .test_chain_tools import FIX, _bsc_job, _clean_state, _use  # noqa: F401

ASYNC = pytest.mark.asyncio(loop_scope="session")


@ASYNC
async def test_review_facts_carries_the_target_snapshot_once(db_pool, monkeypatch):
    jid, pin_root = await _bsc_job(db_pool)
    replay = _use(monkeypatch, FIX / "thena_bsc.json")
    ctx = MemoryJobContext(pin_root)
    ctx.set_state(jid, "ready")
    read_mod.set_context(ctx)
    text = await read_mod._facts({"job_id": jid, "filter": "chain.target."})
    keys = {f["key"] for f in load_facts(pin_root, jid) if f["key"].startswith("chain.target.")}
    assert "chain.target.deployer" in keys and "chain.target.deployer" in text, text
    marker = json.loads((pin_root / jid / chain_mod.AUTO_FILE).read_text())
    assert marker["ok"] is True
    seen = len(replay.seen)
    await read_mod._facts({"job_id": jid})
    assert len(replay.seen) == seen          # no second read for the same job


@ASYNC
async def test_snapshot_runs_before_ready_and_never_fails_the_caller(db_pool, monkeypatch):
    """Thin server (2026-10-31): live state does not depend on the source, so the snapshot runs from job
    start (any pipeline state with a pin directory) and review_status returns it as chain_state."""
    jid, pin_root = await _bsc_job(db_pool, state="analyzing")
    _use(monkeypatch, FIX / "thena_bsc.json")
    assert chain_mod.chain_state({"job_id": jid, "address": "0x" + "1" * 40})["state"] == "pending"
    await chain_mod.auto_snapshot(jid, wait=True)
    marker = json.loads((pin_root / jid / chain_mod.AUTO_FILE).read_text())
    assert marker["ok"] is True
    async with db_pool.connection() as conn:
        row = await (await conn.execute("select address from jobs where job_id = %s", (jid,))).fetchone()
    cs = chain_mod.chain_state({"job_id": jid, "address": row[0]})
    assert cs["state"] == "done" and cs["values"]["deployer"].startswith("0x")
    assert "chain.target.<field>" in cs["note"]
    assert chain_mod.chain_state({"job_id": jid, "address": None}) is None

    jid2, pin_root2 = await _bsc_job(db_pool, state="ready")
    async def boom(job_id):
        raise RuntimeError("upstream exploded")

    monkeypatch.setattr(chain_mod, "_auto_body", boom)
    await chain_mod.auto_snapshot(jid2, wait=True)
    marker = json.loads((pin_root2 / jid2 / chain_mod.AUTO_FILE).read_text())
    assert marker["ok"] is False and marker["detail"] == "RuntimeError"
    assert chain_mod._auto_due(jid2) is False                    # retried only after AUTO_RETRY_S
    assert chain_mod.chain_state({"job_id": jid2, "address": "0x" + "1" * 40})["state"] == "failed"


@ASYNC
async def test_snapshot_waits_for_the_pin_directory(db_pool, monkeypatch):
    jid, pin_root = await _bsc_job(db_pool, state="queued")
    _use(monkeypatch, FIX / "thena_bsc.json")
    import shutil

    shutil.rmtree(pin_root / jid)
    monkeypatch.setattr(chain_mod, "AUTO_PIN_WAIT_S", 0.2)
    monkeypatch.setattr(chain_mod, "AUTO_PIN_POLL_S", 0.05)
    await chain_mod.auto_snapshot(jid, wait=True)
    assert not (pin_root / jid).exists()        # never creates the job directory; retried by review_status


# ── per-job notice state in jobs.client_shape ─────────────────────────────


async def _shape(db_pool, jid):
    async with db_pool.connection() as conn:
        row = await (await conn.execute("select client_shape from jobs where job_id = %s", (jid,))).fetchone()
    return row[0] if row else None


@ASYNC
async def test_notice_state_lives_in_the_job_row(db_pool):
    from soken_review import client_refresh

    jid, _pin = await _bsc_job(db_pool)
    client_refresh.set_pool(db_pool)
    try:
        assert await client_refresh.decide("review_start", {}, {"accepted": True, "job_id": jid}, False)
        assert (await _shape(db_pool, jid))["notices"] == 1
        assert await client_refresh.decide("review_chain_read", {"job_id": jid}, {"accepted": True}, False) is None
        assert (await _shape(db_pool, jid))["fresh"] is True
        assert await client_refresh.decide("review_finalize", {"job_id": jid}, {"accepted": True}, False) is None
    finally:
        client_refresh.set_pool(None)


@ASYNC
async def test_no_state_for_made_up_ids_or_failed_calls(db_pool, tmp_path):
    from soken_review import client_refresh

    jid, pin_root = await _bsc_job(db_pool)
    client_refresh.set_pool(db_pool)
    ghost = "job_" + "Z" * 26
    try:
        assert await client_refresh.decide("review_status", {"job_id": ghost}, {"accepted": True}, False) is None
        assert not (pin_root / ghost).exists()
        missing = {"accepted": False, "errors": [{"code": "E_JOB_NOT_FOUND"}]}
        assert await client_refresh.decide("review_status", {"job_id": jid}, missing, False) is None
        rejected = {"accepted": False, "errors": [{"code": "E_JOB_NOT_READY"}]}
        assert await client_refresh.decide("review_finalize", {"job_id": jid}, rejected, False) is None
        assert await _shape(db_pool, jid) == {}
        sev = {"accepted": False, "errors": [{"code": "E_SEVERITY_CONFIRM"}]}
        assert await client_refresh.decide("review_submit_finding", {"job_id": jid}, sev, False)
    finally:
        client_refresh.set_pool(None)
