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
async def test_snapshot_waits_for_ready_and_never_fails_the_caller(db_pool, monkeypatch):
    jid, pin_root = await _bsc_job(db_pool, state="analyzing")
    _use(monkeypatch, FIX / "thena_bsc.json")
    await chain_mod.auto_snapshot(jid, wait=True)
    assert not (pin_root / jid / chain_mod.AUTO_FILE).exists()   # not ready: no marker, tried again later

    async def boom(job_id):
        raise RuntimeError("upstream exploded")

    async with db_pool.connection() as conn:
        await conn.execute("update jobs set state = 'ready' where job_id = %s", (jid,))
    monkeypatch.setattr(chain_mod, "_auto_body", boom)
    await chain_mod.auto_snapshot(jid, wait=True)
    marker = json.loads((pin_root / jid / chain_mod.AUTO_FILE).read_text())
    assert marker["ok"] is False and marker["detail"] == "RuntimeError"
    assert chain_mod._auto_due(jid) is False                     # retried only after AUTO_RETRY_S
