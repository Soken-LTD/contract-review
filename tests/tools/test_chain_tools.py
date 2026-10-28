"""review_chain_read / roles / balances through the handlers on Postgres (design P1).

Answers come from the BSC recording of tests/fixtures/chain/thena_bsc.json, so the facts are the
real Thena values at block 130,229,517. Checks: facts land in chain_facts.json with their block and
are seen by review_facts and the submit gate; a finding citing them is accepted; read units are
charged per job and refunded when every free source fails; budget and state rejections never
touch the job.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import soken_review.tools  # noqa: F401
from soken_review.chain import store as chain_store
from soken_review.chain.endpoints import Health
from soken_review.chain.proxy import ChainProxy
from soken_review.mapping.facts import load_facts
from soken_review.mapping.step import run_map_step
from soken_review.tools import chain as chain_mod
from soken_review.tools.context import MemoryJobContext
from tests.chain.replay import Replay

from .test_submit_finalize import _VALID_SUBMISSION, _create_ready_job_with_pin

ASYNC = pytest.mark.asyncio(loop_scope="session")
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "chain"
VE = "0xfBBF371C9B0B994EebFcC977CEf603F7f31c070D"
THE = "0xf4c8e32eadec4bfe97e0f595add0f4450a863a11"
META = json.loads((FIX / "thena_bsc.meta.json").read_text())


@pytest.fixture(autouse=True)
def _clean_state():
    Health.reset()
    chain_store._MEM.clear()
    chain_store.limits.cache_clear()
    yield
    Health.reset()
    chain_store._MEM.clear()
    chain_store.limits.cache_clear()


def _use(monkeypatch, rows: Path | dict) -> Replay:
    replay = Replay(rows)
    monkeypatch.setattr(chain_mod, "ChainProxy", lambda **kw: ChainProxy(transport=replay, pace=False, **kw))
    return replay


async def _bsc_job(db_pool, state: str = "ready") -> tuple[str, Path]:
    jid, pin_root = await _create_ready_job_with_pin(db_pool)
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set chain_id = 56, address = %s, state = %s where job_id = %s", (VE, state, jid))
    run_map_step(pin_root, jid, solc_output_path=None, build_ok=False, build_detail="no build in test")
    chain_mod.set_pool(db_pool)
    chain_mod.set_context(MemoryJobContext(pin_root))
    return jid, pin_root


READ_ITEMS = [
    {"alias": "ve", "address": VE, "kind": "call", "fn": "supply()", "returns": "uint256"},
    {"alias": "ve", "address": VE, "kind": "call", "fn": "token()", "returns": "address"},
    {"alias": "ve", "address": VE, "kind": "call", "fn": "getPastTotalSupply(uint256)", "args": [META["past_ts"]],
     "returns": "uint256"},
]


@ASYNC
async def test_chain_read_records_facts_with_block_and_charges_the_job(db_pool, monkeypatch):
    jid, pin_root = await _bsc_job(db_pool)
    _use(monkeypatch, FIX / "thena_bsc.json")
    res = await chain_mod.handle_chain_read({"job_id": jid, "items": READ_ITEMS})
    assert res["accepted"] is True, res
    assert res["block"]["resolved"] == META["block"] and res["network"] == "BNB Smart Chain Mainnet"
    assert res["capability"]["degraded"] is True and res["capability"]["keyed"] is False
    by = {r["fn"]: r for r in res["items"]}
    assert by["supply()"]["value"] == "335304456968324627407175342"
    assert by["getPastTotalSupply(uint256)"]["revert_reason"] == "Panic(0x11): arithmetic underflow or overflow"
    facts = {f["key"]: f for f in load_facts(pin_root, jid)}
    assert facts["chain.ve.supply"]["block"] == META["block"]
    assert "source.files" in facts           # pipeline facts kept beside the chain facts
    assert res["budget"]["charged"] == 3
    async with db_pool.connection() as conn:
        row = await (await conn.execute("select ru_used from chain_job_ru where job_id = %s", (jid,))).fetchone()
    assert row[0] == 3
    # facts.json is never rewritten with chain facts (the map step rewrites it)
    on_disk = json.loads((pin_root / jid / "facts.json").read_text())
    assert not any(f["key"].startswith("chain.ve.") for f in on_disk)


@ASYNC
async def test_finding_citing_chain_facts_is_accepted(db_pool, monkeypatch):
    from soken_review.tools import submit as submit_mod

    jid, pin_root = await _bsc_job(db_pool)
    _use(monkeypatch, FIX / "thena_bsc.json")
    assert (await chain_mod.handle_chain_read({"job_id": jid, "items": READ_ITEMS}))["accepted"]
    bal = await chain_mod.handle_chain_balances({"job_id": jid, "token": THE, "token_alias": "the",
                                                 "holders": [{"alias": "ve", "address": VE}]})
    assert bal["accepted"] and bal["items"][0]["value"] == "150473875546894119406360255"
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    args = json.loads(json.dumps(_VALID_SUBMISSION))
    args.update(job_id=jid, draft_key="chain-cite-001")
    args["body"]["description"] = [{"p": "On chain the recorded lock total is {{fact:chain.ve.supply}} while the escrow "
                                          "holds {{fact:chain.the.balance.ve}}; a past supply query reverts with "
                                          "{{fact:chain.ve.get_past_total_supply.revert_reason}}."}]
    out = await submit_mod.handle_review_submit_finding(args)
    assert out.get("accepted") is True, out


@ASYNC
async def test_roles_reads_the_safe_and_the_deployer(db_pool, monkeypatch):
    jid, _pin = await _bsc_job(db_pool)
    _use(monkeypatch, FIX / "thena_bsc.json")
    res = await chain_mod.handle_chain_roles({"job_id": jid, "address": VE, "alias": "ve",
                                              "getters": ["team", "voter", "artProxy"]})
    assert res["accepted"], res
    team = next(h for h in res["roles"]["holders"] if h["getter"] == "team")
    assert team["kind"] == "safe" and team["safe_threshold"] == 3
    assert res["roles"]["deployment"]["deployer"].lower() == "0x993ae2b514677c7ac52baecd8871d2b362a9d693"


@ASYNC
async def test_every_free_source_failing_is_a_rejection_and_refunded(db_pool, monkeypatch):
    jid, _pin = await _bsc_job(db_pool)
    replay = _use(monkeypatch, {})
    res = await chain_mod.handle_chain_read({"job_id": jid, "items": READ_ITEMS})
    assert res["accepted"] is False
    err = res["errors"][0]
    assert err["code"] == "E_CHAIN_UNAVAILABLE" and "finalize do not depend on it" in err["fix"]
    assert replay.missing
    async with db_pool.connection() as conn:
        row = await (await conn.execute("select ru_used, state from chain_job_ru join jobs using (job_id) "
                                        "where job_id = %s", (jid,))).fetchone()
    assert row == (0, "ready")


@ASYNC
async def test_budget_is_a_rejection_that_leaves_the_job_alone(db_pool, monkeypatch):
    jid, _pin = await _bsc_job(db_pool)
    _use(monkeypatch, FIX / "thena_bsc.json")
    monkeypatch.setenv("SOKEN_CHAIN_JOB_RU", "2")
    chain_store.limits.cache_clear()
    res = await chain_mod.handle_chain_read({"job_id": jid, "items": READ_ITEMS})
    assert res["accepted"] is False and res["errors"][0]["code"] == "E_CHAIN_BUDGET"


@ASYNC
@pytest.mark.parametrize(("state", "code"), [("analyzing", "E_JOB_NOT_READY"), ("finalized", "E_JOB_FROZEN")])
async def test_state_gates(db_pool, monkeypatch, state, code):
    jid, _pin = await _bsc_job(db_pool, state=state)
    _use(monkeypatch, FIX / "thena_bsc.json")
    res = await chain_mod.handle_chain_read({"job_id": jid, "items": READ_ITEMS})
    assert res["accepted"] is False and res["errors"][0]["code"] == code


@ASYNC
async def test_bad_alias_and_address_are_argument_errors(db_pool, monkeypatch):
    from soken_review.errors import ReviewError

    jid, _pin = await _bsc_job(db_pool)
    _use(monkeypatch, FIX / "thena_bsc.json")
    for item in ({**READ_ITEMS[0], "alias": "block"}, {**READ_ITEMS[0], "address": "TRegosVaS1o3DHG85nnW8xYzczPm3xL76K"}):
        with pytest.raises(ReviewError) as exc:
            await chain_mod.handle_chain_read({"job_id": jid, "items": [item]})
        assert exc.value.code == "E_INVALID_ARGUMENT"


@ASYNC
async def test_shared_cache_needs_two_agreeing_hosts_or_a_configured_one(db_pool):
    """Security review 2026-10-28: one lying free endpoint must not poison other jobs' facts."""
    key, other = "a" * 64, "b" * 64
    job_a, job_b = chain_store.Cache(db_pool, "job_A"), chain_store.Cache(db_pool, "job_B")
    await job_a.put(key, {"r": "0x01"}, True, "https://free-one.example", False)
    assert await job_a.get(key) == {"r": "0x01"}          # the reading job keeps its own answer
    assert await job_b.get(key) is None                     # nobody else trusts one free host
    await job_b.put(key, {"r": "0x01"}, True, "https://free-one.example", False)
    chain_store._MEM.clear()
    assert await chain_store.Cache(db_pool, "job_C").get(key) is None   # same host twice is not agreement
    await job_b.put(key, {"r": "0x01"}, True, "https://free-two.example", False)
    chain_store._MEM.clear()
    assert await chain_store.Cache(db_pool, "job_C").get(key) == {"r": "0x01"}
    # a disagreeing host removes the shared entry
    await chain_store.Cache(db_pool, "job_D").put(other, {"r": "0x02"}, True, "https://free-one.example", False)
    await chain_store.Cache(db_pool, "job_E").put(other, {"r": "0x03"}, True, "https://free-two.example", False)
    async with db_pool.connection() as conn:
        assert await (await conn.execute("select 1 from chain_cache where key = %s", (other,))).fetchone() is None
    # an operator-configured host is shared at once, and entries expire
    await chain_store.Cache(db_pool, "job_F").put(other, {"r": "0x04"}, True, "https://mine.example", True)
    chain_store._MEM.clear()
    assert await chain_store.Cache(db_pool, "job_G").get(other) == {"r": "0x04"}
    async with db_pool.connection() as conn:
        await conn.execute("update chain_cache set created_at = now() - interval '40 days' where key = %s", (other,))
    chain_store._MEM.clear()
    assert await chain_store.Cache(db_pool, "job_G").get(other) is None
    async with db_pool.connection() as conn:
        await conn.execute("delete from chain_cache where key in (%s, %s)", (key, other))
