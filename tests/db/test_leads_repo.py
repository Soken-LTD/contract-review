"""leads.json -> leads table mirror (db/leads_repo.py).

The product path never populated the table before 2026-10-22: submit's lead linking, finalize's F2
and F4 gates and the E3 evidence level all read it, so every finding stayed reasoning_only and K4
printed real Highs as Low. These tests pin the mirror and its DDL mapping.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.db.leads_repo import lead_row, lead_states, load_leads_json, persist_leads, persist_leads_from_pin

pytestmark = pytest.mark.anyio

LEADS = [
    {"id": "LEAD-0001", "rule_id": "unprotected-upgrade", "tools": ["slither@0.11.6"],
     "category": "evm.upgradeability.storage_authority", "analyzer_severity_raw": "High", "severity_norm": "High",
     "file": "src/A.sol", "start": 92, "end": 203, "state": "open"},
    {"id": "LEAD-0002", "rule_id": "internal-function-used-once", "tools": ["aderyn@0.6.8"],
     "category": "evm.other", "analyzer_severity_raw": "Low", "severity_norm": "Info",
     "file": "lib/B.sol", "start": 1, "end": 1, "state": "open"},
    # analyzer leads never carry Critical in the DDL: normalised to High
    {"id": "LEAD-0003", "rule_id": "arbitrary-send", "tools": ["slither@0.11.6"],
     "category": "evm.access_control", "analyzer_severity_raw": "Critical", "severity_norm": "Critical",
     "file": "src/A.sol", "start": 10, "end": 12, "state": "open"},
    # does not fit the DDL (no rule id): skipped, never raises
    {"id": "LEAD-0004", "category": "evm.other", "file": "src/A.sol", "start": 1, "end": 1},
]


async def _job(db_pool) -> str:
    from soken_review.tools.report import principal_of

    jid = new_job_id()
    async with db_pool.connection() as conn, conn.transaction():
        await JobRepo(conn).create(job_id=jid, principal_key=principal_of(jid), surface="plugin", state="queued",
                                   requester_role="third_party_public_code", source_kind="files",
                                   source_args={}, has_deployment=False, chain="evm")
    return jid


def test_lead_row_maps_and_normalises():
    row = lead_row("job_X", LEADS[2])
    assert row is not None
    assert row[1] == "LEAD-0003" and row[2] == "analyzer" and row[9] == "High" and row[7] == "evm"
    assert lead_row("job_X", LEADS[3]) is None
    assert lead_row("job_X", {"id": "nope", "rule_id": "r", "category": "evm.x", "file": "f", "start": 1, "end": 1}) is None


def test_load_leads_json_accepts_both_shapes(tmp_path: Path):
    (tmp_path / "j1").mkdir()
    (tmp_path / "j1" / "leads.json").write_text(json.dumps(LEADS[:2]))
    (tmp_path / "j2").mkdir()
    (tmp_path / "j2" / "leads.json").write_text(json.dumps({"leads": LEADS[:1]}))
    assert len(load_leads_json(tmp_path, "j1")) == 2
    assert len(load_leads_json(tmp_path, "j2")) == 1
    assert load_leads_json(tmp_path, "missing") == []


async def test_persist_leads_inserts_open_rows_and_is_idempotent(db_pool):
    jid = await _job(db_pool)
    async with db_pool.connection() as conn, conn.transaction():
        n = await persist_leads(conn, jid, LEADS)
    assert n == 3
    async with db_pool.connection() as conn, conn.transaction():
        again = await persist_leads(conn, jid, LEADS)
        states = await lead_states(conn, jid)
    assert again == 0
    assert set(states) == {"LEAD-0001", "LEAD-0002", "LEAD-0003"}
    assert all(s["state"] == "open" for s in states.values())
    async with db_pool.connection() as conn:
        cur = await conn.execute("select severity_norm, sev_rank, category_family from leads where job_id = %s and lead_id = 'LEAD-0003'", (jid,))
        sev, rank, fam = await cur.fetchone()
    assert (sev, rank, fam) == ("High", 4, "evm")


async def test_persist_keeps_existing_state(db_pool):
    """A re-run before `ready` never resets a lead a reviewer already promoted or dismissed."""
    jid = await _job(db_pool)
    async with db_pool.connection() as conn, conn.transaction():
        await persist_leads(conn, jid, LEADS[:1])
        await conn.execute("update leads set state = 'dismissed', reason = 'fp_guarded' where job_id = %s", (jid,))
        await persist_leads(conn, jid, LEADS[:1])
        states = await lead_states(conn, jid)
    assert states["LEAD-0001"]["state"] == "dismissed"


async def test_persist_from_pin_reads_the_job_file(db_pool, tmp_path: Path):
    jid = await _job(db_pool)
    (tmp_path / jid).mkdir()
    (tmp_path / jid / "leads.json").write_text(json.dumps(LEADS))
    async with db_pool.connection() as conn, conn.transaction():
        assert await persist_leads_from_pin(conn, tmp_path, jid) == 3
        assert await persist_leads_from_pin(conn, tmp_path, "job_" + "Z" * 26) == 0
