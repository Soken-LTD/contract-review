"""Assembly of a tier A TON job against Postgres (matrix run 2026-10-26, job built before the
deployment.json fix): provenance.json only, TON chain_state, no EVM chain id. The report validates
with chain `ton`, a seqno cover label and the code cell hash."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from psycopg.types.json import Jsonb

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.pinning.store import PinnedSource
from soken_review.report.assemble import assemble_report
from soken_review.tools import report as report_tool

ASYNC = pytest.mark.asyncio(loop_scope="session")

HASH = "c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea"
RAW = "0:2f26e1259f494ff1cd98319e2c286c1046dfe49b1982e3de2ff18e134c780e6a"
FRIENDLY = "EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ"
TACT = """import "@stdlib/deploy";
contract FtMaster with Deployable {
    owner: Address;
    init(owner: Address) {
        self.owner = owner;
    }
    receive("withdraw") {
        send(SendParameters{to: self.owner, value: 0, mode: SendRemainingBalance});
    }
}
"""


async def _ton_job(db_pool, tmp_path: Path, *, legacy_provenance_only: bool) -> tuple[str, Path]:
    jid = new_job_id()
    pin_root = tmp_path / "pins"
    path = "contract/contracts/ft_master.tact"
    pin = PinnedSource.from_files({path: TACT.encode()}, langs={path: "tact"})
    pin.persist(pin_root, jid)
    (pin_root / jid / "leads.json").write_text("[]")
    work = tmp_path / "work" / jid
    work.mkdir(parents=True)
    cand = {"provider": "ton_verifier", "sha256": "49" * 32, "language": "tact",
            "compiler": {"version": "1.6.5", "version_pinned_by": "ton_verifier"}, "entry_contract": path,
            "files": [path], "explorer_verified": True}
    (work / "candidates.json").write_text(json.dumps([cand]))
    (work / "chain_state.json").write_text(json.dumps({"mc_seqno": 101445617, "accounts": {
        RAW: {"status": "active", "balance": "1", "code_hash": HASH, "dep_hash": HASH, "code_boc": "b5ee9c72"}}}))
    prov = {"src": 0, "match": "exact", "reason": "MATCH_REBUILD", "tier": "A", "why": None, "dep_hash": HASH,
            "build_hash": HASH, "matched_target": "contract_FtMaster", "tried": [], "checks": [],
            "mc_seqno": 101445617, "address": RAW}
    (work / "provenance.json").write_text(json.dumps(prov))
    if not legacy_provenance_only:
        from soken_review.adapters.ton.provenance import deployment_doc

        (work / "deployment.json").write_text(json.dumps(deployment_doc(prov, cand, FRIENDLY)))
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(job_id=jid, principal_key=report_tool.principal_of(jid), surface="plugin", state="queued",
                          requester_role="third_party_public_code", source_kind="deployed",
                          source_args={"kind": "deployed", "chain": "ton", "address": FRIENDLY},
                          has_deployment=True, chain="ton", chain_id=None, address=FRIENDLY)
        rid = hashlib.sha256(jid.encode()).hexdigest()
        rid = "".join("abcdefghijklmnopqrstuvwxyz234567"[int(c, 16) * 2] for c in rid[:26])
        await conn.execute("update jobs set state = 'finalized', tier = 'A', code_hash = %s, report_id = %s,"
                           " source_pin = %s where job_id = %s", (HASH, rid, pin.source_pin, jid))
        content = {"title": "CreateSquad forwards the whole master balance to a squad owner the caller chooses",
                   "body": {"description": [{"p": "The `withdraw` receiver sends the remaining balance."}],
                            "impact": [{"p": "Any stranded value leaves with the next call."}],
                            "recommendation": [{"p": "Reserve the storage fee first."}]}}
        await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
            current_revision, severity, evidence_level, final_id) values (%s,'create-squad-sweeps-balance',1,'model','accepted',1,'Medium',
            'reasoning_challenged','M-001')""", (jid,))
        await conn.execute("""insert into finding_revisions (job_id, draft_key, revision, content, content_hash,
            category, category_family, impact_class, computed_severity, severity_rule)
            values (%s,'create-squad-sweeps-balance',1,%s,'h','ton.send_mode','ton','theft_of_funds','Medium','S1')""", (jid, Jsonb(content)))
        await conn.execute("insert into finding_quote_ranges values (%s,'create-squad-sweeps-balance',1,0,'location',%s,7,9)", (jid, path))
    return jid, pin_root


@ASYNC
@pytest.mark.parametrize("legacy", [True, False], ids=["provenance_json_only", "deployment_json"])
async def test_ton_tier_a_assembles_from_recorded_provenance(db_pool, tmp_path, legacy):
    jid, pin_root = await _ton_job(db_pool, tmp_path, legacy_provenance_only=legacy)
    async with db_pool.connection() as conn:
        report, _extras = await assemble_report(conn, jid, pin_root)
    meta = report["meta"]
    assert meta["chain"] == "ton" and meta["network"] == "TON mainnet" and meta["chain_id"] is None
    prov = meta["provenance"]
    assert prov["tier"] == "A" and prov["label_key"] == "tier_a"
    assert prov["code_hash"] == HASH and prov["address"] == FRIENDLY
    assert prov["as_of"]["block_or_slot"] == 101445617 and "seqno 101445617" in prov["label"]
    kpi = {k["key"]: k["value"] for k in report["summary"]["kpis"]}
    assert kpi["deployed_code"] == "Matched"
    assert report["verification"][0]["table"]["rows"][0] == ["Address", {"addr": FRIENDLY}]
    assert any(a["area_id"].startswith("ton.") for a in report["review_coverage"]["areas"])
