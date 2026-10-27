"""A repo job whose build failed (1inch farming, matrix run 2026-10-27, job_536H8JDV9PQ5NY4EXCA6GQWG17):
the assembled cover states the failure in one sentence (compiler, error class, consequence), the
network line is a scope statement, the source pin is labelled as the sha256 it is, and review_status
carries the same sentence before the reviewer submits anything."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from psycopg.types.json import Jsonb

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.mapping.facts import write_facts
from soken_review.pinning.store import PinnedSource
from soken_review.report.assemble import NO_DEPLOYMENT_LABEL, _network_label, assemble_report
from soken_review.report.kit.build import build, kit_texts
from soken_review.tools import report as report_tool

from .test_render_flow import CODE

ASYNC = pytest.mark.asyncio(loop_scope="session")
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "matrix_2026_10_27"
COMMIT = "bbb8b0db45dfb4ae0be860fef3ca4df9a761845f"
REPO = "https://github.com/1inch/farming"
SENTENCE = ("The source did not compile with solc 0.8.0 (parser error). No contract map was built and the "
            "analyzers did not run, so the findings rest on the session reading the source alone.")
ONEINCH_JOB = {"job_id": "job_536H8JDV9PQ5NY4EXCA6GQWG17", "source_kind": "repo", "chain": None, "chain_id": None,
               "address": None, "has_deployment": False, "tier": "B", "resolved_commit": COMMIT,
               "source_args": {"kind": "repo", "commit": COMMIT, "subdir": "contracts", "repo_url": REPO},
               "map_status": "failed", "analyzer_degraded": True}


def test_network_label_of_the_real_oneinch_job_row_is_a_scope_statement():
    assert _network_label(ONEINCH_JOB, None, None) == NO_DEPLOYMENT_LABEL
    assert "Not deployed" not in NO_DEPLOYMENT_LABEL and len(NO_DEPLOYMENT_LABEL) <= 60


async def _failed_build_job(db_pool, tmp_path: Path) -> tuple[str, Path]:
    jid = new_job_id()
    pin_root = tmp_path / "pins"
    pin = PinnedSource.from_files({"contracts/FarmingPod.sol": CODE.encode()},
                                  langs={"contracts/FarmingPod.sol": "solidity"})
    pin.persist(pin_root, jid)
    (pin_root / jid / "leads.json").write_text("[]")
    map_dir = pin_root / jid / "map"
    map_dir.mkdir(parents=True)
    (map_dir / "status.json").write_text((FIX / "oneinch.map_status.json").read_text(encoding="utf-8"))
    write_facts(pin_root, jid, [{"key": "compiler.version", "value": "0.8.0", "unit": None, "tags": [],
                                 "source": "candidate"},
                                {"key": "source.nsloc", "value": "624", "unit": "lines", "tags": [], "source": "pin"}])
    work = tmp_path / "work" / jid
    work.mkdir(parents=True)
    (work / "candidates.json").write_text(json.dumps([{"provider": "repo", "entry_contract": None,
                                                       "compiler": {"version": "0.8.0", "version_pinned_by": "pragma_guess"},
                                                       "explorer_verified": False, "sourcify_match": None}]))
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(job_id=jid, principal_key=report_tool.principal_of(jid), surface="plugin", state="queued",
                          requester_role="third_party_public_code", source_kind="repo",
                          source_args=ONEINCH_JOB["source_args"], has_deployment=False)
        rid = hashlib.sha256(jid.encode()).hexdigest()
        rid = "".join("abcdefghijklmnopqrstuvwxyz234567"[int(c, 16) * 2] for c in rid[:26])
        await conn.execute("""update jobs set state = 'finalized', tier = 'B', report_id = %s, source_pin = %s,
                              resolved_commit = %s, map_status = 'failed', analyzer_degraded = true where job_id = %s""",
                           (rid, pin.source_pin, COMMIT, jid))
        content = {"title": "Reward tokens stay registered for the life of the pod",
                   "body": {"description": [{"p": "The `addRewardsToken` function appends and never removes."}],
                            "impact": [{"p": "A paused reward token blocks the aggregate claim."}],
                            "recommendation": [{"p": "Add a removal path guarded by the owner."}]}}
        await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
            current_revision, severity, evidence_level, final_id, caps_applied) values
            (%s,'reward-tokens-permanent',1,'model','accepted',1,'Low','reasoning_only','L-001', %s)""", (jid, ["K6"]))
        await conn.execute("""insert into finding_revisions (job_id, draft_key, revision, content, content_hash,
            category, category_family, impact_class, computed_severity, severity_rule, map_unavailable)
            values (%s,'reward-tokens-permanent',1,%s,'h','evm.dos','evm','temporary_freeze','Low','I1xL2=Low',true)""",
            (jid, Jsonb(content)))
        await conn.execute("insert into finding_quote_ranges values (%s,'reward-tokens-permanent',1,0,'location',"
                           "'contracts/FarmingPod.sol',5,8)", (jid,))
    return jid, pin_root


@ASYNC
async def test_failed_build_is_one_sentence_on_the_cover_the_summary_and_the_method_table(db_pool, tmp_path):
    jid, pin_root = await _failed_build_job(db_pool, tmp_path)
    async with db_pool.connection() as conn:
        report, _extras = await assemble_report(conn, jid, pin_root)
    meta = report["meta"]
    assert meta["build_failure"] == SENTENCE
    assert meta["network"] == NO_DEPLOYMENT_LABEL
    assert meta["source_id_label"] == "Files sha256" and meta["provenance"]["commit"] == COMMIT
    assert meta["provenance"]["label_key"] == "tier_b_commit"
    analyzer_row = next(m for m in report["method"] if m["step"] == kit_texts()["method_steps"]["analyzer"])
    assert analyzer_row["detail"] == SENTENCE
    assert report["findings"][0]["no_map_line"] is True
    html = build(report, tmp_path / "out", mode="print").html_path.read_text(encoding="utf-8")
    assert html.count(SENTENCE) >= 2 and NO_DEPLOYMENT_LABEL in html
    pin = report["meta"]["provenance"]["source_hash"]
    assert "Not deployed" not in html and not re.search(rf"Commit\s*<span[^>]*>{pin[:12]}", html)
    assert re.search(rf"Files sha256\s*<span[^>]*>{pin[:12]}", html)
    assert kit_texts()["no_map_card_line"] in html


@ASYNC
async def test_review_status_carries_the_same_sentence_before_any_submit(db_pool, tmp_path):
    from soken_review.tools import read as read_mod
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.start_status import _build_status_response

    jid, pin_root = await _failed_build_job(db_pool, tmp_path)
    read_mod.set_context(MemoryJobContext(pin_root))
    async with db_pool.connection() as conn:
        job = await JobRepo(conn).get(jid)
    job = dict(job)
    job["state"] = "ready"
    for fmt in ("concise", "detailed"):
        out = _build_status_response(job, fmt)
        assert out["map_status"] == "failed" and out["build_failure"] == SENTENCE
    ok = _build_status_response({**job, "map_status": "full", "analyzer_degraded": False}, "concise")
    assert "build_failure" not in ok
