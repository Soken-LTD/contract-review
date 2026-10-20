"""DB-backed end-to-end for deterministic self-enrichment (evals/enrich.py).

harvest() reads Postgres (the join over finding_drafts / finding_revisions / finding_leads /
leads / finding_quote_ranges) and is not covered by the pure-function tests in test_enrich.py.
These tests exercise it, plus run() and migration 005, against a real Postgres 16 via the shared
`pg_dsn` fixture (Docker, or SOKEN_TEST_PG_DSN for an existing empty database).

Each test uses a unique job_id and removes its own rows afterwards, so the session database is
left as it was found.
"""

from __future__ import annotations

import psycopg
import pytest

from soken_review.db.job_repo import new_job_id
from soken_review.evals import enrich

pytestmark = pytest.mark.usefixtures("pg_dsn")


def _seed_finalized_model_finding(conn: psycopg.Connection, job_id: str, requester_role: str) -> None:
    """A finalized job with one accepted model finding, no linked analyzer lead (an analyzer
    miss), and a location quote. requester_role drives consent (third_party_public_code = public)."""
    with conn.cursor() as cur:
        cur.execute(
            """insert into jobs (job_id, principal_key, surface, state, requester_role, source_kind,
               chain, chain_id, source_args, has_deployment, tier, source_pin, guide_version,
               rubric_version) values (%s,'p','connector','finalized',%s,'deployed','evm',1,
               '{}'::jsonb,true,'B',
               '90e22f845616250afc3f848c039e3c71911aabf325f351382567f68e659c993d','g','r')""",
            (job_id, requester_role),
        )
        cur.execute(
            """insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
               current_revision, severity) values (%s,'reentrancy-in-withdraw',1,'model','accepted',1,'High')""",
            (job_id,),
        )
        cur.execute(
            """insert into finding_revisions (job_id, draft_key, revision, content, content_hash,
               category, category_family, impact_class, computed_severity, severity_rule)
               values (%s,'reentrancy-in-withdraw',1,'{}'::jsonb,'h','evm.reentrancy','evm',
               'theft_of_funds','High','R1')""",
            (job_id,),
        )
        cur.execute(
            """insert into finding_quote_ranges (job_id, draft_key, revision, ord, role, path,
               start_line, end_line) values (%s,'reentrancy-in-withdraw',1,0,'location','Vault.sol',120,134)""",
            (job_id,),
        )
    conn.commit()


def _cleanup(conn: psycopg.Connection, job_id: str) -> None:
    with conn.cursor() as cur:
        for table in ("enrichment_candidates", "finding_quote_ranges", "finding_revisions",
                      "finding_drafts", "jobs"):
            cur.execute(f"delete from {table} where job_id = %s", (job_id,))
    conn.commit()


def test_harvest_and_distill_public_finding(pg_dsn):
    job_id = new_job_id()
    with psycopg.connect(pg_dsn) as conn:
        try:
            _seed_finalized_model_finding(conn, job_id, "third_party_public_code")

            records = enrich.harvest(conn, job_id)
            assert len(records) == 1
            r = records[0]
            assert r.draft_origin == "model" and r.severity == "High"
            assert r.category == "evm.reentrancy" and r.has_linked_lead is False
            assert r.locator == {"file": "Vault.sol", "start": 120, "end": 134}
            assert r.job.consent_public is True

            cases = enrich.run(conn, job_id, dry_run=True)
            assert len(cases) == 1
            assert cases[0]["consent"] == "not_needed"  # harvested public case needs no re-consent
            assert cases[0]["input_mode"] == "address"  # deployed source_kind -> address mode

            # dry_run=False inserts into enrichment_candidates (commits internally).
            enrich.run(conn, job_id, dry_run=False)
            with conn.cursor() as cur:
                cur.execute(
                    "select category, severity, why_missed, consent_public from enrichment_candidates where job_id=%s",
                    (job_id,),
                )
                rows = cur.fetchall()
            assert rows == [("evm.reentrancy", "High", "analyzer_miss", True)]
        finally:
            _cleanup(conn, job_id)


def test_private_finding_is_consent_gated(pg_dsn):
    job_id = new_job_id()
    with psycopg.connect(pg_dsn) as conn:
        try:
            _seed_finalized_model_finding(conn, job_id, "owner")  # private client code

            records = enrich.harvest(conn, job_id)
            assert len(records) == 1 and records[0].job.consent_public is False

            # The consent gate must drop it: no candidate, nothing written to the corpus table.
            assert enrich.run(conn, job_id, dry_run=False) == []
            with conn.cursor() as cur:
                cur.execute("select count(*) from enrichment_candidates where job_id=%s", (job_id,))
                assert cur.fetchone()[0] == 0
        finally:
            _cleanup(conn, job_id)
