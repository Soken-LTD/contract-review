"""Deterministic self-enrichment (MVP): turn analyzer MISSES in finalized reviews into
regression/eval corpus candidates, measured by the EXISTING recall harness.

There is no LLM and no training here. "Self-learning" means the system harvests what it
reviewed and turns analyzer misses into new corpus cases in the case.v1 format that
`soken-eval corpus check` validates and `scripts/eval_driver.py` scores. The pipeline is
three pure, separately testable steps:

  harvest(conn, job_id)  pull each accepted finding of a finalized job, joined to its current
                         revision, plus whether it has a linked analyzer lead in the SAME
                         category (the LEADKEYS join used by the re-rate script).
  gate(records, job)     consent gate. Only PUBLIC-code jobs pass; if consent is unknown the
                         records are dropped (fail-closed).
  distill(records)       keep only analyzer misses (a model-written finding, Medium or above,
                         with NO linked analyzer lead in its category) and emit them as
                         corpus case.v1 candidate dicts.

Default-off: nothing in the normal review path imports or calls this module. Run it
explicitly with `python -m soken_review.evals.enrich --job <job_id>`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .corpus import CHAIN_FAMILY, COMMIT

# Analyzer misses worth a regression case: Medium and above (Low/Informational are noise here).
_MISS_SEVERITIES: frozenset[str] = frozenset({"Critical", "High", "Medium"})
# A job whose reviewed code is public. The only requester role that is public by construction.
_PUBLIC_ROLE = "third_party_public_code"
# jobs.source_kind -> corpus input_mode (see corpus.INPUT_MODES).
_SOURCE_KIND_TO_MODE = {"deployed": "address", "repo": "repo", "files": "files", "upload": "upload"}


@dataclass(frozen=True)
class JobContext:
    """The finalized job a candidate is harvested from."""

    job_id: str
    chain: str | None
    chain_id: int | None
    family: str | None
    source_kind: str
    source_pin: str | None
    commit: str | None
    tier: str | None
    requester_role: str
    consent_public: bool

    @property
    def input_mode(self) -> str:
        return _SOURCE_KIND_TO_MODE.get(self.source_kind, "files")


@dataclass(frozen=True)
class HarvestRecord:
    """One accepted finding plus the facts needed to decide if it is an analyzer miss."""

    job: JobContext
    draft_key: str
    finding_no: int
    draft_origin: str  # 'model' or 'server_needs_text'
    severity: str | None
    category: str
    category_family: str
    has_linked_lead: bool  # a promoted analyzer lead in the SAME category links this finding
    locator: dict[str, Any] | None  # {"file": str, "start": int, "end": int}


# --------------------------------------------------------------------------------------------
# harvest
# --------------------------------------------------------------------------------------------

_JOB_SQL = """
select job_id, state, requester_role, source_kind, chain, chain_id, tier,
       resolved_commit, source_pin
from jobs where job_id = %s
"""

# Accepted findings joined to their current revision, with has_linked_lead computed by the same
# promoted-analyzer-lead-in-same-category join the re-rate script uses, and the location quote
# (finding_quote_ranges role='location') folded into a single locator object.
_DRAFTS_SQL = """
select d.draft_key, d.finding_no, d.origin as draft_origin, d.severity,
       r.category, r.category_family,
       exists (
         select 1 from finding_leads fl
         join leads l on l.job_id = d.job_id and l.lead_id = fl.lead_id
            and l.state = 'promoted' and l.state_ref = d.draft_key and l.origin = 'analyzer'
         where fl.job_id = d.job_id and fl.draft_key = d.draft_key and fl.revision = d.current_revision
           and l.category = r.category
       ) as has_linked_lead,
       (select jsonb_build_object('file', q.path, 'start', q.start_line, 'end', q.end_line)
          from finding_quote_ranges q
         where q.job_id = d.job_id and q.draft_key = d.draft_key and q.revision = d.current_revision
           and q.role = 'location'
         order by q.ord limit 1) as locator
from finding_drafts d
join finding_revisions r on r.job_id = d.job_id and r.draft_key = d.draft_key
                        and r.revision = d.current_revision
where d.job_id = %s and d.status in ('accepted', 'needs_challenge')
order by d.finding_no
"""


def _load_job(conn: Any, job_id: str) -> JobContext | None:
    from psycopg.rows import dict_row

    with conn.cursor(row_factory=dict_row) as cur:
        row = cur.execute(_JOB_SQL, (job_id,)).fetchone()
    if row is None:
        return None
    commit = row["resolved_commit"] if COMMIT.match(str(row["resolved_commit"] or "")) else None
    return JobContext(
        job_id=row["job_id"],
        chain=row["chain"],
        chain_id=row["chain_id"],
        family=CHAIN_FAMILY.get(str(row["chain"])),
        source_kind=row["source_kind"],
        source_pin=row["source_pin"],
        commit=commit,
        tier=row["tier"],
        requester_role=row["requester_role"],
        consent_public=row["requester_role"] == _PUBLIC_ROLE,
    )


def harvest(conn: Any, job_id: str) -> list[HarvestRecord]:
    """Pull accepted findings of a finalized job as raw records. Empty if the job is unknown."""
    from psycopg.rows import dict_row

    job = _load_job(conn, job_id)
    if job is None:
        return []
    with conn.cursor(row_factory=dict_row) as cur:
        rows = cur.execute(_DRAFTS_SQL, (job_id,)).fetchall()
    return [
        HarvestRecord(
            job=job,
            draft_key=r["draft_key"],
            finding_no=r["finding_no"],
            draft_origin=r["draft_origin"],
            severity=r["severity"],
            category=r["category"],
            category_family=r["category_family"],
            has_linked_lead=bool(r["has_linked_lead"]),
            locator=r["locator"],
        )
        for r in rows
    ]


# --------------------------------------------------------------------------------------------
# gate
# --------------------------------------------------------------------------------------------


def _job_is_public(job: JobContext | Mapping[str, Any]) -> bool:
    """Fail-closed consent check. True only on an explicit public signal.

    PUBLIC code (open source or on-chain verified source submitted for free review) may feed the
    corpus; client-private inputs never do. Anything we cannot positively confirm is dropped.
    """
    if isinstance(job, JobContext):
        return job.consent_public is True
    if not isinstance(job, Mapping):
        return False
    if job.get("consent_public") is True:
        return True
    return job.get("requester_role") == _PUBLIC_ROLE


def gate(records: list[HarvestRecord],
         job: JobContext | Mapping[str, Any] | None = None) -> list[HarvestRecord]:
    """Consent gate: keep a record only when its reviewed code is public; else drop it.

    With an explicit ``job`` the whole batch is gated against that one context (for a caller that
    already knows the batch is single-job). With ``job=None`` each record is gated against its OWN
    ``job`` context, so a mixed-job batch can never leak a private job's findings because some
    other record in the batch happened to be public. ``run`` uses the per-record form.
    """
    if job is None:
        return [r for r in records if _job_is_public(r.job)]
    return list(records) if _job_is_public(job) else []


# --------------------------------------------------------------------------------------------
# distill
# --------------------------------------------------------------------------------------------


def is_analyzer_miss(record: HarvestRecord, min_severities: frozenset[str] = _MISS_SEVERITIES) -> bool:
    """An analyzer miss: a model-written, Medium-or-above finding with a location and no linked
    analyzer lead in its category. These are exactly the cases the analyzer should have flagged."""
    return (
        record.draft_origin == "model"
        and not record.has_linked_lead
        and record.severity in min_severities
        and record.locator is not None
    )


def record_to_case(record: HarvestRecord) -> dict[str, Any]:
    """Render one analyzer-miss record as a corpus case.v1 dict (see evals/corpus.check_case)."""
    job = record.job
    loc = record.locator or {}
    source: dict[str, Any] = {
        "provider": "repo" if job.source_kind in ("repo", "upload") else None,
        "repo": None,
        "commit": job.commit,
        "subdir": None,
        "license": None,
        "dataset": None,
        "dataset_license": None,
        "pinned_by": "job.resolved_commit" if job.commit else "job.source_pin",
    }
    ground_truth = [
        {
            "gt_id": "GT-1",
            "title_ref": f"{record.draft_key} analyzer miss",
            "severity": record.severity,
            "category": record.category,
            "root_cause_lines": [{"file": loc["file"], "start": loc["start"], "end": loc["end"]}],
            "related_lines": [],
            "source_url": None,
            "min_match": "location_and_category",
            "exclude_chains": [],
        }
    ]
    origin_part = "own_audit"
    return {
        "case_id": f"{job.chain or 'x'}-{origin_part}-{record.finding_no:04d}",
        "chain": job.chain,
        "chain_id": job.chain_id,
        "split": "dev",
        "origin": origin_part,
        "source": source,
        "input_mode": job.input_mode,
        "run_as_chain": None,
        "provenance_tier_expected": job.tier,
        "expected_outcome": "report",
        "j_class": None,
        "ground_truth": ground_truth,
        "judged": False,
        "seeded": None,
        "rereview_of": None,
        "negatives_note": None,
        "consent": "not_needed",
        "created": dt.datetime.now(tz=dt.UTC).date(),
        "created_by": "enrich",
    }


def distill(records: list[HarvestRecord]) -> list[dict[str, Any]]:
    """Keep only analyzer misses and render each as a corpus case.v1 candidate dict."""
    return [record_to_case(r) for r in records if is_analyzer_miss(r)]


# --------------------------------------------------------------------------------------------
# persistence + CLI (default-off: only runs when invoked explicitly)
# --------------------------------------------------------------------------------------------

_INSERT_SQL = """
insert into enrichment_candidates (
  job_id, draft_key, chain, family, category, severity, source_pin,
  locator_file, locator_start, locator_end, why_missed, consent_public, case_json, status
) values (
  %(job_id)s, %(draft_key)s, %(chain)s, %(family)s, %(category)s, %(severity)s, %(source_pin)s,
  %(locator_file)s, %(locator_start)s, %(locator_end)s, 'analyzer_miss', %(consent_public)s,
  %(case_json)s, 'draft'
)
on conflict (job_id, draft_key) do nothing
"""


def _insert(conn: Any, record: HarvestRecord, case: dict[str, Any]) -> None:
    import json

    import psycopg

    loc = record.locator or {}
    with conn.cursor() as cur:
        cur.execute(
            _INSERT_SQL,
            {
                "job_id": record.job.job_id,
                "draft_key": record.draft_key,
                "chain": record.job.chain,
                "family": record.job.family or record.category_family,
                "category": record.category,
                "severity": record.severity,
                "source_pin": record.job.source_pin,
                "locator_file": loc["file"],
                "locator_start": loc["start"],
                "locator_end": loc["end"],
                "consent_public": record.job.consent_public,
                # case_json carries a JSON-serialisable copy (dates to ISO strings).
                "case_json": psycopg.types.json.Jsonb(json.loads(json.dumps(case, default=str))),
            },
        )


def run(conn: Any, job_id: str, *, dry_run: bool = False) -> list[dict[str, Any]]:
    """harvest -> gate -> distill, inserting draft rows (unless dry_run). Returns the candidates."""
    records = harvest(conn, job_id)
    if not records:
        return []
    # Per-record consent (job=None): gate each record against its own job context rather than
    # trusting records[0] to represent the batch, so the gate holds even if harvest is ever
    # changed to return records from more than one job.
    gated = gate(records)
    kept = [r for r in gated if is_analyzer_miss(r)]
    cases: list[dict[str, Any]] = []
    for record in kept:
        case = record_to_case(record)
        cases.append(case)
        if not dry_run:
            _insert(conn, record, case)
    if not dry_run:
        conn.commit()
    return cases


def main(argv: list[str] | None = None) -> int:
    import psycopg

    parser = argparse.ArgumentParser(prog="soken-enrich", description=__doc__)
    parser.add_argument("--job", required=True, help="finalized job_id to harvest")
    parser.add_argument("--dsn", default=os.environ.get("SOKEN_DATABASE_URL"),
                        help="Postgres DSN (default: SOKEN_DATABASE_URL)")
    parser.add_argument("--dry-run", action="store_true", help="harvest and distill, insert nothing")
    args = parser.parse_args(argv)
    if not args.dsn:
        print("no DSN: pass --dsn or set SOKEN_DATABASE_URL", file=sys.stderr)
        return 2
    with psycopg.connect(args.dsn, autocommit=False) as conn:
        cases = run(conn, args.job, dry_run=args.dry_run)
    verb = "would insert" if args.dry_run else "inserted"
    print(f"{args.job}: {verb} {len(cases)} analyzer-miss candidate(s)")
    for case in cases:
        gt = case["ground_truth"][0]
        print(f"  {case['case_id']}: {gt['severity']} {gt['category']} "
              f"{gt['root_cause_lines'][0]['file']}:{gt['root_cause_lines'][0]['start']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
