-- Migration 005: self-enrichment candidates (deterministic, default-off).
-- Holds corpus candidates DISTILLED from finalized reviews: an accepted, model-written
-- finding that had NO linked analyzer lead in its category is an "analyzer_miss" and becomes
-- a regression/eval candidate, scored later by the existing recall harness. No LLM, no
-- training. Only PUBLIC-code jobs may feed this table (consent gate lives in the code path,
-- consent_public records the decision for audit). Nothing in the normal review path writes
-- here; rows are inserted only when soken_review.evals.enrich is invoked explicitly.

create table if not exists enrichment_candidates (
  id             bigserial primary key,
  job_id         text not null references jobs on delete cascade,
  draft_key      text not null,
  chain          text,
  family         text not null,
  category       text not null,
  severity       text not null check (severity in ('Critical','High','Medium','Low','Informational')),
  source_pin     text,
  locator_file   text not null,
  locator_start  int not null,
  locator_end    int not null,
  why_missed     text not null default 'analyzer_miss' check (why_missed in ('analyzer_miss')),
  consent_public boolean not null,
  case_json      jsonb not null,
  status         text not null default 'draft' check (status in ('draft','accepted','rejected','promoted')),
  created_at     timestamptz not null default now(),
  check (locator_start >= 1 and locator_end >= locator_start),
  unique (job_id, draft_key)
);
create index if not exists enrichment_candidates_status on enrichment_candidates (status, created_at);
