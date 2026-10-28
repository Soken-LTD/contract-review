-- Migration 016: advisory gates (never-worse, CEO direction 2026-10-27 section A).
--
-- gate_warnings keeps the advisory items of every accepted write (submit, set_section, answer_challenge,
-- finalize): rule id, matched text and the suggested rewording, as data for the learning loop. They never
-- reach the report text. jobs.coverage_gaps holds what finalize found not covered (advisory finalize checks
-- with their counts); the report prints the coverage note from it.
-- Additive: no existing row changes.
create table if not exists gate_warnings (
  id bigserial primary key,
  job_id text not null references jobs on delete cascade,
  tool text not null,
  owner_key text not null,
  revision int,
  warnings jsonb not null,
  created_at timestamptz not null default now()
);
create index if not exists gate_warnings_job on gate_warnings (job_id);

alter table jobs add column if not exists coverage_gaps jsonb;
