-- Migration 019: review_verify_on_fork (fork verification of a finding, chain access design 1.7, P4 on EVM).
-- job_steps gains the `verify_fork` step: one container run of a reviewer's Foundry test against a local
-- fork of chain state, reached only through the read-only chain proxy. The worker claims one such step
-- at a time (job_repo.claim_step); the rest stay queued.
-- fork_runs: one row per requested run. The test source is kept with the run (the owner profile of the
-- report prints it); `result` is written by the supervisor only. Deleted with the job. A run counts as
-- evidence only for the draft revision it was queued against (engine/fork_evidence.py).
do $$
declare c text;
begin
  select conname into c
    from pg_constraint
   where conrelid = 'job_steps'::regclass and contype = 'c'
     and pg_get_constraintdef(oid) like '%chain_state%';
  if c is not null then
    execute format('alter table job_steps drop constraint %I', c);
  end if;
  alter table job_steps add constraint job_steps_step_check
    check (step in ('chain_state','fetch','deps','build','map','analyze','verify','render','proof','purge',
                    'context','verify_fork'));
end $$;

create table if not exists fork_runs (
  run_id       text primary key check (run_id ~ '^fork-[0-9a-f]{12}$'),
  job_id       text not null references jobs on delete cascade,
  step_id      bigint references job_steps(id) on delete set null,
  draft_key    text,
  draft_revision int,                          -- the draft's current_revision when the run was queued
  status       text not null default 'queued'
               check (status in ('queued','running','passed','failed','error','timeout')),
  chain_id     bigint not null,
  network      text not null,
  block        bigint not null check (block >= 0),
  test_path    text not null,
  test_sha256  text not null check (test_sha256 ~ '^[0-9a-f]{64}$'),
  test_source  text not null,
  expect       text not null default 'pass' check (expect in ('pass','fail')),
  result       jsonb,
  created_at   timestamptz not null default now(),
  started_at   timestamptz,
  finished_at  timestamptz
);
create index if not exists fork_runs_job on fork_runs (job_id, created_at);
create index if not exists fork_runs_step on fork_runs (step_id);
