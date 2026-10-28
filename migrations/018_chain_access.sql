-- Migration 018: chain access P0 (chain access design 2026-10-27, sections 2.2 and 4).
-- Numbered after 016 (learning ledger, PR #94) and 017 (gate warnings, never-worse branch).
-- chain_cache: public chain data at a final block, shared across jobs only once two distinct hosts
--   agreed (or an operator-configured host answered). No job id, no quota key: the key is sha256 of
--   (family, chain, method, params) and the value is the provider's answer.
-- chain_job_ru: read units a job has spent (deleted with the job, like every job_id table).
-- chain_key_ru: read units per quota key (the hashed key of quota.py) on a rolling 24 hours; no job
--   id, so deleting a job does not refund the key, the same rule as the report quota.
create table if not exists chain_cache (
  key            text primary key check (key ~ '^[0-9a-f]{64}$'),
  result         jsonb not null,
  result_hash    text not null check (result_hash ~ '^[0-9a-f]{64}$'),
  host           text not null,               -- redacted host (scheme://host) that answered first
  trusted        boolean not null default false,  -- the host is an operator-configured endpoint
  confirmed_host text,                        -- a second, different host gave the same answer
  created_at     timestamptz not null default now()
);
-- Served to other jobs only when trusted or confirmed (security review 2026-10-28: one lying free
-- endpoint must not poison every later job); entries expire (chain_access.shared_cache_days).

create table if not exists chain_job_ru (
  job_id     text primary key references jobs on delete cascade,
  ru_used    int not null default 0 check (ru_used >= 0),
  updated_at timestamptz not null default now()
);

create table if not exists chain_key_ru (
  id        bigserial primary key,
  limit_key text not null,
  ru        int not null,
  at        timestamptz not null default now()
);
create index if not exists chain_key_ru_key_at on chain_key_ru (limit_key, at);
