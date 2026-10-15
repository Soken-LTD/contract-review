-- Soken Contract Review, ops tables owned by plan-v4 part 09 (M3).
-- jobs, file, finding, analyzer leads and upload tables: 03.
-- job_events: 01. reports: 08. ownership_proofs: 04.
-- Object keys use job_sha = sha256(job_id)[:24], computed; 09 adds no column to jobs.

create table job_steps (
  id            bigserial primary key,
  job_id        text not null references jobs(job_id) on delete cascade,
  step          text not null check (step in ('chain_state','fetch','deps','build','map','analyze',
                                              'verify','render','proof','purge')),
  seq           smallint not null default 0,   -- analyzer order; chain_state 0 = pin, 1 = post-map plan
  tool          text,                          -- analyzer name on analyze rows
  status        text not null default 'queued'
                check (status in ('queued','running','done','failed','timeout','oom','cancelled')),
  cancel_reason text check (cancel_reason in ('user_delete','budget','host_lost')),
  container     boolean not null,              -- false: supervisor-only row (chain_state, proof, purge, address fetch)
  units         smallint not null,
  ram_mb        int not null,
  priority      smallint not null default 100, -- render 50, purge 200
  affinity      text,                          -- worker host owning the job dir; null = any
  attempt       smallint not null default 0,
  max_attempts  smallint not null,
  not_before    timestamptz not null default now(),
  lease_owner   text,
  lease_until   timestamptz,
  enqueued_at   timestamptz not null default now(),
  started_at    timestamptz,
  finished_at   timestamptz,
  exit_code     int,
  error_code    text,                          -- contract/errors.yaml code only
  provenance    jsonb,                         -- written by the supervisor only (09 3.5)
  check (status <> 'cancelled' or cancel_reason is not null)
);
create index job_steps_ready on job_steps (priority, enqueued_at) where status = 'queued';

create table sandbox_runs (
  id            bigserial primary key,
  step_id       bigint not null references job_steps(id) on delete cascade,
  image_digest  text not null,
  cpu_ms bigint, max_rss_mb int, disk_mb int, wall_ms int, exit_code int,
  killed_by     text check (killed_by in ('timeout','oom','pids','disk'))
);

create table worker_hosts (
  name text primary key, units_total smallint not null, ram_mb_total int not null,
  last_seen timestamptz not null                -- heartbeat every 15 s
);

-- inputs: closed set; any other field, or an unknown value, means the step runs uncached.
-- source_tree_hash (files the step reads), chain, chain_id, subdir, scope_hash, remappings_hash,
-- compiler_settings, analyzer {name, rule_pack_version, config_sha256}, image_digest,
-- cache snapshot ids (solc_sha256, npm_snapshot_sha256, advisory_db_commit, cargo_snapshot_sha256, vendor_hash).
-- verify results are never cached.
create table build_cache (
  cache_key        text primary key,           -- sha256 of RFC 8785 canonical JSON of inputs
  source_tree_hash text not null,
  inputs           jsonb not null,
  provenance       jsonb not null,             -- supervisor-written, copied to the job on a hit
  expires_at       timestamptz not null        -- created + 30 days, never extended
);
create index build_cache_tree on build_cache (source_tree_hash);

-- Outbound politeness buckets only (limits.yaml outbound, key out:s:<provider>[:<host>]); no usage quota tables (D-LIMITS).
create unlogged table rate_buckets (key text primary key check (key like 'out:s:%'),
  tokens real not null, updated_at timestamptz not null);
create table flags (key text primary key, value jsonb not null, updated_by text not null,
  updated_at timestamptz not null default now());

create table report_tombstones (               -- append-only; no UPDATE grant; DELETE only by sched_rw retention
  id         bigserial primary key,
  kind       text not null check (kind in ('report','job')),
  ref_hash   char(64) not null,                -- sha256(report_id or job_id); raw ids never stored
  pdf_sha256 char(64),                         -- report rows: sha256 of the served PDF bytes
  reason     text not null check (reason in ('withdrawn','owner_delete','owner_takedown','user_delete','expiry')),
  ts         timestamptz not null default now()
);
create index tomb_ref on report_tombstones (ref_hash);
create index tomb_pdf on report_tombstones (pdf_sha256);

create table admin_audit (
  id bigserial primary key, actor text not null, action text not null,
  target text check (target is null or target ~ '^(job|report|flag|host):[0-9a-z_.:-]{1,64}$'),
  ts timestamptz not null default now()        -- job and report targets as sha256(id)[:12]
);

-- Notifications: one channel per consumer kind.
create function notify_job_changed() returns trigger language plpgsql as $$
begin
  perform pg_notify('job_changed', substr(encode(sha256(convert_to(new.job_id,'UTF8')),'hex'),1,12));
  return new;
end $$;
create trigger jobs_state_notify after update of state on jobs
  for each row when (old.state is distinct from new.state) execute function notify_job_changed();
create trigger steps_notify after insert or update of status on job_steps
  for each row execute function notify_job_changed();
create function notify_steps_ready() returns trigger language plpgsql as $$
begin
  if new.status = 'queued' then perform pg_notify('steps_ready', coalesce(new.affinity,'')); end if;
  return new;
end $$;
create trigger steps_ready_notify after insert or update of status on job_steps
  for each row execute function notify_steps_ready();

-- Claim (09 3.3). $1 host, $2 free units, $3 lease s, $4 free RAM MiB,
-- $5 / $6 units and RAM the step class may use when idle (render 7 / 14336, other 6 / 12288),
-- $7 true for query A (render), false for query B. Query B passes free units - 1 and RAM - 2048
-- while no render row runs on the host. purge and proof rows run in their own supervisor loop.
update job_steps s
set status='running', lease_owner=$1, lease_until=now()+make_interval(secs => $3),
    started_at=now(), attempt=attempt+1
where s.id = (
  select q.id from job_steps q
  where q.status='queued' and q.not_before <= now()
    and (q.affinity is null or q.affinity = $1)
    and ((q.step = 'render') = $7) and q.step not in ('purge','proof')
    and q.units <= $2 and q.ram_mb <= $4
    and not exists (                                  -- head-of-line reservation, same class
      select 1 from job_steps h
      where h.status='queued' and h.not_before <= now()
        and (h.affinity is null or h.affinity = $1)
        and ((h.step = 'render') = $7) and h.step not in ('purge','proof')
        and h.enqueued_at < now() - interval '120 seconds'
        and (h.units > $2 or h.ram_mb > $4) and h.units <= $5 and h.ram_mb <= $6
        and (h.priority, h.enqueued_at) < (q.priority, q.enqueued_at))
    and not exists (                                  -- serial order inside a job
      select 1 from job_steps p
      where p.job_id = q.job_id and p.id <> q.id and p.status in ('queued','running')
        and p.step <> 'render' and q.step <> 'render' and p.enqueued_at < q.enqueued_at)
  order by q.priority, q.enqueued_at
  for update skip locked limit 1)
returning s.*;
