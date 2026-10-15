-- Migration 001: core job tables (plan-v4 part 03, section 3.6)
-- Postgres 16. Applied before 002_ops.sql (which adds ops tables and notify triggers).

create table jobs (
  job_id            text primary key check (job_id ~ '^job_[0-9A-HJKMNP-TV-Z]{26}$'),
  principal_key     text not null,
  surface           text not null check (surface in ('plugin','connector')),
  state             text not null check (state in ('awaiting_upload','queued','fetching','building',
                      'analyzing','ready','finalized','render_queued','rendering','rendered',
                      'render_failed','insufficient_source','failed','expired','deleted')),
  requester_role    text not null check (requester_role in ('owner','authorized','third_party_public_code')),
  source_kind       text not null check (source_kind in ('deployed','repo','files','upload')),
  chain             text,
  chain_id          bigint,
  address           text,
  source_args       jsonb not null,
  has_deployment    boolean not null,
  previous_report_id text,
  previous_snapshot jsonb,
  upload_id         text unique,
  upload_sha256     text check (upload_sha256 ~ '^[0-9a-f]{64}$'),
  tier              char(1) check (tier in ('A','B','C','D')),
  resolved_commit   text check (resolved_commit ~ '^[0-9a-f]{40}$'),
  code_hash         text,
  source_pin        text,
  guide_version     text not null,
  rubric_version    text not null,
  map_status        text not null default 'none' check (map_status in ('none','full','partial','failed')),
  analyzer_degraded boolean not null default false,
  ownership_proven  boolean not null default false,
  next_finding_no   int not null default 1,
  last_call_at      timestamptz not null default now(),
  error_code        text,
  error_detail      jsonb,
  report_id         text unique,
  created_at        timestamptz not null default now(),
  finalized_at      timestamptz,
  expires_at        timestamptz
);
create index jobs_open on jobs (state, last_call_at);

create table job_files (
  job_id text not null references jobs on delete cascade,
  path text not null, sha256_raw text not null, sha256_lf text not null,
  lines int not null, nsloc int not null, lang text,
  role text not null check (role in ('source','dependency','test','doc')),
  user_supplied boolean not null default false,
  in_scope boolean not null,
  excluded_reason text check (excluded_reason in ('scope_exclude','scope_include','size_limit',
                   'tier_d','invalid_utf8','test_path','vendored','dependency')),
  primary key (job_id, path)
);

create table finding_drafts (
  job_id           text not null references jobs on delete cascade,
  draft_key        text not null check (draft_key ~ '^[a-z0-9][a-z0-9-]{2,47}$'),
  finding_no       int not null,
  origin           text not null check (origin in ('model','server_needs_text')),
  status           text not null check (status in ('needs_text','needs_challenge','accepted','withdrawn')),
  current_revision int not null,
  rejected_count   int not null default 0,
  severity         text check (severity in ('Critical','High','Medium','Low','Informational')),
  matrix_effective jsonb,
  evidence_level   text check (evidence_level in ('analyzer_and_reasoning','reasoning_challenged','reasoning_only')),
  carried_from     text,
  withdrawn_by     text check (withdrawn_by in ('model','challenge')),
  withdrawn_reason text check (withdrawn_reason in ('disproved','merged_into')),
  withdraw_evidence jsonb,
  kill_item        text,
  final_id         text check (final_id ~ '^[CHMLI]-[0-9]{3}$'),
  primary key (job_id, draft_key),
  unique (job_id, finding_no),
  unique (job_id, final_id)
);

create table finding_revisions (
  job_id text not null, draft_key text not null, revision int not null,
  content jsonb not null, content_hash text not null,
  category text not null, category_family text not null, impact_class text not null,
  computed_severity text not null, severity_rule text not null,
  caps_applied text[] not null default '{}', map_unavailable boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (job_id, draft_key, revision),
  foreign key (job_id, draft_key) references finding_drafts on delete cascade
);

create table finding_quote_ranges (
  job_id text not null, draft_key text not null, revision int not null, ord smallint not null,
  role text not null check (role in ('location','bound_ref','role_path','context','documented_intent')),
  path text not null, start_line int not null, end_line int not null,
  primary key (job_id, draft_key, revision, ord),
  foreign key (job_id, draft_key, revision) references finding_revisions on delete cascade
);

create table finding_leads (
  job_id text not null, draft_key text not null, revision int not null, lead_id text not null,
  primary key (job_id, draft_key, revision, lead_id),
  foreign key (job_id, draft_key, revision) references finding_revisions on delete cascade
);

create table leads (
  job_id text not null references jobs on delete cascade,
  lead_id text not null check (lead_id ~ '^LEAD-[0-9]{4}$'),
  origin text not null default 'analyzer' check (origin in ('analyzer','previous_report')),
  prev_finding_id text,
  rule_id text not null, tools text[] not null,
  category text not null, category_family text not null,
  analyzer_severity_raw text not null,
  severity_norm text not null check (severity_norm in ('Critical','High','Medium','Low','Info')),
  sev_rank smallint generated always as (case severity_norm when 'Critical' then 5 when 'High' then 4
           when 'Medium' then 3 when 'Low' then 2 else 1 end) stored,
  located text check (located in ('verbatim','function','moved')),
  path text not null, start_line int not null, end_line int not null,
  state text not null check (state in ('open','promoted','dismissed','merged','not_reviewed')),
  reason text check (reason in ('fp_guarded','fp_unreachable','duplicate_of','fixed',
                                'out_of_scope','disproved_by_challenge')),
  state_ref text, state_item text,
  primary key (job_id, lead_id),
  check ((state = 'dismissed') = (reason is not null)),
  check (case when origin = 'previous_report' then reason is null or (reason = 'fixed' and located <> 'moved')
         else reason is distinct from 'fixed' end),
  check (severity_norm <> 'Critical' or origin = 'previous_report'),
  check ((origin = 'previous_report') = (located is not null))
);
create index leads_keyset on leads (job_id, sev_rank desc, path, start_line, lead_id);

create table lead_dismissals (
  id bigserial primary key, job_id text not null references jobs on delete cascade,
  lead_id text not null, reason text not null, target text, quotes jsonb, note text,
  created_at timestamptz not null default now()
);

create table challenge_answers (
  job_id text not null, draft_key text not null, revision int not null,
  checklist_sha256 text not null, items jsonb not null,
  answers_hash text not null, answers jsonb not null,
  verdict text not null check (verdict in ('passed','downgraded','withdrawn')),
  severity_before text not null, severity_after text,
  created_at timestamptz not null default now(),
  primary key (job_id, draft_key, revision),
  foreign key (job_id, draft_key, revision) references finding_revisions on delete cascade
);

create table sections (
  job_id text not null references jobs on delete cascade,
  section text not null check (section in ('roles_notes','out_of_scope_reasons','coverage')),
  revision int not null, content jsonb not null, content_hash text not null,
  created_at timestamptz not null default now(),
  primary key (job_id, section, revision)
);

create table placeholder_refs (
  job_id text not null references jobs on delete cascade,
  owner_kind text not null check (owner_kind in ('finding','section')),
  owner_key text not null, revision int not null,
  kind text not null check (kind in ('fact','finding','calc')),
  ref text not null, resolved boolean not null,
  primary key (job_id, owner_kind, owner_key, revision, kind, ref)
);

create table job_reads (
  id bigserial primary key, job_id text not null references jobs on delete cascade,
  path text not null, start_line int not null, end_line int not null,
  at timestamptz not null default now()
);
create index job_reads_by_file on job_reads (job_id, path);
