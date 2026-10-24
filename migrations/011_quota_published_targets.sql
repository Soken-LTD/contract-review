-- Migration 011: daily report quota and one publication per reviewed target (CEO 2026-10-24).
--
-- jobs.target_key: what was reviewed (`<chain>:<address>` or `repo:<host/owner/repo>`), stored at
-- review_start. jobs.limit_key: who the quota charges (`ip:<addr>`, `relay:<target_key>`), null
-- when exempt. jobs.report_at: when review_finalize issued the report; the quota counts it over a
-- rolling 24 hours, and review_delete_job keeps it so deleting a job does not refund the quota.
--
-- published_targets: the single public file of each target. A later published review of the
-- same target overwrites that file (same name, new bytes) instead of adding a second report.

alter table jobs add column target_key text;
alter table jobs add column limit_key text;
alter table jobs add column report_at timestamptz;
create index jobs_limit_key_report_at on jobs (limit_key, report_at) where report_at is not null;

create table published_targets (
  target_key        text primary key,
  safe_filename     text not null unique,
  first_report_id   text,
  last_report_id    text,
  first_published_at timestamptz not null default now(),
  last_published_at  timestamptz not null default now()
);
