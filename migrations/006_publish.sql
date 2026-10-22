-- Migration 006: publish requests and consent audit log.
--
-- publish_requests: one row per report_id (UNIQUE dedup).  Idempotent: a second
-- review_publish call on the same report_id returns the existing row status.
-- Privileged publish worker transitions: queued -> publishing -> published | failed.
--
-- publish_consent_log: append-only audit trail.  Every time a caller supplies a
-- consent block the row is inserted here regardless of whether the request is new.

create table publish_requests (
  id            bigserial primary key,
  report_id     text not null unique references reports(report_id) on delete cascade,
  job_id        text not null references jobs(job_id) on delete cascade,
  -- status lifecycle: queued -> publishing -> published | failed
  status        text not null check (status in ('queued','publishing','published','failed')),
  safe_filename text,            -- sanitized filename used in the git commit
  public_url    text,            -- filled when published
  error_detail  text,            -- filled on failure
  queued_at     timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create index publish_requests_status on publish_requests (status, queued_at);

create table publish_consent_log (
  id         bigserial primary key,
  report_id  text not null references reports(report_id) on delete cascade,
  party      text not null,
  name       text not null,
  statement  text not null,
  client_ts  text not null,   -- client-provided ISO-8601 timestamp, stored verbatim
  logged_at  timestamptz not null default now()
);

create index publish_consent_log_report on publish_consent_log (report_id, logged_at);
