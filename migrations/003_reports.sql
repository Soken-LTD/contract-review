-- Migration 003: reports table (plan-v4 part 08 section 3.4; 03 3.6 assigns it to 08).
-- One row per live report; expiry, delete or withdrawal removes the row and writes one 09
-- tombstone per pdf_sha256s entry.

create table reports (
  report_id          text primary key check (report_id ~ '^[a-z2-7]{26}$'),
  report_id_short    text not null unique check (report_id_short ~ '^[a-z2-7]{10}$'),
  job_id             text not null unique references jobs(job_id),
  profile            text not null check (profile in ('owner','public_review')),
  object_prefix      text not null,           -- reports/<report_id>/<render_no>/
  out_name           text not null check (out_name ~ '^[A-Za-z0-9_-]{1,76}\.pdf$'),
  pdf_sha256s        char(64)[] not null,     -- every served PDF, last = current
  subject_candidates jsonb not null,          -- 08 2.6
  key_version        smallint not null,       -- K_v (08 4.1)
  extended           boolean not null default false,
  refresh_code       text,
  rendered_at        timestamptz not null,
  expires_at         timestamptz not null
);
