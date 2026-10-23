-- Migration 010: publication records outlive the report row.
--
-- review_delete_job removes the reports row and its files. The consent log is the only record of
-- who agreed to a permanent publication (publish.py offer text), and the publish request holds the
-- public URL a takedown needs; both used to cascade away with the report (security review of the
-- delete handler, 2026-10-23). They now survive, linked by sha256(report_id) as report_tombstones
-- are, with the report_id reference set to null when the report goes.

alter table publish_consent_log add column report_ref_hash char(64);
alter table publish_consent_log alter column report_id drop not null;
alter table publish_consent_log drop constraint publish_consent_log_report_id_fkey;
alter table publish_consent_log
  add constraint publish_consent_log_report_id_fkey
  foreign key (report_id) references reports(report_id) on delete set null;
create index publish_consent_log_ref on publish_consent_log (report_ref_hash);

alter table publish_requests add column report_ref_hash char(64);
alter table publish_requests alter column report_id drop not null;
alter table publish_requests drop constraint publish_requests_report_id_fkey;
alter table publish_requests
  add constraint publish_requests_report_id_fkey
  foreign key (report_id) references reports(report_id) on delete set null;
create index publish_requests_ref on publish_requests (report_ref_hash);
