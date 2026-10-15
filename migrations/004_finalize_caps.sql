-- Migration 004: add caps_applied to finding_drafts for finalize-time K-cap recording.
-- At finalize, compute_severity re-evaluates caps (K4, K8, K10, K11) and stores the
-- applied caps list alongside the updated severity. caps_applied mirrors the same column
-- on finding_revisions but records the FINAL value after the full K-cap chain.

alter table finding_drafts
  add column if not exists caps_applied text[] not null default '{}';
