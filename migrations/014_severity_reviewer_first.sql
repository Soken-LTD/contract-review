-- Migration 014: reviewer-first severity (blind run 2026-10-26 judgement, section 6).
-- The final severity of a draft carries who set it, why, and the rule string the report prints,
-- so the client reads the same severity_rule / set_by / reason in the verdict and in the PDF.
-- Additive: existing rows read null and the report falls back to the revision's submit-time rule.
alter table finding_drafts
  add column if not exists severity_rule text,
  add column if not exists severity_set_by text check (severity_set_by in ('reviewer', 'matrix', 'cap')),
  add column if not exists severity_reason text;
