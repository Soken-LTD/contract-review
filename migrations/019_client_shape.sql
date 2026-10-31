-- Migration 019: per-job stale tool list state (client_refresh, blind round 5 2026-10-31).
--
-- jobs.client_shape: {"fresh": bool, "notices": int, "status_noticed": bool}. fresh turns true when a tool
-- added since the client baseline is called on the job; notices counts the client_notice texts sent.
-- Written only by an update of an existing job row, so a caller cannot create state for a job id it made up.
-- Additive: no existing row changes.
alter table jobs add column if not exists client_shape jsonb not null default '{}'::jsonb;
