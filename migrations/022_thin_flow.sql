-- Migration 022: the client flow of each job (thin server design 2026-11-03, CEO decision 2026-11-01).
--
-- `thin`: no analyzer leads, no challenge, no sections, no severity matrix; the report prints the reviewer's
-- findings and the server's own data. `legacy`: the flow before this migration.
-- Additive only: every existing row reads `legacy` (the column is added with that default), so its re-render
-- reproduces the sections it printed before; new rows default to `thin`. The application also writes the
-- column explicitly at job creation from SOKEN_FLOW, so `SOKEN_FLOW=legacy` keeps creating legacy jobs.
-- No table is dropped: leads, sections, challenge_answers and the rest simply stop receiving rows for thin
-- jobs and are purged with their jobs by worker/retention.py.
alter table jobs add column if not exists flow text not null default 'legacy'
  check (flow in ('legacy', 'thin'));
alter table jobs alter column flow set default 'thin';
