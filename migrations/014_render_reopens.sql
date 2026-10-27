-- Migration 014: jobs.render_reopens (fix/job-lifecycle-client-path, PR #83 security review).
--
-- render_resets counts the reviewer's own render failures (late gate on model text) and is the
-- client budget. render_reopens counts EVERY review_finalize reopen of a render_failed job, whatever
-- the cause, and is the hard cap (render.MAX_TOTAL_REOPENS) so no classification bug can yield
-- unlimited retries.
alter table jobs add column if not exists render_reopens smallint not null default 0;
