-- Migration 012: launch-fixes-2026-10-24
--
-- render_resets:         track render_failed -> ready resets per job (replaces counting
--                        failed render step rows, which miscount when a retry inserts a
--                        new row).  Refuse when it reaches 3.
--
-- terms_url:             the Terms of Use URL the requester accepted at review_start;
--                        stored so the auto-publish consent log can reference it.
-- terms_accepted_at:     timestamp of acceptance (= review_start time).
--
-- publish_requests:      attempts + next_attempt_at for retry-with-backoff on failed
--                        rows (up to 5 attempts; next_attempt_at gates the retry window).

alter table jobs
  add column render_resets smallint not null default 0,
  add column terms_url text,
  add column terms_accepted_at timestamptz;

alter table publish_requests
  add column attempts smallint not null default 0,
  add column next_attempt_at timestamptz;
