-- Migration 016: learning ledger (learning-loop design 2026-10-27, phase P0).
--
-- Retention and review_delete_job cascade every row keyed by a job away (69 of 101 stand jobs had
-- no leads left on 2026-10-27), so the outcome of each lead and finding is copied here when a job
-- is finalized and again when it is purged. These tables have NO job_id column on purpose:
-- tools/delete.py purges every table with one, and nothing here may point back at a job.
--
-- Nothing identifying is stored: no job id, address, repo, path, line, code, finding or report
-- text, client name or key. `*_tag` columns are HMAC-SHA256 under the learning salt
-- (SOKEN_LEARNING_SALT, rotated yearly, `salt_id` names the key), truncated to 16 hex, used only
-- to count distinct values and to replace a job's rows idempotently. Week granularity only.
-- Additive: no existing table or column changes meaning.

create table lead_outcomes (
  id               bigserial primary key,
  week             date not null,                -- date_trunc('week', finalized_at or purge time)
  salt_id          text not null,
  job_tag          char(16) not null,            -- replace key for re-finalize and purge
  target_tag       char(16) not null,            -- distinct targets (source pin) for the minimum sample
  principal_tag    char(16) not null,            -- distinct principals for the minimum sample
  consent_class    text not null check (consent_class in ('public_code','owner_opt_in','private')),
  chain_family     text not null,
  tool             text not null,
  tool_version     text not null,
  rule_id          text not null,
  category         text not null,
  category_family  text not null,
  severity_norm    text not null check (severity_norm in ('Critical','High','Medium','Low','Info')),
  severity_shown   text not null check (severity_shown in ('Critical','High','Medium','Low','Info')),
  policy_version   text not null,
  tier_shown       text not null check (tier_shown in ('boosted','normal','demoted','collapsed','explore','unknown')),
  outcome          text not null check (outcome in ('promoted','dismissed','auto_closed','open','merged')),
  dismiss_reason   text,
  printed_severity text check (printed_severity in ('Critical','High','Medium','Low','Informational')),
  release          text not null,
  job_state        text not null,                -- state when recorded (finalized, rendered, expired, deleted, ...)
  recorded_by      text not null check (recorded_by in ('finalize','purge','backfill')),
  recorded_at      date not null default current_date,
  check ((outcome = 'dismissed') = (dismiss_reason is not null))
);
create index lead_outcomes_rule on lead_outcomes (tool, rule_id, week);
create index lead_outcomes_job on lead_outcomes (job_tag);

create table finding_outcomes (
  id                 bigserial primary key,
  week               date not null,
  salt_id            text not null,
  job_tag            char(16) not null,
  target_tag         char(16) not null,
  principal_tag      char(16) not null,
  consent_class      text not null check (consent_class in ('public_code','owner_opt_in','private')),
  chain_family       text not null,
  category           text not null,
  category_family    text not null,
  status             text not null check (status in ('accepted','withdrawn','needs_text','needs_challenge')),
  withdrawn_by       text,
  withdrawn_reason   text,
  severity_proposed  text,                       -- reviewer's claimed_severity on the last revision
  severity_computed  text,                       -- matrix result on the last revision
  severity_printed   text check (severity_printed in ('Critical','High','Medium','Low','Informational')),
  severity_set_by    text,
  severity_rule      text,
  caps_applied       text[] not null default '{}',
  evidence_level     text,
  challenge_verdict  text,
  from_lead          boolean not null,
  lead_tool          text,
  lead_rule          text,
  rejected_count     int not null default 0,
  revisions          int not null default 0,
  release            text not null,
  job_state          text not null,
  recorded_by        text not null check (recorded_by in ('finalize','purge','backfill')),
  recorded_at        date not null default current_date
);
create index finding_outcomes_job on finding_outcomes (job_tag);
create index finding_outcomes_lead_rule on finding_outcomes (lead_tool, lead_rule);

-- Judge verdicts (matrix rounds, staff-judged public jobs). Imported by
-- scripts/learning_tiers.py import-judge; the target is a salted tag, never a name or address.
create table judge_verdicts (
  id               bigserial primary key,
  round            text not null,
  release          text not null,
  salt_id          text not null,
  target_tag       char(16) not null,
  chain_family     text not null,
  arm              text not null check (arm in ('mcp','plain','gt')),
  issue_id         text not null,
  real             boolean not null,
  judge_severity   text not null check (judge_severity in ('Critical','High','Medium','Low','Informational')),
  printed_severity text,
  claimed_severity text,
  matrix_severity  text,
  severity_rule    text,
  lead_rules       text[] not null default '{}',  -- "tool:rule" of leads that touched the issue
  source           text not null,                 -- JUDGEMENT.md section reference
  imported_at      timestamptz not null default now(),
  unique (round, salt_id, target_tag, arm, issue_id)
);

-- Friction: one row per rejected submit violation (error code and field only, never the text).
create table gate_events (
  id             bigserial primary key,
  week           date not null,
  salt_id        text not null,
  principal_tag  char(16) not null,
  draft_tag      char(16) not null,               -- links attempts of one draft (resolved / abandoned)
  chain_family   text not null,
  tool           text not null,
  error_code     text not null,
  field          text,
  attempt        int not null,
  release        text not null
);
create index gate_events_code on gate_events (error_code, week);

-- The rule tier policy a job last saw in review_leads (contract/learning/rule_tiers/<version>.yaml),
-- so the ledger records the tier each lead was shown in.
alter table jobs add column if not exists learning_policy_version text;

-- Per-rule statistics the tier generator reads (rolling 180 days of analyzer lead outcomes).
create view rule_stats as
with o as (
  select * from lead_outcomes where week >= current_date - 180
), triaged as (
  select tool, rule_id, principal_tag, count(*) n from o
  where outcome in ('promoted','dismissed') group by tool, rule_id, principal_tag
)
select o.tool, o.rule_id,
  count(*)                                                          as raised,
  count(*) filter (where outcome in ('promoted','dismissed'))       as triaged,
  count(*) filter (where outcome = 'promoted')                      as promoted,
  count(*) filter (where outcome = 'dismissed')                     as dismissed,
  count(*) filter (where outcome = 'auto_closed')                   as auto_closed,
  count(*) filter (where outcome = 'open')                          as left_open,
  count(*) filter (where outcome = 'promoted' and printed_severity in ('Critical','High','Medium')) as promoted_ge_medium,
  count(*) filter (where outcome = 'promoted' and printed_severity in ('Critical','High'))          as promoted_ge_high,
  count(*) filter (where outcome = 'promoted' and printed_severity is not null and
                   (case printed_severity when 'Critical' then 5 when 'High' then 4 when 'Medium' then 3
                                          when 'Low' then 2 else 1 end) >
                   (case severity_norm when 'Critical' then 5 when 'High' then 4 when 'Medium' then 3
                                       when 'Low' then 2 else 1 end))                         as promoted_above_norm,
  count(distinct (o.salt_id, o.target_tag)) filter (where outcome in ('promoted','dismissed'))    as targets,
  count(distinct (o.salt_id, o.principal_tag)) filter (where outcome in ('promoted','dismissed')) as principals,
  coalesce((select max(t.n) from triaged t where t.tool = o.tool and t.rule_id = o.rule_id), 0)  as max_principal_n,
  mode() within group (order by severity_norm)                      as severity_norm,
  max(week)                                                         as last_week
from o group by o.tool, o.rule_id;
