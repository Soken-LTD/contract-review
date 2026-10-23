-- Migration 009: project context ingestion (context ingestion spec 2026-10-23), after 008 widened
-- sections.section with context_notes.
--
-- jobs.context_items: the documents requested for the job (review_start.context and
-- review_add_context), as [{kind, url|null, path|null, content|null, sha256|null, requested_at}];
-- the worker's `context` step reads it and the store under <pin_root>/<job_id>/context/ holds the
-- result. Two row checks back the handler's locked transaction: at most 12 requests per job, and
-- no two requests with the same key (url, or sha256 for inline text). job_steps.step gains
-- 'context' (one row per fetch round, seq counts rounds); its check constraint was created inline
-- in 002 (auto-named), so it is looked up by definition.

alter table jobs add column if not exists context_items jsonb not null default '[]'::jsonb;

create or replace function context_items_keys_unique(items jsonb) returns boolean
language sql immutable as $$
  select jsonb_typeof(items) = 'array'
     and (select count(*) = count(distinct coalesce(e->>'url', e->>'sha256', ''))
            from jsonb_array_elements(items) e)
$$;

alter table jobs drop constraint if exists jobs_context_items_cap;
alter table jobs add constraint jobs_context_items_cap
  check (jsonb_typeof(context_items) = 'array' and jsonb_array_length(context_items) <= 12);
alter table jobs drop constraint if exists jobs_context_items_unique;
alter table jobs add constraint jobs_context_items_unique check (context_items_keys_unique(context_items));

do $$
declare
  c text;
begin
  select conname into c
    from pg_constraint
   where conrelid = 'job_steps'::regclass and contype = 'c'
     and pg_get_constraintdef(oid) like '%chain_state%';
  if c is not null then
    execute format('alter table job_steps drop constraint %I', c);
  end if;
  alter table job_steps add constraint job_steps_step_check
    check (step in ('chain_state','fetch','deps','build','map','analyze','verify','render','proof','purge',
                    'context'));
end $$;
