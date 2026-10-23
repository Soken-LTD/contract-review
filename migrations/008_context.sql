-- Migration 008: project context ingestion (context ingestion spec 2026-10-23).
--
-- jobs.context_items: the documents requested for the job (review_start.context and
-- review_add_context), as [{kind, url|null, path|null, content|null, sha256|null, requested_at}];
-- the worker's `context` step reads it and the store under <pin_root>/<job_id>/context/ holds the
-- result. job_steps.step gains 'context' (one row per fetch round, seq counts rounds).
-- sections.section gains 'context_notes' (the reviewer's prose on the documents, spec section 6).
-- Both check constraints were created inline (auto-named), so they are looked up by definition.

alter table jobs add column if not exists context_items jsonb not null default '[]'::jsonb;

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

  select conname into c
    from pg_constraint
   where conrelid = 'sections'::regclass and contype = 'c'
     and pg_get_constraintdef(oid) like '%roles_notes%';
  if c is not null then
    execute format('alter table sections drop constraint %I', c);
  end if;
  alter table sections add constraint sections_section_check
    check (section in ('roles_notes','out_of_scope_reasons','coverage','context_notes'));
end $$;
