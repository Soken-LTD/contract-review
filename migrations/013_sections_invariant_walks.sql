-- Migration 013: `invariant_walks` section (feat/lifecycle-invariant-pass, 2026-10-26).
--
-- The client answers the job's invariant walks (map/lifecycle.json, rubric invariants.yaml)
-- through review_set_section(section="invariant_walks"); finalize check F9 reads the latest
-- revision. Same lookup-by-definition as 008 because the original check was auto-named.

do $$
declare
  c text;
begin
  select conname into c
    from pg_constraint
   where conrelid = 'sections'::regclass and contype = 'c'
     and pg_get_constraintdef(oid) like '%roles_notes%';
  if c is not null then
    execute format('alter table sections drop constraint %I', c);
  end if;
  alter table sections add constraint sections_section_check
    check (section in ('roles_notes','out_of_scope_reasons','coverage','context_notes','invariant_walks'));
end $$;
