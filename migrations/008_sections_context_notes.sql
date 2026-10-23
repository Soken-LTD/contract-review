-- Migration 008: `context_notes` report section (context ingestion spec, sections 6 and 7).
--
-- The reviewer's prose about the project documents (whitepaper, website, app bundle, docs,
-- terms, privacy) goes through review_set_section(section="context_notes"): model blocks under
-- the same text and number gates as roles_notes, at most 8 blocks, printed under "Project
-- context" in the report. The column check on sections.section lists the sections; it was
-- created inline in 001 (auto-named), so it is looked up by definition.

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
    check (section in ('roles_notes','out_of_scope_reasons','coverage','context_notes'));
end $$;
