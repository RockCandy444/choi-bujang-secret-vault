-- Run in Supabase SQL Editor for the existing learning project.
-- No notes, owners, client permissions, RLS settings or policies are changed.
begin;
grant select, insert, update, delete on table public.notes to service_role;
commit;
