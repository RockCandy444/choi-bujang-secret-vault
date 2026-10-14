-- Setup for the existing learning project; no original note row is copied,
-- updated or deleted. New judge-B notes are backed up during their creation.
-- Run once: collisions stop the transaction instead of replacing old objects.
begin;

create schema aleph_recovery;
revoke all on schema aleph_recovery from public, anon, authenticated;
grant usage on schema aleph_recovery to service_role;

create table aleph_recovery.note_backups (
  run_id uuid not null,
  note_id uuid not null,
  owner_id uuid not null,
  title text not null check (length(title) between 1 and 200),
  content text not null check (length(content) <= 20000),
  content_hash text not null check (content_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz not null,
  verified_at timestamptz not null,
  primary key (run_id, note_id)
);
create table aleph_recovery.note_audit (
  event_id uuid primary key default gen_random_uuid(),
  at timestamptz not null default clock_timestamp(),
  action text not null check (action in ('backup_verified', 'restored')),
  run_id uuid not null,
  note_id uuid not null,
  content_hash text not null check (content_hash ~ '^[a-f0-9]{64}$')
);
alter table aleph_recovery.note_backups enable row level security;
alter table aleph_recovery.note_audit enable row level security;
revoke all on aleph_recovery.note_backups, aleph_recovery.note_audit from public, anon, authenticated, service_role;
grant select, insert on aleph_recovery.note_backups, aleph_recovery.note_audit to service_role;

create function public.aleph_create_test_note(
  p_run_id uuid, p_owner_id uuid, p_note_id uuid, p_title text, p_content text, p_content_hash text
) returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  saved public.notes%rowtype;
  checked_hash text;
begin
  if current_user <> 'service_role' then raise exception using errcode = '42501', message = 'SERVER_ONLY'; end if;
  if p_run_id is null or p_owner_id is null or p_note_id is null or p_title is null
      or length(p_title) not between 1 and 200 or p_content is null or length(p_content) > 20000
      or p_content_hash is null or p_content_hash !~ '^[a-f0-9]{64}$' then
    raise exception using errcode = 'P0001', message = 'INVALID_NOTE';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_note_id::text, 0));
  if exists (select 1 from aleph_recovery.note_backups b where b.run_id = p_run_id and b.note_id = p_note_id) then
    raise exception using errcode = 'P0001', message = 'NOTE_ALREADY_EXISTS';
  end if;
  insert into public.notes(id, owner_id, title, content)
    values (p_note_id, p_owner_id, p_title, p_content) returning * into saved;
  checked_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(saved.title, 'UTF8')
    || pg_catalog.decode('00', 'hex') || pg_catalog.convert_to(saved.content, 'UTF8')), 'hex');
  if saved.id is distinct from p_note_id or saved.owner_id is distinct from p_owner_id
      or checked_hash is distinct from p_content_hash then
    raise exception using errcode = 'P0001', message = 'NOTE_BACKUP_INVALID';
  end if;
  insert into aleph_recovery.note_backups(run_id, note_id, owner_id, title, content, content_hash, created_at, verified_at)
    values (p_run_id, saved.id, saved.owner_id, saved.title, saved.content, checked_hash, saved.created_at, clock_timestamp());
  insert into aleph_recovery.note_audit(action, run_id, note_id, content_hash)
    values ('backup_verified', p_run_id, saved.id, checked_hash);
  return jsonb_build_object('id', saved.id, 'owner_id', saved.owner_id, 'content_hash', checked_hash);
exception when unique_violation then
  raise exception using errcode = 'P0001', message = 'NOTE_ALREADY_EXISTS';
end;
$$;

create function public.aleph_restore_test_note(p_run_id uuid, p_owner_id uuid, p_note_id uuid)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  backup aleph_recovery.note_backups%rowtype;
  restored public.notes%rowtype;
  checked_hash text;
begin
  if current_user <> 'service_role' then raise exception using errcode = '42501', message = 'SERVER_ONLY'; end if;
  if p_run_id is null or p_owner_id is null or p_note_id is null then
    raise exception using errcode = 'P0001', message = 'INVALID_NOTE';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_note_id::text, 0));
  select * into backup from aleph_recovery.note_backups b
    where b.run_id = p_run_id and b.note_id = p_note_id and b.owner_id = p_owner_id;
  if not found then raise exception using errcode = 'P0001', message = 'NOTE_BACKUP_NOT_FOUND'; end if;
  checked_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(backup.title, 'UTF8')
    || pg_catalog.decode('00', 'hex') || pg_catalog.convert_to(backup.content, 'UTF8')), 'hex');
  if backup.content_hash is distinct from checked_hash or backup.verified_at > clock_timestamp() then
    raise exception using errcode = 'P0001', message = 'NOTE_BACKUP_INVALID';
  end if;
  insert into public.notes(id, owner_id, title, content, created_at)
    values (backup.note_id, backup.owner_id, backup.title, backup.content, backup.created_at)
    on conflict (id) do update set title = excluded.title, content = excluded.content, created_at = excluded.created_at
      where public.notes.owner_id = p_owner_id
    returning * into restored;
  if not found then raise exception using errcode = 'P0001', message = 'NOTE_OWNER_CONFLICT'; end if;
  checked_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(restored.title, 'UTF8')
    || pg_catalog.decode('00', 'hex') || pg_catalog.convert_to(restored.content, 'UTF8')), 'hex');
  if restored.id is distinct from backup.note_id or restored.owner_id is distinct from backup.owner_id
      or checked_hash is distinct from backup.content_hash then
    raise exception using errcode = 'P0001', message = 'NOTE_RESTORE_MISMATCH';
  end if;
  insert into aleph_recovery.note_audit(action, run_id, note_id, content_hash)
    values ('restored', p_run_id, restored.id, checked_hash);
  return jsonb_build_object('id', restored.id, 'owner_id', restored.owner_id, 'content_hash', checked_hash);
end;
$$;
revoke execute on function public.aleph_create_test_note(uuid, uuid, uuid, text, text, text) from public, anon, authenticated;
revoke execute on function public.aleph_restore_test_note(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.aleph_create_test_note(uuid, uuid, uuid, text, text, text) to service_role;
grant execute on function public.aleph_restore_test_note(uuid, uuid, uuid) to service_role;
notify pgrst, 'reload schema';
commit;
