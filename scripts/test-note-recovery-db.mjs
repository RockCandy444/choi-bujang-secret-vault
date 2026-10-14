import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { noteContentHash } from '../src/note-recovery.mjs';

// PostgreSQL/WASM lives only in the ignored test-runtime folder. This script
// has no network client, environment credentials or live DB connection.
let db;
let stage = 'LOCAL_RUNTIME_MISSING';
try {
  const { PGlite } = await import('../local-only/recovery-test-runtime/node_modules/@electric-sql/pglite/dist/index.js');
  db = new PGlite();
  const run = randomUUID();
  const owner = randomUUID();
  const id = randomUUID();
  const otherId = randomUUID();
  const title = randomUUID();
  const content = `${randomUUID()}😀`;
  const hash = noteContentHash(title, content);
  stage = 'SCHEMA_SETUP';
  await db.exec(`create role anon nologin; create role authenticated nologin;
    create role service_role nologin bypassrls;
    create table public.notes(id uuid primary key, owner_id uuid, title text, content text,
      created_at timestamptz not null default clock_timestamp());
    alter table public.notes enable row level security;
    grant select, insert, update, delete on public.notes to service_role;`);
  await db.exec(await readFile(new URL('../docs/STEP10_NOTE_RECOVERY.sql', import.meta.url), 'utf8'));
  stage = 'PRIVATE_PERMISSIONS';
  const privileges = (await db.query(`select
    has_schema_privilege('anon','aleph_recovery','usage') as anon_schema,
    has_schema_privilege('authenticated','aleph_recovery','usage') as student_schema,
    has_function_privilege('anon','public.aleph_restore_test_note(uuid,uuid,uuid)','execute') as anon_rpc,
    has_function_privilege('authenticated','public.aleph_restore_test_note(uuid,uuid,uuid)','execute') as student_rpc,
    has_table_privilege('service_role','aleph_recovery.note_backups','update') as backup_update,
    has_table_privilege('service_role','aleph_recovery.note_audit','delete') as audit_delete`)).rows[0];
  assert.ok(Object.values(privileges).every(value => value === false));
  process.stdout.write('통과 · 비공개 사본·감사 권한과 공개 RPC 거부\n');

  await db.exec('set role service_role');
  // Both target and unaffected fixture note belong to the same simulated B.
  await db.query('insert into public.notes(id,owner_id,title,content) values($1,$2,$3,$4)',
    [otherId, owner, randomUUID(), randomUUID()]);
  const otherBefore = (await db.query('select * from public.notes where id=$1', [otherId])).rows[0];
  stage = 'CREATE_VERIFIED_BACKUP';
  const created = (await db.query('select public.aleph_create_test_note($1,$2,$3,$4,$5,$6) as result',
    [run, owner, id, title, content, hash])).rows[0].result;
  assert.deepEqual(created, { id, owner_id: owner, content_hash: hash });
  const auditBefore = (await db.query('select * from aleph_recovery.note_audit order by at,event_id')).rows;
  const restore = async (scopeRun = run, scopeOwner = owner, scopeId = id) =>
    (await db.query('select public.aleph_restore_test_note($1,$2,$3) as result',
      [scopeRun, scopeOwner, scopeId])).rows[0].result;
  stage = 'CHANGED_NOTE_RESTORE';
  await db.query('update public.notes set content=$2 where id=$1', [id, randomUUID()]);
  assert.deepEqual(await restore(), created);
  let row = (await db.query('select * from public.notes where id=$1', [id])).rows[0];
  assert.equal(noteContentHash(row.title, row.content), hash);
  assert.equal(row.owner_id, owner);
  process.stdout.write('통과 · 변조한 가상 B 한 건의 ID·소유자·내용 해시 복원\n');
  stage = 'DELETED_NOTE_RESTORE';
  await db.query('delete from public.notes where id=$1', [id]);
  assert.deepEqual(await restore(), created);
  row = (await db.query('select * from public.notes where id=$1', [id])).rows[0];
  assert.equal(noteContentHash(row.title, row.content), hash);
  assert.deepEqual((await db.query('select * from public.notes where id=$1', [otherId])).rows[0], otherBefore);
  const auditAfter = (await db.query('select * from aleph_recovery.note_audit order by at,event_id')).rows;
  assert.equal(auditAfter.length, auditBefore.length + 2);
  assert.deepEqual(auditAfter[0], auditBefore[0]);
  process.stdout.write('통과 · 삭제한 가상 B 한 건 복원·다른 메모·기존 감사 보존\n');
  stage = 'WRONG_BACKUP_SCOPE';
  await assert.rejects(restore(randomUUID()), { message: 'NOTE_BACKUP_NOT_FOUND' });
  await assert.rejects(restore(run, randomUUID()), { message: 'NOTE_BACKUP_NOT_FOUND' });
  await assert.rejects(restore(run, owner, randomUUID()), { message: 'NOTE_BACKUP_NOT_FOUND' });
  stage = 'OWNER_CONFLICT';
  await db.query('update public.notes set owner_id=$2 where id=$1', [id, randomUUID()]);
  await assert.rejects(restore(), { message: 'NOTE_OWNER_CONFLICT' });
  await db.query('update public.notes set owner_id=$2 where id=$1', [id, owner]);
  process.stdout.write('통과 · 사본 없음·다른 회차·소유자 불일치 거부\n');
  stage = 'BACKUP_HASH_MISMATCH';
  await db.exec('reset role');
  await db.query('update aleph_recovery.note_backups set content=$2 where note_id=$1', [id, randomUUID()]);
  await db.exec('set role service_role');
  await assert.rejects(restore(), { message: 'NOTE_BACKUP_INVALID' });
  await db.exec('reset role');
  await db.query('update aleph_recovery.note_backups set content=$2 where note_id=$1', [id, content]);
  await db.exec('set role service_role');
  process.stdout.write('통과 · 손상된 사본의 내용 해시 불일치 거부\n');
  stage = 'AUDIT_FAILURE_ROLLBACK';
  await db.exec('reset role; revoke insert on aleph_recovery.note_audit from service_role; set role service_role;');
  const changedContent = randomUUID();
  await db.query('update public.notes set content=$2 where id=$1', [id, changedContent]);
  await assert.rejects(restore(), error => error.code === '42501');
  assert.equal((await db.query('select content from public.notes where id=$1', [id])).rows[0].content, changedContent);
  assert.equal((await db.query('select count(*)::int as count from aleph_recovery.note_audit')).rows[0].count, auditAfter.length);
  process.stdout.write('통과 · 감사 쓰기 실패 시 메모 복원도 함께 취소\n');
  process.stdout.write('로컬 PostgreSQL의 가상 B 연습 6항목입니다. 실제 학습 DB·운영 B·심판 판정은 아닙니다.\n');
} catch {
  process.stderr.write(`로컬 복구 DB 검사 첫 오류: ${stage}\n`);
  process.exitCode = 1;
} finally { await db?.close(); }
