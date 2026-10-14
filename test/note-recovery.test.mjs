import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import notesHandler from '../api/notes.js';
import restoreHandler from '../api/restore.js';
import { callNoteRecovery, noteContentHash } from '../src/note-recovery.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const signingKeys = await generateKeyPair('ES256');
const kid = randomUUID();
const publicJwk = { ...await exportJWK(signingKeys.publicKey), kid, alg: 'ES256' };
const ownerB = randomUUID();
const ownerA = randomUUID();
const runId = randomUUID();
const id = randomUUID();
const otherId = randomUUID();
const key = 'fixture-server-credential';
const loginB = { kind: 'judge', userId: ownerB, runId, identity: 'b' };

async function authorization(identity = 'b', extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  return `Bearer ${await new SignJWT({ iss: config.judgeIssuer,
    aud: new URL(config.publicAppUrl).hostname, sub: identity === 'b' ? ownerB : ownerA,
    aleph_role: 'judge', aleph_identity: identity, aleph_run: runId,
    iat: now, exp: now + 300, ...extra }).setProtectedHeader({ alg: 'ES256', kid }).sign(signingKeys.privateKey)}`;
}

function responseCapture() {
  return { headers: {}, code: undefined, body: undefined,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
}

async function configured(work, rpc) {
  const saved = { fetch: globalThis.fetch, url: process.env.SUPABASE_URL,
    key: process.env.SUPABASE_SECRET_KEY, warn: console.warn };
  const calls = [];
  const logs = [];
  process.env.SUPABASE_URL = new URL(config.identityProvider.issuer).origin;
  process.env.SUPABASE_SECRET_KEY = key;
  console.warn = (...args) => logs.push(args);
  globalThis.fetch = async (input, options) => {
    const url = new URL(input);
    if (url.href === `${config.judgeIssuer}/.well-known/jwks.json`
        || url.href === config.identityProvider.jwksUrl) {
      return new Response(JSON.stringify({ keys: [publicJwk] }));
    }
    if (url.pathname === '/auth/v1/user') return new Response('{}', { status: 401 });
    assert.equal(url.origin, process.env.SUPABASE_URL);
    calls.push({ url, options });
    return rpc(url, options);
  };
  try { await work({ calls, logs }); }
  finally {
    globalThis.fetch = saved.fetch; console.warn = saved.warn;
    if (saved.url === undefined) delete process.env.SUPABASE_URL; else process.env.SUPABASE_URL = saved.url;
    if (saved.key === undefined) delete process.env.SUPABASE_SECRET_KEY; else process.env.SUPABASE_SECRET_KEY = saved.key;
  }
}

test('new signed judge-B note is backed up in a single RPC; only the requested damaged/deleted note is restored', async () => {
  const title = randomUUID();
  const content = randomUUID();
  const hash = noteContentHash(title, content);
  const notes = new Map([[otherId, { id: otherId, owner_id: ownerA, title: randomUUID(), content: randomUUID() }]]);
  const otherBefore = structuredClone(notes.get(otherId));
  const backups = new Map();
  const audit = ['fixture-existing-audit'];
  await configured(async ({ calls, logs }) => {
    const created = responseCapture();
    await notesHandler({ url: '/api/notes', method: 'POST', headers: { authorization: await authorization() },
      body: { id, title, body: content, owner_id: ownerA, runId: randomUUID() } }, created);
    assert.equal(created.code, 201);
    assert.deepEqual(created.body, { id });
    assert.equal(backups.size, 1);
    assert.equal(calls.length, 1);
    const originalBackup = structuredClone(backups.get(id));
    for (const damage of ['changed', 'deleted']) {
      if (damage === 'changed') notes.set(id, { ...notes.get(id), content: randomUUID() });
      else notes.delete(id);
      const response = responseCapture();
      await restoreHandler({ url: '/api/restore', method: 'POST',
        headers: { authorization: await authorization() }, body: { id: id.toUpperCase() } }, response);
      assert.equal(response.code, 200);
      assert.deepEqual(response.body, { id, ownerId: ownerB, contentHash: hash, restored: true });
      assert.deepEqual(notes.get(id), originalBackup);
      assert.deepEqual(notes.get(otherId), otherBefore);
      assert.deepEqual(backups.get(id), originalBackup);
      assert.equal(response.headers['cache-control'], 'no-store');
      assert.equal(response.headers['x-aleph-resource-id'], 'notes');
      assert.equal(JSON.stringify(response).includes(content), false);
    }
    assert.deepEqual(audit, ['fixture-existing-audit', 'backup_verified', 'restored', 'restored']);
    assert.deepEqual(logs, []);
  }, async (url, options) => {
    assert.equal(options.method, 'POST');
    assert.equal(options.headers.apikey, key);
    assert.equal(options.headers.Authorization, undefined);
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    const input = JSON.parse(options.body);
    assert.equal(input.p_owner_id, ownerB);
    assert.equal(input.p_run_id, runId);
    assert.equal(input.p_note_id, id);
    if (url.pathname === '/rest/v1/rpc/aleph_create_test_note') {
      assert.equal(input.p_content_hash, hash);
      const row = { id, owner_id: ownerB, title: input.p_title, content: input.p_content };
      notes.set(id, row); backups.set(id, structuredClone(row)); audit.push('backup_verified');
    } else {
      assert.equal(url.pathname, '/rest/v1/rpc/aleph_restore_test_note');
      assert.deepEqual(Object.keys(input).sort(), ['p_note_id', 'p_owner_id', 'p_run_id']);
      notes.set(id, structuredClone(backups.get(id))); audit.push('restored');
    }
    return new Response(JSON.stringify({ id, owner_id: ownerB, content_hash: hash }));
  });
});

test('anonymous, signed A, forged role, invalid method/path/body cannot reach restore RPC', async () => {
  await configured(async ({ calls, logs }) => {
    const signedB = await authorization();
    for (const [request, expected] of [
      [{ url: '/api/restore', method: 'POST', headers: {}, body: { id } }, 401],
      [{ url: '/api/restore', method: 'POST', headers: { authorization: 'invalid', role: 'judge', identity: 'b' }, body: { id } }, 401],
      [{ url: '/api/restore', method: 'POST', headers: { authorization: await authorization('a'), identity: 'b' }, body: { id } }, 403],
      [{ url: '/api/restore', method: 'POST', headers: { authorization: await authorization('b', {
        iss: config.identityProvider.issuer, aud: config.identityProvider.audience, role: 'authenticated',
      }) }, body: { id } }, 403],
      [{ url: '/api/restore', method: 'GET', headers: { authorization: signedB }, body: { id } }, 405],
      [{ url: '/api/restore?id=other', method: 'POST', headers: { authorization: signedB }, body: { id } }, 404],
      [{ url: '/api/restore', method: 'POST', headers: { authorization: signedB }, body: { id, owner_id: ownerA } }, 400],
      [{ url: '/api/restore', method: 'POST', headers: { authorization: signedB }, body: { id: 'all' } }, 400],
      [{ url: '/api/restore', method: 'POST', headers: { authorization: signedB }, body: { id, title: randomUUID(), hash: '0'.repeat(64) } }, 400],
    ]) {
      const response = responseCapture(); await restoreHandler(request, response); assert.equal(response.code, expected);
    }
    assert.equal(calls.length, 0);
    assert.equal(JSON.stringify(logs).includes(ownerB), false);
    assert.equal(JSON.stringify(logs).includes(key), false);
  }, async () => { throw new Error('must-not-rpc'); });
});

test('missing backup, owner conflict, invalid digest and unavailable schema stop with only short codes', async () => {
  await configured(async () => {
    for (const [code, message, expected] of [
      ['P0001', 'NOTE_BACKUP_NOT_FOUND', 404], ['P0001', 'NOTE_OWNER_CONFLICT', 409],
      ['P0001', 'NOTE_BACKUP_INVALID', 409], ['P0001', 'NOTE_RESTORE_MISMATCH', 409],
      ['PGRST202', 'private-upstream-details', 503], ['other', key, 502],
    ]) {
      rpcResponse = new Response(JSON.stringify({ code, message }), { status: 400 });
      const response = responseCapture();
      await restoreHandler({ url: '/api/restore', method: 'POST',
        headers: { authorization: await authorization() }, body: { id } }, response);
      assert.equal(response.code, expected);
      assert.equal(JSON.stringify(response).includes(key), false);
      assert.equal(JSON.stringify(response).includes('private-upstream-details'), false);
    }
  }, async () => rpcResponse);
});
let rpcResponse;

test('server validates recovered summary and never echoes untrusted database output', async () => {
  await configured(async () => {
    for (const result of [
      { id: otherId, owner_id: ownerB, content_hash: '0'.repeat(64) },
      { id, owner_id: ownerA, content_hash: '0'.repeat(64) },
      { id, owner_id: ownerB, content_hash: 'invalid' },
      { id, owner_id: ownerB, content_hash: '0'.repeat(64), content: key },
    ]) {
      rpcResponse = new Response(JSON.stringify(result));
      const response = await callNoteRecovery({ operation: 'restore', login: loginB, id,
        project: process.env.SUPABASE_URL, secret: key });
      assert.deepEqual(response, { status: 502, error: 'NOTE_RECOVERY_UNAVAILABLE' });
    }
    rpcResponse = new Response(JSON.stringify({ id, owner_id: ownerB, content_hash: '0'.repeat(64) }));
    const created = await callNoteRecovery({ operation: 'create', login: loginB, id,
      title: randomUUID(), content: randomUUID(), project: process.env.SUPABASE_URL, secret: key });
    assert.equal(created.status, 502);
  }, async () => rpcResponse);
});

test('SQL schema keeps immutable backups, append-only audit and server-only invoker functions', async () => {
  const sql = await readFile(new URL('../docs/STEP10_NOTE_RECOVERY.sql', import.meta.url), 'utf8');
  assert.equal((sql.match(/security invoker/gu) ?? []).length, 2);
  assert.equal(/security definer/iu.test(sql), false);
  assert.match(sql, /enable row level security/iu);
  assert.match(sql, /grant select, insert on aleph_recovery\.note_backups, aleph_recovery\.note_audit to service_role/iu);
  assert.match(sql, /where public\.notes\.owner_id = p_owner_id/iu);
  assert.match(sql, /from public, anon, authenticated;/iu);
  assert.equal(/delete from|truncate|drop table/iu.test(sql), false);
});
