import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const id = '11111111-1111-4111-8111-111111111111';
function request(method, path, route = `${method} /api/notes/:id`) {
  return { ...fixtureRequests().normal, method, path, route };
}
async function decision(input, expected) {
  const before = structuredClone(input);
  const output = await decide(input);
  assert.equal(output.decision, expected);
  assert.deepEqual(Object.keys(output).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.equal(output.requestId, input.requestId);
  assert.ok(output.ruleIds.every(rule => RULE_IDS.includes(rule)));
  assert.deepEqual(input, before);
  return output;
}

test('official engine demo read is restored without opening unknown IDs or bypassing device/step-up rules', async () => {
  const { normal, suspicious } = fixtureRequests();
  assert.equal(normal.path, '/notes/demo');
  await decision(normal, 'allow');
  await decision(suspicious, 'step_up');
  await decision({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, 'allow');
  const unregistered = await decision({ ...normal, deviceRegistered: false }, 'deny');
  assert.equal(unregistered.reasonCode, 'device_not_registered');
  for (const path of ['/notes/export', '/notes/all', '/notes/unknown', '/api/notes/demo']) {
    await decision({ ...normal, path }, 'deny');
  }
  await decision({ ...normal, route: 'GET /api/notes/:id' }, 'deny');
});

test('only exact GET and PUT note item routes pass the route gate; own list stays available', async () => {
  for (const method of ['GET', 'PUT']) {
    for (const prefix of ['/api/notes', '/notes']) {
      for (const suffix of ['', '/']) {
        await decision(request(method, `${prefix}/${id}${suffix}`, `${method} ${prefix}/:id`), 'allow');
      }
    }
  }
  await decision(request('GET', '/api/my/notes', 'GET /api/my/notes'), 'allow');
  await decision(request('GET', '/api/notes', 'GET /api/notes'), 'deny');
  await decision(request('PUT', '/api/notes', 'PUT /api/notes'), 'deny');
  for (const [path, route] of [['/api/notes/all', 'GET /api/notes/all'],
    ['/api/admin/notes', 'GET /api/admin/notes'], ['/api/my/notes/other', 'GET /api/my/notes/:id']]) {
    await decision(request('GET', path, route), 'deny');
  }
});

test('unknown paths, function names, encoding and mismatched method/route/service are denied', async () => {
  for (const path of ['/api/notes/export', '/notes/export', '/api/notes/all', '/api/notes/:id',
    `/api/notes/${id}/export`, `/api/notes/${id}/edit`, `/api/notes/${id}/..`,
    `/api/notes//${id}`, `/API/notes/${id}`, `/api/notes/%31${id.slice(1)}`,
    `/api/notes/${id}%2fexport`, `/api/notes/${id}?action=export`,
    `/api/notes/${id}#edit`, `https://route.invalid/api/notes/${id}`]) {
    await decision(request('GET', path), 'deny');
  }
  for (const override of [{ method: 'POST' }, { method: 'PATCH' }, { method: 'DELETE' },
    { route: 'PUT /api/notes/:id' }, { route: 'GET /api/notes' }, { service: 'other' }]) {
    await decision({ ...request('GET', `/api/notes/${id}`), ...override }, 'deny');
  }
});

test('opaque queries cannot select actions or override path IDs', async () => {
  for (const query of [`id=${id}`, 'action=export', 'method=PUT', 'role=instructor']) {
    await decision({ ...request('GET', `/api/notes/${id}`), queryLength: query.length,
      querySha256: createHash('sha256').update(query).digest('hex') }, 'deny');
  }
  for (const override of [{ queryLength: '0' }, { queryLength: -1 },
    { querySha256: '0'.repeat(64) }]) {
    await decision({ ...request('GET', `/api/notes/${id}`), ...override }, 'deny');
  }
});

test('notice writes remain denied without a verified instructor permission contract', async () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    for (const [path, route] of [['/api/notices', `${method} /api/notices`],
      [`/api/notices/${id}`, `${method} /api/notices/:id`]]) {
      const output = await decision(request(method, path, route), 'deny');
      assert.deepEqual(output.ruleIds, ['notices_write_denied']);
    }
  }
  await decision({ ...request('PUT', `/api/notices/${id}`, 'PUT /api/notices/:id'),
    role: 'instructor' }, 'deny');
});

test('missing engine identity/device and client-supplied ownership cannot grant access', async () => {
  for (const override of [{ subjectId: '' }, { subjectId: null }, { classId: '' },
    { projectId: '' }, { deviceId: '' }, { deviceId: 'not-verified' },
    { schema: 'other' }, { owner_id: 'learner_fixture' },
    { identity: { sub: 'learner_fixture' } }]) {
    await decision({ ...request('PUT', `/api/notes/${id}`), ...override }, 'deny');
  }
});

test('device and step-up rules still apply to note updates; confirmation never bypasses a bad path', async () => {
  const { suspicious } = fixtureRequests();
  const update = { ...suspicious, method: 'PUT', path: `/api/notes/${id}`, route: 'PUT /api/notes/:id' };
  await decision(update, 'step_up');
  await decision({ ...update, stepUp: { verified: true, authAgeSeconds: 60 } }, 'allow');
  const unregistered = await decision({ ...update, deviceRegistered: false }, 'deny');
  assert.equal(unregistered.reasonCode, 'device_not_registered');
  await decision({ ...update, path: '/api/notes/export',
    stepUp: { verified: true, authAgeSeconds: 60 } }, 'deny');
});
