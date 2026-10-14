import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, cp, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = { ...JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8')), step: 10 };
const environment = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'RockCandy444',
  VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'stage10-build-test.vercel.app' };

test('stage 10 identity matches the implemented recovery route without changing issuer or original API', () => {
  assert.equal(config.step, 10);
  assert.equal(config.restoreRoute, '/api/restore');
  const identity = deploymentIdentity(environment, config);
  assert.deepEqual(identity.restoreRoute, config.restoreRoute);
  assert.equal(identity.judgeIssuer, config.judgeIssuer);
  assert.equal(identity.originalApiUrl, config.originalApiUrl);
  assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
  assert.ok(identity.allowedRoutes.includes('POST /api/restore'));
  for (const invalid of [null, '', '/api/notes', 'POST /api/restore',
    { service: 'notes', method: 'POST', path: '/api/restore' }]) {
    assert.throws(() => deploymentIdentity(environment, { ...config, restoreRoute: invalid }));
  }
  assert.throws(() => deploymentIdentity(environment, { ...config,
    allowedRoutes: config.allowedRoutes.filter(route => route !== 'POST /api/restore') }));
});

test('stage 10 isolated deployment keeps both static note sources empty and records recovery metadata', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step10-'));
  assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
  assert.ok(basename(directory).startsWith('aleph-step10-'));
  try {
    await cp(new URL('../scripts/', import.meta.url), join(directory, 'scripts'), { recursive: true });
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify(config));
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: directory, windowsHide: true,
      stdio: 'pipe', env: { ...process.env, ...environment } });
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public/data.json'), 'utf8')), { notes: [] });
    const identity = JSON.parse(await readFile(join(directory, 'public/aleph.json'), 'utf8'));
    assert.equal(identity.step, 10);
    assert.equal(identity.commit, environment.VERCEL_GIT_COMMIT_SHA);
    assert.equal(identity.restoreRoute, '/api/restore');
    assert.equal(identity.judgeIssuer, config.judgeIssuer);
    assert.deepEqual(JSON.parse(await readFile(new URL('../data.json', import.meta.url), 'utf8')), { notes: [] });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('stage 10 self-check records only actual anonymous/invalid requests and retains recovery as unrun', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const scenario of ['ok', 'old_commit', 'wrong_restore', 'object_restore', 'leaked_denial']) {
      const requests = [];
      globalThis.fetch = async (input, options) => {
        const url = new URL(input);
        assert.equal(url.origin, new URL(config.publicAppUrl).origin);
        assert.equal(options.body, undefined);
        assert.ok(!options.headers?.Authorization || options.headers.Authorization === 'Bearer invalid');
        requests.push({ path: url.pathname, method: options.method });
        if (url.pathname.startsWith('/api/')) {
          const restore = url.pathname === '/api/restore';
          return new Response(JSON.stringify(restore && scenario === 'leaked_denial'
            ? { error: 'LOGIN_REQUIRED', extra: 'private-fixture-must-not-be-recorded' }
            : { error: 'LOGIN_REQUIRED' }), { status: 401, headers: {
            'X-Aleph-Resource-Id': url.pathname === '/api/notices' ? 'instructor_notices' : 'notes' } });
        }
        const identity = deploymentIdentity(environment, config);
        if (scenario === 'old_commit') identity.commit = 'b'.repeat(40);
        if (scenario === 'wrong_restore') identity.restoreRoute = '/other';
        if (scenario === 'object_restore') identity.restoreRoute = { service:'notes', method:'POST', path:'/api/restore' };
        return new Response(JSON.stringify(url.pathname === '/data.json' ? { notes: [] }
          : url.pathname === '/aleph.json' ? identity : {}), { headers: { 'X-Content-Type-Options': 'nosniff' } });
      };
      const results = await runAttackChecks({ ...config, expectedCommit: environment.VERCEL_GIT_COMMIT_SHA });
      assert.equal(requests.length, 20);
      assert.equal(requests.filter(item => item.path === '/api/restore' && item.method === 'POST').length, 2);
      assert.equal(results.length, 20);
      assert.equal(new Set(results.map(item => item.attackId)).size, 20);
      assert.equal(results.filter(item => item.observed.startsWith('미실행:')).length, 5);
      const identity = results.find(item => item.attackId === 'deployment_stage10_identity');
      assert.equal(identity.observed.includes('미확인'), ['old_commit', 'wrong_restore', 'object_restore'].includes(scenario));
      const restore = results.find(item => item.attackId === 'restore_anonymous_invalid_denied');
      assert.equal(restore.observed.includes('점검 실패'), scenario === 'leaked_denial');
      assert.ok(results.find(item => item.attackId === 'verified_policy_and_b_recovery').observed.startsWith('미실행:'));
      assert.ok(results.find(item => item.attackId === 'post_recovery_regression').observed.startsWith('미실행:'));
      assert.equal(JSON.stringify(results).includes('private-fixture-must-not-be-recorded'), false);
    }
  } finally { globalThis.fetch = originalFetch; }
});
