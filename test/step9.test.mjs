import assert from 'node:assert/strict';
import test from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { readFile } from 'node:fs/promises';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));

test('stage 9 metadata preserves routes, original API and judge issuer', () => {
  assert.equal(config.step, 9);
  const identity = deploymentIdentity({ VERCEL_GIT_PROVIDER: 'github',
    VERCEL_GIT_REPO_OWNER: 'RockCandy444', VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
    VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'stage9-test.vercel.app' }, config);
  assert.equal(identity.step, 9);
  assert.equal(identity.judgeIssuer, config.judgeIssuer);
  assert.equal(identity.originalApiUrl, config.originalApiUrl);
  assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
  assert.ok(identity.allowedRoutes.includes('GET /api/my/notes'));
  assert.ok(identity.allowedRoutes.includes('GET /api/notices'));
});

test('stage 9 self-check preserves stage 8 protection checks, without inventing live revocation', async () => {
  const originalFetch = globalThis.fetch;
  try {
    const paths = [];
    globalThis.fetch = async (input, options) => {
      const url = new URL(input);
      assert.equal(url.origin, new URL(config.publicAppUrl).origin);
      assert.equal(options.body, undefined);
      assert.ok(!options.headers?.Authorization || options.headers.Authorization === 'Bearer invalid');
      paths.push(url.pathname);
      if (url.pathname.startsWith('/api/')) {
        return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401,
          headers: url.pathname === '/api/notices' ? { 'X-Aleph-Resource-Id': 'instructor_notices' } : {} });
      }
      const body = url.pathname === '/data.json' ? { notes: [] }
        : url.pathname === '/aleph.json' ? { step: 9, originalApiUrl: config.originalApiUrl,
          allowedRoutes: config.allowedRoutes } : {};
      return new Response(JSON.stringify(body), { headers: { 'X-Content-Type-Options': 'nosniff' } });
    };
    const results = await runAttackChecks(config);
    assert.equal(paths.length, 18);
    assert.equal(paths.filter(path => path === '/api/my/notes').length, 2);
    assert.equal(paths.filter(path => path === '/api/notices').length, 4);
    assert.equal(results.length, 20);
    assert.equal(new Set(results.map(item => item.attackId)).size, 20);
    assert.equal(results.filter(item => item.observed.startsWith('미실행:')).length, 6);
    assert.equal(results.some(item => /revocation|burst_read/u.test(item.attackId)), false);
    assert.match(results.find(item => item.attackId === 'deployment_stage9_identity').observed, /step 9 확인/u);
  } finally { globalThis.fetch = originalFetch; }
});
