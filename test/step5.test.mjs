import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { runAttackChecks } from '../src/attack-check.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

const root = new URL('../', import.meta.url);
const config = { ...JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8')), step: 5 };

test('stage 5 build keeps restored note bodies private and emits the current stage', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step5-'));
  try {
    for (const path of ['scripts', 'aleph.config.json']) {
      await cp(new URL(path, root), join(directory, path), { recursive: true });
    }
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify(config));
    await writeFile(join(directory, 'data.json'), JSON.stringify({ notes: ['synthetic-stale-note'] }));
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: directory,
      windowsHide: true, stdio: 'pipe', env: { ...process.env, VERCEL_GIT_PROVIDER: 'github',
        VERCEL_GIT_REPO_OWNER: 'RockCandy444', VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
        VERCEL_GIT_COMMIT_SHA: 'd'.repeat(40), VERCEL_URL: 'stage5-build-test.vercel.app' } });
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public/data.json'), 'utf8')), { notes: [] });
    const identity = JSON.parse(await readFile(join(directory, 'public/aleph.json'), 'utf8'));
    assert.equal(identity.step, 5);
    assert.equal(identity.originalApiUrl, config.originalApiUrl);
    assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
    assert.equal(identity.commit, 'd'.repeat(40));
    assert.equal(Object.hasOwn(identity, 'sampleMarker'), false);
    execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'],
      { cwd: directory, windowsHide: true, stdio: 'pipe' });
    await assert.rejects(readFile(join(directory, 'public/aleph.json')), { code: 'ENOENT' });
  } finally {
    assert.ok(resolve(directory).startsWith(`${resolve(tmpdir())}${sep}aleph-step5-`));
    await rm(directory, { recursive: true, force: true });
  }
});

for (const [deployedStep, originalPresent] of [[4, false], [5, false], [5, true]]) {
  test(`stage 5 self-check records deployed step ${deployedStep}, original URL present=${originalPresent}, without inventing results`, async () => {
    const originalFetch = globalThis.fetch;
    const requests = [];
    try {
      globalThis.fetch = async (input, options) => {
        const url = new URL(input);
        assert.equal(url.origin, new URL(config.publicAppUrl).origin);
        assert.equal(options.body, undefined);
        requests.push(url.pathname);
        if (url.pathname.startsWith('/api/notes')) {
          assert.ok(!options.headers || options.headers.Authorization === 'Bearer invalid');
          return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401 });
        }
        return new Response(JSON.stringify(url.pathname === '/data.json' ? { notes: [] }
          : url.pathname === '/aleph.json' ? { step: deployedStep,
            ...(originalPresent ? { originalApiUrl: config.originalApiUrl,
              allowedRoutes: config.allowedRoutes } : {}) } : {}),
          { headers: { 'X-Content-Type-Options': 'nosniff' } });
      };
      const results = await runAttackChecks(config);
      assert.equal(requests.length, 14);
      assert.equal(results.length, 20);
      const identity = results.find(item => item.attackId === 'deployment_stage5_identity');
      assert.equal(identity.observed.includes('step 5 확인'), deployedStep === 5 && originalPresent);
      for (const id of ['authenticated_a_crud', 'authenticated_b_crud',
        'foreign_note_access_denied', 'owner_change_denied', 'owner_notes_preserved',
        'original_api_anon_denied', 'notes_direct_privileges_revoked']) {
        assert.match(results.find(item => item.attackId === id).observed, /미실행/u);
      }
      assert.equal(new Set(results.map(item => item.attackId)).size, 20);
    } finally { globalThis.fetch = originalFetch; }
  });
}

test('stage 5 deployment refuses missing, credential-bearing or queried original URLs', () => {
  const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'Student-A',
    VERCEL_GIT_REPO_SLUG: 'aleph-defense', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
    VERCEL_URL: 'stage5-test.vercel.app' };
  const credentialUrl = new URL('https://source.test/notes');
  credentialUrl.username = 'synthetic';
  credentialUrl.password = 'fixture';
  for (const originalApiUrl of [null, '', 'http://source.test/notes',
    'https://source.test/notes?select=id', 'https://source.test/notes#fragment',
    'https://source.test/notes?', 'https://source.test/notes#',
    credentialUrl.href, 'https://source.test/']) {
    assert.throws(() => deploymentIdentity(env, { ...config, originalApiUrl }));
  }
});

test('stage 5 deployment refuses absent or malformed allowed routes', () => {
  const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'Student-A',
    VERCEL_GIT_REPO_SLUG: 'aleph-defense', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
    VERCEL_URL: 'stage5-test.vercel.app' };
  for (const allowedRoutes of [undefined, [], ['GET /api/notes?key=fixture'], ['invalid']]) {
    assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes }));
  }
});

test('stage 5 self-check catches each missing bonus without printing keys', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const missing of ['routes', 'header', 'key']) {
      globalThis.fetch = async input => {
        const path = new URL(input).pathname;
        if (path.startsWith('/api/notes')) return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401 });
        const body = path === '/data.json' ? JSON.stringify({ notes: [] })
          : path === '/aleph.json' ? JSON.stringify({ step: 5, originalApiUrl: config.originalApiUrl,
            ...(missing === 'routes' ? {} : { allowedRoutes: config.allowedRoutes }) })
          : missing === 'key' ? ['sb', 'publishable', 'synthetic_fixture'].join('_') : '{}';
        return new Response(body, { headers: missing === 'header' ? {} : { 'X-Content-Type-Options': 'nosniff' } });
      };
      const results = await runAttackChecks(config);
      const result = results.find(r => r.attackId === (missing === 'routes'
        ? 'deployment_stage5_identity' : 'static_stage1_marker_absent'));
      assert.match(result.observed, /미확인|점검 실패/u);
      assert.ok(!JSON.stringify(results).includes('synthetic_fixture'));
    }
  } finally { globalThis.fetch = originalFetch; }
});
