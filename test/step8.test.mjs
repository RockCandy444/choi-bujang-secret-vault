import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { runAttackChecks } from '../src/attack-check.mjs';

const root = new URL('../', import.meta.url);
const config = { ...JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8')), step: 8 };

test('stage 8 isolated build keeps notes empty, emits current routes and preserves judge issuer', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step8-'));
  try {
    for (const path of ['scripts', 'aleph.config.json']) {
      await cp(new URL(path, root), join(directory, path), { recursive: true });
    }
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify(config));
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: directory,
      windowsHide: true, stdio: 'pipe', env: { ...process.env, VERCEL_GIT_PROVIDER: 'github',
        VERCEL_GIT_REPO_OWNER: 'RockCandy444', VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
        VERCEL_GIT_COMMIT_SHA: 'f'.repeat(40), VERCEL_URL: 'stage8-build-test.vercel.app' } });
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public/data.json'), 'utf8')), { notes: [] });
    const identity = JSON.parse(await readFile(join(directory, 'public/aleph.json'), 'utf8'));
    assert.equal(identity.step, 8);
    assert.equal(identity.originalApiUrl, config.originalApiUrl);
    assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
    assert.ok(identity.allowedRoutes.includes('GET /api/notices'));
    assert.equal(identity.judgeIssuer, config.judgeIssuer);
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify({ ...config, step: 12 }));
    assert.throws(() => execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'],
      { cwd: directory, windowsHide: true, stdio: 'pipe' }));
  } finally {
    assert.ok(resolve(directory).startsWith(`${resolve(tmpdir())}${sep}aleph-step8-`));
    await rm(directory, { recursive: true, force: true });
  }
});

test('stage 8 self-check sends notice requests, catches leakage and leaves authenticated cases unrun', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const leaked of [false, true]) {
      const requests = [];
      globalThis.fetch = async (input, options) => {
        const url = new URL(input);
        assert.equal(url.origin, new URL(config.publicAppUrl).origin);
        assert.equal(options.body, undefined);
        requests.push(url.pathname);
        if (url.pathname.startsWith('/api/notes') || url.pathname === '/api/my/notes' || url.pathname === '/api/notices') {
          assert.ok(!options.headers || options.headers.Authorization === 'Bearer invalid');
          const notice = url.pathname === '/api/notices';
          return new Response(JSON.stringify(notice && leaked
            ? { error: 'LOGIN_REQUIRED', extra: 'synthetic-private-response' } : { error: 'LOGIN_REQUIRED' }),
          { status: 401, headers: notice ? { 'X-Aleph-Resource-Id': 'instructor_notices' } : {} });
        }
        const body = url.pathname === '/data.json' ? { notes: [] }
          : url.pathname === '/aleph.json' ? { step: 8, originalApiUrl: config.originalApiUrl,
            allowedRoutes: config.allowedRoutes } : {};
        return new Response(JSON.stringify(body), { headers: { 'X-Content-Type-Options': 'nosniff' } });
      };
      const results = await runAttackChecks(config);
      assert.equal(requests.length, 18);
      assert.equal(results.length, 20);
      assert.equal(new Set(results.map(item => item.attackId)).size, 20);
      const notice = results.find(item => item.attackId === 'notice_anonymous_invalid_denied');
      assert.equal(notice.observed.includes('점검 실패'), leaked);
      assert.ok(!JSON.stringify(results).includes('synthetic-private-response'));
      assert.equal(results.filter(item => item.observed.startsWith('미실행:')).length, 6);
      assert.match(results.find(item => item.attackId === 'authenticated_a_b_crud').observed, /미실행.*API의 자기 요청 유지/u);
      assert.match(results.find(item => item.attackId === 'student_notice_write_denied').observed, /미실행/u);
    }
  } finally { globalThis.fetch = originalFetch; }
});
