import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { runAttackChecks } from '../src/attack-check.mjs';

const root = new URL('../', import.meta.url);
const config = { ...JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8')), step: 7 };

test('stage 7 isolated build emits empty notes and preserves original API/routes/judge issuer', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step7-'));
  try {
    for (const path of ['scripts', 'aleph.config.json']) {
      await cp(new URL(path, root), join(directory, path), { recursive: true });
    }
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify(config));
    await writeFile(join(directory, 'data.json'), JSON.stringify({ notes: ['synthetic-stale-note'] }));
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: directory,
      windowsHide: true, stdio: 'pipe', env: { ...process.env, VERCEL_GIT_PROVIDER: 'github',
        VERCEL_GIT_REPO_OWNER: 'RockCandy444', VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
        VERCEL_GIT_COMMIT_SHA: 'e'.repeat(40), VERCEL_URL: 'stage7-build-test.vercel.app' } });
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public/data.json'), 'utf8')), { notes: [] });
    const identity = JSON.parse(await readFile(join(directory, 'public/aleph.json'), 'utf8'));
    assert.equal(identity.step, 7);
    assert.equal(identity.originalApiUrl, config.originalApiUrl);
    assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
    assert.equal(identity.judgeIssuer, config.judgeIssuer);
    execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'],
      { cwd: directory, windowsHide: true, stdio: 'pipe' });
    await assert.rejects(readFile(join(directory, 'public/aleph.json')), { code: 'ENOENT' });
  } finally {
    assert.ok(resolve(directory).startsWith(`${resolve(tmpdir())}${sep}aleph-step7-`));
    await rm(directory, { recursive: true, force: true });
  }
});

test('stage 7 self-check keeps virtual confirmation separate from unrun live blocking', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const deployedStep of [6, 7]) {
      const requests = [];
      globalThis.fetch = async (input, options) => {
        const url = new URL(input);
        assert.equal(url.origin, new URL(config.publicAppUrl).origin);
        assert.equal(options.body, undefined);
        requests.push(url.pathname);
        if (url.pathname.startsWith('/api/notes')) {
          assert.ok(!options.headers || options.headers.Authorization === 'Bearer invalid');
          return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401 });
        }
        const body = url.pathname === '/data.json' ? { notes: [] }
          : url.pathname === '/aleph.json' ? { step: deployedStep,
            originalApiUrl: config.originalApiUrl, allowedRoutes: config.allowedRoutes } : {};
        return new Response(JSON.stringify(body), { headers: { 'X-Content-Type-Options': 'nosniff' } });
      };
      const results = await runAttackChecks(config);
      assert.equal(requests.length, 14);
      assert.equal(results.length, 20);
      assert.equal(new Set(results.map(item => item.attackId)).size, 20);
      const identity = results.find(item => item.attackId === 'deployment_stage7_identity');
      assert.equal(identity.observed.includes('step 7 확인'), deployedStep === 7);
      assert.equal(results.filter(item => item.observed.startsWith('미실행:')).length, 7);
      const liveConfirmation = results.find(item => item.attackId === 'authenticated_a_crud');
      assert.match(liveConfirmation.expected, /새 로그인 전 자료 차단·새 요청 재판정 허용/u);
      assert.match(liveConfirmation.observed, /미실행.*새 로그인 시각 검증 계약·자료 차단 연결 미확인/u);
    }
  } finally { globalThis.fetch = originalFetch; }
});
