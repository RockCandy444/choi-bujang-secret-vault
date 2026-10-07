import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAttackChecks } from '../src/attack-check.mjs';

const root = new URL('../', import.meta.url);
const config = JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8'));

test('stage 3 deployment builds empty static data and the checked Git identity', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step3-'));
  try {
    for (const path of ['scripts', 'aleph.config.json']) {
      await cp(new URL(path, root), join(directory, path), { recursive: true });
    }
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: directory,
      windowsHide: true, stdio: 'pipe', env: { ...process.env, VERCEL_GIT_PROVIDER: 'github',
        VERCEL_GIT_REPO_OWNER: 'RockCandy444', VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
        VERCEL_GIT_COMMIT_SHA: 'b'.repeat(40), VERCEL_URL: 'stage3-build-test.vercel.app' } });
    const data = JSON.parse(await readFile(join(directory, 'public/data.json'), 'utf8'));
    const identity = JSON.parse(await readFile(join(directory, 'public/aleph.json'), 'utf8'));
    assert.deepEqual(data, { notes: [] });
    assert.equal(identity.step, 3);
    assert.equal(identity.commit, 'b'.repeat(40));
    assert.equal(Object.hasOwn(identity, 'sampleMarker'), false);
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify({ ...config, step: 4 }));
    assert.throws(() => execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'],
      { cwd: directory, windowsHide: true, stdio: 'pipe' }));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const leaked of [false, true]) {
  test(`stage 3 self-check records real requests, rejects data leakage=${leaked} and leaves A unrun`, async () => {
    const originalFetch = globalThis.fetch;
    const seen = [];
    try {
      globalThis.fetch = async (input, options) => {
        const path = new URL(input).pathname;
        if (path.startsWith('/api/notes')) {
          seen.push({ path, options });
          assert.equal(options.body, undefined);
          assert.ok(!options.headers || options.headers.Authorization === 'Bearer invalid');
          return new Response(JSON.stringify(leaked ? { error: 'LOGIN_REQUIRED', notes: ['private-test-data'] }
            : { error: 'LOGIN_REQUIRED' }), { status: 401 });
        }
        return new Response(JSON.stringify(path === '/data.json' ? { notes: [] }
          : path === '/aleph.json' ? { step: 3 } : {}));
      };
      const results = await runAttackChecks(config);
      assert.equal(seen.length, 10);
      assert.deepEqual(seen.slice(0, 5).map(item => item.options.method), ['GET', 'POST', 'GET', 'PUT', 'DELETE']);
      assert.equal(seen[2].path, seen[4].path);
      const denies = results.filter(item => item.attackId.endsWith('_denied'));
      assert.equal(denies.length, 10);
      assert.ok(denies.every(item => item.observed.includes(leaked ? '점검 실패' : '자료 없음')));
      assert.match(results.find(item => item.attackId === 'authenticated_a_crud').observed, /미실행/u);
      assert.ok(!JSON.stringify(results).includes('private-test-data'));
      assert.equal(results.length, 14);
    } finally { globalThis.fetch = originalFetch; }
  });
}
