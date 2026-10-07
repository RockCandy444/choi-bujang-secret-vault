import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAttackChecks } from '../src/attack-check.mjs';

const root = new URL('../', import.meta.url);
const config = { ...JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8')), step: 4 };

test('stage 4 build removes stale notes and records stage 4 deployment identity', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step4-'));
  try {
    for (const path of ['scripts', 'aleph.config.json']) {
      await cp(new URL(path, root), join(directory, path), { recursive: true });
    }
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify(config));
    assert.equal(config.step, 4);
    await writeFile(join(directory, 'data.json'), 'source must never be read');
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: directory,
      windowsHide: true, stdio: 'pipe', env: { ...process.env, VERCEL_GIT_PROVIDER: 'github',
        VERCEL_GIT_REPO_OWNER: 'RockCandy444', VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
        VERCEL_GIT_COMMIT_SHA: 'c'.repeat(40), VERCEL_URL: 'stage4-build-test.vercel.app' } });
    const identity = JSON.parse(await readFile(join(directory, 'public/aleph.json'), 'utf8'));
    assert.equal(identity.step, 4);
    assert.equal(identity.commit, 'c'.repeat(40));
    assert.equal(identity.judgeIssuer, config.judgeIssuer);
    assert.equal(Object.hasOwn(identity, 'sampleMarker'), false);
    await writeFile(join(directory, 'public/data.json'), JSON.stringify({ notes: ['stale-note'] }));
    execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'],
      { cwd: directory, windowsHide: true, stdio: 'pipe' });
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public/data.json'), 'utf8')), { notes: [] });
    await assert.rejects(readFile(join(directory, 'public/aleph.json')), { code: 'ENOENT' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const deployedStep of [3, 4]) {
  test(`stage 4 self-check distinguishes deployed step ${deployedStep} and never invents A/B success`, async () => {
    const originalFetch = globalThis.fetch;
    const seen = [];
    try {
      globalThis.fetch = async (input, options) => {
        const path = new URL(input).pathname;
        seen.push({ path, options });
        assert.equal(options.body, undefined);
        if (path.startsWith('/api/notes')) {
          assert.ok(!options.headers || options.headers.Authorization === 'Bearer invalid');
          return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401 });
        }
        return new Response(JSON.stringify(path === '/data.json' ? { notes: [] }
          : path === '/aleph.json' ? { step: deployedStep } : {}));
      };
      const results = await runAttackChecks(config);
      assert.equal(seen.length, 14);
      assert.equal(results.length, 18);
      assert.ok(results.filter(item => item.attackId.endsWith('_denied')
        && /^(anonymous|invalid_login)_/u.test(item.attackId))
        .every(item => item.observed.includes('자료 없음')));
      const identity = results.find(item => item.attackId === 'deployment_stage4_identity');
      assert.equal(identity.observed.includes('step 4 확인'), deployedStep === 4);
      for (const id of ['authenticated_a_crud', 'authenticated_b_crud',
        'foreign_note_access_denied', 'owner_change_denied', 'owner_notes_preserved']) {
        assert.match(results.find(item => item.attackId === id).observed, /미실행/u);
      }
      assert.deepEqual(config.allowedRoutes, ['GET /api/notes', 'POST /api/notes',
        'GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id']);
    } finally { globalThis.fetch = originalFetch; }
  });
}
