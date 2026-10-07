import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { runAttackChecks } from '../src/attack-check.mjs';

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

for (const deployedStep of [4, 5]) {
  test(`stage 5 self-check records deployed step ${deployedStep} without inventing DB or authenticated results`, async () => {
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
          : url.pathname === '/aleph.json' ? { step: deployedStep } : {}));
      };
      const results = await runAttackChecks(config);
      assert.equal(requests.length, 14);
      assert.equal(results.length, 20);
      const identity = results.find(item => item.attackId === 'deployment_stage5_identity');
      assert.equal(identity.observed.includes('step 5 확인'), deployedStep === 5);
      for (const id of ['authenticated_a_crud', 'authenticated_b_crud',
        'foreign_note_access_denied', 'owner_change_denied', 'owner_notes_preserved',
        'original_api_anon_denied', 'notes_direct_privileges_revoked']) {
        assert.match(results.find(item => item.attackId === id).observed, /미실행/u);
      }
      assert.equal(new Set(results.map(item => item.attackId)).size, 20);
    } finally { globalThis.fetch = originalFetch; }
  });
}
