import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const root = new URL('../', import.meta.url);
const config = JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8'));

test('stage 2 build never republishes restored source or stale public notes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step2-'));
  try {
    for (const path of ['scripts', 'public', 'aleph.config.json']) {
      await cp(new URL(path, root), join(directory, path), { recursive: true });
    }
    const marker = 'restored-private-note-for-build-test';
    const contaminated = JSON.stringify({ sampleMarker: config.sampleMarker,
      notes: [{ title: 'test', content: marker }] });
    await writeFile(join(directory, 'data.json'), contaminated);
    await writeFile(join(directory, 'public', 'data.json'), contaminated);
    execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'], {
      cwd: directory, windowsHide: true, stdio: 'pipe',
    });
    const built = await readFile(join(directory, 'public', 'data.json'), 'utf8');
    assert.deepEqual(JSON.parse(built), { sampleMarker: config.sampleMarker, notes: [] });
    assert.ok(!built.includes(marker));
    // Even a missing source file cannot cause this build to expose old notes.
    await rm(join(directory, 'data.json'));
    execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'], {
      cwd: directory, windowsHide: true, stdio: 'pipe',
    });
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public', 'data.json'), 'utf8')),
      { sampleMarker: config.sampleMarker, notes: [] });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('source and public data contain no notes', async () => {
  assert.equal(config.step, 2);
  for (const path of ['data.json', 'public/data.json']) {
    assert.deepEqual(JSON.parse(await readFile(new URL(path, root), 'utf8')),
      { sampleMarker: config.sampleMarker, notes: [] });
  }
});

test('deployment identity records stage 2 and still rejects absent metadata', () => {
  const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'RockCandy444',
    VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
    VERCEL_URL: 'choi-bujang-secret-vault-liard.vercel.app' };
  assert.equal(deploymentIdentity(env, config).step, 2);
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: undefined }, config));
});

test('stage 2 anonymous check rejects leaked notes and invalid responses', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const [status, payload, allowed] of [
      [200, { sampleMarker: config.sampleMarker, notes: [] }, true],
      [200, { sampleMarker: config.sampleMarker, notes: [{ title: 'test' }] }, false],
      [200, { sampleMarker: config.sampleMarker, notes: [], content: 'unexpected' }, false],
      [200, '<html>not JSON</html>', false],
      [404, {}, false],
    ]) {
      globalThis.fetch = async (url, options) => {
        assert.equal(String(url), `${config.publicAppUrl}/data.json`);
        assert.equal(options.redirect, 'error');
        assert.equal(options.headers, undefined);
        return new Response(typeof payload === 'string' ? payload : JSON.stringify(payload), { status });
      };
      const [result] = await runAttackChecks(config);
      assert.equal(result.attackId, 'anonymous_static_note_read');
      assert.equal(result.observed.includes('빈 메모 목록'), allowed);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});
