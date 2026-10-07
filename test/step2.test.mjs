import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const root = new URL('../', import.meta.url);
// Keep the previous stage's regression checks independent of the current stage.
const config = { ...JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8')), step: 2 };

test('stage 2 build never republishes restored source or stale public notes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step2-'));
  try {
    for (const path of ['scripts', 'public', 'aleph.config.json']) {
      await cp(new URL(path, root), join(directory, path), { recursive: true });
    }
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify(config));
    const marker = 'restored-private-note-for-build-test';
    const contaminated = JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1',
      notes: [{ title: 'test', content: marker }] });
    await writeFile(join(directory, 'data.json'), contaminated);
    await writeFile(join(directory, 'public', 'data.json'), contaminated);
    execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'], {
      cwd: directory, windowsHide: true, stdio: 'pipe',
    });
    const built = await readFile(join(directory, 'public', 'data.json'), 'utf8');
    assert.deepEqual(JSON.parse(built), { notes: [] });
    assert.ok(!built.includes(marker));
    assert.ok(!built.includes('SAMPLE_NOTE_1'));
    await assert.rejects(readFile(join(directory, 'public', 'aleph.json'), 'utf8'), { code: 'ENOENT' });
    // Even a missing source file cannot cause this build to expose old notes.
    await rm(join(directory, 'data.json'));
    execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'], {
      cwd: directory, windowsHide: true, stdio: 'pipe',
    });
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public', 'data.json'), 'utf8')),
      { notes: [] });
    // A deployment must also replace stale stage-1 identity metadata.
    await writeFile(join(directory, 'public', 'aleph.json'),
      JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1' }));
    execFileSync(process.execPath, ['scripts/build-public.mjs'], {
      cwd: directory, windowsHide: true, stdio: 'pipe',
      env: { ...process.env, VERCEL_GIT_PROVIDER: 'github',
        VERCEL_GIT_REPO_OWNER: 'RockCandy444', VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
        VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'stage2-build-test.vercel.app' },
    });
    for (const path of ['index.html', 'data.json', 'aleph.json']) {
      const output = await readFile(join(directory, 'public', path), 'utf8');
      assert.ok(!output.includes('SAMPLE_NOTE_1'), `Stage-1 marker remains in ${path}`);
      assert.ok(!output.includes(marker), `Restored note remains in ${path}`);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('source and public data contain no notes', async () => {
  assert.equal(config.step, 2);
  for (const path of ['data.json', 'public/data.json']) {
    assert.deepEqual(JSON.parse(await readFile(new URL(path, root), 'utf8')),
      { notes: [] });
  }
});

test('deployment identity records stage 2 and still rejects absent metadata', () => {
  const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'RockCandy444',
    VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
    VERCEL_URL: 'choi-bujang-secret-vault-liard.vercel.app' };
  assert.equal(deploymentIdentity(env, config).step, 2);
  assert.equal(Object.hasOwn(deploymentIdentity(env, config), 'sampleMarker'), false);
  assert.equal(Object.hasOwn(deploymentIdentity(env, { ...config, sampleMarker: 'SAMPLE_NOTE_1' }),
    'sampleMarker'), false);
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: undefined }, config));
});

test('stage 2 anonymous check rejects leaked notes and invalid responses', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const [status, payload, allowed] of [
      [200, { notes: [] }, true],
      [200, { notes: [], sampleMarker: 'SAMPLE_NOTE_1' }, false],
      [200, { notes: [{ title: 'test' }] }, false],
      [200, { notes: [], content: 'unexpected' }, false],
      [200, '<html>not JSON</html>', false],
      [404, {}, false],
    ]) {
      globalThis.fetch = async (url, options) => {
        assert.equal(options.redirect, 'error');
        if (String(url) === `${config.publicAppUrl}/api/notes`) {
          assert.equal(options.headers, undefined);
          return new Response('{}', { status: options.method === 'POST' ? 405 : 503 });
        }
        if (String(url) === `${config.publicAppUrl}/data.json`) {
          assert.equal(options.headers, undefined);
          return new Response(typeof payload === 'string' ? payload : JSON.stringify(payload), { status });
        }
        assert.deepEqual(options.headers, { 'Cache-Control': 'no-cache' });
        return new Response('{}');
      };
      const [result] = await runAttackChecks(config);
      assert.equal(result.attackId, 'anonymous_static_note_read');
      assert.equal(result.observed.includes('빈 메모 목록'), allowed);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('checkpoint checks distinguish public reads, missing configuration, and method rejection', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const [status, payload, expected] of [
      [503, { error: 'NOTES_NOT_CONFIGURED' }, '네 건 조회 미확인이며 인증 거부가 아님'],
      [200, { notes: Array.from({ length: 4 }, () => ({ title: 'test', content: 'test' })) }, '공개 주소의 약점'],
      [502, { error: 'sensitive-upstream-error-for-test' }, '네 건 조회 미확인'],
    ]) {
      globalThis.fetch = async (url, options) => {
        if (String(url).endsWith('/data.json')) {
          return new Response(JSON.stringify({ notes: [] }));
        }
        if (!String(url).endsWith('/api/notes')) return new Response('{}');
        assert.equal(String(url), `${config.publicAppUrl}/api/notes`);
        if (options.method === 'POST') return new Response('{}', { status: 405 });
        return new Response(JSON.stringify(payload), { status });
      };
      const results = await runAttackChecks(config);
      assert.equal(results.length, 4);
      assert.ok(results[1].observed.includes(expected));
      assert.ok(!JSON.stringify(results).includes('sensitive-upstream-error-for-test'));
      assert.equal(results[2].attackId, 'public_api_write_rejected');
      assert.ok(results[2].observed.includes('HTTP 405'));
    }
  } finally { globalThis.fetch = originalFetch; }
});

test('stage 2 static check catches the old marker in any static response and HTTP failures', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const failingPath of [null, '/', '/index.html', '/data.json', '/aleph.json', '/aleph.json-missing']) {
      const seen = [];
      globalThis.fetch = async (url, options) => {
        const path = new URL(url).pathname;
        seen.push(path);
        if (path === '/api/notes') return new Response('{}', { status: options.method === 'POST' ? 405 : 503 });
        if (failingPath === '/aleph.json-missing' && path === '/aleph.json') return new Response('{}', { status: 404 });
        if (path === failingPath) return new Response('SAMPLE_NOTE_1');
        return new Response(path === '/data.json' ? JSON.stringify({ notes: [] }) : '{}');
      };
      const results = await runAttackChecks(config);
      const result = results.find(item => item.attackId === 'static_stage1_marker_absent');
      assert.ok(result);
      assert.equal(result.observed.includes('점검 실패'), failingPath !== null);
      if (failingPath) assert.ok(result.observed.includes(failingPath.replace('-missing', '')));
      assert.ok(!result.observed.includes('SAMPLE_NOTE_1'));
      assert.deepEqual(seen.filter(path => path !== '/api/notes'), ['/data.json', '/', '/index.html', '/aleph.json']);
    }
  } finally { globalThis.fetch = originalFetch; }
});
