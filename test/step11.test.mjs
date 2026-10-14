import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, cp, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import statusHandler from '../api/device/status.js';
import requestHandler from '../api/device/request.js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const root = new URL('../', import.meta.url);
const config = { ...JSON.parse(await readFile(new URL('aleph.config.json', root), 'utf8')), step: 11 };
const environment = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'RockCandy444',
  VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'stage11-build-test.vercel.app' };
function capture() {
  return { headers: {}, setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
    status(value) { this.code = value; return this; }, json(value) { this.body = value; return this; } };
}

test('unconfigured device control cannot approve a login, client flag, or installation', () => {
  for (const [handler, method] of [[statusHandler, 'GET'], [requestHandler, 'POST']]) {
    const response = capture();
    handler({ method, headers: { host: 'localhost:3000', origin: 'http://localhost:3000',
      authorization: 'Bearer invalid', 'x-device-approved': 'true' },
      body: { approved: true, deviceRegistered: true, installed: true } }, response);
    assert.equal(response.code, 503);
    assert.deepEqual(response.body, { approved: false, error: 'DEVICE_APPROVAL_NOT_CONFIGURED' });
    assert.equal(response.headers['cache-control'], 'no-store');
    const unsupported = capture(); handler({ method: 'DELETE' }, unsupported);
    assert.equal(unsupported.code, 405);
    assert.equal(unsupported.body.approved, false);
  }
  for (const origin of [undefined, 'https://untrusted.test', 'http://localhost:3000/?flag=1']) {
    const response = capture();
    requestHandler({ method: 'POST', headers: { host: 'localhost:3000', origin } }, response);
    assert.equal(response.code, 403);
    assert.equal(response.body.approved, false);
  }
});

test('stage 11 isolated build ships manifest/icons with empty notes and retains recovery and issuer', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step11-'));
  try {
    for (const path of ['scripts', 'public', 'aleph.config.json']) {
      await cp(new URL(path, root), join(directory, path), { recursive: true });
    }
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify(config));
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: directory, windowsHide: true,
      stdio: 'pipe', env: { ...process.env, ...environment } });
    const identity = JSON.parse(await readFile(join(directory, 'public/aleph.json'), 'utf8'));
    assert.equal(identity.step, 11);
    assert.equal(identity.restoreRoute, '/api/restore');
    assert.equal(identity.judgeIssuer, config.judgeIssuer);
    assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public/data.json'), 'utf8')), { notes: [] });
    const html = await readFile(join(directory, 'public/index.html'), 'utf8');
    const manifest = JSON.parse(await readFile(join(directory, 'public/manifest.webmanifest'), 'utf8'));
    assert.equal(manifest.name, 'BYTE BACK 내 자료실');
    assert.equal(manifest.display, 'standalone');
    assert.equal(manifest.start_url, '/'); assert.equal(manifest.scope, '/');
    for (const size of [192, 512]) {
      const icon = manifest.icons.find(item => item.sizes === `${size}x${size}`);
      const bytes = await readFile(join(directory, 'public', icon.src));
      assert.equal(bytes.readUInt32BE(16), size); assert.equal(bytes.readUInt32BE(20), size);
    }
    assert.match(html, /href="\/manifest.webmanifest"/u);
    assert.doesNotMatch(html, /localStorage|sessionStorage|indexedDB|caches\.|serviceWorker/u);
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify({ ...config, step: 13 }));
    assert.throws(() => execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'],
      { cwd: directory, windowsHide: true, stdio: 'pipe' }));
  } finally {
    assert.ok(resolve(directory).startsWith(`${resolve(tmpdir())}${sep}aleph-step11-`));
    await rm(directory, { recursive: true, force: true });
  }
});

test('stage 11 self-check uses real response shapes and leaves registered/signature cases unrun', async () => {
  const previousFetch = globalThis.fetch;
  try {
    for (const bad of [false, true]) {
      const calls = [];
      globalThis.fetch = async (input, options) => {
        const path = new URL(input).pathname;
        calls.push(path);
        assert.equal(options.body, undefined);
        assert.ok(!options.headers?.Authorization || options.headers.Authorization === 'Bearer invalid');
        if (path.startsWith('/api/device/')) return new Response(JSON.stringify(bad
          ? { approved: true, reason: 'untrusted' }
          : { approved: false, error: 'DEVICE_APPROVAL_NOT_CONFIGURED' }), { status: bad ? 200 : 503 });
        if (path.startsWith('/api/')) return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401,
          headers: { 'X-Aleph-Resource-Id': path === '/api/notices' ? 'instructor_notices' : 'notes' } });
        if (path === '/manifest.webmanifest' || path.startsWith('/icons/')) {
          return new Response(await readFile(new URL('public' + path, root)));
        }
        return new Response(path === '/data.json' ? JSON.stringify({ notes: [] })
          : path === '/aleph.json' ? JSON.stringify(deploymentIdentity(environment, config))
            : await readFile(new URL('public/index.html', root), 'utf8'),
          { headers: { 'X-Content-Type-Options': 'nosniff' } });
      };
      const results = await runAttackChecks({ ...config, expectedCommit: environment.VERCEL_GIT_COMMIT_SHA });
      assert.equal(results.length, 15);
      assert.equal(calls.length, 27);
      assert.equal(results.filter(item => item.observed.startsWith('미실행:')).length, 6);
      assert.equal(results.find(item => item.attackId === 'device_connection_unavailable').observed.includes('점검 실패'), bad);
      assert.doesNotMatch(results.find(item => item.attackId === 'app_manifest_and_icons').observed, /점검 실패/u);
      assert.match(results.find(item => item.attackId === 'registered_device_and_request_signatures').observed, /^미실행:/u);
    }
  } finally { globalThis.fetch = previousFetch; }
});
