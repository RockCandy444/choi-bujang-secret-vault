import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, cp, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { operationsSummary } from '../src/operations.mjs';
import handler from '../api/operations.js';
import { RULE_IDS } from '../src/decider.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const commit = 'a'.repeat(40);
const capture = () => ({ headers: {}, setHeader(key, value) { this.headers[key] = value; },
  status(value) { this.code = value; return this; }, json(value) { this.body = value; return this; } });

test('operation receipt correlates safe real responses and never invents engine results', async () => {
  const logs = [];
  const previous = console.info;
  console.info = value => logs.push(JSON.parse(value));
  try {
    const requests = [];
    const summary = await operationsSummary({ config, commit, fetchImpl: async (url, options) => {
      requests.push({ url: String(url), options });
      assert.deepEqual(Object.keys(options.headers), ['X-Aleph-Check-Id']);
      assert.equal(options.body, undefined);
      if (url.pathname === '/data.json') return Response.json({ notes: [] });
      if (url.pathname === '/api/device/status') return Response.json(
        { approved: false, error: 'DEVICE_APPROVAL_NOT_CONFIGURED' }, { status: 503 });
      return Response.json({ error: 'LOGIN_REQUIRED' }, { status: 401 });
    } });
    assert.equal(requests.length, 5);
    assert.equal(summary.checks.length, 22);
    assert.deepEqual(summary.counts, { executed: 5, matched: 5, failed: 0, unrun: 17 });
    assert.deepEqual(summary.policy.ruleIds, RULE_IDS);
    assert.equal(summary.officialAttacks.passed, null);
    assert.equal(summary.detection.eventCount, null);
    assert.equal(summary.revocation.revokedCount, null);
    assert.equal(summary.recovery.restoredVersion, null);
    for (const row of summary.checks) {
      if (row.state === 'unrun') {
        assert.equal(row.requestId, null); assert.equal(row.checkedAt, null);
      } else {
        assert.deepEqual(logs.find(log => log.requestId === row.requestId),
          { source: 'student_operations_check', ...row });
      }
    }
  } finally { console.info = previous; }
});

test('mismatched or private upstream payloads and network errors cannot become successes or leak', async () => {
  const previous = console.info;
  const logs = [];
  console.info = value => logs.push(value);
  try {
    const summary = await operationsSummary({ config, commit: 'invalid', fetchImpl: async url => {
      if (url.pathname === '/api/restore') throw new Error('private-test-detail');
      return Response.json({ notes: [{ content: 'private-test-detail' }], approved: true }, { status: 200 });
    } });
    assert.deepEqual(summary.counts, { executed: 5, matched: 0, failed: 5, unrun: 17 });
    assert.equal(summary.commit, null);
    assert.equal(summary.checks.filter(row => row.state === 'error').length, 1);
    assert.doesNotMatch(JSON.stringify(summary) + logs.join(''), /private-test-detail/u);
    await assert.rejects(() => operationsSummary({ config: { ...config, publicAppUrl: 'http://unsafe.test' } }),
      /invalid_operations_target/u);
  } finally { console.info = previous; }
});

test('public operations endpoint rejects writes and records all target failures without private details', async () => {
  const previousFetch = globalThis.fetch;
  try {
    let calls = 0;
    globalThis.fetch = async () => { calls++; throw new Error('private-test-detail'); };
    const write = capture();
    await handler({ method: 'POST', headers: { authorization: 'untrusted' } }, write);
    assert.equal(write.code, 405); assert.equal(calls, 0);
    assert.equal(write.headers['Cache-Control'], 'no-store');
    const previous = console.info; console.info = () => {};
    try {
      const read = capture(); await handler({ method: 'GET' }, read);
      assert.equal(read.code, 200);
      assert.equal(read.body.counts.failed, 5);
      assert.equal(read.headers['X-Aleph-Check-Id'], read.body.requestId);
      assert.doesNotMatch(JSON.stringify(read.body), /private-test-detail/u);
    } finally { console.info = previous; }
  } finally { globalThis.fetch = previousFetch; }
});

test('stage 12 build includes receipt UI while keeping notes empty and older control settings', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'aleph-step12-'));
  try {
    for (const path of ['scripts', 'public', 'aleph.config.json']) {
      await cp(new URL('../' + path, import.meta.url), join(directory, path), { recursive: true });
    }
    execFileSync(process.execPath, ['scripts/build-public.mjs'], { cwd: directory,
      windowsHide: true, stdio: 'pipe', env: { ...process.env, VERCEL_GIT_PROVIDER: 'github',
        VERCEL_GIT_REPO_OWNER: 'RockCandy444', VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
        VERCEL_GIT_COMMIT_SHA: commit, VERCEL_URL: 'stage12-test.vercel.app' } });
    const identity = JSON.parse(await readFile(join(directory, 'public/aleph.json'), 'utf8'));
    assert.equal(identity.step, 12); assert.equal(identity.commit, commit);
    assert.equal(identity.judgeIssuer, config.judgeIssuer);
    assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
    assert.equal(identity.restoreRoute, '/api/restore');
    assert.deepEqual(JSON.parse(await readFile(join(directory, 'public/data.json'), 'utf8')), { notes: [] });
    assert.match(await readFile(join(directory, 'public/index.html'), 'utf8'), /id="operations-heading"/u);
    await writeFile(join(directory, 'aleph.config.json'), JSON.stringify({ ...config, step: 13 }));
    assert.throws(() => execFileSync(process.execPath, ['scripts/build-public.mjs', '--local'],
      { cwd: directory, stdio: 'pipe', windowsHide: true }));
  } finally {
    assert.ok(resolve(directory).startsWith(`${resolve(tmpdir())}${sep}aleph-step12-`));
    await rm(directory, { recursive: true, force: true });
  }
});

test('stage 12 read-only bundle runs with restricted responses and correlates every result to runner evidence', async () => {
  const previousFetch = globalThis.fetch;
  const requests = [];
  // Node's own Response.json() needs Buffer internally. Model the judge's
  // response facade directly so that removing Buffer tests student code only.
  const sandboxResponse = (data, { status = 200, headers = {} } = {}) => {
    const text = () => typeof data === 'string' ? data
      : data instanceof Uint8Array ? new TextDecoder().decode(data) : JSON.stringify(data);
    return { status, ok: status >= 200 && status < 300,
      headers: { get: key => Object.entries(headers).find(([name]) => name.toLowerCase() === key.toLowerCase())?.[1] ?? null },
      json: async () => JSON.parse(text()), text: async () => text() };
  };
  try {
    globalThis.fetch = async (input, options = {}) => {
      const url = new URL(input);
      const method = options.method ?? 'GET';
      // Reproduce the judge restriction at the network boundary, not just by
      // inspecting source text. Any write makes the complete check fail.
      assert.ok(['GET', 'HEAD'].includes(method), `unsupported bundle method: ${method}`);
      assert.equal(url.protocol, 'https:');
      assert.equal(options.body, undefined);
      assert.match(options.alephEvidence?.caseId ?? '', /^[a-z0-9][a-z0-9_.-]{0,79}$/u);
      assert.match(options.alephEvidence?.requestKey ?? '', /^[a-z0-9-]+$/u);
      assert.ok(!Object.keys(options.headers ?? {}).some(name => /evidence|case.?id|attack.?id/iu.test(name)));
      requests.push({ path: url.pathname, method, evidence: options.alephEvidence });
      if (url.pathname === '/data.json') return sandboxResponse({ notes: [] });
      if (url.pathname === '/aleph.json') return sandboxResponse(deploymentIdentity({
        VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'RockCandy444',
        VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: commit,
        VERCEL_URL: 'stage12-test.vercel.app',
      }, config));
      if (url.pathname === '/api/operations') return sandboxResponse({
        schema: 'aleph.operations.v1', step: 12, commit,
        checks: Array.from({ length: 22 }, (_, index) => index < 5
          ? { state: 'matched', requestId: '00000000-0000-4000-8000-000000000000', checkedAt: '2026-10-14T00:00:00.000Z' }
          : { state: 'unrun', requestId: null, checkedAt: null }),
        counts: { executed: 5, matched: 5, failed: 0, unrun: 17 },
        detection: { state: 'unrun' }, revocation: { state: 'unrun' }, recovery: { state: 'unrun' },
        officialAttacks: { state: 'unrun', total: 41, passed: null },
      });
      if (url.pathname === '/api/device/status') return sandboxResponse(
        { approved: false, error: 'DEVICE_APPROVAL_NOT_CONFIGURED' }, { status: 503 });
      if (url.pathname.startsWith('/api/')) return sandboxResponse({ error: 'LOGIN_REQUIRED' },
        { status: 401, headers: { 'X-Aleph-Resource-Id': url.pathname === '/api/notices' ? 'instructor_notices' : 'notes' } });
      const path = url.pathname === '/' ? '/index.html' : url.pathname;
      return sandboxResponse(await readFile(new URL('../public' + path, import.meta.url)),
        { headers: { 'X-Content-Type-Options': 'nosniff',
          ...(path.startsWith('/icons/') ? { 'Content-Type': 'image/png' } : {}) } });
    };
    const previousBuffer = globalThis.Buffer;
    let results;
    try {
      globalThis.Buffer = undefined;
      results = await runAttackChecks({ ...config, expectedCommit: commit });
    } finally { globalThis.Buffer = previousBuffer; }
    assert.equal(requests.length, 19);
    assert.equal(results.length, 20);
    assert.deepEqual(results.filter(row => row.observed === 'not_run').map(row => row.attackId).sort(),
      ['notes_write_requests', 'notice_write_requests', 'restore_anonymous_invalid_denied', 'device_approval_request',
        'authenticated_a_b_crud', 'original_api_and_privileges_unrun', 'student_notice_write_denied',
        'verified_policy_and_b_recovery', 'post_recovery_regression', 'registered_device_and_request_signatures'].sort());
    const measured = results.filter(row => row.observed !== 'not_run');
    assert.equal(measured.length, 10);
    assert.ok(measured.every(row => requests.some(request => request.evidence.caseId === row.attackId)));
    assert.ok(results.filter(row => row.observed === 'not_run')
      .every(row => !requests.some(request => request.evidence.caseId === row.attackId)));
    assert.equal(new Set(requests.map(row => row.evidence.caseId + ':' + row.evidence.requestKey)).size, requests.length);
    assert.ok(!requests.some(row => ['/api/restore', '/api/device/request'].includes(row.path)));
    assert.equal(requests.filter(row => row.path.startsWith('/icons/') && row.method === 'HEAD').length, 2);
    assert.match(results.find(row => row.attackId === 'app_manifest_and_icons').observed, /실제 크기 검사 not_run/u);
    assert.ok(results.filter(row => row.observed !== 'not_run' && !row.observed.startsWith('미실행:'))
      .every(row => !/점검 실패|미확인/u.test(row.observed)));
  } finally { globalThis.fetch = previousFetch; }
});
