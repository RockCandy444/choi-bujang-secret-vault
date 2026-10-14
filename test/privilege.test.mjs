import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, join, resolve, sep } from 'node:path';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import { decide } from '../xdr/privilege/decide.mjs';
import { extractAlerts } from '../xdr/privilege/read-alerts.mjs';
import { respond } from '../xdr/privilege/respond.mjs';
import { decide as ztnaDecide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));
const { alerts } = fixture;
const patterns = JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json', import.meta.url), 'utf8')).patterns;
const now = Date.parse('2026-10-14T00:00:00Z');
const ttl = 15 * 60 * 1000;
const attack = { ...alerts[0], timestamp: new Date(now - 1000).toISOString() };
const normal = { ...alerts[17], timestamp: new Date(now - 1000).toISOString() };
const candidatePath = root => join(root, 'xdr/privilege/deny-candidates.json');
const candidates = async root => JSON.parse(await readFile(candidatePath(root), 'utf8'));

async function isolated(run) {
  const base = resolve('local-only/privilege-test');
  await mkdir(base, { recursive: true });
  const root = await mkdtemp(join(base, 'case-'));
  try { await run(root); }
  finally {
    const target = resolve(root);
    assert.ok(target.startsWith(base + sep) && basename(target).startsWith('case-'));
    await rm(target, { recursive: true, force: true });
  }
}

test('26개 경보: 공격 9·애매 8·정상 9, 정상 차단 0과 세 값 반환', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [index, alert] of alerts.entries()) {
    const out = decide(alert);
    assert.equal(out.action, index < 9 ? 'block' : index < 17 ? 'alert' : 'record');
    assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(out.confidence) && out.confidence >= 0 && out.confidence <= 1);
    assert.equal(out.action, out.confidence >= 0.85 ? 'block' : out.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(!/[\r\n]/u.test(out.reason));
    counts[out.action]++;
  }
  assert.deepEqual(counts, { block: 9, alert: 8, record: 9 });
});

test('인터넷·파일·패키지 없이 단일 파일로 실행하고 패턴 근거를 보존한다', async () => {
  const source = await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');
  assert.ok(!/\b(?:import|require|fetch|process)\b/u.test(source));
  const standalone = runInNewContext(source.replace('export function decide', 'function decide') + '\n decide;', {}, { timeout: 1000 });
  for (const alert of alerts) assert.equal(JSON.stringify(standalone(alert)), JSON.stringify(decide(alert)));
  for (const pattern of patterns) {
    assert.ok(source.includes(pattern.name));
    assert.ok(pattern.condition && pattern.evidence && !/[\r\n]/u.test(pattern.evidence));
  }
});

test('읽기는 다섯 항목·26줄이며 비밀값과 실제 계정·인코딩된 값은 가린다', () => {
  const rows = extractAlerts(fixture);
  assert.equal(rows.length, 26);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'description,level,srcip,srcuser,timestamp'));
  assert.equal(rows[20].srcuser, 'admin01');
  assert.equal(rows[24].srcuser, 'svc-lab');
  const marker = 'DEMO_ONLY_REDACTION_MARKER';
  const row = extractAlerts({ ...fixture, alerts: [{
    ...normal, rule: { ...normal.rule, description: encodeURIComponent('password=' + marker) },
    data: { ...normal.data, srcuser: marker, password: marker },
  }] })[0];
  assert.equal(row.description, '[가림]');
  assert.equal(row.srcuser, '[가림]');
  assert.ok(!JSON.stringify(row).includes(marker));
});

test('식별자·MITRE 태그·수준만으로 차단하지 않고 불완전한 복합 근거는 알림에 남긴다', () => {
  assert.equal(decide({ ...attack, id: 'renamed', data: { ...attack.data, srcuser: 'other' } }).action, 'block');
  assert.equal(decide({ ...attack, rule: { ...attack.rule, mitre: [] } }).action, 'block');
  assert.equal(decide({ ...attack, rule: { ...attack.rule, level: 5 } }).action, 'alert');
  assert.equal(decide({ ...attack, data: { ...attack.data, group: 'project' } }).action, 'alert');
  assert.equal(decide({ ...attack, data: { ...attack.data, srcip: 'invalid' } }).action, 'alert');
  assert.equal(decide({ ...alerts[4], data: { ...alerts[4].data, count: '1' } }).action, 'alert');
  assert.equal(decide({ ...alerts[8], data: { ...alerts[8].data, count: '1' } }).action, 'alert');
  assert.equal(decide({ ...attack, rule: { ...attack.rule, description: attack.rule.description + ' 추가되지 않았습니다.' } }).action, 'alert');
  for (const alert of alerts.slice(17)) assert.equal(decide({ ...alert, rule: { ...alert.rule, level: 16 } }).action, 'record');
  assert.notEqual(decide(null).action, 'block');
  assert.notEqual(decide({ rule: { level: 12, description: 'x'.repeat(10000) } }).action, 'block');
});

test('공격만 근거 번호·만료를 가진 비활성 후보로 저장하고 알림 17줄을 추가한다', async () => {
  await isolated(async root => {
    await mkdir(join(root, 'xdr'), { recursive: true });
    const prior = '{"moduleKey":"persistence","status":"preserved"}\n';
    await writeFile(join(root, 'xdr/alerts.log'), prior);
    const out = await respond(alerts, { root, now });
    assert.deepEqual(out.counts, { block: 9, alert: 8, record: 9, candidates: 9, suppressed: 0, expired: 9, applied: 0 });
    assert.equal(out.ztnaConnected, false);
    assert.equal(out.notices, 17);
    const saved = await candidates(root);
    assert.equal(saved.rules.length, 9);
    for (const rule of saved.rules) {
      assert.equal(rule.active, false);
      assert.equal(rule.match, null);
      assert.equal(rule.status, 'expired_candidate');
      assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), ttl);
      assert.equal(decide(alerts.find(alert => rule.alertIds.includes(alert.id))).action, 'block');
    }
    const text = await readFile(join(root, 'xdr/alerts.log'), 'utf8');
    assert.ok(text.startsWith(prior));
    assert.equal(text.trim().split('\n').length, 18);
    assert.ok(!text.includes(attack.data.srcip) && !text.includes(attack.data.srcuser));
  });
});

test('재전송은 후보를 중복 생성하거나 만료를 연장하지 않고 정확한 경계에서 만료한다', async () => {
  await isolated(async root => {
    await respond([attack], { root, now });
    const first = (await candidates(root)).rules[0];
    assert.equal(first.status, 'pending_verified_binding');
    await respond([attack], { root, now: Date.parse(first.expiresAt) });
    const second = (await candidates(root)).rules;
    assert.equal(second.length, 1);
    assert.equal(second[0].expiresAt, first.expiresAt);
    assert.equal(second[0].status, 'expired_candidate');
  });
});

test('같은 계정·주소의 정상 경보를 호출 경계와 관계없이 기억하고 다른 계정은 구분한다', async () => {
  const sharedNormal = { ...normal, data: { ...normal.data, srcip: attack.data.srcip } };
  for (const input of [[attack, sharedNormal], [sharedNormal, attack]]) {
    await isolated(async root => {
      assert.equal((await respond(input, { root, now })).counts.suppressed, 1);
      assert.equal((await candidates(root)).rules.length, 0);
    });
  }
  await isolated(async root => {
    await respond([attack], { root, now });
    await respond([sharedNormal], { root, now });
    assert.equal((await candidates(root)).rules[0].status, 'suppressed_normal_source');
    assert.equal((await respond([attack], { root, now })).counts.candidates, 0);
  });
  await isolated(async root => {
    const other = { ...sharedNormal, data: { ...sharedNormal.data, srcuser: 'user99' } };
    assert.equal((await respond([attack, other], { root, now })).counts.candidates, 1);
  });
});

test('오염된 후보·잘못된 번호·시각·계정은 적용하지 않고 원문을 기록하지 않는다', async () => {
  await isolated(async root => {
    const marker = 'DEMO_ONLY_REDACTION_MARKER';
    const invalid = [
      { ...attack, id: marker }, { ...attack, timestamp: marker },
      { ...attack, timestamp: new Date(now + 60000).toISOString() },
      { ...attack, data: { ...attack.data, srcuser: marker } },
    ];
    assert.equal((await respond(invalid, { root, now })).counts.candidates, 0);
    assert.ok(!(await readFile(join(root, 'xdr/alerts.log'), 'utf8')).includes(marker));
    await respond([attack], { root, now });
    const saved = await candidates(root);
    saved.rules[0].active = true;
    const text = JSON.stringify(saved);
    await writeFile(candidatePath(root), text);
    const prior = await readFile(join(root, 'xdr/alerts.log'), 'utf8');
    await assert.rejects(respond([attack], { root, now }), /invalid_candidate_file/u);
    assert.equal(await readFile(candidatePath(root), 'utf8'), text);
    assert.equal(await readFile(join(root, 'xdr/alerts.log'), 'utf8'), prior);
  });
});

test('원본·기존 여섯 규칙과 정상 허용·미등록 거부를 보존한다', async () => {
  await isolated(async root => {
    const urls = ['../src/decider.mjs', '../xdr/fixtures/privilege.json'].map(path => new URL(path, import.meta.url));
    const before = await Promise.all(urls.map(url => readFile(url, 'utf8')));
    const rules = [...RULE_IDS];
    const { normal: request } = fixtureRequests();
    const allowed = await ztnaDecide(request);
    const unregistered = { ...request, deviceRegistered: false };
    const denied = await ztnaDecide(unregistered);
    await respond(alerts, { root, now });
    assert.equal(allowed.decision, 'allow');
    assert.equal(denied.decision, 'deny');
    assert.deepEqual(await ztnaDecide(request), allowed);
    assert.deepEqual(await ztnaDecide(unregistered), denied);
    assert.deepEqual(RULE_IDS, rules);
    assert.deepEqual(await Promise.all(urls.map(url => readFile(url, 'utf8'))), before);
  });
});
