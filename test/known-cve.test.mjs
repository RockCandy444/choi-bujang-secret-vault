import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, join, resolve, sep } from 'node:path';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import { decide } from '../xdr/known-cve/decide.mjs';
import { extractAlerts } from '../xdr/known-cve/read-alerts.mjs';
import { respond } from '../xdr/known-cve/respond.mjs';
import { decide as ztnaDecide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));
const { alerts } = fixture;
const patterns = JSON.parse(await readFile(new URL('../xdr/known-cve/patterns.json', import.meta.url), 'utf8')).patterns;
const now = Date.parse('2026-10-14T00:00:00Z');
const ttl = 15 * 60 * 1000;
const attack = { ...alerts[0], timestamp: new Date(now - 1000).toISOString() };
const normal = { ...alerts[16], timestamp: new Date(now - 1000).toISOString() };
const candidatePath = root => join(root, 'xdr/known-cve/deny-candidates.json');
const candidates = async root => JSON.parse(await readFile(candidatePath(root), 'utf8'));

async function isolated(run) {
  const base = resolve('local-only/known-cve-test');
  await mkdir(base, { recursive: true });
  const root = await mkdtemp(join(base, 'case-'));
  try { await run(root); }
  finally {
    const target = resolve(root);
    assert.ok(target.startsWith(base + sep) && basename(target).startsWith('case-'));
    await rm(target, { recursive: true, force: true });
  }
}

test('24개 가상 경보: 명확한 공격 8·애매한 신호 8·정상 8과 정상 차단 0', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [index, alert] of alerts.entries()) {
    const decision = decide(alert);
    assert.equal(decision.action, index < 8 ? 'block' : index < 16 ? 'alert' : 'record');
    assert.deepEqual(Object.keys(decision).sort(), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(decision.confidence) && decision.confidence >= 0 && decision.confidence <= 1);
    assert.equal(decision.action, decision.confidence >= 0.85 ? 'block' : decision.confidence >= 0.5 ? 'alert' : 'record');
    counts[decision.action] += 1;
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
});

test('판단기는 인터넷·파일·패키지 없이 한 파일로 실행하고 패턴 이름과 근거를 보존한다', async () => {
  const source = await readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');
  assert.ok(!/\b(?:import|require|fetch|process)\b/u.test(source));
  const standalone = runInNewContext(source.replace('export function decide', 'function decide') + '\n decide;', {}, { timeout: 1000 });
  for (const alert of alerts) assert.equal(JSON.stringify(standalone(alert)), JSON.stringify(decide(alert)));
  for (const pattern of patterns) {
    assert.ok(source.includes(pattern.name));
    assert.ok(pattern.condition && pattern.evidence && !/[\r\n]/u.test(pattern.evidence));
  }
});

test('번호·수준만으로 차단하지 않고 불완전한 형태·출발 주소 부재는 알림으로 남긴다', () => {
  assert.equal(decide({ ...attack, id: 'renamed' }).action, 'block');
  assert.equal(decide({ ...attack, data: { ...attack.data, srcip: undefined } }).action, 'alert');
  assert.equal(decide({ ...attack, rule: { ...attack.rule, level: 5 } }).action, 'alert');
  assert.equal(decide({ ...attack, data: { srcip: attack.data.srcip, useragent: 'jndi-class-note' } }).action, 'alert');
  assert.equal(decide({ ...normal, rule: { ...normal.rule, level: 13 } }).action, 'alert');
  assert.notEqual(decide(null).action, 'block');
  assert.notEqual(decide({ data: { useragent: 'x'.repeat(10000) } }).action, 'block');
});

test('읽기는 다섯 필드만 24줄 반환하고 비밀·실제 계정·인코딩된 의심 값은 가린다', () => {
  const rows = extractAlerts(fixture);
  assert.equal(rows.length, alerts.length);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'description,level,srcip,srcuser,timestamp'));
  const marker = 'DEMO_ONLY_REDACTION_MARKER';
  const row = extractAlerts({ ...fixture, alerts: [{
    ...normal, rule: { ...normal.rule, description: encodeURIComponent('password=' + marker) },
    data: { ...normal.data, srcuser: marker, password: marker },
  }] })[0];
  assert.equal(row.description, '[가림]');
  assert.equal(row.srcuser, '[가림]');
  assert.ok(!JSON.stringify(row).includes(marker));
});

test('차단 결과만 근거 번호·만료·비활성 후보로 저장하고 원문 대신 가린 알림을 추가한다', async () => {
  await isolated(async root => {
    await mkdir(join(root, 'xdr'), { recursive: true });
    const prior = '{"moduleKey":"web-injection","status":"preserved"}\n';
    await writeFile(join(root, 'xdr/alerts.log'), prior);
    const result = await respond(alerts, { root, now });
    assert.deepEqual(result.counts, { block: 8, alert: 8, record: 8, candidates: 8, suppressed: 0, expired: 8, applied: 0 });
    assert.equal(result.ztnaConnected, false);
    assert.equal(result.notices, 16);
    const saved = await candidates(root);
    assert.equal(saved.rules.length, 8);
    for (const rule of saved.rules) {
      assert.equal(rule.active, false);
      assert.equal(rule.match, null);
      assert.equal(rule.status, 'expired_candidate');
      assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), ttl);
      assert.equal(decide(alerts.find(alert => rule.alertIds.includes(alert.id))).action, 'block');
    }
    const text = await readFile(join(root, 'xdr/alerts.log'), 'utf8');
    assert.ok(text.startsWith(prior));
    assert.equal(text.trim().split('\n').length, 17);
    assert.ok(!text.includes(attack.data.srcip));
    assert.ok(!text.includes(attack.data.useragent));
  });
});

test('재실행과 정확한 만료 경계에서 후보 중복·만료 연장을 하지 않는다', async () => {
  await isolated(async root => {
    await respond([attack], { root, now });
    const first = (await candidates(root)).rules[0];
    assert.equal(first.status, 'pending_verified_binding');
    await respond([attack], { root, now: Date.parse(first.expiresAt) });
    const second = (await candidates(root)).rules;
    assert.equal(second.length, 1);
    assert.equal(second[0].expiresAt, first.expiresAt);
    assert.equal(second[0].status, 'expired_candidate');
    assert.equal(second[0].active, false);
  });
});

test('공유 출발 주소의 정상 경보는 순서·호출 경계와 관계없이 주소 거부를 억제한다', async () => {
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
});

test('잘못된 시각·번호·출발 주소와 오염된 후보는 적용하지 않고 원문을 로그에 넣지 않는다', async () => {
  await isolated(async root => {
    const marker = 'DEMO_ONLY_REDACTION_MARKER';
    const invalid = [
      { ...attack, id: marker }, { ...attack, timestamp: marker },
      { ...attack, timestamp: new Date(now + 60000).toISOString() },
      { ...attack, data: { ...attack.data, srcip: marker } },
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

test('원본 경보·기존 판정 코드·RULE_IDS와 정상 허용·미등록 거부를 보존한다', async () => {
  await isolated(async root => {
    const urls = ['../src/decider.mjs', '../xdr/fixtures/known-cve.json'].map(path => new URL(path, import.meta.url));
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
