import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, join, resolve, sep } from 'node:path';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { extractAlerts } from '../xdr/exfiltration/read-alerts.mjs';
import { respond } from '../xdr/exfiltration/respond.mjs';
import { decide as ztnaDecide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json', import.meta.url), 'utf8'));
const { alerts } = fixture;
const patterns = JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json', import.meta.url), 'utf8')).patterns;
const now = Date.parse('2026-10-14T00:00:00Z');
const ttl = 15 * 60 * 1000;
const attack = { ...alerts[0], timestamp: new Date(now - 1000).toISOString() };
const normal = { ...alerts[20], timestamp: new Date(now - 1000).toISOString() };
const candidatePath = root => join(root, 'xdr/exfiltration/deny-candidates.json');
const candidates = async root => JSON.parse(await readFile(candidatePath(root), 'utf8'));

async function isolated(run) {
  const base = resolve('local-only/exfiltration-test');
  await mkdir(base, { recursive: true });
  const root = await mkdtemp(join(base, 'case-'));
  try { await run(root); }
  finally {
    const target = resolve(root);
    assert.ok(target.startsWith(base + sep) && basename(target).startsWith('case-'));
    await rm(target, { recursive: true, force: true });
  }
}

test('30개 경보를 복합 반출·애매한 신호·정상으로 분류하고 정상은 차단하지 않는다', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [index, alert] of alerts.entries()) {
    const decision = decide(alert);
    assert.equal(decision.action, index < 10 ? 'block' : index < 20 ? 'alert' : 'record', alert.id);
    assert.deepEqual(Object.keys(decision).sort(), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(decision.confidence) && decision.confidence >= 0 && decision.confidence <= 1);
    assert.equal(decision.action, decision.confidence >= 0.85 ? 'block' : decision.confidence >= 0.5 ? 'alert' : 'record');
    counts[decision.action] += 1;
  }
  assert.deepEqual(counts, { block: 10, alert: 10, record: 10 });
});

test('판단기는 한 파일만으로 작동하며 근거가 있는 패턴 이름을 반환한다', async () => {
  const source = await readFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');
  assert.ok(!/\b(?:import|require|fetch|process)\b/u.test(source));
  assert.equal((source.match(/\bexport\b/gu) ?? []).length, 1);
  const standalone = runInNewContext(source.replace('export function decide', 'function decide') + '\n decide;', {}, { timeout: 1000 });
  for (const alert of alerts) assert.equal(JSON.stringify(standalone(alert)), JSON.stringify(decide(alert)));
  for (const pattern of patterns) {
    assert.ok(source.includes(pattern.name));
    assert.ok(pattern.condition && pattern.evidence && !/[\r\n]/u.test(pattern.evidence));
    assert.match(pattern.source, /^https:\/\/attack\.mitre\.org\/techniques\/T104[18]\/$/u);
  }
  assert.ok(alerts.every(alert => decide(alert).action === 'record' || patterns.some(p => p.name === decide(alert).reason)));
});

test('읽기 명령은 실제 30줄을 출력하고 다섯 필드 밖의 값과 의심 값은 가린다', () => {
  const rows = extractAlerts(fixture);
  assert.equal(rows.length, 30);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'description,level,srcip,srcuser,timestamp'));
  const child = spawnSync(process.execPath, ['xdr/exfiltration/read-alerts.mjs'], { encoding: 'utf8', windowsHide: true });
  assert.equal(child.status, 0);
  assert.equal(child.stdout.trim().split(/\r?\n/u).length, alerts.length);
  assert.match(child.stderr, /경보 30건 \/ 추출 30줄/u);
  const marker = 'DEMO_ONLY_REDACTION_MARKER';
  const row = extractAlerts({ ...fixture, alerts: [{
    ...normal, rule: { ...normal.rule, description: encodeURIComponent('password=' + marker) },
    data: { ...normal.data, srcuser: marker, password: marker },
  }] })[0];
  assert.equal(row.description, '[가림]');
  assert.equal(row.srcuser, '[가림]');
  assert.ok(!JSON.stringify(row).includes(marker));
});

test('목적지·완료·크기·반복 증거를 요구하며 번호·계정·기법·수준만으로 차단하지 않는다', () => {
  assert.equal(decide({ ...attack, id: 'renamed', data: { ...attack.data, srcuser: 'other' } }).action, 'block');
  assert.equal(decide({ ...attack, rule: { ...attack.rule, mitre: [] } }).action, 'block');
  assert.equal(decide({ ...attack, rule: { ...attack.rule, level: 5 } }).action, 'alert');
  for (const data of [{ bytes: '400000' }, { bytes: '-1' }, { bytes: true }, { dstip: undefined }, { dstip: '999.0.2.1' }]) {
    assert.equal(decide({ ...attack, data: { ...attack.data, ...data } }).action, 'alert');
  }
  assert.equal(decide({ ...alerts[2], data: { ...alerts[2].data, count: '1' } }).action, 'alert');
  assert.equal(decide({ ...alerts[7], data: { ...alerts[7].data, files: '1' } }).action, 'alert');
  assert.equal(decide({ ...alerts[3], data: { ...alerts[3].data, files: '1' } }).action, 'alert');
  for (const description of [attack.rule.description + ' 전송 실패입니다.', attack.rule.description + ' 외부 전송은 없습니다.']) {
    assert.equal(decide({ ...attack, rule: { ...attack.rule, description } }).action, 'alert');
  }
  for (const alert of alerts.slice(20)) {
    assert.equal(decide({ ...alert, rule: { ...alert.rule, level: 16 }, data: { ...alert.data, bytes: '900000000' } }).action, 'record');
  }
  assert.notEqual(decide(null).action, 'block');
  assert.notEqual(decide({ rule: { level: 12, description: 'x'.repeat(10000) } }).action, 'block');
});

test('block만 만료가 있는 비활성 목적지 후보로 저장하고 기존 로그 뒤에 알림을 추가한다', async () => {
  await isolated(async root => {
    await mkdir(join(root, 'xdr'), { recursive: true });
    const prior = '{"moduleKey":"privilege","status":"preserved"}\n';
    await writeFile(join(root, 'xdr/alerts.log'), prior);
    const result = await respond(alerts, { root, now });
    assert.deepEqual(result.counts, { block: 10, alert: 10, record: 10, candidates: 10, suppressed: 0, expired: 10, applied: 0 });
    assert.equal(result.ztnaConnected, false);
    assert.equal(result.notices, 20);
    const saved = await candidates(root);
    assert.equal(saved.rules.length, 10);
    for (const rule of saved.rules) {
      assert.equal(rule.active, false);
      assert.equal(rule.match, null);
      assert.equal(rule.status, 'expired_candidate');
      assert.match(rule.destinationIpSha256, /^[a-f0-9]{64}$/u);
      assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), ttl);
      assert.equal(decide(alerts.find(alert => rule.alertIds.includes(alert.id))).action, 'block');
    }
    const text = await readFile(join(root, 'xdr/alerts.log'), 'utf8');
    assert.ok(text.startsWith(prior));
    assert.equal(text.trim().split('\n').length, 21);
    for (const value of [attack.data.srcip, attack.data.dstip, attack.data.srcuser, attack.rule.description]) assert.ok(!text.includes(value));
  });
});

test('재전송은 후보를 중복시키거나 사건 시각에서 계산한 만료를 연장하지 않는다', async () => {
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

test('같은 목적지를 쓰는 정상 경보는 순서·호출 경계와 관계없이 목적지 거부를 억제한다', async () => {
  const sharedNormal = { ...normal, data: { ...normal.data, dstip: attack.data.dstip } };
  for (const input of [[attack, sharedNormal], [sharedNormal, attack]]) {
    await isolated(async root => {
      assert.equal((await respond(input, { root, now })).counts.suppressed, 1);
      assert.equal((await candidates(root)).rules.length, 0);
    });
  }
  await isolated(async root => {
    await respond([attack], { root, now });
    await respond([sharedNormal], { root, now });
    assert.equal((await candidates(root)).rules[0].status, 'suppressed_normal_destination');
    assert.equal((await respond([attack], { root, now })).counts.candidates, 0);
  });
  await isolated(async root => {
    const sameSource = { ...normal, data: { ...normal.data, srcip: attack.data.srcip } };
    assert.equal((await respond([attack, sameSource], { root, now })).counts.candidates, 1);
  });
});

test('잘못된 시각·번호·목적지와 오염된 후보를 거부하며 원문을 로그에 넣지 않는다', async () => {
  await isolated(async root => {
    const marker = 'DEMO_ONLY_REDACTION_MARKER';
    const invalid = [
      { ...attack, id: marker }, { ...attack, timestamp: marker },
      { ...attack, timestamp: new Date(now + 60000).toISOString() },
      { ...attack, data: { ...attack.data, dstip: marker } },
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

test('원본·기존 ZTNA 규칙·정상 허용·미등록 거부를 보존한다', async () => {
  await isolated(async root => {
    const urls = ['../src/decider.mjs', '../xdr/fixtures/exfiltration.json'].map(path => new URL(path, import.meta.url));
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
