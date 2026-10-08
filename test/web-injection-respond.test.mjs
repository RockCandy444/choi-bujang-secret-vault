import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve, sep } from 'node:path';
import { test } from 'node:test';
import { respond } from '../xdr/web-injection/respond.mjs';
import { decide } from '../xdr/web-injection/decide.mjs';
import { decide as ztnaDecide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const alerts = JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8')).alerts;
const now = Date.parse('2026-10-08T03:00:00.000Z');
const TTL_MS = 15 * 60 * 1000;
const fresh = alert => ({ ...alert, timestamp: new Date(now - 1000).toISOString() });
const attack = fresh(alerts[0]);
const normal = fresh(alerts.find(alert => alert.rule.level === 3 && alert.data.srcuser));
const candidatePath = root => join(root, 'xdr', 'web-injection', 'deny-candidates.json');
const candidates = async root => JSON.parse(await readFile(candidatePath(root), 'utf8'));
const logs = async root => (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n').map(line => JSON.parse(line));

async function isolated(run) {
  const root = await mkdtemp(join(tmpdir(), 'web-injection-respond-'));
  try { await run(root); }
  finally {
    const target = resolve(root);
    assert.ok(target.startsWith(resolve(tmpdir()) + sep) && basename(target).startsWith('web-injection-respond-'));
    await rm(target, { recursive: true, force: true });
  }
}

test('가상 경보의 명확한 패턴 일치만 만료·근거 번호가 있는 비활성 후보로 저장한다', async () => {
  await isolated(async root => {
    const result = await respond(alerts, { root, now });
    assert.deepEqual(result.counts, { block: 8, alert: 9, record: 9, candidates: 8, suppressed: 0, expired: 8, applied: 0 });
    assert.equal(result.ztnaConnected, false);
    const { rules } = await candidates(root);
    assert.equal(rules.length, 8);
    for (const rule of rules) {
      assert.equal(rule.active, false);
      assert.equal(rule.match, null);
      assert.equal(rule.action, 'deny');
      assert.equal(rule.status, 'expired_candidate');
      assert.equal(rule.alertIds.length, 1);
      const alert = alerts.find(alert => alert.id === rule.alertIds[0]);
      assert.ok(alert.rule.level >= 10);
      assert.equal(rule.createdAt, new Date(alert.timestamp).toISOString());
      assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), TTL_MS);
    }
    const notices = await logs(root);
    assert.equal(result.notices, 17);
    assert.equal(notices.length, 17);
    assert.ok(notices.every(row => ['alert', 'block'].includes(row.action)));
    assert.equal(notices.find(row => row.alertId === 'wi-06').status, 'expired_candidate');
    assert.ok(rules.some(rule => rule.alertIds.includes('wi-06') && rule.pattern === '요청 인자의 명령 구분자 삽입'));
    assert.ok(normal && !rules.some(rule => rule.alertIds.includes(normal.id)));
  });
});

test('명령 구분자 반복은 경보 번호에 의존하지 않고 단일 표기·주소 누락·단순 구분 문자는 차단하지 않는다', () => {
  const command = alerts.find(alert => alert.rule.description.includes('명령 구분자 표기'));
  assert.equal(decide({ ...command, id: 'renamed-alert' }).action, 'block');
  for (const candidate of [
    { ...command, data: { ...command.data, count: '1' } },
    { ...command, data: { ...command.data, srcip: undefined } },
    { ...command, rule: { ...command.rule, description: '명령 구분자 표기가 11번에 있습니다.' } },
    { ...command, rule: { ...command.rule, description: '이름 검색에 구분 문자가 11건 있습니다.' } },
  ]) assert.equal(decide(candidate).action, 'alert');
  assert.ok(alerts.filter(alert => alert.rule.level >= 5 && alert.rule.level <= 8)
    .every(alert => decide(alert).action === 'alert'));
  assert.ok(alerts.filter(alert => alert.rule.level <= 3).every(alert => decide(alert).action === 'record'));
});

test('재전송은 후보를 중복 생성하거나 만료를 연장하지 않고 기존 로그 뒤에 추가한다', async () => {
  await isolated(async root => {
    await mkdir(join(root, 'xdr'), { recursive: true });
    const priorLog = '{"moduleKey":"brute-force","status":"preserved"}\n';
    await writeFile(join(root, 'xdr', 'alerts.log'), priorLog);
    await respond(alerts, { root, now });
    const before = await candidates(root);
    await respond(alerts, { root, now: now + TTL_MS });
    assert.deepEqual(await candidates(root), before);
    const logText = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
    assert.ok(logText.startsWith(priorLog));
    assert.equal((await logs(root)).length, 35);
  });
});

test('새 사건도 검증된 연결 전에는 비활성이며 정확한 만료 경계에서 만료된다', async () => {
  await isolated(async root => {
    const first = await respond([attack], { root, now });
    assert.equal(first.counts.candidates, 1);
    assert.equal(first.counts.expired, 0);
    let rule = (await candidates(root)).rules[0];
    assert.equal(rule.status, 'pending_verified_binding');
    assert.equal(rule.active, false);
    const expiresAt = rule.expiresAt;
    await respond([attack], { root, now: Date.parse(expiresAt) });
    rule = (await candidates(root)).rules[0];
    assert.equal(rule.status, 'expired_candidate');
    assert.equal(rule.expiresAt, expiresAt);
    assert.equal(rule.active, false);
  });
});

test('같은 공유 주소의 정상 경보는 배열 순서와 관계없이 거부 후보 생성을 억제한다', async () => {
  const sharedAttack = { ...attack, data: { ...attack.data, srcip: normal.data.srcip } };
  for (const input of [[sharedAttack, normal], [normal, sharedAttack]]) {
    await isolated(async root => {
      const result = await respond(input, { root, now });
      assert.equal(result.counts.suppressed, 1);
      assert.equal(result.counts.candidates, 0);
      assert.deepEqual((await candidates(root)).rules, []);
      assert.equal((await logs(root))[0].status, 'suppressed_normal_source');
    });
  }
});

test('정상 경보가 먼저 또는 나중에 들어와도 공유 주소의 후보를 계속 억제한다', async () => {
  const sharedNormal = { ...normal, data: { ...normal.data, srcip: attack.data.srcip } };
  await isolated(async root => {
    await respond([sharedNormal], { root, now });
    const result = await respond([attack], { root, now });
    assert.equal(result.counts.suppressed, 1);
    assert.deepEqual((await candidates(root)).rules, []);
  });
  await isolated(async root => {
    await respond([attack], { root, now });
    await respond([sharedNormal], { root, now });
    assert.equal((await candidates(root)).rules[0].status, 'suppressed_normal_source');
    const result = await respond([attack], { root, now });
    assert.equal(result.counts.candidates, 0);
    assert.equal(result.counts.suppressed, 1);
    assert.equal((await candidates(root)).rules[0].status, 'suppressed_normal_source');
  });
});

test('미래 사건·잘못된 번호·출발 주소는 후보로 넣지 않고 비밀처럼 보이는 원문은 기록하지 않는다', async () => {
  await isolated(async root => {
    const marker = 'DEMO_ONLY_REDACTION_MARKER';
    const input = [
      { ...attack, timestamp: new Date(now + 60000).toISOString() },
      { ...attack, id: marker },
      { ...attack, data: { ...attack.data, srcip: marker } },
      { ...attack, timestamp: marker },
    ].map(alert => ({ ...alert, data: { ...alert.data, srcuser: marker, password: marker, token: marker } }));
    const result = await respond(input, { root, now });
    assert.equal(result.counts.candidates, 0);
    assert.deepEqual((await candidates(root)).rules, []);
    const text = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
    assert.ok(!text.includes(marker));
    assert.ok(!text.includes(attack.data.srcip));
    assert.ok(!text.includes(attack.rule.description));
    assert.ok((await logs(root)).every(row => row.status === 'insufficient_verified_data'));
  });
});

test('오염된 후보 파일은 덮어쓰거나 로그에 원문을 출력하지 않고 오류로 거부한다', async () => {
  await isolated(async root => {
    await respond([attack], { root, now });
    const saved = await candidates(root);
    saved.rules[0].active = true;
    const content = JSON.stringify(saved);
    await writeFile(candidatePath(root), content);
    const priorLog = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
    await assert.rejects(respond([attack], { root, now }), /invalid_candidate_file/u);
    assert.equal(await readFile(candidatePath(root), 'utf8'), content);
    assert.equal(await readFile(join(root, 'xdr', 'alerts.log'), 'utf8'), priorLog);
  });
});

test('판단 모듈·원본 경보·기존 ZTNA를 보존하고 정상 요청 통과를 주장하지 않는다', async () => {
  await isolated(async root => {
    const urls = ['../src/decider.mjs', '../xdr/web-injection/decide.mjs', '../xdr/fixtures/web-injection.json']
      .map(path => new URL(path, import.meta.url));
    const original = await Promise.all(urls.map(url => readFile(url)));
    const { normal: request } = fixtureRequests();
    const before = await ztnaDecide(request);
    await respond(alerts, { root, now });
    assert.deepEqual(await ztnaDecide(request), before);
    assert.equal(before.decision, 'deny');
    assert.deepEqual(RULE_IDS, ['starter.deny']);
    for (const [index, url] of urls.entries()) assert.ok(original[index].equals(await readFile(url)));
  });
});
