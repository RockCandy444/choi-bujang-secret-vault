import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve, sep } from 'node:path';
import { test } from 'node:test';
import { respond } from '../xdr/brute-force/respond.mjs';
import { decide as ztnaDecide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const alerts = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8')).alerts;
const now = Date.parse('2026-10-08T03:00:00.000Z');
const TTL_MS = 15 * 60 * 1000;

async function isolated(run) {
  const root = await mkdtemp(join(tmpdir(), 'xdr-respond-'));
  const savedKey = process.env.TYPESAFE_API_KEY;
  delete process.env.TYPESAFE_API_KEY;
  try { await run(root); }
  finally {
    if (savedKey === undefined) delete process.env.TYPESAFE_API_KEY;
    else process.env.TYPESAFE_API_KEY = savedKey;
    const target = resolve(root);
    assert.ok(target.startsWith(resolve(tmpdir()) + sep) && basename(target).startsWith('xdr-respond-'));
    await rm(target, { recursive: true, force: true });
  }
}

const candidates = async root => JSON.parse(await readFile(join(root, 'xdr', 'brute-force', 'deny-candidates.json'), 'utf8')).rules;
const logs = async root => (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n').map(line => JSON.parse(line));

test('차단 후보만 근거 경보와 만료 시각을 붙이고 자동 적용하지 않는다', async () => {
  await isolated(async root => {
    const result = await respond(alerts, { root, now });
    assert.deepEqual(result.counts, { block: 10, alert: 9, record: 9, candidates: 10, suppressed: 0, expired: 10, applied: 0 });
    const rules = await candidates(root);
    assert.equal(rules.length, 10);
    for (const rule of rules) {
      assert.equal(rule.action, 'deny');
      assert.equal(rule.active, false);
      assert.equal(rule.match, null);
      assert.equal(rule.alertIds.length, 1);
      const sourceAlert = alerts.find(alert => alert.id === rule.alertIds[0]);
      assert.ok(sourceAlert.rule.level >= 10);
      assert.equal(rule.createdAt, new Date(sourceAlert.timestamp).toISOString());
      assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), TTL_MS);
      assert.equal(rule.status, 'pending_verified_binding');
    }
    assert.equal(result.notices, 19);
    const notices = await logs(root);
    assert.equal(notices.length, 19);
    assert.ok(notices.every(row => row.action === 'block' || row.action === 'alert'));
    assert.equal(notices.filter(row => row.status === 'expired_candidate').length, 10);
  });
});

test('경보 재전송은 규칙을 중복 생성하거나 만료를 연장하지 않고 로그를 추가한다', async () => {
  await isolated(async root => {
    await respond(alerts, { root, now });
    const before = await candidates(root);
    await respond(alerts, { root, now: now + TTL_MS });
    assert.deepEqual(await candidates(root), before);
    assert.equal((await logs(root)).length, 38);
  });
});

test('같은 출발 주소에 정상 이벤트가 있으면 주소 거부 후보를 추가하지 않는다', async () => {
  await isolated(async root => {
    const normal = alerts.find(alert => alert.rule.description === '로그인이 성공했습니다.');
    const attack = { ...alerts[0], data: { ...alerts[0].data, srcip: normal.data.srcip } };
    const result = await respond([attack, normal], { root, now });
    assert.equal(result.counts.suppressed, 1);
    assert.equal(result.counts.candidates, 0);
    assert.deepEqual(await candidates(root), []);
    assert.equal((await logs(root))[0].status, 'suppressed_normal_source');
  });
});

test('나중에 정상 이벤트가 확인된 주소의 기존 후보도 계속 억제한다', async () => {
  await isolated(async root => {
    const attack = alerts[0];
    const normal = { ...alerts.find(alert => alert.rule.description === '로그인이 성공했습니다.'), data: { srcip: attack.data.srcip } };
    await respond([attack], { root, now });
    await respond([normal], { root, now });
    assert.equal((await candidates(root))[0].status, 'suppressed_normal_source');
    const result = await respond([attack], { root, now });
    assert.equal(result.counts.candidates, 0);
    assert.equal(result.counts.suppressed, 1);
    assert.equal((await candidates(root))[0].status, 'suppressed_normal_source');
  });
});

test('미래 사건·부족한 식별자·비밀처럼 보이는 필드는 활성 규칙이나 로그 원문으로 쓰지 않는다', async () => {
  await isolated(async root => {
    const marker = randomBytes(24).toString('hex');
    const unsafe = { ...alerts[0], id: marker, data: { ...alerts[0].data, srcuser: marker, password: marker, token: marker } };
    const future = { ...alerts[0], timestamp: new Date(now + 60000).toISOString() };
    const result = await respond([unsafe, future], { root, now });
    assert.equal(result.counts.candidates, 0);
    assert.deepEqual(await candidates(root), []);
    const text = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
    assert.ok(!text.includes(marker));
    assert.ok(!text.includes(alerts[0].data.srcip));
    assert.ok(!text.includes(alerts[0].rule.description));
  });
});

test('기존 ZTNA 규칙·다섯 응답 항목을 보존하며 정상 통과를 주장하지 않는다', async () => {
  await isolated(async root => {
    const sourceUrl = new URL('../src/decider.mjs', import.meta.url);
    const original = await readFile(sourceUrl);
    const { normal } = fixtureRequests();
    const before = await ztnaDecide(normal);
    await respond(alerts, { root, now });
    const after = await ztnaDecide(normal);
    assert.deepEqual(after, before);
    assert.equal(after.decision, 'deny');
    assert.deepEqual(RULE_IDS, ['starter.deny']);
    assert.deepEqual(Object.keys(after).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    assert.ok(original.equals(await readFile(sourceUrl)));
  });
});
