import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Script, createContext } from 'node:vm';
import { test } from 'node:test';
import * as module from '../xdr/brute-force/decide.mjs';
import { extractAlerts } from '../xdr/brute-force/read-alerts.mjs';
import { isDecision } from '../scripts/xdr-run.mjs';

const fixtureUrl = new URL('../xdr/fixtures/brute-force.json', import.meta.url);
const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
const ambiguous = fixture.alerts.find(alert => alert.rule.description.includes('평소와 다른 주소'));

async function withJev(fetchStub, run, configured = true) {
  const savedKey = process.env.TYPESAFE_API_KEY;
  const savedFetch = globalThis.fetch;
  if (configured) process.env.TYPESAFE_API_KEY = randomBytes(24).toString('hex');
  else delete process.env.TYPESAFE_API_KEY;
  globalThis.fetch = fetchStub;
  try { return await run(); }
  finally {
    globalThis.fetch = savedFetch;
    if (savedKey === undefined) delete process.env.TYPESAFE_API_KEY;
    else process.env.TYPESAFE_API_KEY = savedKey;
  }
}

function response(noul, type = 'noul') {
  return { ok: true, json: async () => ({ answers: { brute_force: { type, noul } } }) };
}

test('키 없는 가상 경보는 세 행동으로 나뉘며 추출 전후 결과가 같다', async () => {
  assert.deepEqual(Object.keys(module), ['decide']);
  await withJev(() => { throw new Error('네트워크를 부르면 안 됩니다.'); }, async () => {
    const rows = extractAlerts(fixture);
    const patterns = JSON.parse(await readFile(new URL('../xdr/brute-force/patterns.json', import.meta.url), 'utf8'));
    const reasons = new Set([...patterns.map(pattern => pattern.name), '근거 패턴 없음']);
    const counts = { block: 0, alert: 0, record: 0 };
    for (const [index, alert] of fixture.alerts.entries()) {
      const out = await module.decide(alert);
      assert.equal(isDecision(out), true);
      assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
      assert.ok(reasons.has(out.reason));
      assert.equal(/[\r\n]/u.test(out.reason), false);
      assert.deepEqual(await module.decide(rows[index]), out);
      counts[out.action] += 1;
    }
    assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
  }, false);
});

test('Jev는 애매한 경보에만 호출하고 원문·식별자·비밀 필드를 전송하지 않는다', async () => {
  const marker = randomBytes(24).toString('hex');
  let calls = 0;
  await withJev(async (url, options) => {
    calls += 1;
    assert.equal(url, 'https://api.typesafe.ai/v1/systemone');
    assert.equal(options.redirect, 'error');
    const body = JSON.parse(options.body);
    assert.equal(body.model, 'jev-latest');
    assert.equal(body.questions.brute_force.type, 'noul');
    assert.ok(!options.body.includes(marker));
    const { facts } = body.state;
    assert.ok(Object.values(facts).every(value => value === null || typeof value === 'number' || typeof value === 'boolean'));
    return response(0.65);
  }, async () => {
    for (const alert of fixture.alerts) await module.decide(alert);
    assert.equal(calls, 9);
    const out = await module.decide({
      ...ambiguous,
      id: marker, timestamp: marker,
      data: { srcip: marker, srcuser: marker, password: marker, token: marker },
      rule: { ...ambiguous.rule, description: `${ambiguous.rule.description} ${marker}` },
    });
    assert.equal(out.action, 'alert');
    assert.ok(!JSON.stringify(out).includes(marker));
  });
});

test('Jev 공격 가능성에 0.5와 0.85의 경계를 정확하게 적용한다', async () => {
  for (const [noul, action] of [[0, 'record'], [0.4999, 'record'], [0.5, 'alert'], [0.8499, 'alert'], [0.85, 'block'], [1, 'block']]) {
    await withJev(async () => response(noul), async () => {
      const out = await module.decide(ambiguous);
      assert.equal(out.confidence, noul);
      assert.equal(out.action, action);
    });
  }
});

test('Jev의 오류·틀린 응답·범위 밖 숫자는 alert로 남는다', async () => {
  const cases = [
    async () => { throw new Error('모의 연결 실패'); },
    async () => ({ ok: false }),
    async () => ({ ok: true, json: async () => { throw new Error('모의 JSON 실패'); } }),
    async () => response(0.95, 'choice'),
    ...[-0.1, 1.1, NaN, Infinity, '0.95', null, undefined].map(value => async () => response(value)),
  ];
  for (const fetchStub of cases) {
    await withJev(fetchStub, async () => {
      const out = await module.decide(ambiguous);
      assert.equal(out.action, 'alert');
      assert.equal(out.confidence, 0.5);
    });
  }
});

test('요청이나 응답 본문이 멈춰도 1초 제한으로 alert를 반환하고 취소한다', async () => {
  for (const stuckBody of [false, true]) {
    let aborted = false;
    await withJev(async (_url, options) => {
      options.signal.addEventListener('abort', () => { aborted = true; });
      if (stuckBody) return { ok: true, json: () => new Promise(() => {}) };
      return new Promise(() => {});
    }, async () => {
      const start = performance.now();
      const out = await module.decide(ambiguous);
      assert.equal(out.action, 'alert');
      assert.equal(out.confidence, 0.5);
      assert.equal(aborted, true);
      assert.ok(performance.now() - start < 1900);
    });
  }
});

test('수준·주소·계정 수만으로 차단하거나 같은 비밀번호를 추정하지 않는다', async () => {
  await withJev(() => { throw new Error('키 없이 호출 금지'); }, async () => {
    for (const alert of [
      { rule: { level: 12, description: '로그인이 성공했습니다.' }, data: { srcip: '192.0.2.1' } },
      { rule: { level: 7, description: '같은 주소에서 두 계정의 로그인 실패가 4건입니다.' }, data: { srcip: '192.0.2.1', count: '4' } },
      { rule: { level: 12, description: '로그인 실패가 4건입니다.' }, data: { srcip: '192.0.2.1', count: '4' } },
      null, {},
    ]) {
      const out = await module.decide(alert);
      assert.equal(out.action, 'alert');
      const reason = alert?.rule?.description.includes('실패')
        ? '같은 주소의 짧은 시간 연속 로그인 실패' : '근거 패턴 없음';
      assert.equal(out.reason, reason);
    }
  }, false);
});

test('인터넷·환경변수·모듈 import가 없는 격리 환경에서도 판단한다', async () => {
  const source = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  assert.equal(/\bimport\s*(?:\(|["'{*])/u.test(source), false);
  const isolatedDecide = new Script(source.replace('export async function decide', 'async function decide') + '\ndecide;')
    .runInContext(createContext({}));
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) counts[(await isolatedDecide(alert)).action] += 1;
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
});
