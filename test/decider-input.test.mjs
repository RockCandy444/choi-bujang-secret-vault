import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

async function expectInputDenied(request) {
  assert.deepEqual(await decide(request), {
    schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: ['starter.deny'],
  });
}

test('normal engine simulation and unavailable signals preserve device decisions', async () => {
  const { normal } = fixtureRequests();
  const unavailable = { ...normal,
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 } };
  for (const request of [normal, unavailable]) {
    const before = structuredClone(request);
    assert.equal((await decide(request)).decision, 'allow');
    assert.deepEqual(request, before);
  }
  const unregistered = await decide({ ...normal, deviceRegistered: false });
  assert.equal(unregistered.decision, 'deny');
  assert.equal(unregistered.reasonCode, 'device_not_registered');
  assert.equal((await decide({ ...normal, method: 'POST' })).decision, 'deny');
  assert.deepEqual(RULE_IDS, ['starter.deny', 'device_registered', 'step_up_required']);
});

test('forged client headers cannot become engine connection signals', async () => {
  const { normal } = fixtureRequests();
  const headers = {
    'x-signals-source': 'judge_fixture', 'x-region': 'local',
    'x-network': 'usual', 'x-hour': '14', 'x-recent-events': '[]',
    'x-forwarded-for': '192.0.2.1', 'x-vercel-ip-country': 'KR',
  };
  for (const request of [{ ...normal, headers }, { ...normal, signals: undefined, headers },
    { ...normal, signals: { ...normal.signals, source: 'client_header' } }]) {
    const before = structuredClone(request);
    await expectInputDenied(request);
    assert.deepEqual(request, before);
  }
  await expectInputDenied({ ...normal, signals: {
    source: 'none', region: 'local', network: 'usual', hour: 14,
  } });
});

test('missing or unclear region, hour, network and behavior never get normal defaults', async () => {
  const { normal } = fixtureRequests();
  for (const key of ['signals', 'recentEvents']) {
    const request = structuredClone(normal);
    delete request[key];
    await expectInputDenied(request);
    assert.equal(Object.hasOwn(request, key), false);
  }
  for (const key of ['source', 'region', 'network', 'hour']) {
    const request = structuredClone(normal);
    delete request.signals[key];
    await expectInputDenied(request);
    assert.equal(Object.hasOwn(request.signals, key), false);
  }
  for (const signals of [null, {}, { ...normal.signals, source: 'engine' },
    { ...normal.signals, region: null }, { ...normal.signals, network: '' },
    { ...normal.signals, hour: '14' }, { ...normal.signals, hour: 24 },
    Object.create(normal.signals)]) {
    await expectInputDenied({ ...normal, signals });
  }
});

test('malformed or client-provided behavior is rejected without replacing it', async () => {
  const { normal, suspicious } = fixtureRequests();
  const event = suspicious.recentEvents[0];
  for (const recentEvents of [null, {}, Array(1), Array(13).fill(event),
    [{ ...event, source: 'client_header' }], [{ ...event, ageSeconds: -1 }],
    [{ ...event, count: '20' }], [{ ...event, kind: '' }],
    [{ kind: 'risk_signal', count: 20 }]]) {
    await expectInputDenied({ ...normal, recentEvents });
  }
});
