import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('fixed composite fixture requests step-up with a reason and keeps five response fields', async () => {
  const { normal, suspicious } = fixtureRequests();
  const before = structuredClone(suspicious);
  assert.deepEqual(await decide(suspicious), {
    schema: 'aleph.decision.v1', requestId: suspicious.requestId,
    decision: 'step_up', reasonCode: 'step_up_required',
    ruleIds: ['device_registered', 'step_up_required'],
  });
  assert.equal((await decide(normal)).decision, 'allow');
  assert.deepEqual(suspicious, before);
  // No remembered or permanent block after the composite event.
  assert.equal((await decide(normal)).decision, 'allow');
});

test('region alone never blocks and every time/network/bulk component is required', async () => {
  const { normal, suspicious } = fixtureRequests();
  const event = suspicious.recentEvents[0];
  const allowed = [
    { ...normal, signals: { ...normal.signals, region: 'foreign' } },
    { ...suspicious, signals: { ...suspicious.signals, hour: 6 } },
    { ...suspicious, signals: { ...suspicious.signals, network: 'usual' } },
    { ...suspicious, signals: { ...suspicious.signals, network: 'unknown' } },
    { ...suspicious, recentEvents: [] },
    { ...suspicious, recentEvents: [{ ...event, ageSeconds: 61 }] },
    { ...suspicious, recentEvents: [{ ...event, count: 19 }] },
    { ...suspicious, recentEvents: [{ ...event, kind: 'unrelated_event' }] },
    { ...suspicious, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 3 } },
  ];
  for (const request of allowed) assert.equal((await decide(request)).decision, 'allow');
  for (const region of ['local', 'foreign', 'unknown']) {
    for (const hour of [0, 5]) {
      assert.equal((await decide({ ...suspicious,
        signals: { ...suspicious.signals, region, hour } })).decision, 'step_up');
    }
  }
});

test('unregistered devices and non-reading requests keep their existing denials', async () => {
  const { suspicious } = fixtureRequests();
  const denied = await decide({ ...suspicious, deviceRegistered: false,
    stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.reasonCode, 'device_not_registered');
  assert.deepEqual(denied.ruleIds, ['device_registered']);
  for (const request of [{ ...suspicious, service: 'other' }, { ...suspicious, method: 'POST' }]) {
    assert.equal((await decide(request)).decision, 'deny');
  }
});

test('engine confirmation requires both verified=true and a valid recent age', async () => {
  const { suspicious } = fixtureRequests();
  for (const authAgeSeconds of [0, 60, 900]) {
    assert.equal((await decide({ ...suspicious,
      stepUp: { verified: true, authAgeSeconds } })).decision, 'allow');
  }
  for (const stepUp of [null, {}, { verified: true },
    { verified: false, authAgeSeconds: 60 }, { verified: true, authAgeSeconds: null },
    { verified: true, authAgeSeconds: '60' }, { verified: true, authAgeSeconds: -1 },
    { verified: true, authAgeSeconds: 901 },
    { verified: true, authAgeSeconds: 60, source: 'client_header' }]) {
    const response = await decide({ ...suspicious, stepUp });
    assert.equal(response.decision, 'step_up');
    assert.equal(response.reasonCode, 'step_up_required');
  }
});
