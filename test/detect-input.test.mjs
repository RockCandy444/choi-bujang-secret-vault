import assert from 'node:assert/strict';
import test from 'node:test';
import { detect, readDetectionEvents } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1);
const marker = 'must-not-be-stored-or-printed';

function reads(count, subject = 'learner_fixture') {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(START + index * 2000).toISOString(),
    method: 'GET',
    identity: { sub: subject, realName: marker },
    deviceKey: marker,
    noteBody: marker,
    token: marker,
  }));
}

test('normal and suspicious virtual reads keep only contract-safe input', () => {
  for (const events of [reads(30), reads(121)]) {
    const safe = readDetectionEvents(events);
    assert.equal(safe.length, events.length);
    assert.deepEqual(Object.keys(safe[0]), ['at', 'method', 'subject']);
    assert.equal(safe[0].subject, 'learner_fixture');
    assert.equal(JSON.stringify(safe).includes(marker), false);
  }
  assert.deepEqual(detect(reads(30)), { action: 'observe' });
  assert.deepEqual(detect(reads(121)), {
    action: 'propose_revocation', reasonCode: 'burst_read', subject: 'learner_fixture',
  });
});

test('only a same-subject burst inside ten minutes is suspicious', () => {
  assert.deepEqual(detect(reads(120)), { action: 'observe' });
  assert.deepEqual(detect(reads(200).map((event, index) => ({
    ...event, at: new Date(START + index * 7000).toISOString(),
  }))), { action: 'observe' });
  assert.deepEqual(detect([
    ...reads(100), ...reads(100, 'other_fixture'),
  ].reverse()), { action: 'observe' });
});

test('malformed event errors do not echo names, note bodies, tokens or device keys', () => {
  for (const event of [
    { at: 'not-a-time', method: 'GET', identity: { sub: marker }, token: marker },
    { at: new Date(START).toISOString(), method: 'POST', identity: { sub: 'learner_fixture' }, noteBody: marker },
    { at: new Date(START).toISOString(), method: 'GET', identity: { sub: `person name ${marker}` }, deviceKey: marker },
  ]) {
    assert.throws(() => readDetectionEvents([event]), error => {
      assert.equal(error.message, 'invalid_detection_event');
      assert.equal(error.message.includes(marker), false);
      return true;
    });
  }
});
