const SUBJECT = /^[a-z0-9](?:[a-z0-9_:-]{0,118}[a-z0-9])?$/u;

// Read only the fields in docs/DETECT_EVENTS.md. Extra event fields are neither
// copied nor returned, so bodies, tokens, names and device secrets cannot enter
// the detector's working input through this boundary.
export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  return Object.freeze(events.map(event => {
    if (!event || typeof event !== 'object' || Array.isArray(event)
        || typeof event.at !== 'string' || event.at.length > 30
        || !Number.isFinite(Date.parse(event.at))
        || new Date(event.at).toISOString() !== event.at
        || event.method !== 'GET'
        || !event.identity || typeof event.identity !== 'object'
        || Array.isArray(event.identity)
        || typeof event.identity.sub !== 'string'
        || !SUBJECT.test(event.identity.sub)) {
      throw new TypeError('invalid_detection_event');
    }
    return Object.freeze({ at: event.at, method: event.method, subject: event.identity.sub });
  }));
}

// Official starter's local practice contract only: a subject-scoped burst proposal.
// This is NOT the portal's compound network rule or a verified device revocation.
// No permission is changed here; live event delivery/enforcement is unverified.
export function detect(events) {
  const safeEvents = [...readDetectionEvents(events)]
    .sort((left, right) => left.at.localeCompare(right.at));
  const windows = new Map();
  for (const event of safeEvents) {
    const reads = windows.get(event.subject) ?? [];
    const now = Date.parse(event.at);
    while (reads.length > 0 && now - reads[0] > 10 * 60 * 1000) reads.shift();
    reads.push(now);
    windows.set(event.subject, reads);
    if (reads.length > 120) {
      return { action: 'propose_revocation', reasonCode: 'burst_read', subject: event.subject };
    }
  }
  return { action: 'observe' };
}
