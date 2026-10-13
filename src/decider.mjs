// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 등록 기기의 자료실 읽기는 허용하되 복합 가상 이상 사건에는 추가 확인을 요구합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required']);

const REQUEST_KEYS = [
  'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
  'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
];
const record = value => value !== null && typeof value === 'object'
  && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const exactKeys = (value, keys) => record(value)
  && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));

function validConnectionInput(request) {
  // Only accept the engine contract. Never read client headers or invent defaults.
  if (!exactKeys(request, REQUEST_KEYS)
      || !exactKeys(request.signals, ['source', 'region', 'network', 'hour'])) return false;
  const signals = request.signals;
  if (!Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23) return false;
  if (signals.source === 'none') {
    // Unavailable location/network data stays unknown, never local/usual.
    if (signals.region !== 'unknown' || signals.network !== 'unknown') return false;
  } else if (signals.source === 'judge_fixture') {
    // Engine-provided simulation data is not evidence of a real location.
    if (!['local', 'foreign', 'unknown'].includes(signals.region)
        || !['usual', 'unusual', 'unknown'].includes(signals.network)) return false;
  } else {
    return false;
  }
  // recentEvents comes separately from the engine; an absent array is not [].
  if (!Array.isArray(request.recentEvents) || request.recentEvents.length > 12) return false;
  for (const event of request.recentEvents) {
    if (!exactKeys(event, ['kind', 'ageSeconds', 'count'])
        || typeof event.kind !== 'string' || !event.kind.trim()
        || !Number.isSafeInteger(event.ageSeconds) || event.ageSeconds < 0
        || !Number.isSafeInteger(event.count) || event.count < 0) return false;
  }
  return true;
}

export async function decide(request) {
  if (!validConnectionInput(request)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'starter_not_ready',
      ruleIds: [RULE_IDS[0]],
    };
  }
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[1]],
    };
  }
  if (request.service === 'notes' && request.method === 'GET') {
    // Local simulation thresholds, not a real location or per-user history.
    // risk_signal/count is the existing fixture's synthetic bulk-reading event.
    const compositeRisk = request.signals.source === 'judge_fixture'
      && request.signals.hour < 6 && request.signals.network === 'unusual'
      && request.recentEvents.some(event => event.kind === 'risk_signal'
        && event.ageSeconds <= 60 && event.count >= 20);
    // Only a valid, recent confirmation supplied by the engine can satisfy it.
    const recentlyConfirmed = exactKeys(request.stepUp, ['verified', 'authAgeSeconds'])
      && request.stepUp.verified === true
      && Number.isSafeInteger(request.stepUp.authAgeSeconds)
      && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= 900;
    if (compositeRisk && !recentlyConfirmed) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'step_up',
        reasonCode: 'step_up_required',
        ruleIds: [RULE_IDS[1], RULE_IDS[2]],
      };
    }
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: [RULE_IDS[1]],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: [RULE_IDS[0]],
  };
}
