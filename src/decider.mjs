// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 정확한 메모 읽기·수정 경로를 열고 복합 가상 이상 사건에는 추가 확인을 요구합니다.
// 소유권 비교는 기존 메모 API에 남아 있으며 강사 권한 계약은 아직 없습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required',
  'resource_route', 'notes_read_write', 'notices_write_denied']);

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const NOTE_ITEM = new RegExp(`^(/api/notes|/notes)/(${UUID})/?$`, 'u');
const NOTICE_ITEM = new RegExp(`^/api/notices/(${UUID})/?$`, 'u');
const EMPTY_QUERY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function noteRoute(request) {
  if (request.service !== 'notes') return false;
  // The official engine practice resource uses the opaque ID "demo".
  // It is an engine route, not a UUID accepted by the deployed notes API.
  if (['/notes/demo', '/notes/demo/'].includes(request.path)) {
    return ['GET', 'PUT'].includes(request.method)
      && request.route === `${request.method} /notes/:id`;
  }
  if (['/api/my/notes', '/api/my/notes/'].includes(request.path)) {
    return request.method === 'GET' && request.route === 'GET /api/my/notes';
  }
  const item = NOTE_ITEM.exec(request.path);
  return !!item && ['GET', 'PUT'].includes(request.method)
    && request.route === `${request.method} ${item[1]}/:id`;
}

function noticeWriteRoute(request) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return false;
  const routePath = ['/api/notices', '/api/notices/'].includes(request.path)
    ? '/api/notices' : NOTICE_ITEM.test(request.path) ? '/api/notices/:id' : null;
  return routePath !== null && request.route === `${request.method} ${routePath}`;
}

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
  if (request.schema !== 'aleph.decision.v1'
      || !['classId', 'projectId', 'subjectId', 'service', 'method', 'path', 'route']
        .every(key => typeof request[key] === 'string' && request[key].trim()
          && request[key] === request[key].trim())
      || typeof request.deviceId !== 'string' || !/^[0-9a-f]{16}$/u.test(request.deviceId)) return false;
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
  // The contract only supplies query size/fingerprint, not its contents.
  // Use a UUID path segment for selection; never guess a query's operation.
  if (request.queryLength !== 0 || request.querySha256 !== EMPTY_QUERY_SHA256) {
    return {
      schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: ['resource_route'],
    };
  }
  // No verified instructor authority is supplied by the current contract.
  if (noticeWriteRoute(request)) {
    return {
      schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: ['notices_write_denied'],
    };
  }
  if (noteRoute(request)) {
    // This is a route gate. The existing notes API still verifies the login
    // and compares owner_id in the DB before every read or update. subjectId
    // is pseudonymous and must never be compared directly to that owner_id.
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
      ruleIds: [RULE_IDS[1], 'notes_read_write'],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: ['resource_route'],
  };
}
