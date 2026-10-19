// Alekov 학생 클라이언트 — 제공 공통 UI.
// 모든 외부·서버 문자열은 textContent로만 표시한다. innerHTML/insertAdjacentHTML 사용 금지.
// 자동 재시도 없음: 모든 요청은 사용자 동작 또는 최초 1회 로드에서만 일어난다.
import { normalizeScan, createVulnerabilitiesView } from '/vulnerabilities-view.mjs';

const STUDENT_MODULE = '/student/extension.mjs';
const STUDENT_PENDING = '학생 구현 대기';
const REQUEST_TIMEOUT_MS = 10000;
const UNVERIFIED_MESSAGE = '서버 응답 형식을 확인할 수 없습니다(확인 불가). 정상으로 간주하지 마세요.';

const MODE_LABELS = {
  connected: '연결됨',
  demo: '예제 데이터(demo) · 실제 연결 아님',
  disconnected: '연결 없음',
  unknown: '연결 상태 확인 불가',
};

const DECISIONS = {
  allow: { label: '허용', note: '서버가 이 앱 접속을 허용했습니다.' },
  deny: { label: '차단', note: '서버가 이 앱 접속을 차단했습니다.' },
  challenge: { label: '추가 확인 필요', note: '서버가 추가 확인을 요구했습니다. 이 화면은 확인 절차를 대신 수행하지 않습니다.' },
  unknown: { label: '판정 불명', note: '서버가 판정을 내리지 못했습니다. 허용으로 간주하지 마세요.' },
};

const STATE_LABELS = {
  access: { allowed: '허용됨', denied: '거부됨', unknown: '확인 불가' },
  session: { active: '활성', expired: '만료', revoked: '회수됨', unknown: '확인 불가' },
  device: { compliant: '기준 충족', noncompliant: '기준 미충족', unknown: '확인 불가' },
};

const STATE_NAMES = { access: '접속', session: '세션', device: '기기' };

const KIND_LABELS ={ access: '접속 기록', xdr: 'XDR 사건' };

const STUDENT_GET_PATHS = ['/api/me', '/api/apps', '/api/events', '/api/devices', '/api/sessions', '/api/vulnerabilities'];

const RESOURCE_LABELS = {
  me: '로그인 정보',
  apps: '업무 앱',
  events: '보안 기록',
  devices: '기기',
  sessions: '세션',
  access: '접속 판정',
  diagnostics: '도움정보',
  vulnerabilities: '설치 패키지 조회',
};

const state = {
  view: 'protection',
  checkedAt: null,
  me: { status: 'loading' },
  apps: { status: 'loading' },
  events: { status: 'loading' },
  devices: { status: 'loading' },
  sessions: { status: 'loading' },
  access: { status: 'idle' },
  diagnostics: { status: 'idle' },
  vulnerabilities: { status: 'idle' },
  aiConnection: { status: 'idle' },
  selectedExplanation: { event: null, resource: { status: 'idle' } },
  errors: new Map(),
};

// 다시 불러오기마다 세대가 바뀐다. 이전 세대의 GET·접속 판정·AI 응답은 새 상태를 덮지 않는다.
let generation = 0;
let refreshController = null;
let accessController = null;
let vulnerabilitiesController = null;
let vulnerabilitiesGeneration = 0;
let vulnerabilitiesView = null;
const explainControllers = new Map();

const explainSlots = new Map();
let aiConnectionController = null;
let aiConnectionGeneration = 0;
let explanationGeneration = 0;
let studentView = null;
let studentLoadFailed = false;
// Confirmation is private to this module: never sent to DOM, student hooks,
// storage, URLs, diagnostics or logs. One current intent, no automatic retries.
let actionGeneration = 0;
let actionController = null;
let actionTicket = null;
let actionIntent = null;
let actionExpiryTimer = null;
let actionState = { status: 'idle', event: null, actionId: null, target: null, receipt: null, observation: null, message: '조치 제안은 아직 실행되지 않았습니다.' };

// ---------- 계약 검사 ----------

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const isId = (v) => typeof v === 'string' && ID_PATTERN.test(v);
const isText = (v) => typeof v === 'string' && v.length <= 2000;
const isRecord = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const oneOf = (list) => (v) => typeof v === 'string' && Object.hasOwn(list, v);
const isDeviceStatus = oneOf(STATE_LABELS.device);
const isSessionStatus = oneOf(STATE_LABELS.session);
const isAccessState = oneOf(STATE_LABELS.access);
const isTime = (v) => typeof v === 'string' && Number.isFinite(Date.parse(v));
const uniqueIds = (list) => new Set(list.map((row) => row.id)).size === list.length;
const isTextRow = (row) => isRecord(row) && isId(row.id) && isText(row.text);
const exactFields = (value, names) => isRecord(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const aiSecret = /(?:Bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+)/i;
const safeAiText = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max && !aiSecret.test(value) && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value);
const safeAiId = value => isId(value) && !aiSecret.test(value);
const safeAiTime = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));

const VALIDATORS = {
  me: (d) => isRecord(d) && [d.user, d.device, d.session].every((row) => isRecord(row) && isId(row.id))
    && isText(d.user.label) && isText(d.device.label) && isDeviceStatus(d.device.status) && isSessionStatus(d.session.status),
  apps: (d) => Array.isArray(d) && d.every((row) => isRecord(row) && isId(row.id) && isText(row.name)) && uniqueIds(d),
  devices: (d) => Array.isArray(d) && d.every((row) => isRecord(row) && isId(row.id) && isText(row.label) && isDeviceStatus(row.status)),
  sessions: (d) => Array.isArray(d) && d.every((row) => isRecord(row) && isId(row.id) && isSessionStatus(row.status)),
  events: (d) => Array.isArray(d) && uniqueIds(d) && d.every((row) => isRecord(row) && isId(row.id)
    && Object.hasOwn(KIND_LABELS, row.kind) && isTime(row.at) && isText(row.summary)
    && (row.appId == null || isId(row.appId))
    && Array.isArray(row.evidence) && row.evidence.every(isTextRow)
    && Array.isArray(row.rules) && row.rules.every(isTextRow)
    && isRecord(row.state) && isAccessState(row.state.access) && isSessionStatus(row.state.session) && isDeviceStatus(row.state.device)
    && Array.isArray(row.supportedActions) && row.supportedActions.every(isId)),
};

const decisionValidator = (appId) => (d) => isRecord(d) && d.appId === appId
  && Object.hasOwn(DECISIONS, d.decision) && isText(d.reason) && isTime(d.checkedAt);

function validExplanation(data, event) {
  const x = exactFields(data, ['explanation']) ? data.explanation : null;
  if (!exactFields(x, ['summary', 'evidenceIds', 'proposals', 'requiresHumanConfirmation', 'executed']) || !safeEventForAi(event)) return null;
  const evidenceIds = new Set(event.evidence.map((e) => e.id));
  const refs = (list) => Array.isArray(list) && list.length > 0 && new Set(list).size === list.length
    && list.every((ref) => safeAiId(ref) && evidenceIds.has(ref));
  if (!safeAiText(x.summary, 1500) || !refs(x.evidenceIds) || x.evidenceIds.length !== evidenceIds.size) return null;
  if (!Array.isArray(x.proposals) || x.proposals.length > 3) return null;
  const proposalsOk = x.proposals.every((p) => exactFields(p, ['action', 'evidenceIds', 'reason']) && safeAiId(p.action) && event.supportedActions.includes(p.action)
    && refs(p.evidenceIds) && safeAiText(p.reason, 500));
  if (!proposalsOk || x.requiresHumanConfirmation !== true || x.executed !== false) return null;
  return structuredClone(x);
}

function safeEventForAi(event) {
  return event && safeAiId(event.id) && safeAiText(event.summary, 2000)
    && Array.isArray(event.evidence) && event.evidence.length > 0 && event.evidence.length <= 20 && uniqueIds(event.evidence)
    && event.evidence.every(row => safeAiId(row.id) && safeAiText(row.text, 500))
    && Array.isArray(event.rules) && event.rules.length > 0 && event.rules.length <= 20 && uniqueIds(event.rules)
    && event.rules.every(row => safeAiId(row.id) && safeAiText(row.text, 300)) && event.supportedActions.every(safeAiId);
}

function validAiCheck(data, meta) {
  if (!exactFields(data, ['transportChecked', 'audienceAuthorization', 'modelCount', 'help']) || data.transportChecked !== true
    || !['test', 'verified'].includes(data.audienceAuthorization) || !Number.isInteger(data.modelCount) || data.modelCount < 0 || data.modelCount > 10000
    || !safeAiTime(meta?.checkedAt)) return null;
  const help = data.help;
  if (!exactFields(help, ['component', 'code', 'appCredentialsConfigured', 'provisioning', 'automaticRetries', 'workbenchRequiredAtRuntime'])
    || help.component !== 'on-ai' || typeof help.appCredentialsConfigured !== 'boolean' || help.automaticRetries !== 0 || help.workbenchRequiredAtRuntime !== false) return null;
  if (data.audienceAuthorization === 'test' && (help.code !== 'ON_AI_TEST_TRANSPORT_ONLY' || help.provisioning !== 'pending')) return null;
  if (data.audienceAuthorization === 'verified' && (help.code !== 'ON_AI_APP_AUTHORIZATION_VERIFIED' || help.provisioning !== 'verified')) return null;
  return structuredClone(data);
}

const AI_MESSAGES = Object.freeze({
  ON_AI_PROVISIONING_PENDING: '학생 앱 이용 권한의 발급·연결을 준비 중입니다. 담당자에게 확인하세요.',
  WB_CLCO_AUTH_REQUIRED: '앱 전용 열쇠의 인증을 확인하세요. Workbench 열쇠를 복사하지 마세요.',
  WB_CLCO_ACCESS_BLOCKED: '학생 앱의 이용 권한을 확인하세요.',
  WB_CLCO_COHORT_BUDGET_EXHAUSTED: '반의 AI 사용량이 소진됐습니다. 담당자에게 확인하세요.',
  WB_CLCO_RATE_LIMITED: 'AI 요청이 잠시 제한됐습니다. 잠시 후 직접 다시 요청하세요.',
  WB_CLCO_LIMIT_REACHED: 'AI 이용 한도에 도달했습니다. 담당자에게 확인하세요.',
  WB_CLCO_SESSION_CLOSED: '현재 AI 이용 시간이 아닙니다. 이용 시간을 확인하세요.',
  WB_CLCO_TIMEOUT: 'AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.',
  REQUEST_TIMEOUT: '서버의 AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.',
  ENGINE_TIMEOUT: '서버의 확인 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.',
  TIMEOUT: 'AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.',
  WB_CLCO_CANCELLED: 'AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
  CANCELLED: 'AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
  REQUEST_CANCELLED: 'AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
  MODEL_NOT_CONFIGURED: '서버에 사용할 AI 모델을 설정하세요.',
  ON_AI_AUTHORIZATION_CHANGED: 'AI 이용 권한 내용이 점검 도중 바뀌었습니다. 다시 점검하기 전에 담당자에게 현재 권한을 확인하세요.',
  ON_AI_MODEL_LIST_EMPTY: '현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.',
  SUBJECT_SCOPE_UNVERIFIED: '현재 로그인과 사건·프로젝트의 연결을 확인할 수 없습니다.',
  ON_AI_INVALID_INPUT: '설명에 필요한 사건 근거·규칙을 확인할 수 없습니다.',
  ON_AI_INVALID_OUTPUT: 'AI 설명의 근거·조치·응답 형식을 확인할 수 없습니다.',
  AI_REQUEST_UNVERIFIED: 'AI 연결 또는 응답을 확인할 수 없습니다. 기존 기록을 확인하세요.',
});
function safeAiFailure(result) {
  const code = Object.hasOwn(AI_MESSAGES, result?.error?.code) ? result.error.code : 'AI_REQUEST_UNVERIFIED';
  return { status: 'error', error: { code, message: AI_MESSAGES[code] }, meta: UNKNOWN_META };
}

// ---------- DOM 도우미 ----------

const $ = (id) => document.getElementById(id);

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key === 'text') node.textContent = String(value);
    else if (key === 'className') node.className = value;
    else if (key === 'testid') node.dataset.testid = value;
    else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of [].concat(children)) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

function setChildren(target, ...children) {
  target.replaceChildren(...children.filter((c) => c != null && c !== false));
}

function formatTime(value) {
  if (typeof value !== 'string' || !value) return '시각 정보 없음';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('ko-KR');
}

function stateLabel(kind, value) {
  return `${STATE_LABELS[kind][value]}(${value})`;
}

function stateBox(kind, message) {
  return el('p', { className: `state state-${kind}`, role: kind === 'error' ? undefined : 'status', text: message });
}

function loadingBox() {
  return stateBox('loading', '불러오는 중…');
}

// ---------- HTTP ----------

function normalizeMeta(meta) {
  const mode = meta && ['connected', 'demo', 'disconnected'].includes(meta.mode) ? meta.mode : 'unknown';
  const checkedAt = meta && typeof meta.checkedAt === 'string' ? meta.checkedAt : null;
  return { mode, checkedAt };
}

function localFailure(code, message, meta = { mode: 'disconnected', checkedAt: null }) {
  return { ok: false, error: { code, message, retryable: false }, meta };
}

const UNKNOWN_META = { mode: 'unknown', checkedAt: null };

// 모든 요청은 10초 뒤 중단된다. signal로 호출자가 취소할 수 있으며, 응답이 없어도 화면이 잠기지 않는다.
async function request(path, { method = 'GET', body, signal } = {}) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, REQUEST_TIMEOUT_MS);
  const onAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }
  const aborted = () => (timedOut
    ? localFailure('TIMEOUT', '서버 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.', UNKNOWN_META)
    : localFailure('CANCELLED', '요청을 취소했습니다.', UNKNOWN_META));

  try {
    let response;
    try {
      response = await fetch(path, {
        method,
        headers: body ? { 'content-type': 'application/json', accept: 'application/json' } : { accept: 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
        credentials: 'same-origin',
        cache: 'no-store',
        signal: controller.signal,
      });
    } catch {
      return controller.signal.aborted ? aborted() : localFailure('NETWORK_ERROR', '로컬 서버에 연결할 수 없습니다.');
    }

    let json;
    try {
      json = await response.json();
    } catch {
      if (controller.signal.aborted) return aborted();
      return localFailure('INVALID_RESPONSE', `서버 응답을 읽을 수 없습니다. (HTTP ${response.status})`, UNKNOWN_META);
    }

    const meta = normalizeMeta(json && json.meta);
    // 선택 coverage 는 값만 옮긴다. 검증은 loadResource 가 해당 kind 에서만 한다. ok:false 응답의 coverage 는 버린다.
    if (json && json.ok === true && response.ok) {
      return { ok: true, data: json.data, meta, ...(Object.hasOwn(json, 'coverage') ? { coverage: json.coverage } : {}) };
    }
    if (json && json.ok === false) {
      const err = json.error || {};
      return {
        ok: false,
        error: {
          code: typeof err.code === 'string' ? err.code : 'UNKNOWN_ERROR',
          message: typeof err.message === 'string' && err.message ? err.message : '서버가 오류 내용을 제공하지 않았습니다.',
          retryable: err.retryable === true,
        },
        meta,
      };
    }
    return localFailure('INVALID_RESPONSE', `서버 응답 형식이 계약과 다릅니다. (HTTP ${response.status})`, UNKNOWN_META);
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

// AI requests remain bounded even when a test fetch or provider ignores its signal.
async function aiRequest(path, { body, signal } = {}) {
  if (signal?.aborted) return localFailure('CANCELLED', AI_MESSAGES.CANCELLED, UNKNOWN_META);
  const controller = new AbortController();
  let timer, cancel;
  const stopped = new Promise(resolve => {
    cancel = () => { resolve(localFailure('CANCELLED', AI_MESSAGES.CANCELLED, UNKNOWN_META)); controller.abort(); };
    timer = setTimeout(() => { resolve(localFailure('TIMEOUT', AI_MESSAGES.TIMEOUT, UNKNOWN_META)); controller.abort(); }, REQUEST_TIMEOUT_MS);
    if (signal?.aborted) cancel();
    else signal?.addEventListener('abort', cancel, { once: true });
  });
  try { return await Promise.race([request(path, { method: 'POST', body, signal: controller.signal }), stopped]); }
  finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); controller.abort(); }
}

// ---------- 공통 상태 ----------

// 본인 조회 범위(coverage). 서버가 보낸 경우에만 kind 별로 정확히 검사한다. 없으면 기존 어댑터·demo 동작 그대로다.
const COVERAGE_SCHEMA = 'alekov.sdp.coverage.v1';
const COVERAGE_KEYS = ['schema', 'kind', 'scope', 'limit', 'total', 'returned', 'truncated', 'observedAtMs'];
const COVERAGE_RULES = Object.freeze({
  events: { scope: 'own-recorded-events', limit: 40 },
  devices: { scope: 'own-registered-devices', limit: 100 },
  sessions: { scope: 'current-verified-connection', limit: 1 },
});
const COVERAGE_SKEW_MS = 5000;
const COVERAGE_MAX_AGE_MS = 20000;

function validCoverage(kind, coverage, data, timing) {
  const rule = COVERAGE_RULES[kind];
  if (!rule || !exactFields(coverage, COVERAGE_KEYS) || Object.getPrototypeOf(coverage) !== Object.prototype) return false;
  const { total, returned, truncated, observedAtMs, limit } = coverage;
  if (coverage.schema !== COVERAGE_SCHEMA || coverage.kind !== kind || coverage.scope !== rule.scope || limit !== rule.limit) return false;
  if (!Array.isArray(data) || !Number.isSafeInteger(total) || !Number.isSafeInteger(returned) || returned < 0 || returned > limit
    || returned !== data.length || total < returned || typeof truncated !== 'boolean' || truncated !== (total > returned)) return false;
  if (kind === 'sessions' && (total !== 1 || returned !== 1 || truncated !== false)) return false;
  // 이번 요청 전후 ±5초 안에서, 응답을 받은 때보다 20초 넘게 오래되지 않은 원천 확인 시각이어야 한다.
  if (!Number.isSafeInteger(observedAtMs) || observedAtMs <= 0 || !Number.isFinite(new Date(observedAtMs).getTime())
    || !timing || observedAtMs < timing.requestedAt - COVERAGE_SKEW_MS || observedAtMs > timing.receivedAt + COVERAGE_SKEW_MS
    || timing.receivedAt - observedAtMs > COVERAGE_MAX_AGE_MS) return false;
  return true;
}

// coverageKind·timing 은 선택 인자다. 주지 않으면 기존과 같다.
function toResource(result, validate, coverageKind, timing) {
  if (!result.ok) return { status: 'error', error: result.error, meta: result.meta };
  const mismatch = () => ({
    status: 'error',
    error: { code: 'CONTRACT_MISMATCH', message: UNVERIFIED_MESSAGE, retryable: false },
    meta: { mode: 'unknown', checkedAt: result.meta.checkedAt },
  });
  if (validate && !validate(result.data)) return mismatch();
  if (coverageKind && Object.hasOwn(result, 'coverage')) {
    // 잘못된 coverage 는 일부 성공으로 보정하지 않고 목록 전체를 확인 불가로 둔다.
    if (!validCoverage(coverageKind, result.coverage, result.data, timing)) return mismatch();
    const c = result.coverage;
    return { status: 'ok', data: result.data, meta: result.meta, coverage: Object.freeze({ schema: c.schema, kind: c.kind, scope: c.scope,
      limit: c.limit, total: c.total, returned: c.returned, truncated: c.truncated, observedAtMs: c.observedAtMs }) };
  }
  return { status: 'ok', data: result.data, meta: result.meta };
}

const isUnverified = (resource) => resource.status === 'error'
  && ['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED'].includes(resource.error.code);

function trackError(key, resource) {
  if (resource.status === 'error') state.errors.set(key, resource.error.message);
  else state.errors.delete(key);
  renderErrors();
  renderStudent('status');
}

// 현재 세대에서 끝난 응답의 mode가 모두 같을 때만 그 mode를 표시한다. 섞이거나 없으면 확인 불가.
function currentMode() {
  const modes = new Set();
  for (const key of ['me', 'apps', 'events', 'devices', 'sessions', 'access']) {
    const resource = state[key];
    if (resource.status === 'ok' || resource.status === 'error') modes.add(resource.meta ? resource.meta.mode : 'unknown');
  }
  return modes.size === 1 ? [...modes][0] : 'unknown';
}

function renderMode() {
  const badge = $('mode-badge');
  const mode = currentMode();
  badge.dataset.mode = mode;
  badge.textContent = MODE_LABELS[mode];
  $('checked-at').textContent = state.checkedAt ? `확인 시각 ${formatTime(state.checkedAt)}` : '';
  renderStudent('status');
}

function renderErrors() {
  const box = $('error-message');
  if (state.errors.size === 0) {
    box.hidden = true;
    box.replaceChildren();
    return;
  }
  const items = [...state.errors].map(([key, message]) =>
    el('li', {}, [el('strong', { text: `${RESOURCE_LABELS[key] || key}: ` }), message]),
  );
  setChildren(box, el('ul', {}, items));
  box.hidden = false;
}

// ---------- 메뉴 ----------

function selectView(view, { focus = false } = {}) {
  state.view = view;
  for (const tab of document.querySelectorAll('#nav [role="tab"]')) {
    const selected = tab.dataset.view === view;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    if (selected && focus) tab.focus();
    $(tab.getAttribute('aria-controls')).hidden = !selected;
  }
}

function setupNav() {
  const tabs = [...document.querySelectorAll('#nav [role="tab"]')];
  for (const tab of tabs) {
    tab.addEventListener('click', () => selectView(tab.dataset.view));
    tab.addEventListener('keydown', (event) => {
      const index = tabs.indexOf(tab);
      let next = null;
      if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
      else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = tabs[(index - 1 + tabs.length) % tabs.length];
      else if (event.key === 'Home') next = tabs[0];
      else if (event.key === 'End') next = tabs[tabs.length - 1];
      if (!next) return;
      event.preventDefault();
      selectView(next.dataset.view, { focus: true });
    });
  }
}

// ---------- 보호 현황 ----------

function renderAiConnection() {
  const target = $('ai-connection-result'), resource = state.aiConnection;
  target.dataset.state = resource.status;
  $('ai-check-cancel').disabled = resource.status !== 'loading';
  if (resource.status === 'idle') setChildren(target, stateBox('empty', 'AI 연결 점검 전입니다. 설정값 존재는 이용 권한 확인이 아닙니다.'));
  else if (resource.status === 'loading') setChildren(target, stateBox('loading', '현재 로그인으로 AI 모델 응답을 점검하는 중…'));
  else if (resource.status === 'error') setChildren(target, stateBox('error', `${resource.error.code}: ${resource.error.message}`));
  else {
    const data = resource.data;
    setChildren(target, el('p', { text: data.audienceAuthorization === 'test' ? '시험 transport의 모델 응답 점검(test) · 실제 게이트 수용 아님' : '앱 권한 확인 후 모델 응답 점검(verified)' }),
      resource.meta.mode === 'demo' ? el('p', { className: 'tag tag-demo', text: '예제 응답(demo) · 실제 게이트 수용 아님' }) : null,
      el('dl', { className: 'kv' }, [el('dt', { text: '응답 모델 수' }), el('dd', { text: data.modelCount }), el('dt', { text: '점검 시각' }), el('dd', { text: resource.meta.checkedAt })]),
      el('p', { className: 'muted', text: '이 점검은 사건 설명을 실행하지 않았습니다. 실제 사건 설명의 근거와 결과는 보안 기록에서 별도로 확인하세요.' }));
  }
  renderStudent('aiConnection');
}

function cancelAiCheck({ reset = false } = {}) {
  ++aiConnectionGeneration;
  if (aiConnectionController) aiConnectionController.abort();
  aiConnectionController = null;
  state.aiConnection = reset ? { status: 'idle' } : safeAiFailure({ error: { code: 'CANCELLED' } });
  renderAiConnection();
}

async function checkAiConnection() {
  const gen = generation, requestGen = ++aiConnectionGeneration;
  if (aiConnectionController) aiConnectionController.abort();
  const controller = new AbortController();
  aiConnectionController = controller;
  state.aiConnection = { status: 'loading' };
  renderAiConnection();
  try {
    const result = await aiRequest('/api/ai/check', { body: {}, signal: controller.signal });
    if (gen !== generation || requestGen !== aiConnectionGeneration) return;
    const data = result.ok ? validAiCheck(result.data, result.meta) : null;
    state.aiConnection = data ? { status: 'ok', data, meta: result.meta } : safeAiFailure(result.ok ? null : result);
    renderAiConnection();
  } finally { controller.abort(); if (aiConnectionController === controller) aiConnectionController = null; }
}

// ---------- AI 연결(17단계 연결 절차) ----------
// 주소·열쇠 입력 없음. 서버의 비공개 연결 관리자가 native·앱 전용 vault 로 연결을 관리한다.
// 경로가 root 에 연결되기 전에는 미연결 안내만 보이며 가짜 connected/demo 로 대체하지 않는다.
const ART = '/assets/alekov/';
let aiConnect = null;
let aiConnectModule = null;
let aiConnectLoadFailed = false;
let lastIdentityKey = null;

// 장식 그림: alt="" · aria-hidden. 상태 글과 분리하며, 읽지 못하면 숨긴다.
function art(name, className) {
  const img = el('img', { className: `alekov-art ${className}`, src: ART + name, alt: '', 'aria-hidden': 'true', decoding: 'async', draggable: 'false' });
  img.addEventListener('error', () => { img.hidden = true; }, { once: true });
  return img;
}

function guardStaticArt() {
  for (const img of document.querySelectorAll('img.alekov-art')) {
    const broken = () => { img.dataset.broken = 'true'; img.hidden = true; if (img.classList.contains('brand-icon')) $('brand-mark-fallback').hidden = false; };
    if (img.complete && img.naturalWidth === 0) broken();
    else img.addEventListener('error', broken, { once: true });
  }
}

// 승인 기한이 지나면 화면 안내만 바꾼다(서버 확인 없이 연결 상태 자체는 바꾸지 않는다).
let connectExpiryTimer = null;
function renderAiConnect() {
  const target = $('ai-connect-result');
  const s = aiConnect ? aiConnect.state : { phase: aiConnectLoadFailed ? 'unknown' : 'idle', reason: aiConnectLoadFailed ? 'ALEKOV_CONNECT_NOT_MOUNTED' : null };
  const busy = ['starting', 'finishing', 'cancelling'].includes(s.phase);
  if (connectExpiryTimer !== null) { clearTimeout(connectExpiryTimer); connectExpiryTimer = null; }
  const expiresMs = s.phase === 'awaiting_approval' ? Date.parse(s.expiresAt ?? '') : NaN;
  const approvalExpired = Number.isFinite(expiresMs) && Date.now() >= expiresMs;
  if (Number.isFinite(expiresMs) && !approvalExpired) connectExpiryTimer = setTimeout(renderAiConnect, Math.min(expiresMs - Date.now() + 50, 2147483647));
  target.dataset.state = s.phase;
  target.dataset.approvalExpired = approvalExpired ? 'true' : 'false';
  $('ai-connect-start').disabled = !aiConnect || busy || ['awaiting_approval', 'checking'].includes(s.phase);
  $('ai-connect-finish').disabled = !aiConnect || s.phase !== 'awaiting_approval' || approvalExpired;
  $('ai-connect-status').disabled = !aiConnect || !s.connectionId || busy;
  $('ai-connect-cancel').disabled = !aiConnect || !['starting', 'awaiting_approval', 'finishing', 'checking'].includes(s.phase);
  $('ai-connect-check').hidden = s.phase !== 'connected';
  const open = $('ai-connect-open');
  if (s.phase === 'awaiting_approval' && !approvalExpired && s.approvalUrl && aiConnectModule?.validApprovalUrl(s.approvalUrl, s.connectionId)) {
    open.href = s.approvalUrl;
    open.hidden = false;
  } else {
    open.removeAttribute('href');
    open.hidden = true;
  }
  // 초록 확인 표시가 있는 승인 그림은 실제 connected 결과에서만 보인다.
  $('ai-connect-art-connected').hidden = s.phase !== 'connected' || $('ai-connect-art-connected').dataset.broken === 'true';
  $('ai-connect-art-unknown').hidden = !['unknown', 'error'].includes(s.phase) || $('ai-connect-art-unknown').dataset.broken === 'true';
  const message = aiConnectModule ? aiConnectModule.connectMessage(s)
    : aiConnectLoadFailed ? '이 앱 버전에는 아직 AI 연결 화면이 연결되지 않았습니다(미연결). 기존 설명·판정·기록은 그대로 쓸 수 있습니다.' : 'AI 연결 화면을 준비하는 중…';
  const kind = s.phase === 'connected' ? 'ok' : ['error', 'unknown'].includes(s.phase) ? 'error' : ['idle', 'cancelled'].includes(s.phase) ? 'empty' : 'loading';
  setChildren(target,
    stateBox(kind, message),
    s.phase === 'awaiting_approval' ? el('dl', { className: 'kv connect-code' }, [
      el('dt', { text: '확인 번호' }), el('dd', { testid: 'ai-connect-confirmation', text: s.confirmation }),
      el('dt', { text: '승인 기한' }), el('dd', { text: formatTime(s.expiresAt) }),
    ]) : null,
    approvalExpired ? el('p', { testid: 'ai-connect-expired', className: 'muted', text: '승인 기한이 지났습니다. 이 요청으로는 더 승인할 수 없습니다. 「연결 취소」를 누른 뒤 「AI 연결 시작」으로 새로 시작하세요. 이미 승인했다면 「상태 다시 확인」으로 서버 결과를 먼저 확인하세요.' }) : null,
    s.phase === 'awaiting_approval' && !approvalExpired ? el('p', { className: 'muted', text: '새 창이 열리지 않으면 브라우저의 팝업·새 창 차단을 풀고 다시 누르세요. 승인 화면의 계정은 지금 로그인한 계정과 같아야 합니다.' }) : null,
    s.reason ? el('p', { className: 'muted', text: `상태 코드: ${s.reason}` }) : null,
    appConnectInvalidated && s.phase === 'idle' ? el('p', { testid: 'ai-connect-invalidated', className: 'muted', text: '계정 연결이 바뀌어 이전 AI 앱 승인 표시를 화면에서 지웠습니다. 서버의 앱 권한을 취소한 것은 아닙니다. 필요하면 「AI 연결 시작」을 직접 눌러 다시 진행하세요.' }) : null,
  );
}

// ---------- 계정 연결 확인(native 로그인) ----------
// AI 앱 승인과 별개다. 화면을 열 때 서버에 묻지 않고, 모든 요청은 버튼을 누를 때만 보낸다.
// 확인 번호·승인 링크는 저장소·도움정보·학생 hook 에 넘기지 않는다.
let nativeLogin = null;
let appConnectInvalidated = false;

// 사용자가 새 계정 연결·취소를 시작했거나 확인 결과 연결이 사라지면, 기존 앱 승인 표시와 AI 점검의 낡은 성공을 화면에서만 지운다.
// 서버의 앱 권한 취소나 로그인 성공으로 해석하지 않으며, 앱 승인을 자동으로 다시 시작하지 않는다.
function invalidateAppConnectView() {
  if ((aiConnect && aiConnect.state.phase !== 'idle') || state.aiConnection.status !== 'idle') appConnectInvalidated = true;
  if (aiConnect) aiConnect.reset();
  cancelAiCheck({ reset: true });
  renderAiConnect();
}

function renderNativeLogin() {
  const target = $('native-login-result');
  const fallback = { phase: aiConnectLoadFailed ? 'error' : 'idle', reason: aiConnectLoadFailed ? 'NATIVE_LOGIN_NOT_MOUNTED' : null };
  const view = nativeLogin && aiConnectModule ? aiConnectModule.nativeLoginView(nativeLogin.state, Date.now()) : null;
  const phase = view ? view.phase : fallback.phase;
  target.dataset.state = phase;
  $('native-login-start').disabled = !view || !view.canStart;
  $('native-login-redeem').disabled = !view || !view.canRedeem;
  $('native-login-check').disabled = !view || !view.canCheck;
  $('native-login-cancel').disabled = !view || !view.canCancel;
  const open = $('native-login-open');
  if (view && view.approvalUrl && aiConnectModule.validNativeApprovalUrl(view.approvalUrl)) {
    open.href = view.approvalUrl;
    open.hidden = false;
  } else {
    open.removeAttribute('href');
    open.hidden = true;
  }
  const message = view ? view.message
    : aiConnectLoadFailed ? '이 앱 버전에는 아직 계정 연결 화면이 연결되지 않았습니다(미연결). 기존 설명·판정·기록은 그대로 쓸 수 있습니다.' : '계정 연결 화면을 준비하는 중…';
  const kind = view ? view.kind : aiConnectLoadFailed ? 'error' : 'empty';
  const until = view && view.expiresAtMs !== null ? formatTime(new Date(view.expiresAtMs).toISOString()) : null;
  setChildren(target,
    stateBox(kind, message),
    view && view.confirmation ? el('dl', { className: 'kv connect-code' }, [
      el('dt', { text: '확인 번호' }), el('dd', { testid: 'native-login-confirmation', text: view.confirmation }),
      el('dt', { text: '확인 기한' }), el('dd', { text: until }),
    ]) : null,
    view && view.confirmation ? el('p', { className: 'muted', text: '이 번호는 포털에 직접 입력할 때만 쓰고 다른 곳에 옮겨 적지 마세요. 새 창이 열리지 않으면 브라우저의 새 창 차단을 풀고 다시 누르세요.' }) : null,
    view && view.phase === 'connected' ? el('dl', { className: 'kv' }, [el('dt', { text: '연결 확인 기한' }), el('dd', { testid: 'native-login-until', text: until })]) : null,
    view && view.reason ? el('p', { className: 'muted', text: `상태 코드: ${view.reason}` }) : null,
  );
}

async function loadConnectModule() {
  try {
    aiConnectModule = await import('/ai-connect.mjs');
    aiConnect = aiConnectModule.createAiConnectController({ onChange: () => renderAiConnect() });
    // 만들기만 한다. 첫 화면에서 native 요청은 보내지 않는다.
    nativeLogin = aiConnectModule.createNativeLoginController({ onChange: () => renderNativeLogin(), onInvalidate: () => invalidateAppConnectView() });
  } catch {
    aiConnectLoadFailed = true;
  }
  renderAiConnect();
  renderNativeLogin();
}

let connectHelpText = '';
function showConnectHelp() {
  const output = $('ai-connect-help-output');
  const info = aiConnect ? aiConnect.helpInfo() : { component: 'alekov-ai-connect', phase: 'unknown', reason: 'ALEKOV_CONNECT_NOT_MOUNTED', automaticRetries: 0, manualSecretInputs: 0 };
  connectHelpText = JSON.stringify(info, null, 2);
  output.textContent = connectHelpText;
  output.hidden = false;
  $('ai-connect-help-copy').disabled = false;
  $('ai-connect-help-status').textContent = '아래 내용을 직접 확인한 뒤 복사하세요. 연결 ID·승인 주소·학생 ID·로컬 경로는 넣지 않습니다.';
}

async function copyConnectHelp() {
  if (!connectHelpText) return;
  try {
    await navigator.clipboard.writeText(connectHelpText);
    $('ai-connect-help-status').textContent = '연결 도움정보를 클립보드에 복사했습니다.';
  } catch {
    $('ai-connect-help-status').textContent = '자동 복사를 사용할 수 없습니다. 위 내용을 선택해 Ctrl+C로 복사하세요.';
  }
}

// 다시 불러온 로그인·세션이 바뀌면 화면의 연결 진행을 버린다. 서버도 scope 전환을 직접 막는다.
function noteIdentity(resource) {
  if (resource.status !== 'ok') return;
  const key = `${resource.data.user.id}|${resource.data.session.id}`;
  if (lastIdentityKey !== null && lastIdentityKey !== key && aiConnect) aiConnect.reset();
  // 계정 연결 확인도 화면 진행만 버린다. 서버 취소를 보내거나 취소됐다고 표시하지 않는다.
  if (lastIdentityKey !== null && lastIdentityKey !== key && nativeLogin) nativeLogin.reset();
  lastIdentityKey = key;
}

function renderIdentity() {
  const me = state.me;
  const cells = { user: $('identity-user'), device: $('identity-device'), session: $('identity-session') };
  if (me.status === 'loading') {
    for (const cell of Object.values(cells)) cell.textContent = '불러오는 중';
    return;
  }
  if (me.status === 'error') {
    const text = isUnverified(me) ? '확인 불가 (응답 형식 불일치)' : '확인 불가 (요청 실패)';
    for (const cell of Object.values(cells)) cell.textContent = text;
    return;
  }
  const { user, device, session } = me.data;
  cells.user.textContent = user.label || user.id;
  cells.device.textContent = `${device.label || device.id} · ${stateLabel('device', device.status)}`;
  cells.session.textContent = `${session.id} · ${stateLabel('session', session.status)}`;
  if (me.meta && me.meta.mode === 'demo') {
    for (const cell of Object.values(cells)) cell.append(el('span', { className: 'tag tag-demo', text: 'demo' }));
  }
}

// 검증된 coverage 의 확인 시각. 원천이 확인한 시각이며 화면을 그린 시각이 아니다.
const coverageTime = (coverage) => formatTime(new Date(coverage.observedAtMs).toISOString());

// coverage 문구는 검증된 ok 상태에서만, 목록과 분리된 문단으로 보인다. 오류·불러오는 중에는 남기지 않는다.
function renderOwnedList(targetId, resource, emptyText, describe, coverageNotice) {
  const target = $(targetId);
  if (resource.status === 'loading') return setChildren(target, loadingBox());
  if (resource.status === 'error') return setChildren(target, stateBox('error', resource.error.message));
  const notice = resource.coverage && coverageNotice ? coverageNotice(resource.coverage) : null;
  if (resource.data.length === 0) return setChildren(target, stateBox('empty', emptyText), notice);
  setChildren(
    target,
    resource.meta && resource.meta.mode === 'demo' ? el('p', { className: 'tag tag-demo', text: '예제 데이터' }) : null,
    el('ul', { className: 'plain-list' }, resource.data.map((item) => el('li', {}, describe(item)))),
    notice,
  );
}

function renderDevices() {
  renderOwnedList('devices', state.devices, '표시할 기기가 없습니다.', (d) => [
    el('span', { className: 'item-title', text: d.label || d.id }),
    el('span', { className: 'muted', text: stateLabel('device', d.status) }),
  ], (c) => el('p', {
    className: 'muted',
    testid: 'devices-coverage',
    text: `현재 정책에 등록된 본인 기기 ${c.returned}개 / ${c.total}개`
      + (c.truncated ? ` · 나머지 ${c.total - c.returned}개는 생략됐습니다.` : '')
      + ` · 확인 시각 ${coverageTime(c)} · 운영체제 준수나 다른 인증서 상태는 확인하지 않아 상태를 확인 불가로 표시합니다.`,
  }));
}

function renderSessions() {
  renderOwnedList('sessions', state.sessions, '표시할 세션이 없습니다.', (s) => [
    el('span', { className: 'item-title', text: s.id }),
    el('span', { className: 'muted', text: stateLabel('session', s.status) }),
  ], (c) => el('p', {
    className: 'muted',
    testid: 'sessions-coverage',
    text: `현재 확인된 연결 1건 · 확인 시각 ${coverageTime(c)} · 전체 로그인이나 과거·다른 기기 세션 목록이 아닙니다.`,
  }));
}

let diagnosticsText = '';

async function loadDiagnostics() {
  const button = $('diag-load');
  const copy = $('diag-copy');
  const status = $('diag-status');
  const output = $('diag-output');
  button.disabled = true;
  copy.disabled = true;
  diagnosticsText = '';
  status.textContent = '도움정보를 불러오는 중…';
  output.hidden = true;
  state.diagnostics = { status: 'loading' };
  trackError('diagnostics', state.diagnostics);

  try {
    const resource = toResource(await request('/api/diagnostics'));
    state.diagnostics = resource;
    trackError('diagnostics', resource);
    if (resource.status === 'error') {
      status.textContent = `불러오지 못했습니다: ${resource.error.message}`;
      return;
    }
    diagnosticsText = JSON.stringify({ meta: resource.meta, data: resource.data }, null, 2);
    output.textContent = diagnosticsText;
    output.hidden = false;
    copy.disabled = false;
    status.textContent = '아래 내용을 직접 확인한 뒤 복사하세요. 복사 전에는 어디에도 전송되지 않습니다.';
  } finally {
    button.disabled = false;
  }
}

async function copyDiagnostics() {
  const status = $('diag-status');
  if (!diagnosticsText) return;
  try {
    await navigator.clipboard.writeText(diagnosticsText);
    status.textContent = '도움정보를 클립보드에 복사했습니다.';
  } catch {
    const output = $('diag-output');
    const range = document.createRange();
    range.selectNodeContents(output);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    output.focus();
    status.textContent = '자동 복사를 사용할 수 없습니다. 선택된 내용을 Ctrl+C로 복사하세요.';
  }
}

// ---------- 업무 앱 ----------

// OSV는 사용자 요청으로만 조회한다. 각 요청의 제한 시간과 세대를 함께 확인한다.
function renderVulnerabilities() {
  if (!vulnerabilitiesView) vulnerabilitiesView = createVulnerabilitiesView({ document });
  setChildren($('vulnerabilities-result'), vulnerabilitiesView.render(state.vulnerabilities));
  $('vulnerabilities-cancel').disabled = state.vulnerabilities.status !== 'loading';
  renderStudent('vulnerabilities');
}

function clearVulnerabilities() {
  ++vulnerabilitiesGeneration;
  if (vulnerabilitiesController) vulnerabilitiesController.abort();
  vulnerabilitiesController = null;
  state.vulnerabilities = { status: 'idle' };
  renderVulnerabilities();
}

function cancelVulnerabilities() {
  ++vulnerabilitiesGeneration;
  if (vulnerabilitiesController) vulnerabilitiesController.abort();
  vulnerabilitiesController = null;
  state.vulnerabilities = { status: 'error', error: { code: 'CANCELLED', message: '패키지 조회를 취소했습니다. 이전 결과는 현재 확인 결과가 아닙니다.' } };
  renderVulnerabilities();
}

async function loadVulnerabilities() {
  const gen = generation, requestGen = ++vulnerabilitiesGeneration;
  if (vulnerabilitiesController) vulnerabilitiesController.abort();
  const controller = new AbortController();
  vulnerabilitiesController = controller;
  state.vulnerabilities = { status: 'loading' };
  renderVulnerabilities();
  let timer;
  const deadline = new Promise(resolve => { timer = setTimeout(() => {
    resolve(localFailure('TIMEOUT', '패키지 조회 시간이 초과됐습니다. 필요하면 직접 다시 조회하세요.', UNKNOWN_META));
    controller.abort();
  }, REQUEST_TIMEOUT_MS); });
  try {
    const result = await Promise.race([request('/api/vulnerabilities', { signal: controller.signal }), deadline]);
    if (gen !== generation || requestGen !== vulnerabilitiesGeneration) return;
    if (result.ok) {
      const scan = normalizeScan(result.data);
      state.vulnerabilities = scan ? { status: 'ok', data: scan, meta: result.meta }
        : { status: 'error', error: { code: 'CONTRACT_MISMATCH', message: '패키지 조회 응답을 확인할 수 없습니다.' } };
    } else state.vulnerabilities = { status: 'error', error: { code: result.error.code, message: '패키지 조회를 확인할 수 없습니다. 이전 결과를 정상으로 표시하지 않습니다.' } };
    renderVulnerabilities();
  } finally {
    clearTimeout(timer);
    controller.abort();
    if (vulnerabilitiesController === controller) vulnerabilitiesController = null;
  }
}

function renderApps() {
  const target = $('apps');
  const apps = state.apps;
  if (apps.status === 'loading') return setChildren(target, loadingBox());
  if (apps.status === 'error') return setChildren(target, stateBox('error', apps.error.message));
  if (apps.data.length === 0) return setChildren(target, stateBox('empty', '현재 사용자에게 보이는 업무 앱이 없습니다.'));
  setChildren(
    target,
    apps.meta && apps.meta.mode === 'demo' ? el('p', { className: 'tag tag-demo', text: '예제 데이터' }) : null,
    el(
      'ul',
      { className: 'app-list' },
      // id는 계약 pattern(A-Za-z0-9._:-)을 통과한 값만 남으므로 testid에 그대로 쓴다.
      apps.data.map((app) =>
        el('li', {}, [
          el('button', {
            type: 'button',
            className: 'btn app-button',
            testid: `app-access-${app.id}`,
            'data-app-id': app.id,
            text: `${app.name || app.id} 접속 요청`,
            onclick: (event) => requestAccess(app.id, app.name || app.id, event.currentTarget),
          }),
        ]),
      ),
    ),
  );
}

async function requestAccess(appId, appName, button) {
  const gen = generation;
  const buttons = document.querySelectorAll('#apps .app-button');
  for (const b of buttons) b.disabled = true;
  if (accessController) accessController.abort();
  const controller = new AbortController();
  accessController = controller;
  state.access = { status: 'loading', appId, appName };
  renderAccess();
  renderStudent('decision');

  try {
    const result = await request('/api/access', { method: 'POST', body: { appId }, signal: controller.signal });
    if (gen !== generation || controller.signal.aborted) return;
    state.access = { ...toResource(result, decisionValidator(appId)), appId, appName };
    if (state.access.meta && state.access.meta.checkedAt) state.checkedAt = state.access.meta.checkedAt;
    trackError('access', state.access);
    renderMode();
    renderAccess();
    renderStudent('decision');
  } finally {
    if (accessController === controller) accessController = null;
    for (const b of buttons) b.disabled = false;
    if (gen === generation && button && document.body.contains(button)) button.focus();
  }
}

function renderAccess() {
  const target = $('access-result');
  const access = state.access;
  if (access.status === 'idle') {
    target.dataset.decision = 'none';
    return setChildren(target, el('p', { className: 'muted', text: '아직 요청한 앱이 없습니다.' }));
  }
  if (access.status === 'loading') {
    target.dataset.decision = 'pending';
    return setChildren(target, stateBox('loading', `${access.appName} 접속 판정 요청 중…`));
  }
  if (access.status === 'error') {
    const unverified = isUnverified(access);
    target.dataset.decision = unverified ? 'unverified' : 'request-failed';
    return setChildren(
      target,
      el('p', { className: 'decision decision-failed' }, [el('strong', { text: unverified ? '확인 불가' : '판정 요청 실패' }), ` · ${access.appName}`]),
      el('p', { text: access.error.message }),
      el('p', { className: 'muted', text: '요청 실패·확인 불가는 차단·허용 판정이 아닙니다. 필요하면 직접 다시 요청하세요.' }),
    );
  }
  const data = access.data;
  const info = DECISIONS[data.decision];
  target.dataset.decision = data.decision;
  setChildren(
    target,
    el('p', { className: `decision decision-${data.decision}` }, [el('strong', { text: info.label }), ` · ${access.appName}`]),
    el('p', { text: info.note }),
    el('dl', { className: 'kv' }, [
      el('dt', { text: '사유' }), el('dd', { text: data.reason || '사유 정보 없음' }),
      el('dt', { text: '판정 시각' }), el('dd', { text: formatTime(data.checkedAt) }),
      el('dt', { text: '데이터 상태' }), el('dd', { text: MODE_LABELS[(access.meta && access.meta.mode) || 'unknown'] }),
    ]),
  );
}

// ---------- 보안 기록 ----------

function renderEvents() {
  const list = $('records-list');
  const events = state.events;
  explainSlots.clear();
  if (events.status === 'loading') return setChildren(list, el('li', {}, loadingBox()));
  if (events.status === 'error') return setChildren(list, el('li', {}, stateBox('error', events.error.message)));
  // 확인 범위는 사건 카드(.event)와 분리한 항목이다. 전체 과거 로그·전체 XDR 기록이라고 말하지 않는다.
  const c = events.coverage;
  const notice = c ? el('li', { className: 'records-coverage', testid: 'records-coverage' }, el('p', {
    className: 'muted',
    text: `현재 등록부와 대조한 본인 기록 ${c.returned}건 / ${c.total}건`
      + (c.truncated ? ` · 최근 ${c.returned}건을 표시했습니다. 나머지 ${c.total - c.returned}건은 생략됐습니다.` : '')
      + ` · 확인 시각 ${coverageTime(c)}`,
  })) : null;
  if (events.data.length === 0) return setChildren(list, notice, el('li', { className: 'records-empty' }, [art('alekov-empty-records.webp', 'art-empty'), stateBox('empty', '표시할 보안 기록이 없습니다.')]));
  setChildren(list, notice, ...events.data.map((event) => renderEventItem(event, events.meta)));
}

function renderTextList(title, entries) {
  return el('div', { className: 'event-block' }, [
    el('h4', { text: title }),
    entries.length === 0
      ? el('p', { className: 'muted', text: '없음' })
      : el('ul', {}, entries.map((entry) => el('li', { text: entry.text || entry.id }))),
  ]);
}

function renderEventItem(event, meta) {
  const slot = el('div', { className: 'explain-slot', 'aria-live': 'polite' });
  explainSlots.set(event.id, slot);
  const actions = event.supportedActions;

  return el('li', { className: 'event', 'data-event-id': event.id }, [
    el('div', { className: 'event-head' }, [
      el('h3', { text: event.summary || '요약 없음' }),
      el('span', { className: 'tag', text: KIND_LABELS[event.kind] }),
      meta && meta.mode === 'demo' ? el('span', { className: 'tag tag-demo', text: 'demo' }) : null,
    ]),
    el('p', { className: 'muted', text: `${formatTime(event.at)} · 앱 ${event.appId || '없음'} · 기록 ${event.id}` }),
    el('dl', { className: 'kv' }, [
      el('dt', { text: '접속' }), el('dd', { text: stateLabel('access', event.state.access) }),
      el('dt', { text: '세션' }), el('dd', { text: stateLabel('session', event.state.session) }),
      el('dt', { text: '기기' }), el('dd', { text: stateLabel('device', event.state.device) }),
    ]),
    el('div', { className: 'grid-2' }, [renderTextList('근거', event.evidence), renderTextList('규칙', event.rules)]),
    el('div', { className: 'event-actions' }, [
      el('button', {
        type: 'button',
        className: 'btn',
        text: 'AI 설명 요청',
            testid: `ai-explain-${event.id}`,
        onclick: (e) => requestExplain(event, e.currentTarget),
      }),
      ...actions.map((action) =>
        el('button', {
          type: 'button',
          className: 'btn',
          disabled: true,
          'aria-disabled': 'true',
          title: '현재 사건의 AI 제안에서 준비한 뒤 원천 권한과 실제 대상을 확인하세요.',
          text: `${action} · AI 제안에서 준비`,
        }),
      ),
    ]),
    actions.length > 0
      ? el('p', { className: 'muted', text: '이 목록의 버튼은 집행 요청을 보내지 않습니다. AI 제안에서 조치를 직접 준비하고 원천 권한과 대상을 확인해야 하며, 기본 원천 연결은 미지원입니다.' })
      : el('p', { className: 'muted', testid: `no-supported-actions-${event.id}`, text: '이 기록에는 원천이 지원하는 조치가 없습니다. AI 설명은 볼 수 있지만 조치 제안과 집행 버튼은 나오지 않으며, 이것이 정상입니다.' }),
    slot,
  ]);
}

async function requestExplain(event, button) {
  clearAction();
  const gen = generation;
  const slot = explainSlots.get(event.id);
  if (!slot) return;
  const requestGen = ++explanationGeneration;
  for (const active of explainControllers.values()) active.abort();
  explainControllers.clear();
  for (const previousSlot of explainSlots.values()) setChildren(previousSlot);
  const controller = new AbortController();
  explainControllers.set(event.id, controller);
  button.disabled = true;
  const safeEvent = safeEventForAi(event) ? structuredClone(event) : null;
  state.selectedExplanation = { event: safeEvent, resource: { status: 'loading' } };
  renderStudent('explanation');
  $('ai-explanation-cancel').disabled = false;
  setChildren(slot, stateBox('loading', 'AI 설명을 요청하는 중…'));
  try {
    const result = safeEvent ? await aiRequest('/api/ai/explain', { body: { eventId: event.id }, signal: controller.signal })
      : localFailure('ON_AI_INVALID_INPUT', AI_MESSAGES.ON_AI_INVALID_INPUT, UNKNOWN_META);
    // 다시 불러오기 이후이거나 기록 칸이 바뀌었으면 늦은 응답은 버린다.
    if (gen !== generation || requestGen !== explanationGeneration || explainSlots.get(event.id) !== slot) return;
    // AI 결과는 기록 목록 상태와 분리한다. 실패해도 기록은 그대로 둔다.
    if (!result.ok) {
      state.selectedExplanation.resource = safeAiFailure(result);
      setChildren(slot, stateBox('error', `AI 설명 실패: ${state.selectedExplanation.resource.error.message}`), el('p', { className: 'muted', text: '기록은 그대로 유지됩니다. AI 연결이나 응답 문제는 과제 실패로 처리되지 않습니다.' }));
      renderStudent('explanation');
      return;
    }
    const explanation = validExplanation(result.data, event);
    if (!explanation || !safeAiTime(result.meta?.checkedAt)) {
      state.selectedExplanation.resource = safeAiFailure({ error: { code: 'ON_AI_INVALID_OUTPUT' } });
      setChildren(slot, stateBox('error', 'AI 설명 확인 불가: 응답 형식이나 근거 ID가 이 기록과 맞지 않습니다.'), el('p', { className: 'muted', text: '기록은 그대로 유지됩니다.' }));
      renderStudent('explanation');
      return;
    }
    state.selectedExplanation.resource = { status: 'ok', data: explanation, meta: result.meta };
    setChildren(slot, renderExplanation(explanation, event, result.meta));
    renderStudent('explanation');
  } finally {
    if (explainControllers.get(event.id) === controller) explainControllers.delete(event.id);
    if (document.body.contains(button)) button.disabled = false;
    if (requestGen === explanationGeneration) $('ai-explanation-cancel').disabled = true;
  }
}

function cancelExplanation({ reset = false } = {}) {
  clearAction();
  ++explanationGeneration;
  for (const controller of explainControllers.values()) controller.abort();
  explainControllers.clear();
  for (const slot of explainSlots.values()) setChildren(slot);
  const event = reset ? null : state.selectedExplanation.event;
  state.selectedExplanation = { event, resource: reset ? { status: 'idle' } : safeAiFailure({ error: { code: 'CANCELLED' } }) };
  $('ai-explanation-cancel').disabled = true;
  if (!reset && event && explainSlots.has(event.id)) setChildren(explainSlots.get(event.id), stateBox('error', AI_MESSAGES.CANCELLED));
  renderStudent('explanation');
}

function renderExplanation(x, event, meta) {
  const evidenceText = new Map(event.evidence.map((e) => [e.id, e.text]));
  const unknownStates = Object.keys(STATE_LABELS).filter((key) => event.state[key] === 'unknown');
  return el('div', { className: 'explanation' }, [
    el('h4', { text: 'AI 설명 (참고용 · 근거는 기록에 있음)' }),
    meta && meta.mode === 'demo' ? el('span', { className: 'tag tag-demo', text: 'demo' }) : null,
    el('p', { className: 'muted', text: '아래 요약은 AI가 이 기록을 읽고 쓴 해석입니다. 사실 판단은 인용한 근거와 원천이 알려 준 현재 상태를 기준으로 하세요.' }),
    el('p', { text: x.summary }),
    el('h5', { text: '인용한 근거 ID' }),
    el('ul', {}, x.evidenceIds.map((ref) => el('li', { text: `${ref} — ${evidenceText.get(ref)}` }))),
    renderTextList('현재 규칙', event.rules),
    el('h5', { text: '확인되지 않은 현재 상태' }),
    unknownStates.length === 0
      ? el('p', { className: 'muted', text: '없음' })
      : el('ul', {}, unknownStates.map((key) => el('li', { text: `${STATE_NAMES[key]}: 확인 불가(unknown)` }))),
    el('h5', { text: '조치 제안' }),
    x.proposals.length === 0
      ? el('p', { className: 'muted', testid: `no-proposals-${event.id}`, text: event.supportedActions.length === 0
        ? '원천이 지원하는 조치가 없어 AI가 조치를 제안하지 않았습니다. 정상입니다.'
        : 'AI가 이 기록에 맞는 조치를 제안하지 않았습니다. 필요하면 근거를 보고 담당자와 판단하세요.' })
      : el('ul', {}, x.proposals.map((p) => el('li', {}, [
        el('p', { text: `${p.action} — ${p.reason} (근거 ${p.evidenceIds.join(', ')})` }),
        el('button', { type: 'button', className: 'btn', text: `${p.action} 조치 준비`, testid: `action-prepare-${event.id}-${p.action}`, onclick: () => prepareAction(event,p.action) }),
      ]))),
    el('p', { className: 'muted', text: x.proposals.length === 0
      ? 'AI는 아무것도 실행하지 않았습니다.'
      : '제안은 실행되지 않았습니다. 조치 준비 뒤 실제 대상과 확인 기한을 읽고 별도의 사람 확인 버튼을 눌러야 합니다. 원천에서 지원하지 않으면 집행할 수 없습니다.' }),
  ]);
}

const ACTION_MESSAGES = Object.freeze({
  ACTION_UNSUPPORTED: '미지원: 현재 원천의 조치 연결·권한을 확인할 수 없습니다.',
  ACTION_DENIED: '거절: 현재 원천 정책이 이 조치를 허용하지 않습니다.',
  ACTION_CONFIRMATION_EXPIRED: '확인 기한 만료: 조치를 다시 준비하고 대상을 확인하세요.',
  ACTION_CONFIRMATION_INVALID: '조치 확인 정보가 유효하지 않습니다. 다시 준비하세요.',
  ACTION_SCOPE_CHANGED: '사용자·프로젝트·세션 또는 원천 권한이 변경됐습니다. 현재 기록에서 다시 준비하세요.',
  ACTION_SCOPE_UNVERIFIED: '현재 사용자와 조치 권한을 확인할 수 없습니다.',
  SUBJECT_SCOPE_UNVERIFIED: '현재 사용자·프로젝트·세션을 확인할 수 없습니다.',
  ACTION_SNAPSHOT_CHANGED: '사건 대상·근거·상태가 변경됐습니다. 현재 사건으로 다시 준비하세요.',
  ACTION_EVENT_UNAVAILABLE: '현재 본인 사건을 확인할 수 없습니다.',
  ACTION_TIMEOUT: '결과 불명(unknown): 이미 전달된 조치의 효과가 없다고 판단하지 마세요. 결과만 직접 재조회하세요.',
  ACTION_STORE_FAILED: '조치 기록 확인 불가. 자동 집행하지 말고 결과만 직접 조회하세요.',
  ACTION_RESULT_UNVERIFIED: '결과 확인 불가: 성공이나 효과 없음으로 판단하지 마세요.',
});
const actionUuid = v => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
function safeActionData(data,phase,intent) {
  const allowed=['requestId','receiptId','eventId','actionId','status','version','replayed','observation','superseded'];
  if(phase==='prepare')allowed.push('confirmationId','confirmationExpiresAt','target');
  if(!isRecord(data)||Object.keys(data).some(key=>!allowed.includes(key))||!actionUuid(data.requestId)
    ||!['prepared','pending','succeeded','denied','failed','unknown'].includes(data.status))return null;
  if(phase!=='prepare'&&data.requestId!==intent?.requestId)return null;
  const minimal=exactFields(data,['requestId','status'])&&data.status==='unknown';
  if(!minimal&&(!actionUuid(data.receiptId)||!safeAiId(data.eventId)||!safeAiId(data.actionId)||!Number.isSafeInteger(data.version)||data.version<=0||typeof data.replayed!=='boolean'))return null;
  if(!minimal&&(data.eventId!==intent?.eventId||data.actionId!==intent?.actionId||phase!=='prepare'&&data.receiptId!==intent?.receiptId))return null;
  if(phase==='prepare'&&(data.status!=='prepared'||data.replayed!==false||!/^ac-on-[A-Za-z0-9_-]{43}$/.test(data.confirmationId)
    ||!safeAiTime(data.confirmationExpiresAt)||Date.parse(data.confirmationExpiresAt)<=Date.now()||!exactFields(data.target,['id','generation'])
    ||typeof data.target.id!=='string'||aiSecret.test(data.target.id)||!/^(?:subject|device):[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(data.target.id)||!Number.isSafeInteger(data.target.generation)||data.target.generation<=0))return null;
  if(data.observation!==undefined&&(!exactFields(data.observation,['observedAt','effectApplied'])||!safeAiTime(data.observation.observedAt)||typeof data.observation.effectApplied!=='boolean'))return null;
  if(data.status==='succeeded'&&(data.observation?.effectApplied!==true||phase==='prepare'))return null;
  if(phase==='execute'&&data.status==='succeeded'&&data.replayed!==true)return null;
  if(data.superseded!==undefined&&(data.superseded!==true||data.status!=='unknown'||data.observation!==undefined))return null;
  const {confirmationId,...safe}=structuredClone(data);
  return {safe,confirmationId};
}
function clearAction({cancelled=false}={}) {
  ++actionGeneration;actionController?.abort();actionController=null;
  clearTimeout(actionExpiryTimer);actionExpiryTimer=null;actionTicket=null;actionIntent=null;
  actionState={status:'idle',event:null,actionId:null,target:null,receipt:null,observation:null,message:cancelled?'조치 화면을 취소했습니다. 이미 전달된 효과는 별도로 확인해야 합니다.':'조치 제안은 아직 실행되지 않았습니다.'};
  renderAction();
}
function renderAction() {
  const out=$('action-result');if(!out)return;
  out.dataset.state=actionState.status;
  const s=actionState,confirmed=s.status==='succeeded'&&s.observation?.effectApplied===true;
  const labels={loading:'원천에 확인하는 중 · 완료 아님',prepared:'준비됨 · 미실행',executing:'사람 확인 후 원천에 전달 중 · 완료 아님',pending:'처리 중(pending) · ACK는 완료가 아님',succeeded:'원천 효과 확인(succeeded)',denied:'원천 거절(denied)',failed:'원천 실패(failed)',unknown:'결과 불명(unknown) · 효과 없음으로 판단 금지',expired:'확인 기한 만료 · 이번 준비로는 집행할 수 없음',error:'요청이 처리되지 않았습니다 · 아래 원인을 확인하세요'};
  setChildren(out,el('p',{className:confirmed?'action-observed':'muted',text:labels[s.status]||s.message||'조치 상태 확인 불가'}),
    s.event?el('p',{text:`사건 ${s.event.id} · 조치 ${s.actionId}`}):null,
    s.target?el('p',{text:`실제 원천 대상 ${s.target.id} · 세대 ${s.target.generation}`}):null,
    s.receipt?el('p',{text:`요청 ${s.receipt.requestId} · 영수증 ${s.receipt.receiptId||'확인 불가'} · 버전 ${s.receipt.version||'확인 불가'}`}):null,
    s.confirmationExpiresAt?el('p',{text:`사람 확인 기한 ${s.confirmationExpiresAt}`}):null,
    s.observation?el('p',{text:`원천 관측 ${s.observation.observedAt} · 실제 효과 ${s.observation.effectApplied}`}):null,
    s.error?el('p',{className:'state state-error',text:`${s.error.code}: ${s.error.message}`}):null,
    s.receipt?.superseded?el('p',{text:'이전 조회는 최신 결과를 대신하지 않습니다(superseded).'}):null);
  $('action-confirm').disabled=s.status!=='prepared'||!actionTicket;
  $('action-result-load').disabled=!actionIntent||['loading','executing','prepared','expired'].includes(s.status);
  $('action-cancel').disabled=s.status==='idle';
  renderStudent('action');
}
function actionFailure(result,afterDispatch) {
  const raw=result?.error?.code;
  const code=Object.hasOwn(ACTION_MESSAGES,raw)?raw:'ACTION_RESULT_UNVERIFIED';
  const uncertain=afterDispatch&&['ACTION_TIMEOUT','ACTION_STORE_FAILED','ACTION_RESULT_UNVERIFIED'].includes(code);
  actionState={...actionState,status:uncertain?'unknown':code==='ACTION_CONFIRMATION_EXPIRED'?'expired':'error',observation:null,error:{code,message:ACTION_MESSAGES[code]}};
  actionTicket=null;
}
async function prepareAction(event,actionId) {
  const current=state.selectedExplanation;
  if(current.event?.id!==event.id||current.resource.status!=='ok'||!current.resource.data.proposals.some(p=>p.action===actionId)||!event.supportedActions.includes(actionId))return;
  clearAction();const gen=actionGeneration,refreshGen=generation,controller=new AbortController();actionController=controller;
  actionState={status:'loading',event:structuredClone(current.event),actionId,target:null,receipt:null,observation:null,message:'조치 준비 중 · 미실행'};renderAction();
  const result=await aiRequest('/api/actions/prepare',{body:{eventId:event.id,actionId},signal:controller.signal});
  if(gen!==actionGeneration||refreshGen!==generation||controller.signal.aborted)return;
  actionController=null;
  const value=result.ok?safeActionData(result.data,'prepare',{eventId:event.id,actionId}):null;
  if(!value){actionFailure(result,false);renderAction();return;}
  actionTicket=value.confirmationId;
  actionIntent=Object.freeze({requestId:value.safe.requestId,receiptId:value.safe.receiptId,eventId:event.id,actionId,target:Object.freeze({...value.safe.target})});
  actionState={...actionState,status:'prepared',target:structuredClone(value.safe.target),receipt:value.safe,confirmationExpiresAt:value.safe.confirmationExpiresAt};
  actionExpiryTimer=setTimeout(()=>{if(gen!==actionGeneration)return;actionTicket=null;actionState={...actionState,status:'expired',error:{code:'ACTION_CONFIRMATION_EXPIRED',message:ACTION_MESSAGES.ACTION_CONFIRMATION_EXPIRED}};renderAction();},Math.min(2147483647,Date.parse(value.safe.confirmationExpiresAt)-Date.now()));
  renderAction();
}
async function executeAction() {
  if(actionState.status!=='prepared'||!actionTicket||!actionIntent)return;
  if(Date.parse(actionState.confirmationExpiresAt)<=Date.now()){actionTicket=null;actionState={...actionState,status:'expired',error:{code:'ACTION_CONFIRMATION_EXPIRED',message:ACTION_MESSAGES.ACTION_CONFIRMATION_EXPIRED}};renderAction();return;}
  const input=Object.freeze({requestId:actionIntent.requestId,confirmationId:actionTicket});
  actionTicket=null;clearTimeout(actionExpiryTimer);actionExpiryTimer=null;
  await actionOperation('execute',input);
}
async function actionOperation(phase,input) {
  const gen=actionGeneration,refreshGen=generation,intent=actionIntent,controller=new AbortController();actionController=controller;
  actionState={...actionState,status:phase==='execute'?'executing':'loading',observation:null,error:null,message:phase==='execute'?'사람 확인 후 원천에 전달 중 · 완료 아님':'원천 결과 조회 중'};renderAction();
  const result=await aiRequest(`/api/actions/${phase}`,{body:input,signal:controller.signal});
  if(gen!==actionGeneration||refreshGen!==generation||controller.signal.aborted)return;
  actionController=null;const value=result.ok?safeActionData(result.data,phase,intent):null;
  if(!value)actionFailure(result,true);
  else actionState={...actionState,status:value.safe.status,receipt:value.safe,observation:value.safe.observation||null,message:''};
  renderAction();
}

// ---------- 학생 구현 연결 ----------

function snapshot(resource) {
  const base = { status: resource.status, mode: resource.meta ? resource.meta.mode : null };
  if (resource.status === 'ok') base.data = resource.data;
  if (resource.status === 'error') base.error = { code: resource.error.code, message: resource.error.message };
  try {
    return structuredClone(base);
  } catch {
    return { status: base.status, mode: base.mode };
  }
}

// identity의 세 자료는 같은 세대의 응답만 담긴다(다시 불러오기 시 셋 모두 loading으로 초기화).
function studentData(kind) {
  if(kind==='action')return structuredClone(actionState);
  if (kind === 'aiConnection') return { ...snapshot(state.aiConnection), checkedAt: state.aiConnection.meta?.checkedAt ?? null, explanationAccepted: false };
  if (kind === 'explanation') return structuredClone({ event: state.selectedExplanation.event, explanation: snapshot(state.selectedExplanation.resource), checkedAt: state.selectedExplanation.resource.meta?.checkedAt ?? null });
  if (kind === 'vulnerabilities') return snapshot(state.vulnerabilities);
  if (kind === 'identity') return { me: snapshot(state.me), devices: snapshot(state.devices), sessions: snapshot(state.sessions) };
  if (kind === 'decision') {
    const access = state.access;
    return { ...snapshot(access), appId: access.appId ?? null };
  }
  if (kind === 'status') {
    const notifications = [...state.errors].map(([resource, message]) => ({ resource, code: state[resource]?.error?.code || 'UNVERIFIED', message }));
    if (state.devices.status === 'ok') for (const device of state.devices.data) {
      if (device.status !== 'compliant') notifications.push({ resource: 'devices', code: device.status, message: `${device.label || device.id}: ${stateLabel('device', device.status)}` });
    }
    if (state.sessions.status === 'ok') for (const session of state.sessions.data) {
      if (session.status !== 'active') notifications.push({ resource: 'sessions', code: session.status, message: `${session.id}: ${stateLabel('session', session.status)}` });
    }
    if (state.events.status === 'ok') for (const event of state.events.data) {
      if (event.kind === 'xdr' || Object.values(event.state).includes('unknown')) notifications.push({ resource: 'events', code: event.kind, message: `${event.id}: ${event.summary}` });
    }
    return structuredClone({ devices: snapshot(state.devices), sessions: snapshot(state.sessions), notifications, diagnostics: snapshot(state.diagnostics), mode: currentMode() });
  }
  return snapshot(state.events);
}

const STUDENT_SLOTS = {
  identity: { slot: 'student-identity', fn: 'renderIdentity' },
  decision: { slot: 'student-decision', fn: 'renderDecision' },
  events: { slot: 'student-events', fn: 'renderEvents' },
  status: { slot: 'student-status', fn: 'renderStatus' },
  vulnerabilities: { slot: 'student-vulnerabilities', fn: 'renderVulnerabilities' },
  aiConnection: { slot: 'student-ai-connection', fn: 'renderAiConnection' },
  explanation: { slot: 'student-explanation', fn: 'renderExplanation' },
  action: { slot: 'student-action', fn: 'renderAction' },
};

function renderStudent(kind) {
  const { slot, fn } = STUDENT_SLOTS[kind];
  const target = $(slot);
  if (studentLoadFailed) {
    return setChildren(target, stateBox('empty', `${STUDENT_PENDING} (student/extension.mjs를 불러오지 못했습니다)`));
  }
  if (!studentView || typeof studentView[fn] !== 'function') return setChildren(target, stateBox('empty', STUDENT_PENDING));
  let output;
  try {
    output = studentView[fn](studentData(kind));
  } catch {
    return setChildren(target, stateBox('error', `학생 구현 ${fn} 실행 중 오류가 발생했습니다. 제공 UI는 계속 동작합니다.`));
  }
  // 학생 반환은 DOM 요소 또는 텍스트만 허용한다. 문자열은 HTML로 해석하지 않는다.
  if (output instanceof Element) return setChildren(target, output);
  if (typeof output === 'string') return setChildren(target, el('p', { className: 'student-text', text: output }));
  if (output == null) return setChildren(target, stateBox('empty', STUDENT_PENDING));
  setChildren(target, stateBox('error', `학생 구현 ${fn}의 반환 형식이 DOM 요소 또는 텍스트가 아닙니다.`));
}

function renderAllStudent() {
  for (const kind of Object.keys(STUDENT_SLOTS)) renderStudent(kind);
}

const studentApi = Object.freeze({
  get(path) {
    if (!STUDENT_GET_PATHS.includes(path)) {
      return Promise.resolve(localFailure('NOT_ALLOWED', '학생 구현에서 허용되지 않은 주소입니다.', UNKNOWN_META));
    }
    return request(path);
  },
});

async function loadStudentModule() {
  try {
    const mod = await import(STUDENT_MODULE);
    if (typeof mod.createStudentView !== 'function') throw new Error('missing export');
    studentView = mod.createStudentView({ api: studentApi, onChange: () => renderAllStudent() }) || null;
  } catch {
    studentView = null;
    studentLoadFailed = true;
  }
  renderAllStudent();
}

// ---------- 로드 ----------

const RENDERERS = {
  me: () => { renderIdentity(); renderStudent('identity'); },
  devices: () => { renderDevices(); renderStudent('identity'); },
  sessions: () => { renderSessions(); renderStudent('identity'); },
  apps: () => renderApps(),
  events: () => { renderEvents(); renderStudent('events'); },
};

const PATHS = { me: '/api/me', apps: '/api/apps', events: '/api/events', devices: '/api/devices', sessions: '/api/sessions' };

async function loadResource(key, gen, signal) {
  const requestedAt = Date.now();
  const result = await request(PATHS[key], { signal });
  if (gen !== generation) return;
  const coverageKind = Object.hasOwn(COVERAGE_RULES, key) ? key : undefined;
  state[key] = toResource(result, VALIDATORS[key], coverageKind, coverageKind ? { requestedAt, receivedAt: Date.now() } : undefined);
  if (key === 'me' && state[key].meta && state[key].meta.checkedAt) state.checkedAt = state[key].meta.checkedAt;
  if (key === 'me') noteIdentity(state[key]);
  trackError(key, state[key]);
  renderMode();
  RENDERERS[key]();
}

// 진행 중인 접속 판정과 AI 설명을 취소하고 판정 결과를 비운다.
function cancelInteractive() {
  if (accessController) accessController.abort();
  accessController = null;
  for (const controller of explainControllers.values()) controller.abort();
  explainControllers.clear();
  cancelAiCheck({ reset: true });
  cancelExplanation({ reset: true });
  state.access = { status: 'idle' };
  trackError('access', state.access);
  renderAccess();
  renderStudent('decision');
}

async function loadAll() {
  const gen = ++generation;
  if (refreshController) refreshController.abort();
  const controller = new AbortController();
  refreshController = controller;
  cancelInteractive();
  clearVulnerabilities();

  const refresh = $('refresh');
  refresh.disabled = true;
  refresh.textContent = '불러오는 중…';
  state.checkedAt = null;
  for (const key of Object.keys(PATHS)) {
    state[key] = { status: 'loading' };
    trackError(key, state[key]);
    RENDERERS[key]();
  }
  renderMode();

  try {
    await Promise.all(Object.keys(PATHS).map((key) => loadResource(key, gen, controller.signal)));
  } finally {
    if (gen === generation) {
      refreshController = null;
      refresh.disabled = false;
      refresh.textContent = '다시 불러오기';
    }
  }
}

function init() {
  setupNav();
  $('refresh').addEventListener('click', () => loadAll());
  $('diag-load').addEventListener('click', () => loadDiagnostics());
  $('diag-copy').addEventListener('click', () => copyDiagnostics());
  $('vulnerabilities-load').addEventListener('click', () => loadVulnerabilities());
  $('vulnerabilities-cancel').addEventListener('click', () => cancelVulnerabilities());
  $('ai-check').addEventListener('click', () => checkAiConnection());
  $('ai-check-cancel').addEventListener('click', () => cancelAiCheck());
  $('ai-explanation-cancel').addEventListener('click', () => cancelExplanation());
  $('action-confirm').addEventListener('click', () => executeAction());
  $('action-result-load').addEventListener('click', () => {if(actionIntent&&!$('action-result-load').disabled)actionOperation('result',{requestId:actionIntent.requestId});});
  $('action-cancel').addEventListener('click', () => clearAction({cancelled:true}));
  $('ai-connect-start').addEventListener('click', () => { appConnectInvalidated = false; if (aiConnect) aiConnect.start(); });
  $('ai-connect-finish').addEventListener('click', () => { if (aiConnect) aiConnect.finish(); });
  $('ai-connect-status').addEventListener('click', () => { if (aiConnect) aiConnect.refresh(); });
  $('ai-connect-cancel').addEventListener('click', () => { if (aiConnect) aiConnect.cancel(); });
  $('ai-connect-check').addEventListener('click', () => checkAiConnection());
  $('ai-connect-help').addEventListener('click', () => showConnectHelp());
  $('ai-connect-help-copy').addEventListener('click', () => copyConnectHelp());
  $('native-login-start').addEventListener('click', () => { if (nativeLogin) nativeLogin.start(); });
  $('native-login-redeem').addEventListener('click', () => { if (nativeLogin) nativeLogin.redeem(); });
  $('native-login-check').addEventListener('click', () => { if (nativeLogin) nativeLogin.check(); });
  $('native-login-cancel').addEventListener('click', () => { if (nativeLogin) nativeLogin.cancel(); });
  // 페이지를 떠날 때는 화면 진행과 이 화면의 요청만 끝낸다. 원격 취소를 보내거나 성공이라고 주장하지 않는다.
  window.addEventListener('pagehide', () => { if (nativeLogin) nativeLogin.reset(); });
  guardStaticArt();
  renderNativeLogin();
  renderAiConnect();
  loadConnectModule();
  renderAiConnection();
  renderVulnerabilities();
  renderAllStudent();
  loadStudentModule();
  loadAll();
}

init();
