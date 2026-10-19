// Alekov 학생 AI 연결 — 브라우저 모듈(제공 공통 UI).
// AI 앱 승인은 로컬 Alekov 서버의 POST /api/ai/connect/{start,finish,status,cancel} 네 경로만 쓴다.
// 계정 연결 확인(native 로그인)은 파일 아래쪽의 별도 transport·controller 가 POST /api/native-login/* 다섯 경로만 쓴다.
// 주소·열쇠를 입력받지 않고 token·verifier·credential 을 받지도 보관하지도 않는다.
// 늦게 도착한 응답은 세대(generation)로 버린다. 실패한 요청을 자동으로 다시 보내지 않는다.
// 확인 중(checking)일 때만 서버의 비공개 작업 상태를 짧은 간격으로 읽는다(새 요청 재발급이 아님).

export const CONNECT_PATHS = Object.freeze({
  start: '/api/ai/connect/start',
  finish: '/api/ai/connect/finish',
  status: '/api/ai/connect/status',
  cancel: '/api/ai/connect/cancel',
});
export const PORTAL_ORIGIN = 'https://aleph-omega.vercel.app';
const STATES = ['awaiting_approval', 'checking', 'connected', 'error', 'unknown', 'cancelled'];
const TERMINAL = new Set(['connected', 'error', 'unknown', 'cancelled']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CODE = /^[A-Z][A-Z0-9_]{2,63}$/;
const isRecord = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => isRecord(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
const iso = (v) => typeof v === 'string' && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;

// 학생에게 보이는 고정 안내. 서버가 보낸 임의 문장은 화면에 쓰지 않는다.
export const CONNECT_MESSAGES = Object.freeze({
  ALEKOV_CONNECT_NOT_MOUNTED: '이 앱 버전에는 아직 AI 연결 경로가 연결되지 않았습니다(미연결). 기존 설명·판정·기록은 그대로 쓸 수 있습니다.',
  ALEKOV_CONNECT_UNAVAILABLE: 'AI 연결 기능이 아직 준비되지 않았습니다(서버 미준비). 기존 설명·판정·기록은 그대로 쓸 수 있습니다.',
  ALEKOV_CONNECT_NETWORK: '이 PC의 앱 서버에 연결할 수 없습니다. 앱이 실행 중인지 확인한 뒤 다시 누르세요.',
  ALEKOV_CONNECT_CLIENT_TIMEOUT: '서버 응답이 늦습니다. 「상태 다시 확인」으로 현재 상태를 확인하세요.',
  ALEKOV_CONNECT_CONTEXT_UNVERIFIED: '현재 로그인·프로젝트를 확인할 수 없습니다. 다시 로그인한 뒤 연결을 새로 시작하세요.',
  ALEKOV_CONNECT_CONTEXT_CHANGED: '계정·프로젝트·세션이 바뀌어 이전 연결을 멈췄습니다. 현재 계정으로 연결을 새로 시작하세요.',
  ALEKOV_CONNECT_NOT_FOUND: '연결 요청을 찾을 수 없습니다. 연결을 새로 시작하세요.',
  ALEKOV_CONNECT_BUSY: '진행 중인 연결 요청이 많습니다. 기존 요청을 취소한 뒤 다시 시작하세요.',
  ALEKOV_CONNECT_EXPIRED: '승인 기한이 지났습니다. 연결을 새로 시작하세요.',
  ALEKOV_CONNECT_REJECTED: '연결 요청이 거절됐습니다. 승인한 계정이 현재 로그인과 같은지 확인한 뒤 새로 시작하세요.',
  ALEKOV_CONNECT_CANCELLED: '연결을 취소했습니다. 이미 승인했다면 결과가 남아 있을 수 있어 확인 불가로 표시합니다.',
  ALEKOV_CONNECT_TIMEOUT: '확인 시간이 지났습니다. 연결 결과를 확인할 수 없어 자동으로 다시 시도하지 않습니다.',
  ALEKOV_CONNECT_STORAGE_UNVERIFIED: '연결 정보 저장을 확인하지 못했습니다. 연결 완료로 보지 않습니다. 담당자에게 확인을 요청하세요.',
  ALEKOV_CONNECT_RESPONSE_INVALID: '서버 응답 형식을 확인할 수 없습니다(확인 불가). 연결 완료로 보지 않습니다.',
  ALEKOV_CONNECT_DEADLINE: '현재 로그인 확인이나 서버 처리가 늦어 요청을 멈췄습니다. 자동으로 다시 시도하지 않습니다. 잠시 뒤 직접 다시 누르세요.',
  ALEKOV_CONNECT_INPUT_INVALID: '요청 형식이 올바르지 않습니다. 화면을 다시 불러온 뒤 새로 시작하세요.',
  ALEKOV_CONNECT_OUTCOME_UNKNOWN: '연결 결과를 확인할 수 없습니다. 자동으로 다시 시도하지 않습니다. 담당자에게 확인을 요청하세요.',
});
const PHASE_MESSAGES = Object.freeze({
  idle: '아직 연결을 시작하지 않았습니다. 주소·열쇠를 직접 입력하지 않습니다.',
  starting: '연결 요청을 만드는 중…',
  awaiting_approval: '아래 확인 번호를 기억한 뒤 「승인 페이지 열기」를 눌러 Workbench 로그인 승인 화면에서 같은 번호를 확인하고 승인하세요(처음이면 이 PC 프로젝트 등록도 그 화면에서 함께 확인합니다). 승인한 뒤 「승인했으며 연결 확인」을 누르세요.',
  finishing: '연결 확인을 요청하는 중…',
  checking: '승인 결과와 연결 정보 저장을 확인하는 중입니다. 승인 화면에서 아직 승인하지 않았다면 지금 승인하세요.',
  cancelling: '연결을 취소하는 중…',
  connected: '연결이 완료됐습니다. 이제 「현재 API 연결 점검」으로 현재 로그인의 모델 응답을 확인하세요. 이 표시는 17단계 연결 절차이며 통과·점수 판정이 아닙니다.',
  error: '연결하지 못했습니다.',
  unknown: '연결 결과를 확인할 수 없습니다(확인 불가). 연결 완료로 보지 않습니다.',
  cancelled: '연결을 취소했습니다.',
});

// gateway·native 와 같은 프로젝트 논리 라벨 규칙(199자 ASCII, 경로·비밀 형태 거절).
const PROJECT_LABEL = (v) => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,198}$/.test(v) && !v.includes('..')
  && !/^(?:[a-z]:|file:|sk-|sb_secret_|eyJ|bearer(?:$|[._:@-])|token(?:$|[._:@-]))/i.test(v);

/**
 * 승인 URL 은 고정 ALEPH origin 의 /workbench.html 만 허용한다. query 는 기존 exact3
 * (appConnect, appDevice, appChallenge) 또는 프로젝트 등록 exact5(+ appRegistration=v1, appProject)
 * 둘 중 하나여야 한다. 모르는 등록 버전은 exact3 로 낮추지 않고 거절한다.
 */
export function validApprovalUrl(value, connectionId) {
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.href !== value || url.origin !== PORTAL_ORIGIN || url.pathname !== '/workbench.html' || url.hash || url.username || url.password) return false;
  const keys = [...url.searchParams.keys()].join(',');
  const base = url.searchParams.get('appConnect') === 'alekov' && url.searchParams.get('appDevice') === connectionId
    && /^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('appChallenge') ?? '');
  if (keys === 'appConnect,appDevice,appChallenge') return base;
  return keys === 'appConnect,appDevice,appChallenge,appRegistration,appProject' && base
    && url.searchParams.get('appRegistration') === 'v1' && PROJECT_LABEL(url.searchParams.get('appProject'));
}

const fail = (code) => ({ ok: false, error: { code } });

/** 기본 transport: 같은 origin POST JSON, 10초 제한. 응답은 {ok:true,data} 또는 고정 코드만 남긴다. */
export function createFetchTransport({ fetchImpl = (...args) => globalThis.fetch(...args), timeoutMs = 10000 } = {}) {
  return async function transport(kind, body, { signal } = {}) {
    if (!Object.hasOwn(CONNECT_PATHS, kind)) return fail('ALEKOV_CONNECT_INPUT_INVALID');
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    const onAbort = () => controller.abort();
    if (signal?.aborted) controller.abort(); else signal?.addEventListener('abort', onAbort, { once: true });
    try {
      let response;
      try {
        response = await fetchImpl(CONNECT_PATHS[kind], {
          method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
          headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(body),
        });
      } catch { return fail(timedOut ? 'ALEKOV_CONNECT_CLIENT_TIMEOUT' : signal?.aborted ? 'ALEKOV_CONNECT_CANCELLED' : 'ALEKOV_CONNECT_NETWORK'); }
      let value = null;
      try { if (/^application\/json/i.test(response.headers.get('content-type') ?? '')) value = await response.json(); } catch { value = null; }
      if (timedOut) return fail('ALEKOV_CONNECT_CLIENT_TIMEOUT');
      if (value?.ok === true && response.ok && isRecord(value.data)) return { ok: true, data: value.data };
      const code = value?.ok === false && typeof value.error?.code === 'string' && Object.hasOwn(CONNECT_MESSAGES, value.error.code) ? value.error.code : null;
      if (code) return fail(code);
      // 경로가 아직 root 에 연결되지 않은 서버(404/405 등 계약 밖 응답)는 미연결이다. 가짜 연결로 대체하지 않는다.
      if ([404, 405, 501].includes(response.status)) return fail('ALEKOV_CONNECT_NOT_MOUNTED');
      return fail('ALEKOV_CONNECT_RESPONSE_INVALID');
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  };
}

/**
 * 연결 진행 상태기. 화면은 onChange 로 받은 고정 상태만 그린다.
 * phase: idle|starting|awaiting_approval|finishing|checking|cancelling|connected|error|unknown|cancelled
 */
export function createAiConnectController({ transport = createFetchTransport(), onChange = () => {}, clock = () => Date.now(),
  pollMs = 2000, observeGraceMs = 60000, setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (t) => clearTimeout(t) } = {}) {
  let generation = 0, pollTimer = null, controller = null;
  let state = Object.freeze({ phase: 'idle', connectionId: null, approvalUrl: null, confirmation: null, expiresAt: null, reason: null, cancelUnconfirmed: false });
  // cancelUnconfirmed: 취소를 요청했지만 서버가 취소 결과를 확정하지 않은 상태. 실패한 조회·형식 오류·서버의 unknown 응답으로는
  // 지워지지 않는다. 검증된 확정 상태(cancelled·connected·error 등 unknown 이 아닌 서버 응답)나 새 흐름(start)·reset 에서만 지운다.
  const set = (next) => { state = Object.freeze({ ...state, ...next }); onChange(state); };
  const stopPoll = () => { if (pollTimer !== null) clearTimer(pollTimer); pollTimer = null; };
  const abortRequest = () => { controller?.abort(); controller = null; };
  async function call(kind, body) {
    abortRequest();
    const own = new AbortController();
    controller = own;
    try { return await transport(kind, body, { signal: own.signal }); }
    catch { return fail('ALEKOV_CONNECT_RESPONSE_INVALID'); }
    finally { if (controller === own) controller = null; }
  }
  function applyStatus(data, g, { fromCancel = false } = {}) {
    if (g !== generation) return;
    const pendingCancel = fromCancel || state.cancelUnconfirmed === true;
    if (!exact(data, ['connectionId', 'state', 'expiresAt', 'reason']) || data.connectionId !== state.connectionId || !STATES.includes(data.state)
      || (data.reason !== null && !(typeof data.reason === 'string' && CODE.test(data.reason))) || (data.expiresAt !== null && !iso(data.expiresAt))) {
      stopPoll();
      // ok:true 라도 형식이 틀린 응답은 취소 결과를 확인한 것이 아니다.
      return set({ phase: 'unknown', reason: 'ALEKOV_CONNECT_RESPONSE_INVALID', cancelUnconfirmed: pendingCancel });
    }
    // 서버가 unknown 으로 남긴 결과는 취소 완료 확인이 아니다. unknown 이 아닌 검증된 상태만 미확인 표식을 지운다.
    set({ phase: data.state, reason: data.reason, cancelUnconfirmed: data.state === 'unknown' ? pendingCancel : false });
    if (data.state === 'checking') schedulePoll(g); else stopPoll();
  }
  function schedulePoll(g) {
    stopPoll();
    const deadline = Date.parse(state.expiresAt ?? '') + observeGraceMs;
    if (!Number.isFinite(deadline) || clock() > deadline) return set({ phase: 'unknown', reason: 'ALEKOV_CONNECT_TIMEOUT' });
    pollTimer = setTimer(() => { pollTimer = null; void observe(g); }, pollMs);
  }
  async function observe(g) {
    if (g !== generation || state.phase !== 'checking') return;
    const result = await call('status', { connectionId: state.connectionId });
    if (g !== generation) return;
    if (!result.ok) { stopPoll(); return set({ phase: 'unknown', reason: result.error.code }); }
    applyStatus(result.data, g);
  }

  async function start() {
    if (['starting', 'awaiting_approval', 'finishing', 'checking', 'cancelling'].includes(state.phase)) return state;
    const g = ++generation;
    stopPoll();
    set({ phase: 'starting', connectionId: null, approvalUrl: null, confirmation: null, expiresAt: null, reason: null, cancelUnconfirmed: false });
    const result = await call('start', {});
    if (g !== generation) return state;
    if (!result.ok) { set({ phase: 'error', reason: result.error.code }); return state; }
    const d = result.data;
    if (!exact(d, ['connectionId', 'approvalUrl', 'confirmation', 'expiresAt', 'state']) || d.state !== 'awaiting_approval' || !UUID.test(d.connectionId ?? '')
      || !/^[0-9a-f]{4}-[0-9a-f]{4}$/.test(d.confirmation ?? '') || !iso(d.expiresAt) || !validApprovalUrl(d.approvalUrl, d.connectionId)) {
      set({ phase: 'error', reason: 'ALEKOV_CONNECT_RESPONSE_INVALID' });
      return state;
    }
    set({ phase: 'awaiting_approval', connectionId: d.connectionId, approvalUrl: d.approvalUrl, confirmation: d.confirmation, expiresAt: d.expiresAt, reason: null });
    return state;
  }

  async function finish() {
    if (state.phase !== 'awaiting_approval' || !state.connectionId) return state;
    const g = ++generation;
    set({ phase: 'finishing' });
    const result = await call('finish', { connectionId: state.connectionId });
    if (g !== generation) return state;
    if (!result.ok) {
      // 응답을 잃었을 수 있으므로 확인 불가. 자동으로 finish 를 다시 보내지 않는다.
      set({ phase: 'unknown', reason: result.error.code });
      return state;
    }
    applyStatus(result.data, g);
    return state;
  }

  // 학생이 누를 때만 한 번 읽는다. unknown 이후에도 서버의 실제 상태를 읽을 수 있다(재발급 아님).
  async function refresh() {
    if (!state.connectionId || ['starting', 'finishing', 'cancelling'].includes(state.phase)) return state;
    const g = ++generation;
    stopPoll();
    const result = await call('status', { connectionId: state.connectionId });
    if (g !== generation) return state;
    if (!result.ok) { set({ phase: 'unknown', reason: result.error.code }); return state; }
    applyStatus(result.data, g);
    return state;
  }

  async function cancel() {
    const before = state.phase;
    const g = ++generation;
    stopPoll();
    abortRequest();
    if (!state.connectionId || TERMINAL.has(before)) {
      // 시작 응답 전 취소: 늦게 도착한 시작 결과를 버린다.
      if (!TERMINAL.has(before)) set({ phase: 'cancelled', reason: 'ALEKOV_CONNECT_CANCELLED', approvalUrl: null, confirmation: null, cancelUnconfirmed: false });
      return state;
    }
    set({ phase: 'cancelling' });
    const result = await call('cancel', { connectionId: state.connectionId });
    if (g !== generation) return state;
    // 서버가 ok:true 로 돌려준 상태만 취소 결과의 근거다. 실패(응답 유실·시간 초과·확인 불가·거절 등)는
    // 이전 단계가 승인 대기였어도 취소 완료로 추정하지 않는다. 이미 승인됐을 수 있으므로 확인 불가로 둔다.
    if (!result.ok) { set({ phase: 'unknown', reason: result.error.code, cancelUnconfirmed: true }); return state; }
    applyStatus(result.data, g, { fromCancel: true });
    return state;
  }

  /** 계정·세션 전환 등으로 화면의 진행을 버린다. 서버는 다음 호출에서 scope 전환을 직접 막는다. */
  function reset() {
    ++generation;
    stopPoll();
    abortRequest();
    set({ phase: 'idle', connectionId: null, approvalUrl: null, confirmation: null, expiresAt: null, reason: null, cancelUnconfirmed: false });
  }

  /** 비밀 없는 연결 도움정보. 연결 ID·승인 주소·학생 ID·로컬 경로·서버 원문은 넣지 않는다. */
  function helpInfo() {
    return {
      component: 'alekov-ai-connect',
      phase: state.phase,
      reason: state.reason,
      cancelUnconfirmed: state.cancelUnconfirmed,
      approvalExpiresAt: state.expiresAt,
      observedAt: new Date(clock()).toISOString(),
      automaticRetries: 0,
      manualSecretInputs: 0,
      routes: Object.values(CONNECT_PATHS),
    };
  }

  return Object.freeze({ get state() { return state; }, start, finish, refresh, cancel, reset, helpInfo });
}

// 취소 결과를 확인하지 못했을 때의 고정 안내. 취소·회수됐다고 말하지 않고, 먼저 현재 상태를 직접 확인하게 한다.
export const CANCEL_UNCONFIRMED_MESSAGE = '취소 요청의 결과를 확인하지 못했습니다(확인 불가). 취소된 것으로 보지 않습니다. 이미 승인했다면 연결이 남아 있을 수 있습니다. 먼저 「상태 다시 확인」으로 서버의 현재 상태를 직접 확인하세요.';

export function connectMessage(state) {
  const cancelUnconfirmed = state.phase === 'unknown' && state.cancelUnconfirmed === true;
  const base = cancelUnconfirmed ? CANCEL_UNCONFIRMED_MESSAGE : PHASE_MESSAGES[state.phase] ?? PHASE_MESSAGES.unknown;
  // 확인 불가(unknown) 상태에는 이유가 CANCELLED 여도 「연결을 취소했습니다」를 덧붙이지 않는다.
  // 서버가 unknown 으로 남긴 취소는 취소 완료 확인이 아니며, 발급된 권한을 회수했다는 뜻도 아니다.
  const detail = state.phase === 'unknown' && state.reason === 'ALEKOV_CONNECT_CANCELLED'
    ? (cancelUnconfirmed ? '' : '취소 요청은 받았지만 서버가 결과를 확정하지 않았습니다. 이미 승인했다면 연결이 남아 있을 수 있으니 「상태 다시 확인」으로 확인하세요.')
    : state.reason && Object.hasOwn(CONNECT_MESSAGES, state.reason) ? CONNECT_MESSAGES[state.reason]
    : state.reason ? CONNECT_MESSAGES.ALEKOV_CONNECT_OUTCOME_UNKNOWN : '';
  return state.phase === 'connected' ? base : [base, detail].filter(Boolean).join(' ');
}

// ---------- 계정 연결 확인(native 로그인) ----------
// AI 앱 승인과 별개다. 계정 연결이 확인돼도 AI 이용 권한·프로젝트 등록·실제 엔진·단계 성취로 보지 않는다.
// 요청 본문은 언제나 빈 객체 {} 이다. 신원·token·verifier·handle·사용자 입력·경로를 보내지 않는다.
// 화면을 열 때는 서버에 묻지 않는다. 자동 재시도·자동 발급·자동 redeem·자동 current·자동 polling 은 없다.
// 한 사용자 동작은 fetch 와 본문 읽기까지 합쳐 10초 안에 끝나야 하며, 기한은 비동기·동기 지연 뒤마다 다시 본다.

export const NATIVE_LOGIN_PATHS = Object.freeze({
  start: '/api/native-login/start',
  status: '/api/native-login/status',
  redeem: '/api/native-login/redeem',
  current: '/api/native-login/current',
  cancel: '/api/native-login/cancel',
});
export const NATIVE_ACTION_MS = 10000;
export const NATIVE_RESPONSE_MAX_BYTES = 8192;
const NATIVE_SERVER_STATES = ['disconnected', 'starting', 'awaiting_approval', 'connected', 'cancelled', 'unknown'];
// 서버 nativePublicError 의 공개 코드와 비활성 경로(NATIVE_HOST_DISABLED)만 이유로 받아들인다.
export const NATIVE_PUBLIC_CODES = Object.freeze(['INPUT_INVALID', 'DISABLED', 'CANCELLED', 'EXPIRED', 'TIMEOUT', 'RESPONSE_INVALID',
  'CONTEXT_CHANGED', 'UNVERIFIED', 'OUTCOME_UNKNOWN', 'BUSY'].map((code) => `NATIVE_HOST_${code}`));
// 32바이트 base64url 의 정규형: 43자이고 마지막 글자의 하위 2비트가 0 이다.
const NATIVE_APPROVAL = /^https:\/\/aleph-omega\.vercel\.app\/workbench\.html\?nativeLogin=alekov&device=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}&challenge=[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const NATIVE_META_KEYS = ['mode', 'checkedAt', 'starterVersion'];
const NATIVE_BUSY = ['starting', 'redeeming', 'checking', 'cancelling'];
// 원격 ticket 이 생기기 전에 멈춘 실패만 '시작 못 함'(error)이다. 나머지는 확인 불가(unknown)로 두고 취소를 요구한다.
const NATIVE_NO_REMOTE = new Set(['NATIVE_HOST_DISABLED', 'NATIVE_HOST_INPUT_INVALID', 'NATIVE_LOGIN_NOT_MOUNTED', 'NATIVE_LOGIN_INPUT_INVALID']);

export const NATIVE_MESSAGES = Object.freeze({
  NATIVE_HOST_INPUT_INVALID: '요청 형식이 올바르지 않습니다. 화면을 다시 불러온 뒤 직접 다시 누르세요.',
  NATIVE_HOST_DISABLED: '이 PC의 앱 서버에서 계정 연결 기능이 준비되지 않았습니다. 기존 설명·판정·기록은 그대로 쓸 수 있습니다.',
  NATIVE_HOST_CANCELLED: '요청이 중간에 멈췄습니다. 결과를 확인할 수 없어 연결로 보지 않습니다.',
  NATIVE_HOST_EXPIRED: '확인 기한이 지났습니다. 「계정 연결 취소」를 누른 뒤 새로 시작하세요.',
  NATIVE_HOST_TIMEOUT: '포털 응답이 늦어 요청을 멈췄습니다. 자동으로 다시 시도하지 않습니다.',
  NATIVE_HOST_RESPONSE_INVALID: '포털 응답 형식을 확인할 수 없습니다. 연결로 보지 않습니다.',
  NATIVE_HOST_CONTEXT_CHANGED: '계정이나 로그인 상태가 바뀌었습니다. 「계정 연결 취소」를 누른 뒤 새로 시작하세요.',
  NATIVE_HOST_UNVERIFIED: '로그인 연결을 확인할 수 없습니다. 연결로 보지 않습니다.',
  NATIVE_HOST_OUTCOME_UNKNOWN: '결과를 확인할 수 없습니다. 자동으로 다시 시도하지 않습니다.',
  NATIVE_HOST_BUSY: '이전 계정 연결 요청이 남아 있습니다. 「계정 연결 취소」를 누른 뒤 새로 시작하세요.',
  NATIVE_LOGIN_NOT_MOUNTED: '이 앱 버전에는 계정 연결 경로가 없습니다(미연결). 기존 설명·판정·기록은 그대로 쓸 수 있습니다.',
  NATIVE_LOGIN_NETWORK: '이 PC의 앱 서버에 연결할 수 없습니다. 앱이 실행 중인지 확인하세요. 요청이 서버에 닿았을 수 있어 연결로 보지 않습니다.',
  NATIVE_LOGIN_CLIENT_TIMEOUT: '10초 안에 응답을 받지 못해 멈췄습니다. 결과를 확인할 수 없어 연결로 보지 않습니다. 자동으로 다시 시도하지 않습니다.',
  NATIVE_LOGIN_CANCELLED: '이 화면에서 요청을 멈췄습니다.',
  NATIVE_LOGIN_RESPONSE_INVALID: '서버 응답 형식을 확인할 수 없습니다(확인 불가). 연결로 보지 않습니다.',
  NATIVE_LOGIN_UNVERIFIED: '서버 결과를 확인할 수 없습니다(확인 불가). 연결로 보지 않습니다.',
  NATIVE_LOGIN_INPUT_INVALID: '요청 형식이 올바르지 않습니다. 화면을 다시 불러온 뒤 직접 다시 누르세요.',
  NATIVE_LOGIN_PENDING: '포털에서 번호 확인이 아직 끝나지 않았습니다. 포털에서 같은 번호를 확인한 뒤 「로그인 확인 완료」를 다시 누르세요.',
  NATIVE_LOGIN_STATUS_ONLY: '저장된 공개 상태만 읽었습니다. 포털에서 번호를 확인한 뒤 「로그인 확인 완료」를 눌러야 연결됩니다.',
  NATIVE_LOGIN_SERVER_UNKNOWN: '서버가 결과를 확인하지 못했습니다. 「현재 로그인 확인」이나 「계정 연결 취소」를 직접 누르세요.',
  NATIVE_LOGIN_SERVER_STARTING: '다른 연결 시작이 진행 중으로 보입니다. 잠시 뒤 「현재 로그인 확인」을 누르거나 「계정 연결 취소」를 누르세요.',
  NATIVE_LOGIN_EXPIRED_LOCAL: '표시된 기한이 지나 화면의 연결·확인 번호 표시를 지웠습니다. 서버에 다시 묻지 않았습니다.',
  NATIVE_LOGIN_LOCAL_RESET: '이 화면의 진행과 요청만 멈췄습니다. 서버의 계정 연결이 취소됐다고 보지 않습니다. 「현재 로그인 확인」이나 「계정 연결 취소」로 확인하세요.',
});
const NATIVE_PHASE_MESSAGES = Object.freeze({
  idle: '아직 계정 연결을 확인하지 않았습니다. 이 화면을 열어도 서버에 자동으로 묻지 않습니다.',
  starting: '계정 연결 요청을 만드는 중…',
  awaiting_approval: '「계정 확인 페이지 열기」로 포털을 열고, 아래 6자리 확인 번호를 포털에 입력해 확인하세요. 포털에서 확인한 뒤 이 화면에서 「로그인 확인 완료」를 누르세요.',
  redeeming: '로그인 확인 결과를 받는 중…',
  checking: '현재 로그인을 확인하는 중…',
  cancelling: '계정 연결 취소를 요청하는 중…',
  connected: '계정 연결 확인 완료, AI 앱 승인은 별도입니다. 이 표시는 AI 이용 권한·프로젝트 등록·실제 엔진·단계 성취를 뜻하지 않습니다. AI 앱 승인은 「AI 연결 시작」을 따로 눌러 진행하세요.',
  disconnected: '서버에 확인된 계정 연결이 없습니다.',
  cancelled: '서버가 계정 연결 취소를 확인했습니다.',
  expired: '표시 기한이 지났습니다. 「현재 로그인 확인」으로 다시 확인하거나 「계정 연결 취소」 뒤 새로 시작하세요.',
  unknown: '계정 연결 결과를 확인할 수 없습니다(확인 불가). 연결로 보지 않습니다. 「현재 로그인 확인」이나 「계정 연결 취소」를 직접 누르세요.',
  error: '계정 연결을 시작하지 못했습니다.',
});
export const NATIVE_CANCEL_UNCONFIRMED_MESSAGE = '취소 요청의 결과를 확인하지 못했습니다(확인 불가). 취소된 것으로 보지 않습니다. 「현재 로그인 확인」으로 서버 상태를 확인하거나 「계정 연결 취소」를 다시 누르세요.';

const nfail = (code) => Object.freeze({ ok: false, error: Object.freeze({ code }) });
const nativeReason = (code) => (typeof code === 'string' && Object.hasOwn(NATIVE_MESSAGES, code) ? code : 'NATIVE_LOGIN_UNVERIFIED');
const sixDigits = (v) => typeof v === 'string' && /^\d{6}$/.test(v);
const validNativeMeta = (m) => exact(m, NATIVE_META_KEYS) && NATIVE_META_KEYS.every((k) => typeof m[k] === 'string' && m[k].length <= 64);
const nativeCanStart = (phase, expiredFrom) => ['idle', 'disconnected', 'cancelled', 'error', 'connected'].includes(phase)
  || (phase === 'expired' && expiredFrom === 'connected');
const nativeCanCancel = (phase) => !['idle', 'cancelling', 'cancelled', 'disconnected', 'error'].includes(phase);

/** 승인 URL 은 고정 포털의 /workbench.html, query 는 nativeLogin·device·challenge 순서의 정확한 세 개만 허용한다. */
export function validNativeApprovalUrl(value) {
  if (typeof value !== 'string' || value.length > 256 || !NATIVE_APPROVAL.test(value)) return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  return url.href === value && url.origin === PORTAL_ORIGIN && url.pathname === '/workbench.html' && !url.hash && !url.username && !url.password
    && [...url.searchParams.keys()].join(',') === 'nativeLogin,device,challenge';
}

/**
 * 공개 자료 exact4 {state,expiresAtMs,approvalUrl,confirmation} 를 검사한다. 틀리면 null.
 * unknown 은 형식만 확인하고 기한·링크·번호를 버린다(연결 성공이 아니다).
 */
export function validNativeData(data, now) {
  if (!Number.isSafeInteger(now) || !exact(data, ['state', 'expiresAtMs', 'approvalUrl', 'confirmation']) || !NATIVE_SERVER_STATES.includes(data.state)) return null;
  const { state, expiresAtMs, approvalUrl, confirmation } = data;
  const future = Number.isSafeInteger(expiresAtMs) && expiresAtMs > now;
  const empty = Object.freeze({ state, expiresAtMs: null, approvalUrl: null, confirmation: null });
  if (state === 'awaiting_approval') return future && sixDigits(confirmation) && validNativeApprovalUrl(approvalUrl) ? Object.freeze({ state, expiresAtMs, approvalUrl, confirmation }) : null;
  if (state === 'connected') return future && approvalUrl === null && confirmation === null ? Object.freeze({ state, expiresAtMs, approvalUrl: null, confirmation: null }) : null;
  if (state === 'unknown') {
    const shaped = (expiresAtMs === null || (Number.isSafeInteger(expiresAtMs) && expiresAtMs > 0))
      && (approvalUrl === null || validNativeApprovalUrl(approvalUrl)) && (confirmation === null || sixDigits(confirmation));
    return shaped ? empty : null;
  }
  // disconnected·starting·cancelled 는 공개 자료가 모두 null 이어야 한다.
  return expiresAtMs === null && approvalUrl === null && confirmation === null ? empty : null;
}

/** 벽시계와 단조 시계 중 먼저 끝나는 쪽을 따르는 한 사용자 동작의 기한. */
export function createNativeDeadline(totalMs = NATIVE_ACTION_MS, { clock = () => Date.now(), monotonic = () => performance.now() } = {}) {
  const wall = clock() + totalMs, mono = monotonic() + totalMs;
  return Object.freeze({
    left() {
      const a = wall - clock(), b = mono - monotonic();
      return Number.isFinite(a) && Number.isFinite(b) ? Math.min(a, b) : 0;
    },
  });
}

function classifyNative(status, value) {
  const envelope = (keys) => exact(value, keys) || (exact(value, [...keys, 'meta']) && validNativeMeta(value.meta));
  if (value?.ok === true && envelope(['ok', 'data'])) return status === 200 ? Object.freeze({ ok: true, data: value.data }) : nfail('NATIVE_LOGIN_RESPONSE_INVALID');
  if (value?.ok === false && envelope(['ok', 'error']) && exact(value.error, ['code', 'message', 'retryable']) && typeof value.error.code === 'string') {
    // 서버 문장(message)과 추가 필드는 쓰지 않는다. 허용된 공개 코드만 남긴다.
    if (NATIVE_PUBLIC_CODES.includes(value.error.code)) return nfail(value.error.code);
    if (status === 404 && value.error.code === 'NOT_FOUND') return nfail('NATIVE_LOGIN_NOT_MOUNTED');
    return nfail('NATIVE_LOGIN_UNVERIFIED');
  }
  return nfail('NATIVE_LOGIN_RESPONSE_INVALID');
}

/**
 * native 전용 transport. 같은 origin POST, 본문 {} 고정, credentials same-origin, cache no-store, redirect error.
 * fetch 와 본문 읽기 모두 실제로 중단하며, 응답은 {ok:true,data} 또는 고정 코드만 남긴다.
 */
export function createNativeFetchTransport({ fetchImpl = (...args) => globalThis.fetch(...args), maxBytes = NATIVE_RESPONSE_MAX_BYTES } = {}) {
  return async function nativeTransport(kind, { signal, deadline } = {}) {
    if (!Object.hasOwn(NATIVE_LOGIN_PATHS, kind) || typeof deadline?.left !== 'function') return nfail('NATIVE_LOGIN_INPUT_INVALID');
    const first = deadline.left();
    if (!(first > 0)) return nfail('NATIVE_LOGIN_CLIENT_TIMEOUT');
    if (signal?.aborted) return nfail('NATIVE_LOGIN_CANCELLED');
    const controller = new AbortController();
    let timedOut = false, reader = null, stop = null;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, Math.min(first, NATIVE_ACTION_MS));
    const onAbort = () => controller.abort();
    signal?.addEventListener('abort', onAbort, { once: true });
    const outcome = () => nfail(timedOut || !(deadline.left() > 0) ? 'NATIVE_LOGIN_CLIENT_TIMEOUT' : 'NATIVE_LOGIN_CANCELLED');
    // 타이머가 늦게 돌 수 있으므로 매 지연 뒤 기한을 직접 다시 본다.
    const alive = () => {
      if (!(deadline.left() > 0)) { timedOut = true; controller.abort(); }
      return !controller.signal.aborted;
    };
    const stopped = new Promise((resolve) => { stop = () => resolve(outcome()); controller.signal.addEventListener('abort', stop, { once: true }); });
    const work = (async () => {
      let response;
      try {
        response = await fetchImpl(NATIVE_LOGIN_PATHS[kind], {
          method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
          headers: { 'content-type': 'application/json', accept: 'application/json' }, body: '{}',
        });
      } catch { return alive() ? nfail('NATIVE_LOGIN_NETWORK') : outcome(); }
      if (!alive()) return outcome();
      if (!response || response.redirected || response.type === 'opaqueredirect') return nfail('NATIVE_LOGIN_RESPONSE_INVALID');
      const status = response.status;
      if (!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') ?? '')) {
        return [404, 405, 501].includes(status) ? nfail('NATIVE_LOGIN_NOT_MOUNTED') : nfail('NATIVE_LOGIN_RESPONSE_INVALID');
      }
      if (typeof response.body?.getReader !== 'function') return nfail('NATIVE_LOGIN_RESPONSE_INVALID');
      reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      for (;;) {
        let part;
        try { part = await reader.read(); } catch { return alive() ? nfail('NATIVE_LOGIN_RESPONSE_INVALID') : outcome(); }
        if (!alive()) return outcome();
        if (part.done) break;
        if (!(part.value instanceof Uint8Array)) return nfail('NATIVE_LOGIN_RESPONSE_INVALID');
        size += part.value.byteLength;
        if (size > maxBytes) return nfail('NATIVE_LOGIN_RESPONSE_INVALID');
        chunks.push(part.value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      let value;
      try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return nfail('NATIVE_LOGIN_RESPONSE_INVALID'); }
      if (!alive()) return outcome();
      return classifyNative(status, value);
    })().catch(() => nfail('NATIVE_LOGIN_RESPONSE_INVALID'));
    try {
      const result = await Promise.race([work, stopped]);
      if (result.ok && !alive()) return outcome();
      return result;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      controller.signal.removeEventListener('abort', stop);
      controller.abort();
      if (reader) reader.cancel().catch(() => {});
    }
  };
}

/**
 * 계정 연결 확인 상태기. 모든 요청은 사용자 동작에서만 시작한다.
 * phase: idle|starting|awaiting_approval|redeeming|checking|cancelling|connected|disconnected|cancelled|expired|unknown|error
 * onInvalidate(reason): 사용자가 새 로그인·취소를 시작했거나 확인 결과 기존 연결이 사라졌을 때 부른다.
 * 화면은 이것으로 기존 AI 앱 승인 표시와 AI 점검의 낡은 성공만 지운다(실제 권한 취소가 아니다).
 */
export function createNativeLoginController({ transport = createNativeFetchTransport(), onChange = () => {}, onInvalidate = () => {},
  clock = () => Date.now(), monotonic = () => performance.now(), actionMs = NATIVE_ACTION_MS,
  setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (t) => clearTimeout(t) } = {}) {
  let generation = 0, controller = null, expiryTimer = null, monoExpiry = null;
  let state = Object.freeze({ phase: 'idle', expiresAtMs: null, approvalUrl: null, confirmation: null, reason: null, cancelUnconfirmed: false, expiredFrom: null });
  const set = (next) => { state = Object.freeze({ ...state, ...next }); onChange(state); };
  const now = () => { const t = clock(); return Number.isSafeInteger(t) ? t : NaN; };
  const notify = (reason) => { try { onInvalidate(reason); } catch { /* 화면 쪽 실패가 상태기를 멈추지 않게 한다 */ } };
  const stopExpiry = () => { if (expiryTimer !== null) clearTimer(expiryTimer); expiryTimer = null; };
  const abortRequest = () => { controller?.abort(); controller = null; };
  const live = (ctx) => ctx.g === generation;
  const expired = () => state.expiresAtMs !== null && (!(now() < state.expiresAtMs) || (monoExpiry !== null && monotonic() >= monoExpiry));

  // 기한이 지나면 화면 표시만 지운다. 네트워크는 부르지 않는다. 타이머가 일찍 돌면 남은 시간만큼 다시 건다.
  function markExpired(g) {
    if (g !== generation) return;
    const lostConnection = state.phase === 'connected';
    stopExpiry();
    monoExpiry = null;
    set({ phase: 'expired', expiredFrom: state.phase, expiresAtMs: null, approvalUrl: null, confirmation: null, reason: 'NATIVE_LOGIN_EXPIRED_LOCAL' });
    if (lostConnection) notify('lost');
  }
  function scheduleExpiry(g) {
    stopExpiry();
    if (state.expiresAtMs === null) return;
    const wait = Math.min(state.expiresAtMs - now(), monoExpiry - monotonic());
    if (!(wait > 0)) { markExpired(g); return; }
    expiryTimer = setTimer(() => {
      expiryTimer = null;
      if (g !== generation) return;
      if (expired()) markExpired(g); else scheduleExpiry(g);
    }, Math.min(Math.ceil(wait) + 20, 2147483647));
  }
  function accept(data, g, extra = {}) {
    monoExpiry = data.expiresAtMs === null ? null : monotonic() + (data.expiresAtMs - now());
    const phase = data.state === 'unknown' || data.state === 'starting' ? 'unknown' : data.state;
    const reason = data.state === 'unknown' ? 'NATIVE_LOGIN_SERVER_UNKNOWN' : data.state === 'starting' ? 'NATIVE_LOGIN_SERVER_STARTING' : null;
    set({ phase, expiresAtMs: data.expiresAtMs, approvalUrl: data.approvalUrl, confirmation: data.confirmation, reason, cancelUnconfirmed: false, expiredFrom: null, ...extra });
    scheduleExpiry(g);
  }
  function failTo(ctx, code, phase, extra = {}) {
    if (!live(ctx)) return;
    stopExpiry();
    monoExpiry = null;
    set({ phase, expiresAtMs: null, approvalUrl: null, confirmation: null, reason: nativeReason(code), expiredFrom: null, ...extra });
  }
  // 새 세대를 열고 이전 요청을 끊는다. 늦게 온 이전 응답은 세대가 달라 버려진다.
  function begin(phase, extra = {}) {
    const g = ++generation;
    abortRequest();
    stopExpiry();
    const own = new AbortController();
    controller = own;
    const deadline = createNativeDeadline(actionMs, { clock, monotonic });
    set({ phase, reason: null, ...extra });
    return { g, own, deadline };
  }
  function end(ctx) { if (controller === ctx.own) controller = null; ctx.own.abort(); }
  async function call(ctx, kind) {
    if (!live(ctx)) return nfail('NATIVE_LOGIN_CANCELLED');
    if (!(ctx.deadline.left() > 0)) return nfail('NATIVE_LOGIN_CLIENT_TIMEOUT');
    let result;
    try { result = await transport(kind, { signal: ctx.own.signal, deadline: ctx.deadline }); } catch { result = null; }
    if (!isRecord(result) || !(result.ok === true || (result.ok === false && isRecord(result.error)))) return nfail('NATIVE_LOGIN_RESPONSE_INVALID');
    if (result.ok === false) return nfail(nativeReason(result.error.code));
    if (!(ctx.deadline.left() > 0)) return nfail('NATIVE_LOGIN_CLIENT_TIMEOUT');
    return result;
  }
  const timely = (ctx) => ctx.deadline.left() > 0;

  async function start() {
    if (!nativeCanStart(state.phase, state.expiredFrom)) return state;
    notify('start');
    const ctx = begin('starting', { expiresAtMs: null, approvalUrl: null, confirmation: null, cancelUnconfirmed: false, expiredFrom: null });
    monoExpiry = null;
    try {
      const result = await call(ctx, 'start');
      if (!live(ctx)) return state;
      if (!result.ok) { failTo(ctx, result.error.code, NATIVE_NO_REMOTE.has(result.error.code) ? 'error' : 'unknown'); return state; }
      const data = validNativeData(result.data, now());
      if (data?.state !== 'awaiting_approval') { failTo(ctx, 'NATIVE_LOGIN_RESPONSE_INVALID', 'unknown'); return state; }
      if (!timely(ctx)) { failTo(ctx, 'NATIVE_LOGIN_CLIENT_TIMEOUT', 'unknown'); return state; }
      accept(data, ctx.g);
      return state;
    } finally { end(ctx); }
  }

  async function redeem() {
    if (state.phase !== 'awaiting_approval' || expired()) return state;
    const shown = { approvalUrl: state.approvalUrl, confirmation: state.confirmation };
    const ctx = begin('redeeming');
    try {
      const result = await call(ctx, 'redeem');
      if (!live(ctx)) return state;
      // 응답을 잃었을 수 있으므로 확인 불가. redeem 을 자동으로 다시 보내지 않는다.
      if (!result.ok) { failTo(ctx, result.error.code, 'unknown'); return state; }
      const data = validNativeData(result.data, now());
      if (!timely(ctx)) { failTo(ctx, 'NATIVE_LOGIN_CLIENT_TIMEOUT', 'unknown'); return state; }
      if (data?.state === 'connected') { accept(data, ctx.g); return state; }
      if (data?.state === 'awaiting_approval' && data.approvalUrl === shown.approvalUrl && data.confirmation === shown.confirmation) {
        accept(data, ctx.g, { reason: 'NATIVE_LOGIN_PENDING' });
        return state;
      }
      failTo(ctx, 'NATIVE_LOGIN_RESPONSE_INVALID', 'unknown');
      return state;
    } finally { end(ctx); }
  }

  // 「현재 로그인 확인」: 이미 connected 면 current, 아니면 status 를 한 번 읽는다.
  // status 는 저장된 공개 상태일 뿐이다. connected 로 보이면 같은 기한 안에서 current 로 다시 확인한다.
  async function check() {
    if (NATIVE_BUSY.includes(state.phase)) return state;
    const wasConnected = state.phase === 'connected';
    const ctx = begin('checking');
    try {
      let kind = wasConnected ? 'current' : 'status';
      let result = await call(ctx, kind);
      if (!live(ctx)) return state;
      let data = result.ok ? validNativeData(result.data, now()) : null;
      if (result.ok && kind === 'status' && data?.state === 'connected') {
        kind = 'current';
        result = await call(ctx, 'current');
        if (!live(ctx)) return state;
        data = result.ok ? validNativeData(result.data, now()) : null;
      }
      if (!result.ok) failTo(ctx, result.error.code, 'unknown');
      else if (!data || (kind === 'current' && data.state !== 'connected')) failTo(ctx, 'NATIVE_LOGIN_RESPONSE_INVALID', 'unknown');
      else if (!timely(ctx)) failTo(ctx, 'NATIVE_LOGIN_CLIENT_TIMEOUT', 'unknown');
      else accept(data, ctx.g, kind === 'status' && data.state === 'awaiting_approval' ? { reason: 'NATIVE_LOGIN_STATUS_ONLY' } : {});
      if (wasConnected && state.phase !== 'connected') notify('lost');
      return state;
    } finally { end(ctx); }
  }

  // 사용자 취소: 새 세대로 진행 중 요청과 늦은 응답을 버리고 서버에 실제 cancel {} 를 보낸다.
  // starting 중에도 보낸다(서버가 ticket·verifier 를 보관한다). 응답 유실·시간 초과는 취소 성공이 아니다.
  async function cancel() {
    if (!nativeCanCancel(state.phase)) return state;
    notify('cancel');
    const ctx = begin('cancelling', { expiresAtMs: null, approvalUrl: null, confirmation: null, expiredFrom: null });
    monoExpiry = null;
    try {
      const result = await call(ctx, 'cancel');
      if (!live(ctx)) return state;
      if (!result.ok) { failTo(ctx, result.error.code, 'unknown', { cancelUnconfirmed: true }); return state; }
      const data = validNativeData(result.data, now());
      if (data?.state === 'cancelled' && timely(ctx)) { accept(data, ctx.g); return state; }
      failTo(ctx, data?.state === 'cancelled' ? 'NATIVE_LOGIN_CLIENT_TIMEOUT' : 'NATIVE_LOGIN_RESPONSE_INVALID', 'unknown', { cancelUnconfirmed: true });
      return state;
    } finally { end(ctx); }
  }

  /** 계정 전환·pagehide: 화면 진행과 이 화면의 요청만 끝낸다. 서버 취소를 보내거나 주장하지 않는다. */
  function reset() {
    const quiet = ['idle', 'disconnected', 'cancelled', 'error'].includes(state.phase);
    ++generation;
    abortRequest();
    stopExpiry();
    monoExpiry = null;
    set({ phase: quiet ? 'idle' : 'unknown', expiresAtMs: null, approvalUrl: null, confirmation: null,
      reason: quiet ? null : 'NATIVE_LOGIN_LOCAL_RESET', cancelUnconfirmed: false, expiredFrom: null });
  }

  /** 비밀 없는 도움정보. 확인 번호·승인 링크·기한·학생 ID 는 넣지 않는다. */
  function helpInfo() {
    return {
      component: 'alekov-native-login',
      phase: state.phase,
      reason: state.reason,
      cancelUnconfirmed: state.cancelUnconfirmed,
      observedAt: new Date(clock()).toISOString(),
      automaticRetries: 0,
      automaticPolling: 0,
      manualSecretInputs: 0,
      routes: Object.values(NATIVE_LOGIN_PATHS),
    };
  }

  return Object.freeze({ get state() { return state; }, start, redeem, check, cancel, reset, helpInfo });
}

/**
 * 표시용 투영. 화면은 이 값만 그린다. 기한이 지난 connected·승인 링크는 타이머보다 먼저라도 보이지 않는다.
 * message 는 고정 문장만 쓰고, 서버 원문이나 모르는 코드는 확인 불가 코드로 바꾼다.
 */
export function nativeLoginView(state, now = Date.now()) {
  const s = isRecord(state) ? state : {};
  let phase = Object.hasOwn(NATIVE_PHASE_MESSAGES, s.phase) ? s.phase : 'unknown';
  let reason = s.reason == null ? null : nativeReason(s.reason);
  const from = s.phase === 'expired' ? s.expiredFrom : s.phase;
  if ((phase === 'connected' || phase === 'awaiting_approval') && !(Number.isSafeInteger(s.expiresAtMs) && s.expiresAtMs > now)) {
    phase = 'expired';
    reason = 'NATIVE_LOGIN_EXPIRED_LOCAL';
  }
  const awaiting = phase === 'awaiting_approval' && sixDigits(s.confirmation) && validNativeApprovalUrl(s.approvalUrl);
  if (phase === 'awaiting_approval' && !awaiting) { phase = 'unknown'; reason = 'NATIVE_LOGIN_RESPONSE_INVALID'; }
  const busy = NATIVE_BUSY.includes(phase);
  const cancelUnconfirmed = phase === 'unknown' && s.cancelUnconfirmed === true;
  const base = cancelUnconfirmed ? NATIVE_CANCEL_UNCONFIRMED_MESSAGE : NATIVE_PHASE_MESSAGES[phase];
  const detail = reason && !(cancelUnconfirmed && reason === 'NATIVE_LOGIN_CANCELLED') ? NATIVE_MESSAGES[reason] : '';
  return Object.freeze({
    phase,
    reason,
    busy,
    kind: phase === 'connected' ? 'ok' : ['unknown', 'error'].includes(phase) ? 'error' : ['idle', 'disconnected', 'cancelled', 'expired'].includes(phase) ? 'empty' : 'loading',
    message: phase === 'connected' ? base : [base, detail].filter(Boolean).join(' '),
    approvalUrl: awaiting ? s.approvalUrl : null,
    confirmation: awaiting ? s.confirmation : null,
    expiresAtMs: awaiting || phase === 'connected' ? s.expiresAtMs : null,
    canStart: nativeCanStart(phase, from),
    canRedeem: awaiting,
    canCheck: !busy,
    canCancel: nativeCanCancel(phase),
  });
}
