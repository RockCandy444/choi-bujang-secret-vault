import { randomUUID } from 'node:crypto';
import { RULE_IDS } from './decider.mjs';

// These are regression procedures, not the unavailable official 41-case catalog.
const procedures = [
  [1, '정상', '현재 공개 정적 목록 조회', 'HTTP 200 · 메모 0건', 'GET', '/data.json', 'empty'],
  [1, '금지', '정적 파일의 메모 본문 노출', '본문·옛 표시 없음'],
  [2, '정상', '빈 정적 목록 조회', 'HTTP 200 · 메모 0건', 'GET', '/data.json', 'empty'],
  [2, '금지', '원본 API의 공개 역할 직접 조회', '자료 없이 거부'],
  [3, '정상', '등록 기기 A 로그인 후 자기 CRUD', '자기 자료만 허용'],
  [3, '금지', '무로그인 목록 조회', 'HTTP 401 · 자료 없음', 'GET', '/api/my/notes', 'login'],
  [4, '정상', '등록 기기 B의 자기 메모 CRUD', '자기 자료만 허용'],
  [4, '금지', 'A의 B 메모 GET·PUT·DELETE', 'HTTP 404 · B 자료 보존'],
  [5, '정상', '허용 경로를 통한 자기 메모 조회', '서버 경유 허용'],
  [5, '금지', '브라우저 키로 원본 API 우회', '자료 없이 거부'],
  [6, '정상', '등록 기기의 허용된 한 건 요청', '엔진 확인 뒤 allow'],
  [6, '금지', '미등록 기기의 같은 요청', '자료 없이 거부'],
  [7, '정상', '엔진이 확인한 최근 추가 인증', '새 요청 재판정 뒤 허용'],
  [7, '금지', '복합 이상 사건·추가 인증 없음', 'step_up · 자료 차단'],
  [8, '정상', '자기 메모 경로 GET·PUT', '소유자 확인 뒤 허용'],
  [8, '금지', '일반 학생의 공지 수정', 'HTTP 403 · 공지 보존'],
  [9, '정상', '정상 빈도의 운영 조회', '관찰 · 회수 없음'],
  [9, '금지', '운영 이상 조회 뒤 재접속', '탐지·해당 접속 회수 확인'],
  [10, '정상', '검증된 시험 B 한 건 복구', 'ID·소유자·해시 일치'],
  [10, '금지', '무로그인 복구 요청', 'HTTP 401 · 자료 없음', 'POST', '/api/restore', 'login'],
  [11, '정상', '승인된 기기의 접속 앱 CRUD', '서버 등록·서명 확인 뒤 허용'],
  [11, '금지', '승인 연결 없는 기기 상태 조회', 'HTTP 503 · 승인 안 됨', 'GET', '/api/device/status', 'device'],
];

async function measure(procedure, base, fetchImpl) {
  const [step, kind, name, expected, method, path, shape] = procedure;
  const row = { step, kind, name, expected, state: 'unrun', observed: '미실행',
    requestId: null, checkedAt: null, httpStatus: null };
  if (!method) return row;
  row.requestId = randomUUID();
  row.checkedAt = new Date().toISOString();
  try {
    const response = await fetchImpl(new URL(path, base), { method, cache: 'no-store',
      redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'X-Aleph-Check-Id': row.requestId } });
    row.httpStatus = response.status;
    const body = await response.json();
    const keys = body && !Array.isArray(body) ? Object.keys(body).sort().join(',') : '';
    const matches = shape === 'empty'
      ? response.status === 200 && keys === 'notes' && Array.isArray(body.notes) && body.notes.length === 0
      : shape === 'login' ? response.status === 401 && keys === 'error' && body.error === 'LOGIN_REQUIRED'
        : response.status === 503 && keys === 'approved,error' && body.approved === false
          && body.error === 'DEVICE_APPROVAL_NOT_CONFIGURED';
    row.state = matches ? 'matched' : 'mismatch';
    row.observed = matches ? expected : `HTTP ${response.status} · 기대 응답 형식 불일치`;
  } catch {
    row.state = 'error';
    row.observed = '확인 실패 · 통신 또는 JSON 응답 오류';
  }
  // The log and the public receipt contain the SAME allowlisted metadata only.
  // Never log upstream response bodies, credentials, user/device IDs or headers.
  console.info(JSON.stringify({ source: 'student_operations_check', ...row }));
  return row;
}

export async function operationsSummary({ config, commit, fetchImpl = fetch }) {
  const base = new URL(config.publicAppUrl);
  if (base.protocol !== 'https:' || base.username || base.password || base.search
      || base.hash || base.pathname !== '/' || !base.hostname.endsWith('.vercel.app')) {
    throw new Error('invalid_operations_target');
  }
  const checks = await Promise.all(procedures.map(row => measure(row, base, fetchImpl)));
  return {
    schema: 'aleph.operations.v1', requestId: randomUUID(), checkedAt: new Date().toISOString(),
    step: config.step, commit: /^[a-f0-9]{40}$/u.test(commit ?? '') ? commit : null,
    source: { engine: 'ALEPH SDP 엔진 사용', student: '판정기·탐지 규칙·접속 앱·자료실·자기 점검 화면' },
    policy: { ruleIds: [...RULE_IDS], ruleCount: RULE_IDS.length },
    detection: { state: 'unrun', eventCount: null, reason: '운영 사건 전달 미연결 · 가상 연습은 별도' },
    revocation: { state: 'unrun', revokedCount: null, reason: '운영 회수 결과 API 미연결' },
    recovery: { state: 'unrun', restoredVersion: null, reason: '실제 복구 미실행 · 배포 커밋은 복구 버전이 아님' },
    officialAttacks: { total: 41, state: 'unrun', passed: null, reason: '공식 41종 결과 미수신 · 아래 표는 학생 자기 점검' },
    counts: { executed: checks.filter(row => row.state !== 'unrun').length,
      matched: checks.filter(row => row.state === 'matched').length,
      failed: checks.filter(row => ['mismatch', 'error'].includes(row.state)).length,
      unrun: checks.filter(row => row.state === 'unrun').length },
    checks,
  };
}
