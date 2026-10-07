// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
import { randomUUID } from 'node:crypto';

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (config.step === 1 && (typeof config.sampleMarker !== 'string' || !config.sampleMarker)) {
    throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  }
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  let empty = false;
  let staticText = '';
  if (response.ok) {
    try {
      staticText = await response.text();
      const data = JSON.parse(staticText);
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
      empty = Array.isArray(data?.notes) && data.notes.length === 0
        && Object.keys(data).join(',') === 'notes';
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  if ([3, 4, 5].includes(config.step)) {
    const results = [{ attackId: 'anonymous_static_note_read',
      expected: '정적 JSON은 HTTP 200의 빈 메모 목록',
      observed: response.status === 200 && empty ? 'HTTP 200: 정적 메모 0건'
        : `정적 목록 점검 실패 (HTTP ${response.status})` }];
    // No credentials or note payloads. A random missing ID avoids touching saved notes.
    const id = randomUUID();
    const routes = [['GET', '/api/notes', 'list'], ['POST', '/api/notes', 'create'],
      ['GET', `/api/notes/${id}`, 'item'], ['PUT', `/api/notes/${id}`, 'update'],
      ['DELETE', `/api/notes/${id}`, 'delete']];
    for (const invalid of [false, true]) {
      for (const [method, path, name] of routes) {
        const checked = await fetch(new URL(path, app), { method, redirect: 'error',
          signal: AbortSignal.timeout(10000), cache: 'no-store',
          ...(invalid ? { headers: { Authorization: 'Bearer invalid' } } : {}) });
        let denied = false;
        try {
          const data = await checked.json();
          denied = checked.status === 401 && data?.error === 'LOGIN_REQUIRED'
            && Object.keys(data).join(',') === 'error';
        } catch { /* Never include raw response data. */ }
        results.push({ attackId: `${invalid ? 'invalid_login' : 'anonymous'}_${name}_denied`,
          expected: `${invalid ? '잘못된 인증' : '무로그인'} ${method} 요청은 자료 없이 HTTP 401 거부`,
          observed: denied ? 'HTTP 401: LOGIN_REQUIRED만 반환, 자료 없음'
            : `HTTP ${checked.status}: 인증 거부 점검 실패` });
      }
    }
    const failures = [];
    if (response.status !== 200 || staticText.includes('SAMPLE_NOTE_1')) failures.push('/data.json');
    for (const path of ['/', '/index.html', '/aleph.json']) {
      const checked = await fetch(new URL(path, app), { redirect: 'error',
        signal: AbortSignal.timeout(10000), headers: { 'Cache-Control': 'no-cache' } });
      const text = await checked.text();
      if (checked.status !== 200 || text.includes('SAMPLE_NOTE_1')) failures.push(path);
      if (path === '/aleph.json') {
        let current = false;
        try {
          const identity = JSON.parse(text);
          current = identity.step === config.step && (config.step < 5
            || identity.originalApiUrl === config.originalApiUrl);
        } catch { /* Missing identity fails. */ }
        results.push({ attackId: `deployment_stage${config.step}_identity`,
          expected: `운영 배포 식별 파일에 step ${config.step} 기록${config.step >= 5 ? ' 및 원본 HTTPS 주소 일치' : ''}`,
          observed: checked.status === 200 && current ? `HTTP 200: step ${config.step} 확인`
            : `HTTP ${checked.status}: ${config.step}단계 배포 식별 미확인` });
      }
    }
    results.push({ attackId: 'static_stage1_marker_absent',
      expected: '정적 응답 네 경로에 1단계 확인 표시가 없음',
      observed: failures.length ? `정적 표시 점검 실패: ${failures.join(', ')}`
        : '정적 응답 네 경로 HTTP 200; 1단계 확인 표시 없음' });
    results.push({ attackId: 'authenticated_a_crud',
      expected: '운영 A 로그인으로 추가·조회·수정·삭제 후 GET 404',
      observed: '미실행: 자동 점검은 로그인 비밀값을 사용하지 않음; 운영 A 화면에서 별도 확인 필요' });
    if (config.step >= 4) {
      // Local reports belong in README, not in this deployment request run.
      for (const [attackId, expected] of [
        ['authenticated_b_crud', '운영 B 로그인으로 추가·조회·수정·삭제 후 GET 404'],
        ['foreign_note_access_denied', '운영 A/B의 상대 메모 GET·PUT·DELETE는 HTTP 404로 거부'],
        ['owner_change_denied', '운영 A/B의 owner_id 변경 PUT은 HTTP 400으로 거부'],
        ['owner_notes_preserved', '운영 상대 접근 검사 뒤 A/B 메모의 내용과 소유자 보존'],
      ]) {
        results.push({ attackId, expected,
          observed: '미실행: 운영 A/B 인증 요청을 보내지 않음; 로컬 검사 결과와 별도 확인 필요' });
      }
    }
    if (config.step === 5) {
      results.push({ attackId: 'original_api_anon_denied',
        expected: '원본 자료 API의 anon 키 직접 요청은 메모 자료 없이 거부',
        observed: '미실행: 원본 API에 anon 키 요청을 보내지 않음; 심판 확인 항목' });
      results.push({ attackId: 'notes_direct_privileges_revoked',
        expected: 'public.notes의 PUBLIC·anon·authenticated 권한 없음; 서버 CRUD 유지',
        observed: '미실행: 학습 DB SQL 적용·전후 권한과 적용 후 A 화면 결과 미확인' });
    }
    return results;
  }
  if (config.step === 2) {
    const results = [{ attackId: 'anonymous_static_note_read', expected: '비로그인 공개 JSON에 메모 본문이 없음',
      observed: empty ? '비로그인 공개 JSON은 빈 메모 목록 (Supabase 권한 검사는 별도 필요)'
        : `공개 JSON 점검 실패 (HTTP ${response.status})` }];
    const readResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let count = null;
    if (readResponse.ok) {
      try {
        const data = await readResponse.json();
        if (Array.isArray(data?.notes) && data.notes.every(note => note
            && typeof note.title === 'string' && typeof note.content === 'string')) {
          count = data.notes.length;
        }
      } catch {
        // Record only the count and status, never raw responses or note bodies.
      }
    }
    results.push({ attackId: 'public_api_note_read',
      expected: '설정 후 공개 API에서 가상 메모 네 건 조회; 로그인·소유자 검사는 아직 없음',
      observed: readResponse.status === 503
        ? 'HTTP 503: 서버 설정 미완료; 네 건 조회 미확인이며 인증 거부가 아님'
        : count === 4 ? 'HTTP 200: 비로그인 공개 API에서 네 건 조회; 공개 주소의 약점이 남음'
          : `HTTP ${readResponse.status}: 네 건 조회 미확인 (유효 메모 수 ${count ?? '미확인'})` });
    const writeResponse = await fetch(new URL('/api/notes', app), {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    results.push({ attackId: 'public_api_write_rejected', expected: 'POST 요청을 HTTP 405로 거부',
      observed: writeResponse.status === 405 ? 'HTTP 405: 쓰기 요청 거부; 인증 검사가 아닌 메서드 제한'
        : `HTTP ${writeResponse.status}: 쓰기 요청 거부 점검 실패` });
    const marker = 'SAMPLE_NOTE_1';
    const failures = [];
    if (response.status !== 200 || staticText.includes(marker)) failures.push('/data.json');
    for (const path of ['/', '/index.html', '/aleph.json']) {
      const staticResponse = await fetch(new URL(path, app), {
        redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { 'Cache-Control': 'no-cache' },
      });
      if (staticResponse.status !== 200 || (await staticResponse.text()).includes(marker)) failures.push(path);
    }
    results.push({ attackId: 'static_stage1_marker_absent',
      expected: '정적 응답 네 경로에 1단계 확인 표시가 없음',
      observed: failures.length ? `정적 표시 점검 실패: ${failures.join(', ')}`
        : '정적 응답 네 경로 HTTP 200; 1단계 확인 표시 없음' });
    return results;
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
