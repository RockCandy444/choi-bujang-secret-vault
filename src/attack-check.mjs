// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
import { randomUUID } from 'node:crypto';

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  // The stage 12 judge runs the bundle in a GET/HEAD-only sandbox.
  // Keep previous-stage exercises intact; never substitute GET for a write.
  const readOnlyBundle = config.step === 12;
  // Official sample's runner metadata. Fetch ignores it on a normal server;
  // the judge records it locally. Do not transmit it as a header or query.
  const evidence = (caseId, requestKey) => readOnlyBundle
    ? { alephEvidence: { caseId, requestKey } } : {};
  const observedRequests = new Map();
  const probe = async (input, options) => {
    const response = await globalThis.fetch(input, options);
    if (readOnlyBundle) {
      const { caseId, requestKey } = options.alephEvidence;
      const records = observedRequests.get(caseId) ?? [];
      records.push({ requestKey, ordinal: records.filter(row => row.requestKey === requestKey).length + 1,
        status: response.status });
      observedRequests.set(caseId, records);
    }
    return response;
  };
  const response = await probe(new URL('/data.json', app), {
    ...evidence('anonymous_static_note_read', 'data'),
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
  if ([3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) {
    const results = [{ attackId: 'anonymous_static_note_read',
      expected: '정적 JSON은 HTTP 200의 빈 메모 목록',
      observed: response.status === 200 && empty ? 'HTTP 200: 정적 메모 0건'
        : `정적 목록 점검 실패 (HTTP ${response.status})` }];
    // No credentials or note payloads. A random missing ID avoids touching saved notes.
    const id = randomUUID();
    const routes = [['GET', config.step >= 8 ? '/api/my/notes' : '/api/notes', 'list'], ['POST', '/api/notes', 'create'],
      ['GET', `/api/notes/${id}`, 'item'], ['PUT', `/api/notes/${id}`, 'update'],
      ['DELETE', `/api/notes/${id}`, 'delete']];
    for (const invalid of [false, true]) {
      const noteDenials = [];
      for (const [method, path, name] of routes) {
        if (readOnlyBundle && !['GET', 'HEAD'].includes(method)) continue;
        const checked = await probe(new URL(path, app), { method, redirect: 'error',
          ...evidence(`${invalid ? 'invalid_login' : 'anonymous'}_notes_denied`, name),
          signal: AbortSignal.timeout(10000), cache: 'no-store',
          ...(invalid ? { headers: { Authorization: 'Bearer invalid' } } : {}) });
        let denied = false;
        try {
          const data = await checked.json();
          denied = checked.status === 401 && data?.error === 'LOGIN_REQUIRED'
            && Object.keys(data).join(',') === 'error';
        } catch { /* Never include raw response data. */ }
        if (config.step >= 11) noteDenials.push(`${name} ${checked.status}: ${denied ? '자료 없음' : '점검 실패'}`);
        else results.push({ attackId: `${invalid ? 'invalid_login' : 'anonymous'}_${name}_denied`,
          expected: `${invalid ? '잘못된 인증' : '무로그인'} ${method} 요청은 자료 없이 HTTP 401 거부`,
          observed: denied ? 'HTTP 401: LOGIN_REQUIRED만 반환, 자료 없음'
            : `HTTP ${checked.status}: 인증 거부 점검 실패` });
      }
      if (config.step >= 11) results.push({ attackId: `${invalid ? 'invalid_login' : 'anonymous'}_notes_denied`,
        expected: readOnlyBundle
          ? `${invalid ? '잘못된 인증' : '무로그인'} 메모 목록·한 건 GET 두 요청은 자료 없이 401`
          : `${invalid ? '잘못된 인증' : '무로그인'} 메모 목록·추가·한 건 GET·PUT·DELETE 다섯 요청은 자료 없이 401`,
        observed: noteDenials.join('; ') });
    }
    if (readOnlyBundle) results.push({ attackId: 'notes_write_requests',
      expected: '무로그인·잘못된 인증의 메모 POST·PUT·DELETE는 자료 없이 401',
      observed: 'not_run' });
    const failures = [];
    if (response.status !== 200 || staticText.includes('SAMPLE_NOTE_1')) failures.push('/data.json');
    if (readOnlyBundle) {
      const markerData = await probe(new URL('/data.json', app), {
        ...evidence('static_stage1_marker_absent', 'data'), redirect: 'error',
        signal: AbortSignal.timeout(10000), headers: { 'Cache-Control': 'no-cache' } });
      if (markerData.status !== 200 || (await markerData.text()).includes('SAMPLE_NOTE_1')) failures.push('/data.json');
    }
    let homeText = '';
    for (const path of ['/', '/index.html', '/aleph.json']) {
      const checked = await probe(new URL(path, app), { redirect: 'error',
        ...evidence(path === '/aleph.json' ? `deployment_stage${config.step}_identity`
          : 'static_stage1_marker_absent', path === '/' ? 'home' : 'index'),
        signal: AbortSignal.timeout(10000), headers: { 'Cache-Control': 'no-cache' } });
      const text = await checked.text();
      if (path === '/' && checked.status === 200) homeText = text;
      if (checked.status !== 200 || text.includes('SAMPLE_NOTE_1')) failures.push(path);
      if (config.step >= 5 && ['/', '/index.html'].includes(path)
          && /\bsb_publishable_[A-Za-z0-9_-]+|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/u.test(text)) {
        failures.push(`${path}: 화면 공개 키`);
      }
      if (config.step >= 5 && path === '/'
          && checked.headers.get('x-content-type-options') !== 'nosniff'
          && !checked.headers.get('content-security-policy')) failures.push('/: 보안 헤더');
      if (path === '/aleph.json') {
        if (readOnlyBundle) {
          const markerIdentity = await probe(new URL(path, app), {
            ...evidence('static_stage1_marker_absent', 'identity'), redirect: 'error',
            signal: AbortSignal.timeout(10000), headers: { 'Cache-Control': 'no-cache' } });
          if (markerIdentity.status !== 200 || (await markerIdentity.text()).includes('SAMPLE_NOTE_1')) failures.push(path);
        }
        let current = false;
        try {
          const identity = JSON.parse(text);
          current = identity.step === config.step && (config.step < 5
            || (identity.originalApiUrl === config.originalApiUrl
              && Array.isArray(identity.allowedRoutes) && identity.allowedRoutes.length > 0
              && JSON.stringify(identity.allowedRoutes) === JSON.stringify(config.allowedRoutes)))
            && (config.step < 10 || (typeof identity.repoUrl === 'string'
              && identity.repoUrl.toLowerCase() === config.repoUrl.toLowerCase()
              && identity.judgeIssuer === config.judgeIssuer
              && JSON.stringify(identity.restoreRoute) === JSON.stringify(config.restoreRoute)
              && /^[a-f0-9]{40}$/u.test(identity.commit ?? '')
              && (!config.expectedCommit || identity.commit === config.expectedCommit)));
        } catch { /* Missing identity fails. */ }
        results.push({ attackId: `deployment_stage${config.step}_identity`,
          expected: `운영 배포 식별 파일에 step ${config.step} 기록${config.step >= 5 ? ' 및 원본 HTTPS 주소·허용 경로 일치' : ''}${config.step >= 10 ? '; 복구 경로·저장소·발급자·현재 커밋 대조' : ''}`,
          observed: checked.status === 200 && current ? `HTTP 200: step ${config.step} 확인`
            : `HTTP ${checked.status}: ${config.step}단계 배포 식별 미확인` });
      }
    }
    results.push({ attackId: 'static_stage1_marker_absent',
      expected: `정적 응답 네 경로에 1단계 확인 표시가 없음${config.step >= 5 ? '; 첫 화면 보안 헤더 및 화면 공개 키 없음' : ''}`,
      observed: failures.length ? `정적 표시 점검 실패: ${failures.join(', ')}`
        : `정적 응답 네 경로 HTTP 200; 1단계 확인 표시 없음${config.step >= 5 ? '; 보안 헤더 확인; 화면 공개 키 없음' : ''}` });
    results.push({ attackId: config.step >= 8 ? 'authenticated_a_b_crud' : 'authenticated_a_crud',
      expected: config.step === 7
        ? '운영 A 정상 CRUD; 복합 사건의 같은 주체 새 로그인 전 자료 차단·새 요청 재판정 허용'
          : config.step >= 10 ? '운영 A/B 자기 CRUD 유지; 상대 접근 404·소유자 변경 400·다른 메모 보존'
            : config.step >= 8 ? '운영 A/B 자기 메모 CRUD 허용 및 API의 상대 메모 거부'
          : '운영 A 로그인으로 추가·조회·수정·삭제 후 GET 404',
      observed: config.step === 7
        ? '미실행: 운영 A 인증 요청 없음; 같은 주체의 새 로그인 시각 검증 계약·자료 차단 연결 미확인'
        : config.step >= 8 ? '미실행: 운영 A/B 인증 요청 없음; API의 자기 요청 유지·상대 접근 거부는 별도 확인 필요'
          : '미실행: 자동 점검은 로그인 비밀값을 사용하지 않음; 운영 A 화면에서 별도 확인 필요' });
    if (config.step >= 4) {
      // Local reports belong in README, not in this deployment request run.
      for (const [attackId, expected] of [
        ['authenticated_b_crud', '운영 B 로그인으로 추가·조회·수정·삭제 후 GET 404'],
        ['foreign_note_access_denied', '운영 A/B의 상대 메모 GET·PUT·DELETE는 HTTP 404로 거부'],
        ['owner_change_denied', '운영 A/B의 owner_id 변경 PUT은 HTTP 400으로 거부'],
        ['owner_notes_preserved', '운영 상대 접근 검사 뒤 A/B 메모의 내용과 소유자 보존'],
      ].filter(([attackId]) => config.step < 10 && (config.step < 8 || attackId !== 'authenticated_b_crud'))) {
        results.push({ attackId, expected,
          observed: '미실행: 운영 A/B 인증 요청을 보내지 않음; 로컬 검사 결과와 별도 확인 필요' });
      }
    }
    if (config.step >= 5 && config.step < 8) {
      results.push({ attackId: 'original_api_anon_denied',
        expected: '원본 자료 API의 anon 키 직접 요청은 메모 자료 없이 거부',
        observed: '미실행: 원본 API에 anon 키 요청을 보내지 않음; 심판 확인 항목' });
      results.push({ attackId: 'notes_direct_privileges_revoked',
        expected: 'public.notes의 PUBLIC·anon·authenticated 권한 없음; 서버 CRUD 유지',
        observed: '미실행: 학습 DB SQL 적용·전후 권한과 적용 후 A 화면 결과 미확인' });
    }
    if (config.step >= 8) {
      results.push({ attackId: 'original_api_and_privileges_unrun',
        expected: '원본 anon 키 접근 거부와 학습 DB 권한 회수 확인',
        observed: '미실행: 원본 anon 키 요청·학습 DB 권한 검사를 실행하지 않음' });
      const observations = [];
      for (const invalid of [false, true]) {
        for (const method of (readOnlyBundle ? ['GET'] : ['GET', 'PUT'])) {
          const checked = await probe(new URL('/api/notices', app), { method,
            ...evidence('notice_anonymous_invalid_denied', invalid ? 'invalid' : 'anonymous'),
            redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
            ...(invalid ? { headers: { Authorization: 'Bearer invalid' } } : {}) });
          let denied = false;
          try {
            const body = await checked.json();
            denied = checked.status === 401 && body?.error === 'LOGIN_REQUIRED'
              && Object.keys(body).join(',') === 'error'
              && checked.headers.get('x-aleph-resource-id') === 'instructor_notices';
          } catch { /* Never record response bodies or identities. */ }
          observations.push(`${invalid ? '잘못된 인증' : '무로그인'} ${method} ${checked.status}: ${denied ? '자료 없음·공지 ID 확인' : '점검 실패'}`);
        }
      }
      results.push({ attackId: 'notice_anonymous_invalid_denied',
        expected: readOnlyBundle ? '무로그인·잘못된 인증의 공지 GET은 401, 자료 없음·공지 자원 ID 표시'
          : '무로그인·잘못된 인증의 공지 GET·PUT은 401, 자료 없음·공지 자원 ID 표시',
        observed: observations.join('; ') });
      if (readOnlyBundle) results.push({ attackId: 'notice_write_requests',
        expected: '무로그인·잘못된 인증의 공지 PUT은 401, 자료 없음', observed: 'not_run' });
      results.push({ attackId: 'student_notice_write_denied',
        expected: '인증된 일반 학생의 직접 공지 수정은 403, 자료 없음',
        observed: '미실행: 학생 인증 요청·운영 저장 권한 조회를 실행하지 않음' });
    }
    if (config.step >= 10) {
      const observations = [];
      for (const invalid of (readOnlyBundle ? [] : [false, true])) {
        const checked = await probe(new URL('/api/restore', app), { method: 'POST',
          redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
          ...(invalid ? { headers: { Authorization: 'Bearer invalid' } } : {}) });
        let denied = false;
        try {
          const body = await checked.json();
          denied = checked.status === 401 && body?.error === 'LOGIN_REQUIRED'
            && Object.keys(body).join(',') === 'error'
            && checked.headers.get('x-aleph-resource-id') === 'notes';
        } catch { /* Never copy response source or restore metadata. */ }
        observations.push(`${invalid ? '잘못된 인증' : '무로그인'} POST ${checked.status}: ${denied ? '자료 없음·메모 ID 확인' : '점검 실패'}`);
      }
      results.push({ attackId: 'restore_anonymous_invalid_denied',
        expected: '무로그인·잘못된 인증의 복구 POST는 자료 없이 401; 원본·사본·감사 변경 없음',
        observed: readOnlyBundle ? 'not_run' : observations.join('; ') });
      results.push({ attackId: 'verified_policy_and_b_recovery',
        expected: '검증한 시험 정책 버전 복원; B의 변조·삭제 한 건 ID·소유자·해시 일치 및 감사 보존',
        observed: '미실행: 이 자기 점검은 시험 정책·침해 기록이나 운영 B 인증·복원 요청을 사용하지 않음' });
      results.push({ attackId: 'post_recovery_regression',
        expected: '실제 복구 뒤 1~9단계 정상·금지 요청 재시험; 다른 메모·서비스 규칙·감사 보존',
        observed: '미실행: 운영 복구를 실행하지 않음; 가상 검사·운영 사건 전달·기기 회수와 별도 확인 필요' });
    }
    if (config.step >= 11) {
      const assetObservations = [];
      const manifestResponse = await probe(new URL('/manifest.webmanifest', app), {
        ...evidence('app_manifest_and_icons', 'manifest'),
        redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store' });
      let manifestValid = false;
      try {
        const manifest = await manifestResponse.json();
        manifestValid = manifestResponse.status === 200 && manifest?.name === 'BYTE BACK 내 자료실'
          && manifest.start_url === '/' && manifest.scope === '/' && manifest.display === 'standalone'
          && Array.isArray(manifest.icons) && [192, 512].every(size => manifest.icons.some(icon =>
            icon.src === `/icons/app-${size}.png` && icon.sizes === `${size}x${size}` && icon.type === 'image/png'))
          && homeText.includes('href="/manifest.webmanifest"')
          && homeText.includes('id="device-request"') && homeText.includes('id="device-status"');
      } catch { /* Raw manifest data is never recorded. */ }
      assetObservations.push(`manifest ${manifestResponse.status}: ${manifestValid ? '설정·화면 연결 확인' : '점검 실패'}`);
      for (const size of [192, 512]) {
        const iconResponse = await probe(new URL(`/icons/app-${size}.png`, app), {
          ...evidence('app_manifest_and_icons', `icon-${size}`),
          ...(readOnlyBundle ? { method: 'HEAD' } : {}),
          redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store' });
        if (readOnlyBundle) {
          const png = iconResponse.status === 200
            && iconResponse.headers.get('content-type')?.split(';')[0].trim().toLowerCase() === 'image/png';
          assetObservations.push(`icon ${size} HEAD ${iconResponse.status}: ${png ? 'PNG 응답 헤더 확인; 실제 크기 검사 not_run' : '점검 실패'}`);
          continue;
        }
        const bytes = new Uint8Array(await iconResponse.arrayBuffer());
        const pngHeader = [137, 80, 78, 71, 13, 10, 26, 10];
        const uint32 = offset => bytes[offset] * 16777216 + bytes[offset + 1] * 65536
          + bytes[offset + 2] * 256 + bytes[offset + 3];
        const valid = iconResponse.status === 200 && bytes.length >= 24
          && pngHeader.every((value, index) => bytes[index] === value)
          && uint32(16) === size && uint32(20) === size;
        assetObservations.push(`icon ${size} ${iconResponse.status}: ${valid ? '크기 확인' : '점검 실패'}`);
      }
      results.push({ attackId: 'app_manifest_and_icons',
        expected: readOnlyBundle
          ? 'manifest 연결·앱 이름·standalone·아이콘 선언 확인; PNG HEAD 헤더 확인; 실제 크기 검사는 not_run'
          : '배포 화면의 manifest 연결·앱 이름·standalone·192/512 PNG 확인; 설치는 승인이 아님',
        observed: assetObservations.join('; ') });
      const deviceObservations = [];
      for (const invalid of [false, true]) {
        for (const [method, path] of [['GET', '/api/device/status'], ['POST', '/api/device/request']]) {
          if (readOnlyBundle && !['GET', 'HEAD'].includes(method)) continue;
          const checked = await probe(new URL(path, app), { method, redirect: 'error',
            ...evidence('device_connection_unavailable', invalid ? 'invalid' : 'anonymous'),
            signal: AbortSignal.timeout(10000), cache: 'no-store', headers: {
              Origin: app.origin, ...(invalid ? { Authorization: 'Bearer invalid' } : {}) } });
          let unavailable = false;
          try {
            const state = await checked.json();
            unavailable = checked.status === 503 && state?.approved === false
              && state.error === 'DEVICE_APPROVAL_NOT_CONFIGURED'
              && Object.keys(state).sort().join(',') === 'approved,error';
          } catch { /* No identities or raw error data in the receipt. */ }
          deviceObservations.push(`${invalid ? '잘못된 인증' : '무로그인'} ${method} ${checked.status}: ${unavailable ? '미준비·승인 안 됨' : '점검 실패'}`);
        }
      }
      results.push({ attackId: 'device_connection_unavailable',
        expected: readOnlyBundle ? '운영 계약 없는 상태 GET은 503·approved:false; 승인을 만들지 않음'
          : '운영 계약 없는 승인 요청·상태 경로는 503·approved:false; 승인·접수 성공을 만들지 않음',
        observed: deviceObservations.join('; ') });
      if (readOnlyBundle) results.push({ attackId: 'device_approval_request',
        expected: '운영 계약 없는 승인 POST는 503·approved:false; 접수 성공을 만들지 않음',
        observed: 'not_run' });
      results.push({ attackId: 'registered_device_and_request_signatures',
        expected: '승인 전 자료 없음; 운영 등록 기기 화면·CRUD 유지; 서명 없음·경로/본문 변조 거부',
        observed: '미실행: 운영 기기 승인·서명 확인 계약 없음; 등록 기기 열기와 세 서명 공격은 운영 연결 뒤 확인 필요' });
    }
    if (config.step >= 12) {
      const checked = await probe(new URL('/api/operations', app), { redirect: 'error',
        ...evidence('operations_api_receipt', 'summary'),
        signal: AbortSignal.timeout(10000), cache: 'no-store' });
      let valid = false;
      let executed = null;
      let matched = null;
      let unrun = null;
      try {
        const summary = await checked.json();
        const rows = summary.checks;
        executed = summary.counts?.executed;
        matched = summary.counts?.matched;
        unrun = summary.counts?.unrun;
        valid = checked.status === 200 && summary.schema === 'aleph.operations.v1'
          && summary.step === 12 && summary.commit === config.expectedCommit
          && Array.isArray(rows) && rows.length === 22
          && executed === rows.filter(row => row.state !== 'unrun').length
          && matched === rows.filter(row => row.state === 'matched').length
          && unrun === rows.filter(row => row.state === 'unrun').length
          && summary.counts.failed === 0 && executed === 5 && matched === 5 && unrun === 17
          && ['detection', 'revocation', 'recovery', 'officialAttacks'].every(key => summary[key]?.state === 'unrun')
          && summary.officialAttacks.total === 41 && summary.officialAttacks.passed === null
          && rows.every(row => row.state === 'unrun'
            ? row.requestId === null && row.checkedAt === null
            : /^[0-9a-f-]{36}$/u.test(row.requestId) && Number.isFinite(Date.parse(row.checkedAt)))
          && homeText.includes('id="operations-heading"') && homeText.includes('src="/operations.js"');
      } catch { /* No response source, note text, or private metadata in the bundle. */ }
      results.push({ attackId: 'operations_api_receipt',
        expected: '현재 커밋·step 12의 작전실 API; 실측 5건·기대 일치 5건·미실행 17건; 운영 결과·41종 미실행',
        observed: valid ? `HTTP 200: 작전실 실측 ${executed}건·기대 일치 ${matched}건·미실행 ${unrun}건; 공식 41종 미실행`
          : `HTTP ${checked.status}: 작전실 응답·현재 커밋·실측 결과 점검 실패` });
      const asset = await probe(new URL('/operations.js', app), { redirect: 'error',
        ...evidence('operations_client_asset', 'script'),
        signal: AbortSignal.timeout(10000), cache: 'no-store' });
      const code = await asset.text();
      const safeAsset = asset.status === 200 && code.includes("fetch('/api/operations'")
        && !/\bsb_secret_[A-Za-z0-9_-]+|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/u.test(code);
      results.push({ attackId: 'operations_client_asset', expected: '작전실 화면 스크립트 HTTP 200; 요약 API 연결·비밀값 없음',
        observed: safeAsset ? 'HTTP 200: 화면 스크립트·요약 API 연결 확인'
          : `HTTP ${asset.status}: 작전실 화면 스크립트 점검 실패` });
    }
    if (readOnlyBundle) {
      for (const result of results) {
        if (result.observed.startsWith('미실행:')) result.observed = 'not_run';
        if (result.observed === 'not_run') continue;
        const records = observedRequests.get(result.attackId);
        if (!records?.length) throw new Error('ATTACK_EVIDENCE_MISSING');
        const selected = records[0];
        // The judge accepts observable facts only, and one explicit receipt
        // selector when the case sent multiple requests. Do not claim prose,
        // counts, header validation, or a pass verdict in this field.
        result.observed = (records.length > 1 ? `request=${selected.requestKey}#${selected.ordinal}: ` : '')
          + `HTTP ${selected.status}`;
      }
    }
    return results;
  }
  if (config.step === 2) {
    const results = [{ attackId: 'anonymous_static_note_read', expected: '비로그인 공개 JSON에 메모 본문이 없음',
      observed: empty ? '비로그인 공개 JSON은 빈 메모 목록 (Supabase 권한 검사는 별도 필요)'
        : `공개 JSON 점검 실패 (HTTP ${response.status})` }];
    const readResponse = await probe(new URL('/api/notes', app), {
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
    const writeResponse = await probe(new URL('/api/notes', app), {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    results.push({ attackId: 'public_api_write_rejected', expected: 'POST 요청을 HTTP 405로 거부',
      observed: writeResponse.status === 405 ? 'HTTP 405: 쓰기 요청 거부; 인증 검사가 아닌 메서드 제한'
        : `HTTP ${writeResponse.status}: 쓰기 요청 거부 점검 실패` });
    const marker = 'SAMPLE_NOTE_1';
    const failures = [];
    if (response.status !== 200 || staticText.includes(marker)) failures.push('/data.json');
    for (const path of ['/', '/index.html', '/aleph.json']) {
      const staticResponse = await probe(new URL(path, app), {
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
