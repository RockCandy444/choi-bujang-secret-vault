// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![1, 2].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  let empty = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
      empty = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length === 0 && Object.keys(data).sort().join(',') === 'notes,sampleMarker';
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
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
    return results;
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
