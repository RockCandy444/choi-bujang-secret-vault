const button = document.querySelector('#operations-refresh');
const status = document.querySelector('#operations-status');
const summary = document.querySelector('#operations-summary');
const checks = document.querySelector('#operations-checks');

function addSummary(name, value) {
  const term = document.createElement('dt');
  const description = document.createElement('dd');
  term.textContent = name;
  description.textContent = value;
  summary.append(term, description);
}

async function refresh() {
  if (button.disabled) return;
  button.disabled = true;
  summary.replaceChildren();
  checks.replaceChildren();
  status.textContent = '실제 API 결과를 확인하는 중입니다.';
  try {
    // No login token/cookie is sent to this public, sanitized receipt endpoint.
    const response = await fetch('/api/operations', { cache: 'no-store', credentials: 'omit' });
    const data = await response.json();
    if (!response.ok || data.schema !== 'aleph.operations.v1' || data.step !== 12
        || !Array.isArray(data.checks) || data.checks.length !== 22
        || !Array.isArray(data.policy?.ruleIds) || !data.counts
        || ['detection', 'revocation', 'recovery', 'officialAttacks'].some(key => data[key]?.state !== 'unrun')) {
      throw new Error('invalid_receipt');
    }
    addSummary('검사 출처', `${data.source.engine} · 학생 작업: ${data.source.student}`);
    addSummary('배포 버전', data.commit ?? '배포 커밋 미확인');
    addSummary('판정기 규칙', `${data.policy.ruleCount}개 · ${data.policy.ruleIds.join(', ')} · 운영 판정 횟수 미확인`);
    addSummary('탐지 사건', `미실행 · ${data.detection.reason}`);
    addSummary('회수 상태', `미실행 · ${data.revocation.reason}`);
    addSummary('복구 버전', `미실행 · ${data.recovery.reason}`);
    addSummary('41종 시험', `미실행 · ${data.officialAttacks.reason}`);
    for (const row of data.checks) {
      const tr = document.createElement('tr');
      for (const value of [`${row.step} · ${row.kind}`, row.name, row.expected,
        row.state === 'unrun' ? '미실행' : row.observed, row.requestId ?? '—',
        row.checkedAt ? new Date(row.checkedAt).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) + ' KST' : '—']) {
        const td = document.createElement('td');
        td.textContent = value;
        tr.append(td);
      }
      checks.append(tr);
    }
    status.textContent = `자기 점검 ${data.counts.executed}건 실행 · 기대 일치 ${data.counts.matched}건 · 확인 실패 ${data.counts.failed}건 · 미실행 ${data.counts.unrun}건. 확인 ${data.checkedAt} · 요청 ${data.requestId}`;
  } catch {
    summary.replaceChildren();
    checks.replaceChildren();
    status.textContent = '실제 API 결과를 확인하지 못했습니다. 이전 결과를 통과로 표시하지 않습니다. 다시 확인해 주세요.';
  } finally {
    button.disabled = false;
  }
}
button.addEventListener('click', refresh);
void refresh();
